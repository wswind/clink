// Copyright (c) 2020 Christopher Antos
// License: http://opensource.org/licenses/MIT

#include "pch.h"
#include "line_buffer.h"
#include "line_state.h"
#include "word_collector.h"
#include "popup.h"
#include "editor_module.h"
#include "rl_commands.h"
#include "doskey.h"
#include "textlist_impl.h"
#include "history_db.h"
#include "ellipsify.h"

#include "rl_suggestions.h"

#include <core/base.h>
#include <core/log.h>
#include <core/path.h>
#include <core/settings.h>
#include <core/debugheap.h>
#include <terminal/printer.h>
#include <terminal/scroll.h>
#include <terminal/screen_buffer.h>
#include <terminal/terminal_helpers.h>

extern "C" {
#include <readline/readline.h>
#include <readline/rldefs.h>
#include <readline/rlprivate.h>
#include <readline/history.h>
extern void rl_replace_from_history(HIST_ENTRY *entry, int flags);
}

#include <list>
#include <unordered_set>
#include <signal.h>

#include "../../../clink/app/src/version.h" // Ugh.



//------------------------------------------------------------------------------
// Internal ConHost system menu command IDs.
#define ID_CONSOLE_COPY         0xFFF0
#define ID_CONSOLE_PASTE        0xFFF1
#define ID_CONSOLE_MARK         0xFFF2
#define ID_CONSOLE_SCROLL       0xFFF3
#define ID_CONSOLE_FIND         0xFFF4
#define ID_CONSOLE_SELECTALL    0xFFF5
#define ID_CONSOLE_EDIT         0xFFF6
#define ID_CONSOLE_CONTROL      0xFFF7
#define ID_CONSOLE_DEFAULTS     0xFFF8



//------------------------------------------------------------------------------
enum { paste_crlf_delete, paste_crlf_space, paste_crlf_ampersand, paste_crlf_crlf };
static setting_enum g_paste_crlf(
    "clink.paste_crlf",
    "Strips CR and LF chars on paste",
    "Setting this to 'space' makes Clink strip CR and LF characters from text\n"
    "pasted into the current line.  Set this to 'delete' to strip all newline\n"
    "characters to replace them with a space.  Set this to 'ampersand' to replace\n"
    "all newline characters with an ampersand.  Or set this to 'crlf' to paste all\n"
    "newline characters as-is (executing commands that end with newline).",
    "delete,space,ampersand,crlf",
    paste_crlf_crlf);

extern setting_bool g_adjust_cursor_style;
extern setting_color g_color_popup;
extern setting_color g_color_popup_desc;
extern setting_bool g_match_wild;

static bool s_force_reload_scripts = false;



//------------------------------------------------------------------------------
extern line_buffer* g_rl_buffer;
extern word_collector* g_word_collector;
extern editor_module::result* g_result;
extern void host_cmd_enqueue_lines(std::list<str_moveable>& lines, bool hide_prompt, bool show_line);
extern void host_get_app_context(int& id, str_base& binaries, str_base& profile, str_base& scripts);
extern "C" int show_cursor(int visible);
extern void set_suggestion(const char* line, unsigned int endword_offset, const char* suggestion, unsigned int offset);
extern "C" void host_clear_suggestion();
extern "C" int test_ambiguous_width_char(char32_t ucs);

// This is implemented in the app layer, which makes it inaccessible to lower
// layers.  But Readline and History are siblings, so history_db and rl_module
// and rl_commands should be siblings.  That's a lot of reshuffling for little
// benefit, so just use a forward decl for now.
extern bool expand_history(const char* in, str_base& out);

//------------------------------------------------------------------------------
static UINT s_dwCtrlWakeupMask = 0;
void set_ctrl_wakeup_mask(UINT mask)
{
    s_dwCtrlWakeupMask = mask;
}

//------------------------------------------------------------------------------
template<class T> void strip_wakeup_chars_worker(T* chars, unsigned int max_chars)
{
    if (!max_chars)
        return;

    T* read = chars;
    T* write = chars;

    while (max_chars--)
    {
        const T c = *read;
        if (!c)
            break;

        if (c < 0 || c >= 32 || !(s_dwCtrlWakeupMask & 1 << c))
        {
            if (write != read)
                *write = c;
            ++write;
        }

        ++read;
    }

    if (write != read)
        *write = '\0';
}

//------------------------------------------------------------------------------
void strip_wakeup_chars(wchar_t* chars, unsigned int max_chars)
{
    strip_wakeup_chars_worker(chars, max_chars);
}

//------------------------------------------------------------------------------
void strip_wakeup_chars(str_base& out)
{
    unsigned int max_chars = out.length();
    strip_wakeup_chars_worker(out.data(), max_chars);
}

//------------------------------------------------------------------------------
static void strip_crlf(char* line, std::list<str_moveable>& overflow, int setting, bool* _done)
{
    bool has_overflow = false;
    int prev_was_crlf = 0;
    char* write = line;
    const char* read = line;
    bool done = false;
    while (*read)
    {
        char c = *read;
        if (c != '\n' && c != '\r')
        {
            prev_was_crlf = 0;
            *write = c;
            ++write;
        }
        else if (!prev_was_crlf)
        {
            switch (setting)
            {
            default:
                assert(false);
                // fall through
            case paste_crlf_delete:
                break;
            case paste_crlf_space:
                prev_was_crlf = 1;
                *write = ' ';
                ++write;
                break;
            case paste_crlf_ampersand:
                prev_was_crlf = 1;
                *write = '&';
                ++write;
                break;
            case paste_crlf_crlf:
                has_overflow = true;
                if (c == '\n')
                {
                    *write = '\n';
                    ++write;
                }
                break;
            }
        }

        ++read;
    }

    *write = '\0';

    if (has_overflow)
    {
        bool first = true;
        char* start = line;
        while (*start)
        {
            char* end = start;
            while (*end)
            {
                char c = *end;
                ++end;
                if (c == '\n')
                {
                    done = true;
                    if (first)
                        *(end - 1) = '\0';
                    break;
                }
            }

            if (first)
            {
                first = false;
            }
            else
            {
                unsigned int len = (unsigned int)(end - start);
                overflow.emplace_back();
                str_moveable& back = overflow.back();
                back.reserve(len);
                back.concat(start, len);
            }

            start = end;
        }
    }

    if (_done)
        *_done = done;
}

//------------------------------------------------------------------------------
static void get_word_bounds(const line_buffer& buffer, int* left, int* right)
{
    const char* str = buffer.get_buffer();
    unsigned int cursor = buffer.get_cursor();

    // Determine the word delimiter depending on whether the word's quoted.
    int delim = 0;
    for (unsigned int i = 0; i < cursor; ++i)
    {
        char c = str[i];
        delim += (c == '\"');
    }

    // Search outwards from the cursor for the delimiter.
    delim = (delim & 1) ? '\"' : ' ';
    *left = 0;
    for (int i = cursor - 1; i >= 0; --i)
    {
        char c = str[i];
        if (c == delim)
        {
            *left = i + 1;
            break;
        }
    }

    const char* post = strchr(str + cursor, delim);
    if (post != nullptr)
        *right = int(post - str);
    else
        *right = int(strlen(str));
}



//------------------------------------------------------------------------------
int host_add_history(int, const char* line)
{
    history_database* h = history_database::get();
    return h && h->add(line);
}

//------------------------------------------------------------------------------
int host_remove_history(int rl_history_index, const char* line)
{
    history_database* h = history_database::get();
    return h && h->remove(rl_history_index, line);
}



//------------------------------------------------------------------------------
static int s_cua_anchor = -1;

//------------------------------------------------------------------------------
class cua_selection_manager
{
public:
    cua_selection_manager()
    : m_anchor(s_cua_anchor)
    , m_point(rl_point)
    {
        if (s_cua_anchor < 0)
            s_cua_anchor = rl_point;
    }

    ~cua_selection_manager()
    {
        if (s_cua_anchor >= 0)
            host_clear_suggestion();
        if (g_rl_buffer && (m_anchor != s_cua_anchor || m_point != rl_point))
            g_rl_buffer->set_need_draw();
    }

private:
    int m_anchor;
    int m_point;
};

//------------------------------------------------------------------------------
static void cua_delete()
{
    if (s_cua_anchor >= 0)
    {
        if (g_rl_buffer)
        {
            // Make sure rl_point is lower so it ends up in the right place.
            if (s_cua_anchor < rl_point)
                SWAP(s_cua_anchor, rl_point);
            g_rl_buffer->remove(s_cua_anchor, rl_point);
        }
        cua_clear_selection();
    }
}



//------------------------------------------------------------------------------
int clink_reload(int count, int invoking_key)
{
    assert(g_result);
    return force_reload_scripts();
}

//------------------------------------------------------------------------------
int clink_reset_line(int count, int invoking_key)
{
    using_history();
    g_rl_buffer->remove(0, rl_end);
    rl_point = 0;

    return 0;
}

//------------------------------------------------------------------------------
int clink_exit(int count, int invoking_key)
{
    clink_reset_line(1, 0);
    g_rl_buffer->insert("exit");
    rl_newline(1, invoking_key);

    return 0;
}

//------------------------------------------------------------------------------
int clink_ctrl_c(int count, int invoking_key)
{
    if (s_cua_anchor >= 0)
    {
        cua_selection_manager mgr;
        cua_copy(count, invoking_key);
        cua_clear_selection();
        return 0;
    }

    extern void clink_sighandler(int sig);
    clink_sighandler(SIGINT);

    return 0;
}

//------------------------------------------------------------------------------
int clink_paste(int count, int invoking_key)
{
    str<1024> utf8;
    if (!os::get_clipboard_text(utf8))
        return 0;

    dbg_ignore_scope(snapshot, "clink_paste");

    bool done = false;
    bool sel = (s_cua_anchor >= 0);
    std::list<str_moveable> overflow;
    strip_crlf(utf8.data(), overflow, g_paste_crlf.get(), &done);
    strip_wakeup_chars(utf8);
    if (sel)
    {
        g_rl_buffer->begin_undo_group();
        cua_delete();
    }
    _rl_set_mark_at_pos(g_rl_buffer->get_cursor());
    g_rl_buffer->insert(utf8.c_str());
    if (sel)
        g_rl_buffer->end_undo_group();
    host_cmd_enqueue_lines(overflow, false, true);
    if (done)
    {
        (*rl_redisplay_function)();
        rl_newline(1, invoking_key);
    }

    return 0;
}

//------------------------------------------------------------------------------
int clink_copy_line(int count, int invoking_key)
{
    os::set_clipboard_text(g_rl_buffer->get_buffer(), g_rl_buffer->get_length());

    return 0;
}

//------------------------------------------------------------------------------
int clink_copy_word(int count, int invoking_key)
{
    if (count < 0 || !g_rl_buffer || !g_word_collector)
    {
Nope:
        rl_ding();
        return 0;
    }

    std::vector<word> words;
    g_word_collector->collect_words(*g_rl_buffer, words, collect_words_mode::whole_command);

    if (words.empty())
        goto Nope;

    if (!rl_explicit_arg)
    {
        unsigned int line_cursor = g_rl_buffer->get_cursor();
        for (auto const& word : words)
        {
            if (line_cursor >= word.offset &&
                line_cursor <= word.offset + word.length)
            {
                os::set_clipboard_text(g_rl_buffer->get_buffer() + word.offset, word.length);
                return 0;
            }
        }
    }
    else
    {
        for (auto const& word : words)
        {
            if (count-- == 0)
            {
                os::set_clipboard_text(g_rl_buffer->get_buffer() + word.offset, word.length);
                return 0;
            }
        }
    }

    goto Nope;
}

//------------------------------------------------------------------------------
int clink_copy_cwd(int count, int invoking_key)
{
    wstr<270> cwd;
    unsigned int length = GetCurrentDirectoryW(cwd.size(), cwd.data());
    if (length < cwd.size())
    {
        str<> tmp;
        to_utf8(tmp, cwd.c_str());
        tmp << PATH_SEP;
        path::normalise(tmp);
        os::set_clipboard_text(tmp.c_str(), tmp.length());
    }

    return 0;
}

//------------------------------------------------------------------------------
int clink_expand_env_var(int count, int invoking_key)
{
    // Extract the word under the cursor.
    int word_left, word_right;
    get_word_bounds(*g_rl_buffer, &word_left, &word_right);

    str<1024> in;
    in.concat(g_rl_buffer->get_buffer() + word_left, word_right - word_left);

    str<> out;
    os::expand_env(in.c_str(), in.length(), out);

    // Update Readline with the resulting expansion.
    g_rl_buffer->begin_undo_group();
    g_rl_buffer->remove(word_left, word_right);
    g_rl_buffer->set_cursor(word_left);
    g_rl_buffer->insert(out.c_str());
    g_rl_buffer->end_undo_group();

    return 0;
}

//------------------------------------------------------------------------------
enum { el_alias = 1, el_envvar = 2, el_history = 4 };
static int do_expand_line(int flags)
{
    bool expanded = false;
    str<> in;
    str<> out;
    int point = rl_point;

    in = g_rl_buffer->get_buffer();

    if (flags & el_history)
    {
        if (expand_history(in.c_str(), out))
        {
            in = out.c_str();
            point = -1;
            expanded = true;
        }
    }

    if (flags & el_alias)
    {
        doskey_alias alias;
        doskey doskey("cmd.exe");
        doskey.resolve(in.c_str(), alias, point < 0 ? nullptr : &point);
        if (alias)
        {
            alias.next(out);
            in = out.c_str();
            expanded = true;
        }
    }

    if (flags & el_envvar)
    {
        if (os::expand_env(in.c_str(), in.length(), out, point < 0 ? nullptr : &point))
        {
            in = out.c_str();
            expanded = true;
        }
    }

    if (!expanded)
    {
        rl_ding();
        return 0;
    }

    g_rl_buffer->begin_undo_group();
    g_rl_buffer->remove(0, rl_end);
    rl_point = 0;
    if (!out.empty())
        g_rl_buffer->insert(out.c_str());
    if (point >= 0 && point <= rl_end)
        g_rl_buffer->set_cursor(point);
    g_rl_buffer->end_undo_group();

    return 0;
}

//------------------------------------------------------------------------------
// Expands a doskey alias (but only the first line, if $T is present).
int clink_expand_doskey_alias(int count, int invoking_key)
{
    return do_expand_line(el_alias);
}

//------------------------------------------------------------------------------
// Performs history expansion.
int clink_expand_history(int count, int invoking_key)
{
    return do_expand_line(el_history);
}

//------------------------------------------------------------------------------
// Performs history and doskey alias expansion.
int clink_expand_history_and_alias(int count, int invoking_key)
{
    return do_expand_line(el_history|el_alias);
}

//------------------------------------------------------------------------------
// Performs history, doskey alias, and environment variable expansion.
int clink_expand_line(int count, int invoking_key)
{
    return do_expand_line(el_history|el_alias|el_envvar);
}

//------------------------------------------------------------------------------
int clink_up_directory(int count, int invoking_key)
{
    g_rl_buffer->begin_undo_group();
    g_rl_buffer->remove(0, ~0u);
    g_rl_buffer->insert(" cd ..");
    g_rl_buffer->end_undo_group();
    rl_newline(1, invoking_key);

    return 0;
}

//------------------------------------------------------------------------------
int clink_insert_dot_dot(int count, int invoking_key)
{
    str<> str;

    if (unsigned int cursor = g_rl_buffer->get_cursor())
    {
        char last_char = g_rl_buffer->get_buffer()[cursor - 1];
        if (last_char != ' ' && !path::is_separator(last_char))
            str << PATH_SEP;
    }

    str << ".." << PATH_SEP;

    g_rl_buffer->insert(str.c_str());

    return 0;
}

//------------------------------------------------------------------------------
int clink_shift_space(int count, int invoking_key)
{
    return _rl_dispatch(' ', _rl_keymap);
}

//------------------------------------------------------------------------------
int clink_magic_suggest_space(int count, int invoking_key)
{
    insert_suggestion(suggestion_action::insert_next_full_word);
    g_rl_buffer->insert(" ");
    return 0;
}



//------------------------------------------------------------------------------
int clink_scroll_line_up(int count, int invoking_key)
{
    ScrollConsoleRelative(GetStdHandle(STD_OUTPUT_HANDLE), -1, SCR_BYLINE);
    return 0;
}

//------------------------------------------------------------------------------
int clink_scroll_line_down(int count, int invoking_key)
{
    ScrollConsoleRelative(GetStdHandle(STD_OUTPUT_HANDLE), 1, SCR_BYLINE);
    return 0;
}

//------------------------------------------------------------------------------
int clink_scroll_page_up(int count, int invoking_key)
{
    ScrollConsoleRelative(GetStdHandle(STD_OUTPUT_HANDLE), -1, SCR_BYPAGE);
    return 0;
}

//------------------------------------------------------------------------------
int clink_scroll_page_down(int count, int invoking_key)
{
    ScrollConsoleRelative(GetStdHandle(STD_OUTPUT_HANDLE), 1, SCR_BYPAGE);
    return 0;
}

//------------------------------------------------------------------------------
int clink_scroll_top(int count, int invoking_key)
{
    ScrollConsoleRelative(GetStdHandle(STD_OUTPUT_HANDLE), -1, SCR_TOEND);
    return 0;
}

//------------------------------------------------------------------------------
int clink_scroll_bottom(int count, int invoking_key)
{
    ScrollConsoleRelative(GetStdHandle(STD_OUTPUT_HANDLE), 1, SCR_TOEND);
    return 0;
}



//------------------------------------------------------------------------------
int clink_find_conhost(int count, int invoking_key)
{
    HWND hwndConsole = GetConsoleWindow();
    if (!hwndConsole)
    {
        rl_ding();
        return 0;
    }

    // Invoke conhost's Find command via the system menu.
    SendMessage(hwndConsole, WM_SYSCOMMAND, ID_CONSOLE_FIND, 0);
    return 0;
}

//------------------------------------------------------------------------------
int clink_mark_conhost(int count, int invoking_key)
{
    HWND hwndConsole = GetConsoleWindow();
    if (!hwndConsole)
    {
        rl_ding();
        return 0;
    }

    // Conhost's Mark command is asynchronous and saves/restores the cursor info
    // and position.  So we need to trick the cursor into being visible, so that
    // it gets restored as visible since that's the state Readline will be in
    // after the Mark command finishes.
    show_cursor(true);

    // Invoke conhost's Mark command via the system menu.
    SendMessage(hwndConsole, WM_SYSCOMMAND, ID_CONSOLE_MARK, 0);
    return 0;
}

//------------------------------------------------------------------------------
int clink_selectall_conhost(int count, int invoking_key)
{
    bool has_begin = (s_cua_anchor == 0 || rl_point == 0);
    bool has_end = (s_cua_anchor == rl_end || rl_point == rl_end);
    if (!has_begin || !has_end)
        return cua_select_all(0, invoking_key);

    HWND hwndConsole = GetConsoleWindow();
    if (!hwndConsole)
    {
        rl_ding();
        return 0;
    }

    if (rl_point == 0 && s_cua_anchor == rl_end)
    {
        s_cua_anchor = 0;
        rl_point = rl_end;
        (*rl_redisplay_function)();
    }

    // Invoke conhost's Select All command via the system menu.
    SendMessage(hwndConsole, WM_SYSCOMMAND, ID_CONSOLE_SELECTALL, 0);
    return 0;
}



//------------------------------------------------------------------------------
extern const char** host_copy_dir_history(int* total);
int clink_popup_directories(int count, int invoking_key)
{
    // Copy the directory list (just a shallow copy of the dir pointers).
    int total = 0;
    const char** history = host_copy_dir_history(&total);
    if (!history || !total)
    {
        free(history);
        rl_ding();
        return 0;
    }

    // Popup list.
    const popup_results results = activate_directories_text_list(history, total);

    // Handle results.
    switch (results.m_result)
    {
    case popup_result::cancel:
        break;
    case popup_result::error:
        rl_ding();
        break;
    case popup_result::select:
    case popup_result::use:
        {
            bool end_sep = (results.m_text.c_str()[0] &&
                            path::is_separator(results.m_text.c_str()[results.m_text.length() - 1]));

            char qs[2] = {};
            if (rl_basic_quote_characters &&
                rl_basic_quote_characters[0] &&
                rl_filename_quote_characters &&
                _rl_strpbrk(results.m_text.c_str(), rl_filename_quote_characters) != 0)
            {
                qs[0] = rl_basic_quote_characters[0];
            }

            str<> dir;
            dir.format("%s%s%s", qs, results.m_text.c_str(), qs);

            bool use = (results.m_result == popup_result::use);
            rl_begin_undo_group();
            if (use)
            {
                if (!end_sep)
                    dir.concat(PATH_SEP);
                rl_replace_line(dir.c_str(), 0);
                rl_point = rl_end;
            }
            else
            {
                rl_insert_text(dir.c_str());
            }
            rl_end_undo_group();
            (*rl_redisplay_function)();
            if (use)
                rl_newline(1, invoking_key);
        }
        break;
    }

    free(history);

    return 0;
}



//------------------------------------------------------------------------------
extern bool host_call_lua_rl_global_function(const char* func_name);

//------------------------------------------------------------------------------
int clink_complete_numbers(int count, int invoking_key)
{
    if (!host_call_lua_rl_global_function("clink._complete_numbers"))
        rl_ding();
    return 0;
}

//------------------------------------------------------------------------------
int clink_menu_complete_numbers(int count, int invoking_key)
{
    if (!host_call_lua_rl_global_function("clink._menu_complete_numbers"))
        rl_ding();
    return 0;
}

//------------------------------------------------------------------------------
int clink_menu_complete_numbers_backward(int count, int invoking_key)
{
    if (!host_call_lua_rl_global_function("clink._menu_complete_numbers_backward"))
        rl_ding();
    return 0;
}

//------------------------------------------------------------------------------
int clink_old_menu_complete_numbers(int count, int invoking_key)
{
    if (!host_call_lua_rl_global_function("clink._old_menu_complete_numbers"))
        rl_ding();
    return 0;
}

//------------------------------------------------------------------------------
int clink_old_menu_complete_numbers_backward(int count, int invoking_key)
{
    if (!host_call_lua_rl_global_function("clink._old_menu_complete_numbers_backward"))
        rl_ding();
    return 0;
}

//------------------------------------------------------------------------------
int clink_popup_complete_numbers(int count, int invoking_key)
{
    if (!host_call_lua_rl_global_function("clink._popup_complete_numbers"))
        rl_ding();
    return 0;
}

//------------------------------------------------------------------------------
int clink_popup_show_help(int count, int invoking_key)
{
    if (!host_call_lua_rl_global_function("clink._popup_show_help"))
        rl_ding();
    return 0;
}



//------------------------------------------------------------------------------
int clink_select_complete(int count, int invoking_key)
{
    if (RL_ISSTATE(RL_STATE_MACRODEF) != 0)
    {
ding:
        rl_ding();
        return 0;
    }

    extern bool activate_select_complete(editor_module::result& result, bool reactivate);
    if (!g_result || !activate_select_complete(*g_result, rl_last_func == clink_select_complete))
        goto ding;
    return 0;
}



//------------------------------------------------------------------------------
bool cua_clear_selection()
{
    if (s_cua_anchor < 0)
        return false;
    s_cua_anchor = -1;
    return true;
}

//------------------------------------------------------------------------------
bool cua_set_selection(int anchor, int point)
{
    const int new_anchor = min<int>(rl_end, anchor);
    const int new_point = max<int>(0, min<int>(rl_end, point));
    if (new_anchor == s_cua_anchor && new_point == rl_point)
        return false;
    s_cua_anchor = new_anchor;
    rl_point = new_point;
    return true;
}

//------------------------------------------------------------------------------
int cua_get_anchor()
{
    return s_cua_anchor;
}

//------------------------------------------------------------------------------
bool cua_point_in_selection(int in)
{
    if (s_cua_anchor < 0)
        return false;
    if (s_cua_anchor < rl_point)
        return (s_cua_anchor <= in && in < rl_point);
    else
        return (rl_point <= in && in < s_cua_anchor);
}

//------------------------------------------------------------------------------
int cua_selection_event_hook(int event)
{
    if (!g_rl_buffer)
        return 0;

    static bool s_cleanup = false;

    switch (event)
    {
    case SEL_BEFORE_INSERTCHAR:
        assert(!s_cleanup);
        if (s_cua_anchor >= 0)
        {
            s_cleanup = true;
            g_rl_buffer->begin_undo_group();
            cua_delete();
        }
        break;
    case SEL_AFTER_INSERTCHAR:
        if (s_cleanup)
        {
            g_rl_buffer->end_undo_group();
            s_cleanup = false;
        }
        break;
    case SEL_BEFORE_DELETE:
        if (s_cua_anchor < 0 || s_cua_anchor == rl_point)
            break;
        cua_delete();
        return 1;
    }

    return 0;
}

//------------------------------------------------------------------------------
void cua_after_command(bool force_clear)
{
    static std::unordered_set<void*> s_map;

    if (s_map.empty())
    {
        // No action after a cua command.
        s_map.emplace(cua_previous_screen_line);
        s_map.emplace(cua_next_screen_line);
        s_map.emplace(cua_backward_char);
        s_map.emplace(cua_forward_char);
        s_map.emplace(cua_backward_word);
        s_map.emplace(cua_forward_word);
        s_map.emplace(cua_beg_of_line);
        s_map.emplace(cua_end_of_line);
        s_map.emplace(cua_select_all);
        s_map.emplace(cua_copy);
        s_map.emplace(cua_cut);
        s_map.emplace(clink_selectall_conhost);

        // No action after scroll commands.
        s_map.emplace(clink_scroll_line_up);
        s_map.emplace(clink_scroll_line_down);
        s_map.emplace(clink_scroll_page_up);
        s_map.emplace(clink_scroll_page_down);
        s_map.emplace(clink_scroll_top);
        s_map.emplace(clink_scroll_bottom);

        // No action after some special commands.
        s_map.emplace(show_rl_help);
        s_map.emplace(show_rl_help_raw);
    }

    // If not a recognized command, clear the cua selection.
    if (force_clear || s_map.find((void*)rl_last_func) == s_map.end())
        cua_clear_selection();
}

//------------------------------------------------------------------------------
int cua_previous_screen_line(int count, int invoking_key)
{
    cua_selection_manager mgr;
    return rl_previous_screen_line(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_next_screen_line(int count, int invoking_key)
{
    cua_selection_manager mgr;
    return rl_next_screen_line(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_backward_char(int count, int invoking_key)
{
    cua_selection_manager mgr;
    return rl_backward_char(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_forward_char(int count, int invoking_key)
{
    if (count != 0)
    {
another_word:
        if (insert_suggestion(suggestion_action::insert_next_full_word))
        {
            count--;
            if (count > 0)
                goto another_word;
            return 0;
        }
    }

    cua_selection_manager mgr;
    return rl_forward_char(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_backward_word(int count, int invoking_key)
{
    cua_selection_manager mgr;
    return rl_backward_word(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_forward_word(int count, int invoking_key)
{
    cua_selection_manager mgr;
    return rl_forward_word(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_select_word(int count, int invoking_key)
{
    cua_selection_manager mgr;

    const int orig_point = rl_point;

    // Look forward for a word.
    rl_forward_word(1, 0);
    int end = rl_point;
    rl_backward_word(1, 0);
    const int high_mid = rl_point;

    rl_point = orig_point;

    // Look backward for a word.
    rl_backward_word(1, 0);
    int begin = rl_point;
    rl_forward_word(1, 0);
    const int low_mid = rl_point;

    if (high_mid <= orig_point)
    {
        begin = high_mid;
    }
    else if (low_mid > orig_point)
    {
        end = low_mid;
    }
    else
    {
        // The original point is between two words.  For now, select the text
        // between the words.
        begin = low_mid;
        end = high_mid;
    }

    s_cua_anchor = begin;
    rl_point = end;

    return 0;
}

//------------------------------------------------------------------------------
int cua_beg_of_line(int count, int invoking_key)
{
    cua_selection_manager mgr;
    return rl_beg_of_line(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_end_of_line(int count, int invoking_key)
{
    cua_selection_manager mgr;
    return rl_end_of_line(count, invoking_key);
}

//------------------------------------------------------------------------------
int cua_select_all(int count, int invoking_key)
{
    cua_selection_manager mgr;
    s_cua_anchor = 0;
    rl_point = rl_end;
    return 0;
}

//------------------------------------------------------------------------------
int cua_copy(int count, int invoking_key)
{
    if (g_rl_buffer)
    {
        bool has_sel = (s_cua_anchor >= 0);
        unsigned int len = g_rl_buffer->get_length();
        unsigned int beg = has_sel ? min<unsigned int>(len, s_cua_anchor) : 0;
        unsigned int end = has_sel ? min<unsigned int>(len, rl_point) : len;
        if (beg > end)
            SWAP(beg, end);
        if (beg < end)
            os::set_clipboard_text(g_rl_buffer->get_buffer() + beg, end - beg);
    }
    return 0;
}

//------------------------------------------------------------------------------
int cua_cut(int count, int invoking_key)
{
    cua_copy(0, 0);
    cua_delete();
    return 0;
}



//------------------------------------------------------------------------------
static constexpr unsigned char c_colors[] = { 30, 34, 32, 36, 31, 35, 33, 37, 90, 94, 92, 96, 91, 95, 93, 97 };
const char* get_popup_colors()
{
    static str<32> s_popup;

    str<32> tmp;
    g_color_popup.get(tmp);
    if (!tmp.empty())
    {
        s_popup.format("0;%s", tmp.c_str());
        return s_popup.c_str();
    }

    CONSOLE_SCREEN_BUFFER_INFOEX csbiex = { sizeof(csbiex) };
    if (!GetConsoleScreenBufferInfoEx(GetStdHandle(STD_OUTPUT_HANDLE), &csbiex))
        return "0;30;47";

    WORD attr = csbiex.wPopupAttributes;
    s_popup.format("0;%u;%u", c_colors[attr & 0x0f], c_colors[(attr & 0xf0) >> 4] + 10);
    return s_popup.c_str();
}

//------------------------------------------------------------------------------
const char* get_popup_desc_colors()
{
    static str<32> s_popup_desc;

    str<32> tmp;
    g_color_popup_desc.get(tmp);
    if (!tmp.empty())
    {
        s_popup_desc.format("0;%s", tmp.c_str());
        return s_popup_desc.c_str();
    }

    CONSOLE_SCREEN_BUFFER_INFOEX csbiex = { sizeof(csbiex) };
    if (!GetConsoleScreenBufferInfoEx(GetStdHandle(STD_OUTPUT_HANDLE), &csbiex))
        return "0;90;47";

    int dim = 30;
    WORD attr = csbiex.wPopupAttributes;
    if ((attr & 0xf0) == 0x00 || (attr & 0xf0) == 0x10 || (attr & 0xf0) == 0x90)
        dim = 90;
    s_popup_desc.format("0;%u;%u", dim, c_colors[(attr & 0xf0) >> 4] + 10);
    return s_popup_desc.c_str();
}

//------------------------------------------------------------------------------
static int adjust_point_delta(int& point, int delta, char* buffer)
{
    if (delta <= 0)
        return 0;

    const int length = int(strlen(buffer));
    if (point == length)
        return 0;

    if (point > length)
    {
        point = length;
        return 0;
    }

    if (delta > length - point)
        delta = length - point;

    int tmp = point;
    int count = 0;

#if defined (HANDLE_MULTIBYTE)
    if (MB_CUR_MAX == 1 || rl_byte_oriented)
#endif
    {
        tmp += delta;
        count += delta;
    }
#if defined (HANDLE_MULTIBYTE)
    else
    {
        while (delta)
        {
            int was = tmp;
            tmp = _rl_find_next_mbchar(buffer, tmp, 1, MB_FIND_NONZERO);
            if (tmp <= was)
                break;
            count++;
            delta--;
        }
    }
#endif

    point = tmp;
    return count;
}

//------------------------------------------------------------------------------
static int adjust_point_point(int& point, int target, char* buffer)
{
    if (target <= point)
        return 0;

    const int length = int(strlen(buffer));
    if (point == length)
        return 0;

    if (point > length)
    {
        point = length;
        return 0;
    }

    if (target > length)
        target = length;

    int tmp = point;
    int count = 0;

#if defined (HANDLE_MULTIBYTE)
    if (MB_CUR_MAX == 1 || rl_byte_oriented)
#endif
    {
        count = target - tmp;
        tmp = target;
    }
#if defined (HANDLE_MULTIBYTE)
    else
    {
        while (tmp < target)
        {
            int was = tmp;
            tmp = _rl_find_next_mbchar(buffer, tmp, 1, MB_FIND_NONZERO);
            if (tmp <= was)
                break;
            count++;
        }
    }
#endif

    point = tmp;
    return true;
}

//------------------------------------------------------------------------------
static int adjust_point_keyseq(int& point, const char* keyseq, char* buffer)
{
    if (!keyseq || !*keyseq)
        return 0;

    const int length = int(strlen(buffer));
    if (point == length)
        return 0;

    if (point > length)
    {
        point = length;
        return 0;
    }

    int tmp = point;
    int count = 0;

#if defined (HANDLE_MULTIBYTE)
    if (MB_CUR_MAX == 1 || rl_byte_oriented)
#endif
    {
        const char* found = strstr(buffer + tmp, keyseq);
        int delta = found ? int(found - (buffer + tmp)) : length - tmp;
        tmp += delta;
        count += delta;
    }
#if defined (HANDLE_MULTIBYTE)
    else
    {
        int keyseq_len = int(strlen(keyseq));
        while (buffer[tmp] && strncmp(buffer + tmp, keyseq, keyseq_len) != 0)
        {
            tmp = _rl_find_next_mbchar(buffer, tmp, 1, MB_FIND_NONZERO);
            count++;
        }
    }
#endif

    if (tmp > length)
        tmp = length;

    point = tmp;
    return count;
}

//------------------------------------------------------------------------------
static str<16, false> s_win_fn_input_buffer;
static bool read_win_fn_input_char()
{
    int c;

    RL_SETSTATE(RL_STATE_MOREINPUT);
    c = rl_read_key();
    RL_UNSETSTATE(RL_STATE_MOREINPUT);

    if (c < 0)
        return false;

    if (RL_ISSTATE(RL_STATE_MACRODEF))
        _rl_add_macro_char(c);

#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_restore_tty_signals ();
#endif

    if (c == 27/*Esc*/ || c == 7/*^G*/)
    {
nope:
        s_win_fn_input_buffer.clear();
        return true;
    }

    s_win_fn_input_buffer.concat(reinterpret_cast<const char*>(&c), 1);

    WCHAR_T wc;
    mbstate_t mbs = {};
    size_t validate = MBRTOWC(&wc, s_win_fn_input_buffer.c_str(), s_win_fn_input_buffer.length(), &mbs);

    if (MB_NULLWCH(validate))
        goto nope;

    // Once there's a valid UTF8 character, the input is complete.
    return !MB_INVALIDCH(validate);
}

//------------------------------------------------------------------------------
static char* get_history(int item)
{
    HIST_ENTRY** list = history_list();
    if (!list || !history_length)
        return nullptr;

    if (item >= history_length)
        item = history_length - 1;
    if (item < 0)
        return nullptr;

    return list[item]->line;
}

//------------------------------------------------------------------------------
static char* get_previous_command()
{
    int previous = where_history();
    return get_history(previous);
}

//------------------------------------------------------------------------------
int win_f1(int count, int invoking_key)
{
    const bool had_selection = (cua_get_anchor() >= 0);

    if (insert_suggestion(suggestion_action::insert_to_end) || accepted_whole_suggestion())
        return 0;

    if (count <= 0)
        count = 1;

    while (count && rl_point < rl_end)
    {
        rl_forward_char(1, invoking_key);
        count--;
    }

    if (!count)
        return 0;

    if (had_selection)
        return 0;

    char* prev_buffer = get_previous_command();
    if (!prev_buffer)
    {
ding:
        rl_ding();
        return 0;
    }

    int old_point = 0;
    adjust_point_point(old_point, rl_point, prev_buffer);
    if (!prev_buffer[old_point])
        goto ding;

    int end_point = old_point;
    adjust_point_delta(end_point, count, prev_buffer);
    if (end_point <= old_point)
        goto ding;

    str<> more;
    more.concat(prev_buffer + old_point, end_point - old_point);
    rl_insert_text(more.c_str());

    // Prevent generating a suggestion when inserting characters from the
    // previous command, otherwise it's often only possible to insert one
    // character before suggestions take over.
    set_suggestion(rl_line_buffer, 0, rl_line_buffer, 0);

    return 0;
}

//------------------------------------------------------------------------------
static int finish_win_f2()
{
#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_restore_tty_signals();
#endif

    rl_clear_message();

    char* prev_buffer = get_previous_command();
    if (!prev_buffer)
    {
        rl_ding();
        return 0;
    }

    if (s_win_fn_input_buffer.empty())
        return 0;

    int old_point = 0;
    adjust_point_point(old_point, rl_point, prev_buffer);
    if (prev_buffer[old_point])
    {
        int end_point = old_point;
        int count = adjust_point_keyseq(end_point, s_win_fn_input_buffer.c_str(), prev_buffer);
        if (end_point > old_point)
        {
            // How much to delete.
            int del_point = rl_point;
            adjust_point_delta(del_point, count, rl_line_buffer);

            // What to insert.
            str<> more;
            more.concat(prev_buffer + old_point, end_point - old_point);

            rl_begin_undo_group();
            rl_delete_text(rl_point, del_point);
            rl_insert_text(more.c_str());
            rl_end_undo_group();
        }
    }

    return 0;
}

//------------------------------------------------------------------------------
#if defined (READLINE_CALLBACKS)
int _win_f2_callback(_rl_callback_generic_arg *data)
{
    if (!read_win_fn_input_char())
        return 0;

    /* Deregister function, let rl_callback_read_char deallocate data */
    _rl_callback_func = 0;
    _rl_want_redisplay = 1;

    return finish_win_f2();
}
#endif

//------------------------------------------------------------------------------
static const char c_normal[] = "\001\x1b[m\002";
int win_f2(int count, int invoking_key)
{
    s_win_fn_input_buffer.clear();
    rl_message("\x01\x1b[%sm\x02(enter char to copy up to: )%s ", get_popup_colors(), c_normal);

#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_disable_tty_signals ();
#endif

#if defined (READLINE_CALLBACKS)
    if (RL_ISSTATE(RL_STATE_CALLBACK))
    {
        _rl_callback_data = _rl_callback_data_alloc(count);
        _rl_callback_func = _win_f2_callback;
        return 0;
    }
#endif

    while (!read_win_fn_input_char())
        ;

    return finish_win_f2();
}

//------------------------------------------------------------------------------
int win_f3(int count, int invoking_key)
{
    return win_f1(999999, invoking_key);
}

//------------------------------------------------------------------------------
static int finish_win_f4()
{
#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_restore_tty_signals();
#endif

    rl_clear_message();

    if (s_win_fn_input_buffer.empty())
        return 0;

    int end_point = rl_point;
    adjust_point_keyseq(end_point, s_win_fn_input_buffer.c_str(), rl_line_buffer);
    if (end_point > rl_point)
        rl_delete_text(rl_point, end_point);

    return 0;
}

//------------------------------------------------------------------------------
#if defined (READLINE_CALLBACKS)
int _win_f4_callback(_rl_callback_generic_arg *data)
{
    if (!read_win_fn_input_char())
        return 0;

    /* Deregister function, let rl_callback_read_char deallocate data */
    _rl_callback_func = 0;
    _rl_want_redisplay = 1;

    return finish_win_f4();
}
#endif

//------------------------------------------------------------------------------
int win_f4(int count, int invoking_key)
{
    s_win_fn_input_buffer.clear();
    rl_message("\x01\x1b[%sm\x02(enter char to delete up to: )%s ", get_popup_colors(), c_normal);

#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_disable_tty_signals ();
#endif

#if defined (READLINE_CALLBACKS)
    if (RL_ISSTATE(RL_STATE_CALLBACK))
    {
        _rl_callback_data = _rl_callback_data_alloc(count);
        _rl_callback_func = _win_f4_callback;
        return 0;
    }
#endif

    while (!read_win_fn_input_char())
        ;

    return finish_win_f4();
}

//------------------------------------------------------------------------------
int win_f6(int count, int invoking_key)
{
    rl_insert_text("\x1a");
    return 0;
}

//------------------------------------------------------------------------------
int win_f7(int count, int invoking_key)
{
    if (RL_ISSTATE(RL_STATE_MACRODEF) != 0)
    {
ding:
        rl_ding();
        return 0;
    }

    HIST_ENTRY** list = history_list();
    if (!list)
        goto ding;

    const char** history = static_cast<const char**>(calloc(history_length, sizeof(const char**)));
    if (!history)
        goto ding;

#define ding __cant_goto__must_free_local__

    for (int i = 0; i < history_length; i++)
    {
        const char* p = list[i]->line;
        assert(p);
        history[i] = p ? p : "";
    }

    const popup_results results = activate_history_text_list(history, history_length, min<int>(where_history(), history_length - 1), nullptr, true/*win_history*/);

    switch (results.m_result)
    {
    case popup_result::error:
        rl_ding();
        break;

    case popup_result::use:
    case popup_result::select:
        rl_maybe_save_line();
        rl_maybe_replace_line();
        history_set_pos(results.m_index);
        rl_replace_from_history(current_history(), 0);
        if (results.m_result == popup_result::use)
            rl_newline(1, 0);
        break;
    }

    free(history);

    return 0;

#undef ding
}

//------------------------------------------------------------------------------
static int s_history_number = -1;
static int finish_win_f9()
{
#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_restore_tty_signals();
#endif

    rl_clear_message();

    if (s_history_number >= 0)
    {
        if (s_history_number >= history_length)
            s_history_number = history_length - 1;
        if (history_length > 0)
        {
            rl_begin_undo_group();
            rl_delete_text(0, rl_end);
            rl_point = 0;
            rl_insert_text(get_history(s_history_number));
            rl_end_undo_group();
        }
    }

    return 0;
}

//------------------------------------------------------------------------------
static void set_f9_message()
{
    if (s_history_number >= 0)
        rl_message("\x01\x1b[%sm\x02(enter history number: %d)%s ", get_popup_colors(), s_history_number, c_normal);
    else
        rl_message("\x01\x1b[%sm\x02(enter history number: )%s ", get_popup_colors(), c_normal);
}

//------------------------------------------------------------------------------
static bool read_history_digit()
{
    int c;

    RL_SETSTATE(RL_STATE_MOREINPUT);
    c = rl_read_key();
    RL_UNSETSTATE(RL_STATE_MOREINPUT);

    if (c < 0)
        return false;

    if (RL_ISSTATE(RL_STATE_MACRODEF))
        _rl_add_macro_char(c);

#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_restore_tty_signals ();
#endif

    if (c >= '0' && c <= '9')
    {
        if (s_history_number < 0)
            s_history_number = 0;
        if (s_history_number <= 99999)
        {
            s_history_number *= 10;
            s_history_number += c - '0';
        }
    }
    else if (c == 27/*Esc*/ || c == 7/*^G*/)
    {
        s_history_number = -1;
        return true;
    }
    else if (c == 13/*Enter*/)
    {
        return true;
    }
    else if (c == 8/*Backspace*/)
    {
        s_history_number /= 10;
        if (s_history_number == 0)
            s_history_number = -1;
    }

    set_f9_message();
    return false;
}

//------------------------------------------------------------------------------
#if defined (READLINE_CALLBACKS)
int _win_f9_callback(_rl_callback_generic_arg *data)
{
    if (!read_history_digit())
        return 0;

    /* Deregister function, let rl_callback_read_char deallocate data */
    _rl_callback_func = 0;
    _rl_want_redisplay = 1;

    return finish_win_f9();
}
#endif

//------------------------------------------------------------------------------
int win_f9(int count, int invoking_key)
{
    s_history_number = -1;
    set_f9_message();

#if defined (HANDLE_SIGNALS)
    if (RL_ISSTATE(RL_STATE_CALLBACK) == 0)
        _rl_disable_tty_signals ();
#endif

#if defined (READLINE_CALLBACKS)
    if (RL_ISSTATE(RL_STATE_CALLBACK))
    {
        _rl_callback_data = _rl_callback_data_alloc(count);
        _rl_callback_func = _win_f9_callback;
        return 0;
    }
#endif

    while (!read_history_digit())
        ;

    return finish_win_f9();
}

//------------------------------------------------------------------------------
bool win_fn_callback_pending()
{
    return (_rl_callback_func == _win_f2_callback ||
            _rl_callback_func == _win_f4_callback ||
            _rl_callback_func == _win_f9_callback);
}



//------------------------------------------------------------------------------
static bool s_globbing_wild = false;
static bool s_literal_wild = false;
bool is_globbing_wild() { return s_globbing_wild; }
bool is_literal_wild() { return s_literal_wild; }

//------------------------------------------------------------------------------
static int glob_completion_internal(int what_to_do)
{
    s_globbing_wild = true;
    if (!rl_explicit_arg)
        s_literal_wild = true;

    return rl_complete_internal(what_to_do);
}

//------------------------------------------------------------------------------
int glob_complete_word(int count, int invoking_key)
{
    if (rl_editing_mode == emacs_mode)
        rl_explicit_arg = 1; /* force `*' append */

    return glob_completion_internal(rl_completion_mode(glob_complete_word));
}

//------------------------------------------------------------------------------
int glob_expand_word(int count, int invoking_key)
{
    return glob_completion_internal('*');
}

//------------------------------------------------------------------------------
int glob_list_expansions(int count, int invoking_key)
{
    return glob_completion_internal('?');
}



//------------------------------------------------------------------------------
int edit_and_execute_command(int count, int invoking_key)
{
    str<> line;
    if (rl_explicit_arg)
    {
        HIST_ENTRY* h = history_get(count);
        if (!h)
        {
            rl_ding();
            return 0;
        }
        line = h->line;
    }
    else
    {
        line.concat(rl_line_buffer, rl_end);
        if (!host_add_history(0, line.c_str()))
        {
            rl_ding();
            return 0;
        }
    }

    str_moveable tmp_file;
    FILE* file = os::create_temp_file(&tmp_file);
    if (!file)
    {
LDing:
        rl_ding();
        return 0;
    }

    if (fputs(line.c_str(), file) < 0)
    {
        fclose(file);
LUnlinkFile:
        unlink(tmp_file.c_str());
        goto LDing;
    }
    fclose(file);
    file = nullptr;

    // Save and reset console state.
    HANDLE std_handles[2] = { GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE) };
    DWORD prev_mode[2];
    static_assert(_countof(std_handles) == _countof(prev_mode), "array sizes must match");
    for (size_t i = 0; i < _countof(std_handles); ++i)
        GetConsoleMode(std_handles[i], &prev_mode[i]);
    SetConsoleMode(std_handles[0], (prev_mode[0] | ENABLE_PROCESSED_INPUT) & ~(ENABLE_WINDOW_INPUT|ENABLE_MOUSE_INPUT));
    bool was_visible = show_cursor(true);
    rl_clear_signals();

    // Build editor command.
    str<> editor;
    str_moveable command;
    const char* const qs = (strpbrk(tmp_file.c_str(), rl_filename_quote_characters)) ? "\"" : "";
    if ((!os::get_env("VISUAL", editor) && !os::get_env("EDITOR", editor)) || editor.empty())
        editor = "%systemroot%\\system32\\notepad.exe";
    command.format("%s %s%s%s", editor.c_str(), qs, tmp_file.c_str(), qs);

    // Execute editor command.
    wstr_moveable wcommand(command.c_str());
    const int exit_code = _wsystem(wcommand.c_str());

    // Restore console state.
    show_cursor(was_visible);
    for (size_t i = 0; i < _countof(std_handles); ++i)
        SetConsoleMode(std_handles[i], prev_mode[i]);
    rl_set_signals();

    // Was the editor launched successfully?
    if (exit_code < 0)
        goto LUnlinkFile;

    // Read command(s) from temp file.
    line.clear();
    wstr_moveable wtmp_file(tmp_file.c_str());
    file = _wfopen(wtmp_file.c_str(), L"rt");
    if (!file)
        goto LUnlinkFile;
    char buffer[4096];
    while (true)
    {
        const int len = fread(buffer, 1, sizeof(buffer), file);
        if (len <= 0)
            break;
        line.concat(buffer, len);
    }
    fclose(file);

    // Trim trailing newlines to avoid redundant blank commands.  Ensure a final
    // newline so all lines get executed (otherwise it will go into edit mode).
    while (line.length() && line.c_str()[line.length() - 1] == '\n')
        line.truncate(line.length() - 1);
    line.concat("\n");

    // Split into multiple lines.
    std::list<str_moveable> overflow;
    strip_crlf(line.data(), overflow, paste_crlf_crlf, nullptr);
    strip_wakeup_chars(line);

    // Replace the input line with the content from the temp file.
    g_rl_buffer->begin_undo_group();
    g_rl_buffer->remove(0, rl_end);
    rl_point = 0;
    if (!line.empty())
        g_rl_buffer->insert(line.c_str());
    g_rl_buffer->end_undo_group();

    // Queue any additional lines.
    host_cmd_enqueue_lines(overflow, false, true);

    // Accept the input and execute it.
    (*rl_redisplay_function)();
    rl_newline(1, invoking_key);

    return 0;
}

//------------------------------------------------------------------------------
int magic_space(int count, int invoking_key)
{
    str<> in;
    str<> out;

    in.concat(g_rl_buffer->get_buffer(), g_rl_buffer->get_cursor());
    if (expand_history(in.c_str(), out))
    {
        g_rl_buffer->begin_undo_group();
        g_rl_buffer->remove(0, rl_point);
        rl_point = 0;
        if (!out.empty())
            g_rl_buffer->insert(out.c_str());
        g_rl_buffer->end_undo_group();
    }

    rl_insert(1, ' ');
    return 0;
}



//------------------------------------------------------------------------------
static void list_ambiguous_codepoints(const char* tag, const std::vector<char32_t>& chars)
{
    str<> s;
    str<> hex;
    bool first = true;

    s << "  " << tag << ":\n        ";
    for (char32_t c : chars)
    {
        if (first)
            first = false;
        else
            s << ", ";
        hex.format("\x1b[1;31;40m0x%X\x1b[m", c);
        s.concat(hex.c_str(), hex.length());
    }
    s << "\n";

    g_printer->print(s.c_str(), s.length());
}

//------------------------------------------------------------------------------
static void analyze_char_widths(const char* s,
                                std::vector<char32_t>& cjk,
                                std::vector<char32_t>& emoji,
                                std::vector<char32_t>& qualified)
{
    if (!s)
        return;

    bool ignoring = false;
    str_iter iter(s);
    while (int c = iter.next())
    {
        if (c == RL_PROMPT_START_IGNORE && !ignoring)
            ignoring = true;
        else if (c == RL_PROMPT_END_IGNORE && ignoring)
            ignoring = false;
        else if (!ignoring)
        {
            const int kind = test_ambiguous_width_char(c);
            switch (kind)
            {
            case 1: cjk.push_back(c); break;
            case 2: emoji.push_back(c); break;
            case 3: qualified.push_back(c); break;
            }
        }
    }
}

//------------------------------------------------------------------------------
int clink_diagnostics(int count, int invoking_key)
{
    end_prompt(true/*crlf*/);

    static char bold[] = "\x1b[1m";
    static char norm[] = "\x1b[m";
    static char lf[] = "\n";

    str<> s;
    const int spacing = 12;

    int id = 0;
    str<> binaries;
    str<> profile;
    str<> scripts;
    host_get_app_context(id, binaries, profile, scripts);

    // Version and binaries dir.

    s.clear();
    s << bold << "version:" << norm << lf;
    g_printer->print(s.c_str(), s.length());

    printf("  %-*s  %s\n", spacing, "version", CLINK_VERSION_STR);

    s.clear();
    s.format("  %-*s  %s\n", spacing, "binaries", binaries.c_str());
    g_printer->print(s.c_str(), s.length());

    if (rl_explicit_arg)
    {
        s.clear();
        s.format("  %-*s  %s\n", spacing, "architecture", AS_STR(ARCHITECTURE_NAME));
        g_printer->print(s.c_str(), s.length());
    }

    // Session info.

    s.clear();
    s << bold << "session:" << norm << lf;
    g_printer->print(s.c_str(), s.length());

    printf("  %-*s  %d\n", spacing, "session", id);

    s.clear();
    s.format("  %-*s  %s\n", spacing, "profile", profile.c_str());
    g_printer->print(s.c_str(), s.length());

    if (scripts.length())
    {
        s.clear();
        s.format("  %-*s  %s\n", spacing, "scripts", scripts.c_str());
        g_printer->print(s.c_str(), s.length());
    }

    // Terminal info.

    if (rl_explicit_arg)
    {
        s.clear();
        s << bold << "terminal:" << norm << lf;
        g_printer->print(s.c_str(), s.length());

        const char* term = nullptr;
        switch (get_current_ansi_handler())
        {
        default:                            term = "Unknown"; break;
        case ansi_handler::clink:           term = "Clink terminal emulation"; break;
        case ansi_handler::conemu:          term = "ConEmu"; break;
        case ansi_handler::ansicon:         term = "ANSICON"; break;
        case ansi_handler::winterminal:     term = "Windows Terminal"; break;
        case ansi_handler::wezterm:         term = "WezTerm"; break;
        case ansi_handler::winconsolev2:    term = "Console V2 (with 24 bit color)"; break;
        case ansi_handler::winconsole:      term = "Default console (16 bit color only)"; break;
        }
        s.clear();
        s.format("  %-*s  %s\n", spacing, "terminal", term);
        g_printer->print(s.c_str(), s.length());
    }

    host_call_lua_rl_global_function("clink._diagnostics");

    // Check for known potential ambiguous character width issues.

    {
        const char* prompt = strrchr(rl_display_prompt, '\n');
        if (!prompt)
            prompt = rl_display_prompt;
        else
            prompt++;

        std::vector<char32_t> cjk;
        std::vector<char32_t> emoji;
        std::vector<char32_t> qualified;

        analyze_char_widths(prompt, cjk, emoji, qualified);
        analyze_char_widths(rl_rprompt, cjk, emoji, qualified);

        if (cjk.size() || emoji.size() || qualified.size())
        {
            s.clear();
            s << bold << "ambiguous width characters in prompt:" << norm << lf;
            g_printer->print(s.c_str(), s.length());

            if (cjk.size())
            {
                list_ambiguous_codepoints("CJK ambiguous characters", cjk);
                puts("    Running 'chcp 65001' can often fix width problems with these.\n"
                     "    Or you can use a different character.");
            }

            if (emoji.size())
            {
                list_ambiguous_codepoints("color emoji", emoji);
                puts("    To fix problems with these, try using a different symbol or a different\n"
                     "    terminal program.  Or sometimes using a different font can help.");
            }

            if (qualified.size())
            {
                list_ambiguous_codepoints("qualified emoji", qualified);
                puts("    To fix problems with these, try using a different symbol or a different\n"
                     "    terminal program.  Or sometimes using a different font can help.");
                puts("    The fully-qualified forms of these symbols often encounter problems,\n"
                     "    but the unqualified forms often work.  For a table of emoji and their\n"
                     "    forms see https://www.unicode.org/Public/emoji/15.0/emoji-test.txt");
            }
        }
    }

    extern void task_manager_diagnostics();
    task_manager_diagnostics();

    if (!rl_explicit_arg)
        g_printer->print("\n(Use a numeric argument for additional diagnostics; e.g. press Alt+1 first.)\n");

    rl_forced_update_display();
    return 0;
}



//------------------------------------------------------------------------------
int macro_hook_func(const char* macro)
{
    bool is_luafunc = (macro && strnicmp(macro, "luafunc:", 8) == 0);

    if (is_luafunc)
    {
        str<> func_name;
        func_name = macro + 8;
        func_name.trim();

        // TODO: Ideally optimize this so that it only resets match generation if
        // the Lua function triggers completion.
        extern void reset_generate_matches();
        reset_generate_matches();

        HANDLE std_handles[2] = { GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE) };
        DWORD prev_mode[2];
        static_assert(_countof(std_handles) == _countof(prev_mode), "array sizes must match");
        for (size_t i = 0; i < _countof(std_handles); ++i)
            GetConsoleMode(std_handles[i], &prev_mode[i]);

        if (!host_call_lua_rl_global_function(func_name.c_str()))
            rl_ding();

        for (size_t i = 0; i < _countof(std_handles); ++i)
            SetConsoleMode(std_handles[i], prev_mode[i]);
    }

    cua_after_command(!is_luafunc/*force_clear*/);

    return is_luafunc;
}

//------------------------------------------------------------------------------
void reset_command_states()
{
    s_globbing_wild = false;
    s_literal_wild = false;
}

//------------------------------------------------------------------------------
bool is_force_reload_scripts()
{
    return s_force_reload_scripts;
}

//------------------------------------------------------------------------------
void clear_force_reload_scripts()
{
    s_force_reload_scripts = false;
}

//------------------------------------------------------------------------------
int force_reload_scripts()
{
    s_force_reload_scripts = true;
    if (g_result)
        g_result->done(true); // Force a new edit line so scripts can be reloaded.
    readline_internal_teardown(true);
    return rl_re_read_init_file(0, 0);
}
