// Copyright (c) 2016 Martin Ridgers
// License: http://opensource.org/licenses/MIT

#pragma once

#include "bind_resolver.h"
#include "binder.h"
#include "editor_module.h"
#include "input_dispatcher.h"
#include "terminal/input_idle.h"
#include "terminal/key_tester.h"
#include "pager_impl.h"
#include "selectcomplete_impl.h"
#include "textlist_impl.h"
#include "line_editor.h"
#include "line_state.h"
#include "matches_impl.h"
#include "word_classifier.h"
#include "word_classifications.h"
#include "word_collector.h"
#include "rl/rl_module.h"
#include "rl/rl_buffer.h"

#include <core/array.h>
#include <core/str.h>
#include <terminal/printer.h>

enum class reclassify_reason : unsigned char;

//------------------------------------------------------------------------------
class prev_buffer
{
public:
                    ~prev_buffer() { free(m_ptr); }
    void            clear() { free(m_ptr); m_ptr = nullptr; m_len = 0; }
    bool            equals(const char* s, int len) const;
    void            set(const char* s, int len);
    const char*     get() const { return m_ptr; }
    unsigned int    length() const { return m_len; }

private:
    char*           m_ptr = nullptr;
    unsigned int    m_len = 0;
};

//------------------------------------------------------------------------------
class line_editor_impl
    : public line_editor
    , public input_dispatcher
    , public key_tester
{
public:
                        line_editor_impl(const desc& desc);

    // line_editor
    virtual bool        add_module(editor_module& module) override;
    virtual void        set_generator(match_generator& generator) override;
    virtual void        set_classifier(word_classifier& classifier) override;
    virtual void        set_input_idle(input_idle* idle) override;
    virtual void        set_prompt(const char* prompt, const char* rprompt, bool redisplay) override;
    virtual bool        get_line(str_base& out) override;
    virtual bool        edit(str_base& out, bool edit=true) override;
    virtual void        override_line(const char* line, const char* needle, int point) override;
    virtual bool        update() override;
    virtual void        update_matches() override;
#ifdef DEBUG
    virtual bool        is_line_overridden() override;
#endif

    // input_dispatcher
    virtual void        dispatch(int bind_group) override;

    // key_tester
    virtual bool        is_bound(const char* seq, int len) override;
    virtual bool        accepts_mouse_input(mouse_input_type type) override;
    virtual bool        translate(const char* seq, int len, str_base& out) override;
    virtual void        set_keyseq_len(int len) override;

    void                reset_generate_matches();
    void                reclassify(reclassify_reason why);
    void                try_suggest();
    void                force_update_internal(bool restrict=false);
    bool                notify_matches_ready(int generation_id, matches* matches);
    bool                call_lua_rl_global_function(const char* func_name);

private:
    typedef editor_module                       module;
    typedef fixed_array<editor_module*, 16>     modules;
    typedef std::vector<word>                   words;
    friend void update_matches();
    friend matches* get_mutable_matches(bool nosort);
    friend matches* maybe_regenerate_matches(const char* needle, display_filter_flags flags);
    friend bool is_regen_blocked();

    enum flags : unsigned char
    {
        flag_init           = 1 << 0,
        flag_editing        = 1 << 1,
        flag_generate       = 1 << 2,
        flag_restrict       = 1 << 3,
        flag_select         = 1 << 4,
        flag_done           = 1 << 5,
        flag_eof            = 1 << 6,
    };

    struct key_t
    {
        void            reset() { memset(this, 0xff, sizeof(*this)); }
        unsigned int    word_index : 16;
        unsigned int    word_offset : 16;
        unsigned int    word_length : 16;
        unsigned int    cursor_pos : 16;
    };

    void                initialise();
    void                begin_line();
    void                end_line();
    void                collect_words();
    commands            collect_commands();
    unsigned int        collect_words(words& words, matches_impl* matches, collect_words_mode mode, commands& commands);
    void                classify();
    void                maybe_send_oncommand_event();
    matches*            get_mutable_matches(bool nosort=false);
    void                update_internal();
    bool                update_input();
    module::context     get_context() const;
    line_state          get_linestate() const;
    void                set_flag(unsigned char flag);
    void                clear_flag(unsigned char flag);
    bool                check_flag(unsigned char flag) const;

    static bool         is_key_same(const key_t& prev_key, const char* prev_line, int prev_length,
                                    const key_t& next_key, const char* next_line, int next_length,
                                    bool compare_cursor);
    static void         before_display();

    desc                m_desc;
    rl_module           m_module;
    rl_buffer           m_buffer;
    word_collector      m_collector;
    modules             m_modules;
    match_generator*    m_generator = nullptr;
    word_classifier*    m_classifier = nullptr;
    input_idle*         m_idle = nullptr;
    binder              m_binder;
    bind_resolver       m_bind_resolver = { m_binder };
    word_classifications m_classifications;
    matches_impl        m_regen_matches;
    matches_impl        m_matches;
    printer&            m_printer;
    pager_impl          m_pager;
    selectcomplete_impl m_selectcomplete;
    textlist_impl       m_textlist;
    key_t               m_prev_key;
    unsigned char       m_flags = 0;
    int                 m_generation_id = 0;
    str<64>             m_needle;

    prev_buffer         m_prev_generate;
    words               m_words;
    unsigned short      m_command_offset = 0;
    commands            m_commands;

    prev_buffer         m_prev_classify;
    words               m_classify_words;

    str<16>             m_prev_command_word;
    unsigned int        m_prev_command_word_offset;
    bool                m_prev_command_word_quoted;

    const char*         m_override_needle = nullptr;
    words               m_override_words;
    commands            m_override_commands;

#ifdef DEBUG
    bool                m_in_matches_ready = false;
#endif

    const char*         m_insert_on_begin = nullptr;

    // State for dispatch().
    unsigned char       m_dispatching = 0;
    bool                m_invalid_dispatch;
    bind_resolver::binding* m_pending_binding = nullptr;
};
