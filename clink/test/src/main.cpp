// Copyright (c) 2015 Martin Ridgers
// License: http://opensource.org/licenses/MIT

#include "pch.h"

#include "core/str.h"
#include "core/settings.h"
#include "core/os.h"

extern "C" {
#include <readline/readline.h>
#include <readline/rldefs.h>
#include <readline/rlprivate.h>
}

#include <list>
#include <assert.h>

//------------------------------------------------------------------------------
extern bool g_force_load_debugger;

//------------------------------------------------------------------------------
#ifdef DEBUG
bool g_suppress_signal_assert = false;
#endif

//------------------------------------------------------------------------------
void host_cmd_enqueue_lines(std::list<str_moveable>& lines, bool hide_prompt, bool show_line)
{
    assert(false);
}

//------------------------------------------------------------------------------
void host_cleanup_after_signal()
{
}

//------------------------------------------------------------------------------
void host_mark_deprecated_argmatcher(const char* command)
{
}

//------------------------------------------------------------------------------
bool host_has_deprecated_argmatcher(const char* command)
{
    return false;
}

//------------------------------------------------------------------------------
void start_logger()
{
    assert(false);
}

//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    argc--, argv++;

    bool timer = false;

#ifdef DEBUG
    settings::TEST_set_ever_loaded();
#endif

    os::set_shellname(L"clink_test_harness");

    _rl_bell_preference = VISIBLE_BELL;     // Because audible is annoying.
    _rl_optimize_typeahead = false;         // Because not compatible with READLINE_CALLBACKS.

    while (argc > 0)
    {
        if (!strcmp(argv[0], "-?") || !strcmp(argv[0], "--help"))
        {
            puts("Options:\n"
                 "  -?        Show this help.\n"
                 "  -d        Load Lua debugger.\n"
                 "  -t        Show execution time.");
            return 1;
        }
        else if (!strcmp(argv[0], "-d"))
        {
            g_force_load_debugger = true;
        }
        else if (!strcmp(argv[0], "-t"))
        {
            timer = true;
        }
        else if (!strcmp(argv[0], "--"))
        {
        }
        else
        {
            break;
        }

        argc--, argv++;
    }

    DWORD start = GetTickCount();

    clatch::colors::initialize();

    const char* prefix = (argc > 0) ? argv[0] : "";
    int result = (clatch::run(prefix) != true);

    extern void shutdown_recognizer();
    shutdown_recognizer();

    extern void shutdown_task_manager();
    shutdown_task_manager();

    if (timer)
    {
        DWORD elapsed = GetTickCount() - start;
        printf("\nElapsed time %u.%03u seconds.\n", elapsed / 1000, elapsed % 1000);
    }

    return result;
}
