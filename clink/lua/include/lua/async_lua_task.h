// Copyright (c) 2022 Christopher Antos
// License: http://opensource.org/licenses/MIT

#include <core/str.h>

#include <memory>
#include <thread>

class lua_state;

//------------------------------------------------------------------------------
struct callback_ref
{
    callback_ref(int ref) : m_ref(ref) {}
    int m_ref;
};

//------------------------------------------------------------------------------
class async_lua_task
{
    friend class task_manager;

public:
                            async_lua_task(const char* key, const char* src, bool run_until_complete=false);
    virtual                 ~async_lua_task();

    const char*             key() const { return m_key.c_str(); }
    HANDLE                  get_wait_handle() const { return m_event; }
    bool                    is_complete() const { return m_is_complete; }
    bool                    is_canceled() const { return m_is_canceled; }

    void                    set_callback(const std::shared_ptr<callback_ref>& callback);
    void                    run_callback(lua_state& lua);
    void                    disable_callback();
    std::shared_ptr<callback_ref> take_callback();
    void                    cancel();

protected:
    virtual void            do_work() = 0;

private:
    void                    start();
    void                    detach();
    bool                    is_run_until_complete() const { return m_run_until_complete; }
    static void             proc(async_lua_task* task);

private:
    HANDLE                  m_event;
    std::unique_ptr<std::thread> m_thread;
    str_moveable            m_key;
    str_moveable            m_src;
    std::shared_ptr<callback_ref> m_callback_ref;
    const bool              m_run_until_complete = false;
    bool                    m_run_callback = false;
    bool                    m_is_complete = false;
    volatile bool           m_is_canceled = false;
};

//------------------------------------------------------------------------------
std::shared_ptr<async_lua_task> find_async_lua_task(const char* key);
bool add_async_lua_task(std::shared_ptr<async_lua_task>& task);
void task_manager_on_idle(lua_state& lua);
extern "C" void end_task_manager();
void shutdown_task_manager();
void task_manager_diagnostics();
