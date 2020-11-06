// Copyright (c) 2012 Martin Ridgers
// License: http://opensource.org/licenses/MIT

#include "pch.h"
#include "hook_setter.h"

#include <core/base.h>
#include <core/log.h>
#include <process/hook.h>
#include <process/vm.h>
#include <detours.h>

//------------------------------------------------------------------------------
hook_setter::hook_setter()
{
    LONG err = NOERROR;

    // In order to repair out IAT, we need the base address of our module.
    if (!err)
    {
        m_self = vm().get_alloc_base("clink");
        if (m_self == nullptr)
            err = GetLastError();
    }

    // Start a detour transaction.
    if (!err)
        err = DetourTransactionBegin();

    if (err)
    {
        LOG("Unable to start hook transaction (error %u).", err);
        return;
    }

    LOG(">>> Started hook transaction.");
    m_pending = true;
}

//------------------------------------------------------------------------------
hook_setter::~hook_setter()
{
    if (m_pending)
    {
        LOG("<<< Hook transaction aborted.");
        DetourTransactionAbort();
    }

    free_repair_iat_list(m_repair_iat);
}

//------------------------------------------------------------------------------
void* follow_jump(void* addr);
bool hook_setter::attach(const char* module, PVOID* real, const char* name, PVOID detour, bool repair_iat)
{
    PVOID proc = *real;

    if (module)
    {
        LOG("Attempting to hook %s in %s with %p.", name, module, detour);
        proc = DetourFindFunction(module, name);
        if (!proc)
        {
            LOG("Unable to find %s in %s.", name, module);
            return false;
        }
    }
    else
    {
        LOG("Attempting to hook %s with %p.", name, detour);
    }

    // Get the target pointer to hook.
    PVOID replace = follow_jump(proc);
    if (!replace)
    {
        LOG("Unable to get target address.");
        return false;
    }

    // Hook the target pointer.
    PDETOUR_TRAMPOLINE trampoline;
    LONG err = DetourAttachEx(&replace, detour, &trampoline, nullptr, nullptr);
    if (err != NOERROR)
    {
        LOG("Unable to hook %s (error %u).", name, err);
        return false;
    }

    // Hook our IAT back to the original if requested.
    if (repair_iat)
        add_repair_iat_node(m_repair_iat, m_self, module, name, hookptr_t(trampoline));

    *real = trampoline;
    return true;
}

//------------------------------------------------------------------------------
bool hook_setter::detach(PVOID* real, const char* name, PVOID detour)
{
    LOG("Attempting to restore %s at %p.", name, *real);

    LONG err = DetourDetach(real, detour);
    if (err != NOERROR)
    {
        LOG("Unable to unhook %s (error %u).", name, err);
        return false;
    }

    return true;
}

//------------------------------------------------------------------------------
bool hook_setter::commit()
{
    // TODO: suspend threads?  Currently this relies on CMD being essentially
    // single threaded.

    LONG err = DetourTransactionCommit();
    m_pending = false;

    if (err != NOERROR)
    {
        LOG("<<< Unable to commit hooks (error %u).", err);
        free_repair_iat_list(m_repair_iat);
        return false;
    }

    repair_iat_list(m_repair_iat);
    LOG("<<< Hook transaction committed.");

    // TODO: resume threads?  Currently this relies on CMD being essentially
    // single threaded.

    return true;
}
