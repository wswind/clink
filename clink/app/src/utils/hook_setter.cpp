// Copyright (c) 2012 Martin Ridgers
// License: http://opensource.org/licenses/MIT

#include "pch.h"
#include "hook_setter.h"

#include <core/base.h>
#include <core/log.h>
#include <process/hook.h>
#include <process/pe.h>
#include <process/vm.h>
#include <detours.h>

//------------------------------------------------------------------------------
hook_setter::hook_setter()
{
    m_repair_iat = nullptr;

    LONG err = DetourTransactionBegin();
    m_pending = (err == NOERROR);

    if (m_pending)
        LOG("Started hook transaction.");
    else
        LOG("Unable to start hook transaction (error %u).", err);
}

//------------------------------------------------------------------------------
hook_setter::~hook_setter()
{
    if (m_pending)
        DetourTransactionAbort();
    free_repair_list();
}

//------------------------------------------------------------------------------
void* follow_jump(void* addr);
bool hook_setter::attach(const char* module, PVOID* real, const char* name, PVOID detour, bool repair_iat)
{
    PVOID proc = *real;
    PVOID iat = proc;

    if (module)
    {
        LOG("Attempting to hook %s in %s with %p; local IAT at %p.", name, module, detour, iat);
        proc = DetourFindFunction(module, name);
        if (!proc)
        {
            LOG("Unable to find %s in %s.", name, module);
            return false;
        }
    }
    else
    {
        LOG("Attempting to hook %s with %p; local IAT at %p.", name, detour, iat);
    }

    // Get the target pointer to hook.
    PVOID replace = follow_jump(proc);
    if (!replace)
    {
        LOG("Unable to get target address.");
        return false;
    }

    // If iat and replace are the same, then iat isn't really an IAT address and
    // must not be repaired, since attempting to repair it would cancel out the
    // original hook operation.
    if (iat == replace)
    {
        LOG("Skipping request to repair own IAT; there doesn't seem to be an IAT entry at %p.", iat);
        repair_iat = false;
    }

    // Hook the target pointer.
    PDETOUR_TRAMPOLINE trampoline;
    LONG err = DetourAttachEx(&replace, detour, &trampoline, nullptr, nullptr);
    if (err != NOERROR)
    {
        LOG("Unable to hook %s (error %u).", name, err);
        return false;
    }

    // Hook our IAT back to the original.
    if (repair_iat)
    {
        repair_node *r = new repair_node;
        r->m_iat = iat;
        r->m_trampoline = trampoline;
        r->m_name = name;
        r->m_next = m_repair_iat;
        m_repair_iat = r;
    }

    *real = trampoline;
    return true;
}

//------------------------------------------------------------------------------
bool hook_setter::detach(PVOID* real, const char* name, PVOID detour)
{
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
    LONG err = DetourTransactionCommit();
    m_pending = false;

    if (err != NOERROR)
    {
        LOG("Unable to commit hooks (error %u).", err);
        return false;
    }

    bool success = true;
    if (m_repair_iat)
    {
        err = DetourTransactionBegin();
        if (err != NOERROR)
        {
            LOG("Unable to begin IAT repair transaction (error %u).", err);
            return false;
        }

        while (m_repair_iat)
        {
            repair_node* r = m_repair_iat;
            m_repair_iat = m_repair_iat->m_next;

            err = DetourAttach(&r->m_iat, r->m_trampoline);
            if (err != NOERROR)
            {
                LOG("Unable to repair IAT for %s to %p (error %u).", r->m_name, r->m_trampoline, err);
                success = false;
            }

            delete r;
        }

        if (success)
        {
            err = DetourTransactionCommit();
            if (err != NOERROR)
            {
                LOG("Unable to commit IAT repair hooks (error %u).", err);
                success = false;
            }
        }
    }

    if (success)
        LOG("Hook transaction committed.");
    return success;
}

//------------------------------------------------------------------------------
void hook_setter::free_repair_list()
{
    while (m_repair_iat)
    {
        repair_node* d = m_repair_iat;
        m_repair_iat = m_repair_iat->m_next;
        delete d;
    }
}
