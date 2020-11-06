// Copyright (c) 2012 Martin Ridgers
// License: http://opensource.org/licenses/MIT

#pragma once

//------------------------------------------------------------------------------
class hook_setter
{
public:
                                hook_setter();
                                ~hook_setter();

    // WARNING:  detach() currently doesn't support detaching the local IAT!

    bool                        attach(const char* module, PVOID* real, const char* name, PVOID hook, bool repair_iat=false);
    bool                        detach(PVOID* real, const char* name, PVOID hook);
    bool                        commit();

private:
    void                        free_repair_list();

private:
    struct repair_node
    {
        repair_node* m_next;
        PVOID m_iat;
        PVOID m_trampoline;
        const char* m_name;
    };

    repair_node*                m_repair_iat;

    bool                        m_pending;
};
