// Copyright (c) 2012 Martin Ridgers
// License: http://opensource.org/licenses/MIT

#pragma once

struct repair_iat_node;

//------------------------------------------------------------------------------
class hook_setter
{
public:
                                hook_setter();
                                ~hook_setter();

    // WARNING:  detach() isn't able to restore the IAT yet; DO NOT USE if
    // attach() passed true for repair_iat!  Because of this safety restriction
    // repair_iat defaults to false.

    bool                        attach(const char* module, PVOID* real, const char* name, PVOID hook, bool repair_iat=false);
    bool                        detach(PVOID* real, const char* name, PVOID hook);
    bool                        commit();

private:
    void                        free_repair_list();

private:
    PVOID                       m_self = nullptr;
    bool                        m_pending = false;
    repair_iat_node*            m_repair_iat = nullptr;
};
