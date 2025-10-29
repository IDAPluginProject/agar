"""Utilities for modifying local variable types in IDA decompiled functions."""

import secrets
import ida_hexrays
import ida_typeinf


class local_var_type_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, mapping):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.mapping = mapping

    def modify_lvars(self, lvars):
        for lvar in lvars.lvvec:
            if lvar.name in self.mapping:
                lvar.type = self.mapping[lvar.name]
        return True


def replace_local_var_type(cfunc: ida_hexrays.cfunc_t, name: str, new_type: ida_typeinf.tinfo_t):
    """Replace the type of a local variable in a decompiled function."""
    mod = secrets.token_hex(4)
    ida_hexrays.rename_lvar(cfunc.entry_ea, name, f"{name}_{mod}")
    modifier = local_var_type_modifier_t({f"{name}_{mod}": new_type})
    ida_hexrays.modify_user_lvars(cfunc.entry_ea, modifier)
    ida_hexrays.rename_lvar(cfunc.entry_ea, f"{name}_{mod}", name)
