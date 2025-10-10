import secrets
import ida_hexrays
import ida_typeinf
import idc, idaapi
from typing import Optional, Tuple


def get_interface_type(is_ptr):
    interface_type = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(interface_type, idaapi.get_idati(), "interface_ x;", ida_typeinf.PT_TYP)
    if is_ptr:
        interface_type.create_ptr(interface_type)
    return interface_type


class type_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, mapping):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.mapping = mapping

    def modify_lvars(self, lvars):
        for lvar in lvars.lvvec:
            if lvar.name in self.mapping:
                lvar.type = self.mapping[lvar.name]
        return True

class cvisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, yap=True):
        super().__init__(ida_hexrays.CV_FAST)
        self.vars = {}
        self.interface_vars = {}
        self.to_undefine = {}
        self.yap = yap

    def get_concrete(self, expr: ida_hexrays.cexpr_t) -> Optional[int]:
        if expr.op == ida_hexrays.cot_num:
            return expr.numval()
        elif expr.op == ida_hexrays.cot_obj:
            return expr.obj_ea
        elif expr.op in [ida_hexrays.cot_ref, ida_hexrays.cot_cast]:
            return self.get_concrete(expr.x)
        return None

    def find_var(self, expr: ida_hexrays.cexpr_t, refcount: int = 0, require_undefine:bool=False) -> Tuple[ida_hexrays.cexpr_t, int, bool]:
        if expr.op == ida_hexrays.cot_var:
            return expr, refcount, require_undefine
        if expr.op in [ida_hexrays.cot_ref]:
            inner, inner_refcount, require_undefine = self.find_var(expr.x, refcount, require_undefine)
            return inner or expr.x, inner_refcount + 1, require_undefine
        if expr.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_ptr]:
            inner, inner_refcount, require_undefine = self.find_var(expr.x, refcount, require_undefine)
            return inner or expr.x, inner_refcount - 1, require_undefine
        if expr.op in [ida_hexrays.cot_cast, ida_hexrays.cot_memref]:
            return self.find_var(expr.x, refcount, require_undefine)
        if expr.op == ida_hexrays.cot_idx:
            # Break down array
            return self.find_var(expr.x, refcount, True)
        return expr, refcount, require_undefine
        
    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        if expr.op == ida_hexrays.cot_asg:
            addr = self.get_concrete(expr.y)
            if addr is None:
                return 0
            name = idaapi.get_ea_name(addr)
            if not name.startswith("RTYPE"):
                return 0
            var = expr.x
            var, refcount, require_undefine = self.find_var(var)
            if var.op != ida_hexrays.cot_var:
                self.yap and print("Not a variable:", var.dstr())
                return 0
            self.yap and print(var.dstr(), "->", name, "refcount:", refcount, "require_undefine:", require_undefine)
            var_type: ida_typeinf.tinfo_t = var.type
            is_ptr = refcount < 0
            if require_undefine and var_type.is_array():
                self.to_undefine[var.dstr()] = var_type.get_array_element()
            elif var_type != get_interface_type(is_ptr):
                self.vars[var.dstr()] = (name, is_ptr)
            else:
                self.interface_vars[var.dstr()] = (name, is_ptr)

        return 0

def apply_interface_detector(func, yap=True):
    prev = []
    skip = []
    for i in range(100):
        # Failed to set type more than 5 times in a row, give up
        if len(prev) > 5:
            prev = prev[-5:]
            if len(set(prev)) == 1:
                skip += [prev[0]]
                yap and print("Skipping", prev[0])
        yap and print("Iteration", i)
        c = cvisitor(yap)
        c.apply_to(func.body, None)
        type_modifications = {}
        var_names = []
        yap and print(c.vars)
        mod = secrets.token_hex(4)
        if c.to_undefine:
            for var_name, var_type in c.to_undefine.items():
                if var_name in skip:
                    continue
                type_modifications[var_name + mod] = var_type
                var_names.append(var_name)
                break
        else:
            for var_name, (type_name, is_ptr) in c.vars.items():
                if var_name in skip:
                    continue
                type_modifications[var_name + mod] = get_interface_type(is_ptr)
                var_names.append(var_name)
                break

        if not var_names:
            yap and print("Done")
            return c.interface_vars

        func_ea = func.entry_ea
        assert len(var_names) == 1 and len(type_modifications) == 1, f"Expected exactly one var to modify, got {var_names}"
        var_name = var_names[0]
        ida_hexrays.rename_lvar(func_ea, var_name, var_name + mod)
        ida_hexrays.modify_user_lvars(func_ea, type_modifier_t(type_modifications))
        ida_hexrays.rename_lvar(func_ea, var_name + mod, var_name)
        func = ida_hexrays.decompile(func_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        prev += [var_name]

def main():
    func = ida_hexrays.decompile(idc.here(), flags=ida_hexrays.DECOMP_NO_CACHE)
    apply_interface_detector(func)

if __name__ == "__main__":
    main()