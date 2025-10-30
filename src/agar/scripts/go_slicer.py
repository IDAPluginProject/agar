import ida_hexrays, ida_typeinf, idc, idaapi
from typing import Optional

import sys, os
sys.path = [os.path.dirname(os.path.dirname(__file__))] + sys.path

from lvar_utils import replace_local_var_type

class Ref:
    ea: int
    var_name: str
    value: Optional[int] = None

    def __init__(self, var_name, ea) -> None:
        self.var_name = var_name
        self.ea = ea
    
    def __hash__(self) -> int:
        return self.ea

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, Ref):
            return False
        return self.ea == __value.ea
    
class MemRef(Ref):
    parent: Ref
    expr: ida_hexrays.cexpr_t
    value: ida_hexrays.cexpr_t

    def __init__(self, parent: Ref, expr: ida_hexrays.cexpr_t, var_name: str) -> None:
        self.ea = expr.ea
        self.parent = parent
        self.expr = expr
        self.var_name = var_name

    def __str__(self):
        return f"{str(self.parent)}.{self.var_name}"
    
    def __repr__(self) -> str:
        val = self.value.dstr() if isinstance(self.value, ida_hexrays.cexpr_t) else self.value
        return str(self) + " = " + str(val) if self.value is not None else str(self)

class AsgRef(Ref):
    expr: ida_hexrays.cexpr_t
    multiplex: bool

    def __init__(self, var_name, ea: int, expr: ida_hexrays.cexpr_t) -> None:
        super().__init__(var_name, ea)
        self.expr = expr

    def __str__(self):
        return self.var_name
    
    def __repr__(self) -> str:
        return f"AsgRef({hex(self.ea)}: {self.expr.dstr()})"

class cvisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.refs = {}

    def add_ref(self, var_name, d):
        if var_name in self.refs:
            self.refs[var_name].append(d)
        else:
            self.refs[var_name] = [d]

    def get_concrete(self, expr: ida_hexrays.cexpr_t) -> Optional[int]:
        if expr.op == ida_hexrays.cot_num:
            return expr.numval()
        elif expr.op == ida_hexrays.cot_obj:
            return expr.obj_ea
        elif expr.op in [ida_hexrays.cot_ref, ida_hexrays.cot_cast]:
            return self.get_concrete(expr.x)
        elif expr.op == ida_hexrays.cot_idx:
            xtype: ida_typeinf.tinfo_t = expr.x.type
            if xtype is None:
                type_size = 1
            else:
                if xtype.is_ptr_or_array():
                    type_size = xtype.get_pointed_object().get_size()
                    if type_size == idaapi.BADADDR:
                        type_size = xtype.get_array_element().get_size()
                    if type_size == idaapi.BADADDR:
                        type_size = 1
                else:
                    type_size = xtype.get_size()
            type_size = max(1, type_size)
            base = self.get_concrete(expr.x)
            if not base:
                return base

            return base + expr.y.numval() * type_size
        return None

    def find_val(self, expr: ida_hexrays.cexpr_t):
        concrete = self.get_concrete(expr)
        if concrete is not None:
            return concrete
        return self.find_var(expr, True)
    
    def find_var(self, expr: ida_hexrays.cexpr_t, must_be_var = False) -> ida_hexrays.cexpr_t:
        if expr.op == ida_hexrays.cot_var:
            return expr
        elif expr.op in [ida_hexrays.cot_memref, ida_hexrays.cot_memptr, ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_cast]:
            if must_be_var:
                return self.find_var(expr.x, must_be_var=True)
            return self.find_var(expr.x) or expr
        return None
        
    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        if expr.op == ida_hexrays.cot_asg:
            if expr.x.op in [ida_hexrays.cot_memref, ida_hexrays.cot_ptr, ida_hexrays.cot_memptr]:
                mem_ref_expr = expr.x
                var_asg: ida_hexrays.cexpr_t = mem_ref_expr.x
                if var_asg.op == ida_hexrays.cot_var:
                    var_name = var_asg.dstr()
                    var_ref = AsgRef(var_name, var_asg.ea, var_asg)
                    var_type = var_asg.type
                    if var_type is None:
                        return 0
                    if not str(var_type).startswith("_slice"):
                        return 0
                    if not var_type.is_struct():
                        return 0
                    udt = ida_typeinf.udt_type_data_t()
                    var_type.get_udt_details(udt)

                    member_name = next(x.name for x in udt if (x.offset//8) == mem_ref_expr.m)
                    val = self.find_val(expr.y)
                    mem_ref = MemRef(var_ref, expr, member_name)
                    mem_ref.value = val
                    self.add_ref(var_name, mem_ref)
        return 0
    
def build_reftable(func):
    c = cvisitor()
    c.apply_to(func.body, None)
    return c.refs

def apply_slice_builder(func, yap=True):
    if func is None:
        return
    r = build_reftable(func)
    yap and print("References found:", len(r))
    yap and print(r)

    for var, refs in r.items():
        props = {}
        for ref in refs:
            if isinstance(ref, MemRef):
                if ref.value is not None:
                    props[ref.var_name.strip("_1234567890")] = ref
            if (ptr := (props.get("array") or props.get("ptr"))) and (length := props.get("len")) and (cap := props.get("cap")):
                if not isinstance(cap.value, int) or not isinstance(length.value, int):
                    # Length of slice must be concrete
                    break
                if isinstance(ptr.value, int):
                    # Pointer must be a variable
                    break
                if length.value > cap.value:
                    # Length cannot be greater than capacity
                    break
                if length.value > 100 or length.value == 0:
                    # Too long or zero length, skip to avoid messing up the stack!
                    break
                if not ptr.value.op == ida_hexrays.cot_var:
                    break
                if ptr.value.type.is_ptr():
                    break
                ptr_name = ptr.value.dstr()
                slice_type = ptr.parent.expr.type
                element_type = str(slice_type).removeprefix("_slice_")
                element_tinfo = ida_typeinf.tinfo_t()
                if not ida_typeinf.parse_decl(element_tinfo, idaapi.get_idati(), f"{element_type} x;", ida_typeinf.PT_SIL):
                    break
                if length.value > 1:
                    element_tinfo.create_array(element_tinfo, length.value)
                yap and print(f"Replacing {ptr_name} type to {element_type}[{length.value}]")
                replace_local_var_type(func, ptr_name, element_tinfo)
                break
    return r

def main():
    handle = ida_hexrays.open_pseudocode(idc.here(), 0)
    func = ida_hexrays.decompile(idc.here())
    apply_slice_builder(func)
    handle.refresh_view(True)

if __name__ == "__main__":
    main()