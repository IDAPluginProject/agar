import ida_hexrays, ida_typeinf, idc, idaapi, ida_bytes
from typing import Optional

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
    offset: int

    def __init__(self, parent: Ref, expr: ida_hexrays.cexpr_t, offset: int, var_name: str) -> None:
        self.ea = expr.ea
        self.parent = parent
        self.expr = expr
        self.var_name = var_name

    def __str__(self):
        return f"{str(self.parent)}.{self.var_name}"
    
    def __repr__(self) -> str:
        return str(self) + " = " + str(self.value) if self.value is not None else str(self)

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

def deref_maybe(t : ida_typeinf.tinfo_t) -> ida_typeinf.tinfo_t:
    if t is None:
        return None
    if t.is_ptr_or_array():
        return t.get_pointed_object()
    return t

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
    
    def find_var(self, expr: ida_hexrays.cexpr_t) -> ida_hexrays.cexpr_t:
        if expr.op == ida_hexrays.cot_var:
            return expr
        elif expr.op in [ida_hexrays.cot_memref, ida_hexrays.cot_memptr, ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_cast]:
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
                    var_type = deref_maybe(var_asg.type)
                    if not var_type.is_struct():
                        return 0
                    udt = ida_typeinf.udt_type_data_t()
                    var_type.get_udt_details(udt)

                    member_name = next(x.name for x in udt if (x.offset//8) == mem_ref_expr.m)
                    val = self.get_concrete(expr.y)
                    mem_ref = MemRef(var_ref, expr, mem_ref_expr.m, member_name)
                    mem_ref.value = val
                    self.add_ref(var_name, mem_ref)
                else:
                    dstr = expr.dstr()
                    parts = dstr.split("=", maxsplit=1)
                    if mem_ref_expr.op == ida_hexrays.cot_memptr:
                        var_name, prop_name = parts[0].rsplit("->", maxsplit=1)
                    elif mem_ref_expr.op == ida_hexrays.cot_memref or "." in parts[0]:
                        var_name, prop_name = parts[0].rsplit(".", maxsplit=1)
                    else:
                        return 0
                    var_expr = self.find_var(expr.x)
                    var_name = var_expr.dstr() if var_expr and var_expr.op == ida_hexrays.cot_var else var_name.strip()
                    var_ref = AsgRef(var_name, var_expr.ea, var_expr)
                    mem_ref = MemRef(var_ref, expr, mem_ref_expr.m, prop_name.strip())
                    mem_ref.value = self.get_concrete(expr.y)
                    self.add_ref(var_name, mem_ref)
        return 0
    
def build_reftable(func):
    c = cvisitor()
    c.apply_to(func.body, None)
    return c.refs

def handle_string(code_addr, str_addr, length, do_comment=True):
    ida_bytes.del_items(str_addr, ida_bytes.DELIT_EXPAND, length)
    idc.create_strlit(str_addr, str_addr + length)
    if do_comment:
        string = idc.get_strlit_contents(str_addr, length, idc.STRTYPE_C)
        string = string.decode("utf-8", errors="ignore")
        tl = idaapi.treeloc_t()
        tl.ea = code_addr
        tl.itp = idaapi.ITP_SEMI
        cfunc = idaapi.decompile(code_addr)
        cfunc.set_user_cmt(tl, string)
        cfunc.save_user_cmts()

def handle_type_2_string(memref: MemRef):
    if not memref or not memref.value:
        return None
    address = memref.value
    is_64bit = idaapi.inf_is_64bit()
    str_ptr = ida_bytes.get_64bit(address) if is_64bit else ida_bytes.get_32bit(address)
    
    if not ida_bytes.is_mapped(str_ptr):
        return None
    
    length = ida_bytes.get_64bit(address + 8) if is_64bit else ida_bytes.get_32bit(address + 4)
    handle_string(memref.ea, str_ptr, length)


def apply_go_stringer(func, yap=True):
    r = build_reftable(func)
    yap and print("References found:", len(r))
    yap and print(r)
    rtype_string_addr = idaapi.get_name_ea(0, "RTYPE_string")

    for var, refs in r.items():
        props = {}
        for ref in refs:
            if isinstance(ref, MemRef):
                if ref.value is not None:
                    props[ref.var_name.strip("_1234567890")] = ref
            if (string := (props.get("str") or props.get("ptr"))) and (length := props.get("len")):
                yap and print("Creating type 1 string at", hex(string.ea), "with length", length.value)
                handle_string(string.ea, string.value, length.value, do_comment=False)
                if "ptr" in props:
                    del props["ptr"]
                if "str" in props:
                    del props["str"]
                del props["len"]
            if (iface_type := (props.get("tab") or props.get("type"))) and (data := props.get("data")):
                if iface_type.value == rtype_string_addr:
                    yap and print("Creating type 2 string at", hex(data.ea))
                    handle_type_2_string(data)
                if "tab" in props:
                    del props["tab"]
                if "type" in props:
                    del props["type"]
                del props["data"]
    return r

def main():
    handle = ida_hexrays.open_pseudocode(idc.here(), 0)
    func = ida_hexrays.decompile(idc.here())
    apply_go_stringer(func)
    handle.refresh_view(True)

if __name__ == "__main__":
    main()