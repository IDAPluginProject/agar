import idaapi
import idc
import ida_typeinf
from collections import defaultdict


def read_addr(addr):
    if idaapi.inf_is_32bit_exactly():
        return idaapi.get_32bit(addr)
    elif idaapi.inf_is_64bit():
        return idaapi.get_64bit(addr)
    else:
        raise ValueError("Unsupported address size")

def address_size():
    if idaapi.inf_is_32bit_exactly():
        return 4
    elif idaapi.inf_is_64bit():
        return 8
    else:
        raise ValueError("Unsupported address size")

def get_itablink_segment_addr():
    segs = [idaapi.get_segm_by_name(".itablink"), idaapi.get_segm_by_name("__itablink")]
    for seg in segs:
        if seg is not None:
            return (seg.start_ea, seg.end_ea)
    if (addr := idc.get_name_ea(0, "runtime.itablink")) and addr != idaapi.BADADDR:
        end_ea = addr + address_size()
        while not idc.get_name(end_ea):
            end_ea += address_size()
        return addr, end_ea
    return None

def parse_itab(itab_addr):
    try:
        concrete_type_name = idc.get_name(read_addr(itab_addr + address_size()))
    except Exception as e:
        return "", None
    if not concrete_type_name.startswith("RTYPE_"):
        return "", None
    try:
        iface_type_name = idc.get_name(read_addr(itab_addr))
    except Exception as e:
        return "", None

    if not iface_type_name.startswith("RTYPE_"):
        return "", None
    concrete_type_name = concrete_type_name[len("RTYPE_"):]
    iface_type_name = iface_type_name[len("RTYPE_"):]
    type_ptr = ida_typeinf.tinfo_t()
    if not type_ptr.get_named_type(concrete_type_name):
        return "", None

    start = itab_addr + address_size() * 3
    methods = []
    while True:
        name = idaapi.get_name(start)
        if name:
            break
        method_addr = read_addr(start)
        if method_addr == idaapi.BADADDR:
            break
        method_name = idc.get_name(method_addr, idaapi.GN_VISIBLE)
        if not method_name:
            break
        method_type = ida_typeinf.tinfo_t()
        idaapi.get_type(method_addr, method_type, ida_typeinf.TINFO_DEFINITE)
        if not method_type.is_func():
            break
        methods.append((method_name, method_type))
        start += address_size()

    itab_struct = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    udm = ida_typeinf.udm_t()
    RTYPE = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(RTYPE, idaapi.get_idati(), "RTYPE* x;", ida_typeinf.PT_TYP)
    integer = ida_typeinf.tinfo_t()
    if idaapi.inf_is_32bit_exactly():
        integer.create_simple_type(ida_typeinf.BTF_UINT32)
    elif idaapi.inf_is_64bit():
        integer.create_simple_type(ida_typeinf.BTF_UINT64)
    else:
        raise ValueError("Unsupported address size")
    udt.push_back(ida_typeinf.udm_t("inter", RTYPE, 0))
    udt.push_back(ida_typeinf.udm_t("type", RTYPE, RTYPE.get_size()))
    udt.push_back(ida_typeinf.udm_t("hash", integer, RTYPE.get_size() * 2))
    for name, type in methods:
        udm.name = name
        func_ptr_type = ida_typeinf.tinfo_t()
        func_ptr_type.create_ptr(type)
        udm.type = func_ptr_type
        udt.push_back(udm)
    itab_struct.create_udt(udt)
    struct_type_name = concrete_type_name + "_comma_" + iface_type_name
    existing_type_name = idc.get_name(itab_addr, idaapi.GN_VISIBLE)
    if existing_type_name.startswith("go_itab_"):
        struct_type_name = existing_type_name[len("go_itab_"):]
    else:
        idc.set_name(itab_addr, "go_itab_" + struct_type_name, idaapi.SN_FORCE)
    itab_struct.set_named_type(None, struct_type_name, ida_typeinf.NTF_REPLACE)
    ida_typeinf.apply_tinfo(itab_addr, itab_struct, ida_typeinf.TINFO_DEFINITE)

    iface_struct_type_name = "iface_"+struct_type_name
    iface_type = ida_typeinf.tinfo_t()
    udt_2 = ida_typeinf.udt_type_data_t()
    itab_struct.create_ptr(itab_struct)
    type_ptr.create_ptr(type_ptr)
    udt_2.push_back(ida_typeinf.udm_t("tab", itab_struct, 0))
    udt_2.push_back(ida_typeinf.udm_t("data", type_ptr, itab_struct.get_size()))
    iface_type.create_udt(udt_2)
    iface_type.set_named_type(None, iface_struct_type_name, ida_typeinf.NTF_REPLACE)
    return iface_type_name, (iface_type, itab_addr)


def parse_all_itabs(yap=False):
    addrs = get_itablink_segment_addr()
    itabs = defaultdict(list)
    if addrs is None:
        yap and print("No .itablink segment found")
    else:
        start, end = addrs
        for ea in range(start, end, address_size()):
            itab_addr = read_addr(ea)
            iface_type_name, iface_type = parse_itab(itab_addr)
            if iface_type:
                itabs[iface_type_name].append(iface_type)
                yap and print(f"Parsed itab at {hex(itab_addr)}: {iface_type_name}")
            else:
                yap and print(f"Failed to parse itab at {hex(itab_addr)}")
    return itabs

if __name__ == "__main__":
   print(parse_all_itabs())