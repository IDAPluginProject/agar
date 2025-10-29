import idaapi
import ida_typeinf

import sys, os
sys.path = [os.path.dirname(__file__)] + sys.path

import itab_parser
import trie

def replace_type(struct: ida_typeinf.tinfo_t, offset: int, new_type: ida_typeinf.tinfo_t):
    type_name = struct.get_type_name()
    if not struct.is_struct():
        return False
    udt = ida_typeinf.udt_type_data_t()
    if not struct.get_udt_details(udt):
        return False
    for field in udt:
        if field.offset == offset:
            field.type = new_type
            struct.create_udt(udt)
            struct.set_named_type(idaapi.get_idati(), type_name, ida_typeinf.NTF_REPLACE)
            return True
    return False

def get_all_types() -> list[str]:
    types = []
    idati = ida_typeinf.get_idati()
    
    if idati:
        limit = ida_typeinf.get_ordinal_limit()
        for ordinal in range(1, limit):
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.get_numbered_type(idati, ordinal):
                continue
            name = ida_typeinf.get_numbered_type_name(idati, ordinal)
            tinfo.get_realtype()
            if not tinfo.is_typedef():
                continue
            if name:
                types.append(name)
    
    return list(set(types))

def find_interface_implementations():
    itabs = itab_parser.parse_all_itabs()
    types = get_all_types()
    return trie.find_suffix_matches(itabs, types)

def update_all_typedefs(implementations, yap=False):  
    yap and print("Type Interfaces:")
    for type, interfaces in implementations.items():
        if len(interfaces) != 1:
            yap and print(f"Type {type} has multiple interfaces:")
            for name, ea in interfaces:
                yap and print(f"  {name} at {hex(ea)}")
            continue
        
        _, iface_type = itab_parser.parse_itab(interfaces[0][1])

        iface_type, _ = iface_type

        typedef = ida_typeinf.tinfo_t()
        typedef.create_typedef(idaapi.get_idati(), iface_type.get_type_name(), ida_typeinf.BTF_TYPEDEF)
        typedef.set_named_type(idaapi.get_idati(), type, ida_typeinf.NTF_REPLACE)
        yap and print(f"Type {type} resolves to interface {iface_type.get_type_name()} at {hex(interfaces[0][1])}")

if __name__ == "__main__":
    implementations = find_interface_implementations()
    update_all_typedefs(implementations, yap=True)