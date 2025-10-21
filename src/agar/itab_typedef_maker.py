import secrets
import idaapi
import ida_hexrays
import ida_typeinf

import sys, os
sys.path = [os.path.dirname(__file__)] + sys.path

import itab_parser

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
    mod = secrets.token_hex(4)
    ida_hexrays.rename_lvar(cfunc.entry_ea, name, f"{name}_{mod}")
    modifier = local_var_type_modifier_t({f"{name}_{mod}": new_type})
    ida_hexrays.modify_user_lvars(cfunc.entry_ea, modifier)
    ida_hexrays.rename_lvar(cfunc.entry_ea, f"{name}_{mod}", name)

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

def find_suffix_matches(A: dict[str, list], B: list[str]) -> dict[str, list]:
    # Build a trie for all suffixes in A (reversed strings)
    class TrieNode:
        def __init__(self):
            self.children = {}
            self.values = []

    root = TrieNode()
    for a, values in A.items():
        node = root
        for ch in reversed(a):
            node = node.children.setdefault(ch, TrieNode())
        node.values.extend(values)

    result = {}
    for b in B:
        node = root
        matches = []
        for ch in reversed(b.rstrip("_1234567890")):
            if ch not in node.children:
                break
            node = node.children[ch]
            if node.values:
                matches.extend(node.values)
        if matches:
            result[b] = matches
    return result

def find_interface_implementations():
    itabs = itab_parser.parse_all_itabs()
    types = get_all_types()
    return find_suffix_matches(itabs, types)

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