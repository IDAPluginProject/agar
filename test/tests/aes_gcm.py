import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/../../interfaces")

if sys.platform == "win32":
    os.environ["IDAUSR"] = cur_dir
else:
    os.environ["IDAUSR"] = ""

import idapro
idapro.open_database(sys.argv[1], True)
try:
    import idaapi
    import ida_hexrays
    import ida_typeinf, ida_nalt
    import itab_typedef_maker

    gcm_func = "crypto_cipher.NewGCM"
    name = "main.encrypt_aes_gcm"
    expected_type = "crypto_cipher_AEAD"
    expected_type_2 = None

    def check(decomp):
        methods_intel = ["_r0.tab->crypto_cipher__ptr_gcmFallback_NonceSize", "_r0.tab->crypto_cipher__ptr_gcmFallback_Seal"]
        methods_arm = ["_r0.tab->crypto_cipher._ptr_gcmFallback.NonceSize", "_r0.tab->crypto_cipher._ptr_gcmFallback.Seal"]
        return all(method in decomp for method in methods_intel) or all(method in decomp for method in methods_arm)

    def analysis():
        global expected_type_2
        struct = get_struct()
        implementations = itab_typedef_maker.find_interface_implementations()
        assert expected_type in implementations, implementations.keys()
        type_names = [str(x[0]) for x in implementations[expected_type]]
        expected_type_2 = next((x for x in type_names if "gcmFallback" in x), None)
        assert expected_type_2, f"gcm_fallback not found in implementations: {type_names}"
        target_type = implementations[expected_type][type_names.index(expected_type_2)]
        assert itab_typedef_maker.replace_type(struct, 0, target_type[0])

    def get_selected_member(struct, offset):
        udt = ida_typeinf.udt_type_data_t()
        if not struct.get_udt_details(udt):
            return None
        for field in udt:
            if field.offset//8 == offset:
                type_name = field.type.get_final_type_name()
                if not type_name or ("iface" not in type_name and "interface" not in type_name):
                    return None
                return field.name, str(field.type)
        return None
    
    def get_struct():
        gcm_func_ea = idaapi.get_name_ea(0, gcm_func)
        tif = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tif, gcm_func_ea)
        func_details = ida_typeinf.func_type_data_t()
        tif.get_func_details(func_details)
        struct = func_details.rettype.copy()
        res = get_selected_member(struct, 0)
        assert res, f"Expected member at offset 0 not found in struct: {struct}"
        name, type = res
        assert name == "_r0", f"Expected '_r0', got '{name}'"
        assert type == expected_type, f"Expected '{expected_type}', got '{type}'"
        return struct

    target_ea = idaapi.get_name_ea(0, name)

    decomp = str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))

    assert not check(decomp), \
        f"Test conditions satisfied before script actions:\n\n{decomp}"
    
    analysis()

    decomp = str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))
    assert check(decomp), \
        f"Test conditions not satisfied. Decompilation:\n\n{decomp}"
    
    expected_type = expected_type_2
    assert get_struct()

    print("==== Success! ====")
finally:
    idapro.close_database(False)