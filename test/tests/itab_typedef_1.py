import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/../../src/agar")

if sys.platform == "win32":
    os.environ["IDAUSR"] = cur_dir
else:
    os.environ["IDAUSR"] = ""

import idapro
idapro.open_database(sys.argv[1], True)

try:
    import idaapi, ida_hexrays
    import itab_typedef_maker
    def check(decomp):
        return "tab->main__ptr_A_String" in decomp or "tab->main._ptr_A.String" in decomp

    def analysis():
        implementations = itab_typedef_maker.find_interface_implementations()
        assert "main_Stringer_0" in implementations or "main_Stringer" in implementations, implementations.keys()
        main_ea = idaapi.get_name_ea(0, "main.main")
        ida_hexrays.decompile(main_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        itab_typedef_maker.update_all_typedefs(implementations, yap=False)

    name = 'main.Print'
    target_ea = idaapi.get_name_ea(0, name)

    decomp = str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))

    assert not check(decomp), \
        f"Test conditions satisfied before script actions:\n\n{decomp}"
    
    analysis()

    decomp = str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))
    assert check(decomp), \
        f"Test conditions not satisfied. Decompilation:\n\n{decomp}"
    print("==== Success! ====")
finally:
    idapro.close_database(False)