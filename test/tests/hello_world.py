import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/../../src/agar/scripts")

if sys.platform == "win32":
    os.environ["IDAUSR"] = cur_dir
else:
    os.environ["IDAUSR"] = ""

import idapro
import go_stringer
import interface_detector
import go_slicer
idapro.open_database(sys.argv[1], True)

try:
    import idaapi
    import ida_hexrays
    name = 'main.main'
    target_ea = idaapi.get_name_ea(0, name)

    def check(decomp):
        return "// Hello, World!" in str(decomp)

    def analysis():
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        go_slicer.apply_slice_builder(decomp, False)
        interface_detector.apply_interface_detector(decomp, False)
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        go_stringer.apply_go_stringer(decomp, False)

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