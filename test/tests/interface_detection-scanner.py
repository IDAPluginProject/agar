import os
import sys

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/../../strings")

if sys.platform == "win32":
    os.environ["IDAUSR"] = cur_dir
else:
    os.environ["IDAUSR"] = ""

import idapro
import go_stringer
import interface_detector
idapro.open_database(sys.argv[1], True)

try:
    import idaapi
    import ida_hexrays
    name = 'main.ExampleScanner_lines'
    target_ea = idaapi.get_name_ea(0, name)

    def check():
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        go_stringer.apply_go_stringer(decomp, False)
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        decomp = str(decomp)
        return "// reading standard input:" in str(decomp)

    def analysis():
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        iface_res = interface_detector.apply_interface_detector(decomp, False)
        assert all(x == ('RTYPE_string', False) for x in iface_res.values())

    assert not check(), \
        f"Test conditions satisfied before script actions:\n\n{str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))}"
    
    analysis()

    assert check(), \
        f"Test conditions not satisfied. Decompilation:\n\n{str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))}"
    print("==== Success! ====")
finally:
    idapro.close_database(False)