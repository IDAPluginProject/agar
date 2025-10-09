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
from collections import Counter
idapro.open_database(sys.argv[1], True)

try:
    import idaapi
    import ida_hexrays
    name = 'main.main'
    target_ea = idaapi.get_name_ea(0, name)

    def check():
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        go_stringer.apply_go_stringer(decomp, False)
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        decomp = str(decomp)
        # Note: "key" is a type 1 string literal
        strings = ["// Please enter some text (Ctrl+D to end):", '"key"', "// Map:"]
        return all(s in decomp for s in strings)

    def analysis():
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        iface_type_count = Counter()
        iface_res = interface_detector.apply_interface_detector(decomp, False)
        for iface_type in iface_res.values():
            iface_type_count[iface_type] += 1
        assert iface_type_count[('RTYPE_string', False)] >= 1
        assert iface_type_count[('RTYPE_int', True)] >= 1
        assert iface_type_count[('RTYPE_map_string_interface_', False)] >= 1

    assert not check(), \
        f"Test conditions satisfied before script actions:\n\n{str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))}"

    analysis()

    assert check(), \
        f"Test conditions not satisfied. Decompilation:\n\n{str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))}"
    print("==== Success! ====")
finally:
    idapro.close_database(False)