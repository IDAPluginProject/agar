import base64
import os
import sys
import json

cur_dir = os.path.dirname(__file__)

sys.path.append(f"{cur_dir}/../src/agar")
sys.path.append(f"{cur_dir}/../src/agar/scripts")

if sys.platform == "win32":
    os.environ["IDAUSR"] = cur_dir
else:
    os.environ["IDAUSR"] = ""

import idapro
idapro.open_database(sys.argv[1], True)

function_name = base64.b64decode(sys.argv[2]).decode('utf-8')
strings = json.loads(base64.b64decode(sys.argv[3]).decode('utf-8'))


def decomp_contains(decomp, string):
    escaped_string = string.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    res = f'"{string}"' in decomp or f"// {string}" in decomp or f'"{escaped_string}"' in decomp or f"// {escaped_string}" in decomp
    if res:
        return res
    if "\n" in string:
        for line in string.split("\n"):
            if line and line.replace("\t", "\\t").replace("\r", "\\r") not in decomp:
                return False
        return True
    if len(string) > 80: # Longer strings may wrap
        return f'"{string[:80]}' in decomp
    return False

try:
    import idaapi
    import ida_hexrays
    import go_stringer
    import interface_detector
    import set_stdlib_funcproto

    target_ea = idaapi.get_name_ea(0, function_name)
    if target_ea == idaapi.BADADDR:
        print(json.dumps({"success": False, "error": f"Function {function_name} not found"}))
    else:
        initial_decomp = str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))
        initial_string_count = sum(1 for s in strings if decomp_contains(initial_decomp, s))

        set_stdlib_funcproto.main(False)
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        interface_detector.apply_interface_detector(decomp, False)
        decomp = ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
        go_stringer.apply_go_stringer(decomp, False)

        decomp = str(ida_hexrays.decompile(target_ea, flags=ida_hexrays.DECOMP_NO_CACHE))

        final_string_count = sum(1 for s in strings if decomp_contains(decomp, s))
        missing = [s for s in strings if not decomp_contains(decomp, s)]
        print(json.dumps({"success": True, "initial_count": initial_string_count, "final_count": final_string_count, "total": len(strings), "missing": missing}))
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
finally:
    idapro.close_database(False)