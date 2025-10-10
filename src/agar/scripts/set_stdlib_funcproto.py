import json
import os
import idaapi
import ida_typeinf
import idc
import functools

cwd = os.path.dirname(__file__)

data = json.load(open(os.path.join(cwd, "types.json"), "r"))


@functools.lru_cache(maxsize=None)
def parse_type(type_str):
    if type_str == "void":
        return type_str
    remains = ""
    if " " in type_str:
        type_ = type_str.rsplit(" ", 1)[0]
        base = len(type_)
        remains = type_str[base:]
        # new is an invalid identifier in IDA
        bad_words = ["new", "signed", "template"]
        for bw in bad_words:
            remains = remains.replace(f" {bw}", f" _{bw}").replace(f"*{bw}", f"*_{bw}")
        type_str = type_
    if type_str == "runtime_tmpBuf":
        return "void" + remains
    res = idc.parse_decl(type_str, idaapi.PT_SIL)
    if res:
        return type_str + remains
    if type_str[-1].isdigit() or type_str[-1] == '_':
        result = parse_type(type_str[:-1])
        if result:
            return result + remains


def main(yap=True):
    fail_count = 0
    func_not_exist = 0
    total_count = 0
    for func_name, func_decl in data.items():
        func_addr = idc.get_name_ea_simple(func_name)
        if func_addr == idc.BADADDR:
            func_not_exist += 1
            continue
        total_count += 1
        ret_val = func_decl.split(" ")[0]
        ret_val = parse_type(ret_val)
        if not ret_val:
            fail_count += 1
            continue
        args = func_decl[func_decl.index("(")+1:-1]
        old_func_decl = func_decl
        args = [a.strip() for a in args.split(",") if a.strip()]
        parsed_args = []
        failed = False
        for arg in args:
            parsed_arg = parse_type(arg)
            if not parsed_arg:
                failed = True
                break
            parsed_args.append(parsed_arg)
        if failed:
            fail_count += 1
            continue
        func_decl = f"{ret_val} __golang func({', '.join(parsed_args)});"
        tinfo = ida_typeinf.tinfo_t()
        res = ida_typeinf.parse_decl(tinfo, None, func_decl, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
        assert res is not None, (old_func_decl, func_decl)
        ida_typeinf.apply_tinfo(func_addr, tinfo, idaapi.TINFO_DEFINITE)
        

    yap and print(f"Failed to parse {fail_count}/{total_count} functions")
    yap and print(f"Functions not found: {func_not_exist}")

if __name__ == "__main__":
    main()