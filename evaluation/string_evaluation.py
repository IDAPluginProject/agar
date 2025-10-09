import base64
import collections
import os
import sys
import subprocess
import tempfile
import shutil
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(SCRIPT_DIR, "out")
os.makedirs(OUT_DIR, exist_ok=True)

def colorize(line, color_code):
    return f"{color_code}{line}\033[0m"


def run_test(test_file, bin_path, function_name, strings):
    try:
        proc = subprocess.Popen(
            [sys.executable, test_file, bin_path, 
             base64.b64encode(function_name.encode('utf-8')).decode('utf-8'),
             base64.b64encode(json.dumps(list(set(strings))).encode('utf-8')).decode('utf-8')],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        proc.wait()
        return proc.stdout.read()
    except Exception as e:
        print(f"Error running {test_file} with {bin_path}: {e}")
        return None
    finally:
        os.remove(bin_path)

def main():
    test_binary = sys.argv[1]
    bin_path_base = os.path.join(SCRIPT_DIR, "bin", test_binary)
    with open(f"./strings/{test_binary}.json", "r") as f:
        test_data = json.load(f)

    collated_test_data = collections.defaultdict(list)
    for entry in test_data:
        collated_test_data[entry["function"]].append(entry["string"])

    def _run_for_function(function, strings):
        # Informative log per task
        print(f"Running test for function {function} with {len(strings)} strings", flush=True)
        use_i64 = os.path.exists(bin_path_base + "_ida_92_preanalyzed.i64")
        bin_path_base_local = bin_path_base + "_ida_92_preanalyzed.i64" if use_i64 else bin_path_base
        suffix = ".i64" if use_i64 else ""
        fd, temp_path_local = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        shutil.copy2(bin_path_base_local, temp_path_local)
        result = run_test(
            os.path.join(SCRIPT_DIR, "string_evaluation_worker.py"),
            temp_path_local,
            function,
            strings,
        )
        return function, result, "92"
    
    def _run_for_function_91(function, strings):
        use_i64 = os.path.exists(bin_path_base + "_ida_91_preanalyzed.i64")
        bin_path_base_local = bin_path_base + "_ida_91_preanalyzed.i64" if use_i64 else bin_path_base
        suffix = ".i64" if use_i64 else ""
        fd, temp_path_local = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        shutil.copy2(bin_path_base_local, temp_path_local)
        result = run_test(
            os.path.join(SCRIPT_DIR, "string_evaluation_worker.py"),
            temp_path_local,
            function,
            strings,
        )
        return function, result, "91"

    st = time.time()
    # Determine a sensible level of parallelism; allow override via env var
    try:
        max_workers = int(os.environ.get("EVAL_MAX_WORKERS", "0"))
    except ValueError:
        max_workers = 0
    if max_workers <= 0:
        # IDA instances are heavy; default to min(4, cpu_count) unless fewer functions
        cpu = os.cpu_count() or 2
        max_workers = min(cpu, max(1, len(collated_test_data)))
    print(f"Using up to {max_workers} parallel workers for {len(collated_test_data)} functions.")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_run_for_function, function, strings)
                   for function, strings in collated_test_data.items()]
        if os.path.exists(bin_path_base + "_ida_91_preanalyzed.i64"):
            futures += [executor.submit(_run_for_function_91, function, strings)
                        for function, strings in collated_test_data.items()]
        else:
            print("IDA 9.1 preanalyzed binary not found; skipping 9.1 runs.")

        parsed_results = []  # list of dicts: {function, success, initial_count, final_count, total}

        for fut in as_completed(futures):
            function, result, ida_version = fut.result()
            try:
                data = json.loads(result)
            except Exception as e:
                print(f"Error parsing JSON result for function {function}: {e}, {result=}")
                raise e
            parsed_results.append({
                "function": function,
                "ida_version": ida_version,
                **data,
            })
            if not data.get("success") or data.get("missing"):
                print(ida_version, function, data, flush=True)

    ida_92_results = [d for d in parsed_results if d.get("ida_version") == "92"]
    # Compute overall success rates
    total_initial = sum(d.get("initial_count", 0) for d in ida_92_results)
    total_final = sum(d.get("final_count", 0) for d in ida_92_results)
    total_total = sum(d.get("total", 0) for d in ida_92_results) or 1  # avoid div by zero

    ida_91_results = [d for d in parsed_results if d.get("ida_version") == "91"]
    total_initial_91 = sum(d.get("initial_count", 0) for d in ida_91_results)
    total_final_91 = sum(d.get("final_count", 0) for d in ida_91_results)
    total_total_91 = sum(d.get("total", 0) for d in ida_91_results) or 1  # avoid div by zero

    initial_rate = 100.0 * total_initial / total_total
    final_rate = 100.0 * total_final / total_total

    print(f"Completed {len(collated_test_data)} functions in {time.time() - st:.2f}s with {max_workers} workers.")
    print(f"Initial success rate: {initial_rate:.2f}% ({total_initial}/{total_total})")
    print(f"Final success rate:   {final_rate:.2f}% ({total_final}/{total_total})")

    # Persist results for downstream visualization
    results_payload = {
        "test_binary": test_binary,
        "generated_at": time.time(),
        "results": parsed_results,
        "totals": {
            "initial": total_initial,
            "final": total_final,
            "total": total_total,
        },
        "ida_91_totals": {
            "initial": total_initial_91,
            "final": total_final_91,
            "total": total_total_91,
        },
    }
    out_json = os.path.join(OUT_DIR, f"{test_binary}_string_eval_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2)
    print(f"Saved results JSON to: {out_json}")

    # Done. Visualization now happens in a separate script (visualize_string_eval.py)


if __name__ == "__main__":
    main()