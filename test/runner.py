import enum
import os
import sys
import subprocess
import glob
import threading
import tempfile
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def colorize(line, color_code):
    return f"{color_code}{line}\033[0m"

ARCH_COLORS = {
    # Script should work for these two cases
    "amd64": "\033[1;33m",              # Yellow
    "386": "\033[1;32m",                # Green

    # These might not work, more challenging cases
    "amd64_stripped": "\033[1;31m",     # Red
    "windows_amd64": "\033[1;34m",      # Blue
    "arm": "\033[1;35m",                # Magenta
}

class TestResult(enum.Enum):
    SUCCESS = "Success"
    FAILURE = "Failure"
    PRESATISFIED = "Presatisfied"

def run_test(test_file, bin_path, arch, test_name, results):
    color = ARCH_COLORS.get(arch, "\033[0m")
    test_id = test_name + "/" + arch
    results[test_id] = TestResult.FAILURE
    tmp_bin_fd, tmp_bin_path = tempfile.mkstemp(suffix=os.path.splitext(bin_path)[1])
    os.close(tmp_bin_fd)
    shutil.copy2(bin_path, tmp_bin_path)
    try:
        proc = subprocess.Popen(
            [sys.executable, test_file, tmp_bin_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        lines = []
        for line in proc.stdout:
            prefix = f"  [{test_id}] "
            lines.append(colorize(prefix + line.rstrip(), color))
            if "Success!" in line:
                results[test_id] = TestResult.SUCCESS
            if "Test conditions satisfied before script actions:" in line:
                results[test_id] = TestResult.PRESATISFIED
        proc.wait()
        for line in lines:
            print(line)
    except Exception as e:
        print(f"Error running {test_file} with {bin_path}: {e}")
    finally:
        os.remove(tmp_bin_path)

def main():
    if len(sys.argv) > 1:
        test_files = [os.path.join(SCRIPT_DIR, "tests", f"{sys.argv[1]}.py")]
    else:
        test_files = glob.glob(os.path.join(SCRIPT_DIR, "tests", "*.py"))

    architectures = ARCH_COLORS.keys()

    total_tests_count = len(test_files) * len(architectures)
    threads = []
    results = {}

    for test_file in test_files:
        if not os.path.isfile(test_file):
            print(f"Test file {test_file} not found, skipping.")
            continue
        test_name = os.path.splitext(os.path.basename(test_file))[0]
        bin_path_base = os.path.join(SCRIPT_DIR, "bin", test_name.split("-")[0])
        print(f"Running test {test_name}")
        
        for arch in architectures:
            if arch == "windows_amd64":
                bp = f"{bin_path_base}_{arch}.exe"
            else:
                bp = f"{bin_path_base}_{arch}"
            if os.path.isfile(bp):
                t = threading.Thread(target=run_test, args=(test_file, bp, arch, test_name, results))
                t.start()
                threads.append(t)
            else:
                print(f"  Skipping {bp} (not found)")

    for t in threads:
        t.join()
    
    print("\nAnomalous Test Results:")

    successes = 0
    for k, v in results.items():
        if v == TestResult.SUCCESS:
            successes += 1
        if v == TestResult.FAILURE:
            print(colorize(f"- {k}: Failure", "\033[1;31m"))  # Red
        elif v == TestResult.PRESATISFIED:
            print(colorize(f"- {k}: Test conditions presatisfied", "\033[1;35m"))  # Magenta
    
    print(f"{successes}/{total_tests_count} tests passed")
    try:
        os.remove(os.path.join(SCRIPT_DIR, "tests", "proccache.lst"))
    except FileNotFoundError:
        pass

if __name__ == "__main__":
    main()