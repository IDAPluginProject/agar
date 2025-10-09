import os
import concurrent.futures
import subprocess
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(SCRIPT_DIR, "src")
BIN_DIR = os.path.join(SCRIPT_DIR, "bin")
if os.path.exists(BIN_DIR):
    shutil.rmtree(BIN_DIR)
os.makedirs(BIN_DIR, exist_ok=True)

go_builds = [
    ("linux", "amd64", "_amd64"),
    ("linux", "amd64_stripped", "_amd64_stripped"),
    ("linux", "386", "_386"),
    ("linux", "arm", "_arm"),
    ("windows", "amd64", "_windows_amd64.exe"),
    # ("windows", "amd64_stripped", "_windows_amd64_stripped.exe"),
]
build_tasks = []
for filename in os.listdir(SRC_DIR):
    if filename.endswith(".go"):
        base = os.path.splitext(filename)[0]
        src_file = os.path.join(SRC_DIR, filename)
        for goos, goarch, suffix in go_builds:
            out_file = os.path.join(BIN_DIR, base + suffix)
            env = os.environ.copy()
            env["GOOS"] = goos
            if goarch.endswith("stripped"):
                env["GOARCH"] = goarch.replace("_stripped", "")
                cmd = ["go", "build", "-ldflags", "-s -w", "-o", out_file, src_file]
            else:
                env["GOARCH"] = goarch
                cmd = ["go", "build", "-o", out_file, src_file]
            build_tasks.append((cmd, env, out_file, goos, goarch))

def run_build(task):
    cmd, env, out_file, goos, goarch = task
    print(f"Building {out_file} for {goos}/{goarch} ...")
    try:
        subprocess.check_call(cmd, env=env)
        print(f"Success: {out_file}")
    except subprocess.CalledProcessError as e:
        print(f"Failed: {out_file} ({goos}/{goarch}) - {e}")

with concurrent.futures.ThreadPoolExecutor() as executor:
    executor.map(run_build, build_tasks)