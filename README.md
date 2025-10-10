# AGAR

Assisting Go Analysis and Reversing (AGAR) correctly detects **5 to 20x more strings** in Go programs compiled for Linux than standalone IDA 9.2.

You can also use AGAR to demystify method calls on interface types.

## Benchmarks
<img src="./img/string_eval_all.png" width="80%" />

Tested on
- [frpc](https://github.com/fatedier/frp/tree/dev/client) (compiled for Linux)
- Two Go RE CTF challenges from [TISC 2025](https://www.csit.gov.sg/events/tisc/tisc-2025)
- Checksum from Flare-On 11

You can read the test evaluation script [here](./evaluation/string_evaluation_worker.py).
It runs the following scripts in sequence:
1. Function retyper
2. Interface detector
3. Stringer

## Features

### Standard Library Function retyper
**Usage:** `Ctrl+Shift+G` + select `Function retyper`  

**Before:**
![alt text](./img/image.png)

**After:**  
![alt text](./img/image-1.png)

### Interface detection and retyping
**Usage:** `Ctrl+Shift+G` + select `Interface detector`  

**Before:**  
![alt text](./img/interface_detect_before.png)

**After:**  
![alt text](./img/interface_detect_after.png)

### String detection
**Usage:** `Ctrl+Shift+G` + select `Stringer`  

**Before:**  
![alt text](./img/string_before.png)

**After:**  
![alt text](./img/string_after.png)

### Interface specializer
**Usage:**
1. Find a struct that contains an interface type
2. Right click on the interface type field and select "Specialize interface"
3. Select the appropriate concrete implementation from the dropdown

**Before:**  
![alt text](./img/specialization_before.png)

**After:**  
![alt text](./img/specialization_after.png)

## Installation

Copy the contents of `src` to the IDA Plugins directory.

## Tests

The [test](test) directory contains Go programs and Python scripts to assess AGAR's ability to analyze these programs when compiled to a variety of architectures.

Currently, there are 6 known failing tests:
- interface_detection-main/arm: Failure
- aes_gcm/amd64_stripped: Failure
- aes_gcm/windows_amd64: Failure
- itab_typedef_2/amd64_stripped: Failure
- itab_typedef_1/amd64_stripped: Failure
- itab_typedef_1/windows_amd64: Failure

This is primarily due to lack of type information in stripped binaries or binaries compiled for Windows.

To run the tests, 
1. Build the test binaries: `py build.py`
2. Run the tests: `py runner.py`

You will need IDA 9.2 with `idalib` configured.