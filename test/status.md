## Test status on 2025-08-05

IDA: `Version 9.2.250730 Windows x64 (64-bit address size)`

```
Anomalous Test Results:
- aes_gcm/amd64_stripped: Failure
- aes_gcm/windows_amd64: Failure
- aes_gcm/arm: Failure
- interface_detection-main/arm: Failure
- itab_typedef_1/amd64_stripped: Failure
- itab_typedef_1/windows_amd64: Failure
- itab_typedef_2/amd64_stripped: Failure
- itab_typedef_2/windows_amd64: Failure
22/30 tests passed
```


After updates/relaxation of test passing criteria:
```
Anomalous Test Results:
- aes_gcm/amd64_stripped: Failure
- aes_gcm/windows_amd64: Failure
- interface_detection-main/arm: Failure
- itab_typedef_1/amd64_stripped: Failure
- itab_typedef_1/windows_amd64: Failure
- itab_typedef_2/amd64_stripped: Failure
24/30 tests passed
```

## Test status on 2025-09-01

Updated to IDA 9.2 Beta 3 on both Windows and Linux.
Linux version runs much slower (but maybe because it's in a VM)

On Linux:
```
Anomalous Test Results:
- interface_detection-main/arm: Failure
- aes_gcm/amd64_stripped: Failure
- aes_gcm/windows_amd64: Failure
- itab_typedef_2/amd64_stripped: Failure
- itab_typedef_1/amd64_stripped: Failure
- itab_typedef_1/windows_amd64: Failure
24/30 tests passed
```
Basically the same.