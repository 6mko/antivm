## Features

**WMI Checks:**  
Detects missing system hardware sensors (fans, cache, voltage probes), which are usually absent in virtual machines.

**BIOS Inspection:**  
Reads the `RSMB` firmware table and analyzes BIOS flags. Virtual machines often have minimal or unusual BIOS data.

**CPU Feature Checks:**  
Uses `CPUID` instructions to detect missing CPU features, like `RDTSCP`.

**Timing Analysis:**  
Measures CPU cycles with `__rdtsc()` around `CPUID` instructions. Virtual machines often produce inconsistent or delayed timings.

**Output:**  
- `"System appears clean"` if no VM indicators are found.  
- `"VM detected. Detection mask: 0x..."` if one or more VM indicators are detected.

**Detection Flags:**

| Flag       | Meaning                               |
|------------|---------------------------------------|
| `FLG_BIOS` | Suspicious BIOS data (likely VM)      |
| `FLG_CPU`  | Missing CPU features (likely VM)      |
| `FLG_WMI`  | Missing hardware sensors via WMI      |
| `FLG_TIME` | CPU timing anomalies (likely VM)      |
