# Rootkit-Remover
A simple project to remove user-mode rootkits on Windows

## Features

- **DLL Unhooking**: Dynamically restores altered in-memory system DLLs (`ntdll.dll`, `amsi.dll`, `advapi32.dll`, etc.) by rewriting their `.text` sections directly from clean, uncorrupted on-disk binaries
- **Process Memory Sanitation**: Enumerates active system processes using Toolhelp32 snapshots and strips injected hooks from target process spaces
- **Persistence Neutralization**: Leverages Windows Task Scheduler COM APIs (`ITaskService`) to identify and delete rootkit persistence triggers (e.g., `$77svc32` and `$77svc64`)
- **Targeted Process Termination**: Closes compromised host processes commonly exploited by user-mode rootkits, such as `dllhost.exe`

**Run As Adminstretor**
  
**Note**: It is effective and has been tested against the r77 rootkit

Just a simple project; I hope you like it.
