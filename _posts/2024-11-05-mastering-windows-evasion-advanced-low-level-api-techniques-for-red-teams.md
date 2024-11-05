---
layout: post
title: "Deep Windows API Manipulation: Cutting-Edge Techniques for EDR Evasion and Stealth"
date: 2024-11-05 19:43:00 +0300
categories: [Cybersecurity, Red Teaming]
tags: [Windows API, EDR Evasion, Stealth, Persistence, Kernel Manipulation]
---

# Unleashing Advanced Evasion Techniques in Windows with Low-Level API Manipulation

## Introduction

In advanced adversarial operations, bypassing EDRs and security monitoring requires control over system internals that goes well beyond typical API hooking or patching. This article explores advanced techniques using deeply embedded, undocumented Windows functions and layered strategies that allow malware to stay hidden, avoid detection, and gain resilient persistence.

## 1. Deep Kernel-Level Subversion: Manipulating Kernel Objects with `NtCreateSection`

`NtCreateSection` is a powerful kernel-level function that creates a memory-mapped section that multiple processes can share. This is particularly useful for stealthy persistence, as sections can be used to hide code in non-pageable memory regions or even within critical system structures, making them nearly invisible to user-mode detection.

![image](https://github.com/user-attachments/assets/8f5f7050-4e52-48d7-8372-d93469959442)


### Advanced Use Cases for `NtCreateSection`:

- **Code Injection via Kernel Memory Sections**: By injecting code into a section and sharing it with other critical system processes, malware can establish a foothold that’s incredibly hard to detect. For example, you can create a section that maps memory into the System process (`PID 4`), essentially hiding code in an area few EDRs will inspect.

- **Anti-Forensics with Immutable Sections**: Immutable sections created with `SEC_IMAGE` and `SEC_NO_CHANGE` can prevent other processes, including security tools, from modifying or unloading sections. This can lock down injected code and ensure persistence without interference.

### Code Example: Creating and Mapping a Stealthy Memory Section

```cpp
HANDLE hSection;
LARGE_INTEGER maxSize;
maxSize.QuadPart = 0x1000; // 4 KB section for hidden payload

NtCreateSection(&hSection, SECTION_MAP_EXECUTE | SECTION_MAP_WRITE, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_NO_CHANGE, NULL);

PVOID baseAddress = NULL;
SIZE_T viewSize = 0;
NtMapViewOfSection(hSection, GetCurrentProcess(), &baseAddress, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
```

By mapping a section this way, malware can hide payloads in kernel memory regions where most EDRs won’t look, establishing deep persistence.

## 2. Advanced ETW and Telemetry Manipulation: Subverting Internal ETW Stacks with `EtwSetProviderTraits`

Standard ETW evasion involves patching or disabling functions like `EtwEventWrite`, but advanced tactics can target the ETW provider traits, controlling what gets logged at a configuration level without altering ETW functions directly. `EtwSetProviderTraits` is an undocumented API that allows for precise control over what an ETW provider reports.

![image](https://github.com/user-attachments/assets/3e4fbcb0-84e2-4b70-886b-9fa3c8d7724e)


### Using `EtwSetProviderTraits` for Granular Event Control

- **Selective Event Blocking**: By adjusting provider traits, you can configure which events from a provider are recorded and which are ignored. For example, disabling specific traits for Microsoft-Windows-Security-Auditing can prevent certain security logs from being generated.

- **Trait-Based Fuzzing to Avoid Detection**: Changing provider traits at random intervals to inject benign traits temporarily makes event analysis inconsistent, disrupting automated detections.

### Code Example: Subverting Provider Traits for Covert ETW Control

```cpp
// Modify provider traits to minimize logging
GUID providerGuid = ...; // Target provider's GUID, e.g., Security-Auditing
BYTE traits[] = { 0x00 }; // Minimal logging trait configuration

EtwSetProviderTraits(&providerGuid, traits, sizeof(traits));
```

Modifying ETW provider traits at this level can reduce logging from specific providers, allowing stealth operations without triggering ETW-based detection tools.

## 3. Covert Thread Management with `NtCreateThreadEx` and `ThreadExFlags`

`NtCreateThreadEx` is a powerful thread creation function that gives more control than `CreateThread`, allowing for thread injection in suspended states, hidden entry points, and bypassing standard thread enumeration.

![image](https://github.com/user-attachments/assets/241119a7-faa8-443d-bbe5-5d2ebd424a72)


### Advanced Use Cases for `NtCreateThreadEx`:

- **Stealthy Thread Injection in Target Processes**: By creating threads in a target process in a suspended state and then hiding them from enumeration, malware can deploy payloads undetected, avoiding both user-mode and kernel-mode hooks.

- **ThreadExFlags Manipulation**: Setting flags such as `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` and `THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH` allows threads to operate without typical debugger notifications and attach notifications, bypassing hooks set on `DLL_PROCESS_ATTACH`.

### Code Example: Hidden Thread Creation in a Target Process

```cpp
HANDLE hThread;
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProcess, (LPTHREAD_START_ROUTINE)payloadAddr, NULL, 
                 THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH, 
                 NULL, NULL, NULL, NULL);
```

This approach creates a thread that won’t show up in common enumeration routines, ideal for stealth execution in sensitive processes.

## 4. Hidden Execution Layers with `NtAllocateVirtualMemory` and `PAGE_WRITECOMBINE`

`NtAllocateVirtualMemory` is typically used for memory allocation, but combining it with specific memory protection flags, such as `PAGE_WRITECOMBINE`, allows malware to allocate hidden memory regions with non-standard properties. This can be further obscured by embedding code into sparse regions of virtual memory.

![image](https://github.com/user-attachments/assets/5bb6b9d2-fc7b-47b0-a367-7228e0727833)


### Advanced Use Cases with `PAGE_WRITECOMBINE` and Sparse Memory:

- **Sparse Memory Code Insertion**: By allocating memory with `PAGE_WRITECOMBINE` or `PAGE_NOACCESS`, you can create sparse memory regions that don’t trigger common memory inspection tools. Injected code hidden in non-contiguous memory addresses evades sequential memory scans.

- **Executable Combine Pages for Covert Shellcode**: `PAGE_WRITECOMBINE` combined with executable permissions enables optimized code execution in fragmented memory, bypassing most executable memory inspections that assume standard permissions like `PAGE_EXECUTE_READWRITE`.

### Code Example: Sparse Memory Allocation with Hidden Shellcode

```cpp
PVOID baseAddr = NULL;
SIZE_T regionSize = 0x1000; // 4 KB region with sparse structure

NtAllocateVirtualMemory(GetCurrentProcess(), &baseAddr, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_WRITECOMBINE);

memcpy(baseAddr + 0x500, shellcode, sizeof(shellcode)); // Hide shellcode in sparse region
```

Sparse memory allocation with unconventional permissions makes traditional memory forensics less effective.

## 5. Leveraging `RtlSetProcessIsCritical` for Persistent, System-Resilient Processes

Marking processes as critical with `RtlSetProcessIsCritical` provides persistence by locking the process against termination attempts from both user-mode and kernel-mode operations. This technique prevents system tampering by setting specific processes as irremovable, only terminating if explicitly removed by an administrator or by crashing the system.

![image](https://github.com/user-attachments/assets/2f673c1a-be3d-42db-9bb8-770c7aac260a)

### Advanced Use Cases with Critical Processes:

- **Multi-Stage Persistence**: By spawning multiple child processes with `RtlSetProcessIsCritical`, malware can set up a process hierarchy where terminating one process forces the others to reinitialize, creating a resilient persistence model.

- **Protection Against EDRs and Kill Signals**: Processes marked as critical can’t be killed by typical EDRs. Instead, they either fail to terminate the process or trigger a system crash, avoiding most automated containment mechanisms.

### Code Example: Persistent Process Setup with Critical Flag

```cpp
HANDLE hProcess = GetCurrentProcess();
RtlSetProcessIsCritical(TRUE, &hProcess, FALSE); // Set process as critical, preventing termination
```

By combining critical processes with stealth tactics, malware gains a robust persistence mechanism.

## 6. Memory Hook and Trace Blocking via `NtTraceControl` and `TraceProcessMemory`

`NtTraceControl` is a powerful function for managing trace sessions, and combined with undocumented tracing classes, it allows control over memory tracing and can selectively block trace access to specific memory regions.

### Advanced Use Cases with `NtTraceControl`:

- **Process-Level Memory Hook Blocking**: By blocking specific trace classes, malware can evade monitoring solutions that trace specific memory regions (e.g., process heaps).

![image](https://github.com/user-attachments/assets/03fa2a6c-4105-463a-b93f-077064a0970d)


- **Dynamic Trace Evasion for Anti-Analysis**: Adjusting memory traces on-the-fly based on sandbox indicators prevents static analysis and makes it difficult for memory-based forensic tools to track malware activity in real-time.

### Code Example: Trace Blocking for Memory Regions

```cpp
TRACE_CONTROL_INFORMATION traceControlInfo;
traceControlInfo.ControlCode = TRACE_CONTROL_DISABLE_TRACING;
traceControlInfo.TargetPID = GetCurrentProcessId();
NtTraceControl(TraceProcessMemory, &traceControlInfo, sizeof(traceControlInfo), NULL, 0);
```

Memory trace blocking directly undermines tools that rely on continuous memory introspection, effectively cloaking malware actions.

## 7. Token Manipulation with `NtOpenProcessTokenEx` and `NtDuplicateToken`

Manipulating access tokens of high-privilege processes (like `SYSTEM`) allows malware to execute with elevated permissions without triggering typical privilege escalation alerts. `NtOpenProcessTokenEx` and `NtDuplicateToken` can clone and reuse privileged tokens stealthily.

![image](https://github.com/user-attachments/assets/75f499dd-47ab-40ef-afe3-3df5dad907c8)


### Advanced Use Cases for Token Manipulation:

- **Privilege Escalation without Elevation**: Hijack high-privilege tokens and apply them to malicious processes to bypass User Account Control (UAC) and EDR checks.

- **Impersonation of Trusted Processes**: Clone and apply tokens from trusted processes like `lsass.exe` for stealthy actions under a trusted process context.

### Code Example: SYSTEM Token Impersonation

```cpp
HANDLE hToken;
NtOpenProcessTokenEx(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);
SetThreadToken(NULL, hToken);
```

By hijacking and impersonating high-privilege tokens, malware can evade security checks tied to process privileges.

## 8. Process Injection with `NtMapViewOfSection` in Suspended State

`NtMapViewOfSection` allows mapping memory across process boundaries, providing a stealthy way to inject code. Injecting in suspended state helps prevent detection, allowing code to run without immediately executing.

![image](https://github.com/user-attachments/assets/30d17d2d-0dd8-4cda-965a-6a05cc1f4001)


### Advanced Use Cases for Suspended Injection:

- **Silent Memory Injection**: Map sections into target processes without executing code, avoiding thread-based monitoring and immediate scans.

- **Delayed Execution in Target Process**: Run injected code only when specific conditions are met, reducing visibility.

### Code Example: Mapping Hidden Section into Target Process

```cpp
HANDLE hSection;
NtMapViewOfSection(hSection, hTargetProcess, &baseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
```

This approach maps memory invisibly, bypassing user-mode API hooks typically monitored by EDRs.

## 9. Heap Hiding with `RtlCreateHeap` and Custom Flags

`RtlCreateHeap` can create hidden memory regions within processes, avoiding common heap scanning tools. Setting custom flags can hide code in private heaps that are rarely inspected.

![image](https://github.com/user-attachments/assets/5d747bd6-e224-43db-b2f0-1b25d892b014)


### Advanced Use Cases for Hidden Heaps:

- **Isolated Code Storage**: Store payloads in private heaps that standard user-mode heap inspections don’t target.

- **Heap-based Anti-Forensics**: Cause controlled corruption in specific environments (e.g., in sandboxed debugging) by creating heaps with specific flags that resist inspection.

### Code Example: Creating a Private Heap

```cpp
PVOID hHeap = RtlCreateHeap(HEAP_CREATE_ALIGN_16 | HEAP_GENERATE_EXCEPTIONS, NULL, 0, 0, NULL, NULL);
RtlAllocateHeap(hHeap, 0, payloadSize);
```

This makes the payload hard to find, as it’s isolated from the standard heap structure.

## 10. ETW Patching with `EtwEventWrite`

Many security tools use Event Tracing for Windows (ETW) to monitor system events. By directly patching or disabling `EtwEventWrite`, malware can prevent events from being logged without altering ETW providers.

![image](https://github.com/user-attachments/assets/0f2a40fb-fdc8-47be-a499-ffbaba79d02d)


### Advanced Use Cases for ETW Patching:

- **Silencing Specific Logs**: Patch `EtwEventWrite` to ignore critical events, especially in high-sensitivity areas like security audits.

- **Anti-Forensics in Real-Time Logging**: Disrupt logging in real-time without disabling ETW, minimizing footprints during execution.

### Code Example: Disabling `EtwEventWrite`

```cpp
BYTE patch[] = { 0xC3 }; // `RET` instruction to disable function
memcpy(EtwEventWrite, patch, sizeof(patch));
```

This approach prevents ETW from recording specific events, eliminating a primary source of EDR data.

## 11. Registry Manipulation with `NtSetValueKey`

`NtSetValueKey` allows malware to manipulate registry keys directly, avoiding higher-level registry APIs that EDRs often monitor. This helps establish persistence or disable security policies without detection.

![Uploading image.png…]()


### Advanced Use Cases for Registry Persistence:

- **Stealthy Persistence Keys**: Modify `Run` or `RunOnce` registry entries to add persistence without flagging common monitoring tools.

- **Disabling Security Policies**: Modify security-related registry keys like disabling Windows Defender through direct registry writes.

### Code Example: Setting a Persistence Key

```cpp
HKEY hKey;
NtSetValueKey(hKey, &keyName, 0, REG_SZ, payloadPath, pathSize);
```

By writing directly to the registry, malware can bypass user-mode registry monitoring hooks.

## 12. Hook Obfuscation with `NtProtectVirtualMemory`

Using `NtProtectVirtualMemory`, malware can unhook functions in protected DLLs by modifying their memory protections and overwriting hooks set by EDRs.

![image](https://github.com/user-attachments/assets/09ffaf64-a5d4-4a57-832d-10cf29e575f3)


### Advanced Use Cases for Hook Evasion:

- **Unhooking API Functions**: Restore the original code of critical functions like `NtOpenProcess` to prevent EDR monitoring.

- **Self-Protection Against Memory Tampering**: Use this to protect regions of memory, blocking attempts to re-hook.

### Code Example: Unhooking Function

```cpp
NtProtectVirtualMemory(hProcess, &apiAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(apiAddr, originalBytes, sizeof(originalBytes));
NtProtectVirtualMemory(hProcess, &apiAddr, &regionSize, oldProtect, &oldProtect);
```

This prevents the EDR from capturing API calls, allowing stealthy execution.

## 13. DeviceIoControl-Based Payload Execution

Certain drivers expose functionality through `DeviceIoControl`, allowing malware to execute payloads in a lower-level context without creating threads or direct kernel interactions.

![image](https://github.com/user-attachments/assets/0fe7ec96-c1c4-443a-97c3-85c56de517fb)


### Advanced Use Cases with DeviceIoControl:

- **Privileged Execution via Third-Party Drivers**: Exploit less-secure drivers to perform privileged actions without full kernel access.

- **Indirect Code Execution in Kernel Context**: Use drivers to run code indirectly, evading process-based detection.

### Code Example: Sending Payload via IOCTL

```cpp
DeviceIoControl(hDevice, IOCTL_CODE, inputBuffer, sizeof(inputBuffer), outputBuffer, sizeof(outputBuffer), &bytesReturned, NULL);
```

This leverages low-level drivers to perform actions that bypass common process monitoring.

## 14. Fileless Execution Using `NtAllocateVirtualMemory`

Using `NtAllocateVirtualMemory` to create executable, memory-only regions helps achieve fileless execution, which evades signature-based detection and anti-virus.

![image](https://github.com/user-attachments/assets/7580345f-49a4-403e-8ec1-b04823d8308b)


### Advanced Use Cases for Fileless Malware:

- **Stealthy Payload Execution in Memory**: Allocate memory and execute without writing to disk, leaving no file artifacts.

- **Self-Modifying Code in Memory**: Load self-contained, mutable payloads that adapt dynamically, bypassing static analysis.

### Code Example: Memory Allocation for Fileless Payload

```cpp
NtAllocateVirtualMemory(GetCurrentProcess(), &baseAddr, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(baseAddr, payload, payloadSize);
```

By avoiding disk usage, this technique greatly reduces the forensic footprint.

## 15. Anti-Debugging with `NtSetInformationThread` and `ThreadHideFromDebugger`

Setting `ThreadHideFromDebugger` on specific threads prevents them from being inspected by debuggers, frustrating analysis and hindering EDRs that rely on debugging techniques.

![image](https://github.com/user-attachments/assets/525f55a9-860c-4096-be0e-f2b7d260af5e)


### Advanced Use Cases for Anti-Debugging:

- **Invisible Threads for Payload Execution**: Run critical code in hidden threads that are difficult to detect and enumerate.

- **Protection Against Analysis**: Disrupt memory-based debugging, making analysis impractical.

### Code Example: Hiding Threads

```cpp
NtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, 0);
```

Hidden threads evade monitoring from tools that rely on debugging hooks.

## 16. Named Pipe Impersonation with `ImpersonateNamedPipeClient`

Using `ImpersonateNamedPipeClient` can allow malware to impersonate clients connected to a named pipe, gaining access to higher-privilege tokens in certain scenarios.

![image](https://github.com/user-attachments/assets/547c04d7-4e25-49e4-b45f-df3843555b87)


### Advanced Use Cases for Impersonation:

- **Privilege Escalation via Trusted Pipes**: Impersonate clients on trusted pipes to elevate permissions.

- **Cross-Process Evasion**: Use impersonation to interact with other processes stealthily.

### Code Example: Named Pipe Impersonation

```cpp
HANDLE hPipe = CreateNamedPipe(...);
ImpersonateNamedPipeClient(hPipe);
```

This enables indirect access to elevated privileges.

## 17. Thread Injection with `NtQueueApcThread`

Using `NtQueueApcThread`, malware can queue asynchronous procedure calls (APCs) to inject code into another process’s existing threads, avoiding new thread creation.

![image](https://github.com/user-attachments/assets/25a335f6-2cd6-435b-ad34-e6d78b3867a2)


### Advanced Use Cases for APC Injection:

- **Silent Injection**: Execute code within existing threads of a target process, avoiding thread creation that EDRs monitor.

- **Stealthy Execution Flow**: Trigger payloads at specific points by scheduling APCs on benign threads.

### Code Example: APC Injection

```cpp
NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)payloadAddr, NULL, NULL, NULL);
```

APCs allow code to run as part of a legitimate process flow, evading detection.

## Conclusion

These advanced techniques, leveraging deep and often undocumented Windows internals, provide a highly effective toolkit for evasion, persistence, and anti-forensics. From hidden memory allocations and kernel-level injection to opaque threading and critical process settings, this article outlines strategies for attackers to bypass monitoring solutions at every level.

These techniques highlight the need for defensive tools to advance in response, particularly in detecting non-traditional memory allocations and hidden kernel-level manipulation. As always, these strategies are for authorized, controlled environments, as unauthorized use is both illegal and unethical.

---

## Disclaimer

The content here is provided strictly for educational and authorized red teaming purposes. Unauthorized use may result in severe legal consequences.
