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

- **Dynamic Trace Evasion for Anti-Analysis**: Adjusting memory traces on-the-fly based on sandbox indicators prevents static analysis and makes it difficult for memory-based forensic tools to track malware activity in real-time.

### Code Example: Trace Blocking for Memory Regions

```cpp
TRACE_CONTROL_INFORMATION traceControlInfo;
traceControlInfo.ControlCode = TRACE_CONTROL_DISABLE_TRACING;
traceControlInfo.TargetPID = GetCurrentProcessId();
NtTraceControl(TraceProcessMemory, &traceControlInfo, sizeof(traceControlInfo), NULL, 0);
```

Memory trace blocking directly undermines tools that rely on continuous memory introspection, effectively cloaking malware actions.

---

## Conclusion

These advanced techniques, leveraging deep and often undocumented Windows internals, provide a highly effective toolkit for evasion, persistence, and anti-forensics. From hidden memory allocations and kernel-level injection to opaque threading and critical process settings, this article outlines strategies for attackers to bypass monitoring solutions at every level.

These techniques highlight the need for defensive tools to advance in response, particularly in detecting non-traditional memory allocations and hidden kernel-level manipulation. As always, these strategies are for authorized, controlled environments, as unauthorized use is both illegal and unethical.

---

## Disclaimer

The content here is provided strictly for educational and authorized red teaming purposes. Unauthorized use may result in severe legal consequences.

