## Introduction
In modern enterprise environments, employees frequently use third-party and open-source applications such as KeePass, FileZilla, and other utility tools to support daily operations. These applications often rely on multiple Dynamic Link Libraries (DLLs) to load functionality at runtime. While DLL-based modular architecture improves performance and code reuse, improper configuration of DLL loading mechanisms can introduce security risks. If an attacker gains write access to a directory involved in the DLL search order, it may be possible to replace or introduce a malicious DLL. When the application loads this DLL, the attacker-controlled code executes within the context of the legitimate process.

This can potentially lead to:

- Code execution inside trusted processes  
- Privilege escalation (if the application runs with elevated rights)  
- Reverse shell execution  
- EDR evasion attempts  
- Lateral movement opportunities  

This research explores how Windows DLL loading works, how the DLL search order can be abused in misconfigured environments, and how defenders can detect and prevent such abuse.

## What is a DLL?
A DLL (Dynamic Link Library) is a file that contains reusable code and functionality that can be shared across multiple programs. Instead of embedding all functionality inside a single executable (EXE), Windows applications load required DLLs at runtime. This modular design reduces redundancy, improves memory efficiency, and simplifies maintenance. Windows itself relies heavily on DLLs to provide shared system functionality. Without DLLs, each application would need to include duplicate copies of common code, resulting in significant resource waste and increased system overhead.

## DLL Internals

A DLL (Dynamic Link Library) is not merely a passive file containing reusable code. When loaded into a process, Windows maps the DLL into memory and may execute code inside it as part of the initialization sequence.

Understanding this execution behavior is critical when analyzing DLL hijacking scenarios.

---

### What Does "Loading a DLL" Actually Mean?

When a DLL is loaded:

1. The operating system maps the DLL into the process’s virtual memory.
2. The loader resolves imported functions.
3. Relocations are applied if necessary.
4. The entry point function `DllMain()` is executed automatically.

It is important to note that Windows does **not** simply read the file — it executes code inside the DLL during the loading phase.

---

### The DllMain Function

Every standard DLL contains an entry point called DllMain:

#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,      // Handle to DLL module
    DWORD fdwReason,         // Reason for calling function
    LPVOID lpReserved        // Reserved
)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // Executed when the DLL is loaded into a process
            // Initialize global resources here
            break;

        case DLL_THREAD_ATTACH:
            // Executed when a new thread is created
            // Perform thread-specific initialization
            break;

        case DLL_THREAD_DETACH:
            // Executed when a thread exits cleanly
            // Perform thread-specific cleanup
            break;

        case DLL_PROCESS_DETACH:
            // Executed when the DLL is unloaded
            // Cleanup global resources
            break;
    }

    return TRUE;  // Successful load
}

### Understanding the Four DllMain Cases

The Windows loader invokes `DllMain()` automatically and passes one of four official notifications via the `fdwReason` parameter.

#### 1. DLL_PROCESS_ATTACH
Triggered when the DLL is loaded into a process. This is the most critical notification in DLL hijacking scenarios because any initialization code placed here executes immediately when the DLL is mapped into memory.

#### 2. DLL_THREAD_ATTACH
Triggered whenever a new thread is created within the process. Used for thread-specific initialization logic.

#### 3. DLL_THREAD_DETACH
Triggered when a thread exits cleanly. Allows thread-level cleanup operations.

#### 4. DLL_PROCESS_DETACH
Triggered when the DLL is unloaded or when the process terminates. Used for releasing global resources.

---

From a security perspective, `DLL_PROCESS_ATTACH` is the most significant case. If a malicious DLL is loaded due to search order abuse, code placed inside this block executes automatically within the target process context.


