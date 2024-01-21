# Maldev Academy - RemoteTLSCallbackInjection

## Quick Links

[Maldev Academy Home](https://maldevacademy.com)

[Maldev Academy Syllabus](https://maldevacademy.com/syllabus)

## Related Maldev Academy Modules

[New Module 34: TLS Callbacks For Anti-Debugging](https://maldevacademy.com/new/modules/34)

[New Module 35: Threadless Injection](https://maldevacademy.com/new/modules/35)

## Overview

This method utilizes TLS callbacks to execute a payload without spawning any threads in a remote process. This method is inspired by [Threadless Injection](https://github.com/CCob/ThreadlessInject/tree/master) as RemoteTLSCallbackInjection does not invoke any API calls to trigger the injected payload. 

## Implementation Steps

The PoC follows these steps:

1. Create a suspended process using the `CreateProcessViaWinAPIsW` function (i.e. `RuntimeBroker.exe`).
2. Fetch the remote process image base address followed by reading the process's PE headers.
3. Fetch an address to a TLS callback function.
4. Patch a fixed shellcode (i.e. [g_FixedShellcode](https://github.com/Maldev-Academy/RemoteTLSCallbackInjection/blob/main/RemoteTLSCallbackInjection/main.c#L56)) with runtime-retrieved values. This shellcode is responsible for restoring both original bytes and memory permission of the TLS callback function's address.
5. Inject both shellcodes: `g_FixedShellcode` and the main payload.
6. Patch the TLS callback function's address and replace it with the address of our injected payload.
7. Resume process.

The `g_FixedShellcode` shellcode will then make sure that the main payload executes only once by restoring the original TLS callback's original address before calling the main payload. A TLS callback can execute multiple times across the lifespan of a process, therefore it is important to control the number of times the payload is triggered by restoring the original code path execution to the original TLS callback function.

### Demo

The following image shows our implementation, `RemoteTLSCallbackInjection.exe`, spawning a `cmd.exe` as its main payload.

<img width="1200px" alt="demo" src="https://github.com/Maldev-Academy/RemoteTLSCallbackInjection/assets/111295429/1b1b2c9c-17af-490c-8d77-ea11f53ccfaf">




