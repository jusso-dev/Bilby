# Research: System Informer

Read on 9 November 2026 at commit `32ef60573927b26a153df29c258e63db15ab4f7c` of https://github.com/winsiderss/systeminformer.

## Licence

`LICENSE.txt` is the MIT licence, "Copyright (c) 2022 Winsider Seminars & Solutions, Inc." `COPYRIGHT.txt` lists bundled third-party libraries under their own terms (Mini-XML under LGPL with a static linking exception, PCRE and others). MIT would let us copy code with the notice kept. We haven't copied any. Bilby is Rust and System Informer is C, so copying wouldn't save much anyway. If anyone does adapt code later, keep the Winsider notice in the file header and add it to `NOTICE`. Don't copy anything from the third-party libraries listed in `COPYRIGHT.txt` without checking their own licence.

## What System Informer is

A process explorer for Windows (formerly Process Hacker). The main pieces:

| Folder | What it does |
|---|---|
| `SystemInformer/` | The app. Providers that poll the system (`procprv.c` processes, `srvprv.c` services, `netprv.c` network, `modprv.c` modules, `hndlprv.c` handles, `thrdprv.c` threads, `memprv.c` memory) and the list views and property pages over them (`prpgtok.c` tokens, `prpgmod.c` modules, `srvprp.c` services, and so on). |
| `phlib/` | The shared library. `verify.c` (Authenticode and catalog signature checks), `imgcoherency.c` (compares a process image in memory with the file on disk), `mapimg.c` (PE parsing), `native*.c` (wrappers over native APIs), `svcsup.c` (services). |
| `phnt/` | Native API headers. |
| `KSystemInformer/`, `kphlib/` | The kernel driver and its user-mode client. Gives handle, thread and protected-process access that user mode can't get. |
| `plugins/` | `OnlineChecks` (hash lookups and uploads to VirusTotal and other services), `ExtendedServices` (service triggers, recovery, dependencies), `NetworkTools` (ping, traceroute, whois, GeoIP), `ExtendedTools` (disk, network and GPU stats, ETW), `HardwareDevices`, `WindowExplorer`, `UserNotes`, `Updater` and others. |

It's a tool for people who already know what `svchost.exe` should look like. It shows everything and colours rows, and leaves the judgement to the user. Bilby takes the opposite approach: show little, decide carefully, explain in plain words.

## Signals System Informer surfaces, and whether Bilby can reproduce them in user mode

| Signal | Where in System Informer | User mode without a driver? | Bilby plan |
|---|---|---|---|
| Process image path, parent, start time, user | `procprv.c` | Yes. Toolhelp snapshot plus `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` and `QueryFullProcessImageNameW`. Works for most processes, including protected ones for the path. | Processes issue |
| Signature status and signer of each process (the "Verified signer" column, unsigned rows highlighted) | `procprv.c` calls `PhVerifyFileCached`, implemented in `phlib/verify.c` with `WinVerifyTrust` and catalog lookup through `CryptCATAdmin*` | Yes. Same APIs. | Signature helper issue. Idea borrowed: check embedded signature first, then fall back to the system catalogs, because most Windows binaries are catalog-signed and would otherwise look unsigned. |
| Packed or obfuscated images (few imports) | `procprv.c` (`IsPacked`, `ImportModules`, `ImportFunctions`) via `mapimg.c` | Yes, by parsing the PE on disk with a Rust PE crate. | Considered. Low-confidence on its own, so only used to raise confidence on an already-flagged unsigned file in a user-writable folder. Later issue, not MVP. |
| Image coherency (memory image differs from disk: hollowing) | `phlib/imgcoherency.c` | Partly. Needs `PROCESS_VM_READ` on the target, which fails for protected and elevated processes when Bilby isn't admin, and is the sort of behaviour that makes AV suspicious of a tool. | Not in Bilby. Too noisy for non-technical users and out of step with ADR 0006. |
| Hidden or zombie processes | `hidnproc.c` | No reliable user-mode method. | Not in Bilby. |
| Elevated, service, .NET, suspended, immersive process highlighting | `settings.c` colour settings, `procprv.c` | Yes, mostly. | Used as context in the helper view, not as findings. |
| Token: integrity level, privileges, elevation | `prpgtok.c` | Yes for our own user's processes. | Context only. |
| Loaded modules (DLLs) and their signatures | `modprv.c`, `prpgmod.c` | Partly. Module lists need `PROCESS_VM_READ`. | Not in MVP. Possible later issue for unsigned DLLs loaded from user-writable folders into signed processes. |
| Services, their binaries, start type, triggers | `srvprv.c`, `plugins/ExtendedServices` | Yes. SCM APIs and the `Services` registry key. | Persistence: services issue |
| Network connections per process | `netprv.c` | Yes. `GetExtendedTcpTable` and `GetExtendedUdpTable` with owner PID. | Network issue |
| Handles | `hndlprv.c` | Mostly needs the driver or `SeDebugPrivilege`. | Not in Bilby. |
| Online hash reputation (VirusTotal and others) | `plugins/OnlineChecks/api.c` (`/api/v3/files/` lookups), `upload.c` | Yes. | Reputation issue. Idea borrowed: hash lookup first, upload never. Bilby goes further: off by default, hash only, the user's own API key. |
| Autoruns-style startup list | Not a dedicated view in System Informer. Services yes, Run keys and tasks no. | Yes. | Persistence issues, modelled on what Sysinternals Autoruns covers (our own implementation, no Autoruns code or binaries). |

## Ideas borrowed (concepts only, no code)

1. **Embedded signature, then catalog fallback** for Authenticode (from `phlib/verify.c`).
2. **Cache verification results by file identity** (path plus size plus last-write time) so a scan doesn't verify the same `svchost.exe` 80 times (from `PhVerifyFileCached`).
3. **Hash lookup before upload, and treat "not found" as unknown, not clean** (from `plugins/OnlineChecks`).
4. **Highlight unsigned and packed images** as the two strongest cheap signals, then let other facts decide (from the process list colour scheme).
5. **Show the signer's name, not just "signed"**, because a valid signature from an unknown company means something different from one from Microsoft.
6. **Separate providers (gathering) from views (judging)**. System Informer's providers poll and its UI decides how to show things. Bilby's collectors and rules follow the same split.

## What we're not taking

- The kernel driver and anything that depends on it.
- Process termination, suspension, memory editing, handle closing, injection or debugging. Bilby isn't a power tool.
- File uploads to online services.
- Any code. If that changes, see the licence section above.
