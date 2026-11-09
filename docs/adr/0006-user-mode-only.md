# 0006: User-mode only

Date: 2026-11-09. Status: Accepted.

## Context

System Informer gets much of its depth from its kernel driver (KSystemInformer), which needs Microsoft signing and is the reason some antivirus products flag it. A kernel driver for Bilby would need an EV certificate, Microsoft attestation signing and a lot of care, and it would be a large risk on a stranger's computer.

## Decision

Bilby uses documented user-mode APIs only: Win32, COM, WMI, the registry and files. No driver, no undocumented `Nt*` information classes unless there's no documented alternative and the ADR is updated.

## Consequences

- No hidden-process detection via kernel structures, no handle or thread inspection of protected processes, no kernel callback or hook enumeration.
- Some processes (protected and PPL processes) only give us their image path. That's enough for Bilby's rules.
- Bilby will never be flagged as a "hack tool" for loading a driver.
