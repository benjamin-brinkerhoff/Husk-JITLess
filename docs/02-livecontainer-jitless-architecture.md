# Technical Analysis: LiveContainer's JIT-Less Mode & Integration with Husk-JITLess

This document explains how [LiveContainer](https://github.com/LiveContainer/LiveContainer) runs guest binaries without JIT using a developer certificate, and how **Husk-JITLess** adapts this pipeline to Android `arm64-v8a` ELF shared libraries.

## 1. LiveContainer's JIT-Less Pipeline
1. **Mach-O `MH_DYLIB` Conversion (`LCMachOUtils.m`)**: Converts guest binaries to `MH_DYLIB` and injects `LC_ID_DYLIB`.
2. **Developer Certificate Import (`LCSharedUtils.m`)**: Reads the host app's `com.apple.developer.team-identifier` entitlement and imports the user's `.p12` certificate (either directly or from SideStore/AltStore's shared App Group).
3. **On-Device Code Signing (`ZSign/zsign.mm`)**: Generates an `LC_CODE_SIGNATURE` SuperBlob (`CS_CodeDirectory` v20400 with SHA-256 16 KiB page hashes and Team ID) signed with the user's developer certificate, then writes to a temporary file, unlinks the original, and renames the signed file into place so XNU creates a clean vnode before calling `dlopen()`.

## 2. Husk-JITLess 3-Stage Pipeline
1. **Stage 1 — Ahead-Of-Time ELF64-to-Mach-O `MH_DYLIB` Transmutation (`src/elf2macho.c`)**:
   - Aligns `PT_LOAD` segments to 16 KiB pages, runs AOT instruction translation (`x18`, `tpidr_el0`, `ctr_el0`, `svc #0`) in `__TEXT`, emits trampolines in `__TEXT,__stubs_aot`, and creates `__DATA,__husk_host` and `__DATA,__elf_meta`.
2. **Stage 2 — On-Device Developer Certificate Signing (`src/jitless_signer.c`)**:
   - Signs the generated `MH_DYLIB` with the user's `.p12` certificate (matching Team ID) and performs atomic file replacement.
3. **Stage 3 — `dlopen()` + In-Place `__DATA` ELF Relocation (`src/jitless_linker.c`)**:
   - Loads the signed `.dylib` via `dlopen()`, populates `__DATA,__husk_host`, and applies all ELF dynamic relocations (`RELA`, `RELR`, `JMPREL`) inside writable `__DATA` against `src/bionic_shim.c` and `src/jni_dvm.c`.
