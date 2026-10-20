# Technical Analysis: LiveContainer's JIT-Less Mode & Integration in Husk-JITLess

This document explains how [LiveContainer](https://github.com/LiveContainer/LiveContainer) runs guest code on iOS without JIT using a developer certificate, and how **Husk-JITLess** applies this pipeline to Android `arm64-v8a` ELF shared libraries.

## 1. LiveContainer's JIT-Less Pipeline
1. **Mach-O `MH_DYLIB` Conversion (`LCMachOUtils.m`)**: Converts guest binaries to `MH_DYLIB` dynamic libraries with `LC_ID_DYLIB`.
2. **Developer Certificate Signing (`ZSign/zsign.mm`)**: Uses an imported `.p12` Apple Developer Certificate (or SideStore/AltStore shared certificate) to embed an `LC_CODE_SIGNATURE` SuperBlob (`CS_CodeDirectory` v20400 with SHA-256 16 KiB page hashes and matching Team ID).
3. **Atomic File Replacement (`zsign.mm`)**: Writes the signed Mach-O to a temporary file, unlinks the old file, and renames the signed file into place so the kernel validates the fresh vnode.
4. **Native Loading (`LCBootstrap.m`)**: Calls `dlopen()` so `dyld` maps `__TEXT` as `PROT_READ | PROT_EXEC` under standard Library Validation without requiring a debugger or JIT.

## 2. Husk-JITLess 3-Stage Pipeline for Android `.so` Libraries
1. **Stage 1 — Ahead-Of-Time ELF64-to-Mach-O Transmutation (`src/elf2macho.c` & `src/a64_rewriter.c`)**:
   - Aligns ELF `PT_LOAD` segments to 16 KiB pages, translates `x18`, `mrs tpidr_el0`, `mrs ctr_el0`, and `svc #0` AOT inside `__TEXT`, emits trampolines into `__TEXT,__stubs_aot`, and embeds `__DATA,__husk_host` and `__DATA,__elf_meta`.
2. **Stage 2 — On-Device Developer Certificate Signing (`src/jitless_signer.c`)**:
   - Signs the generated `.aot.dylib` with the user's `.p12` developer certificate and performs atomic file replacement.
3. **Stage 3 — `dlopen()` & In-Place `__DATA` Relocation (`src/jitless_linker.c`)**:
   - Loads the signed `.aot.dylib` via `dlopen()`, populates `__DATA,__husk_host`, and applies all ELF dynamic relocations (`RELA`, `RELR`, `JMPREL`) inside writable `__DATA` against `src/bionic_shim.c`.
