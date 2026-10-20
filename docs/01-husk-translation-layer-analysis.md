# Technical Analysis: How Husk's Android-to-iOS Translation Layer Works

This document details how [Leviidev/Husk](https://github.com/Leviidev/Husk) implements its native Android-to-iOS translation layer (`src/translation-layer/` and `src/translation-layer-next/`).

## 1. Core Subsystems in Husk
1. **APK Reader & 16 KiB Page Planner (`husk-tl-zip.c`, `husk-tl-elf.c`)**:
   - Extracts `lib/arm64-v8a/*.so`, `classes*.dex`, `AndroidManifest.xml`, and `resources.arsc` directly from the base APK and any split APKs.
   - Lays out ELF `PT_LOAD` segments onto 16 KiB (`0x4000`) iOS pages (`tl_page_plan`).
2. **Guest Dynamic Linker (`husk-tl-ld.c`)**:
   - Resolves `DT_NEEDED` dependencies in breadth-first order matching Android's linker scoping.
   - Applies AArch64 ELF relocations (`R_AARCH64_RELATIVE`, `R_AARCH64_ABS64`, `R_AARCH64_GLOB_DAT`, `R_AARCH64_JUMP_SLOT`, `R_AARCH64_TLSDESC`, `R_AARCH64_IRELATIVE`), Android packed relocations (`DT_ANDROID_RELA` / `APS2`), and `DT_RELR`.
3. **AArch64 Instruction Adaptation (`husk-tl-a64.c`, `husk-tl-ld.c`)**:
   - **`x18` Register Virtualization**: Redirects instructions referencing `x18` (reserved by Apple on Darwin) to per-thread storage in Darwin's TSD (`tpidrro_el0`).
   - **`mrs Xt, tpidr_el0`**: Rewritten to `adrp` addressing a Thread Control Block holding the stack guard cookie at `+0x28`.
   - **`mrs Xt, ctr_el0`**: Rewritten to load the 64-byte cache line constant (`0x8444c004`).
   - **`svc #0`**: Rewritten to branch to `tl_svc_common` -> `tl_linux_syscall`.
4. **Bionic-on-Darwin Shim (`husk-tl-bionic*.c`)**:
   - Translates `errno` values, signal numbers, 40-byte Bionic `pthread_mutex_t` structures, `stat`/`dirent` layouts, and Android system properties (`__system_property_get`).
5. **64-Bit Dalvik Interpreter & HLE JNI (`husk-tl-dvm.c`, `husk-tl-jni.c`)**:
   - Replaces ART (which requires 32-bit compressed pointers in the low 4 GiB reserved by XNU's `__PAGEZERO`) with a 64-bit Dalvik bytecode interpreter sharing `jobj *` pointers with an HLE `JNIEnv` / `JavaVM` and native Metal/ANGLE/MoltenVK/CoreAudio drivers.
