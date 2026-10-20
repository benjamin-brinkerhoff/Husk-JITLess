# Technical Analysis: How Husk's Android-to-iOS Translation Layer Works

This document details how [Leviidev/Husk](https://github.com/Leviidev/Husk) implements its native Android-to-iOS translation layer (`src/translation-layer/` and `src/translation-layer-next/`).

## 1. Core Subsystems

1. **APK Extraction & 16 KiB Page Planner (`husk-tl-zip.c`, `husk-tl-elf.c`)**:
   - Extracts `lib/arm64-v8a/*.so` and `classes*.dex` directly from the APK and split bundles.
   - Lays out ELF `PT_LOAD` segments onto 16 KiB (`0x4000`) iOS hardware page boundaries (`tl_page_plan`).
2. **Guest Dynamic Linker (`husk-tl-ld.c`)**:
   - Resolves `DT_NEEDED` dependencies in breadth-first order matching Android Bionic scoping.
   - Processes `R_AARCH64_RELATIVE`, `R_AARCH64_ABS64`, `R_AARCH64_GLOB_DAT`, `R_AARCH64_JUMP_SLOT`, `R_AARCH64_TLSDESC`, `R_AARCH64_IRELATIVE`, Android `APS2` packed relocations, and `DT_RELR`.
3. **AArch64 Instruction Adaptation (`husk-tl-a64.c`, `husk-tl-ld.c`)**:
   - **`x18` Register Virtualization**: Apple reserves `x18` as the platform register, while Android compilers allocate `x18` as a scratch register. Husk decodes instructions (`a64_gpr_fields`) and redirects `x18` operations to a per-thread TSD slot (`tpidrro_el0`).
   - **Thread Pointer (`mrs Xt, tpidr_el0`)**: Rewritten to `adrp` addressing a Thread Control Block holding the stack guard cookie at `+0x28`.
   - **Cache Type Register (`mrs Xt, ctr_el0`)**: Rewritten via stub to load `0x8444c004` (64-byte cache line size).
   - **Direct Linux Syscalls (`svc #0`)**: Rewritten via stub to invoke `tl_svc_common` -> `tl_linux_syscall`.
4. **Bionic-on-Darwin Shim (`husk-tl-bionic*.c`)**:
   - Maps Android's `libc.so`, `libm.so`, `libdl.so`, `liblog.so`, and `libandroid.so` onto Darwin (`TL_DIRECT`, `TL_WRAP`, `TL_DATA`), translating Linux `errno` and signal numbers and wrapping 40-byte Bionic `pthread_mutex_t` instances around Darwin pthreads.
5. **64-Bit Dalvik Interpreter & HLE JNI (`husk-tl-dvm.c`, `husk-tl-jni.c`)**:
   - Replaces ART (which requires 32-bit low-4 GiB heap mappings blocked by Darwin's `__PAGEZERO`) with a 64-bit Dalvik bytecode interpreter and HLE `JNIEnv`/`JavaVM` bridged to UIKit, Metal, CoreAudio, ANGLE (OpenGL ES), and MoltenVK (Vulkan).
