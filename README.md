# Husk-JITLess

**Run Android APKs (`arm64-v8a` + Dalvik DEX) natively on iOS without requiring JIT**, combining the user-space Android translation layer architecture of [Leviidev/Husk](https://github.com/Leviidev/Husk) with the Developer-Certificate Mach-O code-signing and `dlopen` pipeline of [LiveContainer](https://github.com/LiveContainer/LiveContainer).

## Overview

[Husk](https://github.com/Leviidev/Husk) runs 64-bit Android games and apps on iOS via an in-process translation layer (`src/translation-layer-next/` and `src/translation-layer/`), avoiding full-system QEMU TCG emulation. However, upstream Husk requires **JIT** (`husk-tl-xmem.c`) because its custom ELF loader maps raw `.so` segments into anonymous memory at runtime and patches AArch64 instructions in-memory across a split-W^X view.

[LiveContainer](https://github.com/LiveContainer/LiveContainer) eliminates the JIT requirement on iOS by converting guest binaries into `MH_DYLIB` Mach-O dynamic libraries (`LCMachOUtils.m`), signing them on-device using **ZSign** (`ZSign/zsign.mm`) with the user's Apple Developer Certificate (`.p12` imported directly or from SideStore/AltStore), and loading them natively through `dlopen()` (`LCBootstrap.m`).

**Husk-JITLess** unifies both architectures so Android APKs can run on iOS **with zero JIT required**:

| Subsystem | Upstream Husk ([Leviidev/Husk](https://github.com/Leviidev/Husk)) | LiveContainer ([LiveContainer/LiveContainer](https://github.com/LiveContainer/LiveContainer)) | **Husk-JITLess (This Repository)** |
|---|---|---|---|
| **Executable Code Mapping** | Runtime `BreakGetJITMapping` + `vm_remap` RW/RX pair (`husk-tl-xmem.c`) | Converts `MH_EXECUTE` to `MH_DYLIB` (`LCMachOUtils.m`) and calls `dlopen()` (`LCBootstrap.m`) | **AOT ELF64-to-Mach-O `MH_DYLIB` converter** (`src/elf2macho.c`) aligned to 16 KiB iOS pages and loaded via `dlopen()` |
| **Code Signing / Library Validation** | Requires attached debugger (`StikDebug`) or `MAP_JIT` | On-device `ZSign` (`ZSign/zsign.mm`) with user's `.p12` dev cert + atomic file replacement | **On-device Mach-O signer** (`src/jitless_signer.c`) emitting `LC_CODE_SIGNATURE` (CodeDirectory v20400 SHA-256 16 KiB page hashes + Team ID + CMS blob) + atomic rename |
| **AArch64 Instruction Adaptation (`x18`, `tpidr_el0`, `ctr_el0`, `svc #0`)** | Patched at load time into the `rw` alias of the split-W^X JIT arena (`husk-tl-ld.c`) | N/A (guest apps are already Darwin ARM64 Mach-O binaries) | **Translated Ahead-Of-Time (AOT)** into `__TEXT` and `__TEXT,__stubs_aot` (`src/a64_rewriter.c`) before code signing; runtime callbacks reached via PC-relative loads from `__DATA,__husk_host` |
| **Dynamic Relocations (`RELA`, `APS2`, `RELR`, `JMPREL`)** | Applied through `rw` alias of split-W^X memory; requires `adrp`/`adr` view-delta rewriting | Handled by `dyld` (`LC_DYLD_CHAINED_FIXUPS`) | **Applied in-place inside writable `__DATA`** (`src/jitless_linker.c`) after `dlopen()` using preserved `__DATA,__elf_meta` tables; zero `TEXTREL` and zero split-view `adrp` delta needed |
| **C Library & Syscall ABI** | Bionic-on-Darwin shim (`husk-tl-bionic*.c`) | Native iOS Darwin `libSystem.B.dylib` | **Bionic-on-Darwin shim** (`src/bionic_shim.c`): Linux/Bionic `errno` & signal translation, 40-byte `pthread_mutex_t` wrapper, `__system_property_get`, and Linux `svc #0` dispatcher |
| **Java / DEX Runtime** | 64-bit pointer Dalvik bytecode interpreter (`husk-tl-dvm.c`, `husk-tl-dex.c`) + HLE JNI (`husk-tl-jni.c`) | N/A | **JIT-less 64-bit Dalvik DEX interpreter** with lazy `<clinit>` initialization + HLE `JavaVM` / `JNIEnv` bridge (`src/jni_dvm.c`) |

## Building and Running Tests

```bash
make all
make test
```

### Converting and Signing an Android `.so` via CLI

```bash
# Convert an Android arm64-v8a .so into a signed iOS Mach-O .dylib using a developer .p12 cert:
./build/husk-jitless-cli convert libmain.so libmain.aot.dylib --p12 dev_cert.p12 --pass "password"

# Verify the embedded CodeDirectory SHA-256 page hashes and Team ID:
./build/husk-jitless-cli verify libmain.aot.dylib
```

## License

GPL-2.0-or-later (compatible with upstream [Leviidev/Husk](https://github.com/Leviidev/Husk)).
