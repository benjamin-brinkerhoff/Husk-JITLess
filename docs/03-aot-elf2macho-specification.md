# Specification: AOT ELF64-to-Mach-O (`MH_DYLIB`) Layout & `__DATA,__husk_host` Bridge

## 1. Virtual Memory Layout of a Translated `.aot.dylib`

| Segment / Section | Protection | Alignment | Contents |
|---|---|---|---|
| `__TEXT` (Header Page) | `R-X` | `0x4000` | `mach_header_64` (`MH_DYLIB`), `LC_ID_DYLIB`, `LC_SEGMENT_64`, `LC_UUID`, `LC_BUILD_VERSION`, `LC_SYMTAB`, `LC_CODE_SIGNATURE` |
| `__TEXT,__text` | `R-X` | `0x4000` | Read-only and executable ELF `PT_LOAD` segments with AOT instruction patches applied |
| `__TEXT,__stubs_aot` | `R-X` | `0x4000` | AOT-generated trampolines for `x18` TSD virtualization, `mrs ctr_el0`, and `svc #0` syscalls |
| `__DATA,__data` | `RW-` | `0x4000` | Writable ELF `PT_LOAD` segments (`.data`, `.got`, `.got.plt`, `.data.rel.ro`, `.bss`) |
| `__DATA,__husk_host` | `RW-` | `0x4000` | 16 KiB runtime bridge page populated after `dlopen()` |
| `__DATA,__elf_meta` | `RW-` | `0x4000` | `husk_elf_meta_header` recording original ELF `PT_DYNAMIC` and `PT_TLS` offsets |
| `__LINKEDIT` | `R--` | `0x4000` | `LC_CODE_SIGNATURE` SuperBlob (`CS_CodeDirectory` v20400 + Requirements + CMS Signature) |

## 2. ASLR-Safe Host Bridge (`__DATA,__husk_host`)
Because `__TEXT` and `__DATA` belong to the same `MH_DYLIB` image, `dyld` slides both segments by the exact same ASLR offset. Any AOT trampoline in `__TEXT` reaches runtime host callbacks (`tl_svc_common` at `+0x00`, `tl_bionic_find` at `+0x20`, and the stack canary at `+0x28`) via PC-relative `adrp` + `ldr` instructions without requiring text relocations or JIT.
