/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * elf2macho.h — Ahead-Of-Time (AOT) converter that translates Android arm64-v8a
 * ELF shared libraries (.so) into 16 KiB page-aligned iOS Mach-O dynamic
 * libraries (MH_DYLIB) for JIT-less loading via dlopen().
 */
#ifndef HUSK_JITLESS_ELF2MACHO_H
#define HUSK_JITLESS_ELF2MACHO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "a64_rewriter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HUSK_IOS_PAGE_SIZE  16384u
#define HUSK_ELF_META_MAGIC 0x4B535548464C4501ULL

typedef struct husk_elf_meta_header {
    uint64_t magic;
    uint64_t elf_base_vaddr;
    uint64_t macho_text_vmaddr;
    uint64_t macho_data_vmaddr;
    uint64_t host_page_vmaddr;

    uint64_t dt_strtab_vaddr;
    uint64_t dt_strsz;
    uint64_t dt_symtab_vaddr;
    uint64_t dt_syment;
    uint64_t dt_hash_vaddr;
    uint64_t dt_gnu_hash_vaddr;

    uint64_t dt_rela_vaddr;
    uint64_t dt_relasz;
    uint64_t dt_jmprel_vaddr;
    uint64_t dt_pltrelsz;
    uint64_t dt_android_rela_vaddr;
    uint64_t dt_android_relasz;
    uint64_t dt_relr_vaddr;
    uint64_t dt_relrsz;

    uint64_t dt_init_vaddr;
    uint64_t dt_init_array_vaddr;
    uint64_t dt_init_arraysz;
    uint64_t dt_fini_array_vaddr;
    uint64_t dt_fini_arraysz;

    uint64_t tls_init_vaddr;
    uint64_t tls_filesz;
    uint64_t tls_memsz;
    uint64_t tls_align;

    uint32_t needed_count;
    uint32_t needed_stroff[48];
    char     soname[96];

    a64_rewrite_stats rewrite_stats;
} husk_elf_meta_header;

typedef struct elf2macho_options {
    const char *install_name;
    uint32_t    vx18_tsd_off;
    bool        verbose;
} elf2macho_options;

typedef struct elf2macho_result {
    bool                 ok;
    char                 error[256];
    uint8_t             *macho_bytes;
    size_t               macho_size;
    husk_elf_meta_header meta;
} elf2macho_result;

bool husk_elf2macho_convert(const uint8_t *elf_bytes,
                            size_t elf_size,
                            const elf2macho_options *opts,
                            elf2macho_result *out);

bool husk_elf2macho_convert_file(const char *elf_path,
                                 const char *macho_out_path,
                                 const elf2macho_options *opts,
                                 elf2macho_result *out);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_JITLESS_ELF2MACHO_H */
