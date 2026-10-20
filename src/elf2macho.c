/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * elf2macho.c — Converts an Android arm64-v8a ELF shared object (.so) into
 * an iOS 16 KiB page-aligned Mach-O dynamic library (MH_DYLIB) with AOT
 * instruction translation for JIT-less dlopen() execution.
 */
#include "elf2macho.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ELF_MAGIC0      0x7Fu
#define ELFCLASS64_     2u
#define ELFDATA2LSB_    1u
#define ET_DYN_         3u
#define EM_AARCH64_     183u

#define PT_LOAD_        1u
#define PT_DYNAMIC_     2u
#define PT_TLS_         7u
#define PT_GNU_RELRO_   0x6474e552u

#define PF_X_           1u
#define PF_W_           2u
#define PF_R_           4u

#define DT_NULL_        0
#define DT_NEEDED_      1
#define DT_PLTRELSZ_    2
#define DT_HASH_        4
#define DT_STRTAB_      5
#define DT_SYMTAB_      6
#define DT_RELA_        7
#define DT_RELASZ_      8
#define DT_STRSZ_       10
#define DT_SYMENT_      11
#define DT_INIT_        12
#define DT_SONAME_      14
#define DT_JMPREL_      23
#define DT_INIT_ARRAY_  25
#define DT_FINI_ARRAY_  26
#define DT_INIT_ARRAYSZ_ 27
#define DT_FINI_ARRAYSZ_ 28
#define DT_RELRSZ_      35
#define DT_RELR_        36
#define DT_GNU_HASH_    0x6ffffef5LL
#define DT_ANDROID_RELA_   0x60000011LL
#define DT_ANDROID_RELASZ_ 0x60000012LL
#define DT_ANDROID_RELR_   0x6fffe000LL
#define DT_ANDROID_RELRSZ_ 0x6fffe001LL

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} elf64_dyn_t;

#define MACHO_MH_MAGIC_64          0xFEEDFACFu
#define MACHO_CPU_TYPE_ARM64       0x0100000Cu
#define MACHO_CPU_SUBTYPE_ARM64_ALL 0u
#define MACHO_MH_DYLIB             0x6u
#define MACHO_MH_NOUNDEFS          0x1u
#define MACHO_MH_DYLDLINK          0x4u
#define MACHO_MH_TWOLEVEL          0x80u
#define MACHO_MH_NO_REEXPORTED_DYLIBS 0x100000u

#define MACHO_LC_SEGMENT_64        0x19u
#define MACHO_LC_SYMTAB            0x02u
#define MACHO_LC_ID_DYLIB          0x0Du
#define MACHO_LC_UUID              0x1Bu
#define MACHO_LC_BUILD_VERSION     0x32u

#define MACHO_VM_PROT_READ         0x01
#define MACHO_VM_PROT_WRITE        0x02
#define MACHO_VM_PROT_EXECUTE      0x04

#define MACHO_S_REGULAR            0x0u
#define MACHO_S_ATTR_PURE_INSTRUCTIONS 0x80000000u
#define MACHO_S_ATTR_SOME_INSTRUCTIONS 0x00000400u

typedef struct {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} macho_header_64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
} macho_segment_command_64_t;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} macho_section_64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
} macho_dylib_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t  uuid[16];
} macho_uuid_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
} macho_build_version_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} macho_symtab_command_t;

static uint64_t align_up(uint64_t v, uint64_t a)
{
    return (v + a - 1) & ~(a - 1);
}

static uint64_t align_down(uint64_t v, uint64_t a)
{
    return v & ~(a - 1);
}

static void set_err(elf2macho_result *out, const char *fmt, ...)
{
    if (!out) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out->error, sizeof(out->error), fmt, ap);
    va_end(ap);
    out->ok = false;
}

bool husk_elf2macho_convert(const uint8_t *elf_bytes,
                            size_t elf_size,
                            const elf2macho_options *opts,
                            elf2macho_result *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!elf_bytes || elf_size < sizeof(elf64_ehdr_t)) {
        set_err(out, "ELF buffer too small");
        return false;
    }

    const elf64_ehdr_t *eh = (const elf64_ehdr_t *)elf_bytes;
    if (eh->e_ident[0] != ELF_MAGIC0 || eh->e_ident[1] != 'E' ||
        eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F') {
        set_err(out, "Not a valid ELF file");
        return false;
    }
    if (eh->e_ident[4] != ELFCLASS64_ || eh->e_ident[5] != ELFDATA2LSB_ ||
        eh->e_machine != EM_AARCH64_ || eh->e_type != ET_DYN_) {
        set_err(out, "Requires 64-bit little-endian ARM64 ET_DYN shared object");
        return false;
    }
    if (eh->e_phoff + (size_t)eh->e_phnum * sizeof(elf64_phdr_t) > elf_size) {
        set_err(out, "Program header table out of bounds");
        return false;
    }

    const elf64_phdr_t *phdrs = (const elf64_phdr_t *)(elf_bytes + eh->e_phoff);
    uint64_t min_vaddr = UINT64_MAX;
    uint64_t max_rx_vaddr = 0;
    uint64_t min_rw_vaddr = UINT64_MAX;
    uint64_t max_vaddr = 0;
    bool has_load = false;

    const elf64_phdr_t *dyn_phdr = NULL;
    const elf64_phdr_t *tls_phdr = NULL;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const elf64_phdr_t *p = &phdrs[i];
        if (p->p_type == PT_LOAD_) {
            if (p->p_offset + p->p_filesz > elf_size) {
                set_err(out, "PT_LOAD segment %u exceeds file bounds", i);
                return false;
            }
            has_load = true;
            if (p->p_vaddr < min_vaddr) min_vaddr = p->p_vaddr;
            if (p->p_vaddr + p->p_memsz > max_vaddr) max_vaddr = p->p_vaddr + p->p_memsz;
            if (p->p_flags & PF_W_) {
                if (p->p_vaddr < min_rw_vaddr) min_rw_vaddr = p->p_vaddr;
            } else {
                if (p->p_vaddr + p->p_memsz > max_rx_vaddr) max_rx_vaddr = p->p_vaddr + p->p_memsz;
            }
        } else if (p->p_type == PT_DYNAMIC_) {
            dyn_phdr = p;
        } else if (p->p_type == PT_TLS_) {
            tls_phdr = p;
        }
    }

    if (!has_load) {
        set_err(out, "ELF contains no PT_LOAD segments");
        return false;
    }

    uint64_t base_vaddr = align_down(min_vaddr, HUSK_IOS_PAGE_SIZE);
    uint64_t rx_end = align_up(max_rx_vaddr > base_vaddr ? max_rx_vaddr : base_vaddr + HUSK_IOS_PAGE_SIZE,
                               HUSK_IOS_PAGE_SIZE);
    uint64_t elf_rx_span = rx_end - base_vaddr;
    uint64_t stub_page_size = HUSK_IOS_PAGE_SIZE;
    uint64_t macho_hdr_page = HUSK_IOS_PAGE_SIZE;

    uint64_t text_vmaddr = 0;
    uint64_t elf_code_vmaddr = text_vmaddr + macho_hdr_page;
    uint64_t stub_vmaddr = elf_code_vmaddr + elf_rx_span;

    uint64_t elf_total_span = align_up(max_vaddr - base_vaddr, HUSK_IOS_PAGE_SIZE);
    uint64_t elf_rw_offset = (min_rw_vaddr != UINT64_MAX && min_rw_vaddr >= rx_end)
                             ? align_down(min_rw_vaddr - base_vaddr, HUSK_IOS_PAGE_SIZE)
                             : elf_rx_span;
    uint64_t elf_rw_span = (elf_total_span > elf_rw_offset)
                           ? (elf_total_span - elf_rw_offset)
                           : HUSK_IOS_PAGE_SIZE;

    bool stubs_in_gap = (min_rw_vaddr != UINT64_MAX &&
                         align_down(min_rw_vaddr - base_vaddr, HUSK_IOS_PAGE_SIZE) >= elf_rx_span + stub_page_size);

    uint64_t final_text_vmsize;
    uint64_t final_data_vmaddr;
    uint64_t final_data_vmsize;
    uint64_t host_page_vmaddr;
    uint64_t meta_page_vmaddr;

    if (stubs_in_gap) {
        stub_vmaddr = elf_code_vmaddr + elf_rx_span;
        final_text_vmsize = macho_hdr_page + align_down(min_rw_vaddr - base_vaddr, HUSK_IOS_PAGE_SIZE);
        final_data_vmaddr = final_text_vmsize;
        uint64_t rw_part = elf_total_span - (final_data_vmaddr - elf_code_vmaddr);
        host_page_vmaddr = final_data_vmaddr + rw_part;
        meta_page_vmaddr = host_page_vmaddr + HUSK_IOS_PAGE_SIZE;
        final_data_vmsize = rw_part + 2 * HUSK_IOS_PAGE_SIZE;
    } else {
        stub_vmaddr = elf_code_vmaddr + elf_rx_span;
        final_text_vmsize = macho_hdr_page + elf_rx_span + stub_page_size;
        final_data_vmaddr = final_text_vmsize;
        host_page_vmaddr = final_data_vmaddr + elf_rw_span;
        meta_page_vmaddr = host_page_vmaddr + HUSK_IOS_PAGE_SIZE;
        final_data_vmsize = elf_rw_span + 2 * HUSK_IOS_PAGE_SIZE;
    }

    uint64_t linkedit_vmaddr = final_data_vmaddr + final_data_vmsize;
    uint64_t linkedit_vmsize = HUSK_IOS_PAGE_SIZE;
    size_t total_macho_size = (size_t)(linkedit_vmaddr + linkedit_vmsize);

    uint8_t *buf = (uint8_t *)calloc(1, total_macho_size);
    if (!buf) {
        set_err(out, "Out of memory allocating %zu bytes for Mach-O", total_macho_size);
        return false;
    }

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const elf64_phdr_t *p = &phdrs[i];
        if (p->p_type != PT_LOAD_ || p->p_filesz == 0) continue;
        uint64_t rel_vaddr = p->p_vaddr - base_vaddr;
        uint64_t target_off;
        if (p->p_flags & PF_W_) {
            if (stubs_in_gap) {
                target_off = elf_code_vmaddr + rel_vaddr;
            } else {
                target_off = final_data_vmaddr + (rel_vaddr - elf_rw_offset);
            }
        } else {
            target_off = elf_code_vmaddr + rel_vaddr;
        }
        if (target_off + p->p_filesz <= total_macho_size) {
            memcpy(buf + target_off, elf_bytes + p->p_offset, (size_t)p->p_filesz);
        }
    }

    a64_rewrite_stats total_stats;
    memset(&total_stats, 0, sizeof(total_stats));
    uint32_t vx18_off = (opts && opts->vx18_tsd_off) ? opts->vx18_tsd_off : 0x100u;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const elf64_phdr_t *p = &phdrs[i];
        if (p->p_type != PT_LOAD_ || !(p->p_flags & PF_X_) || p->p_filesz < 4) continue;
        uint64_t seg_va = elf_code_vmaddr + (p->p_vaddr - base_vaddr);
        size_t code_len = (size_t)(p->p_filesz & ~(uint64_t)3);
        a64_rewrite_stats st;
        a64_rewrite_text_aot((uint32_t *)(buf + seg_va),
                             code_len,
                             seg_va,
                             buf + stub_vmaddr + total_stats.stubs_bytes_used,
                             (size_t)(stub_page_size - total_stats.stubs_bytes_used),
                             stub_vmaddr + total_stats.stubs_bytes_used,
                             host_page_vmaddr,
                             vx18_off,
                             &st);
        total_stats.x18_rewritten += st.x18_rewritten;
        total_stats.x18_failed += st.x18_failed;
        total_stats.tpidr_rewritten += st.tpidr_rewritten;
        total_stats.ctr_rewritten += st.ctr_rewritten;
        total_stats.svc_rewritten += st.svc_rewritten;
        total_stats.svc_enosys_fallback += st.svc_enosys_fallback;
        total_stats.stubs_bytes_used += st.stubs_bytes_used;
    }

    husk_elf_meta_header *meta = (husk_elf_meta_header *)(buf + meta_page_vmaddr);
    meta->magic = HUSK_ELF_META_MAGIC;
    meta->elf_base_vaddr = base_vaddr;
    meta->macho_text_vmaddr = elf_code_vmaddr;
    meta->macho_data_vmaddr = final_data_vmaddr;
    meta->host_page_vmaddr = host_page_vmaddr;
    meta->rewrite_stats = total_stats;

    if (tls_phdr) {
        meta->tls_init_vaddr = tls_phdr->p_vaddr;
        meta->tls_filesz = tls_phdr->p_filesz;
        meta->tls_memsz = tls_phdr->p_memsz;
        meta->tls_align = tls_phdr->p_align;
    }

    int64_t soname_stroff = -1;
    if (dyn_phdr && dyn_phdr->p_offset + dyn_phdr->p_filesz <= elf_size) {
        const elf64_dyn_t *dyns = (const elf64_dyn_t *)(elf_bytes + dyn_phdr->p_offset);
        size_t ndyn = (size_t)(dyn_phdr->p_filesz / sizeof(elf64_dyn_t));
        for (size_t i = 0; i < ndyn; i++) {
            int64_t tag = dyns[i].d_tag;
            uint64_t val = dyns[i].d_val;
            if (tag == DT_NULL_) break;
            switch (tag) {
            case DT_STRTAB_: meta->dt_strtab_vaddr = val; break;
            case DT_STRSZ_:  meta->dt_strsz = val; break;
            case DT_SYMTAB_: meta->dt_symtab_vaddr = val; break;
            case DT_SYMENT_: meta->dt_syment = val; break;
            case DT_HASH_:   meta->dt_hash_vaddr = val; break;
            case DT_GNU_HASH_: meta->dt_gnu_hash_vaddr = val; break;
            case DT_RELA_:   meta->dt_rela_vaddr = val; break;
            case DT_RELASZ_: meta->dt_relasz = val; break;
            case DT_JMPREL_: meta->dt_jmprel_vaddr = val; break;
            case DT_PLTRELSZ_: meta->dt_pltrelsz = val; break;
            case DT_ANDROID_RELA_: meta->dt_android_rela_vaddr = val; break;
            case DT_ANDROID_RELASZ_: meta->dt_android_relasz = val; break;
            case DT_RELR_:
            case DT_ANDROID_RELR_: meta->dt_relr_vaddr = val; break;
            case DT_RELRSZ_:
            case DT_ANDROID_RELRSZ_: meta->dt_relrsz = val; break;
            case DT_INIT_:   meta->dt_init_vaddr = val; break;
            case DT_INIT_ARRAY_: meta->dt_init_array_vaddr = val; break;
            case DT_INIT_ARRAYSZ_: meta->dt_init_arraysz = val; break;
            case DT_FINI_ARRAY_: meta->dt_fini_array_vaddr = val; break;
            case DT_FINI_ARRAYSZ_: meta->dt_fini_arraysz = val; break;
            case DT_SONAME_: soname_stroff = (int64_t)val; break;
            case DT_NEEDED_:
                if (meta->needed_count < 48) {
                    meta->needed_stroff[meta->needed_count++] = (uint32_t)val;
                }
                break;
            default: break;
            }
        }
    }

    if (soname_stroff >= 0 && meta->dt_strtab_vaddr >= base_vaddr) {
        uint64_t str_off = elf_code_vmaddr + (meta->dt_strtab_vaddr - base_vaddr) + (uint64_t)soname_stroff;
        if (str_off < total_macho_size) {
            snprintf(meta->soname, sizeof(meta->soname), "%s", (const char *)(buf + str_off));
        }
    }

    uint64_t canary = 0x000a0d0012345678ULL;
    memcpy(buf + host_page_vmaddr + HUSK_HOST_OFF_STACK_GUARD, &canary, 8);
    uint64_t tsd_off64 = vx18_off;
    memcpy(buf + host_page_vmaddr + HUSK_HOST_OFF_VX18_TSD, &tsd_off64, 8);

    macho_header_64_t *mh = (macho_header_64_t *)buf;
    mh->magic = MACHO_MH_MAGIC_64;
    mh->cputype = (int32_t)MACHO_CPU_TYPE_ARM64;
    mh->cpusubtype = (int32_t)MACHO_CPU_SUBTYPE_ARM64_ALL;
    mh->filetype = MACHO_MH_DYLIB;
    mh->flags = MACHO_MH_NOUNDEFS | MACHO_MH_DYLDLINK | MACHO_MH_TWOLEVEL | MACHO_MH_NO_REEXPORTED_DYLIBS;

    uint8_t *lc_ptr = buf + sizeof(macho_header_64_t);
    uint32_t ncmds = 0;

    const char *inst_name = (opts && opts->install_name) ? opts->install_name : "@rpath/libhusk_guest.aot.dylib";
    uint32_t id_cmdsize = (uint32_t)align_up(sizeof(macho_dylib_command_t) + strlen(inst_name) + 1, 8);
    macho_dylib_command_t *id_cmd = (macho_dylib_command_t *)lc_ptr;
    id_cmd->cmd = MACHO_LC_ID_DYLIB;
    id_cmd->cmdsize = id_cmdsize;
    id_cmd->name_offset = sizeof(macho_dylib_command_t);
    id_cmd->timestamp = 2;
    id_cmd->current_version = 0x00010000u;
    id_cmd->compatibility_version = 0x00010000u;
    memcpy(lc_ptr + sizeof(macho_dylib_command_t), inst_name, strlen(inst_name));
    lc_ptr += id_cmdsize;
    ncmds++;

    macho_segment_command_64_t *seg_text = (macho_segment_command_64_t *)lc_ptr;
    seg_text->cmd = MACHO_LC_SEGMENT_64;
    seg_text->cmdsize = sizeof(macho_segment_command_64_t) + 2 * sizeof(macho_section_64_t);
    strncpy(seg_text->segname, "__TEXT", 16);
    seg_text->vmaddr = 0;
    seg_text->vmsize = final_text_vmsize;
    seg_text->fileoff = 0;
    seg_text->filesize = final_text_vmsize;
    seg_text->maxprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_EXECUTE;
    seg_text->initprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_EXECUTE;
    seg_text->nsects = 2;

    macho_section_64_t *sect_text = (macho_section_64_t *)(lc_ptr + sizeof(macho_segment_command_64_t));
    strncpy(sect_text->sectname, "__text", 16);
    strncpy(sect_text->segname, "__TEXT", 16);
    sect_text->addr = elf_code_vmaddr;
    sect_text->size = elf_rx_span;
    sect_text->offset = (uint32_t)elf_code_vmaddr;
    sect_text->align = 14;
    sect_text->flags = MACHO_S_REGULAR | MACHO_S_ATTR_PURE_INSTRUCTIONS | MACHO_S_ATTR_SOME_INSTRUCTIONS;

    macho_section_64_t *sect_stubs = sect_text + 1;
    strncpy(sect_stubs->sectname, "__stubs_aot", 16);
    strncpy(sect_stubs->segname, "__TEXT", 16);
    sect_stubs->addr = stub_vmaddr;
    sect_stubs->size = stub_page_size;
    sect_stubs->offset = (uint32_t)stub_vmaddr;
    sect_stubs->align = 14;
    sect_stubs->flags = MACHO_S_REGULAR | MACHO_S_ATTR_PURE_INSTRUCTIONS | MACHO_S_ATTR_SOME_INSTRUCTIONS;

    lc_ptr += seg_text->cmdsize;
    ncmds++;

    macho_segment_command_64_t *seg_data = (macho_segment_command_64_t *)lc_ptr;
    seg_data->cmd = MACHO_LC_SEGMENT_64;
    seg_data->cmdsize = sizeof(macho_segment_command_64_t) + 3 * sizeof(macho_section_64_t);
    strncpy(seg_data->segname, "__DATA", 16);
    seg_data->vmaddr = final_data_vmaddr;
    seg_data->vmsize = final_data_vmsize;
    seg_data->fileoff = final_data_vmaddr;
    seg_data->filesize = final_data_vmsize;
    seg_data->maxprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_WRITE;
    seg_data->initprot = MACHO_VM_PROT_READ | MACHO_VM_PROT_WRITE;
    seg_data->nsects = 3;

    macho_section_64_t *sect_data = (macho_section_64_t *)(lc_ptr + sizeof(macho_segment_command_64_t));
    strncpy(sect_data->sectname, "__data", 16);
    strncpy(sect_data->segname, "__DATA", 16);
    sect_data->addr = final_data_vmaddr;
    sect_data->size = host_page_vmaddr - final_data_vmaddr;
    sect_data->offset = (uint32_t)final_data_vmaddr;
    sect_data->align = 14;

    macho_section_64_t *sect_host = sect_data + 1;
    strncpy(sect_host->sectname, "__husk_host", 16);
    strncpy(sect_host->segname, "__DATA", 16);
    sect_host->addr = host_page_vmaddr;
    sect_host->size = HUSK_IOS_PAGE_SIZE;
    sect_host->offset = (uint32_t)host_page_vmaddr;
    sect_host->align = 14;

    macho_section_64_t *sect_meta = sect_data + 2;
    strncpy(sect_meta->sectname, "__elf_meta", 16);
    strncpy(sect_meta->segname, "__DATA", 16);
    sect_meta->addr = meta_page_vmaddr;
    sect_meta->size = HUSK_IOS_PAGE_SIZE;
    sect_meta->offset = (uint32_t)meta_page_vmaddr;
    sect_meta->align = 14;

    lc_ptr += seg_data->cmdsize;
    ncmds++;

    macho_segment_command_64_t *seg_le = (macho_segment_command_64_t *)lc_ptr;
    seg_le->cmd = MACHO_LC_SEGMENT_64;
    seg_le->cmdsize = sizeof(macho_segment_command_64_t);
    strncpy(seg_le->segname, "__LINKEDIT", 16);
    seg_le->vmaddr = linkedit_vmaddr;
    seg_le->vmsize = linkedit_vmsize;
    seg_le->fileoff = linkedit_vmaddr;
    seg_le->filesize = linkedit_vmsize;
    seg_le->maxprot = MACHO_VM_PROT_READ;
    seg_le->initprot = MACHO_VM_PROT_READ;
    seg_le->nsects = 0;
    lc_ptr += seg_le->cmdsize;
    ncmds++;

    macho_uuid_command_t *uuid_cmd = (macho_uuid_command_t *)lc_ptr;
    uuid_cmd->cmd = MACHO_LC_UUID;
    uuid_cmd->cmdsize = sizeof(macho_uuid_command_t);
    for (size_t i = 0; i < elf_size && i < 4096; i++) {
        uuid_cmd->uuid[i & 15] ^= (uint8_t)(elf_bytes[i] + (i * 131));
    }
    lc_ptr += uuid_cmd->cmdsize;
    ncmds++;

    macho_build_version_command_t *bv_cmd = (macho_build_version_command_t *)lc_ptr;
    bv_cmd->cmd = MACHO_LC_BUILD_VERSION;
    bv_cmd->cmdsize = sizeof(macho_build_version_command_t);
    bv_cmd->platform = 2;
    bv_cmd->minos = (16u << 16);
    bv_cmd->sdk = (26u << 16);
    bv_cmd->ntools = 0;
    lc_ptr += bv_cmd->cmdsize;
    ncmds++;

    macho_symtab_command_t *sym_cmd = (macho_symtab_command_t *)lc_ptr;
    sym_cmd->cmd = MACHO_LC_SYMTAB;
    sym_cmd->cmdsize = sizeof(macho_symtab_command_t);
    sym_cmd->symoff = (uint32_t)linkedit_vmaddr;
    sym_cmd->nsyms = 0;
    sym_cmd->stroff = (uint32_t)linkedit_vmaddr;
    sym_cmd->strsize = 8;
    lc_ptr += sym_cmd->cmdsize;
    ncmds++;

    mh->ncmds = ncmds;
    mh->sizeofcmds = (uint32_t)(lc_ptr - (buf + sizeof(macho_header_64_t)));

    out->ok = true;
    out->macho_bytes = buf;
    out->macho_size = total_macho_size;
    out->meta = *meta;
    return true;
}

bool husk_elf2macho_convert_file(const char *elf_path,
                                 const char *macho_out_path,
                                 const elf2macho_options *opts,
                                 elf2macho_result *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(elf_path, "rb");
    if (!f) {
        set_err(out, "Cannot open ELF file: %s", elf_path ? elf_path : "(null)");
        return false;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        set_err(out, "Empty or invalid ELF file: %s", elf_path);
        return false;
    }
    uint8_t *elf_buf = (uint8_t *)malloc((size_t)sz);
    if (!elf_buf || fread(elf_buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(elf_buf);
        set_err(out, "Failed to read ELF file: %s", elf_path);
        return false;
    }
    fclose(f);

    bool ok = husk_elf2macho_convert(elf_buf, (size_t)sz, opts, out);
    free(elf_buf);
    if (!ok) return false;

    FILE *of = fopen(macho_out_path, "wb");
    if (!of || fwrite(out->macho_bytes, 1, out->macho_size, of) != out->macho_size) {
        if (of) fclose(of);
        set_err(out, "Failed to write Mach-O file: %s", macho_out_path);
        return false;
    }
    fclose(of);
    return true;
}
