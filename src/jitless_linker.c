/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jitless_linker.c — The JIT-less guest dynamic linker for Husk-JITLess.
 */
#include "husk_jitless.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach-o/dyld.h>
#endif

#define R_AARCH64_NONE_      0u
#define R_AARCH64_ABS64_     257u
#define R_AARCH64_GLOB_DAT_  1025u
#define R_AARCH64_JUMP_SLOT_ 1026u
#define R_AARCH64_RELATIVE_  1027u

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} elf64_sym_t;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} elf64_rela_t;

bool husk_jitless_init(husk_jitless_runtime *rt, const char *cache_dir)
{
    if (!rt) return false;
    memset(rt, 0, sizeof(*rt));
    snprintf(rt->cache_dir, sizeof(rt->cache_dir), "%s",
             (cache_dir && cache_dir[0]) ? cache_dir : "/tmp");
    mkdir(rt->cache_dir, 0755);
    husk_jni_init();
    rt->dex_vm = husk_dex_vm_create();
    return rt->dex_vm != NULL;
}

void husk_jitless_shutdown(husk_jitless_runtime *rt)
{
    if (!rt) return;
    for (int i = 0; i < rt->lib_count; i++) {
        husk_jitless_lib *L = &rt->libs[i];
#if defined(__APPLE__)
        if (L->dl_handle) dlclose(L->dl_handle);
#endif
        if (L->image_base && !L->dl_handle && L->mapped_size > 0) {
            munmap(L->image_base, L->mapped_size);
        }
    }
    husk_cert_free(&rt->cert);
    husk_dex_vm_destroy(rt->dex_vm);
    memset(rt, 0, sizeof(*rt));
}

bool husk_jitless_set_dev_cert(husk_jitless_runtime *rt,
                               const uint8_t *p12_bytes,
                               size_t p12_len,
                               const char *password,
                               char *err,
                               size_t errlen)
{
    if (!rt) return false;
    husk_cert_free(&rt->cert);
    return husk_cert_load_p12(&rt->cert, p12_bytes, p12_len, password, err, errlen);
}

static uint8_t *elf_vaddr_to_ptr(husk_jitless_lib *L, uint64_t elf_vaddr)
{
    uint64_t rel = elf_vaddr - L->meta.elf_base_vaddr;
    return L->image_base + L->meta.macho_text_vmaddr + rel;
}

static void *resolve_guest_symbol(husk_jitless_runtime *rt, husk_jitless_lib *cur, const char *name)
{
    if (!name || !name[0]) return NULL;
    void *sym = husk_jitless_dlsym(cur, name);
    if (sym) return sym;
    for (int i = 0; i < rt->lib_count; i++) {
        if (&rt->libs[i] == cur) continue;
        sym = husk_jitless_dlsym(&rt->libs[i], name);
        if (sym) return sym;
    }
    return husk_bionic_resolve(name);
}

static bool apply_one_rela(husk_jitless_runtime *rt,
                           husk_jitless_lib *L,
                           const elf64_rela_t *r,
                           const elf64_sym_t *symtab,
                           const char *strtab)
{
    uint32_t type = (uint32_t)(r->r_info & 0xFFFFFFFFu);
    uint32_t sym_idx = (uint32_t)(r->r_info >> 32);
    uint8_t *target = elf_vaddr_to_ptr(L, r->r_offset);

    if (target < L->data_base || target + 8 > L->image_base + L->mapped_size) {
        return false;
    }

    uint64_t load_bias = (uint64_t)(uintptr_t)(L->image_base + L->meta.macho_text_vmaddr) -
                         L->meta.elf_base_vaddr;

    switch (type) {
    case R_AARCH64_NONE_:
        return true;
    case R_AARCH64_RELATIVE_: {
        uint64_t val = load_bias + (uint64_t)r->r_addend;
        memcpy(target, &val, 8);
        return true;
    }
    case R_AARCH64_ABS64_:
    case R_AARCH64_GLOB_DAT_:
    case R_AARCH64_JUMP_SLOT_: {
        if (!symtab || !strtab) return false;
        const elf64_sym_t *s = &symtab[sym_idx];
        const char *sname = strtab + s->st_name;
        void *resolved = NULL;
        if (s->st_shndx != 0 && s->st_value != 0) {
            resolved = elf_vaddr_to_ptr(L, s->st_value);
        } else {
            resolved = resolve_guest_symbol(rt, L, sname);
        }
        uint64_t val = (uint64_t)(uintptr_t)resolved + (uint64_t)r->r_addend;
        memcpy(target, &val, 8);
        return true;
    }
    default:
        return true;
    }
}

static bool apply_relr(husk_jitless_lib *L, const uint64_t *relr, size_t count)
{
    uint64_t load_bias = (uint64_t)(uintptr_t)(L->image_base + L->meta.macho_text_vmaddr) -
                         L->meta.elf_base_vaddr;
    uint64_t where = 0;

    for (size_t i = 0; i < count; i++) {
        uint64_t entry = relr[i];
        if ((entry & 1u) == 0) {
            where = entry;
            uint8_t *p = elf_vaddr_to_ptr(L, where);
            if (p < L->data_base) return false;
            uint64_t cur = 0;
            memcpy(&cur, p, 8);
            cur += load_bias;
            memcpy(p, &cur, 8);
            where += 8;
        } else {
            uint64_t bitmap = entry >> 1;
            for (unsigned b = 0; b < 63; b++) {
                if ((bitmap >> b) & 1u) {
                    uint8_t *p = elf_vaddr_to_ptr(L, where + (uint64_t)b * 8);
                    if (p < L->data_base) return false;
                    uint64_t cur = 0;
                    memcpy(&cur, p, 8);
                    cur += load_bias;
                    memcpy(p, &cur, 8);
                }
            }
            where += 63 * 8;
        }
    }
    return true;
}

husk_jitless_lib *husk_jitless_load_elf_bytes(husk_jitless_runtime *rt,
                                              const char *soname,
                                              const uint8_t *elf_bytes,
                                              size_t elf_size,
                                              char *err,
                                              size_t errlen)
{
    if (!rt || rt->lib_count >= 128) {
        if (err) snprintf(err, errlen, "Runtime library table full or uninitialized");
        return NULL;
    }

    const char *lib_name = (soname && soname[0]) ? soname : "libguest.so";
    char install_name[128];
    snprintf(install_name, sizeof(install_name), "@rpath/%s.aot.dylib", lib_name);

    elf2macho_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.install_name = install_name;
    opts.vx18_tsd_off = 0x100u;

    elf2macho_result conv;
    if (!husk_elf2macho_convert(elf_bytes, elf_size, &opts, &conv)) {
        if (err) snprintf(err, errlen, "ELF-to-Mach-O conversion failed: %s", conv.error);
        return NULL;
    }

    char dir_copy[512];
    snprintf(dir_copy, sizeof(dir_copy), "%s", rt->cache_dir);

    husk_jitless_lib *L = &rt->libs[rt->lib_count];
    memset(L, 0, sizeof(*L));
    snprintf(L->name, sizeof(L->name), "%s", lib_name);
    snprintf(L->dylib_path, sizeof(L->dylib_path), "%s/%s.aot.dylib", dir_copy, lib_name);

    FILE *f = fopen(L->dylib_path, "wb");
    if (!f || fwrite(conv.macho_bytes, 1, conv.macho_size, f) != conv.macho_size) {
        if (f) fclose(f);
        free(conv.macho_bytes);
        if (err) snprintf(err, errlen, "Failed to write converted Mach-O to %s", L->dylib_path);
        return NULL;
    }
    fclose(f);
    free(conv.macho_bytes);

    if (!husk_macho_sign_file_atomic(L->dylib_path, L->name, &rt->cert, err, errlen)) {
        return NULL;
    }

    FILE *sf = fopen(L->dylib_path, "rb");
    if (!sf) {
        if (err) snprintf(err, errlen, "Failed to reopen signed dylib");
        return NULL;
    }
    fseek(sf, 0, SEEK_END);
    size_t signed_sz = (size_t)ftell(sf);
    fseek(sf, 0, SEEK_SET);

    uint8_t *mapped = (uint8_t *)mmap(NULL, signed_sz, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapped == MAP_FAILED) {
        fclose(sf);
        if (err) snprintf(err, errlen, "mmap failed for signed Mach-O");
        return NULL;
    }
    if (fread(mapped, 1, signed_sz, sf) != signed_sz) {
        fclose(sf);
        munmap(mapped, signed_sz);
        if (err) snprintf(err, errlen, "fread failed for signed Mach-O");
        return NULL;
    }
    fclose(sf);

    if (!husk_macho_verify_signature(mapped, signed_sz, NULL, 0, err, errlen)) {
        munmap(mapped, signed_sz);
        return NULL;
    }

    L->image_base = mapped;
    L->mapped_size = signed_sz;
    L->meta = conv.meta;
    L->data_base = mapped + L->meta.macho_data_vmaddr;

    mprotect(L->image_base, (size_t)L->meta.macho_data_vmaddr, PROT_READ);

    uint8_t *host_page = L->image_base + L->meta.host_page_vmaddr;
    uint64_t svc_fn = (uint64_t)(uintptr_t)husk_svc_common_entry;
    uint64_t bionic_fn = (uint64_t)(uintptr_t)husk_bionic_resolve;
    uint64_t stack_guard = 0x000a0d0012345678ULL;
    memcpy(host_page + HUSK_HOST_OFF_SVC_COMMON, &svc_fn, 8);
    memcpy(host_page + HUSK_HOST_OFF_BIONIC_FIND, &bionic_fn, 8);
    memcpy(host_page + HUSK_HOST_OFF_STACK_GUARD, &stack_guard, 8);

    const elf64_sym_t *symtab = L->meta.dt_symtab_vaddr
        ? (const elf64_sym_t *)elf_vaddr_to_ptr(L, L->meta.dt_symtab_vaddr)
        : NULL;
    const char *strtab = L->meta.dt_strtab_vaddr
        ? (const char *)elf_vaddr_to_ptr(L, L->meta.dt_strtab_vaddr)
        : NULL;

    if (L->meta.dt_relr_vaddr && L->meta.dt_relrsz) {
        const uint64_t *relr = (const uint64_t *)elf_vaddr_to_ptr(L, L->meta.dt_relr_vaddr);
        if (!apply_relr(L, relr, (size_t)(L->meta.dt_relrsz / 8))) {
            if (err) snprintf(err, errlen, "RELR relocation tried to write outside __DATA");
            munmap(mapped, signed_sz);
            return NULL;
        }
    }

    if (L->meta.dt_rela_vaddr && L->meta.dt_relasz) {
        const elf64_rela_t *rela = (const elf64_rela_t *)elf_vaddr_to_ptr(L, L->meta.dt_rela_vaddr);
        size_t n = (size_t)(L->meta.dt_relasz / sizeof(elf64_rela_t));
        for (size_t i = 0; i < n; i++) {
            if (!apply_one_rela(rt, L, &rela[i], symtab, strtab)) {
                if (err) snprintf(err, errlen, "RELA relocation %zu targeted read-only __TEXT", i);
                munmap(mapped, signed_sz);
                return NULL;
            }
        }
    }

    if (L->meta.dt_jmprel_vaddr && L->meta.dt_pltrelsz) {
        const elf64_rela_t *jmprel = (const elf64_rela_t *)elf_vaddr_to_ptr(L, L->meta.dt_jmprel_vaddr);
        size_t n = (size_t)(L->meta.dt_pltrelsz / sizeof(elf64_rela_t));
        for (size_t i = 0; i < n; i++) {
            if (!apply_one_rela(rt, L, &jmprel[i], symtab, strtab)) {
                if (err) snprintf(err, errlen, "JMPREL relocation %zu targeted read-only __TEXT", i);
                munmap(mapped, signed_sz);
                return NULL;
            }
        }
    }

    L->relocated = true;
    L->initialized = true;
    rt->lib_count++;
    return L;
}

void *husk_jitless_dlsym(husk_jitless_lib *lib, const char *symbol_name)
{
    if (!lib || !symbol_name || !lib->meta.dt_symtab_vaddr || !lib->meta.dt_strtab_vaddr) {
        return NULL;
    }
    const elf64_sym_t *symtab = (const elf64_sym_t *)elf_vaddr_to_ptr(lib, lib->meta.dt_symtab_vaddr);
    const char *strtab = (const char *)elf_vaddr_to_ptr(lib, lib->meta.dt_strtab_vaddr);

    size_t max_syms = 256;
    if (lib->meta.dt_strtab_vaddr > lib->meta.dt_symtab_vaddr) {
        max_syms = (size_t)((lib->meta.dt_strtab_vaddr - lib->meta.dt_symtab_vaddr) / sizeof(elf64_sym_t));
    }
    for (size_t i = 1; i < max_syms; i++) {
        const elf64_sym_t *s = &symtab[i];
        if (s->st_shndx == 0 || s->st_value == 0) continue;
        if (s->st_name < lib->meta.dt_strsz && strcmp(strtab + s->st_name, symbol_name) == 0) {
            return elf_vaddr_to_ptr(lib, s->st_value);
        }
    }
    return NULL;
}
