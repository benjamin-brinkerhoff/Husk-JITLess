/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * husk_jitless.h — Unified Public API for Husk-JITLess.
 */
#ifndef HUSK_JITLESS_H
#define HUSK_JITLESS_H

#include "a64_rewriter.h"
#include "bionic_shim.h"
#include "elf2macho.h"
#include "jitless_signer.h"
#include "jni_dvm.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct husk_jitless_lib {
    char                 name[96];
    char                 dylib_path[1024];
    void                *dl_handle;
    uint8_t             *image_base;
    uint8_t             *data_base;
    size_t               mapped_size;
    husk_elf_meta_header meta;
    bool                 relocated;
    bool                 initialized;
} husk_jitless_lib;

typedef struct husk_jitless_runtime {
    char             cache_dir[512];
    husk_dev_cert    cert;
    husk_dex_vm     *dex_vm;
    husk_jitless_lib libs[128];
    int              lib_count;
} husk_jitless_runtime;

bool husk_jitless_init(husk_jitless_runtime *rt, const char *cache_dir);
void husk_jitless_shutdown(husk_jitless_runtime *rt);

bool husk_jitless_set_dev_cert(husk_jitless_runtime *rt,
                               const uint8_t *p12_bytes,
                               size_t p12_len,
                               const char *password,
                               char *err,
                               size_t errlen);

husk_jitless_lib *husk_jitless_load_elf_bytes(husk_jitless_runtime *rt,
                                              const char *soname,
                                              const uint8_t *elf_bytes,
                                              size_t elf_size,
                                              char *err,
                                              size_t errlen);

void *husk_jitless_dlsym(husk_jitless_lib *lib, const char *symbol_name);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_JITLESS_H */
