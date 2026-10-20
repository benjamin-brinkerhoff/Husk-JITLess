/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jitless_signer.h — On-device Mach-O code signing using an Apple Developer
 * Certificate (.p12 / PKCS#12) for JIT-less dynamic library loading.
 */
#ifndef HUSK_JITLESS_SIGNER_H
#define HUSK_JITLESS_SIGNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct husk_dev_cert {
    uint8_t *p12_der;
    size_t   p12_len;
    char     password[128];
    char     team_id[32];
    char     subject_cn[128];
    int64_t  not_after_unix;
    bool     loaded;
} husk_dev_cert;

bool husk_cert_load_p12(husk_dev_cert *cert,
                        const uint8_t *p12_bytes,
                        size_t p12_len,
                        const char *password,
                        char *err,
                        size_t errlen);

bool husk_cert_load_p12_file(husk_dev_cert *cert,
                             const char *p12_path,
                             const char *password,
                             char *err,
                             size_t errlen);

void husk_cert_free(husk_dev_cert *cert);

bool husk_macho_sign_buffer(uint8_t **macho_io,
                            size_t *size_io,
                            const char *identifier,
                            const husk_dev_cert *cert,
                            char *err,
                            size_t errlen);

bool husk_macho_sign_file_atomic(const char *path,
                                 const char *identifier,
                                 const husk_dev_cert *cert,
                                 char *err,
                                 size_t errlen);

bool husk_macho_verify_signature(const uint8_t *macho_bytes,
                                 size_t macho_size,
                                 char *out_team_id,
                                 size_t team_id_len,
                                 char *err,
                                 size_t errlen);

#ifdef __cplusplus
}
#endif

#endif /* HUSK_JITLESS_SIGNER_H */
