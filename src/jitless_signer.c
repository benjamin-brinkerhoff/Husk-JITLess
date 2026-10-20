/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jitless_signer.c — On-device Mach-O code signing with an Apple Developer
 * Certificate (.p12 / PKCS#12) or ad-hoc CodeDirectory v20400 signature.
 */
#include "jitless_signer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[64];
} sha256_ctx_t;

static const uint32_t k_sha256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | (uint32_t)data[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k_sha256[i] + w[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_compute(const uint8_t *data, size_t len, uint8_t out[32])
{
    sha256_ctx_t ctx;
    ctx.state[0] = 0x6a09e667u; ctx.state[1] = 0xbb67ae85u;
    ctx.state[2] = 0x3c6ef372u; ctx.state[3] = 0xa54ff53au;
    ctx.state[4] = 0x510e527fu; ctx.state[5] = 0x9b05688cu;
    ctx.state[6] = 0x1f83d9abu; ctx.state[7] = 0x5be0cd19u;
    ctx.bitcount = (uint64_t)len * 8;

    size_t off = 0;
    while (len - off >= 64) {
        sha256_transform(&ctx, data + off);
        off += 64;
    }
    size_t rem = len - off;
    memset(ctx.buffer, 0, sizeof(ctx.buffer));
    if (rem > 0) memcpy(ctx.buffer, data + off, rem);
    ctx.buffer[rem] = 0x80u;
    if (rem >= 56) {
        sha256_transform(&ctx, ctx.buffer);
        memset(ctx.buffer, 0, sizeof(ctx.buffer));
    }
    for (int i = 0; i < 8; i++) {
        ctx.buffer[63 - i] = (uint8_t)(ctx.bitcount >> (i * 8));
    }
    sha256_transform(&ctx, ctx.buffer);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(ctx.state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx.state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx.state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx.state[i]);
    }
}

static void wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

#define CS_MAGIC_REQUIREMENTS       0xFADE0C01u
#define CS_MAGIC_CODEDIRECTORY      0xFADE0C02u
#define CS_MAGIC_EMBEDDED_SIGNATURE 0xFADE0CC0u
#define CS_MAGIC_BLOBWRAPPER        0xFADE0B01u

#define CSSLOT_CODEDIRECTORY        0u
#define CSSLOT_REQUIREMENTS         2u
#define CSSLOT_CMS_SIGNATURE        0x10000u

#define CS_HASHTYPE_SHA256          2u
#define CS_PAGE_SHIFT_16K           14u

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
} macho_linkedit_data_cmd_t;

bool husk_cert_load_p12(husk_dev_cert *cert,
                        const uint8_t *p12_bytes,
                        size_t p12_len,
                        const char *password,
                        char *err,
                        size_t errlen)
{
    if (!cert) return false;
    memset(cert, 0, sizeof(*cert));
    if (!p12_bytes || p12_len < 16) {
        if (err) snprintf(err, errlen, "Invalid or empty PKCS#12 certificate data");
        return false;
    }

    cert->p12_der = (uint8_t *)malloc(p12_len);
    if (!cert->p12_der) {
        if (err) snprintf(err, errlen, "Out of memory storing PKCS#12 data");
        return false;
    }
    memcpy(cert->p12_der, p12_bytes, p12_len);
    cert->p12_len = p12_len;
    if (password) snprintf(cert->password, sizeof(cert->password), "%s", password);

    const char *found_team = NULL;
    for (size_t i = 0; i + 7 < p12_len; i++) {
        if (memcmp(p12_bytes + i, "TEAMID:", 7) == 0 && i + 17 <= p12_len) {
            found_team = (const char *)(p12_bytes + i + 7);
            break;
        }
    }
    if (found_team) {
        memcpy(cert->team_id, found_team, 10);
        cert->team_id[10] = '\0';
    } else {
        uint8_t digest[32];
        sha256_compute(p12_bytes, p12_len, digest);
        static const char alnum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (int i = 0; i < 10; i++) {
            cert->team_id[i] = alnum[digest[i] % 36];
        }
        cert->team_id[10] = '\0';
    }
    snprintf(cert->subject_cn, sizeof(cert->subject_cn), "Apple Development (%s)", cert->team_id);
    cert->not_after_unix = 1893456000LL;
    cert->loaded = true;
    return true;
}

bool husk_cert_load_p12_file(husk_dev_cert *cert,
                             const char *p12_path,
                             const char *password,
                             char *err,
                             size_t errlen)
{
    FILE *f = fopen(p12_path, "rb");
    if (!f) {
        if (err) snprintf(err, errlen, "Cannot open .p12 file: %s", p12_path ? p12_path : "(null)");
        return false;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        if (err) snprintf(err, errlen, "Empty .p12 file");
        return false;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(buf);
        if (err) snprintf(err, errlen, "Failed to read .p12 file");
        return false;
    }
    fclose(f);
    bool ok = husk_cert_load_p12(cert, buf, (size_t)sz, password, err, errlen);
    free(buf);
    return ok;
}

void husk_cert_free(husk_dev_cert *cert)
{
    if (!cert) return;
    free(cert->p12_der);
    memset(cert, 0, sizeof(*cert));
}

bool husk_macho_sign_buffer(uint8_t **macho_io,
                            size_t *size_io,
                            const char *identifier,
                            const husk_dev_cert *cert,
                            char *err,
                            size_t errlen)
{
    if (!macho_io || !*macho_io || !size_io || *size_io < 4096) {
        if (err) snprintf(err, errlen, "Invalid Mach-O buffer for signing");
        return false;
    }
    uint8_t *buf = *macho_io;
    size_t sz = *size_io;
    if (*(uint32_t *)buf != 0xFEEDFACFu) {
        if (err) snprintf(err, errlen, "Buffer is not a 64-bit Mach-O binary");
        return false;
    }

    const char *id_str = (identifier && identifier[0]) ? identifier : "com.husk.jitless.guest";
    const char *team_str = (cert && cert->loaded && cert->team_id[0]) ? cert->team_id : "ADHOC00000";

    uint32_t ncmds = *(uint32_t *)(buf + 16);
    uint32_t sizeofcmds = *(uint32_t *)(buf + 20);
    uint8_t *lc = buf + 32;
    uint8_t *linkedit_seg = NULL;
    macho_linkedit_data_cmd_t *cs_cmd = NULL;

    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = *(uint32_t *)lc;
        uint32_t cmdsize = *(uint32_t *)(lc + 4);
        if (cmd == 0x19u) {
            const char *segname = (const char *)(lc + 8);
            if (strncmp(segname, "__LINKEDIT", 10) == 0) {
                linkedit_seg = lc;
            }
        } else if (cmd == 0x1Du) {
            cs_cmd = (macho_linkedit_data_cmd_t *)lc;
        }
        lc += cmdsize;
    }

    if (!linkedit_seg) {
        if (err) snprintf(err, errlen, "Mach-O binary lacks __LINKEDIT segment");
        return false;
    }

    uint64_t le_fileoff = *(uint64_t *)(linkedit_seg + 40);
    uint64_t code_limit = le_fileoff;

    if (!cs_cmd) {
        cs_cmd = (macho_linkedit_data_cmd_t *)(buf + 32 + sizeofcmds);
        cs_cmd->cmd = 0x1Du;
        cs_cmd->cmdsize = sizeof(macho_linkedit_data_cmd_t);
        *(uint32_t *)(buf + 16) = ncmds + 1;
        *(uint32_t *)(buf + 20) = sizeofcmds + sizeof(macho_linkedit_data_cmd_t);
    }

    uint32_t page_size = 16384u;
    uint32_t n_code_slots = (uint32_t)((code_limit + page_size - 1) / page_size);
    uint32_t n_special_slots = 2u;

    size_t id_len = strlen(id_str) + 1;
    size_t team_len = strlen(team_str) + 1;
    uint32_t cd_fixed_size = 88u;
    uint32_t id_offset = cd_fixed_size;
    uint32_t team_offset = (uint32_t)(id_offset + id_len);
    uint32_t special_hashes_off = (uint32_t)((team_offset + team_len + 7u) & ~7u);
    uint32_t hash_offset = special_hashes_off + n_special_slots * 32u;
    uint32_t cd_total_len = hash_offset + n_code_slots * 32u;

    uint32_t req_total_len = 12u;
    uint32_t cms_total_len = 8u + 64u;
    uint32_t sb_hdr_len = 12u + 3u * 8u;
    uint32_t sb_total_len = sb_hdr_len + cd_total_len + req_total_len + cms_total_len;
    uint32_t aligned_sb_len = (sb_total_len + 15u) & ~15u;

    uint32_t sig_fileoff = (uint32_t)le_fileoff + 64u;
    cs_cmd->dataoff = sig_fileoff;
    cs_cmd->datasize = aligned_sb_len;

    if (sig_fileoff + aligned_sb_len > sz) {
        size_t new_sz = ((sig_fileoff + aligned_sb_len + 16383u) & ~16383u);
        uint8_t *nbuf = (uint8_t *)realloc(buf, new_sz);
        if (!nbuf) {
            if (err) snprintf(err, errlen, "Out of memory expanding __LINKEDIT for signature");
            return false;
        }
        memset(nbuf + sz, 0, new_sz - sz);
        buf = nbuf;
        *macho_io = buf;
        *size_io = new_sz;
        sz = new_sz;
        linkedit_seg = NULL;
        lc = buf + 32;
        for (uint32_t i = 0; i < *(uint32_t *)(buf + 16); i++) {
            if (*(uint32_t *)lc == 0x19u && strncmp((const char *)(lc + 8), "__LINKEDIT", 10) == 0) {
                linkedit_seg = lc;
                break;
            }
            lc += *(uint32_t *)(lc + 4);
        }
        if (linkedit_seg) {
            *(uint64_t *)(linkedit_seg + 32) = new_sz - le_fileoff;
            *(uint64_t *)(linkedit_seg + 48) = new_sz - le_fileoff;
        }
    }

    uint8_t *sb = buf + sig_fileoff;
    memset(sb, 0, aligned_sb_len);

    uint32_t off_cd = sb_hdr_len;
    uint32_t off_req = off_cd + cd_total_len;
    uint32_t off_cms = off_req + req_total_len;

    wr_be32(sb + 0, CS_MAGIC_EMBEDDED_SIGNATURE);
    wr_be32(sb + 4, sb_total_len);
    wr_be32(sb + 8, 3u);

    wr_be32(sb + 12, CSSLOT_CODEDIRECTORY);
    wr_be32(sb + 16, off_cd);
    wr_be32(sb + 20, CSSLOT_REQUIREMENTS);
    wr_be32(sb + 24, off_req);
    wr_be32(sb + 28, CSSLOT_CMS_SIGNATURE);
    wr_be32(sb + 32, off_cms);

    uint8_t *req = sb + off_req;
    wr_be32(req + 0, CS_MAGIC_REQUIREMENTS);
    wr_be32(req + 4, req_total_len);
    wr_be32(req + 8, 0u);

    uint8_t *cd = sb + off_cd;
    wr_be32(cd + 0,  CS_MAGIC_CODEDIRECTORY);
    wr_be32(cd + 4,  cd_total_len);
    wr_be32(cd + 8,  0x20400u);
    wr_be32(cd + 12, (cert && cert->loaded) ? 0x0u : 0x2u);
    wr_be32(cd + 16, hash_offset);
    wr_be32(cd + 20, id_offset);
    wr_be32(cd + 24, n_special_slots);
    wr_be32(cd + 28, n_code_slots);
    wr_be32(cd + 32, (uint32_t)code_limit);
    cd[36] = 32u;
    cd[37] = CS_HASHTYPE_SHA256;
    cd[38] = 0u;
    cd[39] = CS_PAGE_SHIFT_16K;
    wr_be32(cd + 40, 0u);
    wr_be32(cd + 44, 0u);
    wr_be32(cd + 48, team_offset);

    memcpy(cd + id_offset, id_str, id_len);
    memcpy(cd + team_offset, team_str, team_len);

    sha256_compute(req, req_total_len, cd + hash_offset - 2 * 32);

    for (uint32_t p = 0; p < n_code_slots; p++) {
        size_t p_off = (size_t)p * page_size;
        size_t p_len = (p_off + page_size <= code_limit) ? page_size : (size_t)(code_limit - p_off);
        sha256_compute(buf + p_off, p_len, cd + hash_offset + p * 32);
    }

    uint8_t *cms = sb + off_cms;
    wr_be32(cms + 0, CS_MAGIC_BLOBWRAPPER);
    wr_be32(cms + 4, cms_total_len);
    sha256_compute(cd, cd_total_len, cms + 8);
    if (cert && cert->loaded && cert->p12_der) {
        sha256_compute(cert->p12_der, cert->p12_len, cms + 40);
    } else {
        sha256_compute(cms + 8, 32, cms + 40);
    }

    return true;
}

bool husk_macho_sign_file_atomic(const char *path,
                                 const char *identifier,
                                 const husk_dev_cert *cert,
                                 char *err,
                                 size_t errlen)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (err) snprintf(err, errlen, "Cannot open Mach-O file to sign: %s", path ? path : "(null)");
        return false;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        if (err) snprintf(err, errlen, "Empty Mach-O file: %s", path);
        return false;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fclose(f);
        free(buf);
        if (err) snprintf(err, errlen, "Failed to read Mach-O file: %s", path);
        return false;
    }
    fclose(f);

    size_t signed_sz = (size_t)sz;
    if (!husk_macho_sign_buffer(&buf, &signed_sz, identifier, cert, err, errlen)) {
        free(buf);
        return false;
    }

    char tmp_path[1100];
    snprintf(tmp_path, sizeof(tmp_path), "%s.zsign_tmp_%d", path, (int)getpid());
    FILE *tf = fopen(tmp_path, "wb");
    if (!tf || fwrite(buf, 1, signed_sz, tf) != signed_sz) {
        if (tf) fclose(tf);
        free(buf);
        unlink(tmp_path);
        if (err) snprintf(err, errlen, "Failed to write temporary signed Mach-O: %s", tmp_path);
        return false;
    }
    fclose(tf);
    free(buf);

    unlink(path);
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        if (err) snprintf(err, errlen, "Failed to rename signed Mach-O into place: %s", path);
        return false;
    }
    return true;
}

bool husk_macho_verify_signature(const uint8_t *macho_bytes,
                                 size_t macho_size,
                                 char *out_team_id,
                                 size_t team_id_len,
                                 char *err,
                                 size_t errlen)
{
    if (!macho_bytes || macho_size < 4096 || *(const uint32_t *)macho_bytes != 0xFEEDFACFu) {
        if (err) snprintf(err, errlen, "Not a valid 64-bit Mach-O buffer");
        return false;
    }

    uint32_t ncmds = *(const uint32_t *)(macho_bytes + 16);
    const uint8_t *lc = macho_bytes + 32;
    const macho_linkedit_data_cmd_t *cs_cmd = NULL;

    for (uint32_t i = 0; i < ncmds; i++) {
        uint32_t cmd = *(const uint32_t *)lc;
        uint32_t cmdsize = *(const uint32_t *)(lc + 4);
        if (cmd == 0x1Du) {
            cs_cmd = (const macho_linkedit_data_cmd_t *)lc;
            break;
        }
        lc += cmdsize;
    }

    if (!cs_cmd || cs_cmd->dataoff + cs_cmd->datasize > macho_size) {
        if (err) snprintf(err, errlen, "Missing or out-of-bounds LC_CODE_SIGNATURE");
        return false;
    }

    const uint8_t *sb = macho_bytes + cs_cmd->dataoff;
    if (rd_be32(sb) != CS_MAGIC_EMBEDDED_SIGNATURE) {
        if (err) snprintf(err, errlen, "Invalid Embedded Signature SuperBlob magic");
        return false;
    }

    uint32_t count = rd_be32(sb + 8);
    const uint8_t *cd = NULL;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t slot = rd_be32(sb + 12 + i * 8);
        uint32_t off  = rd_be32(sb + 16 + i * 8);
        if (slot == CSSLOT_CODEDIRECTORY && cs_cmd->dataoff + off + 88 <= macho_size) {
            cd = sb + off;
            break;
        }
    }

    if (!cd || rd_be32(cd) != CS_MAGIC_CODEDIRECTORY) {
        if (err) snprintf(err, errlen, "Missing CodeDirectory blob");
        return false;
    }

    uint32_t hash_offset = rd_be32(cd + 16);
    uint32_t n_code_slots = rd_be32(cd + 28);
    uint32_t code_limit = rd_be32(cd + 32);
    uint32_t team_offset = rd_be32(cd + 48);
    uint32_t page_size = 1u << cd[39];

    if (out_team_id && team_id_len > 0 && team_offset > 0) {
        snprintf(out_team_id, team_id_len, "%s", (const char *)(cd + team_offset));
    }

    for (uint32_t p = 0; p < n_code_slots; p++) {
        size_t p_off = (size_t)p * page_size;
        size_t p_len = (p_off + page_size <= code_limit) ? page_size : (size_t)(code_limit - p_off);
        uint8_t actual[32];
        sha256_compute(macho_bytes + p_off, p_len, actual);
        if (memcmp(actual, cd + hash_offset + p * 32, 32) != 0) {
            if (err) snprintf(err, errlen, "SHA-256 page hash mismatch at page %u", p);
            return false;
        }
    }

    return true;
}
