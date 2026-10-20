/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * husk-jitless-cli.c — Command-line utility for Husk-JITLess.
 */
#include "husk_jitless.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s convert <input.so> <output.dylib> [--p12 <cert.p12> --pass <password>]\n"
        "  %s verify  <input.dylib>\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "convert") == 0) {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        const char *in_elf = argv[2];
        const char *out_dylib = argv[3];
        const char *p12_path = NULL;
        const char *p12_pass = "";

        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--p12") == 0 && i + 1 < argc) {
                p12_path = argv[++i];
            } else if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) {
                p12_pass = argv[++i];
            }
        }

        elf2macho_options opts;
        memset(&opts, 0, sizeof(opts));
        opts.install_name = "@rpath/libtranslated.aot.dylib";
        opts.vx18_tsd_off = 0x100u;
        opts.verbose = true;

        elf2macho_result res;
        if (!husk_elf2macho_convert_file(in_elf, out_dylib, &opts, &res)) {
            fprintf(stderr, "Error converting %s: %s\n", in_elf, res.error);
            return 1;
        }
        free(res.macho_bytes);

        husk_dev_cert cert;
        memset(&cert, 0, sizeof(cert));
        char err[256] = {0};
        if (p12_path) {
            if (!husk_cert_load_p12_file(&cert, p12_path, p12_pass, err, sizeof(err))) {
                fprintf(stderr, "Error loading developer certificate %s: %s\n", p12_path, err);
                return 1;
            }
        }

        if (!husk_macho_sign_file_atomic(out_dylib, "com.husk.jitless.translated",
                                         p12_path ? &cert : NULL, err, sizeof(err))) {
            fprintf(stderr, "Error signing %s: %s\n", out_dylib, err);
            husk_cert_free(&cert);
            return 1;
        }

        printf("Successfully converted and signed %s -> %s\n", in_elf, out_dylib);
        printf("  SONAME           : %s\n", res.meta.soname[0] ? res.meta.soname : "(none)");
        printf("  Team ID          : %s\n", cert.loaded ? cert.team_id : "ADHOC00000");
        printf("  x18 rewritten    : %zu\n", res.meta.rewrite_stats.x18_rewritten);
        printf("  tpidr_el0 patched: %zu\n", res.meta.rewrite_stats.tpidr_rewritten);
        printf("  ctr_el0 patched  : %zu\n", res.meta.rewrite_stats.ctr_rewritten);
        printf("  svc #0 patched   : %zu\n", res.meta.rewrite_stats.svc_rewritten);
        printf("  AOT stubs bytes  : %zu\n", res.meta.rewrite_stats.stubs_bytes_used);

        husk_cert_free(&cert);
        return 0;
    } else if (strcmp(argv[1], "verify") == 0) {
        const char *path = argv[2];
        FILE *f = fopen(path, "rb");
        if (!f) {
            fprintf(stderr, "Cannot open %s\n", path);
            return 1;
        }
        fseek(f, 0, SEEK_END);
        size_t sz = (size_t)ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *buf = (uint8_t *)malloc(sz);
        if (!buf || fread(buf, 1, sz, f) != sz) {
            fclose(f);
            free(buf);
            fprintf(stderr, "Failed to read %s\n", path);
            return 1;
        }
        fclose(f);

        char team_id[64] = {0};
        char err[256] = {0};
        bool ok = husk_macho_verify_signature(buf, sz, team_id, sizeof(team_id), err, sizeof(err));
        free(buf);
        if (!ok) {
            fprintf(stderr, "Signature verification FAILED for %s: %s\n", path, err);
            return 1;
        }
        printf("Signature verification PASSED for %s (Team ID: %s)\n", path, team_id);
        return 0;
    }

    usage(argv[0]);
    return 1;
}
