/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * HuskJITLessBootstrap.m — iOS / Objective-C integration bridge for Developer
 * Certificate configuration and Husk-JITLess translation layer initialization.
 */
#if defined(__APPLE__)
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
#include "husk_jitless.h"

@interface HuskJITLessBridge : NSObject
+ (BOOL)configureCertificateWithData:(NSData *)p12Data
                            password:(NSString *)password
                             runtime:(husk_jitless_runtime *)rt
                               error:(NSError **)error;
@end

@implementation HuskJITLessBridge

+ (BOOL)configureCertificateWithData:(NSData *)p12Data
                            password:(NSString *)password
                             runtime:(husk_jitless_runtime *)rt
                               error:(NSError **)error
{
    if (!p12Data || !rt) {
        if (error) {
            *error = [NSError errorWithDomain:@"HuskJITLess"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Missing PKCS#12 developer certificate data."}];
        }
        return NO;
    }

    char errBuf[256] = {0};
    if (!husk_jitless_set_dev_cert(rt, p12Data.bytes, p12Data.length,
                                   (password ?: @"").UTF8String, errBuf, sizeof(errBuf))) {
        if (error) {
            *error = [NSError errorWithDomain:@"HuskJITLess"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: @(errBuf)}];
        }
        return NO;
    }
    return YES;
}

@end
#endif
