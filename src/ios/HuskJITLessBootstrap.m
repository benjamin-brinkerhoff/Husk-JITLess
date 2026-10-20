/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * HuskJITLessBootstrap.m — iOS / Objective-C integration bridge combining
 * LiveContainer's Developer Certificate discovery with Husk-JITLess.
 */
#if defined(__APPLE__)
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
#include "husk_jitless.h"

extern void *SecTaskCreateFromSelf(CFAllocatorRef allocator);
extern CFTypeRef SecTaskCopyValueForEntitlement(void *task, CFStringRef entitlement, CFErrorRef *error);

@interface HuskJITLessBridge : NSObject
+ (nullable NSString *)hostTeamIdentifier;
+ (nullable NSURL *)discoverSideStoreAppGroupURL;
+ (BOOL)importCertificateFromSideStoreIntoRuntime:(husk_jitless_runtime *)rt error:(NSError **)error;
@end

@implementation HuskJITLessBridge

+ (nullable NSString *)hostTeamIdentifier
{
    static NSString *teamId = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void *taskSelf = SecTaskCreateFromSelf(NULL);
        if (taskSelf) {
            CFErrorRef err = NULL;
            CFTypeRef val = SecTaskCopyValueForEntitlement(taskSelf, CFSTR("com.apple.developer.team-identifier"), &err);
            if (val && CFGetTypeID(val) == CFStringGetTypeID()) {
                teamId = [(__bridge NSString *)val copy];
            }
            if (val) CFRelease(val);
            CFRelease(taskSelf);
        }
    });
    return teamId;
}

+ (nullable NSURL *)discoverSideStoreAppGroupURL
{
    NSString *team = [self hostTeamIdentifier];
    if (!team) return nil;
    NSArray<NSString *> *groups = @[
        [@"group.com.SideStore.SideStore." stringByAppendingString:team],
        [@"group.com.rileytestut.AltStore." stringByAppendingString:team]
    ];
    for (NSString *g in groups) {
        NSURL *url = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:g];
        if (url && [[NSFileManager defaultManager] fileExistsAtPath:[[url URLByAppendingPathComponent:@"Apps"] path]]) {
            return url;
        }
    }
    return nil;
}

+ (BOOL)importCertificateFromSideStoreIntoRuntime:(husk_jitless_runtime *)rt error:(NSError **)error
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSData *p12Data = [defaults dataForKey:@"LCCertificateData"];
    NSString *password = [defaults stringForKey:@"LCCertificatePassword"] ?: @"";

    if (!p12Data) {
        if (error) {
            *error = [NSError errorWithDomain:@"HuskJITLess"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"No developer certificate imported yet."}];
        }
        return NO;
    }

    char errBuf[256] = {0};
    if (!husk_jitless_set_dev_cert(rt, p12Data.bytes, p12Data.length, password.UTF8String, errBuf, sizeof(errBuf))) {
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
