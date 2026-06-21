#pragma once

#include <stdint.h>

#define GUARDIAN_APP_POLICY_VERSION 1
#define GUARDIAN_MAX_EXE_PATH_CHARS 520
#define GUARDIAN_MAX_PACKAGE_FAMILY_CHARS 128
#define GUARDIAN_SHA256_BYTES 32
#define GUARDIAN_MAX_SID_BYTES 68
#define GUARDIAN_MAX_SYNC_POLICIES 256

typedef enum _GUARDIAN_POLICY_ACTION {
    GuardianPolicyAllow = 0,
    GuardianPolicyBlock = 1,
    GuardianPolicyRoute = 2,
    GuardianPolicyObserve = 3,
} GUARDIAN_POLICY_ACTION;

typedef enum _GUARDIAN_POLICY_MATCH_KIND {
    GuardianMatchNone = 0,
    GuardianMatchProcessPath = 1,
    GuardianMatchExeHash = 2,
    GuardianMatchSid = 3,
    GuardianMatchPackageFamily = 4,
} GUARDIAN_POLICY_MATCH_KIND;

#pragma pack(push, 1)

typedef struct _GUARDIAN_APP_POLICY_V1 {
    UINT32 Version;
    UINT8 AppId[16];
    UINT32 Action;
    UINT32 MatchKind;
    UINT32 ExePathLengthChars;
    WCHAR ExePath[GUARDIAN_MAX_EXE_PATH_CHARS];
    UINT8 ExeHashSha256[GUARDIAN_SHA256_BYTES];
    UINT32 SidLengthBytes;
    UINT8 SidBytes[GUARDIAN_MAX_SID_BYTES];
    WCHAR PackageFamilyName[GUARDIAN_MAX_PACKAGE_FAMILY_CHARS];
    UINT64 ProfileId;
    UINT64 InterfaceLuid;
} GUARDIAN_APP_POLICY_V1, *PGUARDIAN_APP_POLICY_V1;

typedef struct _GUARDIAN_SYNC_POLICIES_V1 {
    UINT32 Version;
    UINT32 PolicyCount;
    GUARDIAN_APP_POLICY_V1 Policies[1];
} GUARDIAN_SYNC_POLICIES_V1, *PGUARDIAN_SYNC_POLICIES_V1;

#pragma pack(pop)
