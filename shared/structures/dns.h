#pragma once

#include "../guardian_types.h"

#define GUARDIAN_DNS_CONFIG_VERSION 1
#define GUARDIAN_DNS_CAP_OBSERVE 0x00000001u
#define GUARDIAN_DNS_CAP_REDIRECT 0x00000002u

#pragma pack(push, 1)

typedef struct _GUARDIAN_DNS_CONFIG_V1 {
    UINT32 Version;
    UINT32 Capabilities;
    UINT8 Enabled;
    UINT8 ObserveOnly;
    UINT8 Reserved[2];
    UINT16 ProxyPort;
    UINT32 ExcludedPidCount;
    UINT32 ExcludedPids[16];
} GUARDIAN_DNS_CONFIG_V1, *PGUARDIAN_DNS_CONFIG_V1;

typedef struct _GUARDIAN_DNS_STATS_V1 {
    UINT32 Version;
    UINT64 ObservedV4;
    UINT64 ObservedV6;
    UINT64 SkippedLoopback;
    UINT64 SkippedExcluded;
    UINT64 SkippedDisabled;
    UINT64 Errors;
} GUARDIAN_DNS_STATS_V1, *PGUARDIAN_DNS_STATS_V1;

#pragma pack(pop)
