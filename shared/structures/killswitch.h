#pragma once

#include "../guardian_types.h"

#define GUARDIAN_KILL_SWITCH_VERSION 1

typedef enum _GUARDIAN_KILL_SWITCH_MODE {
    GuardianKsOff = 0,
    GuardianKsBlockAll = 1,
    GuardianKsAllowVpnOnly = 2,
    GuardianKsRestore = 3,
} GUARDIAN_KILL_SWITCH_MODE;

#pragma pack(push, 1)

typedef struct _GUARDIAN_KILL_SWITCH_V1 {
    UINT32 Version;
    UINT32 Mode;
    UINT64 VpnInterfaceLuid;
} GUARDIAN_KILL_SWITCH_V1, *PGUARDIAN_KILL_SWITCH_V1;

#pragma pack(pop)
