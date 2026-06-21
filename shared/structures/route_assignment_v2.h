#pragma once

/* Phase 12-K additive route layout — V1 remains in route_assignment.h */

#include "route_assignment.h"

#define GUARDIAN_ROUTE_ASSIGNMENT_V2_VERSION 2

#pragma pack(push, 1)

typedef struct _GUARDIAN_ROUTE_ASSIGNMENT_V2 {
    UINT32 Version;
    UINT8 AppId[16];
    UINT32 RouteKind;
    UINT64 ProfileId;
    UINT64 InterfaceLuid;
    UINT16 SocksPort;
    UINT8 Reserved[6];
    UINT64 MixnetProfileId;
    UINT32 TransformProfile;
    UINT8 Reserved2[4];
} GUARDIAN_ROUTE_ASSIGNMENT_V2, *PGUARDIAN_ROUTE_ASSIGNMENT_V2;

typedef struct _GUARDIAN_SYNC_ROUTES_V2 {
    UINT32 Version;
    UINT32 RouteCount;
    GUARDIAN_ROUTE_ASSIGNMENT_V2 Routes[1];
} GUARDIAN_SYNC_ROUTES_V2, *PGUARDIAN_SYNC_ROUTES_V2;

#pragma pack(pop)
