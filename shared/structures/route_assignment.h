#pragma once

#include <stdint.h>

#define GUARDIAN_ROUTE_ASSIGNMENT_VERSION 1
#define GUARDIAN_MAX_SYNC_ROUTES 512

typedef enum _GUARDIAN_ROUTE_KIND {
    GuardianRouteDirect = 0,
    GuardianRouteVpn = 1,
    GuardianRouteTailnet = 2,
    GuardianRouteTor = 3,
    GuardianRouteAnonymous = 4,
    GuardianRouteBlocked = 5,
    GuardianRouteProxy = 6,
    GuardianRouteChain = 7,
} GUARDIAN_ROUTE_KIND;

#pragma pack(push, 1)

typedef struct _GUARDIAN_ROUTE_ASSIGNMENT_V1 {
    UINT32 Version;
    UINT8 AppId[16];
    UINT32 RouteKind;
    UINT64 ProfileId;
    UINT64 InterfaceLuid;
    UINT16 SocksPort;
    UINT8 Reserved[6];
} GUARDIAN_ROUTE_ASSIGNMENT_V1, *PGUARDIAN_ROUTE_ASSIGNMENT_V1;

typedef struct _GUARDIAN_SYNC_ROUTES_V1 {
    UINT32 Version;
    UINT32 RouteCount;
    GUARDIAN_ROUTE_ASSIGNMENT_V1 Routes[1];
} GUARDIAN_SYNC_ROUTES_V1, *PGUARDIAN_SYNC_ROUTES_V1;

#pragma pack(pop)

/* Phase 12-K mixnet/transform fields: see route_assignment_v2.h (GUARDIAN_ROUTE_ASSIGNMENT_V2). */
