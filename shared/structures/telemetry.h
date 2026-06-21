#pragma once

#include <stdint.h>

#define GUARDIAN_TELEMETRY_VERSION 1
#define GUARDIAN_PERF_STATS_VERSION 1

#pragma pack(push, 1)

typedef struct _GUARDIAN_TELEMETRY_V1 {
    UINT32 Version;
    UINT64 ClassifyCount;
    UINT64 BlockCount;
    UINT64 RouteCount;
    UINT64 PermitCount;
    UINT64 ObserveCount;
    UINT64 ErrorCount;
    UINT64 DnsObserveCount;
    UINT64 AvgClassifyLatency100ns;
    UINT64 MaxClassifyLatency100ns;
} GUARDIAN_TELEMETRY_V1, *PGUARDIAN_TELEMETRY_V1;

typedef struct _GUARDIAN_PERF_STATS_V1 {
    UINT32 Version;
    UINT64 IpcDispatchCount;
    UINT64 IpcRejectCount;
    UINT64 AvgIpcLatency100ns;
    UINT64 MaxIpcLatency100ns;
    UINT64 DeferredWorkCount;
    UINT32 ActivePolicyCount;
    UINT32 ActiveRouteCount;
} GUARDIAN_PERF_STATS_V1, *PGUARDIAN_PERF_STATS_V1;

#pragma pack(pop)
