#include "telemetry.h"

#include "../policy/app_policy.h"
#include "../route/route_assignment.h"

#define GUARDIAN_MAX_CPUS 64
#define GUARDIAN_LATENCY_SAMPLE_MASK 0xFFu

typedef struct _GUARDIAN_TELEMETRY_STATE {
    UINT64 ClassifyCount;
    UINT64 BlockCount;
    UINT64 RouteCount;
    UINT64 PermitCount;
    UINT64 ObserveCount;
    UINT64 ErrorCount;
    UINT64 DnsObserveCount;
    UINT64 LatencySum100ns;
    UINT64 LatencySamples;
    UINT64 MaxLatency100ns;
    UINT64 IpcDispatchCount;
    UINT64 IpcRejectCount;
    UINT64 IpcLatencySum100ns;
    UINT64 IpcLatencySamples;
    UINT64 MaxIpcLatency100ns;
    UINT64 DeferredWorkCount;
} GUARDIAN_TELEMETRY_STATE;

static GUARDIAN_TELEMETRY_STATE g_Telemetry;

VOID
GuardianTelemetryInitialize(VOID)
{
    RtlZeroMemory(&g_Telemetry, sizeof(g_Telemetry));
}

VOID
GuardianTelemetryShutdown(VOID)
{
}

VOID
GuardianTelemetryRecordClassify(
    _In_ GUARDIAN_CLASSIFY_ACTION action,
    _In_ UINT64 latency100ns)
{
    InterlockedIncrement64((volatile LONG64*)&g_Telemetry.ClassifyCount);

    switch (action) {
    case GuardianClassifyBlock:
        InterlockedIncrement64((volatile LONG64*)&g_Telemetry.BlockCount);
        break;
    case GuardianClassifyRoute:
        InterlockedIncrement64((volatile LONG64*)&g_Telemetry.RouteCount);
        break;
    case GuardianClassifyObserve:
        InterlockedIncrement64((volatile LONG64*)&g_Telemetry.ObserveCount);
        break;
    default:
        InterlockedIncrement64((volatile LONG64*)&g_Telemetry.PermitCount);
        break;
    }

    if ((g_Telemetry.LatencySamples & GUARDIAN_LATENCY_SAMPLE_MASK) == 0) {
        InterlockedAdd64((volatile LONG64*)&g_Telemetry.LatencySum100ns, (LONG64)latency100ns);
        InterlockedIncrement64((volatile LONG64*)&g_Telemetry.LatencySamples);
        if (latency100ns > g_Telemetry.MaxLatency100ns) {
            g_Telemetry.MaxLatency100ns = latency100ns;
        }
    }
}

VOID
GuardianTelemetryRecordError(VOID)
{
    InterlockedIncrement64((volatile LONG64*)&g_Telemetry.ErrorCount);
}

VOID
GuardianTelemetryRecordDnsObserve(VOID)
{
    InterlockedIncrement64((volatile LONG64*)&g_Telemetry.DnsObserveCount);
}

VOID
GuardianTelemetryGet(
    _Out_ GUARDIAN_TELEMETRY_V1* telemetry)
{
    RtlZeroMemory(telemetry, sizeof(*telemetry));
    telemetry->Version = GUARDIAN_TELEMETRY_VERSION;
    telemetry->ClassifyCount = g_Telemetry.ClassifyCount;
    telemetry->BlockCount = g_Telemetry.BlockCount;
    telemetry->RouteCount = g_Telemetry.RouteCount;
    telemetry->PermitCount = g_Telemetry.PermitCount;
    telemetry->ObserveCount = g_Telemetry.ObserveCount;
    telemetry->ErrorCount = g_Telemetry.ErrorCount;
    telemetry->DnsObserveCount = g_Telemetry.DnsObserveCount;
    telemetry->MaxClassifyLatency100ns = g_Telemetry.MaxLatency100ns;
    if (g_Telemetry.LatencySamples > 0) {
        telemetry->AvgClassifyLatency100ns =
            g_Telemetry.LatencySum100ns / g_Telemetry.LatencySamples;
    }
}

VOID
GuardianPerfStatsGet(
    _Out_ GUARDIAN_PERF_STATS_V1* stats)
{
    RtlZeroMemory(stats, sizeof(*stats));
    stats->Version = GUARDIAN_PERF_STATS_VERSION;
    stats->IpcDispatchCount = g_Telemetry.IpcDispatchCount;
    stats->IpcRejectCount = g_Telemetry.IpcRejectCount;
    stats->MaxIpcLatency100ns = g_Telemetry.MaxIpcLatency100ns;
    stats->DeferredWorkCount = g_Telemetry.DeferredWorkCount;
    stats->ActivePolicyCount = GuardianAppPolicyActiveCount();
    stats->ActiveRouteCount = GuardianRouteActiveCount();
    if (g_Telemetry.IpcLatencySamples > 0) {
        stats->AvgIpcLatency100ns =
            g_Telemetry.IpcLatencySum100ns / g_Telemetry.IpcLatencySamples;
    }
}

VOID
GuardianPerfRecordIpc(
    _In_ BOOLEAN rejected,
    _In_ UINT64 latency100ns)
{
    InterlockedIncrement64((volatile LONG64*)&g_Telemetry.IpcDispatchCount);
    if (rejected) {
        InterlockedIncrement64((volatile LONG64*)&g_Telemetry.IpcRejectCount);
    }
    InterlockedAdd64((volatile LONG64*)&g_Telemetry.IpcLatencySum100ns, (LONG64)latency100ns);
    InterlockedIncrement64((volatile LONG64*)&g_Telemetry.IpcLatencySamples);
    if (latency100ns > g_Telemetry.MaxIpcLatency100ns) {
        g_Telemetry.MaxIpcLatency100ns = latency100ns;
    }
}
