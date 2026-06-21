#include "dns_observe.h"

#include "../telemetry/telemetry.h"

static GUARDIAN_DNS_CONFIG_V1 g_DnsConfig;
static GUARDIAN_DNS_STATS_V1 g_DnsStats;
static KSPIN_LOCK g_DnsLock;

NTSTATUS
GuardianDnsLayerInitialize(VOID)
{
    KeInitializeSpinLock(&g_DnsLock);
    RtlZeroMemory(&g_DnsConfig, sizeof(g_DnsConfig));
    RtlZeroMemory(&g_DnsStats, sizeof(g_DnsStats));
    g_DnsConfig.Version = GUARDIAN_DNS_CONFIG_VERSION;
    g_DnsConfig.Capabilities = GUARDIAN_DNS_CAP_OBSERVE;
    g_DnsConfig.ObserveOnly = TRUE;
    g_DnsStats.Version = GUARDIAN_DNS_CONFIG_VERSION;
    return STATUS_SUCCESS;
}

VOID
GuardianDnsLayerShutdown(VOID)
{
}

NTSTATUS
GuardianDnsLayerSetConfig(
    _In_ const GUARDIAN_DNS_CONFIG_V1* config)
{
    KIRQL oldIrql;

    if (config == NULL || config->Version != GUARDIAN_DNS_CONFIG_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_DnsLock, &oldIrql);
    RtlCopyMemory(&g_DnsConfig, config, sizeof(*config));
    g_DnsConfig.ObserveOnly = TRUE;
    KeReleaseSpinLock(&g_DnsLock, oldIrql);

    return STATUS_SUCCESS;
}

VOID
GuardianDnsLayerGetStats(
    _Out_ GUARDIAN_DNS_STATS_V1* stats)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_DnsLock, &oldIrql);
    RtlCopyMemory(stats, &g_DnsStats, sizeof(*stats));
    KeReleaseSpinLock(&g_DnsLock, oldIrql);
}

BOOLEAN
GuardianDnsLayerShouldObserve(
    _In_ UINT16 remotePort,
    _In_ UINT32 excludedPid)
{
    KIRQL oldIrql;
    BOOLEAN observe = FALSE;
    UINT32 i;

    if (remotePort != 53) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_DnsLock, &oldIrql);
    if (!g_DnsConfig.Enabled) {
        g_DnsStats.SkippedDisabled++;
        KeReleaseSpinLock(&g_DnsLock, oldIrql);
        return FALSE;
    }

    for (i = 0; i < g_DnsConfig.ExcludedPidCount && i < 16; ++i) {
        if (g_DnsConfig.ExcludedPids[i] == excludedPid) {
            g_DnsStats.SkippedExcluded++;
            KeReleaseSpinLock(&g_DnsLock, oldIrql);
            return FALSE;
        }
    }

    observe = TRUE;
    g_DnsStats.ObservedV4++;
    KeReleaseSpinLock(&g_DnsLock, oldIrql);

    GuardianTelemetryRecordDnsObserve();
    return observe;
}
