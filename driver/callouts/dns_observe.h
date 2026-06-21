#pragma once

#include "../../shared/structures/dns.h"

NTSTATUS
GuardianDnsLayerInitialize(VOID);

VOID
GuardianDnsLayerShutdown(VOID);

NTSTATUS
GuardianDnsLayerSetConfig(
    _In_ const GUARDIAN_DNS_CONFIG_V1* config);

VOID
GuardianDnsLayerGetStats(
    _Out_ GUARDIAN_DNS_STATS_V1* stats);

BOOLEAN
GuardianDnsLayerShouldObserve(
    _In_ UINT16 remotePort,
    _In_ UINT32 excludedPid);
