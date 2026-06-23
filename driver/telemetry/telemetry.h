#pragma once

#include "../classify/classify.h"
#include "../../shared/structures/telemetry.h"

VOID
GuardianTelemetryInitialize(VOID);

VOID
GuardianTelemetryShutdown(VOID);

VOID
GuardianTelemetryRecordClassify(
    _In_ GUARDIAN_CLASSIFY_ACTION action,
    _In_ UINT64 latency100ns);

VOID
GuardianTelemetryRecordError(VOID);

VOID
GuardianTelemetryRecordDnsObserve(VOID);

VOID
GuardianTelemetryGet(
    _Out_ GUARDIAN_TELEMETRY_V1* telemetry);

VOID
GuardianPerfStatsGet(
    _Out_ GUARDIAN_PERF_STATS_V1* stats);

VOID
GuardianPerfRecordIpc(
    _In_ BOOLEAN rejected,
    _In_ UINT64 latency100ns);
