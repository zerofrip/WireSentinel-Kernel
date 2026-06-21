#pragma once

#include <ntddk.h>

#include "../../shared/structures/guardian_state.h"

NTSTATUS
GuardianFiltersInitialize(VOID);

VOID
GuardianFiltersShutdown(VOID);

NTSTATUS
GuardianHybridCoordinatorInitialize(VOID);

VOID
GuardianHybridCoordinatorShutdown(VOID);

NTSTATUS
GuardianHybridPollNdisState(VOID);

UINT32
GuardianHybridGetNdisFilterCount(VOID);

VOID
GuardianHybridSetNdisFilterCount(
    _In_ UINT32 filterCount);

UINT32
GuardianHybridGetCombinedFilterCount(VOID);

GUARDIAN_MODE
GuardianHybridGetMode(VOID);

NTSTATUS
GuardianHybridSetMode(
    _In_ GUARDIAN_MODE mode);
