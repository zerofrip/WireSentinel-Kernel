#pragma once

#include "../../shared/structures/guardian_state.h"
#include "../../shared/structures/app_policy.h"
#include "../../shared/structures/route_assignment.h"

NTSTATUS
GuardianStateManagerInitialize(VOID);

VOID
GuardianStateManagerShutdown(VOID);

NTSTATUS
GuardianStateManagerExport(
    _Out_writes_bytes_(bufferBytes) UINT8* buffer,
    _In_ UINT32 bufferBytes,
    _Out_ UINT32* bytesWritten);

NTSTATUS
GuardianStateManagerImport(
    _In_reads_bytes_(bufferBytes) const UINT8* buffer,
    _In_ UINT32 bufferBytes);

UINT32
GuardianStateManagerRecoveryGeneration(VOID);

VOID
GuardianStateManagerSetRecoveryGeneration(
    _In_ UINT32 generation);

UINT32
GuardianStateManagerFilterCount(VOID);
