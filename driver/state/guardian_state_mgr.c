#include "guardian_state_mgr.h"

#include "../guardian/driver.h"
#include "../policy/app_policy.h"
#include "../route/route_assignment.h"
#include "../killswitch/killswitch.h"

static UINT32 g_RecoveryGeneration = 0;
static UINT32 g_FilterCount = 0;

NTSTATUS
GuardianStateManagerInitialize(VOID)
{
    GuardianAppPolicyInitialize();
    GuardianRouteInitialize();
    g_RecoveryGeneration = 0;
    g_FilterCount = 0;
    return STATUS_SUCCESS;
}

VOID
GuardianStateManagerShutdown(VOID)
{
    GuardianRouteShutdown();
    GuardianAppPolicyShutdown();
}

NTSTATUS
GuardianStateManagerExport(
    _Out_writes_bytes_(bufferBytes) UINT8* buffer,
    _In_ UINT32 bufferBytes,
    _Out_ UINT32* bytesWritten)
{
    GUARDIAN_STATE_BLOB_HEADER_V1 header;

    if (buffer == NULL || bytesWritten == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (bufferBytes < sizeof(header)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&header, sizeof(header));
    header.Version = GUARDIAN_STATE_BLOB_VERSION;
    header.PolicyCount = GuardianAppPolicyActiveCount();
    header.RouteCount = GuardianRouteActiveCount();
    header.KillSwitchMode = (UINT32)GuardianKillSwitchGetMode();
    header.RecoveryGeneration = g_RecoveryGeneration;

    RtlCopyMemory(buffer, &header, sizeof(header));
    *bytesWritten = (UINT32)sizeof(header);

    return STATUS_SUCCESS;
}

NTSTATUS
GuardianStateManagerImport(
    _In_reads_bytes_(bufferBytes) const UINT8* buffer,
    _In_ UINT32 bufferBytes)
{
    const GUARDIAN_STATE_BLOB_HEADER_V1* header;

    if (buffer == NULL || bufferBytes < sizeof(GUARDIAN_STATE_BLOB_HEADER_V1)) {
        return STATUS_INVALID_PARAMETER;
    }

    header = (const GUARDIAN_STATE_BLOB_HEADER_V1*)buffer;
    if (header->Version != GUARDIAN_STATE_BLOB_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    g_RecoveryGeneration = header->RecoveryGeneration;
    g_GuardianDriverState.RecoveryGeneration = g_RecoveryGeneration;
    g_GuardianDriverState.KillSwitchMode = header->KillSwitchMode;

    return STATUS_SUCCESS;
}

UINT32
GuardianStateManagerRecoveryGeneration(VOID)
{
    return g_RecoveryGeneration;
}

VOID
GuardianStateManagerSetRecoveryGeneration(
    _In_ UINT32 generation)
{
    g_RecoveryGeneration = generation;
    g_GuardianDriverState.RecoveryGeneration = generation;
}

UINT32
GuardianStateManagerFilterCount(VOID)
{
    return g_FilterCount;
}
