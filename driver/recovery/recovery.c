#include "recovery.h"

#include "../guardian/driver.h"
#include "../state/guardian_state_mgr.h"

static UINT32 g_RecoveryStatus = GUARDIAN_RECOVERY_STATUS_OK;

NTSTATUS
GuardianRecoveryManagerInitialize(
    _In_opt_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    g_RecoveryStatus = GUARDIAN_RECOVERY_STATUS_OK;
    return STATUS_SUCCESS;
}

NTSTATUS
GuardianRecoveryManagerBegin(VOID)
{
    UINT32 generation = GuardianStateManagerRecoveryGeneration() + 1;
    GuardianStateManagerSetRecoveryGeneration(generation);
    g_GuardianDriverState.RecoveryGeneration = generation;
    g_RecoveryStatus = GUARDIAN_RECOVERY_STATUS_OK;
    return STATUS_SUCCESS;
}

NTSTATUS
GuardianRecoveryReconcile(
    _In_reads_opt_(knownCount) const UINT64* knownFilterIds,
    _In_ UINT32 knownCount,
    _Out_ GUARDIAN_RECONCILE_RESPONSE_V1* response)
{
    UNREFERENCED_PARAMETER(knownFilterIds);
    UNREFERENCED_PARAMETER(knownCount);

    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(response, sizeof(*response));
    response->Version = 1;
    response->RemovedOrphans = 0;
    response->RecoveryGeneration = GuardianStateManagerRecoveryGeneration();
    response->RecoveryStatus = g_RecoveryStatus;

    return STATUS_SUCCESS;
}
