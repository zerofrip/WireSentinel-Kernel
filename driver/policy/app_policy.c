#include "app_policy.h"

#include "../guardian/driver.h"
#include <ntstrsafe.h>

typedef struct _GUARDIAN_POLICY_ENTRY {
    LIST_ENTRY Link;
    GUARDIAN_APP_POLICY_V1 Policy;
} GUARDIAN_POLICY_ENTRY, *PGUARDIAN_POLICY_ENTRY;

static LIST_ENTRY g_PolicyList;
static KSPIN_LOCK g_PolicyLock;
static UINT32 g_PolicyCount;

NTSTATUS
GuardianAppPolicyInitialize(VOID)
{
    InitializeListHead(&g_PolicyList);
    KeInitializeSpinLock(&g_PolicyLock);
    g_PolicyCount = 0;
    return STATUS_SUCCESS;
}

VOID
GuardianAppPolicyShutdown(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    while (!IsListEmpty(&g_PolicyList)) {
        entry = RemoveHeadList(&g_PolicyList);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, GUARDIAN_POLICY_ENTRY, Link), GUARDIAN_POOL_TAG);
    }
    g_PolicyCount = 0;
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);
}

static PGUARDIAN_POLICY_ENTRY
GuardianPolicyFindLocked(
    _In_ const UINT8 appId[16])
{
    PLIST_ENTRY entry;

    for (entry = g_PolicyList.Flink; entry != &g_PolicyList; entry = entry->Flink) {
        PGUARDIAN_POLICY_ENTRY item = CONTAINING_RECORD(entry, GUARDIAN_POLICY_ENTRY, Link);
        if (RtlCompareMemory(item->Policy.AppId, appId, 16) == 16) {
            return item;
        }
    }

    return NULL;
}

NTSTATUS
GuardianAppPolicySet(
    _In_ const GUARDIAN_APP_POLICY_V1* policy)
{
    KIRQL oldIrql;
    PGUARDIAN_POLICY_ENTRY entry;
    PGUARDIAN_POLICY_ENTRY existing;

    if (policy == NULL || policy->Version != GUARDIAN_APP_POLICY_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = (PGUARDIAN_POLICY_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(GUARDIAN_POLICY_ENTRY),
        GUARDIAN_POOL_TAG);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&entry->Policy, policy, sizeof(*policy));

    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    existing = GuardianPolicyFindLocked(policy->AppId);
    if (existing != NULL) {
        RtlCopyMemory(&existing->Policy, policy, sizeof(*policy));
        KeReleaseSpinLock(&g_PolicyLock, oldIrql);
        ExFreePoolWithTag(entry, GUARDIAN_POOL_TAG);
        return STATUS_SUCCESS;
    }

    if (g_PolicyCount >= GUARDIAN_MAX_POLICIES) {
        KeReleaseSpinLock(&g_PolicyLock, oldIrql);
        ExFreePoolWithTag(entry, GUARDIAN_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InsertTailList(&g_PolicyList, &entry->Link);
    g_PolicyCount++;
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);

    return STATUS_SUCCESS;
}

NTSTATUS
GuardianAppPolicyRemove(
    _In_ const UINT8 appId[16])
{
    KIRQL oldIrql;
    PGUARDIAN_POLICY_ENTRY existing;

    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    existing = GuardianPolicyFindLocked(appId);
    if (existing == NULL) {
        KeReleaseSpinLock(&g_PolicyLock, oldIrql);
        return STATUS_NOT_FOUND;
    }

    RemoveEntryList(&existing->Link);
    g_PolicyCount--;
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);

    ExFreePoolWithTag(existing, GUARDIAN_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
GuardianAppPolicySync(
    _In_reads_(count) const GUARDIAN_APP_POLICY_V1* policies,
    _In_ UINT32 count)
{
    UINT32 i;
    NTSTATUS status;

    if (policies == NULL || count > GUARDIAN_MAX_SYNC_POLICIES) {
        return STATUS_INVALID_PARAMETER;
    }

    GuardianAppPolicyShutdown();
    GuardianAppPolicyInitialize();

    for (i = 0; i < count; ++i) {
        status = GuardianAppPolicySet(&policies[i]);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
GuardianAppPolicyLookup(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Out_ GUARDIAN_APP_POLICY_V1* policy,
    _Out_ BOOLEAN* found)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    FWP_BYTE_BLOB const* appIdBlob = NULL;
    UINT32 layerId;

    UNREFERENCED_PARAMETER(inMetaValues);

    *found = FALSE;
    RtlZeroMemory(policy, sizeof(*policy));

    if (inFixedValues == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    layerId = inFixedValues->layerId;

    if (layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
            appIdBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob;
        }
    } else if (layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
            appIdBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.byteBlob;
        }
    }

    KeAcquireSpinLock(&g_PolicyLock, &oldIrql);
    for (entry = g_PolicyList.Flink; entry != &g_PolicyList; entry = entry->Flink) {
        PGUARDIAN_POLICY_ENTRY item = CONTAINING_RECORD(entry, GUARDIAN_POLICY_ENTRY, Link);

        if (item->Policy.MatchKind == GuardianMatchProcessPath && appIdBlob != NULL) {
            if (appIdBlob->size > 0) {
                RtlCopyMemory(policy, &item->Policy, sizeof(*policy));
                *found = TRUE;
                break;
            }
        } else if (item->Policy.MatchKind == GuardianMatchNone) {
            RtlCopyMemory(policy, &item->Policy, sizeof(*policy));
            *found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_PolicyLock, oldIrql);

    return STATUS_SUCCESS;
}

UINT32
GuardianAppPolicyActiveCount(VOID)
{
    return g_PolicyCount;
}
