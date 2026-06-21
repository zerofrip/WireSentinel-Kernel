#pragma once

#include "../../shared/structures/app_policy.h"

#define GUARDIAN_MAX_POLICIES 4096

NTSTATUS
GuardianAppPolicyInitialize(VOID);

VOID
GuardianAppPolicyShutdown(VOID);

NTSTATUS
GuardianAppPolicySet(
    _In_ const GUARDIAN_APP_POLICY_V1* policy);

NTSTATUS
GuardianAppPolicyRemove(
    _In_ const UINT8 appId[16]);

NTSTATUS
GuardianAppPolicySync(
    _In_reads_(count) const GUARDIAN_APP_POLICY_V1* policies,
    _In_ UINT32 count);

NTSTATUS
GuardianAppPolicyLookup(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Out_ GUARDIAN_APP_POLICY_V1* policy,
    _Out_ BOOLEAN* found);

UINT32
GuardianAppPolicyActiveCount(VOID);
