#pragma once

#include <ntddk.h>

#include "../../shared/protocol/guardian_message.h"

NTSTATUS
GuardianRecoveryManagerInitialize(
    _In_opt_ PUNICODE_STRING RegistryPath);

NTSTATUS
GuardianRecoveryManagerBegin(VOID);

NTSTATUS
GuardianRecoveryReconcile(
    _In_reads_opt_(knownCount) const UINT64* knownFilterIds,
    _In_ UINT32 knownCount,
    _Out_ GUARDIAN_RECONCILE_RESPONSE_V1* response);
