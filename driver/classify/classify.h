#pragma once

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>

typedef enum _GUARDIAN_CLASSIFY_ACTION {
    GuardianClassifyPermit = 0,
    GuardianClassifyBlock = 1,
    GuardianClassifyRoute = 2,
    GuardianClassifyObserve = 3,
} GUARDIAN_CLASSIFY_ACTION;

typedef struct _GUARDIAN_CLASSIFY_RESULT {
    GUARDIAN_CLASSIFY_ACTION Action;
    UINT64 InterfaceLuid;
} GUARDIAN_CLASSIFY_RESULT, *PGUARDIAN_CLASSIFY_RESULT;

VOID
GuardianClassifyReset(
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID
GuardianClassifyPermit(
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID
GuardianClassifyBlock(
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

NTSTATUS
GuardianClassifyConnection(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Out_ GUARDIAN_CLASSIFY_RESULT* result);
