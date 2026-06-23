#include "../guardian/driver.h"
#include "manager.h"

#include "../classify/classify.h"
#include "../telemetry/telemetry.h"
#include "dns_observe.h"

static BOOLEAN g_CalloutsRegistered = FALSE;
static UINT32 g_RegisteredCalloutCount = 0;

static VOID NTAPI
GuardianAuthConnectClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    GUARDIAN_CLASSIFY_RESULT result;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    GuardianClassifyReset(classifyOut);

    status = GuardianClassifyConnection(inFixedValues, inMetaValues, &result);
    if (!NT_SUCCESS(status)) {
        GuardianClassifyPermit(classifyOut);
        return;
    }

    switch (result.Action) {
    case GuardianActionBlock:
        GuardianClassifyBlock(classifyOut);
        break;
    case GuardianActionRoute:
        GuardianClassifyPermit(classifyOut);
        break;
    case GuardianActionObserve:
    case GuardianActionPermit:
    default:
        GuardianClassifyPermit(classifyOut);
        break;
    }
}

static VOID NTAPI
GuardianAuthConnectClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    GuardianAuthConnectClassifyV4(
        inFixedValues,
        inMetaValues,
        layerData,
        classifyContext,
        filter,
        flowContext,
        classifyOut);
}

static VOID NTAPI
GuardianFlowEstablishedClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    GuardianClassifyReset(classifyOut);
    GuardianClassifyPermit(classifyOut);
}

static NTSTATUS NTAPI
GuardianNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID NTAPI
GuardianFlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

static const FWPS_CALLOUT1 g_AuthConnectV4Callout = {
    GUARDIAN_CALLOUT_AUTH_CONNECT_V4_GUID,
    0,
    GuardianAuthConnectClassifyV4,
    GuardianNotifyFn,
    GuardianFlowDeleteFn,
};

static const FWPS_CALLOUT1 g_AuthConnectV6Callout = {
    GUARDIAN_CALLOUT_AUTH_CONNECT_V6_GUID,
    0,
    GuardianAuthConnectClassifyV6,
    GuardianNotifyFn,
    GuardianFlowDeleteFn,
};

static const FWPS_CALLOUT1 g_FlowEstablishedV4Callout = {
    GUARDIAN_CALLOUT_FLOW_ESTABLISHED_V4_GUID,
    0,
    GuardianFlowEstablishedClassify,
    GuardianNotifyFn,
    GuardianFlowDeleteFn,
};

static const FWPS_CALLOUT1 g_FlowEstablishedV6Callout = {
    GUARDIAN_CALLOUT_FLOW_ESTABLISHED_V6_GUID,
    0,
    GuardianFlowEstablishedClassify,
    GuardianNotifyFn,
    GuardianFlowDeleteFn,
};

NTSTATUS
GuardianCalloutManagerRegister(VOID)
{
    NTSTATUS status;

    if (g_CalloutsRegistered) {
        return STATUS_SUCCESS;
    }

    GuardianDnsLayerInitialize();

    if (g_GuardianWdmDevice == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = FwpsCalloutRegister1(
        g_GuardianWdmDevice,
        &g_AuthConnectV4Callout,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_RegisteredCalloutCount++;

    status = FwpsCalloutRegister1(
        g_GuardianWdmDevice,
        &g_AuthConnectV6Callout,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_RegisteredCalloutCount++;

    status = FwpsCalloutRegister1(
        g_GuardianWdmDevice,
        &g_FlowEstablishedV4Callout,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_RegisteredCalloutCount++;

    status = FwpsCalloutRegister1(
        g_GuardianWdmDevice,
        &g_FlowEstablishedV6Callout,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_RegisteredCalloutCount++;

    g_CalloutsRegistered = TRUE;
    return STATUS_SUCCESS;
}

VOID
GuardianCalloutManagerUnregister(VOID)
{
    if (!g_CalloutsRegistered) {
        return;
    }

    FwpsCalloutUnregisterByKey0(&GUARDIAN_CALLOUT_AUTH_CONNECT_V4_GUID);
    FwpsCalloutUnregisterByKey0(&GUARDIAN_CALLOUT_AUTH_CONNECT_V6_GUID);
    FwpsCalloutUnregisterByKey0(&GUARDIAN_CALLOUT_FLOW_ESTABLISHED_V4_GUID);
    FwpsCalloutUnregisterByKey0(&GUARDIAN_CALLOUT_FLOW_ESTABLISHED_V6_GUID);

    GuardianDnsLayerShutdown();

    g_CalloutsRegistered = FALSE;
    g_RegisteredCalloutCount = 0;
}

UINT32
GuardianCalloutManagerRegisteredCount(VOID)
{
    return g_RegisteredCalloutCount;
}

BOOLEAN
GuardianCalloutsAreRegistered(VOID)
{
    return g_CalloutsRegistered;
}
