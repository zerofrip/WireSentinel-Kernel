#include "ioctl_dispatch.h"
#include "security.h"

#include "../guardian/driver.h"
#include "../policy/app_policy.h"
#include "../route/route_assignment.h"
#include "../killswitch/killswitch.h"
#include "../state/guardian_state_mgr.h"
#include "../telemetry/telemetry.h"
#include "../recovery/recovery.h"
#include "../callouts/dns_observe.h"
#include "../filters/filters.h"

NTSTATUS
GuardianValidateIoctlBuffer(
    _In_ ULONG ioControlCode,
    _In_ size_t inputLength,
    _In_ size_t outputLength,
    _In_reads_bytes_opt_(inputLength) const VOID* inputBuffer,
    _Out_ size_t* requiredOutput)
{
    UNREFERENCED_PARAMETER(ioControlCode);

    if (requiredOutput == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (inputLength > GUARDIAN_MAX_IOCTL_BUFFER || outputLength > GUARDIAN_MAX_IOCTL_BUFFER) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    switch (ioControlCode) {
    case IOCTL_GUARDIAN_GET_DRIVER_STATE:
        *requiredOutput = sizeof(GUARDIAN_DRIVER_STATE_V1);
        break;
    case IOCTL_GUARDIAN_SET_APP_POLICY:
        if (inputBuffer == NULL || inputLength < sizeof(GUARDIAN_APP_POLICY_V1)) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    case IOCTL_GUARDIAN_SYNC_POLICIES: {
        const GUARDIAN_SYNC_POLICIES_V1* sync;
        if (inputBuffer == NULL || inputLength < sizeof(UINT32) * 2) {
            return STATUS_INVALID_PARAMETER;
        }
        sync = (const GUARDIAN_SYNC_POLICIES_V1*)inputBuffer;
        if (sync->PolicyCount > GUARDIAN_MAX_SYNC_POLICIES) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    }
    case IOCTL_GUARDIAN_SET_ROUTE:
        if (inputBuffer == NULL || inputLength < sizeof(GUARDIAN_ROUTE_ASSIGNMENT_V1)) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    case IOCTL_GUARDIAN_CLEAR_ROUTE:
        if (inputBuffer == NULL || inputLength < 16) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    case IOCTL_GUARDIAN_SYNC_ROUTES: {
        const GUARDIAN_SYNC_ROUTES_V1* sync;
        if (inputBuffer == NULL || inputLength < sizeof(UINT32) * 2) {
            return STATUS_INVALID_PARAMETER;
        }
        sync = (const GUARDIAN_SYNC_ROUTES_V1*)inputBuffer;
        if (sync->RouteCount > GUARDIAN_MAX_SYNC_ROUTES) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    }
    case IOCTL_GUARDIAN_SET_KILL_SWITCH:
        if (inputBuffer == NULL || inputLength < sizeof(GUARDIAN_KILL_SWITCH_V1)) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    case IOCTL_GUARDIAN_GET_TELEMETRY:
        *requiredOutput = sizeof(GUARDIAN_TELEMETRY_V1);
        break;
    case IOCTL_GUARDIAN_EXPORT_STATE:
        *requiredOutput = sizeof(GUARDIAN_STATE_BLOB_HEADER_V1);
        break;
    case IOCTL_GUARDIAN_IMPORT_STATE:
        if (inputBuffer == NULL || inputLength < sizeof(GUARDIAN_STATE_BLOB_HEADER_V1)) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    case IOCTL_GUARDIAN_RECONCILE:
        if (outputLength < sizeof(GUARDIAN_RECONCILE_RESPONSE_V1)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        *requiredOutput = sizeof(GUARDIAN_RECONCILE_RESPONSE_V1);
        break;
    case IOCTL_GUARDIAN_DNS_SET_CONFIG:
        if (inputBuffer == NULL || inputLength < sizeof(GUARDIAN_DNS_CONFIG_V1)) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    case IOCTL_GUARDIAN_GET_PERF_STATS:
        *requiredOutput = sizeof(GUARDIAN_PERF_STATS_V1);
        break;
    case IOCTL_GUARDIAN_GET_DNS_STATS:
        *requiredOutput = sizeof(GUARDIAN_DNS_STATS_V1);
        break;
    case IOCTL_GUARDIAN_SET_GUARDIAN_MODE:
        if (inputBuffer == NULL || inputLength < sizeof(UINT32)) {
            return STATUS_INVALID_PARAMETER;
        }
        *requiredOutput = 0;
        break;
    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    return STATUS_SUCCESS;
}

VOID
GuardianEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t requiredOutput = 0;
    size_t bytesReturned = 0;
    LARGE_INTEGER start;
    LARGE_INTEGER end;

    UNREFERENCED_PARAMETER(Queue);

    KeQueryPerformanceCounter(&start);

    status = GuardianSecurityPolicyVerifyCaller(Request);
    if (!NT_SUCCESS(status)) {
        goto Complete;
    }

    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            goto Complete;
        }
    }

    if (OutputBufferLength > 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            goto Complete;
        }
    }

    status = GuardianValidateIoctlBuffer(
        IoControlCode,
        InputBufferLength,
        OutputBufferLength,
        inputBuffer,
        &requiredOutput);
    if (!NT_SUCCESS(status)) {
        goto Complete;
    }

    if (requiredOutput > OutputBufferLength) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto Complete;
    }

    switch (IoControlCode) {
    case IOCTL_GUARDIAN_GET_DRIVER_STATE:
        RtlCopyMemory(outputBuffer, &g_GuardianDriverState, sizeof(g_GuardianDriverState));
        bytesReturned = sizeof(g_GuardianDriverState);
        break;
    case IOCTL_GUARDIAN_SET_APP_POLICY:
        status = GuardianAppPolicySet((const GUARDIAN_APP_POLICY_V1*)inputBuffer);
        break;
    case IOCTL_GUARDIAN_SYNC_POLICIES: {
        const GUARDIAN_SYNC_POLICIES_V1* sync = (const GUARDIAN_SYNC_POLICIES_V1*)inputBuffer;
        status = GuardianAppPolicySync(sync->Policies, sync->PolicyCount);
        break;
    }
    case IOCTL_GUARDIAN_SET_ROUTE:
        status = GuardianRouteSet((const GUARDIAN_ROUTE_ASSIGNMENT_V1*)inputBuffer);
        break;
    case IOCTL_GUARDIAN_CLEAR_ROUTE:
        status = GuardianRouteClear((const UINT8*)inputBuffer);
        break;
    case IOCTL_GUARDIAN_SYNC_ROUTES: {
        const GUARDIAN_SYNC_ROUTES_V1* sync = (const GUARDIAN_SYNC_ROUTES_V1*)inputBuffer;
        status = GuardianRouteSync(sync->Routes, sync->RouteCount);
        break;
    }
    case IOCTL_GUARDIAN_SET_KILL_SWITCH:
        status = GuardianKillSwitchSet((const GUARDIAN_KILL_SWITCH_V1*)inputBuffer);
        if (NT_SUCCESS(status)) {
            g_GuardianDriverState.KillSwitchMode = GuardianKillSwitchGetMode();
        }
        break;
    case IOCTL_GUARDIAN_GET_TELEMETRY:
        GuardianTelemetryGet((GUARDIAN_TELEMETRY_V1*)outputBuffer);
        bytesReturned = sizeof(GUARDIAN_TELEMETRY_V1);
        break;
    case IOCTL_GUARDIAN_EXPORT_STATE:
        status = GuardianStateManagerExport(
            (UINT8*)outputBuffer,
            (UINT32)OutputBufferLength,
            (UINT32*)&bytesReturned);
        break;
    case IOCTL_GUARDIAN_IMPORT_STATE:
        status = GuardianStateManagerImport((const UINT8*)inputBuffer, (UINT32)InputBufferLength);
        break;
    case IOCTL_GUARDIAN_RECONCILE: {
        const GUARDIAN_RECONCILE_REQUEST_V1* req = (const GUARDIAN_RECONCILE_REQUEST_V1*)inputBuffer;
        status = GuardianRecoveryReconcile(
            req != NULL ? req->KnownFilterIds : NULL,
            req != NULL ? req->KnownFilterCount : 0,
            (GUARDIAN_RECONCILE_RESPONSE_V1*)outputBuffer);
        if (NT_SUCCESS(status)) {
            bytesReturned = sizeof(GUARDIAN_RECONCILE_RESPONSE_V1);
        }
        break;
    }
    case IOCTL_GUARDIAN_DNS_SET_CONFIG:
        status = GuardianDnsLayerSetConfig((const GUARDIAN_DNS_CONFIG_V1*)inputBuffer);
        break;
    case IOCTL_GUARDIAN_GET_PERF_STATS:
        GuardianPerfStatsGet((GUARDIAN_PERF_STATS_V1*)outputBuffer);
        bytesReturned = sizeof(GUARDIAN_PERF_STATS_V1);
        break;
    case IOCTL_GUARDIAN_GET_DNS_STATS:
        GuardianDnsLayerGetStats((GUARDIAN_DNS_STATS_V1*)outputBuffer);
        bytesReturned = sizeof(GUARDIAN_DNS_STATS_V1);
        break;
    case IOCTL_GUARDIAN_SET_GUARDIAN_MODE: {
        const UINT32* mode = (const UINT32*)inputBuffer;
        status = GuardianHybridSetMode((GUARDIAN_MODE)*mode);
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    KeQueryPerformanceCounter(&end);
    GuardianPerfRecordIpc(!NT_SUCCESS(status), (UINT64)(end.QuadPart - start.QuadPart));
    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
