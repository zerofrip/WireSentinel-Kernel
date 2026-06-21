#include "classify.h"

#include "../policy/app_policy.h"
#include "../route/route_assignment.h"
#include "../killswitch/killswitch.h"
#include "../telemetry/telemetry.h"

VOID
GuardianClassifyReset(
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_NONE;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

VOID
GuardianClassifyPermit(
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }
}

VOID
GuardianClassifyBlock(
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_BLOCK;
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    }
}

static VOID
GuardianCopyAppIdFromPolicy(
    _In_ const GUARDIAN_APP_POLICY_V1* policy,
    _Out_writes_(16) UINT8 appId[16])
{
    RtlCopyMemory(appId, policy->AppId, 16);
}

NTSTATUS
GuardianClassifyConnection(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Out_ GUARDIAN_CLASSIFY_RESULT* result)
{
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    GUARDIAN_APP_POLICY_V1 policy;
    GUARDIAN_ROUTE_ASSIGNMENT_V1 route;
    BOOLEAN foundPolicy = FALSE;
    BOOLEAN foundRoute = FALSE;
    UINT8 appId[16];
    UINT64 interfaceLuid = 0;
    GUARDIAN_CLASSIFY_ACTION action = GuardianClassifyPermit;
    GUARDIAN_CLASSIFY_ACTION ksAction;
    NTSTATUS status;

    RtlZeroMemory(result, sizeof(*result));
    KeQueryPerformanceCounter(&start);

    if (GuardianKillSwitchEvaluate(interfaceLuid, &ksAction)) {
        result->Action = ksAction;
        KeQueryPerformanceCounter(&end);
        GuardianTelemetryRecordClassify(
            ksAction,
            (UINT64)(end.QuadPart - start.QuadPart));
        return STATUS_SUCCESS;
    }

    status = GuardianAppPolicyLookup(inFixedValues, inMetaValues, &policy, &foundPolicy);
    if (!NT_SUCCESS(status)) {
        GuardianTelemetryRecordError();
        return status;
    }

    if (foundPolicy) {
        GuardianCopyAppIdFromPolicy(&policy, appId);
        switch (policy.Action) {
        case GuardianPolicyBlock:
            action = GuardianClassifyBlock;
            break;
        case GuardianPolicyRoute:
            action = GuardianClassifyRoute;
            result->InterfaceLuid = policy.InterfaceLuid;
            break;
        case GuardianPolicyObserve:
            action = GuardianClassifyObserve;
            break;
        default:
            action = GuardianClassifyPermit;
            break;
        }
    }

    if (foundPolicy) {
        status = GuardianRouteLookup(appId, &route, &foundRoute);
        if (!NT_SUCCESS(status)) {
            GuardianTelemetryRecordError();
            return status;
        }
    }

    if (foundRoute) {
        switch (route.RouteKind) {
        case GuardianRouteBlocked:
            action = GuardianClassifyBlock;
            break;
        case GuardianRouteVpn:
        case GuardianRouteTailnet:
            action = GuardianClassifyRoute;
            result->InterfaceLuid = route.InterfaceLuid;
            break;
        case GuardianRouteTor:
        case GuardianRouteProxy:
        case GuardianRouteAnonymous:
        case GuardianRouteChain:
            action = GuardianClassifyPermit;
            break;
        default:
            break;
        }
    }

    result->Action = action;

    KeQueryPerformanceCounter(&end);
    GuardianTelemetryRecordClassify(
        action,
        (UINT64)(end.QuadPart - start.QuadPart));

    return STATUS_SUCCESS;
}
