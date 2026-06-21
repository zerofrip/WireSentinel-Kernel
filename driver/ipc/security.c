#include "security.h"

static volatile HANDLE g_GuardianAllowedServicePid = NULL;

NTSTATUS
GuardianSecurityPolicyVerifyCaller(
    _In_opt_ WDFREQUEST Request)
{
    HANDLE callerPid;
    PEPROCESS callerProcess = NULL;
    PEPROCESS serviceProcess = NULL;
    ULONG callerSession = 0;
    ULONG serviceSession = 0;
    NTSTATUS status;

    if (Request == NULL) {
        return STATUS_SUCCESS;
    }

    callerPid = WdfRequestGetRequestorProcessId(Request);
    if (callerPid == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    status = PsLookupProcessByProcessId(callerPid, &callerProcess);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    callerSession = PsGetProcessSessionId(callerProcess);
    ObDereferenceObject(callerProcess);
    callerProcess = NULL;

    if (g_GuardianAllowedServicePid == NULL) {
        g_GuardianAllowedServicePid = callerPid;
        return STATUS_SUCCESS;
    }

    if (callerPid == g_GuardianAllowedServicePid) {
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(g_GuardianAllowedServicePid, &serviceProcess);
    if (!NT_SUCCESS(status)) {
        return STATUS_ACCESS_DENIED;
    }

    serviceSession = PsGetProcessSessionId(serviceProcess);
    ObDereferenceObject(serviceProcess);

    if (callerSession == serviceSession) {
        return STATUS_SUCCESS;
    }

    return STATUS_ACCESS_DENIED;
}
