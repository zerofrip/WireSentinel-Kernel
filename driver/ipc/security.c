// ntifs.h (superset of ntddk.h) provides PsLookupProcessByProcessId / Ob*.
// Must be the TU's NT base; do not also include ntddk.h in this file.
#include <ntifs.h>
#include <wdf.h>
#include <wdfrequest.h>

#include "security.h"

// Exported by ntoskrnl; prototype may be absent in some WDK NuGet drops.
NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);

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
    PIRP irp;

    if (Request == NULL) {
        return STATUS_SUCCESS;
    }

    irp = WdfRequestWdmGetIrp(Request);
    if (irp == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    callerPid = IoGetRequestorProcessId(irp);
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
