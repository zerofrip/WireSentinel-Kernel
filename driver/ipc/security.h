#pragma once

// NT base header (ntddk.h vs ntifs.h) is established by the including TU.
// security.c uses ntifs.h for Ps*/Ob* process APIs; ioctl_dispatch.c uses ntddk.h.
#include <wdf.h>

NTSTATUS
GuardianSecurityPolicyVerifyCaller(
    _In_opt_ WDFREQUEST Request);
