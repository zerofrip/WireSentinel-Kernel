#pragma once

#include <ntddk.h>
#include <wdf.h>

NTSTATUS
GuardianSecurityPolicyVerifyCaller(
    _In_opt_ WDFREQUEST Request);
