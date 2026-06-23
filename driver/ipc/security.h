#pragma once

#include <ntddk.h>
#include <ntifs.h>
#include <wdf.h>
#include <wdfrequest.h>

NTSTATUS
GuardianSecurityPolicyVerifyCaller(
    _In_opt_ WDFREQUEST Request);
