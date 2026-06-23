#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "security.h"

NTSTATUS
GuardianValidateIoctlBuffer(
    _In_ ULONG ioControlCode,
    _In_ size_t inputLength,
    _In_ size_t outputLength,
    _In_reads_bytes_opt_(inputLength) const VOID* inputBuffer,
    _Out_ size_t* requiredOutput);

VOID
GuardianEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode);
