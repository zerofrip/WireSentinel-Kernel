#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "../../shared/protocol/guardian_ioctl.h"
#include "../../shared/ids/guardian_guids.h"

#define GUARDIAN_POOL_TAG 'dnrG'

typedef struct _GUARDIAN_DEVICE_CONTEXT {
    WDFDEVICE Device;
    WDFQUEUE IoctlQueue;
    WDFQUEUE DeferredQueue;
} GUARDIAN_DEVICE_CONTEXT, *PGUARDIAN_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(GUARDIAN_DEVICE_CONTEXT, GuardianGetDeviceContext)

NTSTATUS
GuardianCreateDevice(
    _In_ WDFDRIVER Driver);

EVT_WDF_DRIVER_UNLOAD GuardianEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL GuardianEvtIoDeviceControl;

extern GUARDIAN_DRIVER_STATE_V1 g_GuardianDriverState;
extern PDEVICE_OBJECT g_GuardianWdmDevice;
