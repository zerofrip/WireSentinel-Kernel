#include "driver.h"

#pragma alloc_text(INIT, GuardianCreateDevice)

DECLARE_CONST_UNICODE_STRING(
    GuardianDeviceSddl,
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

NTSTATUS
GuardianCreateDevice(
    _In_ WDFDRIVER Driver)
{
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attributes;
    PGUARDIAN_DEVICE_CONTEXT deviceContext;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;
    WDF_FILEOBJECT_CONFIG fileConfig;

    deviceInit = WdfControlDeviceInitAllocate(Driver, &GuardianDeviceSddl);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&deviceName, GUARDIAN_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicName, GUARDIAN_SYMBOLIC_NAME);

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, GUARDIAN_DEVICE_CONTEXT);

    status = WdfDeviceCreate(&deviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        if (deviceInit != NULL) {
            WdfDeviceInitFree(deviceInit);
        }
        return status;
    }

    deviceContext = GuardianGetDeviceContext(device);
    RtlZeroMemory(deviceContext, sizeof(*deviceContext));
    deviceContext->Device = device;

    status = WdfDeviceCreateSymbolicLink(device, &symbolicName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = GuardianEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    deviceContext->IoctlQueue = queue;
    g_GuardianWdmDevice = WdfDeviceWdmGetDeviceObject(device);

    WdfControlFinishInitializing(device);

    return STATUS_SUCCESS;
}
