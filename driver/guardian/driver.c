#include "driver.h"

#include "../ipc/ioctl_dispatch.h"
#include "../callouts/manager.h"
#include "../state/guardian_state_mgr.h"
#include "../telemetry/telemetry.h"
#include "../recovery/recovery.h"
#include "../killswitch/killswitch.h"
#include "../filters/filters.h"

DRIVER_INITIALIZE DriverEntry;

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, GuardianCreateDevice)

#define GUARDIAN_REG_GUARDIAN_MODE L"GuardianMode"

GUARDIAN_DRIVER_STATE_V1 g_GuardianDriverState;
PDEVICE_OBJECT g_GuardianWdmDevice = NULL;

static VOID
GuardianInitializeDriverState(VOID)
{
    RtlZeroMemory(&g_GuardianDriverState, sizeof(g_GuardianDriverState));
    g_GuardianDriverState.Version = GUARDIAN_DRIVER_STATE_VERSION;
    g_GuardianDriverState.VersionMajor = GUARDIAN_DRIVER_VERSION_MAJOR;
    g_GuardianDriverState.VersionMinor = GUARDIAN_DRIVER_VERSION_MINOR;
    g_GuardianDriverState.VersionPatch = GUARDIAN_DRIVER_VERSION_PATCH;
    g_GuardianDriverState.BuildStamp = GUARDIAN_DRIVER_BUILD_STAMP;
    g_GuardianDriverState.LifecycleState = GuardianLifecycleStarting;
    g_GuardianDriverState.GuardianMode = GuardianModeWfp;
}

#pragma alloc_text(INIT, GuardianReadRegistryGuardianMode)
static UINT32
GuardianReadRegistryGuardianMode(
    _In_opt_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    UNICODE_STRING valueName;
    ULONG mode = GuardianModeWfp;
    ULONG resultLength = 0;

    if (RegistryPath == NULL) {
        return GuardianModeWfp;
    }

    InitializeObjectAttributes(
        &attributes,
        RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        return GuardianModeWfp;
    }

    RtlInitUnicodeString(&valueName, GUARDIAN_REG_GUARDIAN_MODE);
    (VOID)ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        &mode,
        sizeof(mode),
        &resultLength);

    ZwClose(keyHandle);

    if (mode > GuardianModeHybrid) {
        return GuardianModeWfp;
    }

    return mode;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    GuardianInitializeDriverState();
    g_GuardianDriverState.GuardianMode = GuardianReadRegistryGuardianMode(RegistryPath);
    GuardianTelemetryInitialize();
    GuardianStateManagerInitialize();
    GuardianKillSwitchInitialize(RegistryPath);
    GuardianRecoveryManagerInitialize(RegistryPath);

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = GuardianEvtDriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if (!NT_SUCCESS(status)) {
        g_GuardianDriverState.LastError = status;
        g_GuardianDriverState.LifecycleState = GuardianLifecycleFailed;
        return status;
    }

    status = GuardianCreateDevice(driver);
    if (!NT_SUCCESS(status)) {
        g_GuardianDriverState.LastError = status;
        g_GuardianDriverState.LifecycleState = GuardianLifecycleFailed;
        return status;
    }

    status = GuardianCalloutManagerRegister();
    if (!NT_SUCCESS(status)) {
        g_GuardianDriverState.LastError = status;
        g_GuardianDriverState.LifecycleState = GuardianLifecycleFailed;
        return status;
    }

    g_GuardianDriverState.CalloutsRegistered = GuardianCalloutManagerRegisteredCount();
    g_GuardianDriverState.LifecycleState = GuardianLifecycleRecovering;

    status = GuardianHybridSetMode((GUARDIAN_MODE)g_GuardianDriverState.GuardianMode);
    if (!NT_SUCCESS(status)) {
        g_GuardianDriverState.LastError = status;
        g_GuardianDriverState.LifecycleState = GuardianLifecycleFailed;
        return status;
    }

    status = GuardianRecoveryManagerBegin();
    if (!NT_SUCCESS(status)) {
        g_GuardianDriverState.LastError = status;
        g_GuardianDriverState.LifecycleState = GuardianLifecycleFailed;
        return status;
    }

    g_GuardianDriverState.LifecycleState = GuardianLifecycleRunning;
    g_GuardianDriverState.LastError = STATUS_SUCCESS;

    return STATUS_SUCCESS;
}

VOID
GuardianEvtDriverUnload(
    _In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    g_GuardianDriverState.LifecycleState = GuardianLifecycleStopped;

    GuardianHybridCoordinatorShutdown();
    GuardianCalloutManagerUnregister();
    GuardianStateManagerShutdown();
    GuardianTelemetryShutdown();
}
