#include "killswitch.h"

#include "../classify/classify.h"

static GUARDIAN_KILL_SWITCH_MODE g_KillSwitchMode = GuardianKsOff;
static UINT64 g_VpnInterfaceLuid = 0;
static KSPIN_LOCK g_KillSwitchLock;

#define GUARDIAN_REG_PARAMETERS L"\\Parameters"
#define GUARDIAN_REG_KILL_SWITCH L"KillSwitchMode"
#define GUARDIAN_REG_VPN_LUID L"VpnInterfaceLuid"

NTSTATUS
GuardianKillSwitchInitialize(
    _In_opt_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES attributes;
    HANDLE keyHandle = NULL;
    UNICODE_STRING valueName;
    ULONG mode = 0;
    ULONG resultLength = 0;

    KeInitializeSpinLock(&g_KillSwitchLock);
    g_KillSwitchMode = GuardianKsOff;
    g_VpnInterfaceLuid = 0;

    if (RegistryPath == NULL) {
        return STATUS_SUCCESS;
    }

    InitializeObjectAttributes(
        &attributes,
        RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &attributes);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&valueName, GUARDIAN_REG_KILL_SWITCH);
    (VOID)ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        &mode,
        sizeof(mode),
        &resultLength);

    if (mode <= GuardianKsRestore) {
        g_KillSwitchMode = (GUARDIAN_KILL_SWITCH_MODE)mode;
    }

    ZwClose(keyHandle);
    return STATUS_SUCCESS;
}

VOID
GuardianKillSwitchShutdown(VOID)
{
}

NTSTATUS
GuardianKillSwitchSet(
    _In_ const GUARDIAN_KILL_SWITCH_V1* config)
{
    KIRQL oldIrql;

    if (config == NULL || config->Version != GUARDIAN_KILL_SWITCH_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    if (config->Mode > GuardianKsRestore) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_KillSwitchLock, &oldIrql);
    if (config->Mode == GuardianKsRestore) {
        g_KillSwitchMode = GuardianKsOff;
        g_VpnInterfaceLuid = 0;
    } else {
        g_KillSwitchMode = (GUARDIAN_KILL_SWITCH_MODE)config->Mode;
        g_VpnInterfaceLuid = config->VpnInterfaceLuid;
    }
    KeReleaseSpinLock(&g_KillSwitchLock, oldIrql);

    return STATUS_SUCCESS;
}

GUARDIAN_KILL_SWITCH_MODE
GuardianKillSwitchGetMode(VOID)
{
    return g_KillSwitchMode;
}

UINT64
GuardianKillSwitchVpnLuid(VOID)
{
    return g_VpnInterfaceLuid;
}

BOOLEAN
GuardianKillSwitchEvaluate(
    _In_ UINT64 interfaceLuid,
    _Out_ GUARDIAN_CLASSIFY_ACTION* action)
{
    KIRQL oldIrql;
    GUARDIAN_KILL_SWITCH_MODE mode;
    UINT64 vpnLuid;
    BOOLEAN handled = FALSE;

    KeAcquireSpinLock(&g_KillSwitchLock, &oldIrql);
    mode = g_KillSwitchMode;
    vpnLuid = g_VpnInterfaceLuid;
    KeReleaseSpinLock(&g_KillSwitchLock, oldIrql);

    switch (mode) {
    case GuardianKsBlockAll:
        *action = GuardianClassifyBlock;
        handled = TRUE;
        break;
    case GuardianKsAllowVpnOnly:
        if (vpnLuid != 0 && interfaceLuid == vpnLuid) {
            *action = GuardianClassifyPermit;
        } else {
            *action = GuardianClassifyBlock;
        }
        handled = TRUE;
        break;
    default:
        break;
    }

    return handled;
}
