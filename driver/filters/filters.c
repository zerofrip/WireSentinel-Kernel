#include "filters.h"

#include "../guardian/driver.h"
#include "../state/guardian_state_mgr.h"

/* Minimal WireSentinelNdis IOCTL surface for hybrid polling (matches ndis_ioctl.h). */
#define GUARDIAN_NDIS_IOCTL_DEVICE_TYPE 0x8020u
#define GUARDIAN_NDIS_IOCTL_GET_DRIVER_STATE \
    CTL_CODE(GUARDIAN_NDIS_IOCTL_DEVICE_TYPE, 0x900, METHOD_BUFFERED, FILE_READ_DATA)

#define GUARDIAN_NDIS_USER_DEVICE_PATH L"\\??\\WireSentinelNdis"

#pragma pack(push, 1)
typedef struct _GUARDIAN_NDIS_DRIVER_STATE_POLL {
    UINT32 Version;
    UINT32 VersionMajor;
    UINT32 VersionMinor;
    UINT32 VersionPatch;
    UINT32 BuildStamp;
    UINT32 LifecycleState;
    UINT32 FilterAttached;
    UINT32 ActiveRouteCount;
    UINT32 ActiveRedirectCount;
    INT32 LastError;
    UINT8 Reserved[12];
} GUARDIAN_NDIS_DRIVER_STATE_POLL, *PGUARDIAN_NDIS_DRIVER_STATE_POLL;
#pragma pack(pop)

static GUARDIAN_MODE g_GuardianMode = GuardianModeWfp;
static UINT32 g_NdisFilterCount = 0;
static UINT32 g_NdisPollGeneration = 0;
static BOOLEAN g_HybridCoordinatorActive = FALSE;

static BOOLEAN
GuardianHybridIsValidMode(
    _In_ UINT32 mode)
{
    return mode <= GuardianModeHybrid;
}

static NTSTATUS
GuardianNdisQueryFilterCountViaIoctl(
    _Out_ PUINT32 filterCount)
{
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING devicePath;
    HANDLE deviceHandle = NULL;
    GUARDIAN_NDIS_DRIVER_STATE_POLL ndisState;
    NTSTATUS status;

    if (filterCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *filterCount = 0;

    RtlInitUnicodeString(&devicePath, GUARDIAN_NDIS_USER_DEVICE_PATH);
    InitializeObjectAttributes(
        &objectAttributes,
        &devicePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwCreateFile(
        &deviceHandle,
        GENERIC_READ | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&ndisState, sizeof(ndisState));
    status = ZwDeviceIoControlFile(
        deviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        GUARDIAN_NDIS_IOCTL_GET_DRIVER_STATE,
        NULL,
        0,
        &ndisState,
        sizeof(ndisState));

    ZwClose(deviceHandle);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    *filterCount = ndisState.FilterAttached;
    return STATUS_SUCCESS;
}

NTSTATUS
GuardianFiltersInitialize(VOID)
{
    return STATUS_SUCCESS;
}

VOID
GuardianFiltersShutdown(VOID)
{
}

NTSTATUS
GuardianHybridCoordinatorInitialize(VOID)
{
    NTSTATUS status;

    status = GuardianFiltersInitialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_HybridCoordinatorActive = TRUE;
    (VOID)GuardianHybridPollNdisState();
    g_GuardianDriverState.FilterCount = GuardianHybridGetCombinedFilterCount();

    return STATUS_SUCCESS;
}

VOID
GuardianHybridCoordinatorShutdown(VOID)
{
    if (!g_HybridCoordinatorActive) {
        return;
    }

    g_HybridCoordinatorActive = FALSE;
    GuardianFiltersShutdown();
}

NTSTATUS
GuardianHybridPollNdisState(VOID)
{
    UINT32 polledCount = 0;
    NTSTATUS status;

    status = GuardianNdisQueryFilterCountViaIoctl(&polledCount);
    if (NT_SUCCESS(status)) {
        g_NdisFilterCount = polledCount;
    }

    g_NdisPollGeneration++;
    g_GuardianDriverState.FilterCount = GuardianHybridGetCombinedFilterCount();

    return status;
}

UINT32
GuardianHybridGetNdisFilterCount(VOID)
{
    return g_NdisFilterCount;
}

VOID
GuardianHybridSetNdisFilterCount(
    _In_ UINT32 filterCount)
{
    g_NdisFilterCount = filterCount;
    g_GuardianDriverState.FilterCount = GuardianHybridGetCombinedFilterCount();
}

UINT32
GuardianHybridGetCombinedFilterCount(VOID)
{
    UINT32 wfpCount = GuardianStateManagerFilterCount();

    if (g_GuardianMode == GuardianModeHybrid) {
        return wfpCount + g_NdisFilterCount;
    }

    if (g_GuardianMode == GuardianModeNdis) {
        return g_NdisFilterCount;
    }

    return wfpCount;
}

GUARDIAN_MODE
GuardianHybridGetMode(VOID)
{
    return g_GuardianMode;
}

NTSTATUS
GuardianHybridSetMode(
    _In_ GUARDIAN_MODE mode)
{
    if (!GuardianHybridIsValidMode((UINT32)mode)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_HybridCoordinatorActive && mode != GuardianModeHybrid) {
        GuardianHybridCoordinatorShutdown();
    }

    g_GuardianMode = mode;
    g_GuardianDriverState.GuardianMode = (UINT32)mode;

    if (mode == GuardianModeHybrid && !g_HybridCoordinatorActive) {
        return GuardianHybridCoordinatorInitialize();
    }

    if (mode == GuardianModeNdis) {
        (VOID)GuardianHybridPollNdisState();
    }

    g_GuardianDriverState.FilterCount = GuardianHybridGetCombinedFilterCount();
    return STATUS_SUCCESS;
}
