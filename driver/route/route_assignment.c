#include "route_assignment.h"

#include "../guardian/driver.h"

typedef struct _GUARDIAN_ROUTE_ENTRY {
    LIST_ENTRY Link;
    GUARDIAN_ROUTE_ASSIGNMENT_V1 Route;
} GUARDIAN_ROUTE_ENTRY, *PGUARDIAN_ROUTE_ENTRY;

static LIST_ENTRY g_RouteList;
static KSPIN_LOCK g_RouteLock;
static UINT32 g_RouteCount;

NTSTATUS
GuardianRouteInitialize(VOID)
{
    InitializeListHead(&g_RouteList);
    KeInitializeSpinLock(&g_RouteLock);
    g_RouteCount = 0;
    return STATUS_SUCCESS;
}

VOID
GuardianRouteShutdown(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    KeAcquireSpinLock(&g_RouteLock, &oldIrql);
    while (!IsListEmpty(&g_RouteList)) {
        entry = RemoveHeadList(&g_RouteList);
        ExFreePoolWithTag(CONTAINING_RECORD(entry, GUARDIAN_ROUTE_ENTRY, Link), GUARDIAN_POOL_TAG);
    }
    g_RouteCount = 0;
    KeReleaseSpinLock(&g_RouteLock, oldIrql);
}

static PGUARDIAN_ROUTE_ENTRY
GuardianRouteFindLocked(
    _In_ const UINT8 appId[16])
{
    PLIST_ENTRY entry;

    for (entry = g_RouteList.Flink; entry != &g_RouteList; entry = entry->Flink) {
        PGUARDIAN_ROUTE_ENTRY item = CONTAINING_RECORD(entry, GUARDIAN_ROUTE_ENTRY, Link);
        if (RtlCompareMemory(item->Route.AppId, appId, 16) == 16) {
            return item;
        }
    }

    return NULL;
}

NTSTATUS
GuardianRouteSet(
    _In_ const GUARDIAN_ROUTE_ASSIGNMENT_V1* route)
{
    KIRQL oldIrql;
    PGUARDIAN_ROUTE_ENTRY entry;
    PGUARDIAN_ROUTE_ENTRY existing;

    if (route == NULL || route->Version != GUARDIAN_ROUTE_ASSIGNMENT_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    entry = (PGUARDIAN_ROUTE_ENTRY)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(GUARDIAN_ROUTE_ENTRY),
        GUARDIAN_POOL_TAG);
    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&entry->Route, route, sizeof(*route));

    KeAcquireSpinLock(&g_RouteLock, &oldIrql);
    existing = GuardianRouteFindLocked(route->AppId);
    if (existing != NULL) {
        RtlCopyMemory(&existing->Route, route, sizeof(*route));
        KeReleaseSpinLock(&g_RouteLock, oldIrql);
        ExFreePoolWithTag(entry, GUARDIAN_POOL_TAG);
        return STATUS_SUCCESS;
    }

    if (g_RouteCount >= GUARDIAN_MAX_ROUTES) {
        KeReleaseSpinLock(&g_RouteLock, oldIrql);
        ExFreePoolWithTag(entry, GUARDIAN_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InsertTailList(&g_RouteList, &entry->Link);
    g_RouteCount++;
    KeReleaseSpinLock(&g_RouteLock, oldIrql);

    return STATUS_SUCCESS;
}

NTSTATUS
GuardianRouteClear(
    _In_ const UINT8 appId[16])
{
    KIRQL oldIrql;
    PGUARDIAN_ROUTE_ENTRY existing;

    KeAcquireSpinLock(&g_RouteLock, &oldIrql);
    existing = GuardianRouteFindLocked(appId);
    if (existing == NULL) {
        KeReleaseSpinLock(&g_RouteLock, oldIrql);
        return STATUS_NOT_FOUND;
    }

    RemoveEntryList(&existing->Link);
    g_RouteCount--;
    KeReleaseSpinLock(&g_RouteLock, oldIrql);

    ExFreePoolWithTag(existing, GUARDIAN_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
GuardianRouteSync(
    _In_reads_(count) const GUARDIAN_ROUTE_ASSIGNMENT_V1* routes,
    _In_ UINT32 count)
{
    UINT32 i;
    NTSTATUS status;

    if (routes == NULL || count > GUARDIAN_MAX_SYNC_ROUTES) {
        return STATUS_INVALID_PARAMETER;
    }

    GuardianRouteShutdown();
    GuardianRouteInitialize();

    for (i = 0; i < count; ++i) {
        status = GuardianRouteSet(&routes[i]);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
GuardianRouteLookup(
    _In_ const UINT8 appId[16],
    _Out_ GUARDIAN_ROUTE_ASSIGNMENT_V1* route,
    _Out_ BOOLEAN* found)
{
    KIRQL oldIrql;
    PGUARDIAN_ROUTE_ENTRY existing;

    *found = FALSE;
    RtlZeroMemory(route, sizeof(*route));

    KeAcquireSpinLock(&g_RouteLock, &oldIrql);
    existing = GuardianRouteFindLocked(appId);
    if (existing != NULL) {
        RtlCopyMemory(route, &existing->Route, sizeof(*route));
        *found = TRUE;
    }
    KeReleaseSpinLock(&g_RouteLock, oldIrql);

    return STATUS_SUCCESS;
}

UINT32
GuardianRouteActiveCount(VOID)
{
    return g_RouteCount;
}
