#pragma once

#include "../../shared/structures/route_assignment.h"

#define GUARDIAN_MAX_ROUTES 4096

NTSTATUS
GuardianRouteInitialize(VOID);

VOID
GuardianRouteShutdown(VOID);

NTSTATUS
GuardianRouteSet(
    _In_ const GUARDIAN_ROUTE_ASSIGNMENT_V1* route);

NTSTATUS
GuardianRouteClear(
    _In_ const UINT8 appId[16]);

NTSTATUS
GuardianRouteSync(
    _In_reads_(count) const GUARDIAN_ROUTE_ASSIGNMENT_V1* routes,
    _In_ UINT32 count);

NTSTATUS
GuardianRouteLookup(
    _In_ const UINT8 appId[16],
    _Out_ GUARDIAN_ROUTE_ASSIGNMENT_V1* route,
    _Out_ BOOLEAN* found);

UINT32
GuardianRouteActiveCount(VOID);
