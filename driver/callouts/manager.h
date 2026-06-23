#pragma once

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>

NTSTATUS
GuardianCalloutManagerRegister(VOID);

VOID
GuardianCalloutManagerUnregister(VOID);

UINT32
GuardianCalloutManagerRegisteredCount(VOID);

BOOLEAN
GuardianCalloutsAreRegistered(VOID);
