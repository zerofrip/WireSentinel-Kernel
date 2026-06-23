#pragma once

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>

#include "../../shared/ids/guardian_guids.h"

extern PDEVICE_OBJECT g_GuardianWdmDevice;

NTSTATUS
GuardianCalloutManagerRegister(VOID);

VOID
GuardianCalloutManagerUnregister(VOID);

UINT32
GuardianCalloutManagerRegisteredCount(VOID);

BOOLEAN
GuardianCalloutsAreRegistered(VOID);
