#pragma once

#include "../../shared/structures/killswitch.h"
#include "../classify/classify.h"

NTSTATUS
GuardianKillSwitchInitialize(
    _In_opt_ PUNICODE_STRING RegistryPath);

VOID
GuardianKillSwitchShutdown(VOID);

NTSTATUS
GuardianKillSwitchSet(
    _In_ const GUARDIAN_KILL_SWITCH_V1* config);

GUARDIAN_KILL_SWITCH_MODE
GuardianKillSwitchGetMode(VOID);

UINT64
GuardianKillSwitchVpnLuid(VOID);

BOOLEAN
GuardianKillSwitchEvaluate(
    _In_ UINT64 interfaceLuid,
    _Out_ GUARDIAN_CLASSIFY_ACTION* action);
