#pragma once

#include <stdint.h>

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
typedef LONG NTSTATUS;
#endif

#define GUARDIAN_DRIVER_VERSION_MAJOR 0
#define GUARDIAN_DRIVER_VERSION_MINOR 1
#define GUARDIAN_DRIVER_VERSION_PATCH 0
#define GUARDIAN_DRIVER_BUILD_STAMP 2026062101u

typedef enum _GUARDIAN_DRIVER_LIFECYCLE_STATE {
    GuardianLifecycleStopped = 0,
    GuardianLifecycleStarting = 1,
    GuardianLifecycleRunning = 2,
    GuardianLifecycleRecovering = 3,
    GuardianLifecycleFailed = 4,
} GUARDIAN_DRIVER_LIFECYCLE_STATE;

typedef enum _GUARDIAN_MODE {
    GuardianModeWfp = 0,
    GuardianModeNdis = 1,
    GuardianModeHybrid = 2,
} GUARDIAN_MODE;

#pragma pack(push, 1)

typedef struct _GUARDIAN_DRIVER_STATE_V1 {
    UINT32 Version;
    UINT32 VersionMajor;
    UINT32 VersionMinor;
    UINT32 VersionPatch;
    UINT32 BuildStamp;
    UINT32 LifecycleState;
    UINT32 CalloutsRegistered;
    UINT32 FilterCount;
    UINT32 RecoveryGeneration;
    UINT32 KillSwitchMode;
    NTSTATUS LastError;
    /* Phase 12-K: first 4 bytes were Reserved[16]; GuardianMode defaults to Wfp (0). */
    UINT32 GuardianMode;
    UINT8 Reserved[12];
} GUARDIAN_DRIVER_STATE_V1, *PGUARDIAN_DRIVER_STATE_V1;

#define GUARDIAN_DRIVER_STATE_VERSION 1
#define GUARDIAN_DRIVER_STATE_V1_SIZE sizeof(GUARDIAN_DRIVER_STATE_V1)

#pragma pack(pop)
