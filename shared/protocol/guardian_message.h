#pragma once

#include <stdint.h>

#define GUARDIAN_PROTOCOL_VERSION 1

typedef enum _GUARDIAN_MESSAGE_TYPE {
    GuardianMsgGetDriverState = 1,
    GuardianMsgSetAppPolicy = 2,
    GuardianMsgSyncPolicies = 3,
    GuardianMsgSetRoute = 4,
    GuardianMsgClearRoute = 5,
    GuardianMsgSyncRoutes = 6,
    GuardianMsgSetKillSwitch = 7,
    GuardianMsgGetTelemetry = 8,
    GuardianMsgExportState = 9,
    GuardianMsgImportState = 10,
    GuardianMsgReconcile = 11,
    GuardianMsgDnsSetConfig = 12,
    GuardianMsgGetPerfStats = 13,
    GuardianMsgGetDnsStats = 14,
} GUARDIAN_MESSAGE_TYPE;

#pragma pack(push, 1)

typedef struct _GUARDIAN_MESSAGE_HEADER {
    UINT32 Version;
    UINT32 MessageType;
    UINT32 PayloadBytes;
    UINT32 SequenceId;
    UINT64 RequestId;
} GUARDIAN_MESSAGE_HEADER, *PGUARDIAN_MESSAGE_HEADER;

#define GUARDIAN_MESSAGE_HEADER_SIZE sizeof(GUARDIAN_MESSAGE_HEADER)

#pragma pack(pop)

/* State export/import blob header */
#define GUARDIAN_STATE_BLOB_VERSION 1
#define GUARDIAN_MAX_EXPORT_BYTES (4u * 1024u * 1024u)

#pragma pack(push, 1)

typedef struct _GUARDIAN_STATE_BLOB_HEADER_V1 {
    UINT32 Version;
    UINT32 PolicyCount;
    UINT32 RouteCount;
    UINT32 KillSwitchMode;
    UINT32 RecoveryGeneration;
    UINT32 Reserved;
} GUARDIAN_STATE_BLOB_HEADER_V1, *PGUARDIAN_STATE_BLOB_HEADER_V1;

typedef struct _GUARDIAN_RECONCILE_REQUEST_V1 {
    UINT32 Version;
    UINT32 KnownFilterCount;
    UINT64 KnownFilterIds[1];
} GUARDIAN_RECONCILE_REQUEST_V1, *PGUARDIAN_RECONCILE_REQUEST_V1;

typedef struct _GUARDIAN_RECONCILE_RESPONSE_V1 {
    UINT32 Version;
    UINT32 RemovedOrphans;
    UINT32 RecoveryGeneration;
    UINT32 RecoveryStatus;
} GUARDIAN_RECONCILE_RESPONSE_V1, *PGUARDIAN_RECONCILE_RESPONSE_V1;

#define GUARDIAN_RECOVERY_STATUS_OK 0
#define GUARDIAN_RECOVERY_STATUS_FAILED 1

#pragma pack(pop)
