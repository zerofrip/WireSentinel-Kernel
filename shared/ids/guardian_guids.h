#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <guiddef.h>
#endif

/* Fixed GUIDs for WireSentinel Guardian WFP provider, sublayer, and callouts. */

extern const GUID GUARDIAN_WFP_PROVIDER_GUID;
extern const GUID GUARDIAN_WFP_SUBLAYER_GUID;
extern const GUID GUARDIAN_CALLOUT_AUTH_CONNECT_V4_GUID;
extern const GUID GUARDIAN_CALLOUT_AUTH_CONNECT_V6_GUID;
extern const GUID GUARDIAN_CALLOUT_FLOW_ESTABLISHED_V4_GUID;
extern const GUID GUARDIAN_CALLOUT_FLOW_ESTABLISHED_V6_GUID;
extern const GUID GUARDIAN_CALLOUT_DNS_DATAGRAM_V4_GUID;
extern const GUID GUARDIAN_CALLOUT_DNS_DATAGRAM_V6_GUID;
