//
// Sctp
//

#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_SCTP_SCTP__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_SCTP_SCTP__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The pinned usrsctp implementation supports these socket options but omits
 * their declarations from the installed public header. Keep the compatibility
 * values colocated with the adapter until that dependency is updated.
 */
#ifndef SCTP_PLUGGABLE_CC
#define SCTP_PLUGGABLE_CC 0x00001202
#endif
#ifndef SCTP_INTERLEAVING_SUPPORTED
#define SCTP_INTERLEAVING_SUPPORTED 0x00001206
#endif
#ifndef SCTP_FRAG_LEVEL_2
#define SCTP_FRAG_LEVEL_2 0x00000002
#endif
#ifndef SCTP_ACCEPT_ZERO_CHECKSUM
#define SCTP_ACCEPT_ZERO_CHECKSUM 0x00000033
#endif
#ifndef SCTP_EDMID_LOWER_LAYER_DTLS
#define SCTP_EDMID_LOWER_LAYER_DTLS 1
#endif

// 1200 - 12 (SCTP header Size)
#define SCTP_MTU                         1188
#define SCTP_ASSOCIATION_DEFAULT_PORT    5000
#define SCTP_COMMON_HEADER_LENGTH        12
#define SCTP_CHECKSUM_OFFSET             8
#define SCTP_CHECKSUM_LENGTH             4
#define SCTP_DCEP_HEADER_LENGTH          12
#define SCTP_DCEP_LABEL_LEN_OFFSET       8
#define SCTP_DCEP_LABEL_OFFSET           12
#define SCTP_MAX_ALLOWABLE_PACKET_LENGTH (SCTP_DCEP_HEADER_LENGTH + MAX_DATA_CHANNEL_NAME_LEN + MAX_DATA_CHANNEL_PROTOCOL_LEN + 2)

#define SCTP_SESSION_ACTIVE             0
#define SCTP_SESSION_SHUTDOWN_INITIATED 1
#define SCTP_SESSION_SHUTDOWN_COMPLETED 2

#define DEFAULT_SCTP_SHUTDOWN_TIMEOUT 2 * HUNDREDS_OF_NANOS_IN_A_SECOND

#define DEFAULT_USRSCTP_TEARDOWN_POLLING_INTERVAL (10 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)

#define SCTP_TIMER_INTERVAL_MS_DEFAULT 100
#define SCTP_INTERNAL_TIMER_INTERVAL_MS 10

#define SCTP_DEFAULT_OUTBOUND_STREAMS 300
#define SCTP_DEFAULT_INBOUND_STREAMS  300

#define SCTP_CONTEXT_REFERENCE_WAIT_TIMEOUT (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// Values taken from defaults suggested by RFC 9260 spec: https://www.ietf.org/rfc/rfc9260.pdf

// Max retransmits along a given single path. Typical default is 5
#define SCTP_MAX_PATH_RETRANSMITS 5
// Max retransmits across all paths for an endpoint association. Typical default is double max path retransmits
#define SCTP_MAX_ASSOCIATION_RETRANSMITS 10
// Retransmission timeout defaults from the pinned usrsctp version.
#define SCTP_RTO_INITIAL 1000
#define SCTP_RTO_MIN     1000
#define SCTP_RTO_MAX     60000

enum { SCTP_PPID_DCEP = 50, SCTP_PPID_STRING = 51, SCTP_PPID_BINARY = 53, SCTP_PPID_STRING_EMPTY = 56, SCTP_PPID_BINARY_EMPTY = 57 };

enum {
    DCEP_DATA_CHANNEL_OPEN = 0x03,
    DCEP_DATA_CHANNEL_ACK = 0x02,
};

typedef enum {
    DCEP_DATA_CHANNEL_RELIABLE_ORDERED = (BYTE) 0x00,
    DCEP_DATA_CHANNEL_RELIABLE_UNORDERED = (BYTE) 0x80,
    DCEP_DATA_CHANNEL_REXMIT = (BYTE) 0x01,
    DCEP_DATA_CHANNEL_TIMED = (BYTE) 0x02
} DATA_CHANNEL_TYPE;

// Callback that is fired when SCTP Association wishes to send packet
typedef VOID (*SctpSessionOutboundPacketFunc)(UINT64, PBYTE, UINT32);

// Callback that is fired when SCTP has a new DataChannel
// Argument is ChannelID and ChannelName + Len
typedef VOID (*SctpSessionDataChannelOpenFunc)(UINT64, UINT32, PBYTE, UINT32, PRtcDataChannelInit);

// Callback that is fired when SCTP has a DataChannel Message.
// Argument is ChannelID and Message + Len
typedef VOID (*SctpSessionDataChannelMessageFunc)(UINT64, UINT32, BOOL, PBYTE, UINT32);

// Callback fired for a translated usrsctp notification.
typedef VOID (*SctpSessionEventFunc)(UINT64, PRtcSctpEvent);

// Edge-triggered callback fired after a non-blocking send was rejected and the
// socket subsequently has at least the configured number of free bytes.
typedef VOID (*SctpSessionWritableFunc)(UINT64, UINT32);

/// Singleton context for SCTP global state
typedef struct SctpContext {
    // last time the periodic usrsctp timers were called
    UINT64 lastTickTime;
    volatile ATOMIC_BOOL isSctpInitialized;
    SIZE_T contextRefCnt;
    MUTEX sctpContextLock;
    RtcSctpGlobalConfiguration configuration;
} SctpContext, *PSctpContext;

typedef struct {
    UINT64 customData;
    SctpSessionOutboundPacketFunc outboundPacketFunc;
    SctpSessionDataChannelOpenFunc dataChannelOpenFunc;
    SctpSessionDataChannelMessageFunc dataChannelMessageFunc;
    SctpSessionEventFunc eventFunc;
    SctpSessionWritableFunc writableFunc;
} SctpSessionCallbacks, *PSctpSessionCallbacks;

typedef struct {
    volatile SIZE_T shutdownStatus;
    volatile ATOMIC_BOOL sendBlocked;
    volatile SIZE_T sendCalls;
    volatile SIZE_T sendFailures;
    volatile SIZE_T blockedWrites;
    volatile SIZE_T writableCallbacks;
    volatile SIZE_T notifications;
    volatile SIZE_T lastSendErrno;
    volatile SIZE_T lastWritableBytes;
    volatile SIZE_T inboundSctpPackets;
    volatile SIZE_T inboundZeroChecksumPackets;
    volatile SIZE_T outboundSctpPackets;
    volatile SIZE_T outboundZeroChecksumPackets;
    struct socket* socket;
    SctpSessionCallbacks sctpSessionCallbacks;
    TIMER_QUEUE_HANDLE timerQueueHandle;
    UINT32 timerTaskId;
    UINT32 writableThresholdBytes;
    UINT64 timerInterval;
    BOOL internalTimerThread;
    BOOL zeroChecksumRequested;
    BOOL zeroChecksumPacketMetrics;
} SctpSession, *PSctpSession;

STATUS initSctpSession();
VOID deinitSctpSession();
STATUS createSctpSession(PSctpSessionCallbacks, PRtcSctpConfiguration, TIMER_QUEUE_HANDLE, PSctpSession*);
STATUS freeSctpSession(PSctpSession*);
STATUS putSctpPacket(PSctpSession, PBYTE, UINT32);
// Internal primitive. Application writes enter through dataChannelSend(),
// whose association-wide transport batch scope is the single-writer gate.
STATUS sctpSessionWriteMessage(PSctpSession, UINT32, BOOL, PBYTE, UINT32, PRtcDataChannelInit);
STATUS sctpSessionWriteDcep(PSctpSession, UINT32, PCHAR, UINT32, PRtcDataChannelInit);
STATUS handleDcepPacket(PSctpSession, UINT32, PBYTE, SIZE_T);
STATUS handleSctpNotification(PSctpSession, PVOID, ULONG);
STATUS sctpSessionGetMetrics(PSctpSession, PRtcSctpMetrics);

// Callbacks used by usrsctp
INT32 onSctpOutboundPacket(PVOID, PVOID, ULONG, UINT8, UINT8);
INT32 onSctpInboundPacket(struct socket*, union sctp_sockstore, PVOID, ULONG, struct sctp_rcvinfo, INT32, PVOID);
INT32 onSctpSendBufferAvailable(struct socket*, UINT32, PVOID);
// Callback to drive periodic SCTP timers
STATUS sctpTimerCallback(UINT32, UINT64, UINT64);

#ifdef __cplusplus
}
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_SCTP_SCTP__
