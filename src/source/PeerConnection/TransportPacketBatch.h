/*******************************************
PeerConnection DTLS packet batching
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_TRANSPORT_PACKET_BATCH__
#define __KINESIS_VIDEO_WEBRTC_TRANSPORT_PACKET_BATCH__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define TRANSPORT_PACKET_BATCH_CAPACITY      SOCKET_SEND_BATCH_MAX
#define TRANSPORT_PACKET_BATCH_DATAGRAM_SIZE 2048

typedef struct {
    MUTEX lock;
    UINT32 depth;
    UINT32 count;
    UINT32 lengths[TRANSPORT_PACKET_BATCH_CAPACITY];
    BYTE packets[TRANSPORT_PACKET_BATCH_CAPACITY][TRANSPORT_PACKET_BATCH_DATAGRAM_SIZE];
    UINT64 queuedPackets;
    UINT64 batchFlushes;
    UINT64 singlePacketFallbacks;
    UINT32 largestBatch;
} TransportPacketBatch, *PTransportPacketBatch;

STATUS createTransportPacketBatch(PTransportPacketBatch*);
STATUS freeTransportPacketBatch(PTransportPacketBatch*);
STATUS transportPacketBatchBegin(PTransportPacketBatch);
STATUS transportPacketBatchQueue(PTransportPacketBatch, PIceAgent, PBYTE, UINT32);
STATUS transportPacketBatchEnd(PTransportPacketBatch, PIceAgent);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_TRANSPORT_PACKET_BATCH__ */
