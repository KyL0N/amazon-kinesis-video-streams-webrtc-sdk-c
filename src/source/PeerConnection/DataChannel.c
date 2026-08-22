#define LOG_CLASS "DataChannel"

#include "../Include_i.h"

STATUS connectLocalDataChannel()
{
    return STATUS_SUCCESS;
}

STATUS createDataChannel(PRtcPeerConnection pPeerConnection, PCHAR pDataChannelName, PRtcDataChannelInit pRtcDataChannelInit,
                         PRtcDataChannel* ppRtcDataChannel)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsPeerConnection pKvsPeerConnection = (PKvsPeerConnection) pPeerConnection;
    UINT32 channelId = 0;
    PKvsDataChannel pKvsDataChannel = NULL;

    CHK(pKvsPeerConnection != NULL && pDataChannelName != NULL && ppRtcDataChannel != NULL, STATUS_NULL_ARG);

    // Only support creating DataChannels before signaling for now
    CHK(pKvsPeerConnection->pSctpSession == NULL, STATUS_INTERNAL_ERROR);

    CHK((pKvsDataChannel = (PKvsDataChannel) MEMCALLOC(1, SIZEOF(KvsDataChannel))) != NULL, STATUS_NOT_ENOUGH_MEMORY);
    STRNCPY(pKvsDataChannel->dataChannel.name, pDataChannelName, MAX_DATA_CHANNEL_NAME_LEN);
    pKvsDataChannel->pRtcPeerConnection = (PRtcPeerConnection) pKvsPeerConnection;
    if (pRtcDataChannelInit != NULL) {
        // Setting negotiated to false. Not supporting at the moment
        pRtcDataChannelInit->negotiated = FALSE;
        pKvsDataChannel->rtcDataChannelInit = *pRtcDataChannelInit;
    } else {
        // If nothing is set, set default to ordered mode
        pKvsDataChannel->rtcDataChannelInit.ordered = TRUE;
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxPacketLifeTime);
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxRetransmits);
    }
    STRNCPY(pKvsDataChannel->rtcDataChannelDiagnostics.label, pKvsDataChannel->dataChannel.name,
            ARRAY_SIZE(pKvsDataChannel->rtcDataChannelDiagnostics.label) - 1);
    pKvsDataChannel->rtcDataChannelDiagnostics.label[ARRAY_SIZE(pKvsDataChannel->rtcDataChannelDiagnostics.label) - 1] = '\0';
    pKvsDataChannel->rtcDataChannelDiagnostics.state = RTC_DATA_CHANNEL_STATE_CONNECTING;
    CHK_STATUS(hashTableGetCount(pKvsPeerConnection->pDataChannels, &channelId));
    pKvsDataChannel->rtcDataChannelDiagnostics.dataChannelIdentifier = channelId;
    pKvsDataChannel->dataChannel.id = channelId;
    STRNCPY(pKvsDataChannel->rtcDataChannelDiagnostics.protocol, DATA_CHANNEL_PROTOCOL_STR,
            ARRAY_SIZE(pKvsDataChannel->rtcDataChannelDiagnostics.protocol));
    CHK_STATUS(hashTablePut(pKvsPeerConnection->pDataChannels, channelId, (UINT64) pKvsDataChannel));

CleanUp:
    if (STATUS_SUCCEEDED(retStatus)) {
        *ppRtcDataChannel = (PRtcDataChannel) pKvsDataChannel;
    } else {
        SAFE_MEMFREE(pKvsDataChannel);
    }

    LEAVES();
    return retStatus;
}

STATUS dataChannelSend(PRtcDataChannel pRtcDataChannel, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen)
{
    RtcDataChannelMessage message;
    UINT32 messagesSent = 0;

    message.pDataChannel = pRtcDataChannel;
    message.isBinary = isBinary;
    message.pMessage = pMessage;
    message.messageLen = pMessageLen;
    return dataChannelSendBatch(&message, 1, &messagesSent);
}

STATUS dataChannelSendBatch(PRtcDataChannelMessage pMessages, UINT32 messageCount, PUINT32 pMessagesSent)
{
    STATUS retStatus = STATUS_SUCCESS;
    STATUS batchStatus = STATUS_SUCCESS;
    PKvsPeerConnection pKvsPeerConnection = NULL;
    BOOL transportBatchActive = FALSE;
    UINT32 i;

    CHK(pMessagesSent != NULL, STATUS_NULL_ARG);
    *pMessagesSent = 0;
    CHK(pMessages != NULL, STATUS_NULL_ARG);
    CHK(messageCount > 0 && messageCount <= RTC_DATA_CHANNEL_MAX_SEND_BATCH_MESSAGES, STATUS_INVALID_ARG);

    // Validate the whole batch before accepting any prefix. Every message must
    // belong to the same SCTP association because the write gate and UDP batch
    // are PeerConnection-owned.
    for (i = 0; i < messageCount; ++i) {
        PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pMessages[i].pDataChannel;
        PKvsPeerConnection pMessagePeerConnection;
        CHK(pKvsDataChannel != NULL && pMessages[i].pMessage != NULL, STATUS_NULL_ARG);
        pMessagePeerConnection = (PKvsPeerConnection) pKvsDataChannel->pRtcPeerConnection;
        CHK(pMessagePeerConnection != NULL && pMessagePeerConnection->pSctpSession != NULL, STATUS_INVALID_OPERATION);
        if (pKvsPeerConnection == NULL) {
            pKvsPeerConnection = pMessagePeerConnection;
        } else {
            CHK(pKvsPeerConnection == pMessagePeerConnection, STATUS_INVALID_ARG);
        }
    }

    // This association-wide batch scope is also the public DataChannel write
    // gate. Concurrent callers are serialized before entering usrsctp, while
    // every write retains call-local stream and partial-reliability metadata.
    CHK_STATUS(transportPacketBatchBegin(pKvsPeerConnection->pTransportPacketBatch));
    transportBatchActive = TRUE;
    for (i = 0; i < messageCount; ++i) {
        PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pMessages[i].pDataChannel;
        CHK_STATUS(sctpSessionWriteMessage(pKvsPeerConnection->pSctpSession, pKvsDataChannel->channelId, pMessages[i].isBinary,
                                           pMessages[i].pMessage, pMessages[i].messageLen, &pKvsDataChannel->rtcDataChannelInit));
        pKvsDataChannel->rtcDataChannelDiagnostics.messagesSent++;
        pKvsDataChannel->rtcDataChannelDiagnostics.bytesSent += pMessages[i].messageLen;
        ++(*pMessagesSent);
    }
    batchStatus = transportPacketBatchEnd(pKvsPeerConnection->pTransportPacketBatch, pKvsPeerConnection->pIceAgent);
    transportBatchActive = FALSE;
    CHK_STATUS(batchStatus);
CleanUp:
    if (transportBatchActive) {
        batchStatus = transportPacketBatchEnd(pKvsPeerConnection->pTransportPacketBatch, pKvsPeerConnection->pIceAgent);
        if (STATUS_SUCCEEDED(retStatus)) {
            retStatus = batchStatus;
        } else {
            CHK_LOG_ERR(batchStatus);
        }
    }

    return retStatus;
}

STATUS dataChannelOnMessage(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnMessage rtcOnMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnMessage != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onMessage = rtcOnMessage;
    pKvsDataChannel->onMessageCustomData = customData;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS dataChannelOnOpen(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnOpen rtcOnOpen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnOpen != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onOpen = rtcOnOpen;
    pKvsDataChannel->onOpenCustomData = customData;

CleanUp:

    LEAVES();
    return retStatus;
}
