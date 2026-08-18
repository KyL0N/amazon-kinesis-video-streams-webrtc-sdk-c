#define LOG_CLASS "TransportPacketBatch"

#include "../Include_i.h"

static STATUS flushTransportPacketBatch(PTransportPacketBatch pBatch, PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    PBYTE buffers[TRANSPORT_PACKET_BATCH_CAPACITY];
    UINT32 i = 0;

    CHK(pBatch != NULL && pIceAgent != NULL, STATUS_NULL_ARG);
    CHK(pBatch->count > 0, retStatus);

    for (i = 0; i < pBatch->count; i++) {
        buffers[i] = pBatch->packets[i];
    }
    CHK_STATUS(iceAgentSendPacketBatch(pIceAgent, buffers, pBatch->lengths, pBatch->count));

    pBatch->batchFlushes++;
    if (pBatch->count > pBatch->largestBatch) {
        pBatch->largestBatch = pBatch->count;
    }
    pBatch->count = 0;

CleanUp:
    return retStatus;
}

STATUS createTransportPacketBatch(PTransportPacketBatch* ppBatch)
{
    STATUS retStatus = STATUS_SUCCESS;
    PTransportPacketBatch pBatch = NULL;

    CHK(ppBatch != NULL, STATUS_NULL_ARG);
    pBatch = (PTransportPacketBatch) MEMCALLOC(1, SIZEOF(TransportPacketBatch));
    CHK(pBatch != NULL, STATUS_NOT_ENOUGH_MEMORY);
    pBatch->lock = MUTEX_CREATE(TRUE);
    CHK(IS_VALID_MUTEX_VALUE(pBatch->lock), STATUS_INVALID_OPERATION);

CleanUp:
    if (STATUS_FAILED(retStatus)) {
        freeTransportPacketBatch(&pBatch);
    }
    if (ppBatch != NULL) {
        *ppBatch = pBatch;
    }
    return retStatus;
}

STATUS freeTransportPacketBatch(PTransportPacketBatch* ppBatch)
{
    STATUS retStatus = STATUS_SUCCESS;
    PTransportPacketBatch pBatch = NULL;

    CHK(ppBatch != NULL, STATUS_NULL_ARG);
    pBatch = *ppBatch;
    CHK(pBatch != NULL, retStatus);

    DLOGI("DTLS UDP batch summary: queued=%" PRIu64 ", flushes=%" PRIu64 ", singleFallbacks=%" PRIu64 ", largestBatch=%u",
          pBatch->queuedPackets, pBatch->batchFlushes, pBatch->singlePacketFallbacks, pBatch->largestBatch);
    if (IS_VALID_MUTEX_VALUE(pBatch->lock)) {
        MUTEX_FREE(pBatch->lock);
    }
    MEMFREE(pBatch);
    *ppBatch = NULL;

CleanUp:
    return retStatus;
}

STATUS transportPacketBatchBegin(PTransportPacketBatch pBatch)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pBatch != NULL, STATUS_NULL_ARG);
    MUTEX_LOCK(pBatch->lock);
    pBatch->depth++;

CleanUp:
    return retStatus;
}

STATUS transportPacketBatchQueue(PTransportPacketBatch pBatch, PIceAgent pIceAgent, PBYTE pBuffer, UINT32 bufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pBatch != NULL && pIceAgent != NULL && pBuffer != NULL, STATUS_NULL_ARG);
    CHK(bufferLen > 0, STATUS_INVALID_ARG);

    MUTEX_LOCK(pBatch->lock);
    locked = TRUE;

    if (pBatch->depth == 0 || bufferLen > TRANSPORT_PACKET_BATCH_DATAGRAM_SIZE) {
        CHK_STATUS(flushTransportPacketBatch(pBatch, pIceAgent));
        CHK_STATUS(iceAgentSendPacket(pIceAgent, pBuffer, bufferLen));
        pBatch->singlePacketFallbacks++;
        CHK(FALSE, retStatus);
    }

    if (pBatch->count == TRANSPORT_PACKET_BATCH_CAPACITY) {
        CHK_STATUS(flushTransportPacketBatch(pBatch, pIceAgent));
    }

    MEMCPY(pBatch->packets[pBatch->count], pBuffer, bufferLen);
    pBatch->lengths[pBatch->count] = bufferLen;
    pBatch->count++;
    pBatch->queuedPackets++;

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pBatch->lock);
    }
    return retStatus;
}

STATUS transportPacketBatchEnd(PTransportPacketBatch pBatch, PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL unlock = FALSE;

    CHK(pBatch != NULL && pIceAgent != NULL, STATUS_NULL_ARG);
    CHK(pBatch->depth > 0, STATUS_INVALID_OPERATION);
    unlock = TRUE;

    pBatch->depth--;
    if (pBatch->depth == 0) {
        CHK_STATUS(flushTransportPacketBatch(pBatch, pIceAgent));
    }

CleanUp:
    /* Begin deliberately leaves one recursive lock level held across the
     * protocol operation. End always releases that level, including errors. */
    if (unlock) {
        MUTEX_UNLOCK(pBatch->lock);
    }
    return retStatus;
}
