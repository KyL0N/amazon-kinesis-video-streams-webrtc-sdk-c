#define LOG_CLASS "TransportPacketBatch"

#include "../Include_i.h"

#define TRANSPORT_PACKET_BATCH_SCOPE_DEPTH 4

#if defined(_MSC_VER)
#define KVS_TRANSPORT_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__)
#define KVS_TRANSPORT_THREAD_LOCAL __thread
#else
#define KVS_TRANSPORT_THREAD_LOCAL _Thread_local
#endif

typedef struct {
    PTransportPacketBatch batches[TRANSPORT_PACKET_BATCH_SCOPE_DEPTH];
    UINT32 depths[TRANSPORT_PACKET_BATCH_SCOPE_DEPTH];
    UINT32 count;
} TransportPacketBatchThreadState;

static KVS_TRANSPORT_THREAD_LOCAL TransportPacketBatchThreadState gTransportPacketBatchThreadState;

static BOOL isTransportPacketBatchActiveOnCurrentThread(PTransportPacketBatch pBatch)
{
    return pBatch != NULL && gTransportPacketBatchThreadState.count > 0 &&
        gTransportPacketBatchThreadState.batches[gTransportPacketBatchThreadState.count - 1] == pBatch;
}

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
    pBatch->lock = MUTEX_CREATE(FALSE);
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
          pBatch->queuedPackets, pBatch->batchFlushes, (UINT64) ATOMIC_LOAD(&pBatch->singlePacketFallbacks), pBatch->largestBatch);
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
    UINT32 i = 0, scopeIndex = 0;

    CHK(pBatch != NULL, STATUS_NULL_ARG);

    if (isTransportPacketBatchActiveOnCurrentThread(pBatch)) {
        scopeIndex = gTransportPacketBatchThreadState.count - 1;
        gTransportPacketBatchThreadState.depths[scopeIndex]++;
        pBatch->depth++;
        CHK(FALSE, retStatus);
    }

    CHK(gTransportPacketBatchThreadState.count < TRANSPORT_PACKET_BATCH_SCOPE_DEPTH, STATUS_NOT_ENOUGH_MEMORY);
    for (i = 0; i < gTransportPacketBatchThreadState.count; i++) {
        CHK(gTransportPacketBatchThreadState.batches[i] != pBatch, STATUS_INVALID_OPERATION);
    }

    MUTEX_LOCK(pBatch->lock);
    scopeIndex = gTransportPacketBatchThreadState.count++;
    gTransportPacketBatchThreadState.batches[scopeIndex] = pBatch;
    gTransportPacketBatchThreadState.depths[scopeIndex] = 1;
    pBatch->depth = 1;

CleanUp:
    return retStatus;
}

STATUS transportPacketBatchQueue(PTransportPacketBatch pBatch, PIceAgent pIceAgent, PBYTE pBuffer, UINT32 bufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pBatch != NULL && pIceAgent != NULL && pBuffer != NULL, STATUS_NULL_ARG);
    CHK(bufferLen > 0, STATUS_INVALID_ARG);

    if (!isTransportPacketBatchActiveOnCurrentThread(pBatch)) {
        CHK_STATUS(iceAgentSendPacket(pIceAgent, pBuffer, bufferLen));
        ATOMIC_INCREMENT(&pBatch->singlePacketFallbacks);
        CHK(FALSE, retStatus);
    }

    if (bufferLen > TRANSPORT_PACKET_BATCH_DATAGRAM_SIZE) {
        CHK_STATUS(flushTransportPacketBatch(pBatch, pIceAgent));
        CHK_STATUS(iceAgentSendPacket(pIceAgent, pBuffer, bufferLen));
        ATOMIC_INCREMENT(&pBatch->singlePacketFallbacks);
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
    return retStatus;
}

STATUS transportPacketBatchEnd(PTransportPacketBatch pBatch, PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL unlock = FALSE;
    UINT32 scopeIndex = 0;

    CHK(pBatch != NULL && pIceAgent != NULL, STATUS_NULL_ARG);
    CHK(isTransportPacketBatchActiveOnCurrentThread(pBatch), STATUS_INVALID_OPERATION);
    scopeIndex = gTransportPacketBatchThreadState.count - 1;
    CHK(gTransportPacketBatchThreadState.depths[scopeIndex] > 0 && pBatch->depth > 0, STATUS_INVALID_OPERATION);

    gTransportPacketBatchThreadState.depths[scopeIndex]--;
    pBatch->depth--;
    if (gTransportPacketBatchThreadState.depths[scopeIndex] == 0) {
        unlock = TRUE;
        CHK_STATUS(flushTransportPacketBatch(pBatch, pIceAgent));
        gTransportPacketBatchThreadState.batches[scopeIndex] = NULL;
        gTransportPacketBatchThreadState.count--;
    }

CleanUp:
    /* The outer scope owns the non-recursive mutex, but DTLS callbacks on
     * unrelated threads never acquire it. This avoids sslLock/batchLock lock
     * inversion while preserving single-writer SCTP sends. */
    if (unlock) {
        gTransportPacketBatchThreadState.batches[scopeIndex] = NULL;
        gTransportPacketBatchThreadState.depths[scopeIndex] = 0;
        if (gTransportPacketBatchThreadState.count > scopeIndex) {
            gTransportPacketBatchThreadState.count = scopeIndex;
        }
        pBatch->depth = 0;
        MUTEX_UNLOCK(pBatch->lock);
    }
    return retStatus;
}
