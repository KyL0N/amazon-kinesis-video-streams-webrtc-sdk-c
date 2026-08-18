/**
 * Kinesis Video Producer ConnectionListener
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#define LOG_CLASS "ConnectionListener"
#include "../Include_i.h"

static STATUS connectionListenerDispatchDatagram(PSocketConnection, PBYTE, UINT32, UINT32, struct sockaddr_storage*);

STATUS createConnectionListener(PConnectionListener* ppConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 allocationSize = SIZEOF(ConnectionListener) + MAX_UDP_PACKET_SIZE * CONNECTION_LISTENER_RECEIVE_BATCH_SIZE;
    PConnectionListener pConnectionListener = NULL;

    CHK(ppConnectionListener != NULL, STATUS_NULL_ARG);

    pConnectionListener = (PConnectionListener) MEMCALLOC(1, allocationSize);
    CHK(pConnectionListener != NULL, STATUS_NOT_ENOUGH_MEMORY);

    ATOMIC_STORE_BOOL(&pConnectionListener->terminate, FALSE);
    pConnectionListener->receiveDataRoutine = INVALID_TID_VALUE;
    pConnectionListener->lock = MUTEX_CREATE(FALSE);

    // No sockets are present
    pConnectionListener->socketCount = 0;

    // pConnectionListener->pBuffer starts at the end of ConnectionListener struct
    pConnectionListener->pBuffer = (PBYTE) (pConnectionListener + 1);
    pConnectionListener->bufferLen = MAX_UDP_PACKET_SIZE;

    // Use socketpair only if available
#if defined(HAVE_SOCKETPAIR)
    pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_LISTEN] = -1;
    pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_WRITE] = -1;
    CHK_STATUS(createSocketPair(&(pConnectionListener->kickSocket)));
#endif

CleanUp:

    if (STATUS_FAILED(retStatus) && pConnectionListener != NULL) {
        freeConnectionListener(&pConnectionListener);
        pConnectionListener = NULL;
    }

    if (ppConnectionListener != NULL) {
        *ppConnectionListener = pConnectionListener;
    }

    return retStatus;
}

STATUS freeConnectionListener(PConnectionListener* ppConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    PConnectionListener pConnectionListener = NULL;
    TID threadId;
    const char* msg = "1";

    CHK(ppConnectionListener != NULL, STATUS_NULL_ARG);
    CHK(*ppConnectionListener != NULL, retStatus);

    pConnectionListener = *ppConnectionListener;

    ATOMIC_STORE_BOOL(&pConnectionListener->terminate, TRUE);

    if (IS_VALID_MUTEX_VALUE(pConnectionListener->lock)) {
        MUTEX_LOCK(pConnectionListener->lock);
        threadId = pConnectionListener->receiveDataRoutine;
        MUTEX_UNLOCK(pConnectionListener->lock);

        // TODO add support for windows socketpair
        // This writes to the socketpair, kicking the POLL() out early,
        // otherwise wait for the POLL to timeout
#if defined(HAVE_SOCKETPAIR)
        socketWrite(pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_WRITE], msg, STRLEN(msg));
#endif

        // wait for thread to finish.
        if (IS_VALID_TID_VALUE(threadId)) {
            THREAD_JOIN(pConnectionListener->receiveDataRoutine, NULL);
        }

        MUTEX_FREE(pConnectionListener->lock);
    }

    // TODO add support for windows socketpair
#if defined(HAVE_SOCKETPAIR)
    if (pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_LISTEN] != -1) {
        closeSocket(pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_LISTEN]);
    }
    if (pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_WRITE] != -1) {
        closeSocket(pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_WRITE]);
    }
#endif

    MEMFREE(pConnectionListener);

    *ppConnectionListener = NULL;

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

STATUS connectionListenerAddConnection(PConnectionListener pConnectionListener, PSocketConnection pSocketConnection)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE, iterate = TRUE;
    UINT32 i;

    CHK(pConnectionListener != NULL && pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    // Check for space
    CHK(pConnectionListener->socketCount < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION, STATUS_NOT_ENOUGH_MEMORY);

    // Find an empty slot by checking whether connected
    for (i = 0; iterate && i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
        if (pConnectionListener->sockets[i] == NULL) {
            pConnectionListener->sockets[i] = pSocketConnection;
            pConnectionListener->socketCount++;
            iterate = FALSE;
        }
    }

    MUTEX_UNLOCK(pConnectionListener->lock);
    locked = FALSE;

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}

STATUS connectionListenerRemoveConnection(PConnectionListener pConnectionListener, PSocketConnection pSocketConnection)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE, iterate = TRUE;
    UINT32 i;

    CHK(pConnectionListener != NULL && pSocketConnection != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    // Mark socket as closed
    CHK_STATUS(socketConnectionClosed(pSocketConnection));

    // Remove from the list of sockets
    for (i = 0; iterate && i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
        if (pConnectionListener->sockets[i] == pSocketConnection) {
            iterate = FALSE;

            // Mark the slot as empty and decrement the count
            pConnectionListener->sockets[i] = NULL;
            pConnectionListener->socketCount--;
        }
    }

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}

STATUS connectionListenerRemoveAllConnection(PConnectionListener pConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    UINT32 i;

    CHK(pConnectionListener != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    for (i = 0; i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
        if (pConnectionListener->sockets[i] != NULL) {
            CHK_STATUS(socketConnectionClosed(pConnectionListener->sockets[i]));
            pConnectionListener->sockets[i] = NULL;
            pConnectionListener->socketCount--;
        }
    }

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}

STATUS connectionListenerStart(PConnectionListener pConnectionListener)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pConnectionListener != NULL, STATUS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate), retStatus);

    MUTEX_LOCK(pConnectionListener->lock);
    locked = TRUE;

    CHK(!IS_VALID_TID_VALUE(pConnectionListener->receiveDataRoutine), retStatus);
    CHK_STATUS(THREAD_CREATE(&pConnectionListener->receiveDataRoutine, connectionListenerReceiveDataRoutine, (PVOID) pConnectionListener));

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pConnectionListener->lock);
    }

    return retStatus;
}

BOOL canReadFd(INT32 fd, struct pollfd* fds, INT32 nfds)
{
    INT32 i;
    for (i = 0; i < nfds; i++) {
        if (fds[i].fd == fd && (fds[i].revents & POLLIN) != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static STATUS connectionListenerDispatchDatagram(PSocketConnection pSocketConnection, PBYTE pBuffer, UINT32 bufferLen, UINT32 dataLen,
                                                 struct sockaddr_storage* pSrcAddrStorage)
{
    STATUS retStatus = STATUS_SUCCESS;
    struct sockaddr_in* pIpv4Addr = NULL;
    struct sockaddr_in6* pIpv6Addr = NULL;
    KvsIpAddress srcAddr;
    PKvsIpAddress pSrcAddr = NULL;

    CHK(pSocketConnection != NULL && pBuffer != NULL, STATUS_NULL_ARG);
    CHK(ATOMIC_LOAD_BOOL(&pSocketConnection->receiveData) && pSocketConnection->dataAvailableCallbackFn != NULL, retStatus);

    /* Secure SocketConnections decrypt in place. Plain ICE candidate sockets
     * return without changing dataLen. */
    CHK(STATUS_SUCCEEDED(socketConnectionReadData(pSocketConnection, pBuffer, bufferLen, &dataLen)), retStatus);

    if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_UDP && pSrcAddrStorage != NULL) {
        MEMSET(&srcAddr, 0x00, SIZEOF(srcAddr));
        srcAddr.isPointToPoint = FALSE;
        if (pSrcAddrStorage->ss_family == AF_INET) {
            srcAddr.family = KVS_IP_FAMILY_TYPE_IPV4;
            pIpv4Addr = (struct sockaddr_in*) pSrcAddrStorage;
            MEMCPY(srcAddr.address, (PBYTE) &pIpv4Addr->sin_addr, IPV4_ADDRESS_LENGTH);
            srcAddr.port = pIpv4Addr->sin_port;
            pSrcAddr = &srcAddr;
        } else if (pSrcAddrStorage->ss_family == AF_INET6) {
            srcAddr.family = KVS_IP_FAMILY_TYPE_IPV6;
            pIpv6Addr = (struct sockaddr_in6*) pSrcAddrStorage;
            MEMCPY(srcAddr.address, (PBYTE) &pIpv6Addr->sin6_addr, IPV6_ADDRESS_LENGTH);
            srcAddr.port = pIpv6Addr->sin6_port;
            pSrcAddr = &srcAddr;
        }
    }

    if (dataLen > 0) {
        pSocketConnection->dataAvailableCallbackFn(pSocketConnection->dataAvailableCallbackCustomData, pSocketConnection, pBuffer, dataLen,
                                                   pSrcAddr, NULL);
    }

CleanUp:
    return retStatus;
}

PVOID connectionListenerReceiveDataRoutine(PVOID arg)
{
    STATUS retStatus = STATUS_SUCCESS;
    PConnectionListener pConnectionListener = (PConnectionListener) arg;
    PSocketConnection pSocketConnection;
    BOOL iterate = TRUE;
    PSocketConnection sockets[CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION];
    UINT32 i, socketCount;

    INT32 nfds = 0;
    //+1 added for the pipe() to kickout poll()
    struct pollfd rfds[CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION + 1];
    INT32 retval, localSocket;
    INT64 readLen;
    // the source address is put here. sockaddr_storage can hold either sockaddr_in or sockaddr_in6
    struct sockaddr_storage srcAddrBuff;
    socklen_t srcAddrBuffLen = SIZEOF(srcAddrBuff);
#if defined(__linux__)
    struct mmsghdr messages[CONNECTION_LISTENER_RECEIVE_BATCH_SIZE];
    struct iovec ioVectors[CONNECTION_LISTENER_RECEIVE_BATCH_SIZE];
    struct sockaddr_storage batchSrcAddrs[CONNECTION_LISTENER_RECEIVE_BATCH_SIZE];
    UINT32 batchIndex = 0;
    INT32 receivedCount = 0;
#endif

    CHK(pConnectionListener != NULL, STATUS_NULL_ARG);

    /* Ensure that memory sanitizers consider
     * rfds initialized even if FD_ZERO is
     * implemented in assembly. */
    MEMSET(&rfds, 0x00, SIZEOF(rfds));

#if defined(__linux__)
    MEMSET(messages, 0x00, SIZEOF(messages));
    MEMSET(ioVectors, 0x00, SIZEOF(ioVectors));
    MEMSET(batchSrcAddrs, 0x00, SIZEOF(batchSrcAddrs));
    for (batchIndex = 0; batchIndex < CONNECTION_LISTENER_RECEIVE_BATCH_SIZE; batchIndex++) {
        ioVectors[batchIndex].iov_base = pConnectionListener->pBuffer + batchIndex * pConnectionListener->bufferLen;
        ioVectors[batchIndex].iov_len = pConnectionListener->bufferLen;
        messages[batchIndex].msg_hdr.msg_iov = &ioVectors[batchIndex];
        messages[batchIndex].msg_hdr.msg_iovlen = 1;
        messages[batchIndex].msg_hdr.msg_name = &batchSrcAddrs[batchIndex];
    }
#endif

    while (!ATOMIC_LOAD_BOOL(&pConnectionListener->terminate)) {
        nfds = 0;

        // Perform the socket connection gathering under the lock
        // NOTE: There is no cleanup jump from the lock/unlock block
        // so we don't need to use a boolean indicator whether locked
        MUTEX_LOCK(pConnectionListener->lock);
        for (i = 0, socketCount = 0; i < CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION; i++) {
            pSocketConnection = pConnectionListener->sockets[i];
            if (pSocketConnection != NULL) {
                if (!socketConnectionIsClosed(pSocketConnection)) {
                    MUTEX_LOCK(pSocketConnection->lock);
                    localSocket = pSocketConnection->localSocket;
                    MUTEX_UNLOCK(pSocketConnection->lock);
                    rfds[nfds].fd = localSocket;
                    rfds[nfds].events = POLLIN | POLLPRI;
#if !defined(HAVE_SOCKETPAIR)
                    rfds[nfds].events &= ~POLLPRI;
#endif
                    rfds[nfds].revents = 0;
                    nfds++;

                    // Store the sockets locally while in use and mark it as in use
                    sockets[socketCount++] = pSocketConnection;
                    ATOMIC_STORE_BOOL(&pSocketConnection->inUse, TRUE);
                } else {
                    // Remove the connection
                    pConnectionListener->sockets[i] = NULL;
                    pConnectionListener->socketCount--;
                }
            }
        }

        // Need to unlock the mutex to ensure other racing threads unblock
        MUTEX_UNLOCK(pConnectionListener->lock);
        retval = 0;
        if (nfds != 0) {
            // TODO add support for socketpair() in windows
            // This end of the socketpair has been added to the list of sockets polled
            // in order to have a way to end the poll early from the destructor
#if defined(HAVE_SOCKETPAIR)
            rfds[nfds].fd = pConnectionListener->kickSocket[CONNECTION_LISTENER_KICK_SOCKET_LISTEN];
            rfds[nfds].events = POLLIN;
            rfds[nfds].revents = 0;
            nfds++;
#endif
            // blocking call until resolves as a timeout, an error, a signal or data received
            retval = POLL(rfds, nfds, CONNECTION_LISTENER_SOCKET_WAIT_FOR_DATA_TIMEOUT / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
        } else {
            // No sockets to poll (no active sessions). Yield to other tasks.
            THREAD_SLEEP(CONNECTION_LISTENER_SOCKET_WAIT_FOR_DATA_TIMEOUT);
        }

        // In case of 0 we have a timeout and should re-lock to allow for other
        // interlocking operations to proceed. A positive return means we received data
        if (retval == -1) {
            DLOGW("poll() failed with errno %s", getErrorString(getErrorCode()));
        } else if (retval > 0) {
            for (i = 0; i < socketCount; i++) {
                pSocketConnection = sockets[i];
                if (!socketConnectionIsClosed(pSocketConnection)) {
                    MUTEX_LOCK(pSocketConnection->lock);
                    localSocket = pSocketConnection->localSocket;
                    MUTEX_UNLOCK(pSocketConnection->lock);

                    if (canReadFd(localSocket, rfds, nfds)) {
                        iterate = TRUE;
                        while (iterate) {
#if defined(__linux__)
                            if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_UDP) {
                                for (batchIndex = 0; batchIndex < CONNECTION_LISTENER_RECEIVE_BATCH_SIZE; batchIndex++) {
                                    messages[batchIndex].msg_hdr.msg_namelen = SIZEOF(batchSrcAddrs[batchIndex]);
                                    messages[batchIndex].msg_hdr.msg_flags = 0;
                                    messages[batchIndex].msg_len = 0;
                                }

                                receivedCount = recvmmsg(localSocket, messages, CONNECTION_LISTENER_RECEIVE_BATCH_SIZE, MSG_DONTWAIT, NULL);
                                pConnectionListener->udpReceiveCalls++;
                                if (receivedCount < 0) {
                                    switch (getErrorCode()) {
                                        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
                                        case EWOULDBLOCK:
#endif
                                        case EINTR:
                                            break;
                                        default:
                                            CHK_STATUS(socketConnectionClosed(pSocketConnection));
                                            DLOGD("recvmmsg() failed with errno %s for socket %d", getErrorString(getErrorCode()), localSocket);
                                            break;
                                    }
                                    iterate = FALSE;
                                    continue;
                                }

                                if (receivedCount == 0) {
                                    CHK_STATUS(socketConnectionClosed(pSocketConnection));
                                    iterate = FALSE;
                                    continue;
                                }

                                pConnectionListener->udpPacketsReceived += receivedCount;
                                if ((UINT32) receivedCount > pConnectionListener->udpLargestBatch) {
                                    pConnectionListener->udpLargestBatch = (UINT32) receivedCount;
                                }
                                for (batchIndex = 0; batchIndex < (UINT32) receivedCount; batchIndex++) {
                                    if ((messages[batchIndex].msg_hdr.msg_flags & MSG_TRUNC) != 0) {
                                        DLOGW("Dropping truncated UDP datagram on socket %d", localSocket);
                                        continue;
                                    }
                                    CHK_STATUS(connectionListenerDispatchDatagram(
                                        pSocketConnection, (PBYTE) ioVectors[batchIndex].iov_base, (UINT32) ioVectors[batchIndex].iov_len,
                                        messages[batchIndex].msg_len,
                                        &batchSrcAddrs[batchIndex]));
                                }
                                continue;
                            }
#endif
                            readLen = recvfrom(localSocket, pConnectionListener->pBuffer, pConnectionListener->bufferLen, 0,
                                               (struct sockaddr*) &srcAddrBuff, &srcAddrBuffLen);
                            if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_UDP) {
                                pConnectionListener->udpReceiveCalls++;
                            }
                            if (readLen < 0) {
                                switch (getErrorCode()) {
                                    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
                                    case EWOULDBLOCK:
#endif
                                    case EINTR:
                                        break;
                                    default:
                                        /* on any other error, close connection */
                                        CHK_STATUS(socketConnectionClosed(pSocketConnection));
                                        DLOGD("recvfrom() failed with errno %s for socket %d", getErrorString(getErrorCode()), localSocket);
                                        break;
                                }

                                iterate = FALSE;
                            } else if (readLen == 0) {
                                CHK_STATUS(socketConnectionClosed(pSocketConnection));
                                iterate = FALSE;
                            } else {
                                if (pSocketConnection->protocol == KVS_SOCKET_PROTOCOL_UDP) {
                                    pConnectionListener->udpPacketsReceived++;
                                    if (pConnectionListener->udpLargestBatch < 1) {
                                        pConnectionListener->udpLargestBatch = 1;
                                    }
                                }
                                CHK_STATUS(connectionListenerDispatchDatagram(pSocketConnection, pConnectionListener->pBuffer,
                                                                              (UINT32) pConnectionListener->bufferLen, (UINT32) readLen,
                                                                              &srcAddrBuff));
                            }

                            // reset srcAddrBuffLen to actual size
                            srcAddrBuffLen = SIZEOF(srcAddrBuff);
                        }
                    }
                }
            }
        }

        // Mark as unused
        for (i = 0; i < socketCount; i++) {
            ATOMIC_STORE_BOOL(&sockets[i]->inUse, FALSE);
        }
    }

CleanUp:

    if (pConnectionListener != NULL) {
        DLOGI("UDP receive summary: packets=%" PRIu64 ", syscalls=%" PRIu64 ", largestBatch=%u", pConnectionListener->udpPacketsReceived,
              pConnectionListener->udpReceiveCalls, pConnectionListener->udpLargestBatch);
    }

    CHK_LOG_ERR(retStatus);

    return (PVOID) (ULONG_PTR) retStatus;
}
