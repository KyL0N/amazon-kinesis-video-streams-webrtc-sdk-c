#define LOG_CLASS "SCTP"
#include "../Include_i.h"

PSctpContext acquireSctpContext()
{
    ENTERS();
    static SctpContext s = {.lastTickTime = 0, .isSctpInitialized = FALSE, .contextRefCnt = 0, .sctpContextLock = INVALID_MUTEX_VALUE};
    ATOMIC_INCREMENT(&s.contextRefCnt);
    LEAVES();
    return &s;
}

VOID releaseSctpContext(PSctpContext pSctpContext)
{
    ENTERS();
    ATOMIC_DECREMENT(&pSctpContext->contextRefCnt);
    LEAVES();
}

STATUS getKvsSctpGlobalConfiguration(PRtcSctpGlobalConfiguration pConfiguration)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSctpContext pSctpContext = NULL;

    CHK(pConfiguration != NULL, STATUS_NULL_ARG);
    pSctpContext = acquireSctpContext();
    *pConfiguration = pSctpContext->configuration;
    pConfiguration->version = RTC_SCTP_GLOBAL_CONFIGURATION_CURRENT_VERSION;
    if (pConfiguration->timerIntervalMs == 0) {
        pConfiguration->timerIntervalMs = SCTP_TIMER_INTERVAL_MS_DEFAULT;
    }

CleanUp:
    if (pSctpContext != NULL) {
        releaseSctpContext(pSctpContext);
    }
    return retStatus;
}

STATUS configureKvsSctpGlobal(PRtcSctpGlobalConfiguration pConfiguration)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSctpContext pSctpContext = NULL;

    CHK(pConfiguration != NULL, STATUS_NULL_ARG);
    CHK(pConfiguration->version <= RTC_SCTP_GLOBAL_CONFIGURATION_CURRENT_VERSION, STATUS_SCTP_CONFIGURATION_INVALID);
    CHK(pConfiguration->timerIntervalMs <= 1000, STATUS_SCTP_CONFIGURATION_INVALID);

    pSctpContext = acquireSctpContext();
    CHK(!ATOMIC_LOAD_BOOL(&pSctpContext->isSctpInitialized), STATUS_INVALID_OPERATION);
    pSctpContext->configuration = *pConfiguration;

CleanUp:
    if (pSctpContext != NULL) {
        releaseSctpContext(pSctpContext);
    }
    CHK_LOG_ERR(retStatus);
    return retStatus;
}

// Initializes SCTP context, in particular the lastTickTime used for timer handling
STATUS createSctpContext()
{
    ENTERS();
    PSctpContext pSctpContext = acquireSctpContext();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK_WARN(!ATOMIC_LOAD_BOOL(&pSctpContext->isSctpInitialized), retStatus, "SCTP context already initialized, nothing to do");
    CHK_ERR(!IS_VALID_MUTEX_VALUE(pSctpContext->sctpContextLock), retStatus, "Mutex seems to have been created already");

    pSctpContext->sctpContextLock = MUTEX_CREATE(TRUE);
    CHK_ERR(IS_VALID_MUTEX_VALUE(pSctpContext->sctpContextLock), STATUS_NULL_ARG, "Mutex creation failed");
    MUTEX_LOCK(pSctpContext->sctpContextLock);
    locked = TRUE;
    pSctpContext->lastTickTime = GETTIME();
    ATOMIC_STORE_BOOL(&pSctpContext->isSctpInitialized, TRUE);
    DLOGI("Initialized SCTP context instance");

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pSctpContext->sctpContextLock);
    }
    releaseSctpContext(pSctpContext);
    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

STATUS cleanupSctpContext()
{
    ENTERS();
    UINT64 shutdownTimeout;
    STATUS retStatus = STATUS_SUCCESS;

    PSctpContext pSctpContext = acquireSctpContext();

    DLOGD("Releasing SCTP context instance from cleanupSctpContext");
    releaseSctpContext(pSctpContext);

    CHK_WARN(ATOMIC_LOAD_BOOL(&pSctpContext->isSctpInitialized), STATUS_INVALID_OPERATION, "SCTP context not initialized, nothing to clean up");

    ATOMIC_STORE_BOOL(&pSctpContext->isSctpInitialized, FALSE);

    shutdownTimeout = GETTIME() + SCTP_CONTEXT_REFERENCE_WAIT_TIMEOUT;
    while (ATOMIC_LOAD(&pSctpContext->contextRefCnt) > 0 && GETTIME() < shutdownTimeout) {
        DLOGV("Waiting on all references to be returned...%d", pSctpContext->contextRefCnt);
        THREAD_SLEEP(100 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
    }

    if (IS_VALID_MUTEX_VALUE(pSctpContext->sctpContextLock)) {
        MUTEX_FREE(pSctpContext->sctpContextLock);
        pSctpContext->sctpContextLock = INVALID_MUTEX_VALUE;
    }

    DLOGI("Destroyed SCTP context");

CleanUp:
    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

STATUS initSctpAddrConn(PSctpSession pSctpSession, struct sockaddr_conn* sconn)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    sconn->sconn_family = AF_CONN;
    putInt16((PINT16) &sconn->sconn_port, SCTP_ASSOCIATION_DEFAULT_PORT);
    sconn->sconn_addr = pSctpSession;

    LEAVES();
    return retStatus;
}

STATUS configureSctpSocket(struct socket* socket, PRtcSctpConfiguration pConfiguration, BOOL enableExtendedNotifications)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    struct linger linger_opt;
    struct sctp_event event;
    UINT32 i;
    UINT32 valueOn = 1;
    UINT32 fragmentInterleave = SCTP_FRAG_LEVEL_2;
    UINT16 outboundStreams = SCTP_DEFAULT_OUTBOUND_STREAMS;
    UINT16 inboundStreams = SCTP_DEFAULT_INBOUND_STREAMS;
    UINT32 congestionControl = SCTP_CC_RFC2581;
    UINT32 streamScheduler = SCTP_SS_DEFAULT;
    INT32 socketBufferSize;
    struct sctp_assoc_value associationValue;
    UINT16 eventTypes[] = {SCTP_ASSOC_CHANGE,   SCTP_PEER_ADDR_CHANGE,      SCTP_REMOTE_ERROR,
                           SCTP_SHUTDOWN_EVENT, SCTP_ADAPTATION_INDICATION, SCTP_PARTIAL_DELIVERY_EVENT};
    UINT16 extendedEventTypes[] = {SCTP_STREAM_RESET_EVENT, SCTP_SENDER_DRY_EVENT, SCTP_SEND_FAILED_EVENT};

    CHK(socket != NULL && pConfiguration != NULL, STATUS_NULL_ARG);

    CHK(usrsctp_set_non_blocking(socket, 1) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);

    // onSctpOutboundPacket must not be called after close
    linger_opt.l_onoff = 1;
    linger_opt.l_linger = 0;
    CHK(usrsctp_setsockopt(socket, SOL_SOCKET, SO_LINGER, &linger_opt, SIZEOF(linger_opt)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);

    // packets are generally sent as soon as possible and no unnecessary
    // delays are introduced, at the cost of more packets in the network.
    CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_NODELAY, &valueOn, SIZEOF(valueOn)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);

    if (pConfiguration->sendBufferBytes != 0) {
        CHK(pConfiguration->sendBufferBytes <= 0x7fffffffU, STATUS_SCTP_CONFIGURATION_INVALID);
        socketBufferSize = (INT32) pConfiguration->sendBufferBytes;
        CHK(usrsctp_setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &socketBufferSize, SIZEOF(socketBufferSize)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);
    }
    if (pConfiguration->receiveBufferBytes != 0) {
        CHK(pConfiguration->receiveBufferBytes <= 0x7fffffffU, STATUS_SCTP_CONFIGURATION_INVALID);
        socketBufferSize = (INT32) pConfiguration->receiveBufferBytes;
        CHK(usrsctp_setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &socketBufferSize, SIZEOF(socketBufferSize)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);
    }

    MEMSET(&event, 0, SIZEOF(event));
    event.se_assoc_id = SCTP_FUTURE_ASSOC;
    event.se_on = 1;
    // Preserve the notifications enabled by the SDK historically. The extra
    // stream-reset, sender-dry, and send-failed notifications are only enabled
    // when the application registered an event callback; sender-dry can be
    // high-frequency under sustained throughput.
    for (i = 0; i < (UINT32) (SIZEOF(eventTypes) / SIZEOF(UINT16)); i++) {
        event.se_type = eventTypes[i];
        CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_EVENT, &event, SIZEOF(struct sctp_event)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);
    }
    if (enableExtendedNotifications) {
        for (i = 0; i < (UINT32) (SIZEOF(extendedEventTypes) / SIZEOF(UINT16)); i++) {
            event.se_type = extendedEventTypes[i];
            CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_EVENT, &event, SIZEOF(struct sctp_event)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);
        }
    }

    struct sctp_initmsg initmsg;
    MEMSET(&initmsg, 0, SIZEOF(struct sctp_initmsg));
    outboundStreams = pConfiguration->outboundStreams == 0 ? SCTP_DEFAULT_OUTBOUND_STREAMS : pConfiguration->outboundStreams;
    inboundStreams = pConfiguration->inboundStreams == 0 ? SCTP_DEFAULT_INBOUND_STREAMS : pConfiguration->inboundStreams;
    initmsg.sinit_num_ostreams = outboundStreams;
    initmsg.sinit_max_instreams = inboundStreams;
    CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, SIZEOF(struct sctp_initmsg)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);

    struct sctp_rtoinfo rtoinfo;
    MEMSET(&rtoinfo, 0, SIZEOF(struct sctp_rtoinfo));
    rtoinfo.srto_initial = pConfiguration->initialRtoMs;
    rtoinfo.srto_min = pConfiguration->minRtoMs;
    rtoinfo.srto_max = pConfiguration->maxRtoMs == 0 ? SCTP_RTO_MAX : pConfiguration->maxRtoMs;
    CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_RTOINFO, &rtoinfo, SIZEOF(rtoinfo)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);

    MEMSET(&associationValue, 0, SIZEOF(associationValue));
    associationValue.assoc_id = SCTP_FUTURE_ASSOC;
    switch (pConfiguration->congestionControl) {
        case RTC_SCTP_CONGESTION_CONTROL_DEFAULT:
        case RTC_SCTP_CONGESTION_CONTROL_RFC2581:
            congestionControl = SCTP_CC_RFC2581;
            break;
        case RTC_SCTP_CONGESTION_CONTROL_HSTCP:
            congestionControl = SCTP_CC_HSTCP;
            break;
        case RTC_SCTP_CONGESTION_CONTROL_HTCP:
            congestionControl = SCTP_CC_HTCP;
            break;
        case RTC_SCTP_CONGESTION_CONTROL_RTCC:
            congestionControl = SCTP_CC_RTCC;
            break;
        default:
            CHK(FALSE, STATUS_SCTP_CONFIGURATION_INVALID);
    }
    if (pConfiguration->congestionControl != RTC_SCTP_CONGESTION_CONTROL_DEFAULT) {
        associationValue.assoc_value = congestionControl;
        CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_PLUGGABLE_CC, &associationValue, SIZEOF(associationValue)) == 0,
            STATUS_SCTP_SESSION_SETUP_FAILED);
    }

    switch (pConfiguration->streamScheduler) {
        case RTC_SCTP_STREAM_SCHEDULER_DEFAULT:
            streamScheduler = SCTP_SS_DEFAULT;
            break;
        case RTC_SCTP_STREAM_SCHEDULER_ROUND_ROBIN:
            streamScheduler = SCTP_SS_ROUND_ROBIN;
            break;
        case RTC_SCTP_STREAM_SCHEDULER_ROUND_ROBIN_PACKET:
            streamScheduler = SCTP_SS_ROUND_ROBIN_PACKET;
            break;
        case RTC_SCTP_STREAM_SCHEDULER_PRIORITY:
            streamScheduler = SCTP_SS_PRIORITY;
            break;
        case RTC_SCTP_STREAM_SCHEDULER_FAIR_BANDWIDTH:
            streamScheduler = SCTP_SS_FAIR_BANDWITH;
            break;
        case RTC_SCTP_STREAM_SCHEDULER_FIRST_COME:
            streamScheduler = SCTP_SS_FIRST_COME;
            break;
        default:
            CHK(FALSE, STATUS_SCTP_CONFIGURATION_INVALID);
    }
    if (pConfiguration->streamScheduler != RTC_SCTP_STREAM_SCHEDULER_DEFAULT) {
        associationValue.assoc_value = streamScheduler;
        CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_PLUGGABLE_SS, &associationValue, SIZEOF(associationValue)) == 0,
            STATUS_SCTP_SESSION_SETUP_FAILED);
    }

    if (pConfiguration->enableMessageInterleaving) {
        CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_FRAGMENT_INTERLEAVE, &fragmentInterleave, SIZEOF(fragmentInterleave)) == 0,
            STATUS_SCTP_SESSION_SETUP_FAILED);
        associationValue.assoc_value = 1;
        CHK(usrsctp_setsockopt(socket, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &associationValue, SIZEOF(associationValue)) == 0,
            STATUS_SCTP_SESSION_SETUP_FAILED);
    }

CleanUp:
    LEAVES();
    return retStatus;
}

STATUS initSctpSession()
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    RtcSctpGlobalConfiguration configuration;

    usrsctp_init_nothreads(0, &onSctpOutboundPacket, NULL);

    CHK_STATUS(getKvsSctpGlobalConfiguration(&configuration));
    CHK(usrsctp_sysctl_set_sctp_ecn_enable(configuration.enableEcn ? 1 : 0) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);
    if (configuration.sendSpaceBytes != 0) {
        CHK(usrsctp_sysctl_set_sctp_sendspace(configuration.sendSpaceBytes) == 0, STATUS_SCTP_CONFIGURATION_INVALID);
    }
    if (configuration.receiveSpaceBytes != 0) {
        CHK(usrsctp_sysctl_set_sctp_recvspace(configuration.receiveSpaceBytes) == 0, STATUS_SCTP_CONFIGURATION_INVALID);
    }

    CHK_STATUS(createSctpContext());

CleanUp:
    CHK_LOG_ERR(retStatus);

    LEAVES();
    return retStatus;
}

VOID deinitSctpSession()
{
    // need to block until usrsctp_finish or sctp thread could be calling free objects and cause segfault
    while (usrsctp_finish() != 0) {
        THREAD_SLEEP(DEFAULT_USRSCTP_TEARDOWN_POLLING_INTERVAL);
    }

    cleanupSctpContext();
}

STATUS createSctpSession(PSctpSessionCallbacks pSctpSessionCallbacks, PRtcSctpConfiguration pConfiguration, TIMER_QUEUE_HANDLE timerQueueHandle,
                         PSctpSession* ppSctpSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = NULL;
    struct sockaddr_conn localConn, remoteConn;
    struct sctp_paddrparams params;
    struct sctp_assocparams assocParams;
    RtcSctpConfiguration configuration;
    RtcSctpGlobalConfiguration globalConfiguration;
    INT32 connectStatus = 0;

    CHK(ppSctpSession != NULL && pSctpSessionCallbacks != NULL, STATUS_NULL_ARG);

    MEMSET(&configuration, 0, SIZEOF(configuration));
    configuration.version = RTC_SCTP_CONFIGURATION_CURRENT_VERSION;
    if (pConfiguration != NULL) {
        CHK(pConfiguration->version <= RTC_SCTP_CONFIGURATION_CURRENT_VERSION, STATUS_SCTP_CONFIGURATION_INVALID);
        configuration = *pConfiguration;
    }
    CHK_STATUS(getKvsSctpGlobalConfiguration(&globalConfiguration));

    pSctpSession = (PSctpSession) MEMCALLOC(1, SIZEOF(SctpSession));
    CHK(pSctpSession != NULL, STATUS_NOT_ENOUGH_MEMORY);

    MEMSET(&params, 0x00, SIZEOF(struct sctp_paddrparams));
    MEMSET(&localConn, 0x00, SIZEOF(struct sockaddr_conn));
    MEMSET(&remoteConn, 0x00, SIZEOF(struct sockaddr_conn));
    MEMSET(&assocParams, 0x00, SIZEOF(struct sctp_assocparams));

    ATOMIC_STORE(&pSctpSession->shutdownStatus, SCTP_SESSION_ACTIVE);
    ATOMIC_STORE_BOOL(&pSctpSession->sendBlocked, FALSE);
    pSctpSession->sctpSessionCallbacks = *pSctpSessionCallbacks;
    pSctpSession->writableThresholdBytes =
        pSctpSessionCallbacks->writableFunc == NULL ? 0 : (configuration.writableThresholdBytes == 0 ? 1 : configuration.writableThresholdBytes);
    pSctpSession->timerInterval = globalConfiguration.timerIntervalMs * HUNDREDS_OF_NANOS_IN_A_MILLISECOND;

    CHK_STATUS(initSctpAddrConn(pSctpSession, &localConn));
    CHK_STATUS(initSctpAddrConn(pSctpSession, &remoteConn));

    // call the timer callback now to reset the last tick time for this session while ensuring that other sessions'
    // queued timer tasks are correctly advanced
    sctpTimerCallback(0, GETTIME(), (UINT64) pSctpSession);

    CHK((pSctpSession->socket = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, onSctpInboundPacket,
                                               pSctpSessionCallbacks->writableFunc == NULL ? NULL : onSctpSendBufferAvailable,
                                               pSctpSessionCallbacks->writableFunc == NULL ? 0 : pSctpSession->writableThresholdBytes,
                                               pSctpSession)) != NULL,
        STATUS_SCTP_SESSION_SETUP_FAILED);
    usrsctp_register_address(pSctpSession);
    CHK_STATUS(configureSctpSocket(pSctpSession->socket, &configuration, pSctpSessionCallbacks->eventFunc != NULL));

    CHK(usrsctp_bind(pSctpSession->socket, (struct sockaddr*) &localConn, SIZEOF(localConn)) == 0, STATUS_SCTP_SESSION_SETUP_FAILED);

    connectStatus = usrsctp_connect(pSctpSession->socket, (struct sockaddr*) &remoteConn, SIZEOF(remoteConn));
    CHK(connectStatus >= 0 || errno == EINPROGRESS, STATUS_SCTP_SESSION_SETUP_FAILED);

    memcpy(&params.spp_address, &remoteConn, SIZEOF(remoteConn));
    params.spp_flags = SPP_PMTUD_DISABLE;
    params.spp_pathmtu = configuration.pathMtu == 0 ? SCTP_MTU : configuration.pathMtu;
    params.spp_pathmaxrxt = configuration.pathMaxRetransmits == 0 ? SCTP_MAX_PATH_RETRANSMITS : configuration.pathMaxRetransmits;
    CHK(usrsctp_setsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &params, SIZEOF(params)) == 0,
        STATUS_SCTP_SESSION_SETUP_FAILED);

    assocParams.sasoc_asocmaxrxt =
        configuration.associationMaxRetransmits == 0 ? SCTP_MAX_ASSOCIATION_RETRANSMITS : configuration.associationMaxRetransmits;
    CHK(usrsctp_setsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_ASSOCINFO, &assocParams, SIZEOF(assocParams)) == 0,
        STATUS_SCTP_SESSION_SETUP_FAILED);

    pSctpSession->timerQueueHandle = timerQueueHandle;
    CHK_STATUS(timerQueueAddTimer(pSctpSession->timerQueueHandle, pSctpSession->timerInterval, pSctpSession->timerInterval, sctpTimerCallback,
                                  (UINT64) pSctpSession, &pSctpSession->timerTaskId));

CleanUp:
    if (STATUS_FAILED(retStatus)) {
        freeSctpSession(&pSctpSession);
    }

    *ppSctpSession = pSctpSession;

    LEAVES();
    return retStatus;
}

STATUS freeSctpSession(PSctpSession* ppSctpSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession;
    UINT64 shutdownTimeout;

    CHK(ppSctpSession != NULL, STATUS_NULL_ARG);

    pSctpSession = *ppSctpSession;

    CHK(pSctpSession != NULL, retStatus);

    // Cancel the periodic timer before shutting down the socket
    if (IS_VALID_TIMER_QUEUE_HANDLE(pSctpSession->timerQueueHandle)) {
        timerQueueCancelTimer(pSctpSession->timerQueueHandle, pSctpSession->timerTaskId, (UINT64) pSctpSession);
    }

    usrsctp_deregister_address(pSctpSession);
    /* handle issue mentioned here: https://github.com/sctplab/usrsctp/issues/147
     * the change in shutdownStatus will trigger onSctpOutboundPacket to return -1 */
    ATOMIC_STORE(&pSctpSession->shutdownStatus, SCTP_SESSION_SHUTDOWN_INITIATED);

    if (pSctpSession->socket != NULL) {
        usrsctp_set_ulpinfo(pSctpSession->socket, NULL);
        usrsctp_shutdown(pSctpSession->socket, SHUT_RDWR);
        usrsctp_close(pSctpSession->socket);
    }

    shutdownTimeout = GETTIME() + DEFAULT_SCTP_SHUTDOWN_TIMEOUT;
    while (ATOMIC_LOAD(&pSctpSession->shutdownStatus) != SCTP_SESSION_SHUTDOWN_COMPLETED && GETTIME() < shutdownTimeout) {
        THREAD_SLEEP(DEFAULT_USRSCTP_TEARDOWN_POLLING_INTERVAL);
    }

    SAFE_MEMFREE(*ppSctpSession);

    *ppSctpSession = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS sctpSessionWriteMessage(PSctpSession pSctpSession, UINT32 streamId, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen,
                               PRtcDataChannelInit pRtcDataChannelInit)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    struct sctp_sendv_spa spa;
    SSIZE_T sendResult;
    INT32 sendErrno = 0;

    CHK(pSctpSession != NULL && pMessage != NULL && pRtcDataChannelInit != NULL, STATUS_NULL_ARG);

    // sendv copies this metadata before entering the usrsctp association lock. Keep it
    // call-local so writers targeting different DataChannels cannot overwrite snd_sid,
    // PPID, ordering, or partial-reliability settings on the shared SCTP session.
    MEMSET(&spa, 0x00, SIZEOF(struct sctp_sendv_spa));

    spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
    spa.sendv_sndinfo.snd_sid = streamId;

    if (!pRtcDataChannelInit->ordered) {
        spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
    }
    if (pRtcDataChannelInit->maxRetransmits.isNull == FALSE) {
        spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
        spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
        spa.sendv_prinfo.pr_value = pRtcDataChannelInit->maxRetransmits.value;
    } else if (pRtcDataChannelInit->maxPacketLifeTime.isNull == FALSE) {
        spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
        spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
        spa.sendv_prinfo.pr_value = pRtcDataChannelInit->maxPacketLifeTime.value;
    }

    putInt32((PINT32) &spa.sendv_sndinfo.snd_ppid, isBinary ? SCTP_PPID_BINARY : SCTP_PPID_STRING);
    ATOMIC_INCREMENT(&pSctpSession->sendCalls);
    sendResult = usrsctp_sendv(pSctpSession->socket, pMessage, pMessageLen, NULL, 0, &spa, SIZEOF(spa), SCTP_SENDV_SPA, 0);
    if (sendResult <= 0) {
        sendErrno = errno;
        ATOMIC_INCREMENT(&pSctpSession->sendFailures);
        ATOMIC_STORE(&pSctpSession->lastSendErrno, (SIZE_T) sendErrno);
        if (sendErrno == EAGAIN || sendErrno == EWOULDBLOCK) {
            ATOMIC_INCREMENT(&pSctpSession->blockedWrites);
            ATOMIC_STORE_BOOL(&pSctpSession->sendBlocked, TRUE);
        }
        CHK(FALSE, STATUS_SCTP_SENDV_FAILED);
    } else if (pSctpSession->sctpSessionCallbacks.writableFunc == NULL) {
        ATOMIC_STORE_BOOL(&pSctpSession->sendBlocked, FALSE);
    }

CleanUp:
    LEAVES();
    return retStatus;
}

// https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-09#section-5.1
//      0                   1                   2                   3
//      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |  Message Type |  Channel Type |            Priority           |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |                    Reliability Parameter                      |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |         Label Length          |       Protocol Length         |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     \                                                               /
//     |                             Label                             |
//     /                                                               /
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     \                                                               /
//     |                            Protocol                           |
//     /                                                               /
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
STATUS sctpSessionWriteDcep(PSctpSession pSctpSession, UINT32 streamId, PCHAR pChannelName, UINT32 pChannelNameLen,
                            PRtcDataChannelInit pRtcDataChannelInit)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    struct sctp_sendv_spa spa;
    BYTE packet[SCTP_MAX_ALLOWABLE_PACKET_LENGTH];
    UINT32 packetSize;

    CHK(pSctpSession != NULL && pChannelName != NULL && pRtcDataChannelInit != NULL, STATUS_NULL_ARG);

    MEMSET(&spa, 0x00, SIZEOF(struct sctp_sendv_spa));
    MEMSET(packet, 0x00, SIZEOF(packet));
    packetSize = SCTP_DCEP_HEADER_LENGTH + pChannelNameLen;
    /* Setting the fields of DATA_CHANNEL_OPEN message */

    packet[0] = DCEP_DATA_CHANNEL_OPEN; // message type

    // Set Channel type based on supplied parameters
    packet[1] = DCEP_DATA_CHANNEL_RELIABLE_ORDERED;

    //   Set channel type and reliability parameters based on input
    //   SCTP allows fine tuning the channel robustness:
    //      1. Ordering: The data packets can be sent out in an ordered/unordered fashion
    //      2. Reliability: This determines how the retransmission of packets is handled.
    //   There are 2 parameters that can be fine tuned to achieve this:
    //      a. Number of retransmits
    //      b. Packet lifetime
    //   Default values for the parameters is 0. This falls back to reliable channel

    if (!pRtcDataChannelInit->ordered) {
        packet[1] |= DCEP_DATA_CHANNEL_RELIABLE_UNORDERED;
    }
    if (pRtcDataChannelInit->maxRetransmits.value >= 0 && pRtcDataChannelInit->maxRetransmits.isNull == FALSE) {
        packet[1] |= DCEP_DATA_CHANNEL_REXMIT;
        putUnalignedInt32BigEndian(packet + SIZEOF(UINT32), pRtcDataChannelInit->maxRetransmits.value);
    } else if (pRtcDataChannelInit->maxPacketLifeTime.value >= 0 && pRtcDataChannelInit->maxPacketLifeTime.isNull == FALSE) {
        packet[1] |= DCEP_DATA_CHANNEL_TIMED;
        putUnalignedInt32BigEndian(packet + SIZEOF(UINT32), pRtcDataChannelInit->maxPacketLifeTime.value);
    }

    putUnalignedInt16BigEndian(packet + SCTP_DCEP_LABEL_LEN_OFFSET, pChannelNameLen);
    MEMCPY(packet + SCTP_DCEP_LABEL_OFFSET, pChannelName, pChannelNameLen);
    spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
    spa.sendv_sndinfo.snd_sid = streamId;

    putInt32((PINT32) &spa.sendv_sndinfo.snd_ppid, SCTP_PPID_DCEP);
    CHK(usrsctp_sendv(pSctpSession->socket, packet, packetSize, NULL, 0, &spa, SIZEOF(spa), SCTP_SENDV_SPA, 0) > 0,
        STATUS_SCTP_SENDV_FAILED);
CleanUp:

    LEAVES();
    return retStatus;
}

INT32 onSctpOutboundPacket(PVOID addr, PVOID data, ULONG length, UINT8 tos, UINT8 set_df)
{
    UNUSED_PARAM(tos);
    UNUSED_PARAM(set_df);

    PSctpSession pSctpSession = (PSctpSession) addr;

    if (pSctpSession == NULL || ATOMIC_LOAD(&pSctpSession->shutdownStatus) == SCTP_SESSION_SHUTDOWN_INITIATED ||
        pSctpSession->sctpSessionCallbacks.outboundPacketFunc == NULL) {
        if (pSctpSession != NULL) {
            ATOMIC_STORE(&pSctpSession->shutdownStatus, SCTP_SESSION_SHUTDOWN_COMPLETED);
        }
        return -1;
    }

    pSctpSession->sctpSessionCallbacks.outboundPacketFunc(pSctpSession->sctpSessionCallbacks.customData, data, length);

    return 0;
}

STATUS putSctpPacket(PSctpSession pSctpSession, PBYTE buf, UINT32 bufLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    usrsctp_conninput(pSctpSession, buf, bufLen, 0);

    LEAVES();
    return retStatus;
}

STATUS sctpTimerCallback(UINT32 timerID, UINT64 currentTime, UINT64 customData)
{
    UNUSED_PARAM(timerID);
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = (PSctpSession) customData;
    UINT64 elapsedMs;
    BOOL locked = FALSE;
    PSctpContext pSctpContext = acquireSctpContext();
    CHK_WARN(ATOMIC_LOAD_BOOL(&pSctpContext->isSctpInitialized), STATUS_NULL_ARG, "SCTP context not initialized, cannot run timer callback");

    CHK(pSctpSession != NULL, STATUS_NULL_ARG);
    CHK(ATOMIC_LOAD(&pSctpSession->shutdownStatus) == SCTP_SESSION_ACTIVE, retStatus);
    MUTEX_LOCK(pSctpContext->sctpContextLock);
    locked = TRUE;

    elapsedMs = (currentTime - pSctpContext->lastTickTime) / HUNDREDS_OF_NANOS_IN_A_MILLISECOND;
    pSctpContext->lastTickTime = currentTime;
    usrsctp_handle_timers((UINT32) elapsedMs);

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pSctpContext->sctpContextLock);
    }
    releaseSctpContext(pSctpContext);
    CHK_LOG_ERR(retStatus);

    return retStatus;
}

STATUS handleDcepPacket(PSctpSession pSctpSession, UINT32 streamId, PBYTE data, SIZE_T length)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT16 labelLength = 0;
    UINT16 protocolLength = 0;
    UINT32 reliabilityParameter = 0;
    BYTE reliabilityType = 0;
    RtcDataChannelInit rtcDataChannelInit;
    struct sctp_sendv_spa ackSpa;
    BYTE ackPacket = DCEP_DATA_CHANNEL_ACK;

    CHK(pSctpSession != NULL && pSctpSession->socket != NULL && data != NULL, STATUS_NULL_ARG);

    // Assert that is DCEP of type DataChannelOpen
    CHK(length > SCTP_DCEP_HEADER_LENGTH && data[0] == DCEP_DATA_CHANNEL_OPEN, STATUS_SUCCESS);

    MEMCPY(&labelLength, data + 8, SIZEOF(UINT16));
    MEMCPY(&protocolLength, data + 10, SIZEOF(UINT16));
    putInt16((PINT16) &labelLength, labelLength);
    putInt16((PINT16) &protocolLength, protocolLength);

    CHK((labelLength + protocolLength + SCTP_DCEP_HEADER_LENGTH) <= length, STATUS_SCTP_INVALID_DCEP_PACKET);

    CHK(SCTP_MAX_ALLOWABLE_PACKET_LENGTH >= length, STATUS_SCTP_INVALID_DCEP_PACKET);

    MEMSET(&rtcDataChannelInit, 0x00, SIZEOF(RtcDataChannelInit));
    rtcDataChannelInit.ordered = (data[1] & DCEP_DATA_CHANNEL_RELIABLE_UNORDERED) == 0;
    NULLABLE_SET_EMPTY(rtcDataChannelInit.maxPacketLifeTime);
    NULLABLE_SET_EMPTY(rtcDataChannelInit.maxRetransmits);
    reliabilityType = data[1] & ~DCEP_DATA_CHANNEL_RELIABLE_UNORDERED;
    CHK(reliabilityType == DCEP_DATA_CHANNEL_RELIABLE_ORDERED || reliabilityType == DCEP_DATA_CHANNEL_REXMIT ||
            reliabilityType == DCEP_DATA_CHANNEL_TIMED,
        STATUS_SCTP_INVALID_DCEP_PACKET);
    reliabilityParameter = getUnalignedInt32BigEndian((PINT32) (data + SIZEOF(UINT32)));
    reliabilityParameter = reliabilityParameter > MAX_UINT16 ? MAX_UINT16 : reliabilityParameter;
    if (reliabilityType == DCEP_DATA_CHANNEL_REXMIT) {
        NULLABLE_SET_VALUE(rtcDataChannelInit.maxRetransmits, (UINT16) reliabilityParameter);
    } else if (reliabilityType == DCEP_DATA_CHANNEL_TIMED) {
        NULLABLE_SET_VALUE(rtcDataChannelInit.maxPacketLifeTime, (UINT16) reliabilityParameter);
    }

    // Send DATA_CHANNEL_ACK (RFC 8832 Section 5.2) back on the same stream
    // https://datatracker.ietf.org/doc/html/rfc8832#name-data_channel_ack-message
    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |  Message Type |
    //  +-+-+-+-+-+-+-+-+
    MEMSET(&ackSpa, 0x00, SIZEOF(struct sctp_sendv_spa));
    ackSpa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
    ackSpa.sendv_sndinfo.snd_sid = streamId;
    putInt32((PINT32) &ackSpa.sendv_sndinfo.snd_ppid, SCTP_PPID_DCEP);

    DLOGD("Sending DATA_CHANNEL_ACK back to same stream (%u)", streamId);
    CHK(usrsctp_sendv(pSctpSession->socket, &ackPacket, 1, NULL, 0, &ackSpa, SIZEOF(ackSpa), SCTP_SENDV_SPA, 0) > 0, STATUS_SCTP_SENDV_FAILED);

    pSctpSession->sctpSessionCallbacks.dataChannelOpenFunc(pSctpSession->sctpSessionCallbacks.customData, streamId, data + SCTP_DCEP_HEADER_LENGTH,
                                                           labelLength, &rtcDataChannelInit);

CleanUp:

    CHK_LOG_ERR(retStatus);
    LEAVES();
    return retStatus;
}

STATUS handleSctpNotification(PSctpSession pSctpSession, PVOID data, ULONG length)
{
    STATUS retStatus = STATUS_SUCCESS;
    union sctp_notification* pNotification = (union sctp_notification*) data;
    RtcSctpEvent event;
    UINT32 notificationLength;

    CHK(pSctpSession != NULL && data != NULL, STATUS_NULL_ARG);
    CHK(length >= SIZEOF(pNotification->sn_header), STATUS_SCTP_INVALID_NOTIFICATION);
    notificationLength = pNotification->sn_header.sn_length;
    CHK(notificationLength >= SIZEOF(pNotification->sn_header) && notificationLength <= length, STATUS_SCTP_INVALID_NOTIFICATION);

    MEMSET(&event, 0, SIZEOF(event));
    event.version = RTC_SCTP_EVENT_CURRENT_VERSION;
    event.type = RTC_SCTP_EVENT_UNKNOWN;
    event.notificationType = pNotification->sn_header.sn_type;
    event.flags = pNotification->sn_header.sn_flags;

    switch (pNotification->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            CHK(notificationLength >= SIZEOF(struct sctp_assoc_change), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_ASSOCIATION_CHANGE;
            event.state = pNotification->sn_assoc_change.sac_state;
            event.errorCode = pNotification->sn_assoc_change.sac_error;
            event.associationId = pNotification->sn_assoc_change.sac_assoc_id;
            event.outboundStreams = pNotification->sn_assoc_change.sac_outbound_streams;
            event.inboundStreams = pNotification->sn_assoc_change.sac_inbound_streams;
            break;
        case SCTP_PEER_ADDR_CHANGE:
            CHK(notificationLength >= SIZEOF(struct sctp_paddr_change), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_PEER_ADDRESS_CHANGE;
            event.state = pNotification->sn_paddr_change.spc_state;
            event.errorCode = pNotification->sn_paddr_change.spc_error;
            event.associationId = pNotification->sn_paddr_change.spc_assoc_id;
            break;
        case SCTP_REMOTE_ERROR:
            CHK(notificationLength >= SIZEOF(struct sctp_remote_error), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_REMOTE_ERROR;
            event.errorCode = pNotification->sn_remote_error.sre_error;
            event.associationId = pNotification->sn_remote_error.sre_assoc_id;
            break;
        case SCTP_SEND_FAILED_EVENT:
            CHK(notificationLength >= SIZEOF(struct sctp_send_failed_event), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_SEND_FAILED;
            event.errorCode = pNotification->sn_send_failed_event.ssfe_error;
            event.associationId = pNotification->sn_send_failed_event.ssfe_assoc_id;
            event.streamId = pNotification->sn_send_failed_event.ssfe_info.snd_sid;
            break;
        case SCTP_SHUTDOWN_EVENT:
            CHK(notificationLength >= SIZEOF(struct sctp_shutdown_event), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_SHUTDOWN;
            event.associationId = pNotification->sn_shutdown_event.sse_assoc_id;
            break;
        case SCTP_PARTIAL_DELIVERY_EVENT:
            CHK(notificationLength >= SIZEOF(struct sctp_pdapi_event), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_PARTIAL_DELIVERY;
            event.state = pNotification->sn_pdapi_event.pdapi_indication;
            event.associationId = pNotification->sn_pdapi_event.pdapi_assoc_id;
            event.streamId = (UINT16) pNotification->sn_pdapi_event.pdapi_stream;
            break;
        case SCTP_STREAM_RESET_EVENT:
            CHK(notificationLength >= SIZEOF(struct sctp_stream_reset_event), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_STREAM_RESET;
            event.associationId = pNotification->sn_strreset_event.strreset_assoc_id;
            if (notificationLength >= SIZEOF(struct sctp_stream_reset_event) + SIZEOF(UINT16)) {
                event.streamId = pNotification->sn_strreset_event.strreset_stream_list[0];
            }
            break;
        case SCTP_SENDER_DRY_EVENT:
            CHK(notificationLength >= SIZEOF(struct sctp_sender_dry_event), STATUS_SCTP_INVALID_NOTIFICATION);
            event.type = RTC_SCTP_EVENT_SENDER_DRY;
            event.associationId = pNotification->sn_sender_dry_event.sender_dry_assoc_id;
            break;
        default:
            break;
    }

    ATOMIC_INCREMENT(&pSctpSession->notifications);
    if (pSctpSession->sctpSessionCallbacks.eventFunc != NULL) {
        pSctpSession->sctpSessionCallbacks.eventFunc(pSctpSession->sctpSessionCallbacks.customData, &event);
    }

CleanUp:
    CHK_LOG_ERR(retStatus);
    return retStatus;
}

INT32 onSctpSendBufferAvailable(struct socket* socket, UINT32 availableBytes, PVOID arg)
{
    PSctpSession pSctpSession = (PSctpSession) arg;

    UNUSED_PARAM(socket);
    if (pSctpSession == NULL || ATOMIC_LOAD(&pSctpSession->shutdownStatus) != SCTP_SESSION_ACTIVE) {
        return 1;
    }

    ATOMIC_STORE(&pSctpSession->lastWritableBytes, availableBytes);
    if (availableBytes >= pSctpSession->writableThresholdBytes && ATOMIC_EXCHANGE_BOOL(&pSctpSession->sendBlocked, FALSE)) {
        ATOMIC_INCREMENT(&pSctpSession->writableCallbacks);
        if (pSctpSession->sctpSessionCallbacks.writableFunc != NULL) {
            pSctpSession->sctpSessionCallbacks.writableFunc(pSctpSession->sctpSessionCallbacks.customData, availableBytes);
        }
    }
    return 1;
}

STATUS sctpSessionGetMetrics(PSctpSession pSctpSession, PRtcSctpMetrics pMetrics)
{
    STATUS retStatus = STATUS_SUCCESS;
    struct sctp_status status;
    struct sctp_rtoinfo rtoInfo;
    struct sctp_assocparams associationParams;
    struct sctp_paddrparams pathParams;
    struct sctp_assoc_value associationValue;
    INT32 socketBufferSize = 0;
    INT32 events;
    socklen_t optionLength;

    CHK(pSctpSession != NULL && pSctpSession->socket != NULL && pMetrics != NULL, STATUS_NULL_ARG);

    MEMSET(pMetrics, 0, SIZEOF(*pMetrics));
    pMetrics->version = RTC_SCTP_METRICS_CURRENT_VERSION;
    pMetrics->timerIntervalMs = (UINT32) (pSctpSession->timerInterval / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);

    optionLength = SIZEOF(socketBufferSize);
    CHK(usrsctp_getsockopt(pSctpSession->socket, SOL_SOCKET, SO_SNDBUF, &socketBufferSize, &optionLength) == 0, STATUS_SCTP_GET_METRICS_FAILED);
    pMetrics->sendBufferBytes = (UINT32) socketBufferSize;

    socketBufferSize = 0;
    optionLength = SIZEOF(socketBufferSize);
    CHK(usrsctp_getsockopt(pSctpSession->socket, SOL_SOCKET, SO_RCVBUF, &socketBufferSize, &optionLength) == 0, STATUS_SCTP_GET_METRICS_FAILED);
    pMetrics->receiveBufferBytes = (UINT32) socketBufferSize;

    MEMSET(&status, 0, SIZEOF(status));
    optionLength = SIZEOF(status);
    if (usrsctp_getsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_STATUS, &status, &optionLength) == 0) {
        pMetrics->associationState = (UINT32) status.sstat_state;
        pMetrics->peerReceiverWindowBytes = status.sstat_rwnd;
        pMetrics->congestionWindowBytes = status.sstat_primary.spinfo_cwnd;
        pMetrics->smoothedRttMs = status.sstat_primary.spinfo_srtt;
        pMetrics->retransmissionTimeoutMs = status.sstat_primary.spinfo_rto;
        pMetrics->pathMtu = status.sstat_primary.spinfo_mtu;
        pMetrics->fragmentationPointBytes = status.sstat_fragmentation_point;
        pMetrics->unacknowledgedDataChunks = status.sstat_unackdata;
        pMetrics->pendingDataChunks = status.sstat_penddata;
        pMetrics->inboundStreams = status.sstat_instrms;
        pMetrics->outboundStreams = status.sstat_outstrms;

        MEMSET(&pathParams, 0, SIZEOF(pathParams));
        pathParams.spp_assoc_id = status.sstat_assoc_id;
        MEMCPY(&pathParams.spp_address, &status.sstat_primary.spinfo_address, SIZEOF(pathParams.spp_address));
        optionLength = SIZEOF(pathParams);
        if (usrsctp_getsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &pathParams, &optionLength) == 0) {
            pMetrics->pathMaxRetransmits = pathParams.spp_pathmaxrxt;
        }
    }

    MEMSET(&rtoInfo, 0, SIZEOF(rtoInfo));
    optionLength = SIZEOF(rtoInfo);
    if (usrsctp_getsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_RTOINFO, &rtoInfo, &optionLength) == 0) {
        pMetrics->initialRtoMs = rtoInfo.srto_initial;
        pMetrics->minRtoMs = rtoInfo.srto_min;
        pMetrics->maxRtoMs = rtoInfo.srto_max;
    }

    MEMSET(&associationParams, 0, SIZEOF(associationParams));
    optionLength = SIZEOF(associationParams);
    if (usrsctp_getsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_ASSOCINFO, &associationParams, &optionLength) == 0) {
        pMetrics->associationMaxRetransmits = associationParams.sasoc_asocmaxrxt;
    }

    MEMSET(&associationValue, 0, SIZEOF(associationValue));
    optionLength = SIZEOF(associationValue);
    if (usrsctp_getsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_INTERLEAVING_SUPPORTED, &associationValue, &optionLength) == 0) {
        pMetrics->messageInterleaving = associationValue.assoc_value != 0;
    }

    MEMSET(&associationValue, 0, SIZEOF(associationValue));
    optionLength = SIZEOF(associationValue);
    if (usrsctp_getsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_PLUGGABLE_CC, &associationValue, &optionLength) == 0) {
        switch (associationValue.assoc_value) {
            case SCTP_CC_HSTCP:
                pMetrics->congestionControl = RTC_SCTP_CONGESTION_CONTROL_HSTCP;
                break;
            case SCTP_CC_HTCP:
                pMetrics->congestionControl = RTC_SCTP_CONGESTION_CONTROL_HTCP;
                break;
            case SCTP_CC_RTCC:
                pMetrics->congestionControl = RTC_SCTP_CONGESTION_CONTROL_RTCC;
                break;
            case SCTP_CC_RFC2581:
            default:
                pMetrics->congestionControl = RTC_SCTP_CONGESTION_CONTROL_RFC2581;
                break;
        }
    }

    MEMSET(&associationValue, 0, SIZEOF(associationValue));
    optionLength = SIZEOF(associationValue);
    if (usrsctp_getsockopt(pSctpSession->socket, IPPROTO_SCTP, SCTP_PLUGGABLE_SS, &associationValue, &optionLength) == 0) {
        switch (associationValue.assoc_value) {
            case SCTP_SS_ROUND_ROBIN:
                pMetrics->streamScheduler = RTC_SCTP_STREAM_SCHEDULER_ROUND_ROBIN;
                break;
            case SCTP_SS_ROUND_ROBIN_PACKET:
                pMetrics->streamScheduler = RTC_SCTP_STREAM_SCHEDULER_ROUND_ROBIN_PACKET;
                break;
            case SCTP_SS_PRIORITY:
                pMetrics->streamScheduler = RTC_SCTP_STREAM_SCHEDULER_PRIORITY;
                break;
            case SCTP_SS_FAIR_BANDWITH:
                pMetrics->streamScheduler = RTC_SCTP_STREAM_SCHEDULER_FAIR_BANDWIDTH;
                break;
            case SCTP_SS_FIRST_COME:
                pMetrics->streamScheduler = RTC_SCTP_STREAM_SCHEDULER_FIRST_COME;
                break;
            case SCTP_SS_DEFAULT:
            default:
                pMetrics->streamScheduler = RTC_SCTP_STREAM_SCHEDULER_DEFAULT;
                break;
        }
    }

    events = usrsctp_get_events(pSctpSession->socket);
    CHK(events >= 0, STATUS_SCTP_GET_METRICS_FAILED);
    pMetrics->socketWritable = (events & SCTP_EVENT_WRITE) != 0;
    pMetrics->sendBlocked = ATOMIC_LOAD_BOOL(&pSctpSession->sendBlocked);
    pMetrics->writableThresholdBytes = pSctpSession->writableThresholdBytes;
    pMetrics->lastWritableBytes = (UINT32) ATOMIC_LOAD(&pSctpSession->lastWritableBytes);
    pMetrics->sendCalls = (UINT64) ATOMIC_LOAD(&pSctpSession->sendCalls);
    pMetrics->sendFailures = (UINT64) ATOMIC_LOAD(&pSctpSession->sendFailures);
    pMetrics->blockedWrites = (UINT64) ATOMIC_LOAD(&pSctpSession->blockedWrites);
    pMetrics->writableCallbacks = (UINT64) ATOMIC_LOAD(&pSctpSession->writableCallbacks);
    pMetrics->notifications = (UINT64) ATOMIC_LOAD(&pSctpSession->notifications);
    pMetrics->lastSendErrno = (INT32) ATOMIC_LOAD(&pSctpSession->lastSendErrno);

CleanUp:
    CHK_LOG_ERR(retStatus);
    return retStatus;
}

INT32 onSctpInboundPacket(struct socket* sock, union sctp_sockstore addr, PVOID data, ULONG length, struct sctp_rcvinfo rcv, INT32 flags,
                          PVOID ulp_info)
{
    UNUSED_PARAM(sock);
    UNUSED_PARAM(addr);
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = (PSctpSession) ulp_info;
    BOOL isBinary = FALSE;

    if (data == NULL) {
        return 1;
    }
    CHK(pSctpSession != NULL, STATUS_NULL_ARG);
    if ((flags & MSG_NOTIFICATION) != 0) {
        CHK_STATUS(handleSctpNotification(pSctpSession, data, length));
        goto CleanUp;
    }

    rcv.rcv_ppid = ntohl(rcv.rcv_ppid);
    switch (rcv.rcv_ppid) {
        case SCTP_PPID_DCEP:
            CHK_STATUS(handleDcepPacket(pSctpSession, rcv.rcv_sid, data, length));
            break;
        case SCTP_PPID_BINARY:
        case SCTP_PPID_BINARY_EMPTY:
            isBinary = TRUE;
            // fallthrough
        case SCTP_PPID_STRING:
        case SCTP_PPID_STRING_EMPTY:
            pSctpSession->sctpSessionCallbacks.dataChannelMessageFunc(pSctpSession->sctpSessionCallbacks.customData, rcv.rcv_sid, isBinary, data,
                                                                      length);
            break;
        default:
            DLOGI("Unhandled PPID on incoming SCTP message %d", rcv.rcv_ppid);
            break;
    }

CleanUp:

    /*
     * IMPORTANT!!! The allocation is done in the sctp library using default allocator
     * so we need to use the default free API.
     */
    if (data != NULL) {
        free(data);
    }
    if (STATUS_FAILED(retStatus)) {
        return -1;
    }
    return 1;
}
