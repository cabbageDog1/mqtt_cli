/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/net.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "services/atlas_services.h"
#include "infra_timer.h"

#if (defined(__linux__) || defined(__APPLE__))
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "wrappers_defs.h"
#include "cniot_atlas_wrapper.h"
#include "logger/atlas_logger.h"
#include "report/atlas_report.h"
#ifndef CONFIG_MBEDTLS_DEBUG_LEVEL
    #define CONFIG_MBEDTLS_DEBUG_LEVEL 0
#endif

typedef struct _TLSDataParams {
    mbedtls_net_context fd;           /**< mbed TLS network context. */
    mbedtls_ssl_context *ssl;          /**< mbed TLS control context. */
    mbedtls_ssl_config *conf;          /**< mbed TLS configuration context. */
    mbedtls_pk_context *pkey;          /**< mbed TLS Client key. */
    void               *ssl_lock;
} TLSDataParams_t, *TLSDataParams_pt;

static unsigned int mbedtls_mem_used = 0;
static unsigned int mbedtls_max_mem_used = 0;
static char *g_module = {"TLS"};

#define MBEDTLS_MEM_INFO_MAGIC   0x12345678

#ifndef LWIP_SO_SNDRCVTIMEO_NONSTANDARD
#define LWIP_SO_SNDRCVTIMEO_NONSTANDARD 0
#endif

typedef struct {
    int magic;
    int size;
} mbedtls_mem_info_t;

static void TLSDataParams_free(TLSDataParams_t *p) {
    if (p) {
        if (p->ssl) {
            atlas_free(p->ssl);
            p->ssl = NULL;
        }
        if (p->conf) {
            atlas_free(p->conf);
            p->conf = NULL;
        }
        if (p->pkey) {
            atlas_free(p->pkey);
            p->pkey = NULL;
        }
        if (p->ssl_lock) {
            atlas_mutex_destroy(p->ssl_lock);
            p->ssl_lock = NULL;
        }
        atlas_free(p);
    }
}
static TLSDataParams_t *TLSDataParams_new() {
    TLSDataParams_t *p = NULL;
    p = atlas_malloc(sizeof(TLSDataParams_t));
    if (NULL == p) {
        return NULL;
    }

    memset(p, 0, sizeof(TLSDataParams_t));

    p->ssl = atlas_malloc(sizeof(mbedtls_ssl_context));
    if (NULL == p->ssl) {
        TLSDataParams_free(p);
        return NULL;
    }
    p->pkey = atlas_malloc(sizeof(mbedtls_pk_context));
    if (NULL == p->pkey) {
        TLSDataParams_free(p);
        return NULL;
    }
    p->conf = atlas_malloc(sizeof(mbedtls_ssl_config));
    if (NULL == p->conf) {
        TLSDataParams_free(p);
        return NULL;
    }

    p->ssl_lock = atlas_mutex_create();
    if (NULL == p->ssl_lock) {
        TLSDataParams_free(p);
        return NULL;
    }

    return p;
}
static unsigned int _avRandom()
{
    return (((unsigned int)rand() << 16) + rand());
}

static int _ssl_random(void *p_rng, unsigned char *output, size_t output_len)
{
    uint32_t rnglen = output_len;
    uint8_t   rngoffset = 0;

    while (rnglen > 0) {
        *(output + rngoffset) = (unsigned char)_avRandom() ;
        rngoffset++;
        rnglen--;
    }
    return 0;
}

static void _ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);
    if (NULL != ctx) {
        printf("%s\n", str);
    }
}

static int _real_confirm(int verify_result)
{
    printf("certificate verification result: 0x%02x\n", verify_result);

    return 0;
}

static int _ssl_client_init(mbedtls_ssl_context *ssl,
                            mbedtls_net_context *tcp_fd,
                            mbedtls_ssl_config *conf,
                            mbedtls_x509_crt *crt509_ca, const char *ca_crt, size_t ca_len,
                            mbedtls_x509_crt *crt509_cli, const char *cli_crt, size_t cli_len,
                            mbedtls_pk_context *pk_cli, const char *cli_key, size_t key_len,  const char *cli_pwd, size_t pwd_len
                           )
{
    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_debug_set_threshold((int)CONFIG_MBEDTLS_DEBUG_LEVEL);
    mbedtls_net_init(tcp_fd);
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_pk_init(pk_cli);

    return 0;
}
void *_SSLCalloc_wrapper(size_t n, size_t size)
{
    unsigned char *buf = NULL;
    if (n == 0 || size == 0) {
        return NULL;
    }

    buf = (unsigned char *)(atlas_malloc((n * size) ));
    if (NULL != buf) {
        memset(buf, 0, n * size );
    }

    return buf;
}
void _SSLFree_wrapper(void *ptr)
{
    if (NULL == ptr) {
        return;
    }
    atlas_free(ptr);
}

static int net_would_block( const mbedtls_net_context *ctx )
{
    /*
     * Never return 'WOULD BLOCK' on a non-blocking socket
     */
    //if( ( fcntl( ctx->fd, F_GETFL ) & O_NONBLOCK ) != O_NONBLOCK )
    //    return( 0 );

    switch( errno )
    {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
            return( 1 );
    }
    return( 0 );
}


int atlas_mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
{
    int ret;
    int fd = ((mbedtls_net_context *) ctx)->fd;
    TLSDataParams_t * tlsDataParams = (TLSDataParams_t *)ctx;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );

    atlas_mutex_lock(tlsDataParams->ssl_lock);
    ret = (int) read( fd, buf, len );
    atlas_mutex_unlock(tlsDataParams->ssl_lock);

    if( ret < 0 )
    {
        if( net_would_block( ctx ) != 0 )
            return( MBEDTLS_ERR_SSL_WANT_READ );

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );
#else
        if( errno == EPIPE || errno == ECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_READ );
#endif

        return( MBEDTLS_ERR_NET_RECV_FAILED );
    }

    return( ret );
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int atlas_net_recv_timeout( void *ctx, unsigned char *buf, size_t len, uint32_t timeout )
{
    int ret;
    struct timeval tv;
    fd_set read_fds;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if( fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );


    FD_ZERO( &read_fds );
    FD_SET( fd, &read_fds );

    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = ( timeout % 1000 ) * 1000;

    ret = select( fd + 1, &read_fds, NULL, NULL, timeout == 0 ? NULL : &tv );

    /* Zero fds ready means we timed out */
    if( ret == 0 )
        return( MBEDTLS_ERR_SSL_TIMEOUT );

    if( ret < 0 )
    {
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
        if( WSAGetLastError() == WSAEINTR )
            return( MBEDTLS_ERR_SSL_WANT_READ );
#else
        if( errno == EINTR )
            return( MBEDTLS_ERR_SSL_WANT_READ );
#endif

        return( MBEDTLS_ERR_NET_RECV_FAILED );
    }

    /* This call will not block */
    return( atlas_mbedtls_net_recv( ctx, buf, len ) );
}

static int net_prepare( void )
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
    WSADATA wsaData;

    if( wsa_init_done == 0 )
    {
        if( WSAStartup( MAKEWORD(2,0), &wsaData ) != 0 )
            return( MBEDTLS_ERR_NET_SOCKET_FAILED );

        wsa_init_done = 1;
    }
#else
#if !defined(EFIX64) && !defined(EFI32)
    signal( SIGPIPE, SIG_IGN );
#endif
#endif
    return( 0 );
}

static int mbedtls_net_connect_timeout(mbedtls_net_context *ctx, const char *host,
                                       const char *port, int proto, uint16_t flag, unsigned int timeout)
{
    int ret;
    int enable = 1;
    struct addrinfo hints, *addr_list, *cur;
    struct timeval sendtimeout;
    char msg[128] = {0};
    char str[INET_ADDRSTRLEN];   //INET_ADDRSTRLEN这个宏系统默认定义 16
    int ipo_high = 0xa0;
    uint64_t start = atlas_boot_uptime(), end = 0;

    if ((ret = net_prepare()) != 0) {
        return (ret);
    }

    /* Do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if( getaddrinfo( host, port, &hints, &addr_list ) != 0 ) {
        end = atlas_boot_uptime();
        atlas_snprintf(msg, 128, "parse %s failed cost=%d", host, (uint32_t)(end -start));
        cniot_atlas_post_core_event(CNIOT_DNS_RESOLVER_FAILED, msg);
        return( MBEDTLS_ERR_NET_UNKNOWN_HOST );
    } else {
        end = atlas_boot_uptime();
        atlas_snprintf(msg, 128, "parse %s success cost=%d", host, (uint32_t)(end -start));
        cniot_atlas_post_core_event(CNIOT_DNS_RESOLVER_SUCCESS, msg);
    }

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        if (start + timeout  <= atlas_boot_uptime()) {
            atlas_snprintf(msg, 128, "connect %s timeout=%d ms ", host, (uint32_t)(timeout));
            cniot_atlas_post_core_event(CNIOT_TCP_CONNECT_TIMEOUT, msg);
            break;
        }

        ctx->fd = (int) socket(cur->ai_family, cur->ai_socktype,
                               cur->ai_protocol);
        if (ctx->fd < 0) {
            atlas_snprintf(msg, 128, "open %s tcp socket failed ", host);
            cniot_atlas_post_core_event(CNIOT_TCP_OPEN_SOCKET_FAILED, msg);
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        enable = 1;
        ret = setsockopt(ctx->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
        if (ret < 0) {
            printf("[error] tcp %d set no delay failed\n", ctx->fd);
            //continue;
        }
#if defined(LWIP_SO_SNDRCVTIMEO_NONSTANDARD) && (LWIP_SO_SNDRCVTIMEO_NONSTANDARD == 0)
        sendtimeout.tv_sec = timeout / 1000;
        sendtimeout.tv_usec = (timeout % 1000) * 1000;
        logger_info("setsockopt %d connect timeval timeout: %d\n", ctx->fd, (int)sendtimeout.tv_sec);
        if (0 != setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &sendtimeout, sizeof(sendtimeout))) {
            atlas_snprintf(msg, 128, "set %s socket timeout opt failed ", host);
            cniot_atlas_post_core_event(CNIOT_TCP_SET_SOCKET_OPT_FAILED, msg);
            printf("mbedtls setsockopt timeval error\n");
        }
#else
        if (0 != setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
            printf("mbedtls setsockopt int error\n");
        }
        printf("setsockopt %d connect int timeout: %d\n", ctx->fd, timeout);
        if (1 == (flag & 0x01)) {
            if (setsockopt(ctx->fd, IPPROTO_IP, IP_TOS, &ipo_high, sizeof(ipo_high))) {
                printf("setsockopt IPPROTO_IP failed\n");
            }
            printf("set socket %d IP_TOS high_level\n", ctx->fd);
        }
#endif


        struct sockaddr_in *sock = (struct sockaddr_in*)(cur->ai_addr);
        struct in_addr in  = sock->sin_addr;
        inet_ntop(AF_INET,&in, str, sizeof(str));
        if (connect(ctx->fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            atlas_snprintf(msg, 128, "connect to %s success,server ip=%s ", host, str);
            cniot_atlas_post_core_event(CNIOT_TCP_CONNECT_SOCKET_SUCCESS, msg);
            cniot_atlas_dns_resolver(host, 0, inet_addr(str)); //
            ret = 0;
            break;
        }

        atlas_snprintf(msg, 128, "connect to %s failed, server ip=%s ", host, str);
        cniot_atlas_post_core_event(CNIOT_TCP_CONNECT_SOCKET_FAILED, msg);
        close(ctx->fd);
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo(addr_list);
    return (ret);
}

static int _TLSConnectNetwork(TLSDataParams_t *pTlsData, const char *addr, const char *port,
                              const char *ca_crt, size_t ca_crt_len,
                              const char *client_crt,   size_t client_crt_len,
                              const char *client_key,   size_t client_key_len,
                              const char *client_pwd, size_t client_pwd_len,
                              uint16_t flag)
{
    int ret = -1;
    char msg[128] = {0};
    void *fdTest = NULL;
    uint64_t handshake_start = 0, handshake_end = 0;
    /*
     * 0. Init
     */
    if (0 != (ret = _ssl_client_init((pTlsData->ssl), &(pTlsData->fd), (pTlsData->conf),
                                     (NULL), ca_crt, ca_crt_len,
                                     (NULL), client_crt, client_crt_len,
                                     (pTlsData->pkey), client_key, client_key_len, client_pwd, client_pwd_len))) {
        logger_err(" failed ! ssl_client_init returned -0x%04x\n", -ret);
        return ret;
    }

    /*
     * 1. Start the connection
     */
    logger_debug("Connecting to /%s/%s...\n", addr, port);
    if (0 != (ret = mbedtls_net_connect_timeout(&(pTlsData->fd), addr, port, MBEDTLS_NET_PROTO_TCP, flag, 6000))) {
        logger_err(" failed ! net_connect returned -0x%04x\n", -ret);
        cniot_atlas_dns_resolver(addr, -ret, 0);
        return ret;
    }

    cniot_atlas_dns_resolver(addr, 0, 0); // 获取不到地址信息...

    logger_debug("ok ssl fd=%d fd=%p\n", pTlsData->fd.fd, &pTlsData->fd);

    mbedtls_ssl_set_bio((pTlsData->ssl), &(pTlsData->fd), mbedtls_net_send, atlas_mbedtls_net_recv, atlas_net_recv_timeout);
    /*
     * 2. Setup stuff
     */
    logger_debug("  . Setting up the SSL/TLS structure...\n");
    if ((ret = mbedtls_ssl_config_defaults((pTlsData->conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        logger_err(" failed! mbedtls_ssl_config_defaults returned %d\n", ret);
        return ret;
    }

    mbedtls_ssl_conf_authmode((pTlsData->conf), MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng((pTlsData->conf), _ssl_random, NULL);
    mbedtls_ssl_conf_dbg(pTlsData->conf, _ssl_debug, stdout);

    if ((ret = mbedtls_ssl_setup((pTlsData->ssl), (pTlsData->conf))) != 0) {
        logger_err("failed! mbedtls_ssl_setup returned %d\n", ret);
        return ret;
    }
    mbedtls_ssl_set_hostname((pTlsData->ssl), addr);

    /*
    * 4. Handshake
    */
    mbedtls_ssl_conf_read_timeout((pTlsData->conf), 6000);
    logger_debug("Performing the SSL/TLS handshake...\n");

    handshake_start = atlas_boot_uptime();
    while ((ret = mbedtls_ssl_handshake((pTlsData->ssl))) != 0) {
        if ((ret != MBEDTLS_ERR_SSL_WANT_READ) && (ret != MBEDTLS_ERR_SSL_WANT_WRITE)) {
            handshake_end = atlas_boot_uptime();
            logger_err("failed ! mbedtls_ssl_handshake returned -0x%04x\n", -ret);
            atlas_snprintf(msg, 128, "host=%s handshake failed cost=%d ret=%x", addr, handshake_end - handshake_start, -ret);
            cniot_atlas_post_core_event(CNIOT_TSL_HANDSHAKE_FAILED, msg);
            return ret;
        }
    }
    handshake_end = atlas_boot_uptime();
    atlas_snprintf(msg, 128, "host(%s) tls handshake success cost=%d", addr, handshake_end - handshake_start);
    cniot_atlas_post_core_event(CNIOT_TSL_HANDSHAKE_SUCCESS, msg);

    logger_info("TLS handshake success cost %d ms\n", (int)(handshake_end - handshake_start));
    logger_debug("TLS SUCCESS\n");

    //mbedtls_net_set_nonblock(&(pTlsData->fd));

    return 0;

}
static int _network_ssl_select(int fd, int timeout_ms) {
    struct timeval tv;
    fd_set read_fds;

    if ( fd < 0 ) {
        return  -1 ;
    }
    printf("select fd=%d timeout=%d\n", fd, timeout_ms);

    FD_ZERO( &read_fds );
    FD_SET( fd, &read_fds );

    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = ( timeout_ms % 1000 ) * 1000;

    return select( fd + 1, &read_fds, NULL, NULL, timeout_ms == 0 ? NULL : &tv );
}

static int _network_ssl_read(TLSDataParams_t *pTlsData, char *buffer, int len, int timeout_ms)
{
    uint32_t        readLen = 0;
    static int      net_status = 0;
    int             ret = -1;
    char            err_str[33];

    mbedtls_ssl_conf_read_timeout((pTlsData->conf), timeout_ms);
    while (readLen < len) {
        ret = mbedtls_ssl_read((pTlsData->ssl), (unsigned char *)(buffer + readLen), (len - readLen));
        if (ret > 0) {
            readLen += ret;
            net_status = 0;
        } else if (ret == 0) {
            /* if ret is 0 and net_status is -2, indicate the connection is closed during last call */
            return (net_status == -2) ? net_status : readLen;
        } else {
            if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ret) {
                mbedtls_strerror(ret, err_str, sizeof(err_str));
                logger_err("ssl recv error: code = %d, err_str = '%s'\n", ret, err_str);
                net_status = -2; /* connection is closed */
                break;
            } else if ((MBEDTLS_ERR_SSL_TIMEOUT == ret)
                       || (MBEDTLS_ERR_SSL_CONN_EOF == ret)
                       || (MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED == ret)
                       || (MBEDTLS_ERR_SSL_NON_FATAL == ret)) {
                /* read already complete */
                /* if call mbedtls_ssl_read again, it will return 0 (means EOF) */

                return readLen;
            } else {
                mbedtls_strerror(ret, err_str, sizeof(err_str));
                logger_err("ssl recv error: code = %d, err_str = '%s'\n", ret, err_str);
                net_status = -1;
                return -1; /* Connection error */
            }
        }
    }

    return (readLen > 0) ? readLen : net_status;
}

static int _network_ssl_write(TLSDataParams_t *pTlsData, const char *buffer, int len, int timeout_ms)
{
#if 1
    uint32_t writtenLen = 0;
    uint64_t start = 0, mid = 0, end = 0;
    int ret = -1;
    int write_once_len = 1024;
    char msg[128] = {0};
    int time_out_once = 3500;
    struct timeval timeout;
    iotx_time_t timer;

    if (pTlsData == NULL) {
        return -1;
    }

    iotx_time_init(&timer);
    utils_time_countdown_ms(&timer, timeout_ms);

    while (writtenLen < len && !utils_time_is_expired(&timer)) {
        atlas_mutex_lock(pTlsData->ssl_lock);
        start = atlas_boot_uptime();
        write_once_len = 1024;
        /* timeout */
#if defined(LWIP_SO_SNDRCVTIMEO_NONSTANDARD) && (LWIP_SO_SNDRCVTIMEO_NONSTANDARD == 0)
        timeout.tv_sec = time_out_once / 1000;
        timeout.tv_usec = (time_out_once % 1000) * 1000;
        if (setsockopt(pTlsData->fd.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ) {
            printf("setsockopt timeval failed\n");
        }
#else
        if (setsockopt(pTlsData->fd.fd, SOL_SOCKET, SO_SNDTIMEO, &time_out_once, sizeof(int))) {
            printf("setsockopt int failed\n");
        }
#endif
        if (write_once_len > len - writtenLen) {
            write_once_len = len - writtenLen;
        }
        mid = atlas_boot_uptime();
        ret = mbedtls_ssl_write((pTlsData->ssl), (unsigned char *)(buffer + writtenLen), write_once_len);
        end = atlas_boot_uptime();

        if (start + 1000 < end) {
            printf("--->> tcp send %d bytes cost %d ms  ret=%d\n",  write_once_len,  (uint32_t)(end - start), ret);
            atlas_snprintf(msg, 128, "send %d ret=%d cost=%d",  write_once_len, ret,  (uint32_t)(end - start));
#if  defined(FREELINK_TCP_TRACE_LOG) && (FREELINK_TCP_TRACE_LOG == 1)
            extern void freelink_altas_sta_trace_log(uint32_t start,uint32_t mid ,uint32_t end);
            freelink_altas_sta_trace_log(start,mid,end);
#endif
            cniot_atlas_post_core_event(CNIOT_TCP_SEND_TIMEOUT, msg);
        }
        atlas_mutex_unlock(pTlsData->ssl_lock);
        if (ret > 0) {
            writtenLen += ret;
            continue;
        } else if (ret == 0) {
            logger_err("ssl write timeout\n");
        } else {
            char err_str[33];
            mbedtls_strerror(ret, err_str, sizeof(err_str));
            logger_err("ssl write fail, code=%d, str=%s\n", ret, err_str);
            return -1; /* Connnection error */
        }
    }
    return writtenLen;
#else
    int32_t res = 0;
    int32_t write_bytes = 0;
    uint64_t timestart_ms = 0, timenow_ms = 0;
    struct timeval timeout;

    if (pTlsData == NULL) {
        return -1;
    }

    if (timeout_ms < 3000) {
        timeout_ms = 3000;
    }

    /* timeout */
    timeout.tv_sec = timeout_ms/1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    /* Start Time */
    timestart_ms = atlas_boot_uptime();
    atlas_mutex_lock(pTlsData->ssl_lock);
    res = setsockopt(pTlsData->fd.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    atlas_mutex_unlock(pTlsData->ssl_lock);
    if (res < 0) {
        return -1;
    }
    do {
        timenow_ms = atlas_boot_uptime();
        if (timenow_ms - timestart_ms >= timeout_ms) {
            break;
        }
        atlas_mutex_lock(pTlsData->ssl_lock);
        res = mbedtls_ssl_write(pTlsData->ssl, (unsigned char *)buffer + write_bytes, len - write_bytes);
        atlas_mutex_unlock(pTlsData->ssl_lock);
        if (res < 0) {
            if (res != MBEDTLS_ERR_SSL_WANT_READ &&
                res != MBEDTLS_ERR_SSL_WANT_WRITE) {
                if (write_bytes == 0) {
                    return -1;
                }
                break;
            }
        }else if (res == 0) {
            break;
        }else{
            write_bytes += res;
        }
    }while(((timenow_ms - timestart_ms) < timeout_ms) && (write_bytes < len));

    return write_bytes;
#endif
}

static void _network_ssl_disconnect(TLSDataParams_t *pTlsData)
{
//    mbedtls_ssl_close_notify((pTlsData->ssl));
    mbedtls_net_free(&(pTlsData->fd));
    mbedtls_ssl_free((pTlsData->ssl));
    mbedtls_ssl_config_free((pTlsData->conf));
    logger_info("ssl disconnect\n");
}

int HAL_SSL_Read(uintptr_t handle, char *buf, int len, int timeout_ms)
{
    return _network_ssl_read((TLSDataParams_t *)handle, buf, len, timeout_ms);;
}

int HAL_SSL_Write(uintptr_t handle, const char *buf, int len, int timeout_ms)
{
    return _network_ssl_write((TLSDataParams_t *)handle, buf, len, timeout_ms);
}

int32_t HAL_SSL_Destroy(uintptr_t handle)
{
    if ((uintptr_t)-1 == handle) {
        logger_debug("handle is NULL\n");
        return 0;
    }

    _network_ssl_disconnect((TLSDataParams_t *)handle);
    TLSDataParams_free((TLSDataParams_t *)handle);
    return 0;
}

int ssl_hooks_set(ssl_hooks_t *hooks)
{
    if (hooks == NULL || hooks->malloc == NULL || hooks->free == NULL) {
        return -1;
    }

    return 0;
}

uintptr_t HAL_SSL_Establish(const char *host, uint16_t port, const char *ca_crt, uint32_t ca_crt_len, uint16_t flag)
{
    char                port_str[6];
    const char         *alter = host;
    TLSDataParams_pt    pTlsData;

    if (host == NULL || ca_crt == NULL) {
        logger_err("input params are NULL, abort\n");
        return (uintptr_t)(-1);
    }

    if (!strlen(host) || (strlen(host) < 8)) {
        logger_err("invalid host: '%s'(len=%d), abort\n", host, (int)strlen(host));
        return (uintptr_t)(-1);
    }

    pTlsData = TLSDataParams_new();
    if (NULL == pTlsData) {
        return (uintptr_t)(-1);
    }
    atlas_snprintf(port_str, 6,"%u", port);

    mbedtls_platform_set_calloc_free(_SSLCalloc_wrapper, _SSLFree_wrapper);
    if (0 != _TLSConnectNetwork(pTlsData, alter, port_str, ca_crt, ca_crt_len, NULL, 0, NULL, 0, NULL, 0, flag)) {
        _network_ssl_disconnect(pTlsData);
        TLSDataParams_free(pTlsData);
        return (uintptr_t)(-1);
    }

    return (uintptr_t)pTlsData;
}

