/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include "cniot_atlas_wrapper.h"
#include "logger/atlas_logger.h"
#include "report/atlas_report.h"

static char * g_module = {"TCP"};

static uint64_t _linux_time_left(uint64_t t_end, uint64_t t_now)
{
    uint64_t t_left;

    if (t_end > t_now) {
        t_left = t_end - t_now;
    } else {
        t_left = 0;
    }

    return t_left;
}

uintptr_t atlas_tcp_enstablish(const char *host, uint16_t port, uint16_t flag)
{
    struct addrinfo hints;
    struct addrinfo *addrInfoList = NULL;
    struct addrinfo *cur = NULL;
    struct sockaddr_in *  pSin  =  NULL;
    int fd = 0;
    int rc = 0;
    char service[6];
    uint8_t dns_retry = 0;

    memset(&hints, 0, sizeof(hints));

    logger_debug("establish tcp connection with server(host='%s', port=[%d])\n", host, port);

    hints.ai_family = AF_INET; /* only IPv4 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    sprintf(service, "%d", port);

    while(dns_retry++ < 3) {
        rc = getaddrinfo(host, service, &hints, &addrInfoList);
        if (rc != 0) {
            cniot_atlas_dns_resolver(host, rc , 0);
            logger_err("getaddrinfo error[%d], res: %s, host: %s, port: %s\n", dns_retry, gai_strerror(rc), host, service);
            atlas_usleep(100);
            continue;
        }else{
            break;
        }
    }

    if (rc != 0) {
        logger_err("getaddrinfo error(%d), host = '%s', port = [%d]\n", rc, host, port);
        return (uintptr_t)(-1);
    }

    for (cur = addrInfoList; cur != NULL; cur = cur->ai_next) {
        if (cur->ai_family != AF_INET) {
            logger_err("socket type error\n");
            rc = -1;
            continue;
        }

        fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            logger_err("create socket error\n");
            rc = -1;
            continue;
        }

        if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            pSin  =  (struct sockaddr_in * )(cur->ai_addr);
            cniot_atlas_dns_resolver(host, 0 , pSin->sin_addr.s_addr);
            rc = fd;
            break;
        }

        close(fd);
        logger_err("connect error\n");
        rc = -1;
    }

    if (-1 == rc) {
        logger_err("fail to establish tcp\n");
    } else {
        logger_info("success to establish tcp, fd=%d\n", rc);
    }
    freeaddrinfo(addrInfoList);

    return (uintptr_t)rc;
}

int HAL_TCP_Destroy(uintptr_t fd)
{
    int rc;

    /* Shutdown both send and receive operations. */
    rc = shutdown((int) fd, 2);
    if (0 != rc) {
        //logger_err("shutdown error\n");
        return -1;
    }

    rc = close((int) fd);
    if (0 != rc) {
        logger_err("closesocket error\n");
        return -1;
    }

    return 0;
}

int32_t atlas_tcp_write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms)
{
    int ret,tcp_fd;
    uint32_t len_sent;
    uint64_t t_end, t_left;
    fd_set sets;
    int net_err = 0;

    t_end = atlas_boot_uptime() + timeout_ms;
    len_sent = 0;
    ret = 1; /* send one time if timeout_ms is value 0 */

    if (fd >= FD_SETSIZE) {
        return -1;
    }
    tcp_fd = (int)fd;

    do {
        t_left = _linux_time_left(t_end, atlas_boot_uptime());

        if (0 != t_left) {
            struct timeval timeout;

            FD_ZERO(&sets);
            FD_SET(tcp_fd, &sets);

            timeout.tv_sec = t_left / 1000;
            timeout.tv_usec = (t_left % 1000) * 1000;

            ret = select(tcp_fd + 1, NULL, &sets, NULL, &timeout);
            if (ret > 0) {
                if (0 == FD_ISSET(tcp_fd, &sets)) {
                    logger_err("Should NOT arrive\n");
                    /* If timeout in next loop, it will not sent any data */
                    ret = 0;
                    continue;
                }
            } else if (0 == ret) {
                logger_err("select-write timeout %d\n", tcp_fd);
                break;
            } else {
                if (EINTR == errno) {
                    logger_err("EINTR be caught\n");
                    continue;
                }

                logger_err("select-write fail, ret = select() = %d\n", ret);
                net_err = 1;
                break;
            }
        }

        if (ret > 0) {
            ret = send(tcp_fd, buf + len_sent, len - len_sent, 0);
            if (ret > 0) {
                len_sent += ret;
            } else if (0 == ret) {
                logger_err("No data be sent\n");
            } else {
                if (EINTR == errno) {
                    logger_err("EINTR be caught\n");
                    continue;
                }

                logger_err("send fail, ret = send() = %d\n", ret);
                net_err = 1;
                break;
            }
        }
    } while (!net_err && (len_sent < len) && (_linux_time_left(t_end, atlas_boot_uptime()) > 0));

    if (net_err) {
        return -1;
    } else {
        return len_sent;
    }
}

int32_t atlas_tcp_read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms)
{
    int ret, err_code, tcp_fd;
    uint32_t len_recv;
    uint64_t t_end, t_left;
    fd_set sets;
    struct timeval timeout;

    t_end = atlas_boot_uptime() + timeout_ms;
    len_recv = 0;
    err_code = 0;

    if (fd >= FD_SETSIZE) {
        return -1;
    }
    tcp_fd = (int)fd;

    do {
        t_left = _linux_time_left(t_end, atlas_boot_uptime());
        if (0 == t_left) {
            break;
        }
        FD_ZERO(&sets);
        FD_SET(tcp_fd, &sets);

        timeout.tv_sec = t_left / 1000;
        timeout.tv_usec = (t_left % 1000) * 1000;

        ret = select(tcp_fd + 1, &sets, NULL, NULL, &timeout);
        if (ret > 0) {
            ret = recv(tcp_fd, buf + len_recv, len - len_recv, 0);
            if (ret > 0) {
                len_recv += ret;
            } else if (0 == ret) {
                logger_info("connection is closed\n");
                err_code = -1;
                break;
            } else {
                if (EINTR == errno) {
                    continue;
                }
                logger_err("recv fail\n");
                err_code = -2;
                break;
            }
        } else if (0 == ret) {
            break;
        } else {
            if (EINTR == errno) {
                continue;
            }
            logger_err("select-recv fail\n");
            err_code = -2;
            break;
        }
    } while ((len_recv < len));

    /* priority to return data bytes if any data be received from TCP connection. */
    /* It will get error code on next calling */
    return (0 != len_recv) ? len_recv : err_code;
}
