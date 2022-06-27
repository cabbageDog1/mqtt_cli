#ifndef CNIOT_ATLAS_CNIOT_ATLAS_WRAPPER_H
#define CNIOT_ATLAS_CNIOT_ATLAS_WRAPPER_H

#if defined(__cplusplus)
extern "C" {
#endif
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "infra_types.h"

/**
 *  注意说明: 需要实现相应的接口..
 * */

typedef struct {
    char thread_name[64];
    int  thread_prio;
    int  stack_size;
}thread_parm_t;

void  *atlas_malloc(uint32_t size);

void  atlas_free(void *ptr);

void  *atlas_mutex_create(void);

void  atlas_mutex_destroy(void *);

void  atlas_mutex_lock(void *mutex);

void  atlas_mutex_unlock(void *mutex);

int   atlas_vsnprintf(char *str, const int len, const char *format, va_list ap);

int   atlas_snprintf(char *str, const int len, const char *fmt, ...);

int   atlas_thread_create(void **thread_handle, void *(*work_routine)(void *), void *arg, void *hal_os_thread_param,
                          int *stack_used);

void  atlas_thread_delete(void *thread_handle);

uint64_t atlas_boot_uptime();

uint64_t atlas_abs_time();

void  atlas_printf(const char *fmt, ...);

void  atlas_usleep(uint32_t ms);

intptr_t atlas_udp_create(char *host, unsigned short port);

void atlas_udp_close(intptr_t p_socket);

int atlas_udp_write(intptr_t p_socket, const unsigned char *p_data, unsigned int datalen);

int atlas_udp_select(intptr_t p_socket, unsigned int timeout);

int atlas_udp_read(intptr_t p_socket, unsigned char *p_data, unsigned int datalen);

int atlas_udp_read_timeout(intptr_t p_socket, unsigned char *p_data, unsigned int datalen, unsigned int timeout);

intptr_t atlas_udp_create_without_connect(const char *host, unsigned short port);

int atlas_udp_connect(intptr_t sockfd, const char *host, unsigned short port);

int atlas_udp_close_without_connect(intptr_t sockfd);

int atlas_udp_joinmulticast(intptr_t sockfd, char *p_group);

int atlas_udp_recvfrom(intptr_t sockfd, void *p_remote,unsigned char *p_data, unsigned int datalen, unsigned int timeout_ms);

uintptr_t atlas_tcp_enstablish(const char *host, uint16_t port, uint16_t flag);

int32_t atlas_tcp_read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms);

int32_t atlas_tcp_write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms);

int atlas_tcp_destroy(uintptr_t fd);

void *HAL_SemaphoreCreate(void);
void HAL_SemaphoreDestroy(void *sem);
int HAL_SemaphoreWait(void *sem, uint32_t timeout_ms);
void HAL_SemaphorePost(void *sem);

/*--------------------------------------*/
#define HAL_Malloc            atlas_malloc
#define HAL_Free              atlas_free
#define HAL_SleepMs           atlas_usleep
#define HAL_UptimeMs          atlas_boot_uptime
#define HAL_Printf            atlas_printf
#define HAL_Snprintf          atlas_snprintf
#define HAL_MutexCreate       atlas_mutex_create
#define HAL_MutexDestroy      atlas_mutex_destroy
#define HAL_MutexLock         atlas_mutex_lock
#define HAL_MutexUnlock       atlas_mutex_unlock

#define HAL_ThreadCreate      atlas_thread_create
#define HAL_ThreadDelete      atlas_thread_delete

#define HAL_UDP_create        atlas_udp_create
#define HAL_UDP_close         atlas_udp_close
#define HAL_UDP_write                   atlas_udp_write
#define HAL_UDP_SELECT                  atlas_udp_select
#define HAL_UDP_READ                    atlas_udp_read
#define HAL_UDP_readTimeout             atlas_udp_read_timeout
#define HAL_UDP_create_without_connect  atlas_udp_create_without_connect
#define HAL_UDP_connect                 atlas_udp_connect
#define HAL_UDP_close_without_connect   atlas_udp_close_without_connect
#define HAL_UDP_joinmulticast           atlas_udp_joinmulticast
#define HAL_UDP_recvfrom                atlas_udp_recvfrom

#define HAL_TCP_Establish               atlas_tcp_enstablish
#define HAL_TCP_Write                   atlas_tcp_write
#define HAL_TCP_Read                    atlas_tcp_read
#define HAL_TCP_Destroy                 atlas_tcp_destroy

#if defined(__cplusplus)
}
#endif
#endif //CNIOT_ATLAS_CNIOT_ATLAS_WRAPPER_H
