#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <memory.h>

#include <pthread.h>
#include <unistd.h>
//#include <sys/prctl.h>
#include <sys/time.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include "infra_compat.h"
#include "infra_defs.h"
#include "cniot_atlas_wrapper.h"

#define ROUTER_INFO_PATH        "/proc/net/route"
#define ROUTER_RECORD_SIZE      256

void  *atlas_malloc(uint32_t size){
    return malloc(size);
}

void  atlas_free(void *ptr){
    if (ptr) {
        free(ptr);
    }
    return;
}

void  *atlas_mutex_create(void) {

    int err_num;
    pthread_mutex_t *mutex = (pthread_mutex_t *)atlas_malloc(sizeof(pthread_mutex_t));
    if (NULL == mutex) {
        return NULL;
    }

    if (0 != (err_num = pthread_mutex_init(mutex, NULL))) {
        printf("create mutex failed\n");
        atlas_free(mutex);
        return NULL;
    }

    return mutex;
}

void  atlas_mutex_destroy(void *mutex){
    int err_num;

    if (!mutex) {
        printf("mutex want to destroy is NULL!\n");
        return;
    }
    if (0 != (err_num = pthread_mutex_destroy((pthread_mutex_t *)mutex))) {
        printf("destroy mutex failed\n");
    }

    atlas_free(mutex);
}

void  atlas_mutex_lock(void *mutex){
    int err_num;
    if (0 != (err_num = pthread_mutex_lock((pthread_mutex_t *)mutex))) {
        printf("unlock mutex failed - '%s' (%d)\n", strerror(err_num), err_num);
    }
}

void  atlas_mutex_unlock(void *mutex) {
    int err_num;
    if (0 != (err_num = pthread_mutex_unlock((pthread_mutex_t *)mutex))) {
        printf("unlock mutex failed - '%s' (%d)\n", strerror(err_num), err_num);
    }
}

//void  atlas_printf(const char *fmt, ...) {
//    va_list args;
//
//    va_start(args, fmt);
//    vprintf(fmt, args);
//    va_end(args);
//
//    fflush(stdout);
//}
int  atlas_vsnprintf(char *str, const int len, const char *format, va_list ap){
    return vsnprintf(str, len, format, ap);
}

int  atlas_snprintf(char *str, const int len, const char *fmt, ...){
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);

    return rc;
}

int  atlas_thread_create(void **thread_handle, void *(*work_routine)(void *), void *arg, void *hal_os_thread_param,
                         int *stack_used){
    int ret = -1;

    if (stack_used) {
        *stack_used = 0;
    }
    ret = pthread_create((pthread_t *)thread_handle, NULL, work_routine, arg);

    return ret;
}

void  atlas_thread_detach(void *thread_handle) {
    pthread_detach((pthread_t)thread_handle);
}

void  atlas_thread_delete(void *thread_handle){
    if (NULL == thread_handle) {
        return;
    } else {
        /*main thread delete child thread*/
//        pthread_cancel((pthread_t)thread_handle);
        pthread_join((pthread_t)thread_handle, 0);
    }
}

uint64_t  atlas_abs_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (tv.tv_usec / 1000);
}

uint64_t atlas_boot_uptime() {
    uint64_t            time_ms;
    struct timespec     ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_ms = ((uint64_t)ts.tv_sec * (uint64_t)1000) + (ts.tv_nsec / 1000 / 1000);

    return time_ms;
}

void atlas_usleep(uint32_t ms)
{
    usleep(1000 * ms);
}

void atlas_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}

char *_get_default_routing_ifname(char *ifname, int ifname_size)
{
    FILE *fp = NULL;
    char line[ROUTER_RECORD_SIZE] = {0};
    char iface[IFNAMSIZ] = {0};
    char *result = NULL;
    unsigned int destination, gateway, flags, mask;
    unsigned int refCnt, use, metric, mtu, window, irtt;
    char *buff = NULL;

    fp = fopen(ROUTER_INFO_PATH, "r");
    if (fp == NULL) {
        perror("fopen");
        return result;
    }

    buff = fgets(line, sizeof(line), fp);
    if (buff == NULL) {
        perror("fgets");
        goto out;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (11 !=
            sscanf(line, "%s %08x %08x %x %d %d %d %08x %d %d %d",
                   iface, &destination, &gateway, &flags, &refCnt, &use,
                   &metric, &mask, &mtu, &window, &irtt)) {
            perror("sscanf");
            continue;
        }

        /*default route */
        if ((destination == 0) && (mask == 0)) {
            strncpy(ifname, iface, ifname_size - 1);
            result = ifname;
            break;
        }
    }

    out:
    if (fp) {
        fclose(fp);
    }

    return result;
}


uint32_t HAL_Wifi_Get_IP(char ip_str[NETWORK_ADDR_LEN], const char *ifname)
{
    struct ifreq ifreq;
    int sock = -1;
    char ifname_buff[IFNAMSIZ] = {0};

    if ((NULL == ifname || strlen(ifname) == 0) &&
        NULL == (ifname = _get_default_routing_ifname(ifname_buff, sizeof(ifname_buff)))) {
        perror("get default routeing ifname");
        return -1;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    ifreq.ifr_addr.sa_family = AF_INET;
    strncpy(ifreq.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFADDR, &ifreq) < 0) {
        close(sock);
        perror("ioctl");
        return -1;
    }

    close(sock);

    strncpy(ip_str,
            inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr),
            NETWORK_ADDR_LEN);

    return ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr;
}

#if 1

void *HAL_SemaphoreCreate(void)
{

#ifdef __APPLE__
    static int cnt = 0 ;
    char path[128] = {0};
    snprintf(path, 128, "./atlas-sdk-%d", cnt++);
    return sem_open(path ,O_CREAT, S_IRUSR | S_IWUSR, 0);
#else
    void *sem = NULL;
    sem = atlas_malloc(sizeof(sem_t));
    if (!sem) {
        return NULL;
    }
    if (sem_init(sem, 0, 0) < 0 ) {
        atlas_free(sem);
        return NULL;
    }
    return sem;
#endif
}

void HAL_SemaphoreDestroy(void *sem)
{
#ifdef __APPLE__
    sem_close(sem);
#else
    sem_destroy((sem_t *)sem);
    atlas_free(sem);
#endif
}

void HAL_SemaphorePost(void *sem)
{
    sem_post((sem_t *)sem);
}

#ifdef __APPLE__
int sem_timedwait(void *sem, uint32_t ts) {
    int time = 0;
    do{
        usleep(20 * 1000);
        time += 20;
        if (sem_trywait(sem) == 0) {
            return 0;
        }
    } while (time < ts);
    return -1;
}

#endif

int HAL_SemaphoreWait(void *sem, uint32_t timeout_ms)
{
#ifdef __APPLE__
    return sem_timedwait(sem, timeout_ms);
#else
    struct timespec ts;
    int s = 0;
    uint64_t now = atlas_abs_time();

    now += timeout_ms;
    ts.tv_sec = now / 1000;
    ts.tv_nsec = (now % 1000) * 1000 * 1000;

    while ((s = sem_timedwait(sem, &ts)) == -1 && errno == EINTR)
        continue;       /* Restart if interrupted by handler */

    /* Check what happened */
    if (s == -1) {
       if (errno == ETIMEDOUT) {
           //printf("sem_timedwait() timed out\n");
       }
       return -1;
    }
    return 0;
#endif
}

#else

void *HAL_SemaphoreCreate(void)
{
    return ldu_create_sema(0);
}

void HAL_SemaphoreDestroy(void *sem)
{
    ldu_destroy_sema(sem);
}

void HAL_SemaphorePost(void *sem)
{
   return ldu_post_sema(sem);
}

int HAL_SemaphoreWait(void *sem, uint32_t timeout_ms)
{
   if (ldu_wait_sema_timeout(sem , timeout_ms) > 0) {
       return -1;
   }
   return 0;
}
#endif

