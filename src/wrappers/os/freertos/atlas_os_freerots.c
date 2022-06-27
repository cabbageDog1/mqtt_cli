/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "infra_types.h"
#include "infra_defs.h"
#include "wrappers_defs.h"
#include "cniot_atlas_wrapper.h"

#define HAL_SEM_MAX_COUNT           (10)
#define HAL_SEM_INIT_COUNT          (0)

#define DEFAULT_THREAD_NAME         "atlas_task"
#define DEFAULT_THREAD_SIZE         (1440)
#define TASK_STACK_ALIGN_SIZE       (4)

void atlas_free(void *ptr)
{
    if (ptr) {
        ldu_free(ptr);
    }
}


void *atlas_malloc(uint32_t size)
{
    return ldu_malloc(size);
}


void *atlas_mutex_create(void)
{
    return ldu_create_mutex();
}


void atlas_mutex_destroy(void *mutex)
{
     ldu_destroy_mutex(mutex);
}

/**
 * @brief Waits until the specified mutex is in the signaled state.
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void atlas_mutex_lock(void *mutex)
{
     ldu_lock_mutex(mutex);
}


void atlas_mutex_unlock(void *mutex)
{
    ldu_unlock_mutex(mutex);
}


void atlas_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf(fmt, args);
    va_end(args);
    //fflush(stdout);
}

void atlas_usleep(uint32_t ms)
{
    ldu_msleep(ms);
}

int atlas_snprintf(char *str, const int len, const char *fmt, ...)
{
    va_list args;
    int rc;
    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);
    return rc;
}

int  atlas_vsnprintf(char *str, const int len, const char *format, va_list ap)  {
    return vsnprintf(str, len, format, ap);
}
int atlas_thread_create(
        void **thread_handle,
        void *(*work_routine)(void *),
        void *arg,
        void *hal_os_thread_param,
        int *stack_used)
{
    thread_parm_t *parm = (thread_parm_t *)hal_os_thread_param;
    if (!hal_os_thread_param) {
        return -1;
    }
    *thread_handle = ldu_create_thread_with_prio(work_routine, parm->thread_name, arg, parm->thread_prio, parm->stack_size);
    return 0;
}

/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was boot.
 *
 * @return the number of milliseconds.
 * @see None.
 * @note None.
 */
uint64_t atlas_boot_uptime(void)
{
    return (uint64_t)xTaskGetTickCount();
}

void  atlas_thread_delete(void *thread_handle) {
    ldu_delete_thread();
}

uint64_t atlas_abs_time() {
    return (uint64_t)ldu_get_rtc() * 1000;
}

void *HAL_SemaphoreCreate(void)
{
    return ldu_create_sema(HAL_SEM_INIT_COUNT);
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