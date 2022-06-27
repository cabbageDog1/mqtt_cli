#include "logger/atlas_logger.h"
#include "atlas_scheduler.h"
#include "cniot_atlas_wrapper.h"
#include "../protocol/atlas_protocol.h"
#include "./report/atlas_report.h"
#include "./request/atlas_request.h"

static void *g_thread_handle = NULL;

static char *g_module={"scheduler"};
static int g_initialize = 0;
static int g_running = 0;

CNIOT_STATUS_CODE cniot_atlas_scheduler_initialize(void){
    if (g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_initialize = 1;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_scheduler_finalize(void) {
    if (!g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }

    g_initialize = 0;
    return CNIOT_STATUS_CODE_OK;
}


static int _scheduler_thread_proc(void *arg) {
    uint64_t start = 0, end = 0;
    while(g_running) {
        logger_debug("start scheduler last_scheduler_time=%llu", end - start);
        start = atlas_boot_uptime();
        cniot_protocol_proc(C_SCHEDULER_INTERVAL_TIME);
        end  = atlas_boot_uptime();
        if (C_SCHEDULER_INTERVAL_TIME * 2 <= end - start ) {
            logger_err("scheduler timeout happen %llu", end - start);
        }
        if (end - start < C_SCHEDULER_INTERVAL_TIME / 2) {
            atlas_usleep(C_SCHEDULER_INTERVAL_TIME + start - end);
        }
        cniot_atlas_scheduler_count();
    }
    return 0;
}

CNIOT_STATUS_CODE cniot_atlas_scheduler_startup(void) {
    int stack_used = 1;
    thread_parm_t parm ;
    if (g_running) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_running = 1;
    memset(&parm, 0, sizeof(thread_parm_t));
    atlas_snprintf(parm.thread_name, sizeof(parm.thread_name), "atlas_scheduler");
    parm.stack_size = 1440;
    parm.thread_prio = 8; //迫于光年的淫威改成8...
    int ret = atlas_thread_create(&g_thread_handle, _scheduler_thread_proc, NULL, &parm, &stack_used);
    if (ret < 0) {
        g_running = 0;
        return CNIOT_STATUS_CREATE_THREAD_FAILED;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_scheduler_shutdown(void) {
    if (!g_running) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_running = 0;
    atlas_thread_delete(g_thread_handle);
    g_thread_handle = NULL;
    return CNIOT_STATUS_CODE_OK;
}

