#include "report/atlas_report.h"
#include "infra_compat.h"
#include "atlas_utility.h"
#include "atlas_request.h"
#include "cniot_atlas_wrapper.h"
#include "logger/atlas_logger.h"

static int g_initialize = 0;
static char *g_module={"request"};
static void *g_request_mutex = NULL;
static int g_request_count = 0;
static void *g_thread_handle = NULL;

typedef struct {
    list_head_t node;
    int buff_len;
    int rsp_len;
    uint64_t msgId;
    uint64_t expire_time;
    uint64_t send_time;
    uint64_t recv_time;
    void *sem;
    const char *request;
    int  request_len;
    int  is_send;
    int  func_code;
    char *buff;
    atlas_request_done_fun_t fun;
}mqtt_rpc_node_t;

static list_head_t g_request_head = {&g_request_head, &g_request_head};
static int g_running = 0;
static void *g_request_sem = NULL;
static void *g_monitor_mutex = NULL;
static int total_request = 0;
static int success_request = 0;
static int64_t total_cost = 0;
static int avg_cost = 0;
static int proc_count = 0;

static void delete_rpc_node(mqtt_rpc_node_t *rpcNode) {
    if (rpcNode) {
        list_del_init(&rpcNode->node);
        g_request_count--;
        if (rpcNode->sem) {
            HAL_SemaphoreDestroy(rpcNode->sem);
        }
        atlas_free(rpcNode);
    }
}
static void _request_monitor(CNIOT_STATUS_CODE rc, int64_t cost) {
    atlas_mutex_lock(g_monitor_mutex);
    total_request++;
    if (rc == CNIOT_STATUS_CODE_OK) {
        total_cost += cost;
        success_request++;
        avg_cost = total_cost / success_request;
    }
    atlas_mutex_unlock(g_monitor_mutex);
}

CNIOT_STATUS_CODE cniot_atlas_request_initialize(void){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    if (g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    CHECK_MALLOC_VALUE(g_request_mutex, atlas_mutex_create(), L_FAILED, ret);
    list_init(&g_request_head);
    g_request_sem = HAL_SemaphoreCreate();
    g_initialize = 1;
    g_monitor_mutex = atlas_mutex_create();

 L_FAILED:
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_request_finalize(void) {
    mqtt_rpc_node_t *rpc_node = NULL, *tmp = NULL;
    if (!g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    atlas_mutex_lock(g_request_mutex);
    list_for_each_entry_safe(rpc_node, tmp, &g_request_head, node, mqtt_rpc_node_t) {
        delete_rpc_node(rpc_node);
    }
    g_request_count = 0;
    atlas_mutex_unlock(g_request_mutex);
    atlas_mutex_destroy(g_request_mutex);
    HAL_SemaphoreDestroy(g_request_sem);
    g_request_sem = NULL;
    g_request_mutex = NULL;
    g_initialize = 0;
    return CNIOT_STATUS_CODE_OK;
}

static int _request_thread_proc(void *arg) {
#define C_REQUEST_INTERVAL_TIME  1000
#define C_REQUEST_REPORT_INTERVAL  (30 * 1000)
    int proc = 0;
    char trace_id[C_MAX_ID_LEN] = {0};
    char *buff = atlas_malloc(4096);
    uint64_t begin = atlas_boot_uptime();
    while(g_running) {
        if (0 == proc) {
            HAL_SemaphoreWait(g_request_sem, C_REQUEST_INTERVAL_TIME);
        }
        atlas_request_proc(&proc);
        proc_count++;
        if (C_REQUEST_REPORT_INTERVAL + begin < atlas_boot_uptime()) {
            atlas_create_traceId(trace_id);
            atlas_snprintf(buff, 4096, "total:%d,success:%d,rate:%d,cost:%d,proc:%d", total_request, success_request,
                           total_request == 0 ? 0: (int)(success_request * 100 / total_request),
                           avg_cost, proc_count);
            cniot_atlas_report(REPORT_UPLOAD, "DEVICE_CLOUD_SERVICE", trace_id,  atlas_abs_time(), 188, buff, CNIOT_STATUS_CODE_OK);
            begin = atlas_boot_uptime();
        }
    }
    atlas_free(buff);
    return 0;
}

CNIOT_STATUS_CODE cniot_atlas_request_startup(void) {
    int stack_used = 1;
    thread_parm_t parm ;
    if (g_running) {
        return CNIOT_STATUS_CODE_OK;
    }
    memset(&parm, 0, sizeof(thread_parm_t));
    atlas_snprintf(parm.thread_name, sizeof(parm.thread_name), "atlas_request");
    parm.stack_size = 1440;
    parm.thread_prio = 7;
    g_running = 1;
    int ret = atlas_thread_create(&g_thread_handle, _request_thread_proc, NULL, &parm, &stack_used);
    if (ret < 0) {
        g_running = 0;
        return CNIOT_STATUS_CREATE_THREAD_FAILED;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_request_shutdown(void) {
    g_running = 0;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_add_request(uint64_t msgId, int timeout,const char *request, int request_len,
        char* buff, int buff_len, atlas_request_done_fun_t fun){

    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    mqtt_rpc_node_t *rpc_node = NULL;
    CHECK_VALUE_NULL(buff);

    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_request_mutex);
    if (g_request_count > C_MAX_REQUEST_NUM) {
        logger_err("request num overflow :%d bufferCount:%d", g_request_count, C_MAX_REQUEST_NUM);
        ret = CNIOT_STATUS_BUFFER_OVERFLOW;
        goto L_FAILED;
    }
    CHECK_MALLOC_VALUE(rpc_node, atlas_malloc(sizeof(mqtt_rpc_node_t)), L_FAILED, ret);
    rpc_node->msgId = msgId;
    rpc_node->send_time = atlas_boot_uptime();
    rpc_node->recv_time = 0;
    rpc_node->rsp_len = 0;
    rpc_node->is_send = 0;
    rpc_node->expire_time = rpc_node->send_time + timeout;
    rpc_node->buff = buff;
    rpc_node->sem = HAL_SemaphoreCreate();
    rpc_node->buff_len = buff_len;
    rpc_node->fun = fun;
    rpc_node->func_code = CNIOT_STATUS_CODE_OK;
    rpc_node->request = request;
    rpc_node->request_len = request_len;

    list_init(&rpc_node->node);
    list_add_tail(&rpc_node->node, &g_request_head);
    g_request_count++;
    if (!rpc_node->sem) {
        logger_err("create sem failed");
        goto L_FAILED;
    }
    logger_info("add request msgId=%llu add_time=%llu buf_len=%d  request_count=%d success", msgId, rpc_node->send_time, buff_len, g_request_count);
L_FAILED:
    if (ret != CNIOT_STATUS_CODE_OK) {
        delete_rpc_node(rpc_node);
    }
    HAL_SemaphorePost(g_request_sem);
    atlas_mutex_unlock(g_request_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_del_request(uint64_t msgId) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    mqtt_rpc_node_t *rpc_node = NULL;
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_request_mutex);

    list_for_each_entry(rpc_node, &g_request_head, node, mqtt_rpc_node_t) {
        if (msgId == rpc_node->msgId) {
            ret = CNIOT_STATUS_CODE_OK;
            if (rpc_node->recv_time == 0) {
                _request_monitor(CNIOT_STATUS_MSG_TIMEOUT, atlas_boot_uptime() - rpc_node->send_time);
            }
            logger_info("delete request msgId=%llu add_time=%llu total_count=%d success", msgId, rpc_node->send_time, g_request_count);
            delete_rpc_node(rpc_node);

            break;
        }
    }
    atlas_mutex_unlock(g_request_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_set_response(uint64_t msgId, const char *payload, int payload_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_MSG_NOT_FOUND;
    mqtt_rpc_node_t *rpc_node = NULL, *tmp = NULL;
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CHECK_VALUE_NULL(payload);
    atlas_mutex_lock(g_request_mutex);

    list_for_each_entry(rpc_node, &g_request_head, node, mqtt_rpc_node_t) {
        if (msgId == rpc_node->msgId) {
            rpc_node->recv_time = atlas_boot_uptime();
            if (payload_len >= rpc_node->buff_len) {
                ret = CNIOT_STATUS_BUFFER_OVERFLOW;
                rpc_node->func_code = ret;
                HAL_SemaphorePost(rpc_node->sem);
                _request_monitor(CNIOT_STATUS_BUFFER_OVERFLOW, rpc_node->recv_time - rpc_node->send_time);
                break;
            }
            memcpy(rpc_node->buff, payload, payload_len);
            rpc_node->buff[payload_len] = '\0';
            HAL_SemaphorePost(rpc_node->sem);
            ret = CNIOT_STATUS_CODE_OK;
            _request_monitor(ret, rpc_node->recv_time - rpc_node->send_time);
            logger_info("msg_id=%lld receive response msg cost =%lld", rpc_node->msgId,  rpc_node->recv_time - rpc_node->send_time);
            break;
        }
    }
    atlas_mutex_unlock(g_request_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_update_response(uint64_t msgId, CNIOT_STATUS_CODE rc, int rsp_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_MSG_NOT_FOUND;
    mqtt_rpc_node_t *rpc_node = NULL, *tmp = NULL;
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_request_mutex);

    list_for_each_entry(rpc_node, &g_request_head, node, mqtt_rpc_node_t) {
        if (msgId == rpc_node->msgId) {
            rpc_node->func_code = rc;
            if (rc != CNIOT_STATUS_CODE_OK || (0 != rsp_len && rc == CNIOT_STATUS_CODE_OK)) {
                rpc_node->recv_time = atlas_boot_uptime();
                HAL_SemaphorePost(rpc_node->sem);
                _request_monitor(rpc_node->func_code, rpc_node->recv_time - rpc_node->send_time);
                ret = CNIOT_STATUS_CODE_OK;
                logger_info("msg_id=%lld receive response msg cost =%lld", rpc_node->msgId,  rpc_node->recv_time - rpc_node->send_time);
                break;
            }
        }
    }
    atlas_mutex_unlock(g_request_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_get_response(uint64_t msgId) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_MSG_TIMEOUT;
    mqtt_rpc_node_t *rpc_node = NULL;
    uint64_t now = atlas_boot_uptime();
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_request_mutex);

    list_for_each_entry(rpc_node, &g_request_head, node, mqtt_rpc_node_t) {
        if (msgId == rpc_node->msgId) {
            if (0 < rpc_node->recv_time) {
                ret = rpc_node->func_code;
                logger_info("msg_id=%lld get response msg code=%d cost =%lld", rpc_node->msgId, ret, atlas_boot_uptime()- rpc_node->recv_time);
                delete_rpc_node(rpc_node);
            } else {
                if (rpc_node->expire_time <= now) {
                    ret = CNIOT_STATUS_MSG_TIMEOUT;
                    logger_err("request msgId=%llu expire:%llu, %llu", rpc_node->msgId, rpc_node->expire_time, now);
                } else {
                    atlas_mutex_unlock(g_request_mutex);
                    if (HAL_SemaphoreWait(rpc_node->sem, rpc_node->expire_time - now) == 0) {
                        return CNIOT_STATUS_CODE_CONTINUE;
                    }
                    return  CNIOT_STATUS_MSG_TIMEOUT;
                }
            }
            break;
        }
    }
    atlas_mutex_unlock(g_request_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_request_proc(int *proc_request) {
    mqtt_rpc_node_t *rpc_node = NULL, *tmp = NULL;
    uint64_t now = 0;
    void *data = NULL;
    void *rsp = NULL;
    CNIOT_STATUS_CODE  rc = CNIOT_STATUS_CODE_OK;
    int rsp_len = 0;
    uint64_t msgId = 0;
    int len = 0;
#define C_REQUEST_MIN_PROC_TIME   2000
    if (g_request_mutex == NULL) {
        return CNIOT_STATUS_PARAMETER_NULL;
    }
    atlas_mutex_lock(g_request_mutex);
    now = atlas_boot_uptime();
    atlas_request_done_fun_t fun = NULL;

    *proc_request = 0;
    list_for_each_entry_safe(rpc_node, tmp, &g_request_head, node, mqtt_rpc_node_t) {
        if (!rpc_node->is_send && now + C_REQUEST_MIN_PROC_TIME < rpc_node->expire_time) {
            data = atlas_malloc(rpc_node->request_len + 1);
            rpc_node->is_send = 1;
            len = rpc_node->request_len;
            memcpy(data, rpc_node->request, rpc_node->request_len);
            fun = rpc_node->fun;
            rsp = rpc_node->buff;
            msgId = rpc_node->msgId;
            rsp_len = rpc_node->buff_len;
            break;
        }
    }
    atlas_mutex_unlock(g_request_mutex);
    if (data) {
        *proc_request = 1;
        if (fun) {
            rc = fun(data, len, rsp, &rsp_len);
            if (rc != CNIOT_STATUS_CODE_OK) {
                logger_err("[request] request %lld failed rc=%d", msgId, rc);
            }
            atlas_update_response(msgId, rc, rsp_len);
        }
        atlas_free(data);
    }
    return CNIOT_STATUS_CODE_OK;
}