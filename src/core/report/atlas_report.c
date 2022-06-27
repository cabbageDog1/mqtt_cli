#include "infra_cjson.h"
#include "atlas_utility.h"
#include "cniot_atlas_wrapper.h"
#include "atlas_report.h"
#include "atlas_core.h"
#include "logger/atlas_logger.h"

static int g_initialize = 0;
static char *g_report_buff = 0;
static char *g_module = {"report"};
static int g_report_count= 0;
static uint64_t  g_last_report = 0;
static uint64_t  g_last_success_report = 0;
static uint64_t  g_last_failed_report = 0;
static int    g_last_report_failed_code = 0;
static int report_len = 0;
static void *g_report_mutex = NULL;
static int g_running = 0;
static void *g_thread_handle = NULL;
static int need_get_wifi = 0;

#define C_MAX_FAILED_MESSAGE_LEN     (1024)
static void *g_last_failed_message = NULL;

typedef struct {
    uint16_t used;
    uint16_t code;
    uint32_t ip;
    char host[C_MAX_HOST_LEN];
}dns_resolver_t;

#define C_MAX_DNS_COUNT        (5)
#define C_MAX_SCHEDULER_COUNT  (60)
#define C_TIME_COUNT_INTERVAL  (60)
#define C_MAX_HEARTBEAT_COUNT  (600)
static dns_resolver_t *g_dns_resolver  = NULL;

#define C_MAX_REPORT_BUFF_LEN  (4 * 1024)
#define C_MIN_REPORT_BUFF_LEN  (3 * 1024)
static uint8_t  *g_scheduler_count= NULL;
static uint8_t  *g_heartBeat_count = NULL;

static void (*g_wifi_fun)(char *) = NULL;

CNIOT_STATUS_CODE cniot_atlas_report_initialize(void){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    if (g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }

    CHECK_MALLOC_VALUE(g_report_mutex, atlas_mutex_create(), L_FAILED, ret);
    CHECK_MALLOC_VALUE(g_report_buff, atlas_malloc(C_MAX_REPORT_BUFF_LEN), L_FAILED, ret);
    CHECK_MALLOC_VALUE(g_dns_resolver, atlas_malloc(sizeof(dns_resolver_t)* C_MAX_DNS_COUNT), L_FAILED, ret);
    CHECK_MALLOC_VALUE(g_last_failed_message, atlas_malloc(C_MAX_FAILED_MESSAGE_LEN), L_FAILED, ret);
    CHECK_MALLOC_VALUE(g_scheduler_count, atlas_malloc(sizeof(uint8_t)* C_MAX_SCHEDULER_COUNT), L_FAILED, ret);
    CHECK_MALLOC_VALUE(g_heartBeat_count, atlas_malloc(sizeof(uint8_t)* C_MAX_HEARTBEAT_COUNT), L_FAILED, ret);

    memset(g_dns_resolver, 0, sizeof(dns_resolver_t)* C_MAX_DNS_COUNT);
    memset(g_scheduler_count, 0, C_MAX_SCHEDULER_COUNT);
    memset(g_heartBeat_count, 0, C_MAX_HEARTBEAT_COUNT);
    memset(g_last_failed_message, 0, C_MAX_FAILED_MESSAGE_LEN);

    atlas_snprintf(g_last_failed_message, C_MAX_FAILED_MESSAGE_LEN, "{null}");
    logger_info("report initialize success %p report_len=%d", g_report_buff, C_MAX_REPORT_BUFF_LEN);
    g_running = 0;
    g_initialize = 1;
L_FAILED:
    if (ret != CNIOT_STATUS_CODE_OK) {
        atlas_free(g_report_buff);
        atlas_free(g_dns_resolver);
        atlas_free(g_last_failed_message);
        atlas_free(g_scheduler_count);
        atlas_free(g_heartBeat_count);
        atlas_mutex_destroy(g_report_mutex);
        g_report_buff = NULL;
        g_dns_resolver = NULL;
        g_report_mutex = NULL;
        g_last_failed_message = NULL;
    }
    return ret;
}

CNIOT_STATUS_CODE  cniot_atlas_report_finalize(void) {
    if (!g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    atlas_free(g_report_buff);
    atlas_free(g_dns_resolver);
    atlas_free(g_last_failed_message);
    atlas_free(g_scheduler_count);
    atlas_free(g_heartBeat_count);
    g_dns_resolver = NULL;
    g_report_buff = NULL;
    g_last_failed_message = NULL;
    g_scheduler_count = NULL;
    g_heartBeat_count = NULL;
    g_initialize = 0;
    g_running = 0;
    atlas_mutex_destroy(g_report_mutex);
    return CNIOT_STATUS_CODE_OK;
}

static void _check_wifi_message() {
    int len = 0;
    if (need_get_wifi) {
        len = strlen(g_last_failed_message);
        len += atlas_snprintf(g_last_failed_message + len, C_MAX_FAILED_MESSAGE_LEN - len, "\nwifi:{");
        if (g_wifi_fun && C_MAX_FAILED_MESSAGE_LEN - len > 512) {
            g_wifi_fun(g_last_failed_message + len);
        }
        len = strlen(g_last_failed_message);
        atlas_snprintf(g_last_failed_message + len, C_MAX_FAILED_MESSAGE_LEN - len, "}");
        need_get_wifi = 0;
    }
}
static void * _report_thread_proc(void *arg) {
    while(g_running) {
        cniot_atlas_report_proc();
        atlas_usleep(1000);
        _check_wifi_message();
    }
    return NULL;
}

CNIOT_STATUS_CODE cniot_atlas_report_startup(void) {
    int stack_used = 1;
    int ret = 0;
    if (g_running) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_running = 1;
    g_last_report = atlas_boot_uptime();

    thread_parm_t parm ;
    memset(&parm, 0, sizeof(thread_parm_t));
    atlas_snprintf(parm.thread_name, sizeof(parm.thread_name), "atlas_report");
    parm.stack_size = 1440;
    parm.thread_prio = 5;
    ret = atlas_thread_create(&g_thread_handle, _report_thread_proc, NULL, &parm, &stack_used);
    if (ret < 0) {
        g_running = 0;
        return CNIOT_STATUS_CREATE_THREAD_FAILED;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_report_shutdown() {
    if (g_running) {
        g_running = 0;
        atlas_thread_delete(g_thread_handle);
        g_thread_handle = NULL;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_report_proc() {
#define C_REPORT_MAX_INTERVAL     (60000)
#define C_REPORT_MIN_INTERVAL     (20000)
    char *rsp = NULL;
    char url[C_MAX_URL_LEN] = {0};
    char host[C_MAX_HOST_LEN] = {0};
    char *buff = NULL;
    C_CNIOT_NETWORK_STATUS status;
    char *env = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    atlas_mutex_lock(g_report_mutex);
    uint64_t  now = atlas_boot_uptime();
    if ((C_MIN_REPORT_BUFF_LEN < report_len &&  g_last_report + C_REPORT_MIN_INTERVAL < now) ||  g_last_report + C_REPORT_MAX_INTERVAL < now) {
        g_last_report = now;
        if (report_len > 0) {
            if (report_len + 10 < C_MAX_REPORT_BUFF_LEN) { // 被截断了就没有必要上报
                atlas_get_network_status(&status);
                if (status == NETWORK_STATUS_ONLINE && CNIOT_STATUS_CODE_OK == atlas_core_get_env(&env)) {
                    if (CNIOT_STATUS_CODE_OK == atlas_get_report_address(env, host)) {
                        atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/log/trace.do", host);
                        CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_BODY_LEN),L_FAILED, ret);
                        CHECK_MALLOC_VALUE(buff, atlas_malloc(C_MAX_REPORT_BUFF_LEN), L_FAILED, ret);
                        atlas_snprintf(g_report_buff + report_len, C_MAX_REPORT_BUFF_LEN - report_len, "]}");
                        memcpy(buff, g_report_buff, C_MAX_REPORT_BUFF_LEN);
                    }
                }
            }
            report_len = 0;
            g_report_count  = 0;
        }
    }
L_FAILED:
    atlas_mutex_unlock(g_report_mutex);
    if (buff) {
        if (atlas_check_can_upload_log()) {
            ret = atlas_https_post_with_redirect(url, buff, C_HTTP_TIME_OUT, rsp, C_MAX_BODY_LEN, 0);
            if (ret != CNIOT_STATUS_CODE_OK) {
                g_last_report_failed_code = ret;
                g_last_failed_report = atlas_boot_uptime();
            } else {
                g_last_success_report = atlas_boot_uptime();
            }
            logger_info("http post report ret=%d report_count=%d, len=%d", ret, g_report_count, report_len);
        } else {
            logger_err("check wifi status, drop report log report_count=%d, len=%d", g_report_count, report_len);
        }
    }
    atlas_free(buff);
    atlas_free(rsp);
    return CNIOT_STATUS_CODE_OK;
}


static const char *getLogLine(CNIOT_REPORT_LOGLINE line) {
    if (REPORT_ACTION == line) {
        return "BEHAVIOUR";
    } else if (REPORT_UPLOAD == line) {
        return "UP";
    } else if (REPORT_DOWNLOAD == line) {
        return "DOWN";
    }
    return "UNKNOW";
}

static int formatJsonString(const char*data, char *buffer, int buf_len) {
    int data_len = (int)strlen(data);
    int i = 0, desCount = 0;
    while (i < data_len && desCount < buf_len - 1) {
        if (data[i] != '"' && data[i] != '{' && data[i] != '}' && data[i] != '[' && data[i] != ']') {
            buffer[desCount++] = data[i++];
        } else {
            i++;
        }
    }
    buffer[desCount++] = '\0';
    return desCount;
}

CNIOT_STATUS_CODE cniot_atlas_dns_resolver(const char *addr, int code, uint32_t ip) {
    int i = 0;
    if (!g_initialize || !g_dns_resolver) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CHECK_VALUE_NULL(addr);

    logger_info("dns resolver %s code=%d addr=0x%x", addr, code, (ip));

    atlas_mutex_lock(g_report_mutex);
    for (i = 0; i < C_MAX_DNS_COUNT; ++i) {
        if (g_dns_resolver[i].used == 0) {
            g_dns_resolver[i].used = 1;
            memcpy(g_dns_resolver[i].host, addr, C_MAX_HOST_LEN);
        }
        if (0 == strncmp(g_dns_resolver[i].host, addr,C_MAX_HOST_LEN)) {
            g_dns_resolver[i].code = code;
            g_dns_resolver[i].ip = ip;
            break;
        }
    }
    atlas_mutex_unlock(g_report_mutex);

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_scheduler_count() {
    int idx = 0;
    uint64_t  time = 0;
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    time = atlas_boot_uptime() / 1000;
    idx = (int)(time) % C_MAX_SCHEDULER_COUNT;
    g_scheduler_count[idx] = C_TIME_COUNT_INTERVAL + ((time / C_TIME_COUNT_INTERVAL) % C_TIME_COUNT_INTERVAL);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_heartbeat_count() {
    uint64_t  time = 0;
    int idx = 0;
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    time = atlas_boot_uptime() / 1000;
    idx = (int)(time) % C_MAX_HEARTBEAT_COUNT;
    /*
     * C_TIME_COUNT_INTERVAL 过滤默认初始化为0
     * */
    g_heartBeat_count[idx] = C_TIME_COUNT_INTERVAL + ((time / C_TIME_COUNT_INTERVAL) % C_TIME_COUNT_INTERVAL);
    logger_info("heartbeat send success idx=%d", idx);
    return CNIOT_STATUS_CODE_OK;
}

static int build_report_message(char *buff, int buff_len) {
    uint64_t now = atlas_boot_uptime();
    int success_time = -1;
    int failed_time = -1;
    int len = 0;
    if (!buff || buff_len <= 128) {
        return 0;
    }
    if (g_last_success_report != 0) {
        success_time =  (int)((now - g_last_success_report) / 1000);
    }
    if (g_last_failed_report != 0) {
        failed_time =  (int)((now - g_last_failed_report) / 1000);
    }

    len  += atlas_snprintf(buff + len, buff_len - len, "logSuccess:%d", success_time);
    len  += atlas_snprintf(buff + len, buff_len - len, "-logFailed:%d/%d|",failed_time, g_last_report_failed_code);

    return len;
}

static int build_hearBeat_message(char *buff, int buff_len) {
    uint64_t  time = atlas_boot_uptime() / 1000;
    int idx = 0;
    int count = 0;
    int last1min = 0, last3min = 0, last5min = 0;
    idx = (int)(time % C_MAX_HEARTBEAT_COUNT);
    if (!buff || buff_len <= 30) {
        return 0;
    }

    while(count < 300 && count < time) {
        if (g_heartBeat_count[idx] == C_TIME_COUNT_INTERVAL + ((time - count) / C_TIME_COUNT_INTERVAL % C_TIME_COUNT_INTERVAL)) {
            if (count < 60) {
                last1min++;
                last3min++;
                last5min++;
            } else if (count < 180){
                last3min ++;
                last5min ++;
            } else if (count < 300) {
                last5min ++;
            }
        }
        if (idx == 0) {
            idx = C_MAX_HEARTBEAT_COUNT - 1;
        } else {
            idx--;
        }
        count++;
    }
    return atlas_snprintf(buff, buff_len, "heartBeat:%d/%d/%d", last1min, last3min, last5min);
}

static int build_dns_message(char *buff, int buff_len) {
    int len = 0;
    int i = 0;
    if (!buff || buff_len <= 128) {
        return 0;
    }
    int count= 0 ;
    atlas_mutex_lock(g_report_mutex);
    for (i = 0; i < C_MAX_DNS_COUNT; ++i) {
        if (g_dns_resolver[i].used == 1) {
            if (count++ != 0) {
                len += atlas_snprintf(buff + len, buff_len - len,  "|");
            }
            len += atlas_snprintf(buff + len, buff_len - len,  "dns:%s/%d/%x",
                    g_dns_resolver[i].host,
                    g_dns_resolver[i].code,
                    g_dns_resolver[i].ip);
        }
    }
    atlas_mutex_unlock(g_report_mutex);

    return len;
}

static int build_scheduler_message(char *buff, int buff_len) {
    uint64_t  time = atlas_boot_uptime() / 1000;
    int idx = 0;
    int count = 0;
    int last10S = 0, last20S = 0, last30S = 0;
    idx = (int)(time) % C_MAX_SCHEDULER_COUNT;
    if (!buff || buff_len <= 30) {
        return 0;
    }
    while(count < 30 && count < time) {
        if (g_scheduler_count[idx] == C_TIME_COUNT_INTERVAL + ((time - count) / C_TIME_COUNT_INTERVAL % C_TIME_COUNT_INTERVAL)) {
            if (count < 10 ) {
                last10S += 1;
                last20S += 1;
                last30S += 1;
            } else if (count < 20){
                last20S += 1;
                last30S += 1;
            } else if (count < 30) {
                last30S += 1;
            }
        }
        if (idx == 0) {
            idx = C_MAX_SCHEDULER_COUNT - 1;
        } else {
            idx--;
        }
        count++;
    }
    return atlas_snprintf(buff, buff_len, "-scheduler:%d/%d/%d|", last10S, last20S, last30S);
}

static int __get_core_message(char *buff, int buff_len) {
    CNIOT_PROTOCOL protocol;
    int status = 0;
    char host[C_MAX_HOST_LEN] = {0};
    int len = 0;

    atlas_get_core_status(&protocol, &status, host);
    len += atlas_snprintf(buff + len, buff_len - len, "{service:%s/%s/%d|",
                          protocol == 0 ? "UNKNOW" : protocol == 1 ? "COAP" : "MQTT" , host, status);
    len += build_hearBeat_message(buff + len, buff_len - len);
    len += build_scheduler_message(buff + len, buff_len - len);
    len += build_report_message(buff+len, buff_len - len);
    len += build_dns_message(buff+len, buff_len - len);
    len += atlas_snprintf(buff + len , buff_len - len, "}");

    return len;
}

static CNIOT_STATUS_CODE __get_method_from_service(const char *service, const char **method) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    const char *p = service;
    const char *end = service + strlen(service);
    *method = NULL;
    while(p < end) {
        if ('@' == *p || '/' == *p) {
            *method = p + 1;
        }
        p++;
    }
    if (NULL == *method || end <= *method) {
        return CNIOT_STATUS_MSG_NOT_FOUND;
    }

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_build_failed_message(char * trace_id, uint32_t cost, const char *service, const char *bizKey) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    const char *method = NULL;

    CHECK_VALUE_NULL(trace_id);
    CHECK_VALUE_NULL(service);
    CHECK_VALUE_NULL(bizKey);
    if (!g_last_failed_message) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    int buff_len = C_MAX_FAILED_MESSAGE_LEN, len = 0;
    if (CNIOT_STATUS_CODE_OK != __get_method_from_service(service, &method)) {
        method = service;
    }
    len += atlas_snprintf(g_last_failed_message + len, buff_len - len, "{%s/%llu/%llu|"
                                                                       "invoking:%s/%s/%u|",
            trace_id, atlas_boot_uptime() / 1000, atlas_abs_time() / 1000, method, bizKey, cost);

    len += __get_core_message(g_last_failed_message + len, buff_len -  len);
    len += atlas_snprintf(g_last_failed_message + len, buff_len - len, "}");

    need_get_wifi = 1;
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_build_core_message(char *buff, int *buff_len) {
    int len = 0;
    cniot_atlas_thing_entity_t *entity;

    CHECK_VALUE_NULL(buff);
    CHECK_VALUE_NULL(buff_len);

    atlas_core_get_entity(&entity);
    if (!g_initialize || NULL == entity) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    len += atlas_snprintf(buff + len, *buff_len - len, "Device:%s/%s/%llu/%llu|",
                          entity->entity_name,
                          C_ATLAS_SDK_VERSION_STR,
                          atlas_boot_uptime() / 1000, atlas_abs_time() / 1000);

    len += __get_core_message(buff + len, *buff_len - len);
    len += atlas_snprintf(buff + len, *buff_len - len, "\n%s\n", g_last_failed_message);
    *buff_len = len;

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_set_wifi_callback(void (*fun)(char *)) {
    g_wifi_fun = fun;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_report(CNIOT_REPORT_LOGLINE logLine, const char *action, char *traceId, uint64_t beginTime, uint32_t cost,
        const char *content, CNIOT_STATUS_CODE code)
{
    cniot_atlas_thing_entity_t *entity;
    lite_cjson_item_t *node = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    CHECK_VALUE_NULL(traceId);
    CHECK_VALUE_NULL(content);
    CHECK_VALUE_NULL(action);
    char errCode[10] = {0};
    char *body = NULL;
    atlas_core_get_entity(&entity);
    if (!g_initialize || NULL == entity) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_report_mutex);
    if (report_len + 1024 > C_MAX_REPORT_BUFF_LEN) {
        logger_info("drop report msg, traceId=%s cost=%d count=%d", traceId, cost, g_report_count);
        goto L_UNLOCK;
    }

    if (g_report_count == 0) {
        report_len = atlas_snprintf(g_report_buff, C_MAX_REPORT_BUFF_LEN, "{\"logList\":[");
    }

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_UNLOCK, ret);
    formatJsonString(content, body, C_MAX_BODY_LEN);

    if (g_report_count++ != 0){
        report_len += atlas_snprintf(g_report_buff + report_len, C_MAX_REPORT_BUFF_LEN - report_len, ",");
    }
    atlas_snprintf(errCode, 10, "0x%03x", code);

    report_len += atlas_snprintf(g_report_buff + report_len, C_MAX_REPORT_BUFF_LEN - report_len, "{"
                                             "\"traceId\":\"%s\""
                                             ",\"iotId\":\"%s\""
                                             ",\"region\":\"LINK_SH_GN\""
                                             ",\"action\":\"%s\""
                                             ",\"beginTime\":%llu"
                                             ",\"cost\":%d"
                                             ",\"actionContent\":\"%s\""
                                             ",\"resultInfo\":\"%s\""
                                             ",\"resultCode\":\"%s\""
                                             ",\"LogLine\":\"%s\""
                                             "}",
                                             traceId,  entity->iot_id, action,
                                              beginTime, cost, body, code == CNIOT_STATUS_CODE_OK ? "SUCCESS" : "FAILED",
                                             code == CNIOT_STATUS_CODE_OK ? "S666" : errCode , getLogLine(logLine));

    logger_info("add report to buffer success report_count=%d, len=%d", g_report_count, report_len);
L_UNLOCK:
    atlas_free(body);
    atlas_mutex_unlock(g_report_mutex);
    return ret;
}