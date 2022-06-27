#include <stdio.h>
#include "atlas_core.h"
#include "cniot_atlas_wrapper.h"
#include "atlas_utility.h"
#include "infra_httpc.h"
#include "infra_cjson.h"
#include "./request/atlas_request.h"

#include "./services/atlas_services.h"
#include "./protocol/atlas_protocol.h"
#include "./scheduler/atlas_scheduler.h"
#include "./report/atlas_report.h"

static cniot_atlas_thing_entity_t *g_core_entity = NULL;
static void *g_core_mutex = NULL;
static int g_core_initialize = 0;
static int g_core_startup = 0;
static int g_last_network_disconnect  = 0;
static char *g_module = {"core"};
static char  g_core_env[C_MAX_ENV_LEN] = {"online"};
static int g_wifi_roam_status = 0;
static int64_t g_wifi_roam_change_time = 0;

static char  g_core_host[C_MAX_HOST_LEN] = {"https://http-iot.cainiao.com"};
static C_CNIOT_NETWORK_STATUS   g_network_status = NETWORK_STATUS_ONLINE;
static CNIOT_STATUS_CODE  _set_thing(cniot_atlas_thing_entity_t *entry,
        const char *entity_name,
        const char *entity_secret,
        const char *thing_key,
        const char *thing_secret,
        const char *iot_id){

    CHECK_VALUE_NULL(entry);
    COPY_VALUE(entry->entity_name, entity_name, C_MAX_ENTITY_NAME_LEN, strlen);
    COPY_VALUE(entry->entity_secret, entity_secret, C_MAX_ENTITY_SECRET_LEN, strlen);
    COPY_VALUE(entry->thing_key, thing_key, C_MAX_THING_KEY, strlen);
    COPY_VALUE(entry->thing_secret, thing_secret, C_MAX_THING_SECRET_LEN, strlen);
    COPY_VALUE(entry->iot_id, iot_id, C_MAX_ID_LEN, strlen);

    return CNIOT_STATUS_CODE_OK;
}


static CNIOT_STATUS_CODE _parse_register_rsp_data(const char *data, char *atlas_entity_name, char *entity_secret, char *iot_id) {
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "iotId", iot_id, C_MAX_ID_LEN), L_ERROR);

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "deviceName", atlas_entity_name, C_MAX_ID_LEN), L_ERROR);

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "deviceSecret", entity_secret, C_MAX_ENTITY_SECRET_LEN), L_ERROR);

L_ERROR:
    return ret;
}

static CNIOT_STATUS_CODE _parse_properties_rsp_data(const char *data, char *buf, int buf_len) {
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "properties", buf, buf_len), L_ERROR);
L_ERROR:
    return ret;
}

static CNIOT_STATUS_CODE _parse_event_post_rsp_data(const char *data) {
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }
    return ret;
}


static CNIOT_STATUS_CODE _parse_configure_rsp_data(const char *data, char *buf, int buf_len) {
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "appConfigItemList", buf, buf_len), L_ERROR);
L_ERROR:
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_thing_entity_register(const char *env,
                                                    const char *entity_name,
                                                    const char *thing_secret,
                                                    const char *thing_key,
                                                    char *atlas_entity_name,
                                                    char *iot_id,
                                                    char* entity_secret){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_atlas_thing_entity_t *entity =NULL;

    char host[C_MAX_HOST_LEN] = {0};
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *rsp = NULL;

    CHECK_VALUE_NULL(entity_name);
    CHECK_VALUE_NULL(thing_key);
    CHECK_VALUE_NULL(thing_secret);
    CHECK_VALUE_NULL(env);
    CHECK_VALUE_NULL(iot_id);
    CHECK_VALUE_NULL(entity_secret);
    CHECK_VALUE_NULL(atlas_entity_name);

    logger_info("receive register msg  name:%s key:%s\n", entity_name, thing_key);
    CHECK_MALLOC_VALUE(entity, atlas_malloc(sizeof(cniot_atlas_thing_entity_t)), L_FAILED, ret);

    CHECK_RETURN_VALUE(ret, _set_thing(entity, entity_name, "", thing_key, thing_secret, ""), L_FAILED);

    //根据环境获取控制台地址
    CHECK_RETURN_VALUE(ret, atlas_get_https_address_from_env(env, host),  L_FAILED);
    logger_info("get host success=%s, start format url", host);

    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/thing/register.do", host);

    CHECK_RETURN_VALUE(ret,  atlas_sign_by_thing_key(sign, C_MAX_SIGN_JSON_LEN, 0,thing_key,entity_name,thing_secret), L_FAILED);


    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"version\":1}", sign);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, C_MAX_RSP_LEN), L_FAILED);

    CHECK_RETURN_VALUE(ret,_parse_register_rsp_data(rsp, atlas_entity_name, entity_secret, iot_id), L_FAILED);

    logger_info("finish parse post iot_id=%s\n", iot_id);
L_FAILED:
    atlas_free(rsp);
    atlas_free(body);
    atlas_free(entity);
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_register_with_barcode(const char *env,
                                                    const char *entity_name,
                                                    const char *thing_secret,
                                                    const char *thing_key,
                                                    char *atlas_entity_name,
                                                    char *iot_id,
                                                    char* entity_secret,
                                                    const char *barcode){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_atlas_thing_entity_t *entity =NULL;

    char host[C_MAX_HOST_LEN] = {0};
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *rsp = NULL;
    const char *bar_code_value = NULL;

    CHECK_VALUE_NULL(entity_name);
    CHECK_VALUE_NULL(thing_key);
    CHECK_VALUE_NULL(thing_secret);
    CHECK_VALUE_NULL(env);
    CHECK_VALUE_NULL(iot_id);
    CHECK_VALUE_NULL(entity_secret);
    CHECK_VALUE_NULL(atlas_entity_name);
    CHECK_VALUE_NULL(barcode);

    logger_info("receive barCode register msg  name:%s key:%s barcode=%s\n", entity_name, thing_key, barcode);
    if (strlen(barcode) <= 1) {
        ret = CNIOT_STATUS_BARCODE_ERROR;
        goto L_FAILED;
    }
    bar_code_value = barcode + 1;
    CHECK_MALLOC_VALUE(entity, atlas_malloc(sizeof(cniot_atlas_thing_entity_t)), L_FAILED, ret);

    CHECK_RETURN_VALUE(ret, _set_thing(entity, entity_name, "", thing_key, thing_secret, ""), L_FAILED);

    //根据环境获取控制台地址
    CHECK_RETURN_VALUE(ret, atlas_get_https_address_from_env_and_barcode(env, barcode, host),  L_FAILED);
    logger_info("get host success=%s, start format url", host);

    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/thing/register.do", host);

    CHECK_RETURN_VALUE(ret,  atlas_sign_by_thing_key(sign, C_MAX_SIGN_JSON_LEN, 0, thing_key,entity_name,thing_secret), L_FAILED);


    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"barCode\":\"%s\""
                                         ",\"version\":1}", sign, bar_code_value);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, C_MAX_RSP_LEN), L_FAILED);

    CHECK_RETURN_VALUE(ret,_parse_register_rsp_data(rsp, atlas_entity_name, entity_secret, iot_id), L_FAILED);

    logger_info("finish parse post iot_id=%s\n", iot_id);
L_FAILED:
    atlas_free(rsp);
    atlas_free(body);
    atlas_free(entity);
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_initialize(char *env,
                                         char *entity_name,
                                         char *entity_secret,
                                         char *thing_key,
                                         char *iot_id){

    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    if (g_core_initialize != 0) { //已经初始化完成
        return ret;
    }

    CHECK_VALUE_NULL(entity_name);
    CHECK_VALUE_NULL(thing_key);
    CHECK_VALUE_NULL(env);
    CHECK_VALUE_NULL(iot_id);
    CHECK_VALUE_NULL(entity_secret);

    atlas_set_loglevel(LOG_DEBUG_LEVEL);

    //@todo 预发环境调试设置接入总线云端地址
    if (0 == strcmp(env, "pre")) {
        atlas_set_server_addr(C_CNIOT_PROTOCOL_MQTT, 1, "ssl://ssl-preshiot.cainiao.com");
    }

    COPY_VALUE(g_core_env, env, C_MAX_ENV_LEN, strlen);

    CHECK_RETURN_VALUE(ret, atlas_get_https_address_from_env(g_core_env, g_core_host), L_BASE_ERROR);

    CHECK_MALLOC_VALUE(g_core_entity, atlas_malloc(sizeof(cniot_atlas_thing_entity_t)), L_BASE_ERROR, ret);

    CHECK_RETURN_VALUE(ret, _set_thing(g_core_entity, entity_name, entity_secret, thing_key, "" , iot_id), L_BASE_ERROR);

    CHECK_MALLOC_VALUE(g_core_mutex, atlas_mutex_create(), L_BASE_ERROR, ret);

    CHECK_RETURN_VALUE(ret, cniot_atlas_request_initialize(), L_REQUEST_ERROR);

    CHECK_RETURN_VALUE(ret, cniot_atlas_services_initialize(), L_SERVICE_ERROR);

    CHECK_RETURN_VALUE(ret, cniot_atlas_protocol_initialize(), L_PROTOCOL_ERROR);

    CHECK_RETURN_VALUE(ret, cniot_atlas_report_initialize(), L_REPORT_ERROR);

    CHECK_RETURN_VALUE(ret, cniot_atlas_scheduler_initialize(), L_SCHEDULER_ERROR);


    g_core_initialize = 1;
    return CNIOT_STATUS_CODE_OK;

L_SCHEDULER_ERROR:
    cniot_atlas_report_finalize();
L_REPORT_ERROR:
    cniot_atlas_protocol_finalize();
L_PROTOCOL_ERROR:
    cniot_atlas_services_finalize();
L_SERVICE_ERROR:
    cniot_atlas_request_finalize();
L_REQUEST_ERROR:
L_BASE_ERROR:
    if (g_core_mutex) {
        atlas_mutex_destroy(g_core_mutex);
        g_core_mutex = NULL;
    }
    if (g_core_entity) {
        atlas_free(g_core_entity);
        g_core_entity = NULL;
    }
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_finalize(){
    if (0 != g_core_startup) {
        return CNIOT_STATUS_NOT_SHUTDOWN;
    }
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    if (!g_core_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    cniot_atlas_scheduler_finalize();

    cniot_atlas_report_finalize();

    cniot_atlas_protocol_finalize();

    cniot_atlas_services_finalize();

    cniot_atlas_request_finalize();

    atlas_free(g_core_entity);
    g_core_entity = NULL;

    atlas_mutex_destroy(g_core_mutex);
    g_core_mutex = NULL;
    g_core_initialize = 0;

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_startup() {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_core_mutex);
    if (g_core_startup) {
        goto L_STARTUP_LOCK;
    }

    printf("start protocol\n");
    /*底层协议通道模块启动*/
    CHECK_RETURN_VALUE(ret, cniot_atlas_protocol_startup(), L_STARTUP_LOCK);

    /*请求管理模块启动*/
    printf("start request success, start request\n");
    CHECK_RETURN_VALUE(ret, cniot_atlas_request_startup(), L_REQUEST_STARTUP_ERROR);

    /*服务管理模块启动*/
    printf("start services success, start services\n");
    CHECK_RETURN_VALUE(ret, cniot_atlas_services_startup(), L_SERVICE_STARTUP_ERROR);

    /*汇报管理模块启动*/
    printf("start services success, start report\n");
    CHECK_RETURN_VALUE(ret, cniot_atlas_report_startup(), L_SERVICE_REPORT_ERROR);

    /*调度模块启动*/
    printf("start report success, start scheduler\n");
    CHECK_RETURN_VALUE(ret, cniot_atlas_scheduler_startup(), L_SERVICE_SCHEDULER_ERROR);

    printf("cniot startup success\n");
    g_core_startup = 1;
    atlas_mutex_unlock(g_core_mutex);
    return CNIOT_STATUS_CODE_OK;

L_SERVICE_SCHEDULER_ERROR:
    cniot_atlas_report_shutdown();
L_SERVICE_REPORT_ERROR:
    cniot_atlas_services_shutdown();
L_SERVICE_STARTUP_ERROR:
    cniot_atlas_request_shutdown();
L_REQUEST_STARTUP_ERROR:
    cniot_atlas_protocol_shutdown();
L_STARTUP_LOCK:
    atlas_mutex_unlock(g_core_mutex);
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_shutdown() {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_core_mutex);
    if (!g_core_startup) {
        goto L_SHUTDOWN_LOCK;
    }

    /*停止顺序和启动顺序相反*/
    CHECK_RETURN_VALUE(ret, cniot_atlas_scheduler_shutdown(), L_SHUTDOWN_LOCK);

    CHECK_RETURN_VALUE(ret, cniot_atlas_report_shutdown(),   L_SHUTDOWN_LOCK);

    CHECK_RETURN_VALUE(ret, cniot_atlas_services_shutdown(), L_SHUTDOWN_LOCK);

    CHECK_RETURN_VALUE(ret, cniot_atlas_request_shutdown(),  L_SHUTDOWN_LOCK);

    CHECK_RETURN_VALUE(ret, cniot_atlas_protocol_shutdown(), L_SHUTDOWN_LOCK);

    g_core_startup = 0;
 L_SHUTDOWN_LOCK:
    atlas_mutex_unlock(g_core_mutex);
    return ret;
}


CNIOT_STATUS_CODE atlas_thing_set_properties(const char *property) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char *rsp = NULL;
    int len = C_MAX_BODY_LEN;
    CHECK_VALUE_NULL(property);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    ret = atlas_check_isprint(property);
    if (ret != CNIOT_STATUS_CODE_OK) {
        logger_err("found receive property=%s is not json", property);
        return ret;
    }
    atlas_mutex_lock(g_core_mutex);
    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_BODY_LEN), L_ERROR, ret);
    CHECK_RETURN_VALUE(ret, cniot_atlas_write(g_core_entity, "property", property, rsp, &len), L_ERROR);
L_ERROR:
    atlas_free(rsp);
    atlas_mutex_unlock(g_core_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_thing_event_post(const char *event, const char *data){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char *rsp = NULL;
    int len = C_MAX_BODY_LEN;
    CHECK_VALUE_NULL(event);
    CHECK_VALUE_NULL(data);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    ret = atlas_check_isprint(data);
    if (ret != CNIOT_STATUS_CODE_OK) {
        logger_err("found receive property=%s is not json", data);
        return ret;
    }
    atlas_mutex_lock(g_core_mutex);
    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_BODY_LEN), L_ERROR, ret);
    CHECK_RETURN_VALUE(ret, cniot_atlas_write(g_core_entity, event, data, rsp, &len), L_ERROR);
L_ERROR:
    atlas_free(rsp);
    atlas_mutex_unlock(g_core_mutex);
    return ret;
}

CNIOT_STATUS_CODE  atlas_thing_event_post_with_https(const char *event, const char *data) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    int body_len = 0;
    char *body = NULL;
    char *rsp  = NULL;

    CHECK_VALUE_NULL(event);
    CHECK_VALUE_NULL(data);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    ret = atlas_check_isprint(data);
    if (ret != CNIOT_STATUS_CODE_OK) {
        logger_err("found receive property=%s is not json", data);
        return ret;
    }
    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/thing/eventPost.do", g_core_host);

    CHECK_RETURN_VALUE(ret, atlas_sign_by_thing_key(sign, C_MAX_SIGN_JSON_LEN,
                                                 1,
                                                 g_core_entity->thing_key,
                                                 g_core_entity->entity_name,
                                                 g_core_entity->entity_secret), L_FAILED);

    body_len = (int)strlen(data) + C_MAX_SIGNAL_LEN;
    CHECK_MALLOC_VALUE(body, atlas_malloc(body_len), L_FAILED, ret);

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    atlas_snprintf(body, body_len, "{%s"
                                         "\"eventName\":\"%s\","
                                         "\"version\":3,"
                                         "\"params\":%s"
                                         "}",
                   sign,  event, data);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, C_MAX_RSP_LEN), L_FAILED);

    CHECK_RETURN_VALUE(ret,_parse_event_post_rsp_data(rsp), L_FAILED);

L_FAILED:
    atlas_free(body);
    atlas_free(rsp);
    return ret;
}

CNIOT_STATUS_CODE atlas_thing_service_register(char *server_name, atlas_service_callback_fun_t fun, void *ptr){
    CHECK_VALUE_NULL(server_name);
    CHECK_VALUE_NULL(fun);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    return cniot_atlas_services_register(server_name, fun, ptr);
}

CNIOT_STATUS_CODE atlas_properties_change_register(atlas_service_callback_fun_t fun, void *ptr){
    CHECK_VALUE_NULL(fun);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    return cniot_atlas_services_register("propertySet", fun, ptr);
}

CNIOT_STATUS_CODE atlas_thing_service_unregister(char *server_name){
    CHECK_VALUE_NULL(server_name);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    return cniot_atlas_services_unregister(server_name);
}

static CNIOT_STATUS_CODE atlas_check_session_expire(char *data, char *sessionId) {
    lite_cjson_t root, node;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_CODE_OK;
    }
    n = lite_cjson_object_item(&root, "errorCode", strlen("errorCode"), &node);
    if (n < 0) {
        return CNIOT_STATUS_CODE_OK;
    }

    if (node.value && 0 == strncmp(node.value,  "SESSION_EXPIRE", strlen("SESSION_EXPIRE"))) {
        return CNIOT_STATUS_SESSION_EXPIRE;
    }

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_thing_service_invoking(const char *service,
                                               const char *bizKey,
                                               const char *params,
                                               char *rsp_buff,
                                               int rsp_buff_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char trace_id[C_MAX_ID_LEN] = {0};
    char session_id[C_MAX_ID_LEN] = {0};
    char request_Id[C_MAX_ID_LEN] = {0};
    uint64_t begin_time = atlas_abs_time();
    uint64_t boot_time = atlas_boot_uptime();
    uint32_t cost = 0;

    CHECK_VALUE_NULL(service);
    CHECK_VALUE_NULL(params);
    CHECK_VALUE_NULL(bizKey);
    CHECK_VALUE_NULL(rsp_buff);

    if (!g_core_entity) {
        logger_info("atlas core not initailize");
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    logger_debug("receive request service=%s bizKey=%s parm=%s", service, bizKey, params);

    ret = atlas_check_isprint(params);
    if (ret != CNIOT_STATUS_CODE_OK) {
        logger_err("found receive param=%s is not json", params);
        return ret;
    }

    CHECK_RETURN_VALUE(ret,  atlas_create_traceId(trace_id), L_FAILED);

    strncpy(request_Id,  trace_id, C_MAX_ID_LEN);

    CHECK_RETURN_VALUE(ret, atlas_protocol_invoker_service(service, params, request_Id, trace_id, session_id, bizKey, rsp_buff, rsp_buff_len), L_FAILED);

    ret = atlas_check_session_expire(rsp_buff, NULL);

L_FAILED:
    cost = (uint32_t)(atlas_boot_uptime() - boot_time);
    if (ret == CNIOT_STATUS_CODE_OK) {
        logger_debug("request success rsp=%s cost=%d", rsp_buff, cost);
    } else {
        logger_debug("request failed ret=0x%x cost=%d", ret,  cost);
    }

    cniot_atlas_report(REPORT_UPLOAD, "DEVICE_CLOUD_SERVICE", trace_id, begin_time, cost, params, ret);
    if (ret == CNIOT_STATUS_MSG_TIMEOUT) {
        cniot_atlas_build_failed_message(trace_id, cost, service, bizKey);
    }
    return ret;
}

CNIOT_STATUS_CODE atlas_thing_get_properties(const char *iotId, char *data, int data_len) {
    //根据环境获取控制台地址
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *rsp  = NULL;

    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    CHECK_VALUE_NULL(data);
    CHECK_VALUE_NULL(iotId);
    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/thing/property.do", g_core_host);

    CHECK_RETURN_VALUE(ret, atlas_sign_by_iot_id(sign, C_MAX_SIGN_JSON_LEN,
            g_core_entity->iot_id, g_core_entity->entity_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"version\":3,"
                                         "\"targetIotId\":\"%s\""
                                         "}",
                                         sign,  iotId);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, C_MAX_RSP_LEN), L_FAILED);

    CHECK_RETURN_VALUE(ret,_parse_properties_rsp_data(rsp,  data, data_len), L_FAILED);

L_FAILED:
    atlas_free(body);
    atlas_free(rsp);
    return ret;
}

CNIOT_STATUS_CODE atlas_thing_service_invoking_v2(const char *serviceName,
                                                  const char *params,
                                                  const char *bizKey,
                                                  char *requestId,
                                                  char *traceId,
                                                  char *sessionId,
                                                  char *rspBuff,
                                                  int rspBuffLen){

    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    uint64_t begin_time = atlas_abs_time();
    uint64_t boot_time = atlas_boot_uptime();
    uint32_t cost = 0;

    CHECK_VALUE_NULL(serviceName);
    CHECK_VALUE_NULL(params);
    CHECK_VALUE_NULL(requestId);
    CHECK_VALUE_NULL(bizKey);
    CHECK_VALUE_NULL(sessionId);
    CHECK_VALUE_NULL(traceId);
    CHECK_VALUE_NULL(rspBuff);

    if (!g_core_entity) {
        logger_info("atlas core not initialize");
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    logger_debug("receive request service=%s requestId=%s params=%s", serviceName, requestId, params);

    ret = atlas_check_isprint(params);
    if (ret != CNIOT_STATUS_CODE_OK) {
        logger_err("found receive params=%s is not json", params);
        return ret;
    }

    if (atlas_check_id_is_empty(traceId)) {
        CHECK_RETURN_VALUE(ret,  atlas_create_traceId(traceId), L_FAILED);
    }

    if (atlas_check_id_is_empty(requestId)) {
        strcpy(requestId, traceId);
    }

    CHECK_RETURN_VALUE(ret, atlas_protocol_invoker_service(serviceName, params, requestId, traceId, sessionId, bizKey, rspBuff, rspBuffLen), L_FAILED);

    ret = atlas_check_session_expire(rspBuff, sessionId);

L_FAILED:
    cost = (uint32_t)(atlas_boot_uptime() - boot_time);
    if (ret == CNIOT_STATUS_CODE_OK) {
        logger_debug("request success rsp=%s cost=%d", rspBuff, cost);
    } else {
        logger_debug("request failed ret=0x%x cost=%d", ret,  cost);
    }

    cniot_atlas_report(REPORT_UPLOAD, "DEVICE_CLOUD_SERVICE", traceId, begin_time, cost, params, ret);
    if (ret == CNIOT_STATUS_MSG_TIMEOUT) {
        cniot_atlas_build_failed_message(traceId, cost, serviceName, sessionId);
    }
    return ret;
}

CNIOT_STATUS_CODE atlas_thing_service_runtime_report(const char *identifier, const char *meta_data,
        const char *expression) {
    //根据环境获取控制台地址
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *rsp  = NULL;
    int n = 0;

    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    CHECK_VALUE_NULL(identifier);
    CHECK_VALUE_NULL(meta_data);
    CHECK_VALUE_NULL(expression);
    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/service/reportRuntimeService.do", g_core_host);

    CHECK_RETURN_VALUE(ret, atlas_sign_by_iot_id(sign, C_MAX_SIGN_JSON_LEN,
                                                 g_core_entity->iot_id, g_core_entity->entity_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"version\":3,"
                                         "\"productKey\":\"%s\","
                                         "\"deviceName\":\"%s\","
                                         "\"payload\":{"
                                         "\"identifier\":\"%s\","
                                         "\"serviceMetaData\":\"%s\","
                                         "\"expression\":\"%s\""
                                         "}}",
                   sign, g_core_entity->thing_key, g_core_entity->entity_name, identifier, meta_data, expression);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, C_MAX_RSP_LEN), L_FAILED);

    n = lite_cjson_parse(rsp, (int)strlen(rsp), &root);
    if (n < 0) {
        ret = CNIOT_STATUS_JSON_NOT_FORMAT;
        goto L_FAILED;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        ret= CNIOT_STATUS_JSON_NOT_FOUND_KEY;
        goto L_FAILED;
    }

    if (node.type == cJSON_False) {
        ret = CNIOT_STATUS_RSP_NOT_SUCCESS;
        goto L_FAILED;
    }

L_FAILED:
    atlas_free(body);
    atlas_free(rsp);
    return ret;
}


CNIOT_STATUS_CODE atlas_thing_service_runtime_query(char *data, int data_len) {
    //根据环境获取控制台地址
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *rsp  = NULL;
    int n = 0;

    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    CHECK_VALUE_NULL(data);
    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/service/queryRuntimeService.do", g_core_host);

    CHECK_RETURN_VALUE(ret, atlas_sign_by_iot_id(sign, C_MAX_SIGN_JSON_LEN,
                                                 g_core_entity->iot_id, g_core_entity->entity_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"version\":3,"
                                         "\"productKey\":\"%s\","
                                         "\"deviceName\":\"%s\","
                                         "\"payload\":{"
                                         "\"group\":\"tenant\","
                                         "\"pageSize\":20,"
                                         "\"pageIndex\":1"
                                         "}}",
                   sign, g_core_entity->thing_key, g_core_entity->entity_name);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, C_MAX_RSP_LEN), L_FAILED);

    n = lite_cjson_parse(rsp, (int)strlen(rsp), &root);
    if (n < 0) {
        ret = CNIOT_STATUS_JSON_NOT_FORMAT;
        goto L_FAILED;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        ret= CNIOT_STATUS_JSON_NOT_FOUND_KEY;
        goto L_FAILED;
    }

    if (node.type == cJSON_False) {
        ret = CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "services", data, data_len), L_FAILED);
L_FAILED:
    atlas_free(body);
    atlas_free(rsp);
    return ret;
}

static CNIOT_STATUS_CODE _parse_login_or_refresh_rsp(char *rsp,
                                                     char *session,
                                                     char *token,
                                                     char *msg) {
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    int n = lite_cjson_parse(rsp, (int)strlen(rsp), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "errorMsg", msg, C_MAX_ERROR_MSG_LEN), L_ERROR);
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "sessionId", session, C_MAX_SESSION_LEN), L_ERROR);

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "refreshToken", token, C_MAX_TOKEN_LEN), L_ERROR);

L_ERROR:
    return ret;
}


CNIOT_STATUS_CODE atlas_get_config(int config_version, char *config, int len){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *rsp = NULL;

    CHECK_VALUE_NULL(config);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/thing/ota/queryAppConfigItems.do", g_core_host);

    CHECK_RETURN_VALUE(ret, atlas_sign_by_thing_key(sign, C_MAX_SIGN_JSON_LEN,1, g_core_entity->thing_key,
            g_core_entity->entity_name,
            g_core_entity->entity_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);
    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"version\":3,"
                                         "\"payload\":{"
                                         "\"localConfigVersion\":%d"
                                         "}}",
                   sign, config_version);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, C_MAX_RSP_LEN), L_FAILED);

    CHECK_RETURN_VALUE(ret, _parse_configure_rsp_data(rsp, config, len), L_FAILED);

L_FAILED:
    atlas_free(body);
    atlas_free(rsp);
    return ret;
}

CNIOT_STATUS_CODE atlas_core_get_entity(cniot_atlas_thing_entity_t **entry) {
    CHECK_VALUE_NULL(entry);
    if (NULL == g_core_entity) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    *entry = g_core_entity;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_core_get_env(char ** env){
    CHECK_VALUE_NULL(env);
    *env = g_core_env;
    return CNIOT_STATUS_CODE_OK;;
}

CNIOT_STATUS_CODE atlas_core_get_addr(char ** host) {
    CHECK_VALUE_NULL(host);
    *host = g_core_host;
    return CNIOT_STATUS_CODE_OK;;
}

CNIOT_STATUS_CODE  atlas_get_network_status(C_CNIOT_NETWORK_STATUS *status){
    CHECK_VALUE_NULL(status);
    *status =  g_network_status;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE  atlas_check_network_disconnect(unsigned long long last_check_time, int *is_disconnect){
    CHECK_VALUE_NULL(is_disconnect);
    *is_disconnect = last_check_time < g_last_network_disconnect  ? 1 : 0;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_get_core_status(CNIOT_PROTOCOL *protocol, int *status, char addr[C_MAX_HOST_LEN]){
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CHECK_VALUE_NULL(protocol);
    CHECK_VALUE_NULL(status);
    CHECK_VALUE_NULL(addr);
    cniot_protocol_get_protocol(protocol);
    *status = 0;
    switch(*protocol) {
        case C_CNIOT_PROTOCOL_UNKNOW:
            return CNIOT_STATUS_CODE_OK;
        case C_CNIOT_PROTOCOL_MQTT:
        case C_CNIOT_PROTOCOL_COAP:
            cniot_protocol_get_addr(addr, status);
            break;
        default:
            break;
    }

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_set_server_addr(CNIOT_PROTOCOL protocol, int version, char *addr){
    return cniot_protocol_set_addr(protocol, version, addr);
}

CNIOT_STATUS_CODE cniot_atlas_site_bind(const char *env, const char *iot_id, const char *entity_secret,
                                        const char *spaceId, const char *spaceProductKey, const char *spaceCode, char *rsp, int rsp_len){
    char url[C_MAX_URL_LEN] = {0};
    char trace_id[C_MAX_ID_LEN] = {0};
    char host[C_MAX_HOST_LEN] = {0};
    char *body = NULL;
    char *sign = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    CHECK_VALUE_NULL(env);
    CHECK_VALUE_NULL(iot_id);
    CHECK_VALUE_NULL(entity_secret);
    CHECK_VALUE_NULL(rsp);

    if (rsp_len < C_RSP_DATA_LEN) {
        logger_err("site query input rsp_len is %d", rsp_len);
        return CNIOT_STATUS_PARMETER_OVERFOLW;
    }

    if (!spaceId && (!spaceProductKey || !spaceCode)) {
        logger_err("input parm spaceId and spaceProductKey and spaceCode is NULL");
        return CNIOT_STATUS_PARM_ERROR;
    }
    CHECK_RETURN_VALUE(ret, atlas_get_https_address_from_env(env, host), L_FAILED);
    logger_info("query host=%s iot_id =%s entity_secret=%s ", host, iot_id, entity_secret);

    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/thing/init.do", host);
    CHECK_RETURN_VALUE(ret, atlas_create_traceId(trace_id), L_FAILED);
    CHECK_MALLOC_VALUE(sign, atlas_malloc(C_MAX_SIGN_JSON_LEN), L_FAILED, ret);
    CHECK_RETURN_VALUE(ret, atlas_sign_by_iot_id(sign, C_MAX_SIGN_JSON_LEN, iot_id, entity_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    if (spaceId != NULL ){
        atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                             "\"version\":3,"
                                             "\"traceId\":\"%s\","
                                             "\"spaceId\":\"%s\"}", sign, trace_id, spaceId);
    } else {
        atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                             "\"version\":3,"
                                             "\"traceId\":\"%s\","
                                             "\"spaceProductKey\":\"%s\","
                                             "\"spaceCode\":\"%s\""
                                             "}", sign, trace_id, spaceProductKey, spaceCode);
    }

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, rsp_len), L_FAILED);
L_FAILED:
    atlas_free(sign);
    atlas_free(body);
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_site_query(const char *env,const char *iot_id, const char *entity_secret, char *rsp, int rsp_len){
    char url[C_MAX_URL_LEN] = {0};
    char trace_id[C_MAX_ID_LEN] = {0};
    char host[C_MAX_HOST_LEN] = {0};
    char *body = NULL;
    char *sign = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    CHECK_VALUE_NULL(env);
    CHECK_VALUE_NULL(iot_id);
    CHECK_VALUE_NULL(entity_secret);
    CHECK_VALUE_NULL(rsp);

    if (rsp_len < C_RSP_DATA_LEN) {
        logger_err("site query input rsp_len is %d", rsp_len);
        return CNIOT_STATUS_PARMETER_OVERFOLW;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_https_address_from_env(env, host), L_FAILED);
    logger_info("query host=%s iot_id =%s entity_secret=%s ", host, iot_id, entity_secret);

    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/thing/querySiteThing.do", host);
    CHECK_RETURN_VALUE(ret, atlas_create_traceId(trace_id), L_FAILED);
    CHECK_MALLOC_VALUE(sign, atlas_malloc(C_MAX_SIGN_JSON_LEN), L_FAILED, ret);
    CHECK_RETURN_VALUE(ret, atlas_sign_by_iot_id(sign, C_MAX_SIGN_JSON_LEN, iot_id, entity_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"version\":3,"
                                         "\"traceId\":\"%s\","
                                         "\"payload\":{"
                                         "\"iotId\":\"%s\""
                                         "}}", sign, trace_id, iot_id);

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, rsp_len), L_FAILED);
L_FAILED:
    atlas_free(sign);
    atlas_free(body);
    return ret;
}

CNIOT_STATUS_CODE atlas_set_network_status(C_CNIOT_NETWORK_STATUS status) {
    if (g_network_status != status) {
        if (status == NETWORK_STATUS_OFFLINE) {
            g_last_network_disconnect = atlas_boot_uptime();
        }
        printf("sdk receive network change:%s \n", status == NETWORK_STATUS_OFFLINE ? "offline": "online");
        g_network_status = status;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_get_diagnose_message(char *buff, int len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    printf("receive diagnose request buff_len=%d\n", len);
    if (!g_core_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CHECK_VALUE_NULL(buff);
    if (len < 1024){
        return CNIOT_STATUS_BUFFER_OVERFLOW;
    }
    ret = cniot_atlas_build_core_message(buff, &len);
    printf("process diagnose request ret=0x%x len=%d\n", ret, len);
    return ret;
}

static CNIOT_STATUS_CODE _parse_query_domain_rsp(char *rsp, CNIOT_ATLAS_DOMAIN_CODE *code) {
    lite_cjson_t root, node, result;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char domain[C_MAX_DOMAIN_LEN] = {0};
    int n = lite_cjson_parse(rsp, (int)strlen(rsp), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    n = lite_cjson_object_item(&root, "result", strlen("result"), &result);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&result, "domain", domain, C_MAX_DOMAIN_LEN), L_ERROR);
    if (0 == strcmp(domain,"ali")) {
        *code = CNIOT_ATLAS_DOMAIN_ALI;
    } else if (0 == strcmp(domain, "wutong")) {
        *code = CNIOT_ATLAS_DOMAIN_WUTONG;
    } else if (0 == strcmp(domain, "NotFound")) {
        *code = CNIOT_ATLAS_DOMAIN_UNKNOW;
    } else {
        return CNIOT_STATUS_NOT_SUPPORT;
    }
L_ERROR:
    return ret;
}

CNIOT_STATUS_CODE atlas_query_domain_by_deviceName(const char *thing_secret, const char *thing_key,
                                                   char entity_name[C_MAX_ID_LEN], CNIOT_ATLAS_DOMAIN_CODE *code){
    char url[C_MAX_URL_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *rsp = NULL;
    int rsp_len = C_MAX_RSP_LEN;

    CHECK_VALUE_NULL(thing_secret);
    CHECK_VALUE_NULL(thing_key);
    CHECK_VALUE_NULL(code);

    CNIOT_STATUS_CODE  ret = CNIOT_STATUS_CODE_OK;

    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/global/deviceQuery", "https://domain.iot.cainiao.com");

    CHECK_RETURN_VALUE(ret, atlas_sign_by_thing_key(sign, C_MAX_SIGN_JSON_LEN, 1, thing_key,entity_name, thing_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(rsp_len), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"traceId\":\"%s\"}", sign, "123");

    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, rsp, rsp_len), L_FAILED);

    CHECK_RETURN_VALUE(ret, _parse_query_domain_rsp(rsp, code), L_FAILED);

L_FAILED:
    atlas_free(body);
    atlas_free(rsp);
    return ret;
}

void atlas_set_wifi_roam_status(int roam_status) {
    if (0 == roam_status) {
        if (g_wifi_roam_status != 0) {
            g_wifi_roam_change_time = atlas_boot_uptime();
        }
    } else {
        if (0 == g_wifi_roam_status) {
            g_wifi_roam_change_time = atlas_boot_uptime();
        }
    }
    g_wifi_roam_status = roam_status;
}

int atlas_check_can_upload_log() {
    if (0 == g_wifi_roam_status ) {
        return 1;
    }
#define C_ROAM_MAX_TIMEOUT   (5 * 60 * 1000)
    if (g_wifi_roam_change_time + C_ROAM_MAX_TIMEOUT < atlas_boot_uptime() ) {
        return 1;
    }
    return 0;
}