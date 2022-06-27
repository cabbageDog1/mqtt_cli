#include <stdlib.h>
#include <stdio.h>
#include "atlas_utility.h"
#include "infra_cjson.h"
#include "report/atlas_report.h"
#include "edge/atlas_edge_cache.h"
#include "atlas_protocol.h"

#include "atlas_protocol_coap.h"
#include "atlas_protocol_mqtt.h"
#include "cniot_atlas_wrapper.h"
#include "logger/infra_log.h"
#include "services/atlas_services.h"

static char *g_module = {"protocol"};
static CNIOT_PROTOCOL g_protocol = C_CNIOT_PROTOCOL_UNKNOW;
static int g_protocol_version = 2;
static char  g_server_addr[C_MAX_HOST_LEN] = {0};
static uint64_t   g_last_edgeServer_req = 0;
static int g_edgeService_req_count = 0;
static void * g_protocol_mutex = NULL;
static int  g_is_fixed_addr = 0;
#define C_EDGE_SERVER_REQ_INTERVAL      (1000)
#define C_MAX_STEP_REQ_INTERVAL        (30 * 1000)

static CNIOT_STATUS_CODE __encode_clink_properties(char *buff, int buff_len, uint64_t time, const char *properties) {
    lite_cjson_t root, node, key, property;
    CHECK_VALUE_NULL(buff);
    CHECK_VALUE_NULL(properties);
    char propertyKey[C_MAX_ID_LEN] = {0};
    int i = 0;
    int len = 0;
    int n = lite_cjson_parse(properties, (int)strlen(properties), &root);
    if (n < 0) {
        logger_err("post properties is not json %s", properties);
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    len += atlas_snprintf(buff + len , buff_len - len, "{");
    while(1) {
        n = lite_cjson_object_item_by_index(&root, i, &key, &property);
        if (n < 0) {
            break;
        }
        if (0 != i) {
            len += atlas_snprintf(buff + len, buff_len, ",");
        }
        i++;
        COPY_JSON_VALUE(propertyKey, key, C_MAX_ID_LEN);
        len += atlas_snprintf(buff + len, buff_len - len, "\"%s\":{\"time\":%llu,\"value\":", propertyKey, time);
        if (property.type == cJSON_String) {
            len += atlas_snprintf(buff + len, buff_len - len, "\"");
        }
        COPY_JSON_VALUE(buff + len, property,  buff_len - len);
        len = (int)strlen(buff);
        if (property.type == cJSON_String) {
            len += atlas_snprintf(buff + len, buff_len - len, "\"");
        }
        len += atlas_snprintf(buff + len, buff_len, "}");
    }
    len += atlas_snprintf(buff + len, buff_len, "}");
    return CNIOT_STATUS_CODE_OK;
}

static CNIOT_STATUS_CODE __atlas_protocol_encode(cniot_atlas_thing_entity_t *entry, char *trace_id, const char *event, char * body, int body_len, const char *properties){
    CNIOT_STATUS_CODE ret =CNIOT_STATUS_CODE_OK;
    uint64_t abs_time = atlas_abs_time();
    uint64_t messageId = 0;
    char *enCodeBuff = NULL;

    CHECK_RETURN_VALUE(ret, atlas_create_traceId(trace_id), L_ERROR);
    CHECK_RETURN_VALUE(ret, atlas_create_messageId(&messageId), L_ERROR);

    if (g_protocol == C_CNIOT_PROTOCOL_MQTT) {
        if (g_protocol_version == 2) {
            if (0 != strcasecmp(event, "property")) {
                atlas_snprintf(body, body_len, "{\"traceId\":\"%s\","
                                               "\"requestId\":\"%s\","
                                               "\"id\":\"%llu\","
                                               "\"version\":\"1.0\","
                                               "\"method\":\"thing.event.%s.post\","
                                               "\"params\":{"
                                               "\"time\":%llu,"
                                               "\"value\":%s"
                                               "}}",
                               trace_id, trace_id, messageId, event, abs_time, properties);
            } else {
                CHECK_MALLOC_VALUE(enCodeBuff, atlas_malloc(C_MAX_INVOCATION_LEN), L_ERROR, ret);
                CHECK_RETURN_VALUE(ret, __encode_clink_properties(enCodeBuff, C_MAX_INVOCATION_LEN, abs_time, properties), L_ERROR);
                atlas_snprintf(body, body_len, "{\"traceId\":\"%s\","
                                               "\"requestId\":\"%s\","
                                               "\"id\":\"%llu\","
                                               "\"version\":\"1.0\","
                                               "\"method\":\"thing.event.property.post\","
                                               "\"params\":%s}",
                               trace_id, trace_id, messageId,  enCodeBuff);
            }
        } else {
            atlas_snprintf(body, body_len, "{\"traceId\":\"%s\","
                                           "\"messageId\":\"%llu\","
                                           "\"version\":\"1.0\","
                                           "\"time\":%llu,"
                                           "\"productKey\":\"%s\","
                                           "\"deviceName\":\"%s\","
                                           "\"event\":\"%s\","
                                           "\"iotId\":\"%s\", "
                                           "\"sync\":false, "
                                           "\"params\":%s}",
                           trace_id, messageId, abs_time, entry->thing_key, entry->entity_name, event,
                           entry->iot_id, properties);
        }
    } else if (g_protocol == C_CNIOT_PROTOCOL_COAP){
        if (0 == strncmp(event, "cloudService", sizeof("cloudService")) ||
            0 == strncmp(event, "loadResource", sizeof("loadResource")) ) {
            atlas_snprintf(body, body_len, "{\"traceId\":\"%s\","
                                           "\"version\":1,"
                                           "\"timestamp\":%llu,"
                                           "\"method\":\"%s\","
                                           "\"productKey\":\"%s\","
                                           "\"deviceName\":\"%s\","
                                           "\"iotId\":\"%s\", "
                                           "\"params\":%s}",
                           trace_id, abs_time, event, entry->thing_key, entry->entity_name, entry->iot_id, properties);
        } else {
            atlas_snprintf(body, body_len, "{\"traceId\":\"%s\","
                                           "\"version\":1,"
                                           "\"timestamp\":%llu,"
                                           "\"method\":\"event\","
                                           "\"event\":\"%s\","
                                           "\"productKey\":\"%s\","
                                           "\"deviceName\":\"%s\","
                                           "\"iotId\":\"%s\", "
                                           "\"params\":%s}",
                           trace_id, abs_time, event, entry->thing_key, entry->entity_name, entry->iot_id, properties);
        }

    } else {
        ret = CNIOT_STATUS_CONNECTING;
    }

L_ERROR:
    if (NULL != enCodeBuff) {
        atlas_free(enCodeBuff);
    }
    return ret;
}

static CNIOT_STATUS_CODE _parse_edge_services_resp_message(char *data) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    lite_cjson_t root, node, bus, device, protocols, protocol;
    int count = 0, supportMqtt = 0;
    atlas_bus_protocol_t *busProtocolPtr = NULL;

    CHECK_MALLOC_VALUE(busProtocolPtr, atlas_malloc(sizeof(atlas_bus_protocol_t)), L_FAILED, ret);

    int i = 0,  n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        logger_err("get edge services rsp not json data %s", data);
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        logger_err("get edge services rsp not found json success %s", data);
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        logger_err("get edge services rsp failed %s", data); //NO_RELATED_DATA_SPACE
        n = lite_cjson_object_item(&root, "errorCode", strlen("errorCode"), &node);
        if (n < 0) {
            logger_err("get edge services failed not found errorCode");
            return CNIOT_STATUS_RSP_NOT_SUCCESS;
        }
        if (node.value && 0 == strncmp(node.value, "NO_RELATED_DATA_SPACE", node.value_length)){
            cniot_atlas_post_core_event(CNIOT_EVENT_EDGE_ERROR, data);
            return CNIOT_STATUS_CODE_OK; //没有关联物流节点
        }
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    n = lite_cjson_object_item(&root, "result", strlen("result"), &node);
    if (n < 0) {
        logger_err("Get edge services rsp data not found json value devices");
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    n = lite_cjson_object_item(&node, "deviceGatewayResponses", strlen("deviceGatewayResponses"), &bus);
    if (n < 0) {
        logger_err("Get edge services rsp data not found json value devices");
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (0 < bus.size ) {
        i = (int)(atlas_boot_uptime() % bus.size);
        logger_info("start check edge service from %d", i);
        for (count = 0; count < bus.size; ++count) {
            if (bus.size <= ++i) {
                i = 0;
            }
            n = lite_cjson_array_item(&bus, i, &device);
            if (n < 0) {
                break;
            }
            n = lite_cjson_object_item(&device, "status", strlen("status"), &node);
            if (n < 0) {
                logger_err("Get edge services rsp data not found json value status");
                continue;
            }
            if (0 == strncmp(node.value, "offline", node.value_length)) {
                continue;
            }
            n = lite_cjson_object_item(&device, "protocolInfoList", strlen("protocolInfoList"), &protocols);
            if (n < 0 || protocols.size == 0) {
                continue;
            }

            for (int j = 0; j < protocols.size; ++j) {
                n = lite_cjson_array_item(&protocols, j, &protocol);
                if (n < 0) {
                    break;
                }
                memset(busProtocolPtr, 0, sizeof(atlas_bus_protocol_t));
                n = lite_cjson_object_item(&protocol, "protocol", strlen("protocol"), &node);
                if (n < 0) {
                    logger_err("Get edge services rsp data not found json value protocol");
                    continue;
                }

                COPY_JSON_VALUE(busProtocolPtr->protocol, node, C_MAX_PROTOCOL_LEN);

                if (0 == strcmp(busProtocolPtr->protocol, "mqtt")) {
                    if (0 == supportMqtt) {
                        atlas_edge_cache_clear();
                    }
                    supportMqtt = 1;
                } else {
                    if (0 != supportMqtt) {
                        continue;
                    }
                }

                n = lite_cjson_object_item(&protocol, "address", strlen("address"), &node);
                if (n < 0) {
                    logger_err("Get edge services rsp data not found json value address");
                    continue;
                }

                COPY_JSON_VALUE(busProtocolPtr->addr, node, C_MAX_URL_LEN);
                n = lite_cjson_object_item(&protocol, "version", strlen("version"), &node);
                if (n < 0) {
                    logger_err("Get edge services rsp data not found json value version");
                    continue;
                }
                COPY_JSON_VALUE(busProtocolPtr->version, node, C_MAX_VERSION_LEN);
                atlas_edge_cache_push(busProtocolPtr);
            }
        }
    }
L_FAILED:
    if (NULL != busProtocolPtr) {
        atlas_free(busProtocolPtr);
    }
    return ret;
}

static void __changeToMqtt() {
    char *env = NULL;
    atlas_core_get_env(&env);
    atlas_get_mqtt_address_from_env(env, g_server_addr);
    g_protocol = C_CNIOT_PROTOCOL_MQTT;
    logger_info("service change to mqtt addr=%s", g_server_addr);
}

static CNIOT_STATUS_CODE cniot_get_gateway_addr() {
    atlas_bus_protocol_t  busProtocol;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    while(1) {
        CHECK_RETURN_VALUE(ret, atlas_edge_cache_pop(&busProtocol), L_FAILED);
        if (NULL != strstr(busProtocol.protocol, "mqtt")) {
            strcpy(g_server_addr, busProtocol.addr);
            g_protocol = C_CNIOT_PROTOCOL_MQTT;
            g_protocol_version = atoi(busProtocol.version);
            printf("service change to mqtt addr=%s version=%d\n", g_server_addr, g_protocol_version);
        } else if (NULL != strstr(busProtocol.protocol, "coap")) {
            strcpy(g_server_addr, busProtocol.addr);
            g_protocol = C_CNIOT_PROTOCOL_COAP;
            g_protocol_version = atoi(busProtocol.version);
            printf("service change to coap addr=%s version=%d\n", g_server_addr, g_protocol_version);
        } else {
            logger_warning("not support protocol=%s", busProtocol.protocol);
            continue;
        }
        break;
    }
L_FAILED:
    return ret;
}

static CNIOT_STATUS_CODE cniot_atlas_unknow_proc() {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char *rsp = NULL;
    int is_edge = 0;
    atlas_bus_protocol_t  busProtocol;
    uint64_t now = atlas_boot_uptime();
    uint64_t step_interval = (C_EDGE_SERVER_REQ_INTERVAL* g_edgeService_req_count);
    if (step_interval  > C_MAX_STEP_REQ_INTERVAL) {
        step_interval = C_MAX_STEP_REQ_INTERVAL;
    }
    if (g_last_edgeServer_req + step_interval > now) {
        return CNIOT_STATUS_CODE_OK;
    }

    g_last_edgeServer_req = now;
#define C_MAX_REQUEST_FAILED_INTERVAL (3) // 使得操作更新流程
    if (g_edgeService_req_count < C_MAX_REQUEST_FAILED_INTERVAL) {
        g_edgeService_req_count++;
    }

    CHECK_MALLOC_VALUE(rsp, atlas_malloc(C_MAX_RSP_LEN), L_FAILED, ret);

    CHECK_RETURN_VALUE(ret, atlas_get_edge_service_list(rsp, C_MAX_RSP_LEN), L_FAILED);

    //保护线上服务器
    g_edgeService_req_count++;

    CHECK_RETURN_VALUE(ret, _parse_edge_services_resp_message(rsp), L_FAILED);

    CHECK_RETURN_VALUE(ret, cniot_get_gateway_addr(), L_FAILED);

L_FAILED:
    if (g_protocol != C_CNIOT_PROTOCOL_UNKNOW) {
        g_edgeService_req_count = 0;
    }
    atlas_free(rsp);
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_protocol_initialize(){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    g_protocol_mutex = atlas_mutex_create();
    CHECK_RETURN_VALUE(ret, cniot_atlas_edge_cache_initialize(), L_FAILED);
    CHECK_RETURN_VALUE(ret, cniot_atlas_knife_protocol_initialize(), L_FAILED);

    return CNIOT_STATUS_CODE_OK;

L_KNIFE_FAILED:
    cniot_atlas_edge_cache_finalize();
L_FAILED:
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_protocol_finalize(){
    atlas_mutex_destroy(g_protocol_mutex);
    cniot_atlas_edge_cache_finalize();
    cniot_atlas_knife_protocol_finalize();
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_protocol_startup(){
    cniot_atlas_knife_protocol_startup();
    return cniot_atlas_edge_cache_startup();
}

CNIOT_STATUS_CODE cniot_atlas_protocol_shutdown() {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    switch(g_protocol) {
        case C_CNIOT_PROTOCOL_MQTT:
            ret = cniot_atlas_mqtt_disconnect();
            break;
        case C_CNIOT_PROTOCOL_COAP:
            ret = cniot_atlas_coap_disconnect();
            break;
        default:
            break;
    }
    cniot_atlas_edge_cache_shutdown();
    cniot_atlas_knife_protocol_shutdown();
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_write(cniot_atlas_thing_entity_t *entity, const char *event, const char *data, char *rsp, int *rsp_len) {
    char *topic = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char trace_id[C_MAX_ID_LEN] = {0};
    char trace_msg[C_MAX_TRACE_MSG_LEN] = {0};
    char *body  = NULL;
    uint64_t  messageId;
    uint64_t beginTime = atlas_abs_time();
    uint64_t bootTime = atlas_boot_uptime();
    uint32_t cost = 0;

    CHECK_VALUE_NULL(entity);
    CHECK_VALUE_NULL(event);
    CHECK_VALUE_NULL(data);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN + strlen(data)), L_ERROR, ret);
    CHECK_RETURN_VALUE(ret, __atlas_protocol_encode(entity, trace_id, event, body, C_MAX_BODY_LEN + strlen(data), data), L_ERROR);
    switch(g_protocol) {
        case C_CNIOT_PROTOCOL_MQTT:
            CHECK_MALLOC_VALUE(topic, atlas_malloc(C_MAX_TOPIC_LEN), L_ERROR, ret);
            if (g_protocol_version == 2) {
                if (0 == strcasecmp(event, "property")){
                    atlas_snprintf(topic, C_MAX_TOPIC_LEN, "/%s/%s/property/post", entity->thing_key, entity->entity_name);
                } else {
                    atlas_snprintf(topic, C_MAX_TOPIC_LEN, "/%s/%s/event/%s/post", entity->thing_key, entity->entity_name, event);
                }
            } else {
                atlas_snprintf(topic, C_MAX_TOPIC_LEN, "/%s/%s/atlas/sys/update", entity->thing_key, entity->entity_name);
            }
            ret = cniot_atlas_mqtt_write(entity, topic, body);
            atlas_snprintf(trace_msg, C_MAX_TRACE_MSG_LEN, "protocol:mqtt, event:%s", event);
            break;
        case C_CNIOT_PROTOCOL_COAP:
//            atlas_mutex_lock(g_protocol_mutex);
            if (0 == strcmp(event, "loadResource")) {
                ret = cniot_atlas_coap_request("iot/edge", body, strlen(body), C_RSP_FORMAT_TEXT, rsp, rsp_len);
            } else {
                atlas_create_messageId(&messageId);
                ret = cniot_atlas_coap_invoking(messageId, body, strlen(body), rsp, *rsp_len);
            }
//            atlas_mutex_unlock(g_protocol_mutex);
            atlas_snprintf(trace_msg, C_MAX_TRACE_MSG_LEN, "protocol:coAP, event:%s", event);
            break;
        default:
            atlas_snprintf(trace_msg, C_MAX_TRACE_MSG_LEN, "protocol not init, system boot time: %lld event:%s", atlas_boot_uptime(),  event);
            ret = CNIOT_STATUS_CONNECTING;
            break;
    }
L_ERROR:
    cost = (uint32_t)(atlas_boot_uptime() - bootTime);
    if (0 == strcmp(event, "property")) {
        cniot_atlas_report(REPORT_UPLOAD, "DEVICE_PROPERTY_POST", trace_id,  beginTime, cost, trace_msg, ret);
    } else {
        cniot_atlas_report(REPORT_UPLOAD, "DEVICE_EVENT_POST", trace_id,  beginTime, cost, trace_msg, ret);
    }
    atlas_free(body);
    if (topic != NULL) {
        atlas_free(topic);
    }
    return ret;
}

static void check_server_status() {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    C_CNIOT_NETWORK_STATUS status;
    atlas_get_network_status(&status);
    if (0 == g_is_fixed_addr && status == NETWORK_STATUS_ONLINE) { // 如果没有固定mock或者网络状态是好的则切换地址
        if (ret != CNIOT_STATUS_NETWORK_DISCONNECTED) { //本地网络断开连接
            ret = cniot_get_gateway_addr();
            if (ret != CNIOT_STATUS_CODE_OK) {
                g_protocol = C_CNIOT_PROTOCOL_UNKNOW; //重新选择服务器.
            }
        }
    }
}

CNIOT_STATUS_CODE cniot_protocol_proc(uint32_t time) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    C_CNIOT_NETWORK_STATUS status;
    switch(g_protocol) {
        case C_CNIOT_PROTOCOL_MQTT:
            ret = cniot_atlas_mqtt_proc(g_server_addr, g_protocol_version, time);
            if (ret != CNIOT_STATUS_CODE_OK) {
                check_server_status();
            }
            break;
        case C_CNIOT_PROTOCOL_COAP:
            ret = cniot_atlas_coap_proc(g_server_addr, time);
            if (ret != CNIOT_STATUS_CODE_OK) {
                logger_err("coAP proc found error addr=%s ret=%d", g_server_addr, ret);
                atlas_mutex_lock(g_protocol_mutex);
                atlas_get_network_status(&status);
                cniot_atlas_coap_disconnect();
                check_server_status();
                atlas_mutex_unlock(g_protocol_mutex);
            }
            break;
        case C_CNIOT_PROTOCOL_UNKNOW:
            ret = cniot_atlas_unknow_proc();
            break;
        default:
            ret = CNIOT_STATUS_NOT_SUPPORT;
            break;
    }

    return ret;
}

static CNIOT_STATUS_CODE __send_service_rsp(lite_cjson_t *root, int sync, char *serviceName, CNIOT_STATUS_CODE rsp_code, char *rsp_parm) {
    cniot_atlas_thing_entity_t *entity = NULL;
    lite_cjson_t message_id, trace_id;
    int n = 0, len = 0;
    char *body = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    uint64_t abs_time = atlas_abs_time();
    char message_id_str[C_MAX_ID_LEN] = {0};
    char trace_id_str[C_MAX_ID_LEN] = {0};
    char *topic =NULL;

    //老版本协议属性下发不需要回复
    if (0 == strcasecmp(serviceName, "propertySet")) {
        return ret;
    }

    n = lite_cjson_object_item(root, "messageId", strlen("messageId"), &message_id);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    n = lite_cjson_object_item(root, "traceId", strlen("traceId"), &trace_id);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    COPY_JSON_VALUE(message_id_str, message_id, C_MAX_ID_LEN);
    COPY_JSON_VALUE(trace_id_str, trace_id, C_MAX_ID_LEN);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_ERROR, ret);

    CHECK_RETURN_VALUE(ret, atlas_core_get_entity(&entity), L_ERROR);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{\"success\":%s,"
                                         "\"errorCode\":\"%d\","
                                         "\"errorMsg\":\"%s\","
                                         "\"traceId\":\"%s\","
                                         "\"messageId\":\"%s\","
                                         "\"version\":\"1.0\","
                                         "\"time\":%llu,"
                                         "\"productKey\":\"%s\","
                                         "\"deviceName\":\"%s\","
                                         "\"iotId\":\"%s\","
                                         "\"sync\": true,"
                                         "\"params\":%s}",
                   rsp_code == CNIOT_STATUS_CODE_OK ? "true" :"false",
                   rsp_code, "",
                   trace_id_str,
                   message_id_str, abs_time, entity->thing_key,
                   entity->entity_name,
                   entity->iot_id, rsp_parm == NULL ? "{}": rsp_parm);


    CHECK_MALLOC_VALUE(topic, atlas_malloc(C_MAX_TOPIC_LEN), L_ERROR, ret );
    if (sync) {
        atlas_snprintf(topic,C_MAX_TOPIC_LEN, "/%s/%s/atlas/sys/update",entity->thing_key, entity->entity_name);
    } else {
        atlas_snprintf(topic,C_MAX_TOPIC_LEN, "/%s/%s/method/%s/async/response",entity->thing_key, entity->entity_name,serviceName);
    }
    ret = cniot_atlas_mqtt_write(entity, topic, body);

    logger_debug("send rsp ret=%d", ret);
L_ERROR:
    atlas_free(body);
    atlas_free(topic);
    return ret;
}

static CNIOT_STATUS_CODE __send_service_clink_rsp(lite_cjson_t *root, CNIOT_STATUS_CODE rsp_code, char *rsp_parm) {
    cniot_atlas_thing_entity_t *entity = NULL;
    lite_cjson_t message_id, trace_id, resp_topic, request_id;
    int n = 0;
    char *body = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char message_id_str[C_MAX_ID_LEN] = {0};
    char trace_id_str[C_MAX_ID_LEN] = {0};
    char request_id_str[C_MAX_ID_LEN] = {0};
    char topic_str[1024] = {0};

    n = lite_cjson_object_item(root, "id", strlen("id"), &message_id);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    n = lite_cjson_object_item(root, "traceId", strlen("traceId"), &trace_id);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    n = lite_cjson_object_item(root, "requestId", strlen("requestId"), &request_id);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    n = lite_cjson_object_item(root, "responseTopic", strlen("responseTopic"), &resp_topic);
    if (0 <= n) {
        COPY_JSON_VALUE(topic_str, resp_topic, 1024);
    }

    COPY_JSON_VALUE(message_id_str, message_id, C_MAX_ID_LEN);
    COPY_JSON_VALUE(trace_id_str, trace_id, C_MAX_ID_LEN);
    COPY_JSON_VALUE(request_id_str, request_id, C_MAX_ID_LEN);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_ERROR, ret);


    atlas_snprintf(body, C_MAX_BODY_LEN, "{"
                                         "\"code\":%d,"
                                         "\"id\":\"%s\","
                                         "\"traceId\":\"%s\","
                                         "\"requestId\":\"%s\","
                                         "\"data\":%s}",
                   rsp_code == CNIOT_STATUS_CODE_OK ? 200 : rsp_code ,message_id_str,
                   trace_id_str, request_id_str, rsp_parm == NULL ? "{}": rsp_parm);

    if (0 < strlen(topic_str)) {
        ret = cniot_atlas_mqtt_write(entity, topic_str, body);
    }

    logger_debug("send rsp ret=%d", ret);
 L_ERROR:
    atlas_free(body);
    return ret;
}

static CNIOT_STATUS_CODE _parse_invoking_rsp_data(char *data, int data_len, char *sessionId) {
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

    n = lite_cjson_object_item(&root, "sessionId", strlen("sessionId"), &node);
    if (n >= 0) {
        COPY_JSON_VALUE(sessionId, node, C_MAX_ID_LEN);
    }

    n = lite_cjson_object_item(&root, "bizResponse", strlen("bizResponse"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    if (NULL == node.value ) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    if (data_len + 1 < node.value_length) {
        return CNIOT_STATUS_PARMETER_OVERFOLW;
    }
    memmove(data, node.value, node.value_length);
    data[node.value_length] = '\0';
    return ret;
}


static CNIOT_STATUS_CODE _parse_invoking_rsp_v2(char *data, int data_len, char *sessionId) {
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "code", strlen("code"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.value_int != 200) {
        logger_err("receive code not success code=%d", node.value_int);
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    n = lite_cjson_object_item(&root, "sessionId", strlen("sessionId"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    COPY_JSON_VALUE(sessionId, node, C_MAX_ID_LEN);

    n = lite_cjson_object_item(&root, "data", strlen("data"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    if (NULL == node.value ) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    if (data_len + 1 < node.value_length) {
        return CNIOT_STATUS_PARMETER_OVERFOLW;
    }
    memmove(data, node.value, node.value_length);
    data[node.value_length] = '\0';
    return ret;
}

CNIOT_STATUS_CODE cniot_protocol_process_method_v1(const char *data, int data_len){
    lite_cjson_t root, node;
    char server_name[C_MAX_SERVICE_NAME] = {0};
    char trace_id[C_MAX_ID_LEN] = {0};
    char *rsp = NULL;
    atlas_service_callback_fun_t fun = NULL;
    void *pHandle = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    uint64_t beginTime = atlas_abs_time(), bootTime = atlas_boot_uptime();
    uint32_t cost = 0;
    int n = lite_cjson_parse(data, data_len, &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }

    n = lite_cjson_object_item(&root, "service", strlen("service"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    COPY_JSON_VALUE(server_name, node, C_MAX_SERVICE_NAME);

    CHECK_RETURN_VALUE(ret,cniot_atlas_get_service(server_name, &fun, &pHandle), L_ERROR);

    n = lite_cjson_object_item(&root, "params", strlen("params"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    ret = fun(pHandle, node.value, node.value_length, &rsp);

    n = lite_cjson_object_item(&root, "sync", strlen("sync"), &node);

    __send_service_rsp(&root,n >= 0 && node.type == cJSON_True, server_name, ret, rsp); //coAP not need send rsp

    n = lite_cjson_object_item(&root, "traceId", strlen("traceId"), &node);
    if (n >= 0) {
        COPY_JSON_VALUE(trace_id, node, C_MAX_ID_LEN);
    } else {
        atlas_create_traceId(trace_id);
    }

L_ERROR:
    cost = atlas_boot_uptime() - bootTime;
    cniot_atlas_report(REPORT_DOWNLOAD, "DEVICE_RRPC_SERVICE", trace_id,  beginTime, cost, server_name, ret);
    atlas_free(rsp);
    return ret;
}

CNIOT_STATUS_CODE cniot_protocol_process_method_v2(const char *data, int data_len){
    lite_cjson_t root, node;
    char methodName[C_MAX_SERVICE_NAME] = {0};
    char trace_id[C_MAX_ID_LEN] = {0};
    char *rsp = NULL;
    char *methodPtr = NULL;
    atlas_service_callback_fun_t fun = NULL;
    void *pHandle = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    uint64_t beginTime = atlas_abs_time(), bootTime = atlas_boot_uptime();
    uint32_t cost = 0;
    int n = lite_cjson_parse(data, data_len, &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }

    n = lite_cjson_object_item(&root, "method", strlen("method"), &node);
    if (n < 0) {
        logger_err("protocol v2 receive not found method key");
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    COPY_JSON_VALUE(methodName, node, C_MAX_SERVICE_NAME);

    methodPtr = strstr(methodName, "thing.method.");
    if (methodPtr == NULL) {
        logger_err("protocol v2 receive err method=%s, not support", methodName);
        return CNIOT_STATUS_NOT_SUPPORT;
    }
    methodPtr += strlen("thing.method.");

    CHECK_RETURN_VALUE(ret,cniot_atlas_get_service(methodPtr, &fun, &pHandle), L_ERROR);

    n = lite_cjson_object_item(&root, "params", strlen("params"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    ret = fun(pHandle, node.value, node.value_length, &rsp);

    __send_service_clink_rsp(&root, ret, rsp);

    n = lite_cjson_object_item(&root, "traceId", strlen("traceId"), &node);
    if (n >= 0) {
        COPY_JSON_VALUE(trace_id, node, C_MAX_ID_LEN);
    } else {
        atlas_create_traceId(trace_id);
    }

L_ERROR:
    cost = atlas_boot_uptime() - bootTime;
    cniot_atlas_report(REPORT_DOWNLOAD, "DEVICE_RRPC_SERVICE", trace_id,  beginTime, cost, methodName, ret);
    atlas_free(rsp);
    return ret;
}

CNIOT_STATUS_CODE cniot_protocol_process_properties_change(const char *data, int data_len){
    lite_cjson_t root, node;
    char trace_id[C_MAX_ID_LEN] = {0};
    char *rsp = NULL;
    atlas_service_callback_fun_t fun = NULL;
    void *pHandle = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    uint64_t beginTime = atlas_abs_time(), bootTime = atlas_boot_uptime();
    uint32_t cost = 0;
    int n = lite_cjson_parse(data, data_len, &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }

    CHECK_RETURN_VALUE(ret,cniot_atlas_get_service("propertySet", &fun, &pHandle), L_ERROR);

    n = lite_cjson_object_item(&root, "params", strlen("params"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    ret = fun(pHandle, node.value, node.value_length, &rsp);

    __send_service_clink_rsp(&root, ret, rsp);

    n = lite_cjson_object_item(&root, "traceId", strlen("traceId"), &node);
    if (n >= 0) {
        COPY_JSON_VALUE(trace_id, node, C_MAX_ID_LEN);
    } else {
        atlas_create_traceId(trace_id);
    }

    L_ERROR:
    cost = atlas_boot_uptime() - bootTime;
    cniot_atlas_report(REPORT_DOWNLOAD, "DEVICE_RRPC_SERVICE", trace_id,  beginTime, cost, "propertySet", ret);
    atlas_free(rsp);
    return ret;
}

static CNIOT_STATUS_CODE __adapter_invoking_rsp(char *data) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    lite_cjson_t root, node;
    int i = 0;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        logger_err("invoking cloud server failed %s", data);
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    n = lite_cjson_object_item(&root, "params", strlen("params"), &node);
    if (n < 0) {
        logger_err("not found json value params");
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (NULL == node.value ) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    memmove(data, node.value, node.value_length);
    data[node.value_length] = '\0';
    return CNIOT_STATUS_CODE_OK;
}
CNIOT_STATUS_CODE cniot_stats_server_binary_data_invoking(char *data, char *rsp, int rsp_len) {
    char url[C_MAX_URL_LEN] = {0};
    char *body = NULL;
    char *host = NULL;
    int body_len = C_MAX_BINARY_DATA_LEN;
    CNIOT_STATUS_CODE  ret = CNIOT_STATUS_CODE_OK;

    CHECK_VALUE_NULL(data);
    CHECK_VALUE_NULL(rsp);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BINARY_DATA_LEN), L_FAILED, ret);
    atlas_core_get_addr(&host);
    atlas_snprintf(url, C_MAX_URL_LEN, "%s/iot/service/invoke.do", host);
    CHECK_RETURN_VALUE(ret, atlas_knife_protocol_encode(data, body, &body_len), L_FAILED);
    CHECK_RETURN_VALUE(ret, atlas_https_post_binary_data(url, body, body_len, C_HTTP_TIME_OUT, rsp, rsp_len), L_FAILED);
 L_FAILED:
    atlas_free(body);
    data = NULL;
    return ret;
}

CNIOT_STATUS_CODE atlas_protocol_invoker_service(const char *serviceName,
        const char *params, const char *requestId, const char *traceId,
        char *sessionId,const char *bizKey, char *rsp, int rsp_len){

    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char *body = NULL, *binary_buff = NULL;
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    int binary_data_len = C_MAX_BINARY_DATA_LEN;
    cniot_atlas_thing_entity_t *entity = NULL;
    uint64_t messageId = 0;
    char *invocation = NULL;
    int invocationLen = C_MAX_INVOCATION_LEN;

    if (g_protocol != C_CNIOT_PROTOCOL_MQTT && g_protocol != C_CNIOT_PROTOCOL_COAP) {
        return CNIOT_STATUS_CONNECTING;
    }

    CHECK_MALLOC_VALUE(body,atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);
    atlas_core_get_entity(&entity);

    CHECK_RETURN_VALUE(ret, atlas_sign_by_thing_key(sign, C_MAX_SIGN_JSON_LEN, 1, entity->thing_key,
                                                    entity->entity_name,
                                                    entity->entity_secret), L_FAILED);

    invocationLen = strlen(params) + C_MAX_SIGN_JSON_LEN;

    CHECK_MALLOC_VALUE(invocation, atlas_malloc(invocationLen), L_FAILED, ret);
    atlas_snprintf(invocation, invocationLen, "{\"traceId\":\"%s\""
                                              ",\"serviceUniqueName\":\"%s\""
                                              ",\"version\":\"3.0\""
                                              ",\"bizKey\":\"%s\""
                                              ",\"params\":%s}",
                                              traceId, serviceName, bizKey, params);

    if (g_protocol == C_CNIOT_PROTOCOL_MQTT) {
        CHECK_RETURN_VALUE(ret, atlas_create_messageId(&messageId), L_FAILED);
        if (g_protocol_version == 2) {
            atlas_snprintf(body, C_MAX_BODY_LEN, "{"
                                                 "\"responseTopic\":\"/%s/%s/rpc/sync/response\","
                                                 "\"requestId\":\"%s\","
                                                 "\"traceId\":\"%s\","
                                                 "\"id\":\"%llu\","
                                                 "\"sessionId\":\"%s\","
                                                 "\"bizKey\":\"%s\","
                                                 "\"version\":\"1.0\","
                                                 "\"method\":\"thing.rpc.%s\","
                                                 "\"serviceName\":\"%s\","
                                                 "\"params\":%s}",
                                                 entity->thing_key,entity->entity_name,
                                                 requestId,
                                                 traceId,
                                                 messageId,
                                                 sessionId,
                                                 bizKey,
                                                 serviceName,
                                                 serviceName,
                                                 params);
            logger_debug("mqtt invoking server request body=%s", body);
        } else {
            atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                                 "\"version\":\"2.0\","
                                                 "\"sync\":false,"
                                                 "\"time\":%llu,"
                                                 "\"requestId\":\"%s\","
                                                 "\"sessionId\":\"%s\","
                                                 "\"traceId\":\"%s\","
                                                 "\"messageId\":\"%llu\","
                                                 "\"Invocation\":%s}", sign, atlas_abs_time(),
                                                 requestId,sessionId, traceId,  messageId, invocation);
            logger_debug("mqtt invoking server request body=%s", body);
        }
        if (CNIOT_STATUS_CODE_OK == atlas_knife_check(params)) {
            CHECK_MALLOC_VALUE(binary_buff, atlas_malloc(binary_data_len), L_FAILED, ret);
            CHECK_RETURN_VALUE(ret, atlas_knife_protocol_encode(body, binary_buff, &binary_data_len), L_FAILED);
            CHECK_RETURN_VALUE(ret, cniot_atlas_mqtt_invoking(entity, messageId, binary_buff, binary_data_len,  rsp, rsp_len), L_FAILED);
        } else {
            CHECK_RETURN_VALUE(ret,cniot_atlas_mqtt_invoking(entity, messageId, body, strlen(body),  rsp, rsp_len), L_FAILED);
        }
        if (g_protocol_version == 1) {
            CHECK_RETURN_VALUE(ret, _parse_invoking_rsp_data(rsp, rsp_len, sessionId), L_FAILED);
        } else {
            CHECK_RETURN_VALUE(ret, _parse_invoking_rsp_v2(rsp, rsp_len, sessionId), L_FAILED);
        }
    } else if (g_protocol == C_CNIOT_PROTOCOL_COAP) {
        if (CNIOT_STATUS_CODE_OK == atlas_knife_check(params)) {
            return CNIOT_STATUS_NOT_SUPPORT;
        }
        atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                             "\"iotId\":\"%s\","
                                             "\"version\":2,"
                                             "\"method\":\"invokeService\","
                                             "\"invocation\":%s}", sign, entity->iot_id,  invocation);
        logger_debug("coAP invoking server request body=%s", body);
        ret = cniot_atlas_coap_invoking(messageId, body, strlen(body), rsp, rsp_len);
        if (ret != CNIOT_STATUS_CODE_OK) {
            logger_err("coAP request failed, invocation=%s ret=%d", invocation,  ret);
            goto L_FAILED;
        }
        ret = __adapter_invoking_rsp(rsp);
        if (ret != CNIOT_STATUS_CODE_OK) {
            logger_err("coAP request failed, payload data is error, invocation=%s rsp=%s", invocation,  rsp);
        }
    } else {
        ret = CNIOT_STATUS_CONNECTING;
    }

L_FAILED:
    atlas_free(body);
    atlas_free(invocation);
    atlas_free(binary_buff);
    return ret;
}

CNIOT_STATUS_CODE atlas_get_edge_service_list(char *buf, int buf_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char url[C_MAX_URL_LEN] = {0};
    char trace_id [C_MAX_ID_LEN] = {0};
    char sign[C_MAX_SIGN_JSON_LEN] = {0};
    char *body = NULL;
    char *env = NULL;
    char host[C_MAX_HOST_LEN] = {0};
    uint64_t start = 0, end = 0;
    cniot_atlas_thing_entity_t *entity = NULL;


    CHECK_RETURN_VALUE(ret, atlas_core_get_env(&env), L_FAILED);

    CHECK_RETURN_VALUE(ret, atlas_core_get_entity(&entity), L_FAILED);
    CHECK_RETURN_VALUE(ret, atlas_get_registerSrv_address(env, host), L_FAILED);

    atlas_snprintf(url, C_MAX_URL_LEN, "%s/global/server/findDeviceGateway", host);

    logger_warning("start get edge service list url=%s\n", url);

    CHECK_RETURN_VALUE(ret, atlas_create_traceId(trace_id), L_FAILED);
    CHECK_RETURN_VALUE(ret, atlas_sign_by_thing_key(sign, C_MAX_SIGN_JSON_LEN,1,
            entity->thing_key,entity->entity_name,entity->entity_secret), L_FAILED);

    CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);

    atlas_snprintf(body, C_MAX_BODY_LEN, "{%s"
                                         "\"version\":3,"
                                         "\"traceId\":\"%s\"}",sign, trace_id, entity->iot_id);

    logger_info("get edge service list body len=%d\n", (int)strlen(body));

    start = atlas_boot_uptime();
    CHECK_RETURN_VALUE(ret,atlas_https_post(url, body, C_HTTP_TIME_OUT, buf, buf_len), L_FAILED);
    end = atlas_boot_uptime();
    printf("Get edge service list success cost %llu ms\n", end - start);

    logger_info("get edge service list success:%s", buf);
L_FAILED:
    atlas_free(body);
    return ret;
}

CNIOT_STATUS_CODE cniot_protocol_get_protocol(CNIOT_PROTOCOL *protocol){
    *protocol = g_protocol;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_protocol_get_addr(char *addr, int *status){
    CHECK_VALUE_NULL(status);
    CHECK_VALUE_NULL(addr);
    atlas_mutex_lock(g_protocol_mutex);
    memcpy(addr, g_server_addr, C_MAX_HOST_LEN);
    atlas_mutex_unlock(g_protocol_mutex);
    if (g_protocol == C_CNIOT_PROTOCOL_COAP) {
        cniot_atlas_get_coap_status(status);
    } else if (g_protocol == C_CNIOT_PROTOCOL_MQTT) {
        cniot_stlas_mqtt_status(status);
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_protocol_set_addr(int protocol, int version, char *addr){
    switch(g_protocol) {
        case C_CNIOT_PROTOCOL_COAP:
        case C_CNIOT_PROTOCOL_MQTT:
            return CNIOT_STATUS_NOT_SUPPORT;
        case C_CNIOT_PROTOCOL_UNKNOW:
            g_protocol = protocol;
            strcpy(g_server_addr, addr);
            g_is_fixed_addr = 1;
            g_protocol_version = version;
            logger_info("set mock protocol=%d addr=%s", protocol, addr);
            break;
        default:
            return CNIOT_STATUS_NOT_SUPPORT;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE  atlas_binary_data_encode(const void *data, int data_len, char *parm) {
    int type = 0;
    return atlas_knife_parm_encode(data, data_len, parm, &type);
}

CNIOT_STATUS_CODE  atlas_binary_data_free(char *data) {
    return atlas_knife_parm_finalize(data);
}