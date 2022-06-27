#include <string.h>
#include "infra_cjson.h"
#include "services/atlas_services.h"
#include "infra_compat.h"
#include "atlas_utility.h"
#include "report/atlas_report.h"
#include "atlas_protocol_mqtt.h"
#include "mqtt_wrapper.h"
#include "logger/infra_log.h"
#include "cniot_atlas_wrapper.h"
#include "../atlas_protocol.h"
#include "request/atlas_request.h"

static void *g_mqtt_client  = NULL;
static char *g_module = {"mqtt"};
extern const char *iotx_ca_crt;
static uint64_t g_last_connect_time = 0;
static uint64_t g_disconnect_time = 0;
static char g_mqtt_userName[C_MAX_USER_NAME_LEN] = {0};
static char g_mqtt_clientId[C_MAX_CLIENT_ID_LEN] = {0};
static char g_mqtt_pwd[C_MAX_SIGN_LEN] = {0};
static int  g_mqtt_subscribe = 0;
static int  g_mqtt_protocol_version=1;

static CNIOT_STATUS_CODE _mqtt_init(void ** pClient, iotx_mqtt_param_t *param) {
    *pClient = wrapper_mqtt_init(param);
    if (NULL == *pClient) {
        return CNIOT_STATUS_MQTT_INIT_FAILED;
    }
    return CNIOT_STATUS_CODE_OK;
}

static CNIOT_STATUS_CODE _mqtt_connect(void * pClient) {
    int ret = wrapper_mqtt_connect(pClient);
    if (ret < 0) {
        logger_err("mqtt connect failed ret=%d", ret);
        return CNIOT_STATUS_MQTT_CONNECT_FAILED;
    }
    return CNIOT_STATUS_CODE_OK;
}

static void _invoker_method_receive_v1(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg) {
    iotx_mqtt_topic_info_t     *topic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            logger_debug("receive data_len=%d data %s", topic_info->payload_len, topic_info->payload);
            cniot_protocol_process_method_v1(topic_info->payload, topic_info->payload_len);
            break;
        default:
            break;
    }
}

static void _invoker_method_receive_v2(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg) {
    iotx_mqtt_topic_info_t     *topic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            logger_debug("protocol v2 receive data_len=%d data %s", topic_info->payload_len, topic_info->payload);
            cniot_protocol_process_method_v2(topic_info->payload, topic_info->payload_len);
            break;
        default:
            break;
    }
}

static void _property_set_receive(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg) {
    iotx_mqtt_topic_info_t     *topic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            logger_debug("receive data_len=%d data %s", topic_info->payload_len, topic_info->payload);
            cniot_protocol_process_properties_change(topic_info->payload, topic_info->payload_len);
            break;
        default:
            break;
    }
}

static CNIOT_STATUS_CODE __rpc_process(const char *data, int protocol_version, int len) {
    lite_cjson_t root;
    int n = 0;
    uint64_t mId = 0;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char messageId[C_MAX_ID_LEN] = {0};
    n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        logger_err("receive rpc data rsp not json data len=%d", len);
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }

    if (protocol_version == 1) {
        CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "messageId", messageId, C_MAX_ID_LEN), L_FAILED);
    } else if (protocol_version == 2) {
        CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "id", messageId, C_MAX_ID_LEN), L_FAILED);
    } else {
        logger_err("protocol version =%d not support", protocol_version);
        return CNIOT_STATUS_NOT_SUPPORT;
    }
    mId = (uint64_t)(atoll(messageId));
    atlas_set_response(mId, data, len);
L_FAILED:
    return ret;
}

static void _rpc_response_receive_v1(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg) {
    iotx_mqtt_topic_info_t    *topic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            logger_debug("protocol v1 rpc receive data_len=%d data %s", topic_info->payload_len, topic_info->payload);
            __rpc_process(topic_info->payload, 1, topic_info->payload_len);
            break;
        default:
            break;
    }
}

static void _rpc_response_receive_v2(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg) {
    iotx_mqtt_topic_info_t    *topic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            logger_debug("protocol v2 rpc receive data_len=%d data %s", topic_info->payload_len, topic_info->payload);
            __rpc_process(topic_info->payload, 2, topic_info->payload_len);
            break;
        default:
            break;
    }
}

static void __mqtt_configure_receive(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg) {
    iotx_mqtt_topic_info_t    *topic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            logger_debug("configure receive data_len=%d data %s", topic_info->payload_len, topic_info->payload);
            break;
        default:
            break;
    }
}

static void __mqtt_client_receive(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg) {
    iotx_mqtt_topic_info_t     *topic_info = (iotx_mqtt_topic_info_pt) msg->msg;
    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            logger_debug("client receive data_len=%d data %s", topic_info->payload_len, topic_info->payload);
            break;
        case IOTX_MQTT_EVENT_PUBLISH_SUCCESS:
            logger_info("client publish success receive ack");
            break;
        case IOTX_MQTT_EVENT_DISCONNECT:
            cniot_atlas_post_core_event(CNIOT_EVENT_DISCONNECT, "mqtt disconnect");
            logger_err("mqtt disconnect");
            g_disconnect_time = atlas_boot_uptime();
            g_mqtt_subscribe = 0;
            break;
        case IOTX_MQTT_EVENT_RECONNECT:
            cniot_atlas_post_core_event(CNIOT_EVENT_CONNECTED, "mqtt connected");
            logger_err("mqtt reconnect success");
            g_disconnect_time = 0;
            break;
        case IOTX_MQTT_EVENT_SUBCRIBE_SUCCESS:
            logger_info("subscribe %d success\n", g_mqtt_subscribe);
            g_mqtt_subscribe++;
            break;
        case IOTX_MQTT_EVENT_SUBCRIBE_NACK:
            logger_err("subscribe %d failed\n", g_mqtt_subscribe);
            if (0 < g_mqtt_subscribe){
                g_mqtt_subscribe--;
            }
            break;
        default:
            break;
    }
}

static CNIOT_STATUS_CODE _mqtt_subscribe(char * topic, iotx_mqtt_event_handle_func_fpt funcFpt) {
    int ret = wrapper_mqtt_subscribe(g_mqtt_client, topic,
                                     IOTX_MQTT_QOS1,  // QOS2 没有实现
                                     funcFpt,
                                     NULL);
    if (ret < 0) {
        logger_err("mqtt subscribe topic %s failed ret=%d", topic, ret);
        return CNIOT_STATUS_MQTT_SUBSCRIBE_FAILED;
    }

    logger_info("mqtt send subscribe topic %s success", topic);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE __check_topic_subscribe(){
    char topic[CONFIG_MQTT_TOPIC_MAXLEN] = {0};
    cniot_atlas_thing_entity_t * entity = NULL;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    if (0 != g_disconnect_time) {
        return CNIOT_STATUS_CONNECTING;
    }

    switch(g_mqtt_subscribe) {
        case 0:
            atlas_core_get_entity(&entity);
            if (g_mqtt_protocol_version == 1 || g_mqtt_protocol_version == 2) {
                if (g_mqtt_protocol_version == 1) {
                    atlas_snprintf(topic, CONFIG_MQTT_TOPIC_MAXLEN, "/%s/%s/rpc/response",
                                   entity->thing_key, entity->entity_name);
                    ret = _mqtt_subscribe(topic, _rpc_response_receive_v1);
                } else {
                    atlas_snprintf(topic, CONFIG_MQTT_TOPIC_MAXLEN, "/%s/%s/rpc/sync/response",
                                   entity->thing_key, entity->entity_name);
                    ret = _mqtt_subscribe(topic, _rpc_response_receive_v2);
                }
            }
            if (ret == CNIOT_STATUS_CODE_OK) {
                g_mqtt_subscribe++;
            }
            break;
        case 2:
            atlas_core_get_entity(&entity);
            if (g_mqtt_protocol_version == 1 ) {
                atlas_snprintf(topic, CONFIG_MQTT_TOPIC_MAXLEN, "/%s/%s/atlas/sys/get",
                               entity->thing_key, entity->entity_name);
                ret = _mqtt_subscribe(topic, _invoker_method_receive_v1);
            } else if (g_mqtt_protocol_version == 2) {
                atlas_snprintf(topic, CONFIG_MQTT_TOPIC_MAXLEN, "/%s/%s/method/+/+/request",
                               entity->thing_key, entity->entity_name);
                ret = _mqtt_subscribe(topic, _invoker_method_receive_v2);
            }
            if (ret == CNIOT_STATUS_CODE_OK) {
                g_mqtt_subscribe++;
            }
            break;
        case 4:
            if (g_mqtt_protocol_version == 2) {
                atlas_core_get_entity(&entity);
                atlas_snprintf(topic, CONFIG_MQTT_TOPIC_MAXLEN, "/%s/%s/property/set",
                               entity->thing_key, entity->entity_name);
                ret = _mqtt_subscribe(topic, _property_set_receive);
                if (ret == CNIOT_STATUS_CODE_OK) {
                    g_mqtt_subscribe++;
                }
            } else {
                g_mqtt_subscribe += 2;
            }
        case 5:
        case 1:
        case 3:
            break;
        default:
            return CNIOT_STATUS_CODE_OK;
    }
    return CNIOT_STATUS_CODE_OK;
}


static uint16_t  parse_port_from_url(const char *addr) {
    uint16_t port  = 0;
    char *hostPtr = strstr(addr, "://");
    char *portPtr = NULL;
    if (NULL == hostPtr) {
        hostPtr = (char *)addr;
    } else {
        hostPtr += 3;
    }
    portPtr =strstr(hostPtr, ":");
    if (portPtr == NULL) {
        if (strstr(addr, "ssl")) {
            return  443;
        } else {
            return 1883;
        }
    } else {
        portPtr++;
        for (int i = 0; i < 5; ++i,portPtr++) {
            if ('0' <= *portPtr && *portPtr <= '9') {
                port = port * 10 + (*portPtr - '0');
            } else {
                break;
            }
        }
    }
    logger_info("parse mqtt from addr=%s port=%u", addr, port);
    return port;
}

static char *parse_host_from_url(const char *addr) {
    static char host[C_MAX_HOST_LEN] = {0};
    char *hostPtr = strstr(addr, "://");
    char *portPtr = NULL;
    int hostLen = C_MAX_HOST_LEN;
    if (hostPtr != NULL) {
        hostPtr += 3;
    } else {
        hostPtr = (char *)addr;
    }
    portPtr = strstr(hostPtr, ":");
    if (portPtr != NULL) {
        hostLen = portPtr - hostPtr;
    }
    strncpy(host, hostPtr, hostLen);
    logger_info("parse mqtt from addr=%s host=%s", addr, host);
    return host;
}

CNIOT_STATUS_CODE cniot_atlas_mqtt_connect(const char* addr, cniot_atlas_thing_entity_t *entity) {

    char key[C_MAX_MQTT_KEY_LEN] = {0};

    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    uint64_t time = atlas_abs_time();
    iotx_mqtt_param_t mqttParam;
    CHECK_VALUE_NULL(addr);
    CHECK_VALUE_NULL(entity);

    memset(&mqttParam, 0, sizeof(iotx_mqtt_param_t));

    if (NULL != strstr(addr, "ssl://")) {
        mqttParam.pub_key = iotx_ca_crt;
    } else {
        mqttParam.pub_key = NULL;
    }
    mqttParam.port = parse_port_from_url(addr);

    mqttParam.host = parse_host_from_url(addr); // 注意此addr 必须是永久地址.

    mqttParam.handle_event.pcontext = NULL;
    mqttParam.request_timeout_ms    = CONFIG_MQTT_REQUEST_TIMEOUT;
    mqttParam.clean_session         = 0;
    mqttParam.keepalive_interval_ms = 30 * 1000;
    mqttParam.read_buf_size         = CONFIG_MQTT_MESSAGE_MAXLEN;
    mqttParam.write_buf_size        = CONFIG_MQTT_MESSAGE_MAXLEN;
    mqttParam.handle_event.h_fp     = __mqtt_client_receive;
    mqttParam.handle_event.pcontext = NULL;
    mqttParam.username = g_mqtt_userName;
    mqttParam.client_id= g_mqtt_clientId;

    atlas_snprintf(g_mqtt_userName, C_MAX_USER_NAME_LEN, "%s&%s", entity->entity_name, entity->thing_key);
    atlas_snprintf(g_mqtt_clientId, C_MAX_CLIENT_ID_LEN, "%s|securemode=2,signmethod=hmacsha1,version=3,connecttype=device,timestamp=%llu|",
            entity->entity_name, time);

    atlas_snprintf(key, C_MAX_MQTT_KEY_LEN, "deviceName%sproductKey%stimestamp%llu",
                   entity->entity_name, entity->thing_key, time);
    atlas_utils_hmac_sha1(key, g_mqtt_pwd, entity->entity_secret);

    mqttParam.password = g_mqtt_pwd;

    CHECK_RETURN_VALUE(ret, _mqtt_init(&g_mqtt_client, &mqttParam), L_ERROR);

    g_disconnect_time = atlas_boot_uptime();
    CHECK_RETURN_VALUE(ret, _mqtt_connect(g_mqtt_client), L_ERROR);

    g_disconnect_time = 0;

    __check_topic_subscribe();

    cniot_atlas_post_core_event(CNIOT_EVENT_CONNECTED, "mqtt connected");
    return ret;
L_ERROR:
    if (NULL != g_mqtt_client) {
        wrapper_mqtt_release(&g_mqtt_client);
        g_mqtt_client = NULL;
    }
    return ret;
}

static CNIOT_STATUS_CODE cniot_atlas_send_request(void *data, int len, void *rsp_buff, int *rsp_len) {
    iotx_mqtt_topic_info_t topic_info = {0};
    char topic[CONFIG_MQTT_TOPIC_MAXLEN] = {0};
    int n = 0;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_atlas_thing_entity_t *entity;
    if (!g_mqtt_client) {
        return CNIOT_STATUS_CONNECTING; // not init
    }
    if (0 != g_disconnect_time) {
        return CNIOT_STATUS_CONNECTING;
    }
    if (rsp_len != NULL) {
        *rsp_len = 0;
    }
    memset(&topic_info, 0, sizeof(iotx_mqtt_topic_info_t));
    topic_info.qos = IOTX_MQTT_QOS0;
    topic_info.payload = data;
    topic_info.payload_len = len;
    atlas_core_get_entity(&entity);
    if (g_mqtt_protocol_version == 2) {
        atlas_snprintf(topic, CONFIG_MQTT_TOPIC_MAXLEN, "/%s/%s/rpc/sync/request", entity->thing_key, entity->entity_name);
    } else {
        atlas_snprintf(topic, CONFIG_MQTT_TOPIC_MAXLEN, "/%s/%s/rpc/request", entity->thing_key, entity->entity_name);
    }
    n = wrapper_mqtt_publish(g_mqtt_client, topic, &topic_info);
    if (n < 0) {
        log_err("mqtt", "publish message failed ret=%d",  n);
        ret = CNIOT_STATUS_CONNECTING;
        goto L_FAILED;
    }
    wrapper_mqtt_set_send_time(g_mqtt_client);
L_FAILED:
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_mqtt_invoking(cniot_atlas_thing_entity_t *entity, uint64_t messageId, const char *request,
        int request_len, char *buff, int buf_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    int add_request = 0;

    CHECK_VALUE_NULL(entity);
    CHECK_VALUE_NULL(request);
    CHECK_VALUE_NULL(buff);
    logger_debug("receive message request_len=%d", request_len);
    if (!g_mqtt_client) {
        return CNIOT_STATUS_CONNECTING; // not init
    }
    if (0 != g_disconnect_time) {
        return CNIOT_STATUS_CONNECTING;
    }
    CHECK_RETURN_VALUE(ret, atlas_add_request(messageId, C_MQTT_REQUEST_TIMEOUT, request, request_len, buff, buf_len, cniot_atlas_send_request), L_FAILED);
    add_request = 1;
    while(1) {
        ret = atlas_get_response(messageId);
        if (ret == CNIOT_STATUS_CODE_CONTINUE) {
            continue;
        }
        break;
    }
    logger_debug("publish message buff_len=%d ret=%d", buf_len, ret);
L_FAILED:
    if (add_request) {
        atlas_del_request(messageId);
    }
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_mqtt_write(cniot_atlas_thing_entity_t *entity, const char *topic, const char *data) {
    int ret = 0;
    iotx_mqtt_topic_info_t topic_info = {0};

    logger_debug("receive message len=%d %s", strlen(data), data);

    if (!g_mqtt_client) {
        return CNIOT_STATUS_CONNECTING;
    }

    if (0 != g_disconnect_time) {
        return CNIOT_STATUS_CONNECTING;
    }

    memset(&topic_info, 0, sizeof(iotx_mqtt_topic_info_t));

    topic_info.qos = IOTX_MQTT_QOS0;

    topic_info.payload = data;
    topic_info.payload_len = strlen(data);

    ret = wrapper_mqtt_publish(g_mqtt_client, topic, &topic_info);
    if (ret < 0) {
        log_err("mqtt", "publish message failed ret=%d", ret);
        return CNIOT_STATUS_CONNECTING;
    }

    logger_debug("publish message success");
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_mqtt_proc(char *addr, int protocol_version, uint32_t time){
    static int connect_count = 0;
    cniot_atlas_thing_entity_t *entity = NULL;
    uint64_t now = atlas_boot_uptime();
#define C_STEP_RETRY_INTERVAL_TIME (2000)
#define C_MAX_RECONNECT_TIMEOUT  (60000)
    if (!g_mqtt_client) {
        uint64_t interval =  C_STEP_RETRY_INTERVAL_TIME;
        if (now < interval + g_last_connect_time) {
            return CNIOT_STATUS_CODE_OK;
        }
        logger_info("start mqtt connect connect_count=%d now=%llu flag=%llu", connect_count, now, g_last_connect_time);
        g_last_connect_time = now;
        connect_count++;
        atlas_core_get_entity(&entity);
        cniot_atlas_post_core_event(CNIOT_EVENT_CONNECTING, addr);
        g_mqtt_protocol_version = protocol_version;
        cniot_atlas_mqtt_connect(addr, entity);
    } else {
        connect_count = 0;
        g_last_connect_time = 0;
        if ((0 != g_disconnect_time  && (now > g_disconnect_time + C_MAX_RECONNECT_TIMEOUT))) {
            cniot_atlas_mqtt_disconnect();
            cniot_atlas_post_core_event(CNIOT_EVENT_RELEASE, addr);
            return CNIOT_STATUS_MQTT_DISCONNECT;
        }
        __check_topic_subscribe();
        wrapper_mqtt_yield(g_mqtt_client, time);
    }

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_mqtt_disconnect() {
    if (NULL != g_mqtt_client) {
        wrapper_mqtt_release(&g_mqtt_client); //双线程释放 g_mqtt_client 使用g_disconnect_time 隔离保证安全
        g_mqtt_client = NULL;
        g_mqtt_subscribe = 0;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_stlas_mqtt_status(int *status) {
    CHECK_VALUE_NULL(status);
    *status = 0;
    if (g_mqtt_client && g_disconnect_time == 0) {
        *status = 1;
    }
    return CNIOT_STATUS_CODE_OK;
}

