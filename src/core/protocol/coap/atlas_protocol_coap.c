#include "services/atlas_services.h"
#include "./client/Cloud_CoAPExport.h"
#include "./client/Cloud_CoAPMessage.h"
#include "./CoAPPacket/CoAPDeserialize.h"
#include "request/atlas_request.h"

#include "atlas_protocol_coap.h"
#include "atlas_core.h"
#include "./protocol/atlas_protocol.h"
#include "cniot_atlas_wrapper.h"
#include "atlas_utility.h"
#include "report/atlas_report.h"

static char g_module[] = {"coap"};
static volatile void *g_coap_ctx = NULL;
static char g_coap_addr[C_MAX_HOST_LEN] = {0};
static uint64_t  g_last_heartbeat = 0;
static uint64_t  g_last_recvMsg = 0;
static int g_heartbeat_msgid = 0;
static int g_exchange_msgid = 0;
static int is_connected = 0;

static CNIOT_STATUS_CODE _split_path_2_option(char *uri, Cloud_CoAPMessage *message)
{
    char *ptr     = NULL;
    char *pstr    = NULL;
    char  path[COAP_MSG_MAX_PATH_LEN]  = {0};
    CHECK_VALUE_NULL(uri);
    CHECK_VALUE_NULL(message);

    if (IOTX_URI_MAX_LEN < strlen(uri)) {
        logger_err("The uri length is too loog,len = %d", (int)strlen(uri));
        return CNIOT_STATUS_URI_OVERFLOW;
    }

    logger_debug("The uri is %s", uri);
    ptr = pstr = uri;
    while ('\0' != *ptr) {
        if ('/' == *ptr) {
            if (ptr != pstr) {
                memset(path, 0x00, sizeof(path));
                strncpy(path, pstr, ptr - pstr);
                logger_debug("path: %s,len=%d", path, (int)(ptr - pstr));
                CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                                  (unsigned char *)path, (int)strlen(path));
            }
            pstr = ptr + 1;

        }
        if ('\0' == *(ptr + 1) && '\0' != *pstr) {
            memset(path, 0x00, sizeof(path));
            strncpy(path, pstr, sizeof(path) - 1);
            logger_debug("path: %s,len=%d", path, (int)strlen(path));
            CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                              (unsigned char *)path, (int)strlen(path));
        }
        ptr ++;
    }

    return CNIOT_STATUS_CODE_OK;
}

void __coap_message_recv(void *sem, void *message) {
    if (sem) {
        HAL_SemaphorePost(sem);
    }
}


static void __coap_event_notify(unsigned int code, Cloud_CoAPMessage *message)
{
    if (NULL == message) {
        return ;
    }

    logger_debug("receive coAP message msgId=%d code=%d type=%d len=%d",
            message->header.msgid, code, message->header.type, message->payloadlen);

    g_last_recvMsg = atlas_boot_uptime();

    if (!is_connected) {
        cniot_atlas_post_core_event(CNIOT_EVENT_CONNECTED, g_coap_addr);
        is_connected = 1;
    }

    switch (code) {
        case COAP_MSG_CODE_402_BAD_OPTION:
        case COAP_MSG_CODE_401_UNAUTHORIZED: {
            // 鉴权
            break;
        }
        case COAP_MSG_CODE_231_CONTINUE: {
            break;
        }
        case COAP_MSG_CODE_204_CHANGED: {
            break;
        }
        default:
            break;
    }
}

static CNIOT_STATUS_CODE __check_coap_link_timeout() {
    if (g_last_recvMsg + C_MAX_COAP_REQUEST_TIMEOUT <  atlas_boot_uptime()) {
        logger_err("not found service rsp message timeout=%d", C_MAX_COAP_REQUEST_TIMEOUT); // 超过请求事件不再发请求,超过超时时间就重新建立连接...
        return CNIOT_STATUS_CONNECTING;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_coap_connect(const char* addr) {
    Cloud_CoAPInitParam param;

    atlas_snprintf(g_coap_addr, C_MAX_HOST_LEN,"coap://%s:21119", addr);
    is_connected = 0;
    cniot_atlas_post_core_event(CNIOT_EVENT_CONNECTING, g_coap_addr);

    param.maxcount = 10;
    param.notifier = (Cloud_CoAPEventNotifier)__coap_event_notify;
    param.waittime = C_PROC_INTERVAL_TIME;
    param.url = g_coap_addr;
    //g_last_heartbeat = atlas_boot_uptime();
    g_last_recvMsg = atlas_boot_uptime();
    CNIOT_STATUS_CODE ret  = CNIOT_STATUS_CODE_OK;
    if (g_coap_ctx != NULL) {
        return CNIOT_STATUS_CODE_OK;
    }
    CHECK_MALLOC_VALUE(g_coap_ctx, Cloud_CoAPContext_create(&param), L_ERROR, ret);
L_ERROR:
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_coap_sendMsg(char *path,
                                           int method,
                                           const char *data,
                                           int data_len,
                                           unsigned char *token,
                                           int block1,
                                           int block2,
                                           int observe,
                                           int need_rsp,
                                           int *msgId,
                                           void *sem,
                                           int is_heartbeat) {
    CoAPMessage message;
    int n = 0, len=  0;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    void *coap_handler = g_coap_ctx;
    if (NULL == coap_handler) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    if (!is_heartbeat) {
        CHECK_RETURN_VALUE(ret, __check_coap_link_timeout(), L_CHECK_FAILED);
    }

    CHECK_VALUE_NULL(token);
    CHECK_VALUE_NULL(path);
    CHECK_VALUE_NULL(data);

    if (data_len > C_MAX_COAP_MSG_LENGTH) {
        return CNIOT_STATUS_PARMETER_OVERFOLW;
    }
    CoAPMessage_init(&message);
    message.need_rsp = need_rsp;
    CoAPMessageType_set(&message, COAP_MESSAGE_TYPE_CON);
    CoAPMessageCode_set(&message, method);
    CoAPMessageId_set(&message, Cloud_CoAPMessageId_gen(coap_handler));
    CoAPMessageToken_set(&message, token, 4);
    CoAPMessageUserData_set(&message, sem);
    Cloud_CoAPMessageHandler_set(&message, __coap_message_recv);
    if (0 < observe) { // observe：0 不设置 1： 订阅  2： 取消订阅
        CoAPUintOption_add(&message, COAP_OPTION_OBSERVE, observe - 1);
    }

    /*设置option 必须是从值小开始...*/
    CHECK_RETURN_VALUE(ret, _split_path_2_option(path, &message), L_FAILED);

    CoAPUintOption_add(&message, COAP_OPTION_CONTENT_FORMAT, COAP_CT_APP_JSON);
    CoAPUintOption_add(&message, COAP_OPTION_ACCEPT, COAP_CT_APP_JSON);

    if (block2 != 0) {
        CoAPUintOption_add(&message, COAP_OPTION_BLOCK2, block2);
    }

    if (block1 != 0) {
        CoAPUintOption_add(&message, COAP_OPTION_BLOCK1, block1);
    }

    if (NULL != data && method == COAP_PERM_POST) {
        if (data_len > 0) {
            CoAPMessagePayload_set(&message, (unsigned char *)data, data_len);
        }
    }

    n = Cloud_CoAPMessage_send(coap_handler, &message);
    if (n < 0) {
        logger_err("send message failed, ret=%d", n);
        ret  = CNIOT_STATUS_NO_MEMORY;
    }
    if (msgId) {
        *msgId = message.header.msgid;
    }
    logger_info("send coAP to %s  msgLen = %d msgId=%d success", g_coap_addr, data_len,message.header.msgid);

L_FAILED:
    CoAPMessage_destory(&message);
L_CHECK_FAILED:
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_coap_recvMsg(int msgId, unsigned char **data, unsigned  int *len, uint64_t end_time, void *sem) {
    *data = NULL;
    *len = 0;
    uint64_t  now = 0;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    while(NULL == *data) {
        if (NULL == g_coap_ctx || !is_connected) {
            ret= CNIOT_STATUS_CONNECTING;
            break;
        }
        now = atlas_boot_uptime();
        if (end_time <= now) {
            ret = CNIOT_STATUS_MSG_TIMEOUT;
            break;
        }
        HAL_SemaphoreWait(sem, end_time - now);
        if (Cloud_GetCoAPRespMessage(g_coap_ctx, msgId, data, len) != COAP_SUCCESS) {
            ret = CNIOT_STATUS_MSG_TIMEOUT;
            break;
        }

        if (NULL != *data) {
            break;
        }
        CHECK_RETURN_VALUE(ret, __check_coap_link_timeout(), L_FAILED);
    }

    if (ret != CNIOT_STATUS_CODE_OK) {
        if (NULL != g_coap_ctx) {
            Cloud_CoAPMessage_delete(g_coap_ctx, msgId);
        }
    }
L_FAILED:
    return ret;
}


static CNIOT_STATUS_CODE _parse_coap_message(unsigned char *buf, int datalen, char *body, int *body_len, unsigned int *block2,
                                             unsigned int *size2) {
    CoAPMessage message;
    CNIOT_STATUS_CODE ret  = CNIOT_STATUS_CODE_OK;

    CHECK_VALUE_NULL(buf);
    CHECK_VALUE_NULL(body);
    CHECK_VALUE_NULL(body_len);
    CHECK_VALUE_NULL(block2);

    int coAPCode = CoAPDeserialize_Message(&message, buf, datalen);
    if (coAPCode != COAP_SUCCESS) {
        return CNIOT_STATUS_MSG_DECODE_FAILED;
    }
    if (COAP_MSG_CODE_400_BAD_REQUEST < coAPCode) {
        return CNIOT_STATUS_RSP_CODE_ERROR;
    }

    CoAPUintOption_get(&message, COAP_OPTION_BLOCK2, block2);
    CoAPUintOption_get(&message, COAP_OPTION_SIZE2, size2);

    if (NULL != message.payload) {
        if (*body_len < message.payloadlen + 1) {
            return CNIOT_STATUS_PARMETER_OVERFOLW;
        }
        memcpy(body, message.payload, message.payloadlen);
        *body_len = *body_len - message.payloadlen;
    }
    return ret;
}

static CNIOT_STATUS_CODE _parse_resp_message(char *data, int data_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    lite_cjson_t root,  node;
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

    n = lite_cjson_object_item(&root, "payload", strlen("payload"), &node);
    if (n < 0) {
        logger_err("not found json value payload");
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

    return CNIOT_STATUS_CODE_OK;
}
static CNIOT_STATUS_CODE _send_coap_request(const char *data, int data_len, char *rsp, int *rsp_len) {
    return cniot_atlas_coap_request("iot/edge", data, data_len,C_RSP_FORMAT_JSON, rsp, rsp_len);
}

CNIOT_STATUS_CODE cniot_atlas_coap_invoking(uint64_t messageId, const char *request, int request_len, char *buff, int buf_len){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    int add_request = 0;

    CHECK_VALUE_NULL(request);
    CHECK_VALUE_NULL(buff);
    logger_debug("receive coap message request_len=%d", request_len);
    if (!g_coap_ctx || !is_connected) {
        return CNIOT_STATUS_CONNECTING;
    }
    CHECK_RETURN_VALUE(ret, atlas_add_request(messageId, C_MQTT_REQUEST_TIMEOUT, request, request_len, buff, buf_len, _send_coap_request), L_FAILED);
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

CNIOT_STATUS_CODE cniot_atlas_coap_request(char *path, const char *data, int data_len, coAP_rsp_format_t format, char *rsp, int *rsp_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char *body = NULL;
    int msgid = 0, body_len = 0, data_send_len = 0, send_len = 0;
    unsigned char *buf = NULL;
    unsigned char token[10] = {0};
    unsigned int buf_len = 0, block2 = 0x00, size2=0, block1 = 0;
    int send_finish = 0;
    uint64_t end_time = atlas_boot_uptime() + C_COAP_REQUEST_TIMEOUT, now =0;

    int block_cnt = 0, send_block_cnt = 0,  need_rsp = 0;
    void *sem = NULL;
    CHECK_VALUE_NULL(path);
    CHECK_VALUE_NULL(data);
    void *coap_handle = g_coap_ctx;
    if (!coap_handle || !is_connected) {
        return CNIOT_STATUS_CONNECTING;
    }
    if (rsp != NULL && rsp_len == NULL) {
        logger_info("rsp not null but rsp_len=NULL");
        return CNIOT_STATUS_PARM_ERROR;
    }

    CHECK_RETURN_VALUE(ret, __check_coap_link_timeout(), L_FAILED);

    logger_debug("receive request %s ", data);
    if (NULL != rsp_len) {
        body_len = *rsp_len;
    }
    Cloud_CoAPToken_gen(coap_handle, token);
    sem = HAL_SemaphoreCreate();

    while(1) {
        send_len = data_len;
        need_rsp = (rsp != NULL);
        now = atlas_boot_uptime();
        if (end_time <= now) {
            ret = CNIOT_STATUS_MSG_TIMEOUT;
            break;
        }
        if (!send_finish) {
            if (data_len > C_MAX_COAP_MSG_LENGTH) { // 上行块传输
                now = atlas_boot_uptime();
                if (end_time <= now) {
                    ret = CNIOT_STATUS_MSG_TIMEOUT;
                    break;
                }
                if (send_block_cnt > 0 && HAL_SemaphoreWait(sem, end_time - now) < 0 ) {
                    Cloud_CoAPMessage_delete(coap_handle, msgid);
                    ret = CNIOT_STATUS_MSG_TIMEOUT;
                    break;
                }
                if (data_len - data_send_len >= C_MAX_COAP_MSG_LENGTH) {
                    block1 = 0x0e + (send_block_cnt << 4);
                    need_rsp = 0;
                    send_len = C_MAX_COAP_MSG_LENGTH;
                } else {
                    block1 = 0x06 + (send_block_cnt << 4);
                    send_len = data_len - data_send_len;
                }
                send_block_cnt++;
            } else {
                data_send_len = 0;
            }
        } else {
            block1 = 0;
            send_len = 0;
        }
        CHECK_RETURN_VALUE(ret, cniot_atlas_coap_sendMsg(path, COAP_PERM_POST, data + data_send_len,  send_len, token, block1, block2, 0, need_rsp, &msgid, sem, 0), L_FAILED);
        data_send_len += send_len;
        if ((!send_finish) && ((block1 & 0x08) != 0)) {
            continue;
        }
        send_finish = 1;
        if (!rsp) {
            break;
        }
        body = rsp + (*rsp_len - body_len);
        atlas_free(buf); // 块传输 释放
        buf = NULL;
        CHECK_RETURN_VALUE(ret, cniot_atlas_coap_recvMsg(msgid, &buf, &buf_len, end_time, sem), L_FAILED);
        CHECK_RETURN_VALUE(ret, _parse_coap_message(buf, buf_len, body, &body_len, &block2, &size2), L_FAILED);

        if (*rsp_len <= size2) {
            logger_err("buffer is overflow buf_len=%d rsp_body_len=%d", *rsp_len, size2);
            ret = CNIOT_STATUS_BUFFER_OVERFLOW;
            break;
        }
        if (0 != (block2 & 0x08)) { //下载数据块传输
            int receive_cnt = (block2 & 0xfff0)>>4;
            if (receive_cnt != block_cnt) {
                logger_err("coap found error msgid=%d receive err block_cnt=%d exp_cnt=%d", msgid, receive_cnt, block_cnt);
                ret = CNIOT_STATUS_RSP_NOT_SUCCESS;
                break;
            }
            block_cnt++;
            block2 = 0x06 + (block_cnt << 4); //服务器不能设置小于1024大小.否则会丢数据...
        } else {
            break;
        }
    }

    if (ret == CNIOT_STATUS_CODE_OK && rsp) {
        logger_debug("receive rsp %s", rsp);
        if (format == C_RSP_FORMAT_JSON) {
            CHECK_RETURN_VALUE(ret, _parse_resp_message(rsp, *rsp_len), L_FAILED);
            *rsp_len = (int) strlen(rsp);
        } else {
            *rsp_len -= body_len;
        }
    }

L_FAILED:
    atlas_free(buf);
    if (NULL != sem) {
        HAL_SemaphoreDestroy(sem);
    }
    return ret;
}

CNIOT_STATUS_CODE cniot_send_coap_loadTest() {
//    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
//    cniot_atlas_thing_entity_t *entry = NULL;
//    char msg[C_MAX_BODY_LEN] = {0};
//    char rsp[20000] = {0};
//    atlas_core_get_entity(&entry);
//    int rsp_len = 20000;
//    atlas_snprintf(msg, C_MAX_BODY_LEN, "{\"traceId\":\"222222222ffff\","
//                             "\"version\":1,"
//                             "\"timestamp\":%llu,"
//                             "\"method\":\"loadTest\","
//                             "\"productKey\":\"%s\","
//                             "\"deviceName\":\"%s\","
//                             "\"iotId\":\"%s\", "
//                             "\"params\":{ \"resourceId\":\"10k.txt\"}}",
//                   atlas_abs_time(), entry->thing_key, entry->entity_name, entry->iot_id);
//    cniot_atlas_coap_request("iot/edge", msg, strlen(msg), C_RSP_FORMAT_JSON, rsp,&rsp_len);
//
//
//    cniot_atlas_coap_request("iot/edge", rsp, strlen(rsp), C_RSP_FORMAT_JSON, msg, &rsp_len);

    return CNIOT_STATUS_CODE_OK;
}

static  CNIOT_STATUS_CODE __parse_exchange_msgs(char *buff, int buff_len) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    lite_cjson_t root, payload, node, msg;
    int i = 0;
    int n = lite_cjson_parse(buff, (int)strlen(buff), &root);
    if (n < 0) {
        logger_err("parse exchange msgs is not json data %s", buff);
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }

    n = lite_cjson_object_item(&root, "payload", strlen("payload"), &payload);
    if (n < 0) {
        logger_err("parse payload is not json data %s", buff);
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }

    n = lite_cjson_object_item(&payload, "exchangeMsgId", strlen("exchangeMsgId"), &node);
    if (n >= 0) {
        g_exchange_msgid = node.value_int;
    }

    n = lite_cjson_object_item(&payload, "exchangeMsg", strlen("exchangeMsg"), &node);
    if (n < 0) {
        return CNIOT_STATUS_CODE_OK;
    }

    for (i = 0; i < node.size; ++i) {
        n = lite_cjson_array_item(&node, i, &msg);
        if (n < 0) {
            break;
        }
        cniot_protocol_process_method_v1(msg.value, msg.value_length);
    }

    return CNIOT_STATUS_CODE_OK;
}

static  CNIOT_STATUS_CODE _check_heartbeat_rsp_msg() {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    unsigned char *buff = NULL;
    char *body = NULL;
    int body_len = C_MAX_COAP_MSG_LENGTH;
    unsigned int len = 0, size2 = 0,block2 = 0;

    if (g_heartbeat_msgid == 0) {
        return CNIOT_STATUS_CODE_OK;
    }
    if (Cloud_GetCoAPRespMessage(g_coap_ctx, g_heartbeat_msgid, &buff, &len) != COAP_SUCCESS) {
        return CNIOT_STATUS_MSG_TIMEOUT;
    }

    if (NULL != buff) {
        logger_info("-->>receive heartbeat msgid=%d\n", g_heartbeat_msgid);
        g_heartbeat_msgid = 0;
        CHECK_MALLOC_VALUE(body, atlas_malloc(C_MAX_COAP_MSG_LENGTH), L_FAILED, ret);
        CHECK_RETURN_VALUE(ret, _parse_coap_message(buff, len, body, &body_len, &block2, &size2), L_FAILED);
        CHECK_RETURN_VALUE(ret, __parse_exchange_msgs(body, body_len), L_FAILED);
    }
L_FAILED:
    atlas_free(buff);
    atlas_free(body);
    return ret;
}

static  CNIOT_STATUS_CODE cniot_send_coap_heartbeat() {
    char *msg = NULL;
    char trace_id[C_MAX_ID_LEN] = {0};
    unsigned char token[10] = {0};
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_atlas_thing_entity_t *entry = NULL;
    uint64_t time = atlas_boot_uptime();

    if (g_last_recvMsg + C_MAX_COAP_TIMEOUT < time) {
        return CNIOT_STATUS_MSG_TIMEOUT;
    }

    if (time > g_last_heartbeat + C_MAX_COAP_HEARTBEAT) {
        g_last_heartbeat = time;
        atlas_core_get_entity(&entry);
        CHECK_RETURN_VALUE(ret, atlas_create_traceId(trace_id), L_FAILED);
        CHECK_MALLOC_VALUE(msg, atlas_malloc(C_MAX_BODY_LEN), L_FAILED, ret);
        atlas_snprintf(msg, C_MAX_BODY_LEN, "{\"traceId\":\"%s\","
                                       "\"version\":1,"
                                       "\"timestamp\":%llu,"
                                       "\"method\":\"heartBeat\","
                                       "\"productKey\":\"%s\","
                                       "\"deviceName\":\"%s\","
                                       "\"iotId\":\"%s\", "
                                       "\"params\":{"
                                       "\"exchangeMsgId\":%d"
                                       "}}",
                       trace_id, atlas_abs_time(), entry->thing_key, entry->entity_name, entry->iot_id, g_exchange_msgid);

        logger_debug("coAP send heartBeat to %s", g_coap_addr);
        Cloud_CoAPToken_gen(g_coap_ctx, token);
        CHECK_RETURN_VALUE(ret, cniot_atlas_coap_sendMsg("iot/edge",COAP_PERM_POST, msg,  strlen(msg), token, 0, 0, 1, 1, &g_heartbeat_msgid, NULL, 1), L_FAILED);
        cniot_atlas_heartbeat_count();
    }
L_FAILED:
    atlas_free(msg);
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_coap_proc(const char *addr, uint32_t time) {
    //不能在proc线程中去做阻塞的事情.例如coap收取包
    int i = 0;
    int proc_cnt = (int) time / C_PROC_INTERVAL_TIME;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    static uint64_t last_network_check_time = 0;
    C_CNIOT_NETWORK_STATUS status;
    int is_disconnect = 0;
#define C_WAIT_ONLINE_TIME     (15 * 1000)
    if (NULL == g_coap_ctx) {
        atlas_get_network_status(&status);
        // 15秒网络都没有重连成功,则会重试
        if (status == NETWORK_STATUS_OFFLINE && atlas_boot_uptime() <= last_network_check_time + C_WAIT_ONLINE_TIME) {
            return CNIOT_STATUS_CODE_OK;
        }
        CHECK_RETURN_VALUE(ret, cniot_atlas_coap_connect(addr), L_FAILED);
    }
    atlas_check_network_disconnect(last_network_check_time, &is_disconnect);
    if (is_disconnect) {
        printf("receive network disconnect reconnect coap\n");
        last_network_check_time = atlas_boot_uptime();
        return CNIOT_STATUS_NETWORK_DISCONNECTED;
    }

    CHECK_RETURN_VALUE(ret, cniot_send_coap_heartbeat(), L_FAILED);
    if (proc_cnt > C_MIN_PROC_TIMES_PRE_SECOND) {
        proc_cnt = C_MIN_PROC_TIMES_PRE_SECOND;
    }
    for (i = 0; i < proc_cnt; ++i) {
        Cloud_CoAPMessage_cycle(g_coap_ctx);
        _check_heartbeat_rsp_msg();
    }
L_FAILED:
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_get_coap_status(int *status) {
    CHECK_VALUE_NULL(status);
    *status = 0;
    if (g_coap_ctx) {
        *status = is_connected;
    }
    return CNIOT_STATUS_CODE_OK;
}

static void *free_header_thread(void *handler) {
    atlas_usleep(2 * C_COAP_REQUEST_TIMEOUT);
    Cloud_CoAPContext_free(handler);
    atlas_thread_delete(NULL);
    return NULL;
}

CNIOT_STATUS_CODE cniot_atlas_coap_disconnect() {
    void *free_handler = NULL;
    int stack_used = 0;
    void *coap_handle = g_coap_ctx;
    thread_parm_t parm ;
    if (NULL != g_coap_ctx) {
        if (is_connected) {
            logger_err("coAP Disconnect %s", g_coap_addr);
            cniot_atlas_post_core_event(CNIOT_EVENT_DISCONNECT, g_coap_addr);
        }
        is_connected = 0;
        atlas_usleep(1000);
        memset(&parm, 0, sizeof(thread_parm_t));
        atlas_snprintf(parm.thread_name, sizeof(parm.thread_name), "atlas_coap_free");
        parm.stack_size = 1200;
        parm.thread_prio = 5;
        atlas_thread_create(&free_handler, free_header_thread, coap_handle, &parm, &stack_used);
        g_coap_ctx = NULL;
    }
    return CNIOT_STATUS_CODE_OK;
}

