#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <infra_cjson.h>
#include <infra_timer.h>
#include "protocol/http/infra_httpc.h"
#include "atlas_utility.h"
#include "cniot_atlas_wrapper.h"
#include "infra_sha1.h"
#include "atlas_core.h"

extern const char *iotx_ca_crt;
static char g_module[] = {"utility"};

static CNIOT_ATLAS_DOMAIN_CODE g_domain_code = CNIOT_ATLAS_DOMAIN_ALI;
static uint32_t g_random_flag = 0;
CNIOT_STATUS_CODE atlas_get_server_domain_byCode(const char *code, CNIOT_ATLAS_DOMAIN_CODE *domain_code){
    int num = 0;
    CHECK_VALUE_NULL(domain_code);
    CHECK_VALUE_NULL(code);
    if (strlen(code) <= 5) {
        printf("set domain failed, code is invalid\n");
        return CNIOT_STATUS_PARAMETER_NULL;
    }
    num = *code - '0';
    if (num <= 0 || num >= CNIOT_ATLAS_DOMAIN_MAX) {
        printf("set domain failed, code=%s, domain=%d max_domain=%d\n", code, num, CNIOT_ATLAS_DOMAIN_MAX);
        return CNIOT_STATUS_BARCODE_ERROR;
    }
    *domain_code = num;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_set_server_domain(CNIOT_ATLAS_DOMAIN_CODE code) {
    if (code <= 0 || code >= CNIOT_ATLAS_DOMAIN_MAX) {
        printf("set domain failed, domain_code=%d max_domain=%d\n", code,  CNIOT_ATLAS_DOMAIN_MAX);
        return CNIOT_STATUS_PARMETER_OVERFOLW;
    }
    g_domain_code = code;
    printf("set domain success code=%d\n", g_domain_code);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_get_http_address(CNIOT_ATLAS_DOMAIN_CODE domainCode, const char *env, char *address) {
    CHECK_VALUE_NULL(env);
    CHECK_VALUE_NULL(address);
    if (0 == strcmp(env, "daily")) {//日常环境
        if (domainCode == CNIOT_ATLAS_DOMAIN_ALI){
            atlas_snprintf(address, C_MAX_HOST_LEN, "http://http-shiot.cainiao.test");
        } else if (domainCode == CNIOT_ATLAS_DOMAIN_WUTONG){
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://daily-https.iot.cainiao.com");
        } else {
            return CNIOT_STATUS_PARM_ERROR;
        }
    } else if (0 == strcmp(env, "pre")) { //预发环境
        if (domainCode == CNIOT_ATLAS_DOMAIN_ALI) {
            atlas_snprintf(address, C_MAX_HOST_LEN, "http://http-preshiot.cainiao.com");
        } else if (domainCode == CNIOT_ATLAS_DOMAIN_WUTONG){
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://daily-https.iot.cainiao.com");
        } else {
            return CNIOT_STATUS_PARM_ERROR;
        }
    } else if (0 == strcmp(env, "online")) { //线上环境
        if (domainCode == CNIOT_ATLAS_DOMAIN_ALI) {
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://http-iot.cainiao.com");
        } else if (domainCode == CNIOT_ATLAS_DOMAIN_WUTONG){
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://https.iot.cainiao.com");
        } else {
            return CNIOT_STATUS_PARM_ERROR;
        }
    } else {
        return CNIOT_STATUS_PARM_ERROR;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_get_https_address_from_env(const char *env, char *address) {
    return atlas_get_http_address(g_domain_code, env,address);
}

CNIOT_STATUS_CODE atlas_get_report_address(const char * env, char *address) {
    if (g_domain_code == CNIOT_ATLAS_DOMAIN_ALI) {
        if ( 0 == strcmp(env, "daily")) {
            atlas_snprintf(address, C_MAX_HOST_LEN, "http://http-shiot.cainiao.test");
        } else if (0 == strcmp(env, "pre")){
            atlas_snprintf(address, C_MAX_HOST_LEN, "http://http-preshiot.cainiao.com");
        } else {
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://http-iot.cainiao.com");
        }
    } else if (g_domain_code == CNIOT_ATLAS_DOMAIN_WUTONG){
        if ( 0 == strcmp(env, "online")) {
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://https.iot.cainiao.com");
        } else {
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://daily-https.iot.cainiao.com");
        }
    } else {
        return CNIOT_STATUS_PARM_ERROR;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_get_registerSrv_address(const char * env, char *address) {
    if ( 0 == strcmp(env, "daily")) {
        atlas_snprintf(address, C_MAX_HOST_LEN, "http://47.103.190.69");
    } else if (0 == strcmp(env, "pre")){
        atlas_snprintf(address, C_MAX_HOST_LEN, "http://47.103.190.69");
    } else {
        atlas_snprintf(address, C_MAX_HOST_LEN, "https://domain.iot.cainiao.com");
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_get_https_address_from_env_and_barcode(const char *env, const char *barcode, char *address) {
    int num = 0;
    if (NULL == env || NULL == address || NULL == barcode) {
        return CNIOT_STATUS_PARAMETER_NULL;
    }
    num = *barcode - '0';
    if (num <= 0 || num >= CNIOT_ATLAS_DOMAIN_MAX ) {
        printf("get domain failed, code=%s, domain=%d max_domain=%d\n", barcode, num, CNIOT_ATLAS_DOMAIN_MAX);
        return CNIOT_STATUS_BARCODE_ERROR;
    }

    if (0 == strcmp(env, "daily")) {//日常环境
        if (num == CNIOT_ATLAS_DOMAIN_ALI){
            atlas_snprintf(address, C_MAX_HOST_LEN, "http://http-shiot.cainiao.test");
        } else if (num == CNIOT_ATLAS_DOMAIN_WUTONG){
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://daily-https.iot.cainiao.com");
        } else {
            return CNIOT_STATUS_PARM_ERROR;
        }
    } else if (0 == strcmp(env, "pre")) { //预发环境
        if (num == CNIOT_ATLAS_DOMAIN_ALI) {
            atlas_snprintf(address, C_MAX_HOST_LEN, "http://http-preshiot.cainiao.com");
        } else if (num == CNIOT_ATLAS_DOMAIN_WUTONG){
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://daily-https.iot.cainiao.com");
        } else {
            return CNIOT_STATUS_PARM_ERROR;
        }
    } else if (0 == strcmp(env, "online")) { //线上环境
        if (num == CNIOT_ATLAS_DOMAIN_ALI) {
            atlas_snprintf(address, C_MAX_HOST_LEN, "https://http-iot.cainiao.com");
        } else if (num == CNIOT_ATLAS_DOMAIN_WUTONG){
            atlas_snprintf(address, C_MAX_HOST_LEN, "http://https.iot.cainiao.com");
        } else {
            return CNIOT_STATUS_PARM_ERROR;
        }
    } else {
        return CNIOT_STATUS_PARM_ERROR;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_utils_hmac_sha1(const char *key, char *sign, const char *sec){
    if (strlen(sec) > 0) {
        utils_hmac_sha1(key, (int)strlen(key), sign, sec, (int)strlen(sec));
    } else {
        //se芯片加密
    }

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_sign_by_iot_id(char *body, int body_len, const char *iot_id, const char *secret) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char key[C_MAX_SIGN_LEN] = {0};
    char sign[C_MAX_SIGN_LEN] = {0};
    uint64_t abs_time = atlas_abs_time();

    CHECK_VALUE_NULL(body);
    CHECK_VALUE_NULL(iot_id);
    CHECK_VALUE_NULL(secret);
    atlas_snprintf(key, C_MAX_SIGN_LEN, "iotId%stimestamp%llu", iot_id, abs_time);

    CHECK_RETURN_VALUE(ret, atlas_utils_hmac_sha1(key, sign, secret), L_FAILED);

    atlas_snprintf(body, body_len, "\"iotId\":\"%s\","
                                    "\"timestamp\":%llu,"
                                    "\"sign\":\"%s\","
                                    "\"signMethod\":\"hmacsha1\",", iot_id, abs_time, sign);
L_FAILED:
    return ret;
}

CNIOT_STATUS_CODE atlas_sign_by_thing_key(char *body, int body_len, int joinDeviceName, const char *thing_key, const char *device_name, const char *secret) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    char key[C_MAX_SIGN_LEN] = {0};
    char sign[C_MAX_SIGN_LEN] = {0};
    uint64_t abs_time = atlas_abs_time();

    CHECK_VALUE_NULL(body);
    CHECK_VALUE_NULL(thing_key);
    CHECK_VALUE_NULL(secret);

    if (joinDeviceName) {
        atlas_snprintf(key, C_MAX_SIGN_LEN, "deviceName%sproductKey%stimestamp%llu", device_name, thing_key, abs_time);
    } else {
        atlas_snprintf(key, C_MAX_SIGN_LEN, "productKey%stimestamp%llu", thing_key, abs_time);
    }

    logger_info("sign key=%s", key);

    CHECK_RETURN_VALUE(ret, atlas_utils_hmac_sha1(key, sign, secret), L_FAILED);

    logger_info("sign success sign=%s", sign);

    atlas_snprintf(body, body_len,  "\"productKey\":\"%s\","
                                    "\"deviceName\":\"%s\","
                                    "\"timestamp\":%llu,"
                                    "\"sign\":\"%s\","
                                    "\"signMethod\":\"hmacsha1\",", thing_key, device_name, abs_time, sign);

    logger_info("format body success body=%s", body);
L_FAILED:
    return ret;
}

CNIOT_STATUS_CODE atlas_get_mqtt_address_from_env(const char *env, char *address) {
    if (NULL == address) {
        return CNIOT_STATUS_PARAMETER_NULL;
    }
    if (0 == strcmp(env, "daily")) {//日常环境
        if (g_domain_code == CNIOT_ATLAS_DOMAIN_ALI) {
            strcpy(address, "ssl-shiot.cainiao.test");
        } else if (g_domain_code == CNIOT_ATLAS_DOMAIN_WUTONG) {
            strcpy(address, "daily-iot-ssl.wt.cainiao-inc.com");
        } else {
            return CNIOT_STATUS_PARM_ERROR;
        }
    } else if (0 == strcmp(env, "pre")) { //预发环境
        if (g_domain_code == CNIOT_ATLAS_DOMAIN_ALI) {
            strcpy(address, "ssl-preshiot.cainiao.com");
        } else if (g_domain_code == CNIOT_ATLAS_DOMAIN_WUTONG) {
            strcpy(address, "daily-iot-ssl.wt.cainiao-inc.com");
        }
    } else if (0 == strcmp(env, "online")) { //线上环境
        if (g_domain_code == CNIOT_ATLAS_DOMAIN_ALI) {
            strcpy(address, "ssl-shiot.cainiao.com");
        } else if (g_domain_code == CNIOT_ATLAS_DOMAIN_WUTONG) {
            strcpy(address, "ssl.iot.cainiao.com");
        }
    } else {
        return CNIOT_STATUS_PARM_ERROR;
    }
    return CNIOT_STATUS_CODE_OK;
}
CNIOT_STATUS_CODE atlas_check_isprint(const char *data) {
    CHECK_VALUE_NULL(data);
    lite_cjson_t root;
    int n = lite_cjson_parse(data, (int)strlen(data), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    return CNIOT_STATUS_CODE_OK;
}

int atlas_check_id_is_empty(const char *id) {
    CHECK_VALUE_NULL(id);

    if (('0' < id[0] && '9' >= id[0] ) || ('a' < id[0] && 'z' >= id[0] ) ||  ('A' < id[0] && 'Z' >= id[0] )) {
        return 0;
    }
    return 1;
}

CNIOT_STATUS_CODE atlas_https_post_with_redirect(const char *url, char *body, int time_out, char *resp_buff,
        int rsp_buff_len, int times) {
    httpclient_t httpclient;
    httpclient_data_t data;
    httpclient_t *httpc = (httpclient_t *)&httpclient;
    char *redirect_url = NULL;
    int size = 0;
    uint64_t request_start = atlas_boot_uptime(), now = 0;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    logger_info("receive request url=%s\n", url);
    memset(&httpclient, 0, sizeof(httpclient_t));
    memset(&data, 0, sizeof(httpclient_data_t));

    data.post_content_type = "application/json";
    data.post_buf = body;
    data.post_buf_len = (int)strlen(body);
    data.response_buf = resp_buff;
    data.response_buf_len = rsp_buff_len;

    httpc->header = "Connection: Keep-Alive\r\n";

    logger_debug("start http client common body_len=%d body=%s", (int)(strlen(body)), body);
    if (NULL != strstr(url, "https://")) {
        size = httpclient_common(&httpclient, url, 443,
                                 iotx_ca_crt, HTTPCLIENT_POST, time_out, &data);
    } else {
        size = httpclient_common(&httpclient, url, 80,
                                 NULL, HTTPCLIENT_POST, time_out, &data);
    }

    logger_debug("httpclient common resp size=%d code=%d resp_len=%d rsp=%s\n", size, httpclient.response_code, data.response_buf_len, resp_buff);

    if (size < 0) {
        return CNIOT_STATUS_MSG_TIMEOUT;
    }

    if (400 <= httpclient.response_code) {
        return CNIOT_STATUS_HTTP_RSP_CODE_FAILED;
    }
    //支持重定向
    if (httpclient.response_code == 301 || httpclient.response_code == 302) {
        if (times <= 0) {
            return CNIOT_STATUS_REDIRECT_OVERFLOW;
        }
        now = atlas_boot_uptime();
        if (now - request_start + 500 >= time_out ) {
            return CNIOT_STATUS_MSG_TIMEOUT;
        }
        if (data.response_buf_len > C_MAX_URL_LEN) {
            return CNIOT_STATUS_BUFFER_OVERFLOW;
        }

        redirect_url = atlas_malloc(data.response_buf_len + 1);
        if (NULL == redirect_url) {
            return CNIOT_STATUS_NO_MEMORY;
        }
        strcpy(redirect_url, resp_buff);
        time_out = time_out - (int)(now - request_start);
        ret = atlas_https_post_with_redirect(redirect_url, body, time_out, resp_buff, rsp_buff_len, times - 1);
        atlas_free(redirect_url);
        return ret;
    }

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_https_post(const char *url, char *body, int time_out, char *resp_buff, int rsp_buff_len) {
    return atlas_https_post_with_redirect(url, body, time_out, resp_buff, rsp_buff_len, 1);
}


CNIOT_STATUS_CODE atlas_https_post_binary_data(const char *url, char *body, int body_len, int time_out, char *resp_buff, int rsp_buff_len) {
    httpclient_t httpclient;
    httpclient_data_t data;
    httpclient_t *httpc = (httpclient_t *)&httpclient;
    int size = 0;
    logger_info("receive binary data request url=%s\n", url);
    memset(&httpclient, 0, sizeof(httpclient_t));
    memset(&data, 0, sizeof(httpclient_data_t));

    data.post_content_type = "application/octet-stream";
    data.post_buf = body;
    data.post_buf_len = body_len;
    data.response_buf = resp_buff;
    data.response_buf_len = rsp_buff_len;

    httpc->header = "Connection: Keep-Alive\r\n";

    logger_debug("http binary data body_len=%d ", (int)(strlen(body)), body);
    if (NULL != strstr(url, "https://")) {
        size = httpclient_common(&httpclient, url, 443,
                                 iotx_ca_crt, HTTPCLIENT_POST, time_out, &data);
    } else {
        size = httpclient_common(&httpclient, url, 80,
                                 NULL, HTTPCLIENT_POST, time_out, &data);
    }

    if (size < 0) {
        return CNIOT_STATUS_MSG_TIMEOUT;
    }

    if (400 <= httpclient.response_code) {
        return CNIOT_STATUS_HTTP_RSP_CODE_FAILED;
    }

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_create_traceId(char *traceId){
    CHECK_VALUE_NULL(traceId);
    static int nextId = 1;
    uint64_t bootTime = 0;
    uint64_t time = atlas_abs_time();
    if (0 == g_random_flag) {
        bootTime = atlas_boot_uptime();
        srandom(bootTime);
        g_random_flag = (uint32_t)random();
    }
    if (nextId >= 9900) {
        nextId = 1;
    }
    atlas_snprintf(traceId, C_MAX_ID_LEN, "%08x%llu%04dd7%s", g_random_flag, time, nextId, C_ATLAS_SDK_VERSION_STR);
    nextId++;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_create_messageId(uint64_t  *id){
    static uint64_t  g_local_id = 0;
    CHECK_VALUE_NULL(id);
    if (g_local_id == 0 ){
        g_local_id = atlas_abs_time();
    }
    *id = g_local_id++;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_get_json_string_value(void *ptr, const char *item, char *value, int len) {
    lite_cjson_t *root = (lite_cjson_t *)ptr;
    lite_cjson_t node;
    int ret = lite_cjson_object_item(root, item, strlen(item), &node);
    if (ret < 0) {
        log_err(g_module, "not found json value %s", item);
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }
    COPY_JSON_VALUE(value, node, len);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_tcp_request(const char *host, unsigned short port,
                                                      const char *write_buffer, int write_buff_len,
                                                      char *read_buff, int *read_buff_len,
                                                      unsigned int write_timeout_ms,
                                                      unsigned  int read_timeout_ms) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    utils_network_t net;
    uint32_t send = 0, left_t = 0, read = 0;
    int rc  = 0;
    iotx_time_t timer;
    CHECK_VALUE_NULL(host);
    CHECK_VALUE_NULL(write_buffer);
    CHECK_VALUE_NULL(read_buff);
    CHECK_VALUE_NULL(read_buff_len);

    logger_info("[tcp] receive tcp request to read host[%s:%d] bodyLen=%d read_len=%d "
                "write_timeout=%d read_timeout=%d\n",
            host, port, write_buff_len, *read_buff_len, write_timeout_ms, read_timeout_ms);

    if (write_buff_len <= 0 || *read_buff_len <= 0 || port == 0 || 0 == write_timeout_ms || 0 == read_timeout_ms) {
        return CNIOT_STATUS_PARM_ERROR;
    }

    ret = iotx_net_init(&net, host, port, NULL, 0);
    if (0 != ret) {
        logger_err("[tcp]init network failed, ret=%d", ret);
        return CNIOT_STATUS_TCP_INIT_FAILED;
    }

    ret  = iotx_net_connect(&net);
    if (ret != 0) {
        logger_err("[tcp]network connect %s failed, ret=%d", host, ret);
        iotx_net_disconnect(&net);
        iotx_net_exit(&net);
        return CNIOT_STATUS_TCP_CONNECT_FAILED;
    }

    iotx_time_init(&timer);
    utils_time_countdown_ms(&timer, write_timeout_ms);

    while (send < write_buff_len && !utils_time_is_expired(&timer)) {
        left_t = iotx_time_left(&timer);
        left_t = (left_t == 0) ? 1 : left_t;
        rc =  utils_net_write(&net,  &write_buffer[send], write_buff_len - send, left_t);
        if (rc < 0) { /* there was an error writing the data */
            logger_err("[tcp]network write to %s failed, rc=%d", host, ret);
            break;
        }
        send += rc;
    }

    if (utils_time_is_expired(&timer)) {
        iotx_net_disconnect(&net);
        iotx_net_exit(&net);
        return CNIOT_STATUS_TCP_WRITE_TIMEOUT;
    }

    if (send < write_buff_len){
        iotx_net_disconnect(&net);
        iotx_net_exit(&net);
        return CNIOT_STATUS_TCP_WRITE_FAILED;
    }

    iotx_time_init(&timer);
    utils_time_countdown_ms(&timer, read_timeout_ms);

    logger_info("[tcp] start to read %s:%d\n", host, port);
    while (read < *read_buff_len && !utils_time_is_expired(&timer)) {
        left_t = iotx_time_left(&timer);
        left_t = (left_t == 0) ? 1 : left_t;
        rc =  utils_net_read(&net,  &read_buff[read], *read_buff_len - read, left_t);
        if (rc < 0) { /* there was an error writing the data */
            logger_err("[tcp] network read %s failed, rc=%d", host, ret);
            break;
        }
        logger_debug("[tcp] receive %s read data len=%d\n", host, rc);
        read += rc;
    }

    iotx_net_disconnect(&net);
    iotx_net_exit(&net);
    *read_buff_len = read;

    if (utils_time_is_expired(&timer)) {
        return CNIOT_STATUS_TCP_READ_TIMEOUT;
    }

    return CNIOT_STATUS_CODE_OK;
}