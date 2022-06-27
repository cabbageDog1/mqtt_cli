#ifndef CNIOT_ATLAS_ATLAS_UTILITY_H
#define CNIOT_ATLAS_ATLAS_UTILITY_H
#if defined(__cplusplus)
extern "C" {
#endif
#include "cniot_atlas_code.h"
#include "logger/atlas_logger.h"

#define CHECK_RETURN_VALUE(a, b, c)    do{ a=b; if (a != CNIOT_STATUS_CODE_OK){logger_err("function=%s return=0x%02x", #b, ret); goto c; }}while(0)
#define CHECK_MALLOC_VALUE(a, b, c, d) do{ a=b; if (NULL == a){logger_err("%s malloc failed", #a); d = CNIOT_STATUS_NO_MEMORY; goto c;}}while(0)
#define CHECK_VALUE_NULL(a) do{if(NULL == a){logger_err("%s value is NULL", #a); return CNIOT_STATUS_PARAMETER_NULL;}}while(0)
#define COPY_VALUE(a,b,c,d) \
do{CHECK_VALUE_NULL(b);  \
if(d(b) > c) { \
logger_err("%s buffer is small %d <%d", #a, c, d(b));\
return CNIOT_STATUS_PARMETER_OVERFOLW; \
}; \
strcpy(a, b); \
}while(0)

#define COPY_JSON_VALUE(a,b,c) \
do{ \
if((b.value_length) > c) { \
logger_err("%s buffer is small %d <%d", #a, c, (b.value_length));\
return CNIOT_STATUS_PARMETER_OVERFOLW; \
}; \
strncpy(a, b.value, (b.value_length)); \
*(a + b.value_length) = '\0';\
}while(0)

/*
 * 根据环境获取控制台地址
 */
CNIOT_STATUS_CODE atlas_get_https_address_from_env(const char *env, char *address);

CNIOT_STATUS_CODE atlas_get_report_address(const char *env, char *address);

CNIOT_STATUS_CODE atlas_get_registerSrv_address(const char *env, char *address);

CNIOT_STATUS_CODE atlas_sign_by_iot_id(char *sign, int sign_len, const char *iot_id, const char *secret);

CNIOT_STATUS_CODE atlas_sign_by_thing_key(char *sign, int sign_len, int joinDeviceName, const char *thing_key, const char *device_name, const char *secret);

/*
 * 根据环境获取mqtt地址
 */
CNIOT_STATUS_CODE atlas_get_mqtt_address_from_env(const char *env, char *address);

/*
 * sha1 加密
 */
CNIOT_STATUS_CODE atlas_utils_hmac_sha1(const char *key, char *sign, const char *sec);


/*
 * https post方法 json 数据
 */
CNIOT_STATUS_CODE atlas_https_post_with_redirect(const char *url, char *body, int time_out, char *resp_buff,
                                                 int rsp_buff_len, int times);
/*
 * https post方法 json 数据
 */

CNIOT_STATUS_CODE atlas_https_post(const char *url, char *body, int time_out, char *resp_buff, int rsp_buff_len);

CNIOT_STATUS_CODE atlas_create_traceId(char *traceId);

CNIOT_STATUS_CODE atlas_create_messageId(uint64_t  *messageId);

CNIOT_STATUS_CODE atlas_get_json_string_value(void *root, const char *item, char *value, int len);

CNIOT_STATUS_CODE atlas_check_isprint(const char *data);

int atlas_check_id_is_empty(const char *id);

/*
 * https post方法传输二进制
 */
CNIOT_STATUS_CODE atlas_https_post_binary_data(const char *url, char *body, int body_len, int time_out, char *resp_buff, int rsp_buff_len);

#if defined(__cplusplus)
}
#endif
#endif //CNIOT_ATLAS_ATLAS_UTILITY_H
