#ifndef CNIOT_ATLAS_ATLAS_PROTOCOL_COAP_H
#define CNIOT_ATLAS_ATLAS_PROTOCOL_COAP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "cniot_atlas_code.h"

#define C_MAX_COAP_MSG_LENGTH   (1024)
typedef enum {
    C_RSP_FORMAT_TEXT = 1,
    C_RSP_FORMAT_JSON = 2
}coAP_rsp_format_t;

#define C_MAX_COAP_HEARTBEAT        (5000)
#define C_MAX_COAP_REQUEST_TIMEOUT  (16000)
#define C_MAX_COAP_TIMEOUT          (27000)
#define C_MIN_PROC_TIMES_PRE_SECOND     (10)
#define C_PROC_INTERVAL_TIME           (100)

CNIOT_STATUS_CODE cniot_atlas_coap_connect(const char* addr);

CNIOT_STATUS_CODE cniot_atlas_coap_request(char *path, const char *data, int len, coAP_rsp_format_t rsp_format, char *rsp, int *rsp_len);

CNIOT_STATUS_CODE cniot_atlas_coap_invoking(uint64_t messageId, const char *request, int request_len, char *buff, int buf_len);

CNIOT_STATUS_CODE cniot_atlas_coap_proc(const char *addr, uint32_t timeout);

CNIOT_STATUS_CODE cniot_atlas_coap_disconnect();

CNIOT_STATUS_CODE cniot_atlas_get_coap_status(int *status);

CNIOT_STATUS_CODE cniot_send_coap_loadTest();

#if defined(__cplusplus)
}
#endif

#endif
