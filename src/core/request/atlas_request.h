#ifndef CNIOT_ATLAS_ATLAS_REQUEST_H
#define CNIOT_ATLAS_ATLAS_REQUEST_H

#include "cniot_atlas.h"

#define C_MAX_REQUEST_NUM (10)

typedef CNIOT_STATUS_CODE (*atlas_request_done_fun_t)(void *ptr, int len, void *rsp_buff, int *rsp_len);

CNIOT_STATUS_CODE cniot_atlas_request_initialize(void);

CNIOT_STATUS_CODE cniot_atlas_request_finalize(void);

CNIOT_STATUS_CODE cniot_atlas_request_startup(void);

CNIOT_STATUS_CODE cniot_atlas_request_shutdown(void);

CNIOT_STATUS_CODE atlas_add_request(uint64_t msgId, int timeout,const char *request, int request_len, char*buff, int buff_len, atlas_request_done_fun_t fun);

CNIOT_STATUS_CODE atlas_del_request(uint64_t msgId);

CNIOT_STATUS_CODE atlas_set_response(uint64_t msgId, const char *payload, int payload_len);

CNIOT_STATUS_CODE atlas_get_response(uint64_t msgId);

CNIOT_STATUS_CODE atlas_request_proc(int *proc_request);

#endif //CNIOT_ATLAS_ATLAS_REQUEST_H
