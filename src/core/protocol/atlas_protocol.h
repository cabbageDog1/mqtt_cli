#ifndef CNIOT_ATLAS_ATLAS_PROTOCOL_H
#define CNIOT_ATLAS_ATLAS_PROTOCOL_H

#if defined(__cplusplus)
extern "C" {
#endif
#include "cniot_atlas_code.h"
#include "../atlas_core.h"
#include "knife/atlas_knife_protocol.h"

#define C_PROTOCOL_PROC_TIMEOUT    (1000)

CNIOT_STATUS_CODE cniot_atlas_protocol_initialize(void);

CNIOT_STATUS_CODE cniot_atlas_protocol_finalize(void);

CNIOT_STATUS_CODE cniot_atlas_protocol_startup(void);

CNIOT_STATUS_CODE cniot_atlas_protocol_shutdown(void);

/*
 * 上传物实体信息
 * 参数：
 *     entity 物实体
 *     event  上报事件名称
 *     body   上报参数json
 *
 */
CNIOT_STATUS_CODE cniot_atlas_write(cniot_atlas_thing_entity_t *entity, const char *event, const char *body, char *rsp, int *rsp_len);


CNIOT_STATUS_CODE atlas_protocol_invoker_service(const char *serviceName,
        const char *params,
        const char *requestId,
        const char *traceId,
        char *sessionId,
        const char *bizKey,
        char *rsp,
        int rsp_len);

/*
 * 协议调度线程
 */
CNIOT_STATUS_CODE cniot_protocol_proc(uint32_t time);

CNIOT_STATUS_CODE cniot_protocol_process_method_v1(const char *data, int data_len);

CNIOT_STATUS_CODE cniot_protocol_process_method_v2(const char *data, int data_len);

CNIOT_STATUS_CODE cniot_protocol_process_properties_change(const char *data, int data_len);

CNIOT_STATUS_CODE cniot_protocol_get_protocol(CNIOT_PROTOCOL *protocol);

CNIOT_STATUS_CODE cniot_protocol_get_addr(char *addr, int *status);

CNIOT_STATUS_CODE cniot_protocol_set_addr(int protocol,int version, char *addr);

#if defined(__cplusplus)
}
#endif

#endif
