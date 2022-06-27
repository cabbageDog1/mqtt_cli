#ifndef CNIOT_ATLAS_ATLAS_CORE_H
#define CNIOT_ATLAS_ATLAS_CORE_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "cniot_atlas.h"

typedef struct {
    char iot_id[C_MAX_ID_LEN]; // 星图的iotID
    char entity_name[C_MAX_ENTITY_NAME_LEN]; // 物实体名称
    char entity_secret[C_MAX_ENTITY_SECRET_LEN]; // 物实体密钥
    char thing_key[C_MAX_THING_KEY];  // 物类型key
    char thing_secret[C_MAX_THING_SECRET_LEN]; //物类型密钥
}cniot_atlas_thing_entity_t;

/*
 * 获取运行环境
 * */
CNIOT_STATUS_CODE atlas_core_get_env(char ** env);

/*
 * 获取http地址
 * */
CNIOT_STATUS_CODE atlas_core_get_addr(char ** host);

/*
 * 获取物实体信息
 */
CNIOT_STATUS_CODE atlas_core_get_entity(cniot_atlas_thing_entity_t **entry);

/*
 * 获取边缘网关列表
 */
CNIOT_STATUS_CODE  atlas_get_edge_service_list(char *buf, int buf_len);

CNIOT_STATUS_CODE  atlas_get_network_status(C_CNIOT_NETWORK_STATUS *status);

CNIOT_STATUS_CODE  atlas_check_network_disconnect(unsigned long long last_check_time, int *is_disconnect);

int atlas_check_can_upload_log();

#if defined(__cplusplus)
}
#endif

#endif //CNIOT_ATLAS_ATLAS_CORE_H
