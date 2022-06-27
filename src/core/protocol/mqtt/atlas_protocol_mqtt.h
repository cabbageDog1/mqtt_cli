#ifndef CNIOT_ATLAS_ATLAS_PROTOCOL_MQTT_H
#define CNIOT_ATLAS_ATLAS_PROTOCOL_MQTT_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "atlas_core.h"
#define C_MAX_MQTT_KEY_LEN   (256)
#define C_MAX_USER_NAME_LEN  (128)
#define C_MAX_CLIENT_ID_LEN  (256)

CNIOT_STATUS_CODE cniot_atlas_mqtt_connect(const char* addr, cniot_atlas_thing_entity_t *entity);

CNIOT_STATUS_CODE cniot_atlas_mqtt_write(cniot_atlas_thing_entity_t *entity, const char *topic, const char *data);

CNIOT_STATUS_CODE cniot_atlas_mqtt_invoking(cniot_atlas_thing_entity_t *entity, uint64_t messageId,
        const char *request, int request_len, char *buff, int len);

CNIOT_STATUS_CODE cniot_atlas_mqtt_proc(char *addr, int protocol_version, uint32_t time);

CNIOT_STATUS_CODE cniot_atlas_mqtt_disconnect();

CNIOT_STATUS_CODE cniot_stlas_mqtt_status(int *status);

#if defined(__cplusplus)
}
#endif
#endif //CNIOT_ATLAS_ATLAS_PROTOCOL_MQTT_H
