#ifndef CNIOT_ATLAS_ATLAS_SERVICES_H
#define CNIOT_ATLAS_ATLAS_SERVICES_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "cniot_atlas.h"
#include "cniot_atlas_code.h"

#define C_MAX_SERVICE_NAME   128

CNIOT_STATUS_CODE cniot_atlas_services_initialize(void);

CNIOT_STATUS_CODE cniot_atlas_services_finalize(void);

CNIOT_STATUS_CODE cniot_atlas_services_startup(void);

CNIOT_STATUS_CODE cniot_atlas_services_shutdown(void);

CNIOT_STATUS_CODE cniot_atlas_services_register(const char *service_name, atlas_service_callback_fun_t fun, void *handle);

CNIOT_STATUS_CODE cniot_atlas_services_unregister(const char *service_name);

CNIOT_STATUS_CODE cniot_atlas_get_service(const char *service_name, atlas_service_callback_fun_t*fun, void **handle);

CNIOT_STATUS_CODE cniot_atlas_post_core_event(CNIOT_EVENT_T event, char *event_msg);

#if defined(__cplusplus)
}
#endif

#endif //CNIOT_ATLAS_ATLAS_SERVICES_H
