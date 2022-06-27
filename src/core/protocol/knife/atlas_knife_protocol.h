#ifndef CNIOT_ATLAS_ATLAS_KNIFE_PROTOCOL_H
#define CNIOT_ATLAS_ATLAS_KNIFE_PROTOCOL_H
#if defined(__cplusplus)
extern "C" {
#endif
#include "atlas_core.h"

#define C_MAX_KNIFE_PARM_LENGTH    (64)

    CNIOT_STATUS_CODE cniot_atlas_knife_protocol_initialize(void);

    CNIOT_STATUS_CODE cniot_atlas_knife_protocol_finalize(void);

    CNIOT_STATUS_CODE cniot_atlas_knife_protocol_startup(void);

    CNIOT_STATUS_CODE cniot_atlas_knife_protocol_shutdown(void);

    CNIOT_STATUS_CODE atlas_knife_parm_encode(const void *data, int data_len,char *parm, int *encode_flag);

    CNIOT_STATUS_CODE atlas_knife_parm_decode(const char *parm, int *key, void **data, int *data_len);

    CNIOT_STATUS_CODE atlas_knife_parm_finalize(void *data);

    CNIOT_STATUS_CODE atlas_knife_check(const char *data);

    CNIOT_STATUS_CODE atlas_knife_protocol_encode(const char *body, void *buff, int* data_len);

    CNIOT_STATUS_CODE atlas_knife_protocol_decode(void *data, int data_len);

#if defined(__cplusplus)
}
#endif

#endif
