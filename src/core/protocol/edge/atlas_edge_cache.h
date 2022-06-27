#ifndef CNIOT_ATLAS_ATLAS_EDGE_CACHE_H
#define CNIOT_ATLAS_ATLAS_EDGE_CACHE_H

#include "cniot_atlas.h"

typedef struct {
    char addr[C_MAX_URL_LEN];
    char protocol[C_MAX_PROTOCOL_LEN];
    char version[C_MAX_VERSION_LEN];
}atlas_bus_protocol_t;

CNIOT_STATUS_CODE cniot_atlas_edge_cache_initialize(void);

CNIOT_STATUS_CODE cniot_atlas_edge_cache_finalize(void);

CNIOT_STATUS_CODE cniot_atlas_edge_cache_startup(void);

CNIOT_STATUS_CODE cniot_atlas_edge_cache_shutdown(void);

CNIOT_STATUS_CODE atlas_edge_cache_push(atlas_bus_protocol_t *info);

CNIOT_STATUS_CODE atlas_edge_cache_pop(atlas_bus_protocol_t *info);

CNIOT_STATUS_CODE atlas_edge_cache_clear(void);

#endif //CNIOT_ATLAS_ATLAS_EDGE_CACHE_H
