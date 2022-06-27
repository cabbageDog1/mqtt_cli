#ifndef CNIOT_ATLAS_ATLAS_HTTP_POOL_H
#define CNIOT_ATLAS_ATLAS_HTTP_POOL_H

#include "cniot_atlas.h"

CNIOT_STATUS_CODE http_pool_new(const char *host, int pool_size);

CNIOT_STATUS_CODE http_pool_scheduler();

CNIOT_STATUS_CODE http_pool_send_body(unsigned char *body, int body_len, char *rsp, int *rsp_len);

CNIOT_STATUS_CODE http_pool_free();

#endif
