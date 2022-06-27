#ifndef _COAP_WRAPPER_H_
#define _COAP_WRAPPER_H_

#include "infra_types.h"
#include "infra_defs.h"
#include "wrappers_defs.h"
#include "cniot_atlas_wrapper.h"

int HAL_DTLSHooks_set(dtls_hooks_t *hooks);
DTLSContext *HAL_DTLSSession_create(coap_dtls_options_t  *p_options);
unsigned int HAL_DTLSSession_write(DTLSContext *context,
        const unsigned char *p_data,
        unsigned int *p_datalen);
unsigned int HAL_DTLSSession_read(DTLSContext *context,
        unsigned char *p_data,
        unsigned int *p_datalen,
        unsigned int timeout_ms);
unsigned int HAL_DTLSSession_free(DTLSContext *context);
p_HAL_Aes128_t HAL_Aes128_Init(
            const uint8_t *key,
            const uint8_t *iv,
            AES_DIR_t dir);
int HAL_Aes128_Destroy(p_HAL_Aes128_t aes);
int HAL_Aes128_Cbc_Encrypt(
            p_HAL_Aes128_t aes,
            const void *src,
            size_t blockNum,
            void *dst);
int HAL_Aes128_Cbc_Decrypt(
            p_HAL_Aes128_t aes,
            const void *src,
            size_t blockNum,
            void *dst);
#endif
