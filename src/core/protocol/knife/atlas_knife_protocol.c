#include "atlas_knife_protocol.h"
#include "atlas_utility.h"
#include <stdlib.h>
#include "infra_binarydata.h"

static char *g_module = {"KNIFE"};
#pragma pack (1)
typedef struct {
    uint16_t flag;
    uint8_t version;
    uint32_t json_length;
    uint8_t  json_data;
} atlas_knife_header_t;

typedef struct {
    uint16_t type;
    uint32_t length;
    uint8_t value;
}atlas_knife_data_t;

typedef struct {
    uint8_t used;
    uint8_t flag;
    uint16_t key;
    int32_t data_len;
    uint64_t kick_off;
    void *data;
}knife_entry_t;
#pragma pack()

static void *g_knife_mutex = NULL;
static int g_knife_initialize = 0;

static knife_entry_t *g_knife_list = NULL;
#define C_MAX_ENTRY_NUM        (256)

CNIOT_STATUS_CODE cniot_atlas_knife_protocol_initialize(void) {
    CNIOT_STATUS_CODE  ret = CNIOT_STATUS_CODE_OK;
    if (g_knife_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_knife_initialize = 1;
    g_knife_mutex = atlas_mutex_create();
    CHECK_MALLOC_VALUE(g_knife_mutex, atlas_mutex_create(), L_FAILED, ret);
    CHECK_MALLOC_VALUE(g_knife_list,  atlas_malloc(sizeof(knife_entry_t) * C_MAX_ENTRY_NUM), L_FAILED, ret);
    memset(g_knife_list, 0, sizeof(knife_entry_t) * C_MAX_ENTRY_NUM);
    return CNIOT_STATUS_CODE_OK;
L_FAILED:
    cniot_atlas_knife_protocol_finalize();
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_knife_protocol_finalize(void) {
    if (!g_knife_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_knife_initialize = 0;
    atlas_mutex_destroy(g_knife_mutex);
    g_knife_mutex = NULL;
    atlas_free(g_knife_list);
    g_knife_list = NULL;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_knife_protocol_startup(void) {
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_knife_protocol_shutdown(void) {
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_knife_parm_encode(const void *data, int data_len,char *parm, int *type) {
    int i = 1;
    int idx = C_MAX_ENTRY_NUM;
    uint64_t lru_time = atlas_boot_uptime();
    CNIOT_STATUS_CODE  ret  = CNIOT_STATUS_BUFFER_OVERFLOW;
    if (!g_knife_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CHECK_VALUE_NULL(data);
    CHECK_VALUE_NULL(parm);
    CHECK_VALUE_NULL(type);

    if (C_MAX_BINARY_DATA_LEN <= data_len) {
        return CNIOT_STATUS_BUFFER_OVERFLOW;
    }
    atlas_mutex_lock(g_knife_mutex);

    for (i = 1; i < C_MAX_ENTRY_NUM; ++i) {
        if (0 == g_knife_list[i].used) {
            idx = i;
            break;
        }
        if (g_knife_list[i].kick_off < lru_time) {
            lru_time = g_knife_list[i].kick_off;
            idx = i;
        }
    }
    atlas_snprintf(parm, C_MAX_KNIFE_PARM_LENGTH, "$KNIFE%d", idx, data, data_len);
    g_knife_list[idx].data = (void *)data;
    g_knife_list[idx].data_len = data_len;
    g_knife_list[idx].flag = 0;
    g_knife_list[idx].used = 1;
    g_knife_list[idx].kick_off = atlas_boot_uptime();
    *type = idx;
    logger_info("encode data=%p data_len=%d type=%d", data, data_len, idx);
    ret = CNIOT_STATUS_CODE_OK;
    atlas_mutex_unlock(g_knife_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_knife_parm_decode(const char *parm, int *key, void **data, int *data_len) {
    char *p = NULL;
    const char *end = NULL;
    if (!g_knife_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CHECK_VALUE_NULL(data);
    CHECK_VALUE_NULL(parm);
    CHECK_VALUE_NULL(key);
    CHECK_VALUE_NULL(data_len);

    p = strstr(parm , "$KNIFE");
    if (p == NULL || p != parm) {
        logger_err("parm %s is not knife", parm);
        return CNIOT_STATUS_PARM_ERROR;
    }
    end = parm + strlen(parm);
    *key = 0;
    p += strlen("$KNIFE");

    while(p <= end) {
        if (*p < '0' || '9' < *p) {
            break;
        }
        *key = (*key) * 10 + (*(p) - '0');
        p++;
    }

    if (C_MAX_ENTRY_NUM < *key || *key <= 0) {
        return CNIOT_STATUS_PARM_ERROR;
    }

    atlas_mutex_lock(g_knife_mutex);
    if (g_knife_list[*key].used == 0) {
        atlas_mutex_unlock(g_knife_mutex);
        logger_err("found key=%d not exist in list", *key);
        return CNIOT_STATUS_PARM_ERROR;
    }
    *data = g_knife_list[*key].data;
    *data_len = g_knife_list[*key].data_len;
    atlas_mutex_unlock(g_knife_mutex);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_knife_parm_free(int type) {
    if (!g_knife_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    if (C_MAX_ENTRY_NUM <= type || type <= 0) {
        return CNIOT_STATUS_PARM_ERROR;
    }
    atlas_mutex_lock(g_knife_mutex);
    if (g_knife_list[type].used == 0) {
        atlas_mutex_unlock(g_knife_mutex);
        logger_err("found type=%d not exist in list", type);
        return CNIOT_STATUS_PARM_ERROR;
    }
    g_knife_list[type].used = 0;
    g_knife_list[type].data_len = 0;
    g_knife_list[type].data = NULL;
    g_knife_list[type].flag = 0;
    g_knife_list[type].kick_off = 0;
    logger_info("free knife type=%d ", type);
    atlas_mutex_unlock(g_knife_mutex);

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_knife_check(const char *data) {
    CHECK_VALUE_NULL(data);
    if (NULL == strstr(data, "$KNIFE")) {
        return CNIOT_STATUS_PARM_ERROR;
    }
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE atlas_knife_protocol_encode(const char *json_data, void *buff, int *data_len) {
    CNIOT_STATUS_CODE  ret = CNIOT_STATUS_CODE_OK;
    atlas_knife_header_t *header = buff;
    atlas_knife_data_t *knife_data = NULL;
    uint8_t *p = NULL, *end = NULL;
    void *entry_data = NULL;
    int parm_len = 0, knife_type = 0, entry_length = 0;
    const char *knife_parm = json_data;
    CHECK_VALUE_NULL(json_data);
    CHECK_VALUE_NULL(buff);
    CHECK_VALUE_NULL(data_len);
    if (!g_knife_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }

    parm_len = (int)strlen(json_data);
    if (*data_len < parm_len) {
        return CNIOT_STATUS_BUFFER_OVERFLOW;
    }
    end = buff + *data_len;
    header->flag = atlas_htons(0x0510);
    header->version = 1;
    header->json_length = atlas_htonl(parm_len);
    memcpy(&header->json_data, json_data, parm_len);
    p = &header->json_data + parm_len;
    knife_data = (atlas_knife_data_t *)(p);
    while(NULL != (knife_parm = strstr(knife_parm, "$KNIFE"))) {
        CHECK_RETURN_VALUE(ret, atlas_knife_parm_decode(knife_parm, &knife_type, &entry_data, &entry_length), L_FAILED);
        knife_data->type = atlas_htons(knife_type);
        knife_data->length = atlas_htonl(entry_length);
        if (end <= (uint8_t *)knife_data + sizeof(atlas_knife_data_t) + entry_length - 1 ) {
            ret = CNIOT_STATUS_BUFFER_OVERFLOW;
            goto L_FAILED;
        }
        memcpy(&knife_data->value, entry_data, entry_length);
        knife_data = (atlas_knife_data_t *)(&knife_data->value + entry_length);
        knife_parm += sizeof("$KNIFE");
    }
    knife_data->type = 0;
    *data_len = (int)((uint8_t *)(&knife_data->length) - (uint8_t *)buff);
L_FAILED:
    return ret;
}

CNIOT_STATUS_CODE atlas_knife_protocol_decode(void *data, int data_len) {
    atlas_knife_header_t *header = data;
    atlas_knife_data_t *knife_data = NULL;
    int length = 0, knife_length = 0;
    char *json_data = NULL;
    uint8_t *end = (uint8_t *)data + data_len;
    CNIOT_STATUS_CODE  ret = CNIOT_STATUS_CODE_OK;

    CHECK_VALUE_NULL(data);

    if (atlas_ntohs(header->flag) != 0x0510) {
        logger_err("is not kenife protocol flag=%x", header->flag);
        return CNIOT_STATUS_PARM_ERROR;
    }

    if (header->version != 0x01) {
        logger_err("knife version not match version=%u", header->version);
        return CNIOT_STATUS_NOT_SUPPORT;
    }

    length = (int)atlas_ntohl(header->json_length);
    if (data_len < length) {
        logger_err("decode json length=%u is bigger than body length=%u", length, data_len);
        return CNIOT_STATUS_PARM_ERROR;
    }

    CHECK_MALLOC_VALUE(json_data, atlas_malloc(length + 1), L_FAILED, ret);
    memcpy(json_data, &header->json_data, length);
    json_data[length] = '\0';
    knife_data = (atlas_knife_data_t *) (&header->json_data + length);
    knife_length = atlas_ntohl(knife_data->length);
    while (knife_data->type != 0x00 && ((&knife_data->value + knife_length) < end)) {
        printf("decode type=%d length=%d\n", atlas_ntohs(knife_data->type), knife_length);
        knife_data = (atlas_knife_data_t *)(&knife_data->value + knife_length);
        knife_length = atlas_ntohl(knife_data->length);
    }
L_FAILED:
    atlas_free(json_data);
    return ret;
}

CNIOT_STATUS_CODE atlas_knife_parm_finalize(void *data) {
    char *knife_parm = data;
    int knife_type = 0, entry_length = 0;
    void *entry_data = NULL;
    CNIOT_STATUS_CODE  ret = CNIOT_STATUS_CODE_OK;
    if (!g_knife_initialize){
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CHECK_VALUE_NULL(data);
    while(NULL != (knife_parm = strstr(knife_parm, "$KNIFE"))) {
        CHECK_RETURN_VALUE(ret, atlas_knife_parm_decode(knife_parm, &knife_type, &entry_data, &entry_length), L_FAILED);
        atlas_knife_parm_free(knife_type);
        knife_parm += sizeof("$KNIFE");
    }
L_FAILED:
    return ret;
}