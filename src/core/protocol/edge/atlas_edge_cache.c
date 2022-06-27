#include "infra_compat.h"
#include "atlas_edge_cache.h"
#include "atlas_utility.h"

#define C_MAX_EDGE_LIST_COUNT  (10)
static char *g_module = {"edgeCache"};
static int g_initialize = 0;
static list_head_t  g_edge_list = {&g_edge_list, &g_edge_list};
static void *g_edge_list_mutex = NULL;
static int g_list_count = 0;

typedef struct {
    atlas_bus_protocol_t  info;
    list_head_t node;
}cniot_edge_node_t;

CNIOT_STATUS_CODE cniot_atlas_edge_cache_initialize(void){
    if (g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_initialize = 1;
    list_init(&g_edge_list);
    g_edge_list_mutex = atlas_mutex_create();
    logger_info("edge cache initialize success");
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_edge_cache_finalize(void) {
    if (!g_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_initialize = 0;
    atlas_mutex_destroy(g_edge_list_mutex);
    g_edge_list_mutex = NULL;
    logger_info("edge cache finalize success");
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_edge_cache_startup(void) {
    logger_info("edge cache startup success");
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_edge_cache_shutdown(void) {
    logger_info("edge cache shutdown success");
    return CNIOT_STATUS_CODE_OK;
}

static int is_intranet_ip(const char *addr) {
    int ip[4] = {0,0,0,0};
    int ip_count = 0;
    int len = 0;
    int idx = 0;

    if (!addr) {
        return -1;
    }

    len = (int)strlen(addr);
    while (idx < len) {
        if (addr[idx] == '.') {
            if(++ip_count >= 4) {
                return -1;
            }
            idx++;
            continue;
        }
        if ('0' <= addr[idx] && addr[idx] <= '9') {
            ip[ip_count] = ip[ip_count] * 10 + (addr[idx] - '0');
        } else {
            return -1;
        }
        idx++;
    }
    if (ip_count != 3) {
        return -1;
    }
    if ((ip[0] == 10)  || (192 == ip[0] && 168 == ip[1]) || (172 == ip[0] && 16 <= ip[1] && ip[1] <= 31)) {
        return 1;
    }
    return 0;
}

static char *parse_host_from_url(char *host, const char *addr) {
    char *hostPtr = strstr(addr, "://");
    char *portPtr = NULL;
    int hostLen = C_MAX_HOST_LEN;
    if (hostPtr != NULL) {
        hostPtr += 3;
    } else {
        hostPtr = (char *)addr;
    }
    portPtr = strstr(hostPtr, ":");
    if (portPtr != NULL) {
        hostLen = portPtr - hostPtr;
    }
    strncpy(host, hostPtr, hostLen);
    logger_info("[edge] parse mqtt from addr=%s host=%s", addr, host);
    return host;
}

CNIOT_STATUS_CODE atlas_edge_cache_push(atlas_bus_protocol_t *info) {
    char host[C_MAX_HOST_LEN] = {0};
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_edge_node_t *edge_node = NULL;
    int malloc_success = 0;
    int ip_type = 0;
    CHECK_VALUE_NULL(info);

    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    if (0 == strcmp(info->protocol, "mqtt")) {
        parse_host_from_url(host, info->addr);
    } else {
        strcpy(host, info->addr);
    }
    ip_type = is_intranet_ip(host);
    atlas_mutex_lock(g_edge_list_mutex);
    if (g_list_count > C_MAX_EDGE_LIST_COUNT) {
        ret = CNIOT_STATUS_BUFFER_OVERFLOW;
        goto L_FAILED;
    }
    CHECK_MALLOC_VALUE(edge_node, atlas_malloc(sizeof(cniot_edge_node_t)), L_FAILED, ret);
    malloc_success = 1;
    strcpy(edge_node->info.addr, info->addr);
    strcpy(edge_node->info.version, info->version);
    strcpy(edge_node->info.protocol, info->protocol);
    list_init(&edge_node->node);
    if (ip_type <= 0) {
        list_add_tail(&edge_node->node, &g_edge_list);
    } else {
        list_add(&edge_node->node, &g_edge_list);
    }
    g_list_count++;
    logger_warning("edge cache add list addr=%s success total_count=%d", info->addr, g_list_count);
L_FAILED:
    if (ret != CNIOT_STATUS_CODE_OK && malloc_success) {
        atlas_free(edge_node);
    }
    atlas_mutex_unlock(g_edge_list_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_edge_cache_pop(atlas_bus_protocol_t *info) {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_edge_node_t *edge_node = NULL;
    CHECK_VALUE_NULL(info);
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_edge_list_mutex);
    if (g_list_count == 0) {
        ret = CNIOT_STATUS_BUFFER_EMPTY;
        goto L_FAILED;
    }
    list_for_each_entry(edge_node, &g_edge_list, node, cniot_edge_node_t) {
        strcpy(info->addr, edge_node->info.addr);
        strcpy(info->version, edge_node->info.version);
        strcpy(info->protocol, edge_node->info.protocol);
        list_del_init(&edge_node->node);
        atlas_free(edge_node);
        g_list_count--;
        logger_warning("edge cache pop addr=%s success total_count=%d", info->addr, g_list_count);
        break;
    }
L_FAILED:
    atlas_mutex_unlock(g_edge_list_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_edge_cache_clear() {
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_edge_node_t *edge_node = NULL, *tmp = NULL;
    if (!g_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_edge_list_mutex);
    if (g_list_count == 0) {
        ret = CNIOT_STATUS_BUFFER_EMPTY;
        goto L_FAILED;
    }
    list_for_each_entry_safe(edge_node, tmp, &g_edge_list, node, cniot_edge_node_t) {
        list_del_init(&edge_node->node);
        atlas_free(edge_node);
        g_list_count--;
    }
    logger_warning("[edge]edge cache clear total_count=%d", g_list_count);
L_FAILED:
    atlas_mutex_unlock(g_edge_list_mutex);
    return ret;
}