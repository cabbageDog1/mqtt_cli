#include "cniot_atlas_wrapper.h"
#include "infra_compat.h"
#include "atlas_services.h"
#include "atlas_utility.h"

typedef struct {
    char service_name[C_MAX_SERVICE_NAME];
    atlas_service_callback_fun_t fun;
    void *pHandle;
    list_head_t node;
}cniot_service_t;

static int g_services_initialize = 0;
static void *g_service_mutex = NULL;
static list_head_t g_services_list = {&g_services_list, &g_services_list};
static char *g_module = {"services"};
static atlas_status_callback_fun_t g_status_callback;
static void *g_callback_data = NULL;

CNIOT_STATUS_CODE cniot_atlas_services_initialize(void) {
    if (g_services_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    g_service_mutex = atlas_mutex_create();
    g_services_initialize = 1;
    return CNIOT_STATUS_CODE_OK;
}
CNIOT_STATUS_CODE cniot_atlas_services_finalize(void) {
    if (!g_services_initialize) {
        return CNIOT_STATUS_CODE_OK;
    }
    atlas_mutex_destroy(g_service_mutex);
    g_service_mutex = NULL;
    g_services_initialize = 0;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_services_startup(void) {
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_services_shutdown(void) {
    cniot_service_t *sevice = NULL, *tmp = NULL;
    atlas_mutex_lock(g_service_mutex);
    list_for_each_entry_safe(sevice, tmp,&g_services_list, node, cniot_service_t) {
            list_del(&sevice->node);
            atlas_free(sevice);
    }
    atlas_mutex_unlock(g_service_mutex);

    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_services_register(const char* service_name, atlas_service_callback_fun_t fun, void *handle){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_service_t *sevice = NULL;

    CHECK_VALUE_NULL(service_name);
    CHECK_VALUE_NULL(fun);

    if (!g_services_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_service_mutex);

    list_for_each_entry(sevice, &g_services_list, node, cniot_service_t) {
        if (0 == strcmp(sevice->service_name, service_name)) {
            ret = CNIOT_STATUS_ALREADY_EXIST;
            goto L_ERROR;
        }
    }
    if (C_MAX_SERVICE_NAME <= strlen(service_name)) {
        ret = CNIOT_STATUS_PARMETER_OVERFOLW;
        goto L_ERROR;
    }
    CHECK_MALLOC_VALUE(sevice, atlas_malloc(sizeof(cniot_service_t)), L_ERROR, ret);
    strcpy(sevice->service_name, service_name);
    sevice->fun = fun;
    sevice->pHandle = handle;
    list_add_tail(&sevice->node, &g_services_list);
    log_info(g_module, "register service %s handle=%p success", service_name, handle);
L_ERROR:
    atlas_mutex_unlock(g_service_mutex);
    return ret;
}

CNIOT_STATUS_CODE cniot_atlas_services_unregister(const char *service_name){
    CHECK_VALUE_NULL(service_name);
    if (!g_services_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    cniot_service_t *sevice = NULL;

    atlas_mutex_lock(g_service_mutex);
    list_for_each_entry(sevice, &g_services_list, node, cniot_service_t) {
        if (0 == strcmp(sevice->service_name, service_name)) {
            list_del(&sevice->node);
            atlas_free(sevice);
            log_info(g_module, "unregister service %s", service_name);
            break;
        }
    }
    atlas_mutex_unlock(g_service_mutex);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_get_service(const char *service_name, atlas_service_callback_fun_t *fun, void **handle){
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_NOT_EXIST;
    cniot_service_t *sevice = NULL;

    CHECK_VALUE_NULL(service_name);
    CHECK_VALUE_NULL(fun);
    CHECK_VALUE_NULL(handle);
    if (!g_services_initialize) {
        return CNIOT_STATUS_NOT_INITIALIZE;
    }
    atlas_mutex_lock(g_service_mutex);
    list_for_each_entry(sevice, &g_services_list, node, cniot_service_t) {
        if (0 == strcmp(sevice->service_name, service_name)) {
            *fun = sevice->fun;
            *handle = sevice->pHandle;
            ret = CNIOT_STATUS_CODE_OK;
            break;
        }
    }
    atlas_mutex_unlock(g_service_mutex);
    return ret;
}

CNIOT_STATUS_CODE atlas_register_status_callback(atlas_status_callback_fun_t fun, void *user_data){
    CHECK_VALUE_NULL(fun);
    g_status_callback = fun;
    g_callback_data = user_data;
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE cniot_atlas_post_core_event(CNIOT_EVENT_T event, char *event_msg) {
    if (NULL != g_status_callback) {
        g_status_callback(g_callback_data, event, event_msg);
    }
    return CNIOT_STATUS_CODE_OK;
}