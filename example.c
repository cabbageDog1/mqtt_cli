#include <stdlib.h>
#include <stdio.h>
#include "cniot_atlas.h"
#include "cniot_atlas_wrapper.h"

static char *g_module={"main"};
static uint64_t startup_time = 0;

CNIOT_STATUS_CODE connectTest(void *ptr, const char *parm, int parm_length, char **rsp) {
    *rsp = atlas_malloc(64);
    atlas_snprintf(*rsp, 64, "{\"retMessage\":\"just for sdk test %llu\"}", atlas_abs_time());
    printf("receive %s\n", parm);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE status_callback(void *ptr, CNIOT_EVENT_T event, char *msg) {
    printf("--->>> event=%d msg=%s cost_time=%lld\n", event, msg, atlas_boot_uptime() - startup_time);
    return CNIOT_STATUS_CODE_OK;
}

int main(int arg, char *argv[]) {
    char iot_id[C_MAX_ID_LEN] = {0};
    char secret[C_MAX_ID_LEN] = {0};
    char device_name[C_MAX_ID_LEN] = {0};
    char msg[C_MAX_BODY_LEN] = {0};
    char deviceName[C_MAX_ID_LEN] = {"testDevice"}; //设备标识
    CNIOT_STATUS_CODE res = CNIOT_STATUS_CODE_OK;

    atlas_register_status_callback(status_callback, NULL); //事件状态回调
    atlas_set_server_addr(C_CNIOT_PROTOCOL_MQTT, "ssl-shiot.cainiao.com"); //指定连接mqtt

    atlas_set_server_domain(CNIOT_ATLAS_DOMAIN_WUTONG); //指定连接域..

    res = cniot_atlas_thing_entity_register("online", deviceName,
                                            "58f6937513cd40cf",
                                            "linxun_test",
                                            device_name,
                                            iot_id,
                                            secret);  //参数对齐控制台参数

    if (res != CNIOT_STATUS_CODE_OK) { //@todo 注册失败则需要重试...
        return -1;
    }
    printf("get res=%d iot_id=%s secret=%s\n", res, iot_id, secret);
    //初始化资源
    cniot_atlas_initialize("online", deviceName, secret,"linxun_test", iot_id);

    startup_time = atlas_boot_uptime();

    //启动sdk
    cniot_atlas_startup();

    atlas_usleep(5000); // 修改为通过状态判断是否连接上

    //以下事件方法属性需要先在控制台配置

    atlas_thing_service_register("pushMessage", connectTest, msg); //注册服务.耗时长的服务注意开线程处理

    atlas_snprintf(msg, C_MAX_BODY_LEN, "{\"message\":\"%s\"}", "event post");

    res = atlas_thing_event_post("logReport", msg); //事件汇报

    atlas_snprintf(msg, C_MAX_BODY_LEN, "{\"floor\":%llu}", 123);

    res = atlas_thing_set_properties(msg); //属性上报

    atlas_usleep(1000 * 1000);

    return 0;
}

