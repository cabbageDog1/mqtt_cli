#include <stdlib.h>
#include <stdio.h>
#include "protocol/mqtt/atlas_protocol_mqtt.h"
#include "atlas_utility.h"
#include "infra_cjson.h"
#include "protocol/atlas_protocol.h"
#include "protocol/http/infra_httpc.h"
#include "protocol/edge/atlas_edge_cache.h"
#include "cniot_atlas.h"
#include "cniot_atlas_wrapper.h"
#include "protocol/coap/atlas_protocol_coap.h"

static char g_sessionId[C_MAX_ID_LEN] = {0};
static char *g_module={"main"};
static int g_running = 1;
static int g_request_success = 0;
static int g_request_failed = 0;
static void *g_atlas_mutex = NULL;
extern const char *iotx_ca_crt;
static uint64_t startup_time = 0;
static void add_request_ret(CNIOT_STATUS_CODE code) {
    atlas_mutex_lock(g_atlas_mutex);
    if (code == CNIOT_STATUS_CODE_OK) {
        g_request_success++;
    } else {
        g_request_failed++;
    }
    atlas_mutex_unlock(g_atlas_mutex);
}

void setWifiTestMessage(char *buff) {
    atlas_snprintf(buff, 512, "assoc:1,1,1585020046\n"
                              "auth:1,1234567890\n"
                              "dhcp:1,1234567890\n"
                              "bss:ff:ff:ff:ff:ff:ff\n"
                              "ssid:alibaba-inc\n"
                              "rssi:65\n"
                              "channel:165\n"
                              "ip:223.233.233.233\n"
                              "gw:233.233.233.254\n"
                              "dns:223.222.223.223");
}
void registerTest() {
    CNIOT_STATUS_CODE res  = CNIOT_STATUS_CODE_OK;
    char iot_id[128] = {0};
    char secret[128] = {0};
    char device_name[128] = {0};
    atlas_set_loglevel(5);
    //atlas_set_server_domain(CNIOT_ATLAS_DOMAIN_WUTONG);
    res = cniot_atlas_thing_entity_register("online", "test_00001",
                                            "9ca39e81152a4452",
                                            "LEMO",
                                            device_name,
                                            iot_id,
                                            secret);

    printf("get res=%d iot_id=%s secret=%s\n", res, iot_id, secret);
}

void topicSubscribe(char * macAddr) {
    CNIOT_STATUS_CODE res  = CNIOT_STATUS_CODE_OK;
    char iot_id[128] = {0};
    char secret[128] = {0};
    char device_name[128] = {0};
    char addr[64] = {0};
    strncpy(addr,  macAddr, 17);
    int idx = 16;

    while(idx >=0 && (addr[idx] == 'f' || addr[idx] == ':') ) {
        if (addr[idx] == 'f') {
            addr[idx] = '0';
        }
        idx--;
    }

    addr[idx] = addr[idx] + 1;
    printf("start subscribe %s\n", addr);
    atlas_set_loglevel(0);
    res = cniot_atlas_thing_entity_register("online", addr,
                                            "9ca39e81152a4452",
                                            "LEMO",
                                            device_name,
                                            iot_id,
                                            secret);

    if (res != CNIOT_STATUS_CODE_OK) {
        printf("register %s failed\n", macAddr);
    }
    //printf("get res=%d iot_id=%s secret=%s\n", res, iot_id, secret);
    cniot_atlas_initialize("online", device_name, secret,"LEMO",iot_id);

    cniot_atlas_startup();

    atlas_usleep(5000);
    cniot_atlas_shutdown();
    cniot_atlas_finalize();
}

void processTopic() {
    int i =0;
    const char macAddress[] = {"b0:f8:93:eb:a4:83\n"};
    while((i + 1) * 18 <= strlen(macAddress)) {
        topicSubscribe(&macAddress[i * 18]);
        i++;
    }
}

void edgeTest() {
    char addr[64] = {0};
    atlas_bus_protocol_t busProtocol;
    cniot_atlas_edge_cache_initialize();
    cniot_atlas_edge_cache_startup();

    atlas_snprintf(busProtocol.protocol,C_MAX_PROTOCOL_LEN, "mqtt");
    atlas_snprintf(busProtocol.version,C_MAX_PROTOCOL_LEN, "2.0");

    atlas_snprintf(busProtocol.addr,C_MAX_URL_LEN, "tcp://78.3.2.6:1984");
    atlas_edge_cache_push(&busProtocol);
    atlas_snprintf(busProtocol.addr,C_MAX_URL_LEN, "tcp://192.168.2.1:1984");
    atlas_edge_cache_push(&busProtocol);
    atlas_edge_cache_clear();
    atlas_snprintf(busProtocol.addr,C_MAX_URL_LEN, "tcp://192.168.2.2:1984");
    atlas_edge_cache_push(&busProtocol);
    atlas_snprintf(busProtocol.addr,C_MAX_URL_LEN, "tcp://78.78.1.1:1984");
    atlas_edge_cache_push(&busProtocol);
    atlas_snprintf(busProtocol.addr,C_MAX_URL_LEN, "tcp://78.78.1.2:1984");
    atlas_edge_cache_push(&busProtocol);
    atlas_snprintf(busProtocol.protocol,C_MAX_PROTOCOL_LEN, "coap");
    atlas_snprintf(busProtocol.addr,C_MAX_URL_LEN, "192.168.2.3");
    atlas_edge_cache_push(&busProtocol);
    atlas_snprintf(busProtocol.protocol,C_MAX_PROTOCOL_LEN, "mqtt");
    atlas_snprintf(busProtocol.addr,C_MAX_URL_LEN, "tcp://78.3.2.3:1984");
    atlas_edge_cache_push(&busProtocol);
    while (CNIOT_STATUS_CODE_OK == atlas_edge_cache_pop(&busProtocol)) {
        printf("pop protocol=%s version=%s addr=%s\n", busProtocol.protocol, busProtocol.version, busProtocol.addr);
    }

    cniot_atlas_edge_cache_shutdown();
    cniot_atlas_edge_cache_finalize();

}
CNIOT_STATUS_CODE connectTest(void *ptr, const char *parm, int parm_length, char **rsp) {
    *rsp = atlas_malloc(64);
    atlas_snprintf(*rsp, 64, "{\"result\":\"just for sdk test %llu\"}", atlas_abs_time());
    printf("receive %s\n", parm);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE propertiesChange(void *ptr, const char *parm, int parm_length, char **rsp) {
    printf("properties change receive %s\n", parm);
    return CNIOT_STATUS_CODE_OK;
}

static CNIOT_STATUS_CODE _parse_start_rsp(char *rsp,
                                          char *flowId, char*stepNum) {
    lite_cjson_t root, node, data;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    int n = lite_cjson_parse(rsp, (int)strlen(rsp), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    n = lite_cjson_object_item(&root, "data", strlen("data"), &data);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    n = lite_cjson_object_item(&data, "data", strlen("data"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&node, "$flowId", flowId, C_MAX_SESSION_LEN), L_ERROR);

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&node, "$stepNum", stepNum, C_MAX_SESSION_LEN), L_ERROR);
    L_ERROR:
    return ret;
}

CNIOT_STATUS_CODE serviceTestForWendell() {
    char rsp[4096];
    int buff_len = 1024;
    int   ret= atlas_thing_service_invoking("com.cainiao.conplatform.servicecenter.client.service.IotDeviceService:1.0.0@count",
                                            "[\"java.lang.String\"]", "[\"LEMO\"]", rsp, buff_len);

    printf("ret=0x%03x rsp=%s\n", ret, rsp);
    return CNIOT_STATUS_CODE_OK;
}

CNIOT_STATUS_CODE downloadTestForWendell() {
    char rsp[4096];
    char parm[1024] = {0};
    int buff_len = 1024;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;
    atlas_snprintf(parm, 1024, "[\"09899c1f1b16447c928324d1b04fbae2\",\"connectTest\",\"{\\\"weight\\\":123}\"]");
    ret = atlas_thing_service_invoking("com.cainiao.iots.api.service.IotsAppService:1.0.0@syncInvokeService",
                                       "[\"java.lang.String\", \"java.lang.String\", \"java.util.Map\"]", parm, rsp, buff_len);
    printf("ret=0x%x rsp=%s\n",ret, rsp);
    return ret;
}

void coapServerTest() {
    char *rsp = atlas_malloc(4096);
    int buff_len = 4096;
    char buf[1024] = {0};
    int ret = 0;

    atlas_snprintf(buf, 1024, "[{\"workerNo\":\"2000190053\" ,\"sessionId\":\"%s\"}]", g_sessionId);
    ret = atlas_thing_service_invoking("/com.cainiao.cnidol.digit.agent.extension.service.MicroAppService/getAppList",
                                       "[\"java.util.Map\"]",
                                       buf, rsp, buff_len);

    printf("server test getAPPlist--->ret=%d rsp:%s\n", ret, rsp);

    atlas_snprintf(buf, 1024, "[{\"workerNo\":\"2000190053\",\"iotid\":\"%s\",\"taskType\":\"%s\",\"sessionId\":\"%s\"}]",
                   "0124ccd2e0bc45a5bedc25c00fad890c", "entruck", "222222"); //@todo taskType == 去掉GS-SCRIPT：这个前缀

    ret = atlas_thing_service_invoking("/com.cainiao.digit.edge.driver.lemo.ecn.LemoEcnInterrupt/start",
                                       "[\"java.util.Map\"]",
                                       buf, rsp, buff_len);

    printf("server test start--->ret=%d rsp:%s\n", ret, rsp);
    atlas_free(rsp);
}

void knifeTest(int idx) {
    char *rsp = atlas_malloc(30 * 1024);
    int buff_len = 30 * 1024;
    int ret = 0;
    int  n =0;
    char fileName[256] = {0};
    char buf[1024] = {0};
    char *image = NULL;
    char encode_data[64] = {"hello atlas"};

    image = atlas_malloc(256 * 1024);
    atlas_snprintf(fileName, 256, "./pic1/%d_hw.jpg", 34);
    FILE *fd = fopen (fileName, "rb");
    if (fd == NULL) {
        printf("ERROR: not found img_13.png\n");
        return;
    }
    int image_size, errno=0;

    while (!feof (fd)){
        image_size = fread (image, sizeof (char), 256 * 1024, fd);
        n = feof (fd);
        //printf ("%d,%d\n", count, n);
        //printf ("%s\n",strerror (errno));
    }

    fclose(fd);

    atlas_binary_data_encode(image,  image_size, encode_data);
    atlas_snprintf(buf, 1024, "{\"stepNum\":\"2\""
                              ",\"inputValue\":\"%s\""
                              ",\"flowId\":\"1172526071815\"}", encode_data);
    uint64_t start = atlas_boot_uptime();
    ret = atlas_thing_service_invoking("/com.cainiao.digit.edge.driver.lemo.ecn.LemoEcnInterrupt/testImage",
                                       "805773d504bf480caf6fb5fdb5e366f3",
                                       buf,
                                       rsp,
                                       buff_len);
    if (NULL != strstr(rsp, "13328051293")) {
        printf("server testImage file %s  success --->ret=0x%x cost:%llums, rsp:%s\n", fileName, ret, atlas_boot_uptime() - start, rsp);
    } else {
        printf("server testImage file %s  failed  --->ret=0x%x cost:%llums, rsp:%s\n", fileName, ret, atlas_boot_uptime() - start, rsp);
    }
    atlas_free(image);
    atlas_binary_data_free(buf);
}

void serviceTest() {
    char *rsp = atlas_malloc(30 * 1024);
    int buff_len = 30 * 1024;
    int ret = 0;
    int i =0;
    char flowId[128] = {};
    char stepNum[128] = {};
    char buf[1024] = {0};

    uint64_t cost = 0;
    for (int j = 0; j < 10; ++j) {
        uint64_t start = atlas_boot_uptime();
        atlas_snprintf(buf, 1024, "{\"taskType\":\"welcome\",\"iotid\":\"5d7483a125fd41f78d2956ffd526a8fd\",\"sn\":\"H02001L10100105\",\"version\":\"MAC_TEST_VERSION_1.0\"}");
        ret = atlas_thing_service_invoking("/com.cainiao.digit.edge.driver.lemo.ecn.LemoEcnInterrupt/start",
                                           "bdecff5ce70e42df",buf, rsp, buff_len);

        cost += atlas_boot_uptime() - start;
        printf("server test start--->ret=0x%x time:%llu\n", ret, atlas_boot_uptime() - start);
        atlas_usleep(1000);

        for (int k = 0; k < 0; ++k) {
            atlas_snprintf(buf, 1024, "{\"stepNum\":\"2\",\"iotid\":\"aaf31efedfc34700aeb54adf9e3b9206\",\"inputValue\":\"123\","
                                      "\"sessionId\":\"32173921392183\",\"optionName\":\"\",\"flowId\":\"123124123\"}");
            start = atlas_boot_uptime();
            ret = atlas_thing_service_invoking("/com.cainiao.digit.edge.driver.lemo.ecn.LemoEcnInterrupt/next",
                                               "8f8432fed5bd40e9",buf, rsp, buff_len);

            printf("server test next--->ret=0x%x time:%llu\n", ret, atlas_boot_uptime() - start);
            atlas_usleep(3000);
        }
    }


    return;
    atlas_snprintf(buf, 1024, "{\n"
                              "        \"workerNo\":     \"TEST100\",\n"
                              "        \"iotid\":        \"74774193ff1345feb5e56ffaa22310db\",\n"
                              "        \"logisticNodeId\":       \"RET001\",\n"
                              "        \"sn\":   \"D01901SPL101000286\",\n"
                              "        \"taskType\":     \"offline_mode_test\",\n"
                              "        \"version\":      \"1.1.\",\n"
                              "        \"sessionId\":    \"\",\n"
                              "        \"appkey\":       \"star-atlas\"\n"
                              "}"); //@todo taskType == 去掉GS-SCRIPT：这个前缀

    ret = atlas_thing_service_invoking("/com.cainiao.iot.digital.os.driver.lemo.ecn.LemoEcnInterrupt/start",
                                       "805773d504bf480caf6fb5fdb5e366f3",buf, rsp, buff_len);
    printf("server test start--->ret=0x%x rsp:%s\n", ret, rsp);
    ret = _parse_start_rsp(rsp, flowId, stepNum);

    printf("server test start ret =%d--->flowId=%s stepNum:%s\n", ret, flowId, stepNum);
    atlas_usleep(300);

    for (i = 0; i < 10; ++i) {
        atlas_snprintf(buf, 1024, "[{\"sessionId\":\"%s\""
                                  ",\"flowId\":\"%s\""
                                  ",\"stepNum\":\"%s\""
                                  ",\"inputValue\":\"123456789\""
                                  ",\"optionName\":\"\"}]",
                       g_sessionId, flowId, stepNum);
        ret = atlas_thing_service_invoking("/com.cainiao.digit.edge.driver.lemo.ecn.LemoEcnInterrupt/next",
                                           "805773d504bf480caf6fb5fdb5e366f3",buf, rsp, 4096);
        printf("server test next--->ret=%d rsp:%s\n", ret, rsp);
        ret = _parse_start_rsp(rsp, flowId, stepNum);
        printf("server test next--->ret=%d flowID=%s stepNum=%s\n", ret, flowId, stepNum);
        atlas_usleep(300);
    }
    atlas_free(rsp);
}

void blockCoAPTest() {
    cniot_send_coap_loadTest();
}

static CNIOT_STATUS_CODE _parse_login_rsp(char *rsp, char *session, char* token) {
    lite_cjson_t root, node;
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    int n = lite_cjson_parse(rsp, (int)strlen(rsp), &root);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FORMAT;
    }
    n = lite_cjson_object_item(&root, "success", strlen("success"), &node);
    if (n < 0) {
        return CNIOT_STATUS_JSON_NOT_FOUND_KEY;
    }

    if (node.type == cJSON_False) {
        return CNIOT_STATUS_RSP_NOT_SUCCESS;
    }

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "sessionId", session, C_MAX_SESSION_LEN), L_ERROR);

    CHECK_RETURN_VALUE(ret, atlas_get_json_string_value(&root, "refreshToken", token, C_MAX_SESSION_LEN), L_ERROR);

    L_ERROR:
    return ret;
}

CNIOT_STATUS_CODE status_callback(void *ptr, CNIOT_EVENT_T event, char *msg) {
    printf("--->>> event=%d msg=%s cost_time=%lld\n", event, msg, atlas_boot_uptime() - startup_time);
    return CNIOT_STATUS_CODE_OK;
}

void *uploadPressureTestCase(void *arg) {
    char msg[4097] = {0};
    char rsp[32 * 1024]= {0};
    int rsp_len = 32 * 1024;
    int *threadId = (int *)arg;
    int count = 0;
    uint32_t sleepTime = 10;
    char log[4096] = {0};
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    for (int i = 0; i < 3678; ++i) {
        log[i] = 'a';
    }
    while(g_running) {
//        atlas_snprintf(msg, 128, "{\"deviceName\":\"coapTest%d\",\"ipAddr\":\"11.168.3.2\"}", threadId);
//        ret= atlas_thing_event_post("connect", msg);
//        add_request_ret(ret);
//        atlas_snprintf(msg,128, "{\"weight\":%d,\"code\":\"tmp msg %llu\"}", count++, atlas_abs_time());
//        ret = atlas_thing_set_properties(msg);
//        add_request_ret(ret);
        //ret = serviceTestForWendell();
        atlas_snprintf(msg, 1024, "{\"workerNo\":\"2000190053\" ,\"sessionId\":\"%s\"}", g_sessionId);
        //atlas_snprintf(msg, 1024, "{\"taskType\":\"welcome\",\"iotid\":\"7163ef46f37a4a06a3e52c2177b1985d\",\"sn\":\"D01901SPL101000421\",\"version\":\"1.9.2.1\"}");
        ret = atlas_thing_service_invoking("/com.cainiao.cnidol.digit.agent.extension.service.MicroAppService/getAppList",
                                           "805773d504bf480caf6fb5fdb5e366f3",
                                           msg, rsp, rsp_len);

        //printf("server test getAPPlist--->ret=0x%x rsp:%s\n", ret, rsp);
        add_request_ret(ret);
        sleepTime = random() % 1000;
        atlas_usleep(sleepTime);

        atlas_snprintf(msg, 4195, "{\"data\":\"%s\",\"time\":2323}", log);
        ret = atlas_thing_event_post("logReport", msg);
        printf("server test send event--->ret=0x%x \n", ret);
        add_request_ret(ret);
        sleepTime = random() % 1000;
        atlas_usleep(sleepTime);
    }
    return NULL;
}

void *downloadPressureTestCase(void *arg) {
    return NULL;
}

int startPressure(int threadNum) {
    void *thread_handle;
    int used = 0;

    for (int i = 0; i < threadNum; ++i) {
        int *thread = atlas_malloc(sizeof(int));
        *thread = i;
        atlas_thread_create(&thread_handle, uploadPressureTestCase, thread, NULL, &used);
    }

    return 0;
}

void knifeProtocolTest() {
    char msg[1024] = {0};
    int i = 0;
    char parm[128] = {0}, parm2[128] = {0};
    uint8_t *body = atlas_malloc(512 * 1024);
    uint8_t *data = atlas_malloc(128 * 1024);
    int body_length = 512 * 1024;
    CNIOT_STATUS_CODE  ret = CNIOT_STATUS_CODE_OK;
    for (i = 0; i < 1024; i++) {
        data[i] = 'A' + (i % 26);
    }
    cniot_atlas_knife_protocol_initialize();
    cniot_atlas_knife_protocol_startup();
    atlas_binary_data_encode(data, 223, parm);
    atlas_binary_data_encode(data + 323, 1228, parm2);
    atlas_snprintf(msg, 1024, "{\"code\":123"
                              ",\"imag\":\"%s\""
                              ",\"stringTest\":\"2321321321\""
                              ",\"imag2\":\"%s\"}", parm, parm2);

    ret = atlas_knife_protocol_encode(msg, body, &body_length);
    if (ret != CNIOT_STATUS_CODE_OK) {
        printf("encode failed ret =%d\n", ret);
        return;
    }
    atlas_knife_protocol_decode(body, body_length);
    cniot_atlas_knife_protocol_shutdown();
    cniot_atlas_knife_protocol_finalize();
}
void uploadImagTest() {
    httpclient_t httpclient;
    httpclient_data_t data;
    httpclient_t *httpc = (httpclient_t *)&httpclient;
    int size = 0, n = 0;
    char resp_buff[1024] = {0};
    char *body = NULL;

    body = atlas_malloc(32 * 1024);
    FILE *fd = fopen ("./img_13.png", "rb");
    if (fd == NULL) {
        printf("ERROR: not found img_13.png\n");
        return;
    }
    int count, errno=0;

    while (!feof (fd)){
        count = fread (body, sizeof (char), 32 * 1024, fd);
        n = feof (fd);
        printf ("%d,%d\n", count, n);
        printf ("%s\n",strerror (errno));
    }

    fclose(fd);
    memset(&httpclient, 0, sizeof(httpclient_t));
    memset(&data, 0, sizeof(httpclient_data_t));

    data.post_content_type = "application/x-png";
    data.post_buf = body;
    data.post_buf_len = count;
    data.response_buf = resp_buff;
    data.response_buf_len = 1024;

    httpc->header = "Connection: Keep-Alive\r\n";

    printf("start http client common body_len=%d\n", (int)(strlen(body)));
    size = httpclient_common(&httpclient, "https://192.168.1.106/index", 12122,
                             NULL, HTTPCLIENT_POST, 10000, &data);
    printf("upload ret=%d\n", size);
}

void iotHubDemo() {
    char iot_id[C_MAX_ID_LEN] = {0};
    char secret[C_MAX_ID_LEN] = {0};
    char device_name[C_MAX_ID_LEN] = {0};
    char msg[C_MAX_BODY_LEN] = {0};
    char macAddress[C_MAX_ID_LEN] = {0};
    CNIOT_STATUS_CODE res = CNIOT_STATUS_CODE_OK;

    //@todo获取mac地址 放入macAddress
    atlas_register_status_callback(status_callback, NULL); //事件状态回调
    atlas_set_server_addr(C_CNIOT_PROTOCOL_MQTT, 1, "ssl-shiot.cainiao.com"); //指定连接mqtt

    res = cniot_atlas_thing_entity_register("online", macAddress,
                                            "97a480d4dc994bc4",
                                            "LEMOHUB",
                                            device_name,
                                            iot_id,
                                            secret);  //参数对齐星图控制台

    if (res != CNIOT_STATUS_CODE_OK) { //@todo 注册失败则需要重试...
        return;
    }
    printf("get res=%d iot_id=%s secret=%s\n", res, iot_id, secret);
    //初始化资源
    res = cniot_atlas_initialize("online", macAddress,
                                 "secret",
                                 "LEMOHUB",
                                 iot_id);

    if (res != CNIOT_STATUS_CODE_OK) { //@todo 注册失败则需要重试...
        return;
    }

    //启动sdk
    cniot_atlas_startup();

    atlas_thing_service_register("pushMessage", connectTest, msg); //注册服务

    res = atlas_thing_event_post("logReport", msg); //事件汇报

    atlas_snprintf(msg, C_MAX_BODY_LEN, "{\"stepsPer5Min\":%llu}", atlas_abs_time() % 10000);

    res = atlas_thing_set_properties(msg); //属性上报

}

void knife_protocol_test() {
    void *data = atlas_malloc(10 * 1024);
    int len = 10 * 1024;
    int flag = 234;
    char parm[128] = {0};

    int parm_len ;
    void *parm_data = NULL;
    int key = 336 ;
    atlas_knife_parm_encode(data, len,  parm, &flag);
    printf("encode parm = %s\n", parm);

    atlas_knife_parm_decode(parm, &key, &parm_data, &parm_len);
    printf("decode parm = %s data=%llu len=%d\n", parm, parm_data, parm_len);

    if (parm_data != data || parm_len != len || key != 234) {
        printf("kenife encode or decode error\n");
    }
    atlas_free(data);
    data = NULL;
}

static void testTcp() {
    char data[8192] = {0};
    char msg[8192] = {0};
    atlas_set_loglevel(5);

    int read = 1024;
    uint64_t begin = atlas_boot_uptime();
    int request_len = atlas_snprintf(data, 8192, "GET /bus/api/v1/getEdgeBusInfo HTTP/1.1\r\n"
                                                 "Host: 127.0.0.1:1984\r\n"
                                                 "User-Agent: curl/7.54.0\r\n"
                                                 "Accept: */* \r\n\r\n");
    CNIOT_STATUS_CODE  ret = atlas_tcp_request("127.0.0.1", 1984, data, request_len, msg, &read,  2000, 1000);
    printf("[tcpTest] ret=%d readLen=%d cost=%llu\n", ret, read, atlas_boot_uptime() - begin);
}

int main(int arg, char *argv[]) {
    int thread_num = 2;
    char data[8192] = {0};
    char msg[8192] = {0};

    //edgeTest();
    CNIOT_STATUS_CODE ret = CNIOT_STATUS_CODE_OK;

    //testTcp();

    atlas_register_status_callback(status_callback, NULL);
    g_atlas_mutex = atlas_mutex_create();
    atlas_set_wifi_callback(setWifiTestMessage);
    CNIOT_ATLAS_DOMAIN_CODE code;
    char device_name[128] = {0};
    char iot_id[128] = {0};
    char secret[128] = {0};
    registerTest();
    //atlas_set_server_addr(C_CNIOT_PROTOCOL_COAP, 1, "47.96.37.234");
    atlas_set_server_addr(C_CNIOT_PROTOCOL_MQTT, 2, "tcp://47.96.37.234:1984");
    //atlas_set_server_addr(C_CNIOT_PROTOCOL_MQTT, 1,"ssl://ssl-shiot.cainiao.test");

    //atlas_set_loglevel(5);
    //atlas_query_domain_by_deviceName("9ca39e81152a4452", "LEMO", "fc:bc:0e:09:4d:b7", &code);

//    CNIOT_ATLAS_DOMAIN_CODE domainCode;
//    ret = atlas_get_server_domain_byCode("810001", &domainCode);
//
//    ret = cniot_atlas_register_with_barcode("pre", "lemo_barcode_005", "9ca39e81152a4452", "LEMO",
//                                      device_name, iot_id, secret, "110000");

    //   printf("barCode register ret=%d\n", ret);


    cniot_atlas_initialize("online", "test_bus",
                           "7D22F750F5F346AC2F8A35D39D046FBA766D9CBF4BA92A1592C2896CA858B2F8",
                           "LEMO",
                           "b15f729acfa34206a8c9d5a555c68619");
    cniot_atlas_startup();
    atlas_set_loglevel(3);
    startup_time = atlas_boot_uptime();
    atlas_usleep(15000);

    atlas_properties_change_register(propertiesChange, NULL);

//    atlas_set_network_status(NETWORK_STATUS_OFFLINE);
////    atlas_usleep(5000);
//    atlas_set_network_status(NETWORK_STATUS_ONLINE);
//    atlas_usleep(10000);
    char buff[4096] = {0};
    char topic[1024] = {0};
    atlas_set_loglevel(3);
    cniot_atlas_thing_entity_t *entity = NULL;

//    atlas_snprintf(topic, 1024, "/g0fmZVTwfzb/zd888/method/TemplatePrint/async/request");
//
//    atlas_core_get_entity(&entity);
//
    //atlas_snprintf(buff, 4096, "{\"id\":\"213213213\",\"traceId\":\"32103921392123219389012\",\"requestId\":\"32103921392123219389012\",\"responseTopic\":\"/linxun_test_entry/test_0002/rpc/sync/response\",\"timeout\":5000,\"version\":\"1.0\",\"params\":{\"productKey\":\"loginx-edge-platform\",\"deviceName\":\"720635015\"}}");
    //cniot_atlas_mqtt_write(entity, topic,  buff);

//    char *bigBody = atlas_malloc(32 * 1024);
//    int n = atlas_snprintf(bigBody,32 * 1024, "{\"data\":\"");
//    for (int i = 0; i < 28 * 1024; ++i) {
//        n += atlas_snprintf(bigBody + n ,32 * 1024 - n, "A");
//    }
//    n += atlas_snprintf(bigBody + n ,20 * 1024 - n, "\",\"time\":123456}");
//    atlas_thing_event_post_with_https("logReport", bigBody);

    //atlas_thing_set_properties("{\"runtimeInfo\":{\"diskSize\":8388608,\"diskUsed\":2461696,\"memorySize\":4193280,\"memoryUsed\":1808040,\"CPUUsage\":0},\"batteryInfo\":{\"powerValue\":36,\"temperature\":19},\"network\":{\"successRequest\":0,\"averageRT\":86,\"totalRequest\":9}}");
    //atlas_thing_get_properties("c263c2c524b84167bc590bb76b18ca62",buff, 1024);

    //serviceTest();

    atlas_thing_service_register("rebootSystem", connectTest, NULL);

    for (int i = 0; i < 100; i ++) {
        char buf[1024] = {0};
        char rsp[4096] = {9};
        char requestId[64] = {0};
        char traceId[64] = {0};
        char sessionId[64] = {"ZTQ3NGJhODQtZGVmNC00YWMxLThmYWUtYjI2MjQ2M2YwYTAx"};
        atlas_snprintf(buf, 1024, "{\"taskType\":\"welcome\",\"iotid\":\"edf19bbcc76548aaa65e7e692e7a79ee\",\"sn\":\"D01904SPL101001705\",\"version\":\"2.0.2\"}");

        ret = atlas_thing_service_invoking_v2("/com.cainiao.digit.edge.driver.lemo.ecn.LemoEcnInterrupt/start",
                                              buf, "805773d504bf480caf6fb5fdb5e366f3", requestId, traceId, sessionId, rsp, 4096);
//
        printf("rpc  idx = %d ret=%d sessionId=%s rsp=%s\n", i, ret, sessionId, rsp);
        atlas_usleep( 3000);
    }

    atlas_usleep(  500000000);

    startPressure(thread_num);

    while(g_running) {
        //atlas_snprintf(msg,8192, "{\"stepsPer5Min\":%llu}", atlas_abs_time() % 10000);
        //ret = atlas_thing_set_properties(msg);
        int idx = (atlas_boot_uptime() / 1000) % 10;
        if ( idx < 3) {
            //atlas_set_network_status(NETWORK_STATUS_OFFLINE);
            atlas_usleep(1000 + random() % 1000);
            //atlas_set_network_status(NETWORK_STATUS_ONLINE);
        }
        printf("request thread_num=%d success=%d failed=%d  ret=0x%x\n", thread_num, g_request_success, g_request_failed,  ret);
        atlas_usleep(  1000);
    }
    return 0;
}
