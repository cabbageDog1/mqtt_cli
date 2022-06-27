#ifndef ATLAS_CNIOT_ATLAS_H
#define ATLAS_CNIOT_ATLAS_H

#if defined(__cplusplus)
extern "C" {
#endif
#include "cniot_atlas_code.h"

typedef CNIOT_STATUS_CODE (*atlas_service_callback_fun_t)(void *ptr, const char *parm, int parm_length, char **rsp_data);

typedef CNIOT_STATUS_CODE (*atlas_status_callback_fun_t)(void *ptr, CNIOT_EVENT_T event, char *msg);

typedef enum {
    NETWORK_STATUS_OFFLINE,
    NETWORK_STATUS_ONLINE
}C_CNIOT_NETWORK_STATUS;

typedef enum {
    CNIOT_ATLAS_DOMAIN_ALI  = 1,
    CNIOT_ATLAS_DOMAIN_WUTONG = 2,
    CNIOT_ATLAS_DOMAIN_UNKNOW = 3,
    CNIOT_ATLAS_DOMAIN_MAX
}CNIOT_ATLAS_DOMAIN_CODE;

/*
*  函数功能:设备注册接口
*  说明: 没有注册过的设备, 必选首先注册保存返回的iot_id 和物实体秘钥
*        此接口需要在星图的通道配置中选择打开或者未激活返回秘钥才能注册.
*        未激活返回秘钥和打开的区别是 未激活返回秘钥 只能注册一次，下次注册不返回.
*        打开可以多次注册拿到iot_id和物实体秘钥(推荐)
*  参数: device 设备信息
*        env:   "daily"  日常环境
*               "pre"    预发环境
*               "online" 线上环境
*        entity_name   物实体名称
*        thing_secret  物类型秘钥
*        thing_key     物类型key
*  返回:
*     iot_id:         成功后会更新iot_id
*     entity_secret:  成功后会更新entity_secret
*     atlas_entity_name: 成功后会更新的服务端存储的设备名称.
*/
CNIOT_STATUS_CODE cniot_atlas_thing_entity_register(const char *env, const char *entity_name,
                                                    const char *thing_secret, const char *thing_key,
                                                    char atlas_entity_name[C_MAX_ID_LEN],
                                                    char iot_id[C_MAX_ID_LEN],
                                                    char entity_secret[C_MAX_ENTITY_SECRET_LEN]);


/*
*  函数功能:设备注册接口
*  说明: 没有注册过的设备, 必选首先注册保存返回的iot_id 和物实体秘钥
*        此接口需要在星图的通道配置中选择打开或者未激活返回秘钥才能注册.
*        未激活返回秘钥和打开的区别是 未激活返回秘钥 只能注册一次，下次注册不返回.
*        打开可以多次注册拿到iot_id和物实体秘钥(推荐)
*  参数:
*        env:   "daily"    日常环境
*               "pre"      预发环境
*               "online"   线上环境
*        entity_name       物实体名称
*        thing_secret      物类型秘钥
*        thing_key         物类型key
*        atlas_entity_name 星图存储的物实体名称
*        barcode           激活码
*  返回:
*     iot_id:         成功后会更新iot_id
*     entity_secret:  成功后会更新entity_secret
*     atlas_entity_name: 成功后会更新的服务端存储的设备名称.
*/
CNIOT_STATUS_CODE cniot_atlas_register_with_barcode(const char *env, const char *entity_name,
                                                    const char *thing_secret, const char *thing_key,
                                                    char atlas_entity_name[C_MAX_ID_LEN],
                                                    char iot_id[C_MAX_ID_LEN],
                                                    char entity_secret[C_MAX_ENTITY_SECRET_LEN],
                                                    const char *barcode);
/*
*  函数功能:获取设备绑定的物流节点信息
*  参数: device 设备信息
*        env:   "daily"  日常环境
*               "pre"    预发环境
*               "online" 线上环境
*     iot_id:         iot_id
*     entity_secret:  entity_secret
*     rsp_buff        消息buff
*     rsp_buff_len    消息大小 最小4K
*  返回:
*       返回消息内容 rsp
*       获取成功的格式:
*           "{\"iotCode\":\"ZMDBG0001\",\"iotId\":\"ab149182cbe54ef98bcfe7c4360d18d5\",\"productKey\":\"warehouse\",\"success\":true}"
*       获取失败的格式:
*           "{\"errorCode\":\"CHANNEL_NOT_EXIST\",\"errorMsg\":\"CHANNEL_NOT_EXIST\",\"success\":false}"
*/
CNIOT_STATUS_CODE cniot_atlas_site_query(const char *env,const char *iot_id, const char *entity_secret, char *rsp_buff, int rsp_buff_len);


/*
 *  函数功能: 初始化星图资源
 *  备注:线程不安全, 必须保证一个线程初始化
 *  参数:
 *       env:    "daily"  日常环境
 *               "pre"    预发环境
 *               "online" 线上环境
 *       entity_name  （物实体名称）
 *       entity_secret (物实体秘钥)
 *       thing_key    （物类型名称）
 *       iot_id        iotID
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE cniot_atlas_initialize(char *env, char *entity_name, char *entity_secret, char *thing_key, char *iot_id);

/*
 *  函数功能: 启动星图服务
 *  说明:  首先需要调用cniot_atlas_initialize接口
 *  参数:
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE cniot_atlas_startup();


/*
 *  函数功能: 停止星图服务
 *  说明:  无
 *  参数:
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE cniot_atlas_shutdown();

/*
 *  函数功能: 释放星图资源
 *  备注: 线程不安全,
 *       如果模块已经启动,必须先停止（调用cniot_atlas_shutdown）
 *  参数:
 *
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE cniot_atlas_finalize();

/*
 *  函数功能: 从云端获取物实体属性
 *  参数:
 *      iot_id:  设备iot_id(能获取自己的属性或子设备属性)
 *      buf      缓存
 *      buf_len  缓存长度
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_thing_get_properties(const char *iot_id, char *buf, int buf_len);

/*
 *  函数功能: 设置物实体属性同步到云
 *  参数:
 *      property: json 格式的属性字符
 *  返回:
 *      CNIOT_STATUS_CODE
 *  失败错误码
 *      CNIOT_STATUS_NOT_INITIALIZE  没有初始化
 *      CNIOT_STATUS_CONNECTING      正在连接服务器
 *      CNIOT_STATUS_MQTT_DISCONNECT  mqtt连接断开
 *      CNIOT_STATUS_MQTT_PUBLISH_FAILED mqtt 发送消息失败
 *      CNIOT_STATUS_BUFFER_OVERFLOW  缓冲区过小
 *      CNIOT_STATUS_MSG_TIMEOUT      服务调用超时
 *      CNIOT_STATUS_RSP_NOT_SUCCESS 调用服务出错,请检测云服务
 *      CNIOT_STATUS_JSON_NOT_FORMAT   返回数据不是个json（可能是数据量超过了缓存）
 *      CNIOT_STATUS_JSON_NOT_FOUND_KEY  json中没有状态key
 *
 */
CNIOT_STATUS_CODE atlas_thing_set_properties(const char *property);
/*
 *  函数功能: 星图物实体事件上报
 *  参数:
 *      event 事件名称
 *      data  事件参数json 如果没有参数，输入{}
 *  返回:
 *      CNIOT_STATUS_CODE
 *  错误码:
 *     同上设置接口
 */
CNIOT_STATUS_CODE atlas_thing_event_post(const char *event, const char *data);

/*
 *  函数功能: 二进制数据编码
 *  参数:
 *      data     二进制数据
 *      data_len 数据长度
 *      parm     编码后的标识 （大小必须大于64字节）
 *  返回:
 *      CNIOT_STATUS_CODE
 *  备注:
 *      对于同一块二进制数据,如果是放到多个JSON中,需要分开encode
 *      支持同时并发256个二进制参数
 */
CNIOT_STATUS_CODE  atlas_binary_data_encode(const void *data, int data_len, char *parm);

/*
 *  函数功能: 释放二进制数据协议资源
 *  参数:
 *      data  包含多个二进制数据的JSON数据
 *  返回:
 *      CNIOT_STATUS_CODE
 *  备注:
 */
CNIOT_STATUS_CODE  atlas_binary_data_free(char *data);

/*
 *  函数功能: 星图远程服务调用
 *  说明：
 *      如果是连接边,边缘服务有这个服务优先调用边缘，其次云端调用...
 *      支持二进制数据编码传输
 *  参数:
 *      service 服务名称
 *      bizKey  业务key
 *      parm 参数
 *
 *      rsp_buff 返回数据buff
 *      rsp_buff_len 返回数据长度
 *  返回:
 *      CNIOT_STATUS_CODE
 *      CNIOT_STATUS_CODE_OK        调用成功
 *  失败错误码:
 *      CNIOT_STATUS_NOT_INITIALIZE 没有初始化就调用
 *      CNIOT_STATUS_MSG_NOT_FOUND  service填写错误
 *      CNIOT_STATUS_NO_MEMORY      内存申请失败,没有内存了
 *      CNIOT_STATUS_CONNECTING     正在连接服务器...
 *      CNIOT_STATUS_MQTT_DISCONNECT 与服务器断开连接.
 *      CNIOT_STATUS_BUFFER_OVERFLOW  缓冲区过小
 *      CNIOT_STATUS_MSG_TIMEOUT      服务调用超时
 *      CNIOT_STATUS_RSP_NOT_SUCCESS 调用服务出错,请检测云服务
 *      CNIOT_STATUS_JSON_NOT_FORMAT   返回数据不是个json（可能是数据量超过了缓存）
 *      CNIOT_STATUS_JSON_NOT_FOUND_KEY  json中没有状态key
 */
CNIOT_STATUS_CODE atlas_thing_service_invoking(const char *service,  const char *bizKey,  const char *parm,
                                               char *rsp_buff, int rsp_buff_len);



/*
 *  函数功能: 星图远程服务调用
 *  说明：
 *      支持二进制数据编码传输
 *  参数:
 *      serviceName 服务名
 *      params      参数 json object
 *      bizKey      业务key
 *      requestId   业务请求Id  不能为NULL 长度不能小于C_MAX_ID_LEN  如果为空会随机生成
 *      traceId     链路跟踪Id  不能为NULL 长度不能小于C_MAX_ID_LEN  如果为空会随机生成
 *      sessionId   会话Id     不能为NULL 长度不能小于C_MAX_ID_LEN  rpc应用会话ID，服务端生成
 *
 *      rspBuff    返回数据buff
 *      rspBuffLen 返回数据长度
 *
 *  返回:
 *      CNIOT_STATUS_CODE
 *      CNIOT_STATUS_CODE_OK        调用成功
 *  失败错误码:
 *      CNIOT_STATUS_NOT_INITIALIZE 没有初始化就调用
 *      CNIOT_STATUS_MSG_NOT_FOUND  service填写错误
 *      CNIOT_STATUS_NO_MEMORY      内存申请失败,没有内存了
 *      CNIOT_STATUS_CONNECTING     正在连接服务器...
 *      CNIOT_STATUS_MQTT_DISCONNECT 与服务器断开连接.
 *      CNIOT_STATUS_BUFFER_OVERFLOW  缓冲区过小
 *      CNIOT_STATUS_MSG_TIMEOUT      服务调用超时
 *      CNIOT_STATUS_RSP_NOT_SUCCESS 调用服务出错,请检测云服务
 *      CNIOT_STATUS_JSON_NOT_FORMAT   返回数据不是个json（可能是数据量超过了缓存）
 *      CNIOT_STATUS_JSON_NOT_FOUND_KEY  json中没有状态key
 */
CNIOT_STATUS_CODE atlas_thing_service_invoking_v2(const char *serviceName,
                                                  const char *params,
                                                  const char *bizKey,
                                                  char *requestId,
                                                  char *traceId,
                                                  char *sessionId,
                                                  char *rspBuff,
                                                  int rspBuffLen);
/*
 *  函数功能: 服务注册
 *  参数:
 *      server_name 服务名称, 最大长度128字符
 *      fun 回调函数
 *      ptr 参数 可为空
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_thing_service_register(char *server_name, atlas_service_callback_fun_t fun, void *ptr);



/*
 *  函数功能: 云端属性下发监听
 *  参数:
 *      fun 回调函数
 *      ptr 参数 可为空
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_properties_change_register(atlas_service_callback_fun_t fun, void *ptr);
/*
 *  函数功能: 取消注册的服务
 *  参数:
 *      server_name 服务名称
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_thing_service_unregister(char *server_name);

/*
 * 函数功能: 设置网络状态,及时的设置网络状态链路能够快速恢复
 * 参数:
 *     status 网络状态
 *  返回:
 *     CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_set_network_status(C_CNIOT_NETWORK_STATUS  status);


/*
 * 函数功能: 监听状态变化信息
 * 参数:
 *    fun callback函数
 *    user_data   用户数据
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_register_status_callback(atlas_status_callback_fun_t fun, void *user_data);

/*
 * 函数功能: 获取core状态信息
 * 参数:
 *     protocol 协议
 *     addr   连接地址;
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_get_core_status(CNIOT_PROTOCOL *protocol, int *status, char addr[C_MAX_HOST_LEN]);


/*
 * 函数功能: 设置连接协议与服务器地址()
 * 备注：必须初始化前调用设置，设置完成默认使用默认addr;
 * 参数:
 *     protocol   设定连接协议
 *     version    协议版本号
 *     addr       物理边地址;
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_set_server_addr(CNIOT_PROTOCOL protocol, int version, char *addr);


/*
 * 函数功能: 使用barcode获取域地址
 * 参数:
 *     bar_code   域code
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_get_server_domain_byCode(const char *bar_code, CNIOT_ATLAS_DOMAIN_CODE *code);


/*
 * 函数功能: 用设备获取连接域
 * 备注：必须初始化前调用设置, 不设置默认使用弹内.
 * 参数:
 *     thing_key   物类型名称
 *     thing_secret 物类型秘钥
 *     entity_name  物实体名称
 *     code  域地址
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_query_domain_by_deviceName(const char *thing_secret, const char *thing_key,
                                                 char entity_name[C_MAX_ID_LEN], CNIOT_ATLAS_DOMAIN_CODE *code);
/*
 * 函数功能: 获取设备注册域
 * 参数:
 *     code   域code
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_set_server_domain(CNIOT_ATLAS_DOMAIN_CODE code);


/*
 * 函数功能: 通过环境和二维码获取星图域名
 * 备注：
 * 参数:
 *        env:   "daily"  日常环境
 *               "pre"    预发环境
 *               "online" 线上环境
 *       barcode: 激活码
 *       address: 地址最小空间需要64字节
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_get_https_address_from_env_and_barcode(const char *env, const char *barcode, char *address);

/*
 * 函数功能: 设置获取wifi信息函数
 * 备注：
 * 参数:
 *     fun 回调函数
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_set_wifi_callback(void (*fun)(char *));

/*
 * 函数功能: 获取sdk的诊断信息
 * 备注：必须初始化后调用
 * 参数:
 *     buff   内存空间地址
 *     len    空间大小 最小空间1KB
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_get_diagnose_message(char *buff, int len);

/*
 * 函数功能: 汇报服务运行时信息
 * 备注：必须初始化后调用
 * 参数:
 *     identifier   物模型表识
 *     meta_data    服务元信息
 *     expression   规则表达
 *  返回:
 *      CNIOT_STATUS_CODE
 */

CNIOT_STATUS_CODE atlas_thing_service_runtime_report(const char *identifier, const char *meta_data,
                                                     const char *expression);

/*
 * 函数功能: 查询服务运行时信息
 * 备注：必须初始化后调用
 * 参数:
 *     buff        字符
 *     data_len    数据长度
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_thing_service_runtime_query(char *buff, int buff_len);


/*
 * 函数功能: 查询星图网关https地址
 * 参数:
 *     domainCode  域code
 *     env    环境
 *     address 地址
 *  返回:
 *      CNIOT_STATUS_CODE
 */
CNIOT_STATUS_CODE atlas_get_http_address(CNIOT_ATLAS_DOMAIN_CODE domainCode, const char *env, char *address);

/*
 *  函数功能: 通过http事件上报
 *  参数:
 *      event 事件名称
 *      data  事件参数json 如果没有参数，输入{}
 *  返回:
 *      CNIOT_STATUS_CODE
 *  错误码:
 *     同上设置接口
 */
CNIOT_STATUS_CODE atlas_thing_event_post_with_https(const char *event, const char *data);


/*
 *  函数功能:设置当前漫游状态
 *  参数:
 *      roam_status wifi漫游状态
 *      0表示漫游结束，非0表示漫游进行中 （1 表示漫游扫描中，2表示漫游连接中）
 *  返回:
 *      VOID
 *  备注:
 *      当漫游状态的时候 日志不会上传, 如果一致处于漫游5分钟还是会上传.
 */
void  atlas_set_wifi_roam_status(int roam_status);

/*
 *  函数功能: 向tcp服务器请求数据
 *  参数:
 *      host  ip地址或者域名  不能为NULL
 *      port  端口           大于0
 *      write_buffer       请求数据 不能为NULL
 *      write_buff_len    数据大小 不能小于 0
 *      read_buff         读取数据缓存区 不能为NULL
 *      read_buff-len     数据大小指针,读取完成后返回读取数据大小
 *      write_timeout_ms  写数据的超时时间 单位毫秒 不能为0
 *      read_timeout_ms   读取数据的超时时间 单位毫秒 不能为0
 *  返回:
 *  正常
 *      CNIOT_STATUS_CODE 成功 更新 read_buff_len读取数据值
 * 可能正常
 *      CNIOT_STATUS_TCP_READ_TIMEOUT   读取数据超时(服务器不主动关闭,需要判断读回的数据)
 *      CNIOT_STATUS_TCP_READ_FAILED    读取数据异常(服务器主动关闭,需要判断读回的数据)
 *  错误码:
 *     CNIOT_STATUS_PARM_ERROR 入参错误
 *     CNIOT_STATUS_TCP_INIT_FAILED 协议初始化失败
 *     CNIOT_STATUS_TCP_CONNECT_FAILED tcp连接服务器超时
 *     CNIOT_STATUS_TCP_WRITE_FAILED   tcp写入数据错误
 *     CNIOT_STATUS_TCP_WRITE_TIMEOUT  写入数据超时.
 *
 */

CNIOT_STATUS_CODE atlas_tcp_request(const char *host, unsigned short port,
                                    const char *write_buffer, int write_buff_len,
                                    char *read_buff, int *read_buff_len,
                                    unsigned int write_timeout_ms,
                                    unsigned  int read_timeout_ms);
#if defined(__cplusplus)
}
#endif

#endif //ATLAS_CNIOT_ATLAS_H
