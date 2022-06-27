/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include "report/atlas_report.h"
#include "iotx_coap_internal.h"
#include "Cloud_CoAPExport.h"
#include "./CoAPPacket/CoAPSerialize.h"
#include "./CoAPPacket/CoAPDeserialize.h"
#include "Cloud_CoAPPlatform.h"
#include "logger/atlas_logger.h"

#define COAPAckMsg(header) \
    ((header.code == COAP_MSG_CODE_EMPTY_MESSAGE || header.code == COAP_MSG_CODE_231_CONTINUE) \
     &&(header.type == COAP_MESSAGE_TYPE_ACK))

#define Cloud_CoAPRespMsg(header)\
    ((header.code >= 0x40) && (header.code < 0xc0))

#define Cloud_CoAPPingMsg(header)\
    ((header.code == COAP_MSG_CODE_EMPTY_MESSAGE)\
     && (header.type == COAP_MESSAGE_TYPE_CON))

#define Cloud_CoAPRstMsg(header)\
    (header.type == COAP_MESSAGE_TYPE_RST)

#define Cloud_CoAPCONRespMsg(header)\
    ((header.code == COAP_MSG_CODE_205_CONTENT) \
     && (header.type == COAP_MESSAGE_TYPE_CON))

#define Cloud_CoAPReqMsg(header)\
    ((1 <= header.code) && (32 > header.code))


#define COAP_CUR_VERSION        1
#define COAP_WAIT_TIME_MS       2000
#define COAP_MAX_MESSAGE_ID     65535
#define COAP_MAX_RETRY_COUNT    8
#define COAP_ACK_TIMEOUT        1
#define COAP_ACK_RANDOM_FACTOR  2
#define COAP_MAX_TRANSMISSION_SPAN   50

unsigned short Cloud_CoAPMessageId_gen(Cloud_CoAPContext *context)
{
    unsigned short msg_id = 0;
    atlas_mutex_lock(context->list_mutex);
    context->message_id++;
    if (context->message_id >= COAP_MAX_MESSAGE_ID) {
        context->message_id = 1;
    }
    msg_id = context->message_id;
    atlas_mutex_unlock(context->list_mutex);
    return msg_id;
}

int Cloud_CoAPToken_gen(Cloud_CoAPContext *context, unsigned char *p_encoded_data)
{
    if (NULL == context) {
        return 0;
    }
    atlas_mutex_lock(context->list_mutex);
    context->token++;
    p_encoded_data[0] = (unsigned char)((context->token & 0x00FF) >> 0);
    p_encoded_data[1] = (unsigned char)((context->token & 0xFF00) >> 8);
    p_encoded_data[2] = (unsigned char)((context->token & 0xFF0000) >> 16);
    p_encoded_data[3] = (unsigned char)((context->token & 0xFF000000) >> 24);
    atlas_mutex_unlock(context->list_mutex);
    return 0;
}

int Cloud_CoAPMessageHandler_set(Cloud_CoAPMessage *message, Cloud_CoAPRespMsgHandler resp)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->resp = resp;
    return COAP_SUCCESS;
}


static int Cloud_message_report(Cloud_CoAPSendNode *node, char *context) {
    char traceId[C_MAX_ID_LEN] = {0};
    uint32_t cost = 0;
    uint64_t time =  atlas_boot_uptime();
    if (!context || !node) {
        return -1;
    }
    if (!node->user) { // heartBeat
        if (node->msgid % 5 != 0) {
            return 0;
        }
    }

    atlas_snprintf(traceId, C_MAX_ID_LEN, "ffffffff%llu%05d67%s",node->send_msg_time ,node->msgid, C_ATLAS_SDK_VERSION_STR);
    cost = (uint32_t)(time - node->send_msg_time);
    cniot_atlas_report(REPORT_UPLOAD,"DEVICE_COAP_MESSAGE", traceId, atlas_abs_time(), cost, context, CNIOT_STATUS_CODE_OK);
    return 0;
}

static int Cloud_CoAPMessageList_add(Cloud_CoAPContext *context, Cloud_CoAPMessage *message, unsigned char *buff, int len)
{
    Cloud_CoAPSendNode *node = NULL;
    node = coap_malloc(sizeof(Cloud_CoAPSendNode));

    if (NULL != node) {
        node->acked        = 0;
        node->user         = message->user;
        node->msgid        = message->header.msgid;
        node->resp         = message->resp;
        node->msglen       = len;
        node->rsp_msg      = NULL;
        node->rsp_msg_len  = 0;
        node->recv_msg_time = 0;
        node->send_msg_time = atlas_boot_uptime();
        node->need_rsp      = message->need_rsp;
        node->timeout_val   = COAP_ACK_TIMEOUT * COAP_ACK_RANDOM_FACTOR;

        if (COAP_MESSAGE_TYPE_CON == message->header.type) {
            node->timeout       = node->timeout_val;
            node->retrans_count = 0;
        } else {
            node->timeout       = COAP_MAX_TRANSMISSION_SPAN;
            node->retrans_count = COAP_MAX_RETRY_COUNT;
        }
        node->tokenlen     = message->header.tokenlen;
        memcpy(node->token, message->token, message->header.tokenlen);
        node->message      = (unsigned char *)coap_malloc(len);
        if (NULL != node->message) {
            memcpy(node->message, buff, len);
        }
        //Cloud_message_report(node, (char *)message->payload);

        if (&context->list.count >= &context->list.maxcount) {
            coap_free(node);
            return -1;
        } else {
            atlas_mutex_lock(context->list_mutex);
            list_add_tail(&node->sendlist, &context->list.sendlist);
            atlas_mutex_unlock(context->list_mutex);
            context->list.count ++;
            return 0;
        }
    } else {
        return -1;
    }
}

int Cloud_CoAPMessage_send(Cloud_CoAPContext *context, Cloud_CoAPMessage *message)
{
    unsigned int   ret            = COAP_SUCCESS;
    unsigned short msglen         = 0;
    unsigned char *buff = NULL;
    if (NULL == message || NULL == context) {
        return (COAP_ERROR_INVALID_PARAM);
    }

    /* TODO: get the message length */
    /* msglen = CoAPSerialize_MessageLength(message); */
    msglen = CoAPSerialize_MessageLength(message);
    if (COAP_MSG_MAX_PDU_LEN < msglen) {
        COAP_INFO("The message length %d is too loog", msglen);
        return COAP_ERROR_DATA_SIZE;
    }

    buff = coap_malloc(COAP_MSG_MAX_PDU_LEN);
    if (!buff) {
        return COAP_ERROR_MALLOC;
    }
    memset(buff, 0x00, COAP_MSG_MAX_PDU_LEN);
    msglen = CoAPSerialize_Message(message, buff, COAP_MSG_MAX_PDU_LEN);
    COAP_DEBUG("----The message length %d-----", msglen);
    ret = Cloud_CoAPNetwork_write(&context->network, context->lwip_mutex, buff, (unsigned int)msglen);
    if (COAP_SUCCESS == ret) {
        if (Cloud_CoAPReqMsg(message->header) || Cloud_CoAPCONRespMsg(message->header)) {
            COAP_DEBUG("Add message id %d len %d to the list",
                       message->header.msgid, msglen);
            Cloud_CoAPMessageList_add(context, message, buff, msglen);
        } else {
            COAP_DEBUG("The message doesn't need to be retransmitted");
        }
    } else {
        COAP_ERR("CoAP transport write failed, return %d", ret);
    }

    coap_free(buff);
    return ret;
}


static int Cloud_CoAPAckMessage_handle(Cloud_CoAPContext *context, Cloud_CoAPMessage *message)
{
    Cloud_CoAPSendNode *node = NULL;
    atlas_mutex_lock(context->list_mutex);
    list_for_each_entry(node, &context->list.sendlist, sendlist, Cloud_CoAPSendNode) {
        if (node->msgid == message->header.msgid) {
            node->acked = 1;
            Cloud_message_report(node, "receive ack");
            if (!node->need_rsp || message->header.code == COAP_MSG_CODE_231_CONTINUE) {
                list_del_init(&node->sendlist);
                if (node->resp) {
                    node->resp(node->user, message);
                }
                context->list.count--;
                coap_free(node->rsp_msg);
                coap_free(node->message);
                coap_free(node);
            }
            break;
        }
    }
    atlas_mutex_unlock(context->list_mutex);

    return COAP_SUCCESS;
}

static int Cloud_CoAPAckMessage_send(Cloud_CoAPContext *context, unsigned short msgid)
{
    Cloud_CoAPMessage message;
    CoAPMessage_init(&message);
    CoAPMessageId_set(&message, msgid);
    return Cloud_CoAPMessage_send(context, &message);
}

int Cloud_CoAPMessage_delete(Cloud_CoAPContext *context, unsigned  int messageId) {
    Cloud_CoAPSendNode *node = NULL;
    CoAPMessage message;
    int code = 0;
    int ret = COAP_ERROR_NOT_FOUND;
    if (!context) {
        return ret;
    }

    atlas_mutex_lock(context->list_mutex);

    list_for_each_entry(node, &context->list.sendlist, sendlist, Cloud_CoAPSendNode) {
        if (node->msgid == messageId) {
            list_del_init(&node->sendlist);
            context->list.count--;
            if (NULL != node->message) {
                coap_free(node->message);
            }
            ret = COAP_SUCCESS;
            coap_free(node);
            node = NULL;
            break;
        }
    }
    atlas_mutex_unlock(context->list_mutex);
    return ret;
}

int Cloud_GetCoAPRespMessage(Cloud_CoAPContext *context, unsigned  int messageId,  unsigned char **buff, unsigned int *buff_len) {
    Cloud_CoAPSendNode *node = NULL;
    CoAPMessage message;
    int ret = COAP_ERROR_NOT_FOUND;
    if (!context) {
        return ret;
    }
    atlas_mutex_lock(context->list_mutex);

    list_for_each_entry(node, &context->list.sendlist, sendlist, Cloud_CoAPSendNode) {
        if (node->msgid == messageId) {
            if (!node->rsp_msg) { // 没有收到消息
                ret = COAP_SUCCESS;
                break;
            }
            ret = CoAPDeserialize_Message(&message, node->rsp_msg, node->rsp_msg_len);
            if (ret != COAP_SUCCESS) {
                break;
            }
            *buff = node->rsp_msg;
            *buff_len = node->rsp_msg_len;
            list_del_init(&node->sendlist);
            context->list.count--;
            if (NULL != node->message) {
                coap_free(node->message);
            }
            coap_free(node);
            node = NULL;
            break;
        }
    }
    atlas_mutex_unlock(context->list_mutex);
    return ret;
}

static int Cloud_CoAPRespMessage_handle(Cloud_CoAPContext *context, Cloud_CoAPMessage *message, unsigned char *buff, int buff_len)
{
    Cloud_CoAPSendNode *node = NULL;
    int ret = COAP_ERROR_NOT_FOUND;
    if (COAP_MESSAGE_TYPE_CON == message->header.type) {
        Cloud_CoAPAckMessage_send(context, message->header.msgid);
    }

    atlas_mutex_lock(context->list_mutex);

    list_for_each_entry(node, &context->list.sendlist, sendlist, Cloud_CoAPSendNode) {
//        if (0 != node->tokenlen && node->tokenlen == message->header.tokenlen
//            && 0 == memcmp(node->token, message->token, message->header.tokenlen)) {  //下行块传输，收到的重传包不能很好的处理..
         if (node->msgid == message->header.msgid) {
            if (node->rsp_msg) { // 重复包不用处理
                ret = COAP_SUCCESS;
                break;
            }
            Cloud_message_report(node, "receive rsp");
            node->recv_msg_time = atlas_boot_uptime();
            node->rsp_msg_len = buff_len;
            node->rsp_msg = coap_malloc(node->rsp_msg_len + 1);
            if (!node->rsp_msg) {
                ret = COAP_ERROR_MALLOC;
                break;
            }
            memcpy(node->rsp_msg, buff, buff_len);
            if (node->resp) {
                node->resp(node->user, message);
            }
            break;
        }
    }

    atlas_mutex_unlock(context->list_mutex);

    return ret;
}

static void Cloud_CoAPMessage_handle(Cloud_CoAPContext *context,
                                     unsigned char     *buf,
                                     unsigned short      datalen)
{
    int    ret  = COAP_SUCCESS;
    Cloud_CoAPMessage     message;
    unsigned char code, msgclass, detail;
    memset(&message, 0x00, sizeof(Cloud_CoAPMessage));

    ret = CoAPDeserialize_Message(&message, buf, datalen);
    if (COAP_SUCCESS != ret) {
        if (NULL != context->notifier) {
            /* TODO: */
            /* context->notifier(context, event); */
        }
        return;
    } else {
        if (context->notifier) {
            context->notifier(code, &message);
        }
    }
    code = (unsigned char)message.header.code;
    msgclass = code >> 5;
    detail = code & 0x1F;

    COAP_DEBUG("Version     : %d", message.header.version);
    COAP_DEBUG("Code        : %d.%02d(0x%x)", msgclass, detail, code);
    COAP_DEBUG("Type        : 0x%x", message.header.type);
    COAP_DEBUG("Msgid       : %d", message.header.msgid);
    COAP_DEBUG("Option      : %d", message.optcount);
    COAP_DEBUG("Payload Len : %d", message.payloadlen);

    msgclass = msgclass;
    detail = detail;


    if (COAPAckMsg(message.header)) {
        COAP_DEBUG("Receive CoAP ACK Message,ID %d", message.header.msgid);
        Cloud_CoAPAckMessage_handle(context, &message);

    } else if (Cloud_CoAPRespMsg(message.header)) {
        COAP_DEBUG("Receive CoAP Response Message,ID %d", message.header.msgid);
        Cloud_CoAPRespMessage_handle(context, &message, buf, datalen);
    }
}

int Cloud_CoAPMessage_recv(Cloud_CoAPContext *context, unsigned int timeout, int readcount)
{
    int len = 0;
    int count = readcount;

    uint64_t end = atlas_boot_uptime() + timeout, now =0, read_end = 0;
    while (1) {
        now =  atlas_boot_uptime();
        if (end < now + 30) {
           return 0;
        }
        timeout = end - now;
        len = Cloud_CoAPNetwork_read(&context->network, context->lwip_mutex, context->recvbuf,
                                     COAP_MSG_MAX_PDU_LEN, timeout);
        read_end = atlas_boot_uptime();
        if (read_end  > now + timeout + 1000) {
            COAP_ERR("select read timeout timeout=%d read time=%llu", timeout, read_end - now);
        }
        if (len > 0) {
            if (0 == readcount) {
                Cloud_CoAPMessage_handle(context, context->recvbuf, len);
            } else {
                count--;
                Cloud_CoAPMessage_handle(context, context->recvbuf, len);
                if (0 == count) {
                    return len;
                }
            }
        } else {
            return 0;
        }
    }
}

int Cloud_CoAPMessage_cycle(Cloud_CoAPContext *context)
{
    unsigned int ret = 0;
    Cloud_CoAPSendNode *node = NULL, *next = NULL;
    if (NULL == context) {
        return COAP_ERROR_INVALID_PARAM;
    }
    Cloud_CoAPMessage_recv(context, context->waittime, 10);
#define C_MAX_COAP_RECV_TIMEOUT (5000)
    atlas_mutex_lock(context->list_mutex);
    list_for_each_entry_safe(node, next, &context->list.sendlist, sendlist, Cloud_CoAPSendNode) {
        if (NULL != node) {
            if (node->timeout == 0) {
                if (node->retrans_count < COAP_MAX_RETRY_COUNT && (0 == node->acked && !node->rsp_msg)) {
                    node->timeout     = node->timeout_val  + 1; // rfc -> *2 for rtos
                    node->timeout_val = node->timeout;
                    node->retrans_count++;
                    ret = Cloud_CoAPNetwork_write(&context->network, context->lwip_mutex, node->message, node->msglen);
                    COAP_ERR("Retansmit the message id %d len %d  timeout=%llu", node->msgid, node->msglen, atlas_boot_uptime() - node->send_msg_time);
                    if (ret != COAP_SUCCESS) {
                        if (NULL != context->notifier) {
                            /* TODO: */
                            /* context->notifier(context, event); */
                        }
                    }
                }

                if ((node->timeout > COAP_MAX_TRANSMISSION_SPAN) ||
                    (node->retrans_count >= COAP_MAX_RETRY_COUNT) ||
                    (0 != node->recv_msg_time && node->recv_msg_time  + C_MAX_COAP_RECV_TIMEOUT < atlas_boot_uptime())) {
                    /*Remove the node from the list*/
                    list_del_init(&node->sendlist);
                    context->list.count--;
                    if (node->retrans_count >= COAP_MAX_RETRY_COUNT || node->timeout > COAP_MAX_TRANSMISSION_SPAN) {
                        COAP_ERR("Retransmit timeout,remove the message id %d list_count %d",
                                 node->msgid, context->list.count);
                        Cloud_message_report(node, "Retransmit timeout");
                    }
                    if (0 != node->recv_msg_time && node->need_rsp && node->recv_msg_time  + C_MAX_COAP_RECV_TIMEOUT < atlas_boot_uptime()) {
                        COAP_ERR("Recevie message buff timeout,remove the message id %d list_count %d",
                                 node->msgid, context->list.count);
                        Cloud_message_report(node, "rsp data not process");
                    }
                    coap_free(node->rsp_msg);
                    coap_free(node->message);
                    coap_free(node);
                }
            } else {
                node->timeout--;
            }
        }
    }

    atlas_mutex_unlock(context->list_mutex);
    return COAP_SUCCESS;
}

