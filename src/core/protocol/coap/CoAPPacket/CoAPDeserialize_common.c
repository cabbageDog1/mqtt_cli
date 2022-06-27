/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */




#include <stdio.h>
#include <string.h>
#include "iotx_coap_internal.h"

int CoAPDeserialize_Header(CoAPMessage *msg, unsigned char *buf)
{
    msg->header.version   = ((buf[0] >> 6) & 0x03);
    msg->header.type      = ((buf[0] >> 4) & 0x03);
    msg->header.tokenlen  = (buf[0] & 0x0F);
    msg->header.code      =  buf[1];
    msg->header.msgid     =  buf[2] << 8;
    msg->header.msgid    +=  buf[3];

    return 4;
}

int CoAPDeserialize_Token(CoAPMessage *msg, unsigned char *buf)
{
    memcpy(msg->token, buf, msg->header.tokenlen);
    return msg->header.tokenlen;
}

static int CoAPDeserialize_Option(CoAPMsgOption *option, unsigned char *buf, unsigned short *predeltas, int buf_len)
{
    unsigned char  *ptr      = buf;
    unsigned short optdelta  = 0;
    unsigned short optlen    = 0;
    unsigned short predelta  = 0;

    optdelta  = (*ptr & 0xF0) >> 4;
    optlen    = (*ptr & 0x0F);
    if (buf + buf_len < ptr + 1) {
        return -1;
    }
    ptr++;

    predelta = *predeltas;
    if (13 == optdelta) {
        predelta += 13 + *ptr;
        if (buf + buf_len < ptr + 1) {
            return -1;
        }
        ptr ++;
    } else if (14 == optdelta) {
        predelta += 269;
        if (buf + buf_len < ptr +2) {
            return -1;
        }
        predelta += (*ptr << 8);
        predelta +=  *(ptr + 1);
        ptr += 2;
    } else {
        predelta += optdelta;
    }
    option->num = predelta;

    if (13 == optlen) {
        optlen = 13 + *ptr;
        if (buf + buf_len < ptr + 1) {
            return -1;
        }
        ptr ++;
    } else if (14 == optlen) {
        optlen = 269;
        if (buf + buf_len < ptr + 2) {
            return -1;
        }
        optlen += (*ptr << 8);
        optlen += *(ptr + 1);
        ptr += 2;

    }
    option->len = optlen;

    option->val = ptr;
    *predeltas = option->num;

    return (ptr - buf + option->len);
}

int CoAPDeserialize_Options(CoAPMessage *msg, unsigned char *buf, int buflen)
{
    int  index = 0;
    int  count = 0;
    unsigned char  *ptr      = buf;
    unsigned short len       = 0;
    unsigned short optdeltas = 0;

    msg->optcount = 0;
    while ((count < buflen) && (0xFF != *ptr)) {
        len = CoAPDeserialize_Option(&msg->options[index], ptr, &optdeltas, buflen - count);
        if (len  < 0) {
            return len;
        }
        msg->optcount += 1;
        ptr += len;
        index ++;
        if (index >= COAP_MSG_MAX_OPTION_NUM) {
            return -1; //越界
        }
        count += len;
    }

    return (int)(ptr - buf);
}

int CoAPDeserialize_Payload(CoAPMessage *msg, unsigned char *buf, int buflen)
{
    unsigned char *ptr = buf;

    if (0xFF == *ptr) {
        if (buflen == 0) {
            return -1;
        }
        ptr ++;
    } else {
        return 0;
    }
    msg->payloadlen = buflen - 1;
    msg->payload = (unsigned char *)ptr;

    return buflen;
}

int CoAPDeserialize_Message(CoAPMessage *msg, unsigned char *buf, int buflen)
{
    int count  = 0;
    int remlen = buflen;
    unsigned char *ptr = buf;

    if (NULL == buf || NULL == msg) {
        return COAP_ERROR_INVALID_PARAM;
    }

    if (buflen < 4) {
        return COAP_ERROR_INVALID_LENGTH;
    }

    /* Deserialize CoAP header. */
    count = CoAPDeserialize_Header(msg, ptr);
    ptr += count;
    remlen -= count;

    if (remlen < 0) {
        printf("parse header failed, receive not coap packet len=%d remlen=%d\n", buflen, remlen);
        return COAP_ERROR_INVALID_LENGTH;
    }

    if (msg->header.tokenlen > COAP_MSG_MAX_TOKEN_LEN) {
        printf("parse header failed, token len is over 8 len=%d\n", msg->header.tokenlen);
        return COAP_ERROR_INVALID_LENGTH;
    }

    if (remlen == 0) {
        return COAP_SUCCESS;
    }
    /* Deserialize the token, if any. */
    count = CoAPDeserialize_Token(msg, ptr);
    ptr += count;
    remlen -= count;

    if (remlen < 0) {
        printf("parse token failed, receive not coap packet len=%d remlen=%d\n", buflen, remlen);
        return COAP_ERROR_INVALID_LENGTH;
    }

    count = CoAPDeserialize_Options(msg, ptr, remlen);
    if (count < 0) {
        printf("parse options return failed, receive not coap packet len=%d remlen=%d\n", buflen, remlen);
        return COAP_ERROR_INVALID_LENGTH;
    }
    ptr += count;
    remlen -= count;

    if (remlen < 0) {
        printf("parse options failed, receive not coap packet len=%d remlen=%d\n", buflen, remlen);
        return COAP_ERROR_INVALID_LENGTH;
    }

    CoAPDeserialize_Payload(msg, ptr, remlen);

    return COAP_SUCCESS;
}
