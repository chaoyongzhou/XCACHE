/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <sys/stat.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"
#include "cqueue.h"

#include "cbc.h"

#include "cmisc.h"

#include "task.h"
#include "tasks.h"
#include "csocket.h"

#include "cepoll.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "cssl.h"
#include "chttp.h"
#include "chttps.h"

#include "cdns.h"
#include "coroutine.h"
#include "csrv.h"
#include "cconnp.h"


static CQUEUE g_chttps_defer_request_queue;
static EC_BOOL g_chttps_defer_request_queue_init_flag = EC_FALSE;

static CLIST  *g_chttps_rest_list  = NULL_PTR;

#if 1
#define CHTTPS_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error:assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

/*---------------------------------------------- FOR SSL  ----------------------------------------------*/

/*write until all data out or no further data can be sent out at present*/
EC_BOOL chttps_ssl_send(CHTTPS_NODE *chttps_node, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos)
{
    CSSL_NODE *cssl_node;

    cssl_node = CHTTPS_NODE_CSSL_NODE(chttps_node);
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_ssl_send: cssl_node does not exist\n");
        return (EC_FALSE);
    }

    return cssl_node_send(cssl_node, once_max_size, out_buff, out_buff_max_len, pos); 
}

EC_BOOL chttps_ssl_recv(CHTTPS_NODE *chttps_node, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    CSSL_NODE *cssl_node;

    cssl_node = CHTTPS_NODE_CSSL_NODE(chttps_node);
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_ssl_recv: cssl_node does not exist\n");
        return (EC_FALSE);
    }

    return cssl_node_recv(cssl_node, once_max_size, in_buff, in_buff_expect_len, pos);
}

EC_BOOL chttps_send(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode, const UINT8 * out_buff, const UINT32 out_buff_max_len, UINT32 * pos)
{
    if(CSOCKET_TYPE_TCP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return chttps_ssl_send(chttps_node, CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode),
                            out_buff, out_buff_max_len, pos); 
    }

    dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "error:chttps_send: sockfd %d, invalid type %u \n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_TYPE(csocket_cnode));
    return (EC_FALSE);
}

EC_BOOL chttps_recv(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    if(CSOCKET_TYPE_TCP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return chttps_ssl_recv(chttps_node, CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode),
                            in_buff, in_buff_expect_len, pos);
    }

    dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "error:chttps_recv: sockfd %d, invalid type %u \n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_TYPE(csocket_cnode));
    return (EC_FALSE);
}

/*private interface, not for http parser*/
static EC_BOOL __chttps_on_recv_complete(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE *csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT,
            "[DEBUG] __chttps_on_recv_complete: sockfd %d, body parsed %ld\n",
            CSOCKET_CNODE_SOCKFD(csocket_cnode), CHTTPS_NODE_BODY_PARSED_LEN(chttps_node));

    CHTTPS_NODE_LOG_TIME_WHEN_RCVD(chttps_node);/*record the received or parsed time*/

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTPS_NODE_TYPE(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE REQ]\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
 
        /*note: http request is ready now. stop read from socket to prevent recving during handling request*/
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        
        if(BIT_TRUE == CHTTPS_NODE_HEADER_COMPLETE(chttps_node))
        {
            chttps_pause_parser(CHTTPS_NODE_PARSER(chttps_node)); /*pause parser*/
         
            /*commit*/
            chttps_defer_request_queue_push(chttps_node);

            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE REQ] commit request\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

            CHTTPS_NODE_RECV_COMPLETE(chttps_node) = BIT_TRUE;
            return (EC_TRUE);
        }
     
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_recv_complete: socket %d, [type: HANDLE REQ] header not completed\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE RSP]\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));

        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
 
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0001);
        }

        if(BIT_TRUE == CHTTPS_NODE_HEADER_COMPLETE(chttps_node))
        {
            CHTTPS_NODE_RECV_COMPLETE(chttps_node) = BIT_TRUE;
        }
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE CHECK]\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
                     
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
     
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0002);
        }

        CHTTPS_NODE_RECV_COMPLETE(chttps_node) = BIT_TRUE;
        return (EC_TRUE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE: unknown 0x%lx]\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), CHTTPS_NODE_TYPE(chttps_node));
                 
    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    return (EC_FALSE);
}

/*private interface, not for http parser*/
static EC_BOOL __chttps_on_send_complete(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE *csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    
    /*note: http request is ready now. stop read from socket to prevent recving during handling request*/
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))
    {
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0003);
        }
    }

    CHTTPS_NODE_SEND_COMPLETE(chttps_node) = BIT_TRUE;

    return (EC_TRUE);
}

/*---------------------------------------- HTTP PASER INTERFACE ----------------------------------------*/
static int __chttps_on_message_begin(http_parser_t* http_parser)
{
    CHTTPS_NODE *chttps_node;

    chttps_node= (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_message_begin: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_message_begin: chttps_node %p, ***MESSAGE BEGIN***\n",
                    chttps_node);
    return (0);
}

/**
*
* refer http parser case s_headers_almost_done
*
* if return 0, succ
* if return 1, SKIP BODY
* otherwise, error
*
**/
static int __chttps_on_headers_complete(http_parser_t* http_parser, const char* last, size_t length)
{
    CHTTPS_NODE    *chttps_node;

    chttps_node = (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_headers_complete: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }

    chttps_parse_host(chttps_node);
    chttps_parse_uri(chttps_node);
    chttps_parse_content_length(chttps_node);
#if 1
    if(EC_FALSE == chttps_parse_connection_keepalive(chttps_node))
    {
        /*should never reach here due to csocket_cnode was checked before*/
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_headers_complete: chttps_node %p parse connection keepalive failed\n",
                        chttps_node);
        return (-1);/*error*/
    }
#else
    CHTTPS_NODE_KEEPALIVE(chttps_node) = BIT_FALSE; /*force to disable keepalive*/
#endif 

    CHTTPS_NODE_HEADER_COMPLETE(chttps_node) = BIT_TRUE;  /*header is ready*/
    CHTTPS_NODE_HEADER_PARSED_LEN(chttps_node) += length; /*the last part of header*/

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        sys_log(LOGSTDOUT, "[DEBUG] __chttps_on_headers_complete: socket %d, ***HEADERS COMPLETE***\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode)); 
    }

    return (0);/*succ*/
}

static int __chttps_on_message_complete(http_parser_t* http_parser)
{
    CHTTPS_NODE    *chttps_node;
     CSOCKET_CNODE  *csocket_cnode;

    chttps_node= (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_message_complete: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_message_complete: http_parser %p -> chttps_node %p -> csocket_cnode is null\n", http_parser, chttps_node);
        return (-1);/*error*/
    } 

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT,
            "[DEBUG] __chttps_on_message_complete: sockfd %d, http state %s, header parsed %u, body parsed %"PRId64", errno = %d, name = %s, description = %s\n",
            CSOCKET_CNODE_SOCKFD(csocket_cnode), http_state_str(http_parser->state),
            CHTTPS_NODE_HEADER_PARSED_LEN(chttps_node),CHTTPS_NODE_BODY_PARSED_LEN(chttps_node),
            HTTP_PARSER_ERRNO(http_parser), http_errno_name(HTTP_PARSER_ERRNO(http_parser)), http_errno_description(HTTP_PARSER_ERRNO(http_parser)));

     __chttps_on_recv_complete(chttps_node);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_message_complete: socket %d, ***MESSAGE COMPLETE***\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return (0);
}

static int __chttps_on_url(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTPS_NODE    *chttps_node;

    chttps_node= (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_url: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }

    cbuffer_set(CHTTPS_NODE_URL(chttps_node), (uint8_t *)at, length);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_url: chttps_node %p, url: %.*s\n",
                    chttps_node, (int)length, at);

    return (0);
}

/*only for http response*/
static int __chttps_on_status(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTPS_NODE    *chttps_node;
    CSOCKET_CNODE  *csocket_cnode;

    chttps_node= (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_status: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_status: http_parser %p -> chttps_node %p -> csocket_cnode is null\n", http_parser, chttps_node);
        return (-1);/*error*/
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node))
    {
        CHTTPS_NODE_STATUS_CODE(chttps_node) = http_parser->status_code;

        if(do_log(SEC_0157_CHTTPS, 9))
        {
            UINT32 status_code;

            status_code = CHTTPS_NODE_STATUS_CODE(chttps_node);
            sys_log(LOGSTDOUT, "[DEBUG] __chttps_on_status: socket %d, status: %u %.*s ==> %ld\n",
                                CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                http_parser->status_code, (int)length, at,
                                status_code);     
        }
    }

    return (0);
}

static int __chttps_on_header_field(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTPS_NODE    *chttps_node;
    CSTRKV *cstrkv;

    chttps_node= (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_field: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }

    cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_field: new cstrkv failed where header field: %.*s\n",
                           (int)length, at);
        return (-1);
    }

    cstrkv_set_key_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length);
    cstrkv_mgr_add_kv(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), cstrkv);

    //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_field: chttps_node %p, Header field: '%.*s'\n", chttps_node, (int)length, at);
    return (0);
}

static int __chttps_on_header_value(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTPS_NODE    *chttps_node;
    CSTRKV *cstrkv;

    chttps_node= (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_value: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }
 
    cstrkv = cstrkv_mgr_last_kv(CHTTPS_NODE_HEADER_IN_KVS(chttps_node));
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_value: no cstrkv existing where value field: %.*s\n",
                           (int)length, at);
        return (-1);
    }

    cstrkv_set_val_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length);
    //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_value: chttps_node %p, Header value: '%.*s'\n", chttps_node, (int)length, at);
#if 0
    if(do_log(SEC_0157_CHTTPS, 9))
    {
        cstrkv_print(LOGSTDOUT, cstrkv);
    }
#endif
 
    return (0);
}

static int __chttps_on_body(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTPS_NODE    *chttps_node;
    CHUNK_MGR      *recv_chunks;

    chttps_node= (CHTTPS_NODE *)http_parser->data;
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_body: http_parser %p -> chttps_node is null\n", http_parser);
        return (-1);/*error*/
    }

    recv_chunks = CHTTPS_NODE_RECV_BUF(chttps_node);

    if(EC_FALSE == chunk_mgr_append_data_min(recv_chunks, (uint8_t *)at, length, CHTTP_IN_BUF_SIZE))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_body: append %d bytes failed\n", length);
        return (-1);
    }
    CHTTPS_NODE_BODY_PARSED_LEN(chttps_node) += length;

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_body: chttps_node %p, len %d => body parsed %"PRId64"\n",
                    chttps_node, length, CHTTPS_NODE_BODY_PARSED_LEN(chttps_node));

    return (0);
}

/*---------------------------------------- INTERFACE WITH HTTP PASER  ----------------------------------------*/
static void __chttps_parser_init(http_parser_t   *http_parser, const UINT32 type)
{
    if(NULL_PTR != http_parser)
    {
        if(CHTTP_TYPE_DO_SRV_REQ == type)
        {
            http_parser_init(http_parser, HTTP_REQUEST);
            return;
        }

        if(CHTTP_TYPE_DO_CLT_RSP == type)
        {
            http_parser_init(http_parser, HTTP_RESPONSE);
            return;
        }

        if(CHTTP_TYPE_DO_REQ_RSP == type)
        {
            http_parser_init(http_parser, HTTP_BOTH);
            return;
        }
    }
    return;
}

static void __chttps_parser_setting_init(http_parser_settings_t   *http_parser_setting)
{
    if(NULL_PTR != http_parser_setting)
    {
        http_parser_setting->on_message_begin    = __chttps_on_message_begin;
        http_parser_setting->on_url              = __chttps_on_url;
        http_parser_setting->on_status           = __chttps_on_status;
        http_parser_setting->on_header_field     = __chttps_on_header_field;
        http_parser_setting->on_header_value     = __chttps_on_header_value;
        http_parser_setting->on_headers_complete = __chttps_on_headers_complete;
        http_parser_setting->on_body             = __chttps_on_body;
        http_parser_setting->on_message_complete = __chttps_on_message_complete;
    }

    return;
}

static void __chttps_parser_clean(http_parser_t   *http_parser)
{
    if(NULL_PTR != http_parser)
    {
        /** PRIVATE **/
        http_parser->type           = 0x03;   /*2 bits, invalid type, enum http_parser_type*/
        http_parser->flags          = 0x3F;   /*6 bits, invalid flag, enum flags*/
        http_parser->state          = s_undef;/*8 bits, invalid state, enum state*/
        http_parser->header_state   = 0xFF;   /*8 bits, invalid header_state, enum header_states*/
        http_parser->index          = 0xFF;   /*8 bits, invalid index*/
        http_parser->nread          = 0;
        http_parser->content_length = 0;

        /** READ-ONLY **/
        http_parser->http_major     = 0;
        http_parser->http_minor     = 0;
        http_parser->status_code    = 0;       /*16 bits, invalid status code, 1xx, 2xx,3xx,4xx,5xx, responses only*/
        http_parser->method         = 0xFF;    /*8 bits, invalid method, HTTP_METHOD_MAP, requests only*/
        http_parser->http_errno     = 0x7F;    /*7 bits, invalid errno, HTTP_ERRNO_MAP*/
        http_parser->upgrade        = 0;       /*1 bit*/

        /** PUBLIC **/
        http_parser->data           = NULL_PTR;
    }
    return;
}

static void __chttps_parser_setting_clean(http_parser_settings_t   *http_parser_setting)
{
    if(NULL_PTR != http_parser_setting)
    {
        http_parser_setting->on_message_begin    = NULL_PTR;
        http_parser_setting->on_url              = NULL_PTR;
        http_parser_setting->on_status           = NULL_PTR;
        http_parser_setting->on_header_field     = NULL_PTR;
        http_parser_setting->on_header_value     = NULL_PTR;
        http_parser_setting->on_headers_complete = NULL_PTR;
        http_parser_setting->on_body             = NULL_PTR;
        http_parser_setting->on_message_complete = NULL_PTR;
    }

    return;
}

/*---------------------------------------- INTERFACE WITH HTTPS NODE  ----------------------------------------*/
CHTTPS_NODE *chttps_node_new(const UINT32 type)
{
    CHTTPS_NODE *chttps_node;

    alloc_static_mem(MM_CHTTPS_NODE, &chttps_node, LOC_CHTTPS_0004);
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_new: new chttps_node failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == chttps_node_init(chttps_node, type))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_new: init chttps_node failed\n");
        free_static_mem(MM_CHTTPS_NODE, chttps_node, LOC_CHTTPS_0005);
        return (NULL_PTR);
    }

    return (chttps_node);
}

EC_BOOL chttps_node_init(CHTTPS_NODE *chttps_node, const UINT32 type)
{
    if(NULL_PTR != chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_init: chttps_node: %p\n", chttps_node);

        CHTTPS_NODE_STATUS(chttps_node)        = CHTTPS_NODE_STATUS_UNDEF;

        CHTTPS_NODE_CSSL_NODE(chttps_node)     = NULL_PTR; /* initialize ssl */
     
        CHTTPS_NODE_CSRV(chttps_node)          = NULL_PTR;
     
        CHTTPS_NODE_CROUTINE_NODE(chttps_node) = NULL_PTR;

        CHTTPS_NODE_CROUTINE_COND(chttps_node) = NULL_PTR;

        CHTTPS_NODE_TYPE(chttps_node) = type;

        CHTTPS_NODE_STATUS_CODE(chttps_node) = CHTTP_STATUS_NONE;
     
        __chttps_parser_init(CHTTPS_NODE_PARSER(chttps_node), type);
        __chttps_parser_setting_init(CHTTPS_NODE_SETTING(chttps_node));

        CHTTPS_NODE_CSOCKET_CNODE(chttps_node)     = NULL_PTR;
        CHTTPS_NODE_CQUEUE_DATA(chttps_node)       = NULL_PTR;

        cbuffer_init(CHTTPS_NODE_URL(chttps_node) , 0);
        cbuffer_init(CHTTPS_NODE_HOST(chttps_node), 0);
        cbuffer_init(CHTTPS_NODE_URI(chttps_node) , 0);
        cbuffer_init(CHTTPS_NODE_EXPIRES(chttps_node) , 0);

        cstrkv_mgr_init(CHTTPS_NODE_HEADER_IN_KVS(chttps_node));
        cstrkv_mgr_init(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node));

        cbytes_init(CHTTPS_NODE_CONTENT_CBYTES(chttps_node));

        CTMV_INIT(CHTTPS_NODE_START_TMV(chttps_node));

        CHTTPS_NODE_CONTENT_LENGTH(chttps_node)    = 0;
        CHTTPS_NODE_BODY_PARSED_LEN(chttps_node)   = 0;
        CHTTPS_NODE_BODY_STORED_LEN(chttps_node)   = 0;
        CHTTPS_NODE_HEADER_PARSED_LEN(chttps_node) = 0;
        CHTTPS_NODE_RSP_STATUS(chttps_node)        = CHTTP_STATUS_NONE;

        CHTTPS_NODE_EXPIRED_BODY_NEED(chttps_node) = BIT_TRUE;
        CHTTPS_NODE_KEEPALIVE(chttps_node)         = BIT_FALSE;
        CHTTPS_NODE_HEADER_COMPLETE(chttps_node)   = BIT_FALSE;
        CHTTPS_NODE_RECV_COMPLETE(chttps_node)     = BIT_FALSE;
        CHTTPS_NODE_SEND_COMPLETE(chttps_node)     = BIT_FALSE;
        CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_FALSE;

        cbuffer_init(CHTTPS_NODE_IN_BUF(chttps_node), CHTTP_IN_BUF_SIZE);
        chunk_mgr_init(CHTTPS_NODE_SEND_BUF(chttps_node));
        chunk_mgr_init(CHTTPS_NODE_RECV_BUF(chttps_node));

        chttp_stat_init(CHTTPS_NODE_STAT(chttps_node));
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_node_clean(CHTTPS_NODE *chttps_node)
{
    if(NULL_PTR != chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_clean: chttps_node %p\n", chttps_node);

        /* free CSSL_NODE */
        if(NULL_PTR != CHTTPS_NODE_CSSL_NODE(chttps_node))
        {
            cssl_node_free(CHTTPS_NODE_CSSL_NODE(chttps_node));
            CHTTPS_NODE_CSSL_NODE(chttps_node) = NULL_PTR;
        }

        CHTTPS_NODE_CSRV(chttps_node) = NULL_PTR;

        if(NULL_PTR != CHTTPS_NODE_CROUTINE_NODE(chttps_node))
        {
            croutine_pool_unload(TASK_REQ_CTHREAD_POOL(task_brd_default_get()), CHTTPS_NODE_CROUTINE_NODE(chttps_node));
            CHTTPS_NODE_CROUTINE_NODE(chttps_node) = NULL_PTR;
        }

        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node))
        {
            croutine_cond_free(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0006);
            CHTTPS_NODE_CROUTINE_COND(chttps_node) = NULL_PTR;
        }

        CHTTPS_NODE_TYPE(chttps_node)        = CHTTP_TYPE_DO_NOTHING;
        CHTTPS_NODE_STATUS_CODE(chttps_node) = CHTTP_STATUS_NONE;
 
        __chttps_parser_clean(CHTTPS_NODE_PARSER(chttps_node));
        __chttps_parser_setting_clean(CHTTPS_NODE_SETTING(chttps_node));

        cbuffer_clean(CHTTPS_NODE_IN_BUF(chttps_node));
        chunk_mgr_clean(CHTTPS_NODE_SEND_BUF(chttps_node));
        chunk_mgr_clean(CHTTPS_NODE_RECV_BUF(chttps_node));
     
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node)     = NULL_PTR; /*not handle the mounted csocket_cnode*/
        CHTTPS_NODE_CQUEUE_DATA(chttps_node)       = NULL_PTR; /*already umount chttps_node from defer list*/
     
        cbuffer_clean(CHTTPS_NODE_URL(chttps_node));
        cbuffer_clean(CHTTPS_NODE_HOST(chttps_node));
        cbuffer_clean(CHTTPS_NODE_URI(chttps_node));
        cbuffer_clean(CHTTPS_NODE_EXPIRES(chttps_node));

        cstrkv_mgr_clean(CHTTPS_NODE_HEADER_IN_KVS(chttps_node));
        cstrkv_mgr_clean(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node));

        cbytes_clean(CHTTPS_NODE_CONTENT_CBYTES(chttps_node));

        CTMV_CLEAN(CHTTPS_NODE_START_TMV(chttps_node));

        CHTTPS_NODE_CONTENT_LENGTH(chttps_node)    = 0;
        CHTTPS_NODE_BODY_PARSED_LEN(chttps_node)   = 0;
        CHTTPS_NODE_BODY_STORED_LEN(chttps_node)   = 0;
        CHTTPS_NODE_HEADER_PARSED_LEN(chttps_node) = 0;
        CHTTPS_NODE_RSP_STATUS(chttps_node)        = CHTTP_STATUS_NONE;

        CHTTPS_NODE_EXPIRED_BODY_NEED(chttps_node) = BIT_TRUE;
        CHTTPS_NODE_KEEPALIVE(chttps_node)         = BIT_FALSE;
        CHTTPS_NODE_HEADER_COMPLETE(chttps_node)   = BIT_FALSE;
        CHTTPS_NODE_RECV_COMPLETE(chttps_node)     = BIT_FALSE;
        CHTTPS_NODE_SEND_COMPLETE(chttps_node)     = BIT_FALSE;
        CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_FALSE;

        chttp_stat_clean(CHTTPS_NODE_STAT(chttps_node));

        CHTTPS_NODE_STATUS(chttps_node)            = CHTTPS_NODE_STATUS_UNDEF;
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_node_free(CHTTPS_NODE *chttps_node)
{
    if(NULL_PTR != chttps_node)
    {
        chttps_node_clean(chttps_node);
        free_static_mem(MM_CHTTPS_NODE, chttps_node, LOC_CHTTPS_0007);
    }

    return (EC_TRUE);
}

/*note: chttps_node_clear is ONLY for memory recycle asap before it comes to life-cycle end*/
EC_BOOL chttps_node_clear(CHTTPS_NODE *chttps_node)
{
    if(NULL_PTR != chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_clear: try to clear chttps_node %p unused data\n", chttps_node);

        //cbuffer_clean(CHTTPS_NODE_IN_BUF(chttps_node));
        chunk_mgr_clean(CHTTPS_NODE_SEND_BUF(chttps_node));
        chunk_mgr_clean(CHTTPS_NODE_RECV_BUF(chttps_node));
     
        cbuffer_clean(CHTTPS_NODE_URL(chttps_node));
        cbuffer_clean(CHTTPS_NODE_HOST(chttps_node));
        cbuffer_clean(CHTTPS_NODE_URI(chttps_node));
        cbuffer_clean(CHTTPS_NODE_EXPIRES(chttps_node));

        cstrkv_mgr_clean(CHTTPS_NODE_HEADER_IN_KVS(chttps_node));
        cstrkv_mgr_clean(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node));
     
        cbytes_clean(CHTTPS_NODE_CONTENT_CBYTES(chttps_node));

        CTMV_CLEAN(CHTTPS_NODE_START_TMV(chttps_node));

        CHTTPS_NODE_CONTENT_LENGTH(chttps_node)    = 0;
        CHTTPS_NODE_BODY_PARSED_LEN(chttps_node)   = 0;
        CHTTPS_NODE_BODY_STORED_LEN(chttps_node)   = 0;
        CHTTPS_NODE_HEADER_PARSED_LEN(chttps_node) = 0;
        //CHTTPS_NODE_RSP_STATUS(chttps_node)        = CHTTP_STATUS_NONE;

        //CHTTPS_NODE_EXPIRED_BODY_NEED(chttps_node) = BIT_TRUE;
        //CHTTPS_NODE_KEEPALIVE(chttps_node)         = BIT_FALSE;
        CHTTPS_NODE_HEADER_COMPLETE(chttps_node)   = BIT_FALSE;
        CHTTPS_NODE_RECV_COMPLETE(chttps_node)     = BIT_FALSE;
        CHTTPS_NODE_SEND_COMPLETE(chttps_node)     = BIT_FALSE;
        //CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_FALSE;

        chttp_stat_clean(CHTTPS_NODE_STAT(chttps_node));
    }

    return (EC_TRUE);
}

/*on server side: wait to resume*/
EC_BOOL chttps_node_wait_resume(CHTTPS_NODE *chttps_node)
{
    if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
    {
        CSOCKET_CNODE *csocket_cnode;
        CSRV          *csrv;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_wait_resume: chttps_node %p => csocket_cnode is null\n",
                       chttps_node);
            return (EC_FALSE);                    
        }

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
        CSOCKET_CNODE_PENDING(csocket_cnode) = BIT_TRUE;

        csrv = (CSRV *)CHTTPS_NODE_CSRV(chttps_node);

        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          (const char *)"csocket_cnode_irecv",
                          (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_wait_resume: sockfd %d >>> resume parser\n",
                   CSOCKET_CNODE_SOCKFD(csocket_cnode));
                
        chttp_resume_parser(CHTTPS_NODE_PARSER(chttps_node)); /*resume parser*/

        chttps_node_clear(chttps_node);

        /*reset start time after resume parser*/
        if(SWITCH_ON == HIGH_PRECISION_TIME_SWITCH)
        {
            task_brd_update_time_default();
        }
        CTMV_CLONE(task_brd_default_get_daytime(), CHTTPS_NODE_START_TMV(chttps_node));

        if(EC_TRUE == chttps_node_has_data_in(chttps_node))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_wait_resume: sockfd %d has more data in => parse now\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));     

            CSOCKET_CNODE_PENDING(csocket_cnode) = BIT_FALSE;
            CHTTPS_NODE_LOG_TIME_WHEN_START(chttps_node); /*record start time*/
     
            chttps_parse(chttps_node); /*try to parse if i-buffer has data more*/ 
        }
        return (EC_TRUE);/*wait for next http request*/
    }

    /*not keep-alive*/
    if(NULL_PTR != CHTTPS_NODE_CSOCKET_CNODE(chttps_node))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        /* unbind */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;/*trigger socket closing*/
    } 
    
    /*free*/
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_wait_resume: not keep-alive, clear chttps_node %p\n",
                                          chttps_node);    
    chttps_node_free(chttps_node);

    return (EC_TRUE);
}

void chttps_node_print(LOG *log, const CHTTPS_NODE *chttps_node)
{
    sys_log(log, "chttps_node_print:chttps_node: %p\n", chttps_node);
 
    sys_log(log, "chttps_node_print:url : \n");
    cbuffer_print_str(log, CHTTPS_NODE_URL(chttps_node));
 
    sys_log(log, "chttps_node_print:host : \n");
    cbuffer_print_str(log, CHTTPS_NODE_HOST(chttps_node));

    sys_log(log, "chttps_node_print:uri : \n");
    cbuffer_print_str(log, CHTTPS_NODE_URI(chttps_node));

    sys_log(log, "chttps_node_print:header_in kvs: \n");
    cstrkv_mgr_print(log, CHTTPS_NODE_HEADER_IN_KVS(chttps_node));

    sys_log(log, "chttps_node_print:header_out kvs: \n");
    cstrkv_mgr_print(log, CHTTPS_NODE_HEADER_OUT_KVS(chttps_node));
 
    sys_log(log, "chttps_node_print:header content length: %"PRId64"\n", CHTTPS_NODE_CONTENT_LENGTH(chttps_node));

    //sys_log(log, "chttps_node_print:req body chunks: total length %"PRId64"\n", chttps_node_recv_len(chttps_node));
 
    //chunk_mgr_print_str(log, chttps_node_recv_chunks(chttps_node));
    //chunk_mgr_print_info(log, chttps_node_recv_chunks(chttps_node));

    return;
}

EC_BOOL chttps_node_is_chunked(const CHTTPS_NODE *chttps_node)
{
    char *transfer_encoding;
    transfer_encoding = cstrkv_mgr_get_val_str_ignore_case(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), (const char *)"Transfer-Encoding");
    if(NULL_PTR == transfer_encoding)
    {
        return (EC_FALSE);
    }

    if(0 != STRCASECMP(transfer_encoding, (const char *)"chunked"))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_is_norange(const CHTTPS_NODE *chttps_node)
{
    char *content_range;
    content_range = cstrkv_mgr_get_val_str_ignore_case(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), (const char *)"Content-Range");
    if(NULL_PTR == content_range)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE); 
}

EC_BOOL chttps_node_recv(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    CBUFFER *http_in_buffer;
    UINT32   pos;
    EC_BOOL  ret;

    http_in_buffer = CHTTPS_NODE_IN_BUF(chttps_node);
 
    pos = CBUFFER_USED(http_in_buffer);
    ret = chttps_recv(chttps_node,
                    csocket_cnode,
                    CBUFFER_DATA(http_in_buffer),
                    CBUFFER_SIZE(http_in_buffer), /* fixed */
                    &pos);
 
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv: read on sockfd %d failed where size %d and used %d\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CBUFFER_SIZE(http_in_buffer),
                            CBUFFER_USED(http_in_buffer));

        return (EC_FALSE);                         
    }

    if(EC_TRUE == ret && CBUFFER_USED(http_in_buffer) == pos)
    {
        __chttps_on_recv_complete(chttps_node);
     
        if(EC_TRUE == csocket_cnode_is_connected(csocket_cnode))
        {
            return (EC_DONE);/*no more data to recv*/
        }
     
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                            "warn:chttps_node_recv: read nothing on sockfd %d (%s) where buffer size %d and used %d\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),  csocket_cnode_tcpi_stat_desc(csocket_cnode),
                            CBUFFER_SIZE(http_in_buffer),
                            CBUFFER_USED(http_in_buffer));
     
        return (EC_FALSE);
    }

    /*statistics*/
    CHTTPS_NODE_S_RECV_LEN_INC(chttps_node, (((uint32_t)pos) - CBUFFER_USED(http_in_buffer)));

    CBUFFER_USED(http_in_buffer) = (uint32_t)pos;
    return (EC_TRUE);
}

EC_BOOL chttps_node_send(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    CHUNK_MGR                *send_chunks;
    EC_BOOL                   data_sent_flag;

    send_chunks = CHTTPS_NODE_SEND_BUF(chttps_node);

    data_sent_flag = EC_FALSE; /*if any data is sent out, set it to EC_TRUE*/
    while(EC_FALSE == chunk_mgr_is_empty(send_chunks))
    {
        CHUNK      *chunk;
        UINT32      pos;
        EC_BOOL     ret;
     
        chunk = chunk_mgr_first_chunk(send_chunks);
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_send: sockfd %d chunk %p offset %d, buffer used %d\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            chunk, CHUNK_OFFSET(chunk), CHUNK_USED(chunk));
        if(CHUNK_OFFSET(chunk) >= CHUNK_USED(chunk))
        {
            /*send completely*/
            chunk_mgr_pop_first_chunk(send_chunks);
            chunk_free(chunk);
            continue;
        }

        pos = CHUNK_OFFSET(chunk);
        ret = chttps_send(chttps_node, csocket_cnode, CHUNK_DATA(chunk), CHUNK_USED(chunk), &pos);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send: sockfd %d send %ld bytes failed\n",
                               CSOCKET_CNODE_SOCKFD(csocket_cnode),
                               CHUNK_USED(chunk) - CHUNK_OFFSET(chunk)
                               );
         
            return (EC_FALSE);                        
        }

        if(CHUNK_OFFSET(chunk) == (uint32_t)pos)
        {
            if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode)) /*Jun 17, 2017*/
            {
                return (EC_FALSE);
            }
     
            if(EC_FALSE == data_sent_flag)/*Exception!*/
            {
                dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                                    "error:chttps_node_send: send nothing on sockfd %d failed whence chunk offset %d and used %d\n",
                                    CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                    CHUNK_OFFSET(chunk),
                                    CHUNK_USED(chunk));

                return (EC_FALSE);
            }
        }
        else
        {
            data_sent_flag = EC_TRUE;
        }

        /*statistics*/
        CHTTPS_NODE_S_SEND_LEN_INC(chttps_node, (((uint32_t)pos) - CHUNK_OFFSET(chunk)));

        CHUNK_OFFSET(chunk) = (uint32_t)pos;
        if(CHUNK_OFFSET(chunk) < CHUNK_USED(chunk))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_send: sockfd %d continous chunk %p, offset %u size %u\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode), chunk, CHUNK_OFFSET(chunk), CHUNK_USED(chunk)); 
     
            return (EC_TRUE);
        }

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_send: sockfd %d pop chunk %p and clean it, size %u\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode), chunk, CHUNK_USED(chunk)); 
     
        /*chunk is sent completely*/
        chunk_mgr_pop_first_chunk(send_chunks);
        chunk_free(chunk);
    } 

    return (EC_TRUE);
}

EC_BOOL chttps_node_need_send(CHTTPS_NODE *chttps_node)
{
    CHUNK_MGR                *send_chunks;

    send_chunks = CHTTPS_NODE_SEND_BUF(chttps_node);

    if(EC_TRUE == chunk_mgr_is_empty(send_chunks))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_need_parse(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == cbuffer_is_empty(CHTTPS_NODE_IN_BUF(chttps_node)))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chttps_node_has_data_in(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == cbuffer_is_empty(CHTTPS_NODE_IN_BUF(chttps_node)))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chttps_node_recv_export_to_cbytes(CHTTPS_NODE *chttps_node, CBYTES *cbytes, const UINT32 body_len)
{
    uint8_t       *data;
    uint32_t       size;

    if(EC_TRUE == chunk_mgr_umount_data(CHTTPS_NODE_RECV_BUF(chttps_node), &data, &size)) /*no data copying but data transfering*/
    {
        ASSERT(body_len == size);
        cbytes_mount(cbytes, size, data);
        return (EC_TRUE);
    }

    if(EC_FALSE == cbytes_expand_to(cbytes, body_len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_export_to_cbytes: expand cbytes to %ld failed\n",
                        body_len);
        return (EC_FALSE);
    }

    return chunk_mgr_export(CHTTPS_NODE_RECV_BUF(chttps_node), CBYTES_BUF(cbytes), CBYTES_LEN(cbytes), &CBYTES_LEN(cbytes));/*try again*/
}

EC_BOOL chttps_node_recv_clean(CHTTPS_NODE *chttps_node)
{
    return chunk_mgr_clean(CHTTPS_NODE_RECV_BUF(chttps_node));
}

/*for debug only*/
CHUNK_MGR *chttps_node_recv_chunks(const CHTTPS_NODE *chttps_node)
{
    return (CHUNK_MGR *)CHTTPS_NODE_RECV_BUF(chttps_node);
}

/*for debug only*/
UINT32 chttps_node_recv_chunks_num(const CHTTPS_NODE *chttps_node)
{
    return chunk_mgr_count_chunks(CHTTPS_NODE_RECV_BUF(chttps_node));
}


/*for debug only*/
UINT32 chttps_node_recv_len(const CHTTPS_NODE *chttps_node)
{
    return (UINT32)chunk_mgr_total_length(CHTTPS_NODE_RECV_BUF(chttps_node));
}

/*for debug only*/
UINT32 chttps_node_send_len(const CHTTPS_NODE *chttps_node)
{
    return (UINT32)chunk_mgr_send_length(CHTTPS_NODE_SEND_BUF(chttps_node));
}

EC_BOOL chttps_node_add_header(CHTTPS_NODE *chttps_node, const char *k, const char *v)
{
    return cstrkv_mgr_add_kv_str(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), k, v);
}

char *chttps_node_get_header(CHTTPS_NODE *chttps_node, const char *k)
{
    return cstrkv_mgr_get_val_str_ignore_case(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), k);
}

EC_BOOL chttps_node_del_header(CHTTPS_NODE *chttps_node, const char *k)
{
    return cstrkv_mgr_del_key_str(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), k);
}

EC_BOOL chttps_node_renew_header(CHTTPS_NODE *chttps_node, const char *k, const char *v)
{
    if(NULL_PTR == k)
    {
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_node_renew_header: k is null => no header renewed\n");
        return (EC_FALSE);
    }
 
    chttps_node_del_header(chttps_node, k);

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_node_renew_header: v is null => header ['%s'] was deleted only\n");
        return (EC_FALSE);
    }
 
    chttps_node_add_header(chttps_node, k, v);

    return (EC_TRUE);
}

EC_BOOL chttps_node_fetch_header(CHTTPS_NODE *chttps_node, const char *k, CSTRKV_MGR *cstrkv_mgr)
{
    char   * v;
 
    v = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR != v)
    {
        cstrkv_mgr_add_kv_str(cstrkv_mgr, k, v);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_fetch_headers(CHTTPS_NODE *chttps_node, const char *keys, CSTRKV_MGR *cstrkv_mgr)
{
    char    *s;
    char    *k[ 16 ];
 
    UINT32   num;
    UINT32   idx;

    s = c_str_dup(keys);
    if(NULL_PTR == s)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_fetch_headers: dup '%s' failed\n", keys);
        return (EC_FALSE);
    }

    num = c_str_split(s, ":;", k, sizeof(k)/sizeof(k[0]));
    for(idx = 0; idx < num; idx ++)
    {
        char   * v;
     
        v = chttps_node_get_header(chttps_node, k[ idx ]);
        if(NULL_PTR != v)
        {
            cstrkv_mgr_add_kv_str(cstrkv_mgr, k[ idx ], v);
        } 
    }

    safe_free(s, LOC_CHTTPS_0008);

    return (EC_TRUE);
}

EC_BOOL chttps_node_has_header_key(CHTTPS_NODE *chttps_node, const char *k)
{
    char *val;

    val = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == val)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_has_header(CHTTPS_NODE *chttps_node, const char *k, const char *v)
{
    char *val;

    val = chttps_node_get_header(chttps_node, k);
    if(NULL_PTR == val)
    {
        return (EC_FALSE);
    }

    if(NULL_PTR == v || 0 == STRCASECMP(val, v))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chttps_node_check_http_cache_control(CHTTPS_NODE *chttps_node)
{
    char     *v;

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_http_cache_control: enter\n");
    /*http specification*/
    v = chttps_node_get_header(chttps_node, (const char *)"Cache-Control");
    if(NULL_PTR != v)
    {
        if(EC_TRUE == c_str_is_in(v, ",", "no-cache,no-store,private"))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_http_cache_control: '%s' => false\n", v);
            return (EC_FALSE);
        }
        if(EC_TRUE == c_str_is_in(v, ",", "max-age=0"))/*case hpcc-52*/
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_http_cache_control: '%s' => true\n", v);
            return (EC_TRUE);
        }
    }
 
    v = chttps_node_get_header(chttps_node, (const char *)"Pragma");
    if(NULL_PTR != v)
    {
        if(EC_TRUE == c_str_is_in(v, ",", "no-cache"))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_http_cache_control: '%s' => false\n", v);
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_http_cache_control: leave\n");
    return (EC_TRUE);
}

EC_BOOL chttps_node_check_private_cache_control(CHTTPS_NODE *chttps_node)
{
    char     *v;

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_private_cache_control: enter\n");
    v = chttps_node_get_header(chttps_node, (const char *)"Expires");
    if(NULL_PTR != v)
    {
        if(EC_TRUE == c_str_is_in(v, ",", "-1"))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_private_cache_control: '%s' => false\n", v);
            return (EC_FALSE);
        }
    }
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check_private_cache_control: leave\n");
    return (EC_TRUE);
}

uint64_t chttps_node_fetch_file_size(CHTTPS_NODE *chttps_node)
{
    char        *v;
    char        *p;
 
    v = chttps_node_get_header(chttps_node, (const char *)"Content-Range");
    if(NULL_PTR == v)
    {
        v = chttps_node_get_header(chttps_node, (const char *)"Content-Length");
        if(NULL_PTR == v)
        {
            return ((uint64_t)0);
        }
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_fetch_file_size: Content-Length: '%s'\n", v);
        return c_str_to_uint64_t(v);
    }

    /*format should be xx-xx/xxx*/
    p = v + strlen(v) - 1;
    while('/' != (*p) && p > v)
    {
        p --;
    }

    if(p <= v)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_fetch_file_size: invalid Content-Range: '%s'\n", v);
        return((uint64_t)0);
    }
 
    p ++;
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_fetch_file_size: Content-Range: '%s'\n", p);
    return c_str_to_uint64_t(p);
}

/*---------------------------------------- HTTP HEADER PASER  ----------------------------------------*/

EC_BOOL chttps_parse_host(CHTTPS_NODE *chttps_node)
{
    CSTRING       *host_cstr;
    CBUFFER       *url;
    uint8_t       *data;
    uint8_t       *host_str;
    uint32_t       offset;
    uint32_t       host_len;
 
    host_cstr = cstrkv_mgr_get_val_cstr(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), "Host");
    if(NULL_PTR != host_cstr)
    {
        cbuffer_set(CHTTPS_NODE_HOST(chttps_node), cstring_get_str(host_cstr), (uint32_t)cstring_get_len(host_cstr));
        return (EC_TRUE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse_host: not found 'Host' in http header\n");

    url  = CHTTPS_NODE_URL(chttps_node);
    data = CBUFFER_DATA(url); 
 
    for(offset = CONST_STR_LEN("http://"); offset < CBUFFER_USED(url); offset ++)
    {
        if('/' == data [ offset ])
        {
            break;
        }
    }
 
    host_str = CBUFFER_DATA(url) + CONST_STR_LEN("http://");
    host_len = offset - CONST_STR_LEN("http://");

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse_host: fetch domain %.*s as 'Host' in http header\n", host_len, host_str);
 
    cbuffer_set(CHTTPS_NODE_HOST(chttps_node), host_str, host_len); 

    return (EC_TRUE);
}

EC_BOOL chttps_parse_content_length(CHTTPS_NODE *chttps_node)
{
    CSTRING       *content_length_cstr;
 
    content_length_cstr = cstrkv_mgr_get_val_cstr(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), "Content-Length");
    if(NULL_PTR == content_length_cstr)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse_content_length: not found 'Content-Length' in http header\n");
        CHTTPS_NODE_CONTENT_LENGTH(chttps_node) = 0;
        return (EC_TRUE);
    }
    CHTTPS_NODE_CONTENT_LENGTH(chttps_node) = c_chars_to_uint64_t((char *)cstring_get_str(content_length_cstr),
                                                                    (uint32_t)cstring_get_len(content_length_cstr));
    return (EC_TRUE);
}

EC_BOOL chttps_parse_connection_keepalive(CHTTPS_NODE *chttps_node)
{
    CSTRING       *connection_keepalive_cstr;
     
    connection_keepalive_cstr = cstrkv_mgr_get_val_cstr(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), "Connection");
    if(NULL_PTR == connection_keepalive_cstr)
    {
        connection_keepalive_cstr = cstrkv_mgr_get_val_cstr(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), "Proxy-Connection");
    }
 
    if(NULL_PTR == connection_keepalive_cstr)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse_connection_keepalive: no header 'Connection'\n"); 
        return (EC_TRUE);
    }
                     
    if(EC_TRUE == cstring_is_str_ignore_case(connection_keepalive_cstr, (const UINT8 *)"close"))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_parse_connection_keepalive: chttps_node %p -> csocket_cnode is null\n",
                            chttps_node);
            return (EC_FALSE);
        }
     
        CHTTPS_NODE_KEEPALIVE(chttps_node) = BIT_FALSE; /*force to disable keepalive*/
     
        if(EC_TRUE == csocket_disable_keepalive(CSOCKET_CNODE_SOCKFD(csocket_cnode)))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse_connection_keepalive: disable sockfd %d keepalive done\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
            return (EC_TRUE);     
        }
     
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                    "error:chttps_parse_connection_keepalive: disable chttps_node %p -> csocket_cnode %p -> sockfd %d keepalive failed, ignore that\n",
                    chttps_node, csocket_cnode, CSOCKET_CNODE_SOCKFD(csocket_cnode));
                 
        return (EC_TRUE);
    } 

    if(EC_TRUE == cstring_is_str_ignore_case(connection_keepalive_cstr, (const UINT8 *)"keepalive")
    || EC_TRUE == cstring_is_str_ignore_case(connection_keepalive_cstr, (const UINT8 *)"keep-alive"))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_parse_connection_keepalive: chttps_node %p -> csocket_cnode is null\n",
                            chttps_node);
            return (EC_FALSE);
        }

        /*force to enable keepalive due to csocket_enable_keepalive not adapative to unix domain socket*/
        CHTTPS_NODE_KEEPALIVE(chttps_node) = BIT_TRUE;

        if(BIT_FALSE == CSOCKET_CNODE_UNIX(csocket_cnode))
        {
            if(EC_TRUE == csocket_enable_keepalive(CSOCKET_CNODE_SOCKFD(csocket_cnode)))
            {
                dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse_connection_keepalive: enable sockfd %d keepalive done\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
                return (EC_TRUE);     
            }
         
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                        "error:chttps_parse_connection_keepalive: enable chttps_node %p -> csocket_cnode %p -> sockfd %d keepalive failed, ignore that\n",
                        chttps_node, csocket_cnode, CSOCKET_CNODE_SOCKFD(csocket_cnode));
            /*note: ingore that enable keepalive failure*/
        }
    }

    return (EC_TRUE);
}

EC_BOOL chttps_parse_uri(CHTTPS_NODE *chttps_node)
{
    CBUFFER       *url_cbuffer;
    CBUFFER       *host_cbuffer;
    CBUFFER       *uri_cbuffer;

    uint8_t       *uri_str; 
    uint32_t       uri_len;
    uint32_t       skip_len;
 
    url_cbuffer  = CHTTPS_NODE_URL(chttps_node);
    host_cbuffer = CHTTPS_NODE_HOST(chttps_node);
    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    if(EC_FALSE == cbuffer_cmp_bytes(url_cbuffer, 0, CONST_UINT8_STR_AND_LEN("http://")))
    {
        cbuffer_clone(url_cbuffer, uri_cbuffer);
        return (EC_TRUE);
    }

    skip_len = sizeof("http://") - 1 + CBUFFER_USED(host_cbuffer);
    uri_str  = CBUFFER_DATA(url_cbuffer) + skip_len;
    uri_len  = CBUFFER_USED(url_cbuffer) - skip_len;

    if(EC_FALSE == cbuffer_set(uri_cbuffer, uri_str, uri_len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_parse_uri: set uri %.*s failed\n", uri_len, uri_str);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_parse(CHTTPS_NODE *chttps_node)
{
    http_parser_t            *http_parser;
    http_parser_settings_t   *http_parser_setting;
    CBUFFER                  *http_in_buffer;

    CSOCKET_CNODE            *csocket_cnode;

    uint32_t parsed_len;
   
    http_parser         = CHTTPS_NODE_PARSER(chttps_node);
    http_parser_setting = CHTTPS_NODE_SETTING(chttps_node);
    http_in_buffer      = CHTTPS_NODE_IN_BUF(chttps_node);

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
 
    parsed_len = http_parser_execute(http_parser, http_parser_setting, (char *)CBUFFER_DATA(http_in_buffer) , CBUFFER_USED(http_in_buffer));
    if(HPE_OK != HTTP_PARSER_ERRNO(http_parser) && HPE_PAUSED != HTTP_PARSER_ERRNO(http_parser))/*check parser error*/
    {
        if(HPE_INVALID_URL == HTTP_PARSER_ERRNO(http_parser))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                            "error:chttps_parse: http parser encounter error on sockfd %d where errno = %d, name = %s, description = %s, [%.*s]\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            HTTP_PARSER_ERRNO(http_parser),
                            http_errno_name(HTTP_PARSER_ERRNO(http_parser)),
                            http_errno_description(HTTP_PARSER_ERRNO(http_parser)),
                            DMIN(CBUFFER_USED(http_in_buffer), 300), (char *)CBUFFER_DATA(http_in_buffer)
                            );
            return (EC_FALSE);                         
        }
     
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                            "error:chttps_parse: http parser encounter error on sockfd %d where errno = %d, name = %s, description = %s, [%.*s]\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            HTTP_PARSER_ERRNO(http_parser),
                            http_errno_name(HTTP_PARSER_ERRNO(http_parser)),
                            http_errno_description(HTTP_PARSER_ERRNO(http_parser)),
                            DMIN(CBUFFER_USED(http_in_buffer), 300), (char *)CBUFFER_DATA(http_in_buffer)
                            );
        return (EC_FALSE);
    }
         
    if(0 < parsed_len)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse: sockfd %d, header parsed %u,  body parsed %"PRId64", in buf %u => shift out %u\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode), CHTTPS_NODE_HEADER_PARSED_LEN(chttps_node), CHTTPS_NODE_BODY_PARSED_LEN(chttps_node), CBUFFER_USED(http_in_buffer), parsed_len);
 
        cbuffer_left_shift_out(http_in_buffer, NULL_PTR, parsed_len); 
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_parse: sockfd %d, http state %s, parsed_len %u\n",
            CSOCKET_CNODE_SOCKFD(csocket_cnode), http_state_str(http_parser->state), parsed_len);
         
    return (EC_TRUE);         
}

EC_BOOL chttps_pause_parser(http_parser_t* http_parser)
{
    if(NULL_PTR != http_parser)
    {
        http_parser_pause(http_parser, CHTTP_PASER_PAUSED);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL chttps_resume_parser(http_parser_t* http_parser)
{
    if(NULL_PTR != http_parser)
    {
        http_parser_pause(http_parser, CHTTP_PASER_RESUME);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


/*---------------------------------------- MAKE RESPONSE ----------------------------------------*/
EC_BOOL chttps_make_response_header_protocol(CHTTPS_NODE *chttps_node, const uint16_t major, const uint16_t minor, const uint32_t status)
{
    uint8_t  header_protocol[64];
    uint32_t len;
 
    len = snprintf(((char *)header_protocol), sizeof(header_protocol), "HTTP/%d.%d %d %s\r\n",
                   major, minor, status, chttp_status_str_get(status));
                
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), header_protocol, len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_protocol: append '%.*s' to chunks failed\n",
                           len, (char *)header_protocol);
        return (EC_FALSE);                         
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_keepalive(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CONST_UINT8_STR_AND_LEN("Connection:keep-alive\r\n")))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_keepalive: append 'Connection:keep-alive' to chunks failed\n");
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_date(CHTTPS_NODE *chttps_node)
{
    uint8_t  header_date[64];
    uint32_t len;
    ctime_t  time_in_sec;

    time_in_sec = task_brd_default_get_time();

    /*e.g., Date:Thu, 01 May 2014 12:12:16 GMT*/
    len = strftime(((char *)header_date), sizeof(header_date), "Date:%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&time_in_sec)); 
    //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_make_response_header_date: [%.*s] len = %u\n", len - 1, (char *)header_date, len - 1);
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), header_date, len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_date: append '%.*s' to chunks failed\n", len, header_date);
        return (EC_FALSE);
    }  
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_expires(CHTTPS_NODE *chttps_node)
{
    CBUFFER *expires;
 
    expires = CHTTPS_NODE_EXPIRES(chttps_node);
     
    if(0 < CBUFFER_USED(expires))
    {
        //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_make_response_header_expires: [%.*s] len = %u\n", CBUFFER_USED(expires), (char *)CBUFFER_DATA(expires), CBUFFER_USED(expires));
        if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CBUFFER_DATA(expires), CBUFFER_USED(expires)))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_expires: append '%.*s' to chunks failed\n",
                               CBUFFER_USED(expires), CBUFFER_DATA(expires));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_token(CHTTPS_NODE *chttps_node, const uint8_t *token, const uint32_t len)
{
    if(0 < len)
    {
        if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), token, len))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_token: append '%.*s' to chunks failed\n",
                               len, token);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_data(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t len)
{
    if(0 < len)
    {
        if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), data, len))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_data: append '%.*s' to chunks failed\n",
                               len, data);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_retire(CHTTPS_NODE *chttps_node, const uint8_t *retire_result, const uint32_t len)
{
    if(0 < len)
    {
        if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), retire_result, len))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_retire: append '%.*s' to chunks failed\n",
                               len, retire_result);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_recycle(CHTTPS_NODE *chttps_node, const uint8_t *recycle_result, const uint32_t len)
{
    if(0 < len)
    {
        if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), recycle_result, len))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_recycle: append '%.*s' to chunks failed\n",
                               len, recycle_result);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_elapsed(CHTTPS_NODE *chttps_node)
{
    uint8_t  header_date[128];
    uint32_t len;
    CTMV    *s_tmv;
    CTMV    *e_tmv;
 
    uint32_t elapsed_msec;

    if(SWITCH_ON == HIGH_PRECISION_TIME_SWITCH)
    {
        task_brd_update_time_default();
    }
    s_tmv = CHTTPS_NODE_START_TMV(chttps_node);
    e_tmv = task_brd_default_get_daytime();

    CHTTPS_ASSERT(CTMV_NSEC(e_tmv) >= CTMV_NSEC(s_tmv));
    elapsed_msec = (CTMV_NSEC(e_tmv) - CTMV_NSEC(s_tmv)) * 1000 + CTMV_MSEC(e_tmv) - CTMV_MSEC(s_tmv);

    len = 0;
    //len += snprintf(((char *)header_date) + len, sizeof(header_date) - len, "BegTime:%u.%03u\r\n", (uint32_t)CTMV_NSEC(s_tmv), (uint32_t)CTMV_MSEC(s_tmv));
    //len += snprintf(((char *)header_date) + len, sizeof(header_date) - len, "EndTime:%u.%03u\r\n", (uint32_t)CTMV_NSEC(e_tmv), (uint32_t)CTMV_MSEC(e_tmv));
    len += snprintf(((char *)header_date) + len, sizeof(header_date) - len, "Elapsed:%u micro seconds\r\n", elapsed_msec);

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), header_date, len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_elapsed: append '%.*s' to chunks failed\n", len, header_date);
        return (EC_FALSE);
    }  
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_content_type(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t size)
{
    if(NULL_PTR == data || 0 == size)
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CONST_UINT8_STR_AND_LEN("Content-Type:")))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_content_type: append 'Content-Type:' to chunks failed\n");
        return (EC_FALSE);
    } 

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), data, size))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_content_type: append %d bytes to chunks failed\n", size);
        return (EC_FALSE);
    }

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CONST_UINT8_STR_AND_LEN("\r\n")))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_content_type: append EOL to chunks failed\n");
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_content_length(CHTTPS_NODE *chttps_node, const uint64_t size)
{
    uint8_t  content_length[64];
    uint32_t len;

    len = snprintf(((char *)content_length), sizeof(content_length), "Content-Length:%"PRId64"\r\n", size);

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), content_length, len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_content_length: append '%.*s' to chunks failed\n",
                           len - 2, (char *)content_length);
        return (EC_FALSE);                         
    }
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_make_response_header_content_length: append '%.*s' to chunks done\n",
                       len - 2, (char *)content_length); 
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_kv(CHTTPS_NODE *chttps_node, const CSTRKV *cstrkv)
{
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CSTRKV_KEY_STR(cstrkv), (uint32_t)CSTRKV_KEY_LEN(cstrkv)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_kv: append key '%.*s' to chunks failed\n",
                    (uint32_t)CSTRKV_KEY_LEN(cstrkv), (char *)CSTRKV_KEY_STR(cstrkv));
        return (EC_FALSE);                         
    }

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CONST_UINT8_STR_AND_LEN(":")))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_kv: append '\r\n' to chunks failed\n");
        return (EC_FALSE);                         
    }
 
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CSTRKV_VAL_STR(cstrkv), (uint32_t)CSTRKV_VAL_LEN(cstrkv)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_kv: append val '%.*s' to chunks failed\n",
                    (uint32_t)CSTRKV_VAL_LEN(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
        return (EC_FALSE);                         
    }

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CONST_UINT8_STR_AND_LEN("\r\n")))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_kv: append '\r\n' to chunks failed\n");
        return (EC_FALSE);                         
    }

    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_kvs(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == cstrkv_mgr_walk(CHTTPS_NODE_HEADER_OUT_KVS(chttps_node), (void *)chttps_node, (CSTRKV_MGR_WALKER)chttps_make_response_header_kv))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_kvs: append kvs to chunks failed\n");
        return (EC_FALSE);                         
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_end(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CONST_UINT8_STR_AND_LEN("\r\n")))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_end: append '\r\n' to chunks failed\n");
        return (EC_FALSE);                         
    }
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_body(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t size)
{
    if(NULL_PTR == data || 0 == size)
    {
        return (EC_TRUE);
    }

    //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_make_response_body: body: '%.*s'\n", size, data);
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), data, size))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_body: append %d bytes to chunks failed\n", size);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

/*make response body without data copying but data transfering*/
EC_BOOL chttps_make_response_body_ext(CHTTPS_NODE *chttps_node, const uint8_t *data, const uint32_t size)
{
    if(NULL_PTR == data || 0 == size)
    {
        return (EC_TRUE);
    }
 
    if(EC_FALSE == chunk_mgr_mount_data(CHTTPS_NODE_SEND_BUF(chttps_node), data, size))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_body_ext: mount %d bytes to chunks failed\n", size);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_make_response_header_common(CHTTPS_NODE *chttps_node, const uint64_t body_len)
{
    if(EC_FALSE == chttps_make_response_header_protocol(chttps_node,
                                                          CHTTP_VERSION_MAJOR, CHTTP_VERSION_MINOR,
                                                          CHTTPS_NODE_RSP_STATUS(chttps_node)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_common: make header protocol failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_date(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_common: make header date failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_content_type(chttps_node, NULL_PTR, 0))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_common: make header content type failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_make_response_header_content_length(chttps_node, body_len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_response_header_common: make header content length failed\n");     
        return (EC_FALSE);
    }   

    return (EC_TRUE);
}

EC_BOOL chttps_make_error_response(CHTTPS_NODE *chttps_node)
{
    if(EC_FALSE == chttps_make_response_header_common(chttps_node, (uint64_t)0))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_error_response: make error response header failed\n");
     
        return (EC_FALSE);
    }

    /*note: not send keepalive header*/

    if(EC_FALSE == chttps_make_response_header_end(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_make_error_response: make header end failed\n");
        return (EC_FALSE);
    } 

    return (EC_TRUE);
}

/*---------------------------------------- HTTPS SERVER ----------------------------------------*/
CSRV * chttps_srv_start(const UINT32 srv_ipaddr, const UINT32 srv_port, const UINT32 md_id)
{
    CSRV      *csrv;
    CSSL_NODE *cssl_node;
    int        srv_sockfd;
    int        srv_unix_sockfd;
    char      *srv_certificate_file;
    char      *srv_private_file;
    char      *fields[ 2 ];

    if(EC_FALSE == csocket_listen(srv_ipaddr, srv_port, &srv_sockfd)) /* create server socket, bind & listen */
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDERR, "error:chttps_srv_start: failed to listen on port %s:%ld\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port);
        return (NULL_PTR);
    }

    srv_unix_sockfd = ERR_FD;
    csrv = csrv_new();
    if(NULL_PTR == csrv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_start: new csrv failed, close srv sockfd %d\n",
                        srv_sockfd);
        csocket_close(srv_sockfd);
        return (NULL_PTR);
    }

    cssl_node = cssl_node_new();
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_start: new cssl_node failed, close srv sockfd %d\n",
                        srv_sockfd);
        csocket_close(srv_sockfd);

        csrv_free(csrv);
        return (NULL_PTR);
    }
    CSSL_NODE_TYPE(cssl_node) = CSSL_NODE_SERVER_TYPE;

    if(EC_FALSE == cssl_node_create_ctx(cssl_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_start: create ctx failed, close srv sockfd %d\n",
                        srv_sockfd);
        csocket_close(srv_sockfd);
     
        cssl_node_free(cssl_node);

        csrv_free(csrv);
        return (NULL_PTR);
    }

    CSRV_IPADDR(csrv)               = srv_ipaddr;
    CSRV_PORT(csrv)                 = srv_port;
    CSRV_SOCKFD(csrv)               = srv_sockfd;
    CSRV_UNIX_SOCKFD(csrv)          = srv_unix_sockfd;
 
    CSRV_MD_ID(csrv)                = md_id;
    CSRV_CSSL_NODE(csrv)            = cssl_node;

    fields[ 0 ] = (char *)cstring_get_str(TASK_BRD_SSL_PATH(task_brd_default_get()));
 
    /*load certificate*/
    fields[ 1 ] = (char *)SSL_CERTIFICATE_FILE_NAME;
    if(NULL_PTR != fields[ 0 ] && '/' != c_str_last_char(fields[ 0 ]))
    {
        srv_certificate_file = c_str_join((const char *)"/", (const char **)fields, 2);
    }
    else
    {
        srv_certificate_file = c_str_cat(fields[ 0 ], fields[ 1 ]);
    }
    if(EC_FALSE == cssl_node_load_certificate(cssl_node, srv_certificate_file))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_start: load certificate from '%s' failed, close srv sockfd %d\n",
                        srv_certificate_file, srv_sockfd);
        csocket_close(srv_sockfd);
        csrv_free(csrv);
        return (NULL_PTR);
    }
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_srv_start: srv sockfd %d, load certificate from '%s' done\n",
                    srv_sockfd, srv_certificate_file);

    /*load private key*/
    fields[ 1 ] = (char *)SSL_PRIVATE_KEY_FILE_NAME;
    if(NULL_PTR != fields[ 0 ] && '/' != c_str_last_char(fields[ 0 ]))
    {
        srv_private_file = c_str_join((const char *)"/", (const char **)fields, 2);
    }
    else
    {
        srv_private_file = c_str_cat(fields[ 0 ], fields[ 1 ]);
    }
    if(EC_FALSE == cssl_node_load_private_key(cssl_node, srv_private_file))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_start: load private key from '%s' failed, close srv sockfd %d\n",
                        srv_private_file, srv_sockfd);
        csocket_close(srv_sockfd);
        csrv_free(csrv);
        return (NULL_PTR);
    }
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_srv_start: srv sockfd %d, load private key from '%s' done\n",
                        srv_sockfd, srv_private_file);

    /*check private key*/
    if(EC_FALSE == cssl_node_check_private_key(cssl_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_start: check private key of '%s' failed, close srv sockfd %d\n",
                        srv_private_file, srv_sockfd);
        csocket_close(srv_sockfd);
        csrv_free(csrv);
        return (NULL_PTR);
    } 
 
    cepoll_set_event(task_brd_default_get_cepoll(),
                      CSRV_SOCKFD(csrv),
                      CEPOLL_RD_EVENT,
                      (const char *)"chttps_srv_accept",
                      (CEPOLL_EVENT_HANDLER)chttps_srv_accept,
                      (void *)csrv);

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "[DEBUG] chttps_srv_start: start srv sockfd %d on %s:%ld\n",
                       srv_sockfd, c_word_to_ipv4(srv_ipaddr), srv_port);
    return (csrv);
}

EC_BOOL chttps_srv_end(CSRV *csrv)
{
    return csrv_free(csrv);
}

EC_BOOL chttps_srv_bind_modi(CSRV *csrv, const UINT32 modi)
{
    CSRV_MD_ID(csrv) = modi;

    return (EC_TRUE);
}

EC_BOOL chttps_srv_accept_once(CSRV *csrv, EC_BOOL *continue_flag)
{
    UINT32  client_ipaddr; 
    EC_BOOL ret;
    int     client_conn_sockfd; 

    ret = csocket_accept(CSRV_SOCKFD(csrv), &(client_conn_sockfd), CSOCKET_IS_NONBLOCK_MODE, &(client_ipaddr));
    if(EC_TRUE == ret)
    {
        CSOCKET_CNODE  *csocket_cnode;
        CHTTPS_NODE    *chttps_node;
     
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_srv_accept_once: handle new sockfd %d\n", client_conn_sockfd);

        csocket_cnode = csocket_cnode_new(CMPI_ERROR_TCID, client_conn_sockfd, CSOCKET_TYPE_TCP, client_ipaddr, CMPI_ERROR_SRVPORT);/*here do not know the remote client srv port*/
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_accept_once:failed to alloc csocket cnode for sockfd %d, hence close it\n", client_conn_sockfd);
            csocket_close(client_conn_sockfd);
            return (EC_FALSE);
        }

        chttps_node = chttps_node_new(CHTTP_TYPE_DO_SRV_REQ);
        if(NULL_PTR == chttps_node)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_accept_once: new chttps_node for sockfd %d failed\n", client_conn_sockfd);
            csocket_cnode_close(csocket_cnode);
            return (EC_FALSE);
        }
     
        CHTTPS_NODE_LOG_TIME_WHEN_START(chttps_node); /*record start time*/
     
        /*mount csrv*/
        CHTTPS_NODE_CSRV(chttps_node) = (void *)csrv;

        /*mount csocket_cnode*/
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = csocket_cnode;

        chttps_node_init_parser(chttps_node);
        
        if(SWITCH_ON == HIGH_PRECISION_TIME_SWITCH)
        {
            task_brd_update_time_default();
        }
        CTMV_CLONE(task_brd_default_get_daytime(), CHTTPS_NODE_START_TMV(chttps_node));     

        CSOCKET_CNODE_MODI(csocket_cnode) = CSRV_MD_ID(csrv);

        chttps_node_set_socket_callback(chttps_node, csocket_cnode);
        chttps_node_set_socket_epoll(chttps_node, csocket_cnode);

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_srv_accept_once: accept sockfd %d done\n", client_conn_sockfd);
    }

    (*continue_flag) = ret;
 
    return (EC_TRUE);
}

EC_BOOL chttps_srv_accept(CSRV *csrv)
{
    UINT32   idx;
    UINT32   num;
    EC_BOOL  continue_flag;

    num = CSRV_ACCEPT_MAX_NUM;
    for(idx = 0; idx < num; idx ++)
    {
        if(EC_FALSE == chttps_srv_accept_once(csrv, &continue_flag))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_accept: accept No. %ld client failed where expect %ld clients\n", idx, num);
            return (EC_FALSE);
        }

        if(EC_FALSE == continue_flag)
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_srv_accept: accept No. %ld client terminate where expect %ld clients\n", idx, num);
            break;
        }     
    }

    return (EC_TRUE);
}


/*---------------------------------------- COMMIT RESPONSE FOR EMITTING  ----------------------------------------*/
EC_BOOL chttps_commit_error_response(CHTTPS_NODE *chttps_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_commit_error_response: csocket_cnode of chttps_node %p is null\n", chttps_node);
        return (EC_FALSE);
    }
 
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    
    /*exception would be handled in cepoll*/
    if(EC_FALSE == cepoll_set_event(task_brd_default_get_cepoll(), 
                             CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                             CEPOLL_WR_EVENT,
                             (const char *)"csocket_cnode_isend",
                             (CEPOLL_EVENT_HANDLER)csocket_cnode_isend, 
                             csocket_cnode))
    {
        return (EC_FALSE);
    }
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
    return (EC_TRUE);
}

EC_BOOL chttps_commit_error_request(CHTTPS_NODE *chttps_node)
{ 
    /*cleanup request body and response body*/
    chttps_node_recv_clean(chttps_node);
    cbytes_clean(CHTTPS_NODE_CONTENT_CBYTES(chttps_node));

    if(EC_FALSE == chttps_make_error_response(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_commit_error_request: make error response failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_commit_error_response(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_commit_error_request: commit error response failed\n");
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

/*---------------------------------------- CONNECTION INIT and CLOSE HANDLER ----------------------------------------*/
EC_BOOL chttps_node_init_parser(CHTTPS_NODE *chttps_node)
{
    http_parser_t *http_parser;

    http_parser = CHTTPS_NODE_PARSER(chttps_node);
    http_parser->data = (void *)chttps_node;
    return (EC_TRUE);
}

EC_BOOL chttps_node_complete(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;

    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTPS_NODE_TYPE(chttps_node))/*on server side*/
    {
        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttps_node);

        /*keep-alive*/
        if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_complete: [server] keep-alive, resume socket %d\n", sockfd);

            /*resume*/
            //CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
            chttps_node_wait_resume(chttps_node);
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_complete: [server] keep-alive, resume socket %d done\n", sockfd);

            return (EC_TRUE);
        }

        /*no keep-alive*/

        /* unbind */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node)    = NULL_PTR;

        /*free*/
        chttps_node_free(chttps_node);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;/*trigger socket closing*/
        
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node))/*on client side*/
    {
        /* unbind */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node)    = NULL_PTR;

        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0009);
        }

        //CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; /*xxx*/
        return (EC_TRUE);
     
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))/*on client side*/
    {
        /*not unbind*/
     
        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0010);
        }
        
        //CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
        return (EC_TRUE);
    }
 
    /*should never reacher here!*/

    /* unbind */
    CHTTPS_NODE_CSOCKET_CNODE(chttps_node)    = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_complete:should never reach here, release chttps_node and try to close socket %d\n", sockfd);

    /*free*/
    chttps_node_free(chttps_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;    
    
    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; 

    return (EC_TRUE);
}

EC_BOOL chttps_node_close(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;
    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);
 
    if(CHTTP_TYPE_DO_SRV_REQ == CHTTPS_NODE_TYPE(chttps_node))/*on server side*/
    {
        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttps_node);

        if(BIT_TRUE == CHTTPS_NODE_KEEPALIVE(chttps_node))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_close: [server] keep-alive, resume socket %d\n", sockfd);

            /*resume*/
            CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
            chttps_node_wait_resume(chttps_node);
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_close: [server] keep-alive, resume socket %d done\n", sockfd);

            return (EC_TRUE);
        }

        /* unmount */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /*free*/
        chttps_node_free(chttps_node);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;/*trigger socket closing*/
        
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node))/*on client side*/
    {
        /* unmount */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending http request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0011);
        }

        return (EC_TRUE);
     
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))/*on client side*/
    {
        /*not unmount*/
     
        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending http request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0012);
        }

        return (EC_TRUE);
    }
 
    /*should never reacher here!*/

    /* unmount */
    CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_close:should never reach here, release chttps_node and try to close socket %d\n", sockfd);

    /*free*/
    chttps_node_free(chttps_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; 
    return (EC_TRUE);
}

EC_BOOL chttps_node_timeout(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;

    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTPS_NODE_TYPE(chttps_node)) /*server side*/
    {
        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttps_node);

        /* unbind */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /*free*/
        chttps_node_free(chttps_node);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; 
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node)) /*client side*/
    {
        /* unbind */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0013);
        }

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; /*xxx*/
        return (EC_TRUE);
     
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))/*client side*/
    {
        /*not unbind*/
     
        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0014);
        }

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE; 
        return (EC_TRUE);
    }
 
    /*should never reacher here!*/

    /* unbind */
    CHTTPS_NODE_CSOCKET_CNODE(chttps_node)    = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_force_close:should never reach here, release chttps_node and try to close socket %d\n", sockfd);

    /*free*/
    chttps_node_free(chttps_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; 
    return (EC_TRUE);
}

EC_BOOL chttps_node_shutdown(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;

    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTPS_NODE_TYPE(chttps_node)) /*server side*/
    {
        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttps_node);

        /* unbind */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /*free*/
        chttps_node_free(chttps_node);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; 
        
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node)) /*client side*/
    {
        /* unbind */
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0015);
        }

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; /*xxx*/
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))/*client side*/
    {
        /*not unbind*/
     
        /**
         * not free chttps_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTPS_NODE_CROUTINE_COND(chttps_node) && BIT_FALSE == CHTTPS_NODE_COROUTINE_RESTORE(chttps_node))
        {
            CHTTPS_NODE_COROUTINE_RESTORE(chttps_node) = BIT_TRUE;
            croutine_cond_release(CHTTPS_NODE_CROUTINE_COND(chttps_node), LOC_CHTTPS_0016);
        }

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE; 
        return (EC_TRUE);
    }
 
    /*should never reacher here!*/

    /* unbind */
    CHTTPS_NODE_CSOCKET_CNODE(chttps_node)    = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_force_close:should never reach here, release chttps_node and try to close socket %d\n", sockfd);

    /*free*/
    chttps_node_free(chttps_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; 
    return (EC_TRUE);
}

/*---------------------------------------- SEND AND RECV MANAGEMENT  ----------------------------------------*/
EC_BOOL chttps_node_recv_req(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    EC_BOOL       ret;

    if(0 == (CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE & CHTTPS_NODE_STATUS(chttps_node)))
    {
        /*skip*/
        return (EC_TRUE);
    }
    
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_req: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(BIT_TRUE == CSOCKET_CNODE_PENDING(csocket_cnode))
    {
        CSOCKET_CNODE_PENDING(csocket_cnode) = BIT_FALSE;
        CHTTPS_NODE_LOG_TIME_WHEN_START(chttps_node); /*record start time*/
    }

    ret = chttps_node_recv(chttps_node, csocket_cnode);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_req: recv req on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);                         
    }

    if(EC_DONE == ret)
    {
        if(BIT_FALSE == CHTTPS_NODE_RECV_COMPLETE(chttps_node))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_req: sockfd %d, recv not completed => false\n",
                                CSOCKET_CNODE_SOCKFD(csocket_cnode));
     
            return (EC_FALSE);
        }
     
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_req: sockfd %d, no more data to recv or parse\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

        /*note: for http request, recv done means the whole request ready, and MUST NOT close the connection. hence return true*/
        return (EC_TRUE);
    }

    if(EC_FALSE == chttps_parse(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_req: parse on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);                         
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_req: sockfd %d, recv and parse done\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return (EC_TRUE);
}

EC_BOOL chttps_node_send_rsp(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    if(0 == (CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE & CHTTPS_NODE_STATUS(chttps_node)))
    {
        /*skip*/
        return (EC_TRUE);
    } 
    
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send_rsp: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(0)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGUSER07, "[DEBUG] sockfd %d, to send len: %ld, uri: %.*s\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       chttps_node_send_len(chttps_node),
                       CBUFFER_USED(CHTTPS_NODE_URI(chttps_node)), (char *)CBUFFER_DATA(CHTTPS_NODE_URI(chttps_node))); 
    }

    if(EC_FALSE == chttps_node_send(chttps_node, csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send_rsp: sockfd %d send rsp failed\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(EC_TRUE == chttps_node_need_send(chttps_node))
    {
        /*wait for next writing*/

        /**********************************************************************************
        *   note:
        *       assume caller would set WR event when return EC_AGAIN.
        *       we cannot determine who will trigger send op:
        *         if cepoll trigger send op, WR event should not be set,
        *         if chttp trigger send op before WR event was set, chttp should set later
        *       thus, return EC_AGAIN is more safe.
        *
        ***********************************************************************************/
        return (EC_AGAIN);
    }

    CHTTPS_NODE_LOG_TIME_WHEN_END(chttps_node);
    CHTTPS_NODE_LOG_PRINT(chttps_node);
 
    /*now all data had been sent out, del WR event and set RD event*/
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_send_rsp: sockfd %d had sent out all rsp data\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));  

    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    return (EC_DONE);/*return EC_DONE will trigger CEPOLL cleanup*/
}

/*---------------------------------------- REQUEST REST LIST MANAGEMENT ----------------------------------------*/
CHTTPS_REST *chttps_rest_new()
{
    CHTTPS_REST *chttps_rest;
    alloc_static_mem(MM_CHTTPS_REST, &chttps_rest, LOC_CHTTPS_0017);
    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_rest_new: new chttps_rest failed\n");
        return (NULL_PTR);
    }
    chttps_rest_init(chttps_rest);
    return (chttps_rest);
}
EC_BOOL chttps_rest_init(CHTTPS_REST *chttps_rest)
{           
    CHTTPS_REST_NAME(chttps_rest)   = NULL_PTR;
    CHTTPS_REST_LEN(chttps_rest)    = 0;
    CHTTPS_REST_COMMIT(chttps_rest) = NULL_PTR;
 
    return (EC_TRUE);
}

EC_BOOL chttps_rest_clean(CHTTPS_REST *chttps_rest)
{
    CHTTPS_REST_NAME(chttps_rest)   = NULL_PTR;
    CHTTPS_REST_LEN(chttps_rest)    = 0;
    CHTTPS_REST_COMMIT(chttps_rest) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL chttps_rest_free(CHTTPS_REST *chttps_rest)
{
    if(NULL_PTR != chttps_rest)
    {
        chttps_rest_clean(chttps_rest);
        free_static_mem(MM_CHTTPS_REST, chttps_rest, LOC_CHTTPS_0018);
    }
 
    return (EC_TRUE);
}

void chttps_rest_print(LOG *log, const CHTTPS_REST *chttps_rest)
{
    sys_log(log, "chttps_rest_print: chttps_rest: %p, name '%s', commit %p\n", 
                 chttps_rest, 
                 CHTTPS_REST_NAME(chttps_rest), 
                 CHTTPS_REST_COMMIT(chttps_rest));

    return;
}

EC_BOOL chttps_rest_cmp(const CHTTPS_REST *chttps_rest_1st, const CHTTPS_REST *chttps_rest_2nd)
{
    if(CHTTPS_REST_LEN(chttps_rest_1st) != CHTTPS_REST_LEN(chttps_rest_2nd))
    {
        return (EC_FALSE);
    }

    if(0 != STRNCASECMP(CHTTP_REST_NAME(chttps_rest_1st), CHTTP_REST_NAME(chttps_rest_2nd), CHTTP_REST_LEN(chttps_rest_1st)))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_rest_list_push(const char *name, EC_BOOL (*commit)(CHTTPS_NODE *))
{
    CHTTPS_REST *chttps_rest;
    CHTTPS_REST *chttps_rest_t;

    if(NULL_PTR == g_chttps_rest_list)
    {
        g_chttps_rest_list = clist_new(MM_CHTTPS_REST, LOC_CHTTPS_0019);
        if(NULL_PTR == g_chttps_rest_list)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_rest_list_push: new rest list failed\n");
            return (NULL_PTR);        
        }
    }

    chttps_rest = chttps_rest_new();
    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_rest_list_push: new chttps_rest failed\n");
        return (NULL_PTR);
    }

    CHTTPS_REST_NAME(chttps_rest)   = name;
    CHTTPS_REST_LEN(chttps_rest)    = strlen(name);
    CHTTPS_REST_COMMIT(chttps_rest) = commit;

    chttps_rest_t = (CHTTPS_REST *)clist_search_data_back(g_chttps_rest_list, (void *)chttps_rest, 
                                                    (CLIST_DATA_DATA_CMP)chttps_rest_cmp);
    if(NULL_PTR != chttps_rest_t)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_push: already exist rest %p ('%.*s', %p)\n",
                    chttps_rest_t,
                    CHTTPS_REST_LEN(chttps_rest), CHTTPS_REST_NAME(chttps_rest), 
                    CHTTPS_REST_COMMIT(chttps_rest));
        chttps_rest_free(chttps_rest);            
        return (EC_TRUE);
    }
    
    clist_push_back(g_chttps_rest_list, (void *)chttps_rest);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_push: push rest %p ('%s', %p) done\n",
                    chttps_rest, name, commit);
        
    return (EC_TRUE);
}

CHTTPS_REST *chttps_rest_list_pop(const char *name, const uint32_t len)
{
    CHTTPS_REST   chttps_rest_t;
    CHTTPS_REST  *chttps_rest;
    
    if(NULL_PTR == g_chttps_rest_list)
    {
        dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "warn:chttps_rest_list_pop: rest list is null\n");
        return (NULL_PTR);
    }

    CHTTPS_REST_NAME(&chttps_rest_t)   = name;
    CHTTPS_REST_LEN(&chttps_rest_t)    = len;
    CHTTPS_REST_COMMIT(&chttps_rest_t) = NULL_PTR;    

    chttps_rest = (CHTTPS_REST *)clist_del(g_chttps_rest_list, (void *)&chttps_rest_t, 
                                            (CLIST_DATA_DATA_CMP)chttps_rest_cmp);

    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_pop: not found rest of '%.*s'\n",
                    len, name);
        return (NULL_PTR);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_pop: found rest %p of ('%.*s', %p)\n",
                    chttps_rest,
                    CHTTPS_REST_LEN(chttps_rest), CHTTPS_REST_NAME(chttps_rest), 
                    CHTTPS_REST_COMMIT(chttps_rest));

    return (chttps_rest);
}

CHTTPS_REST *chttps_rest_list_find(const char *name, const uint32_t len)
{
    CHTTPS_REST   chttps_rest_t;
    CHTTPS_REST  *chttps_rest;
    
    if(NULL_PTR == g_chttps_rest_list)
    {
        dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "warn:chttps_rest_list_find: rest list is null\n");
        return (NULL_PTR);
    }

    CHTTPS_REST_NAME(&chttps_rest_t)   = name;
    CHTTPS_REST_LEN(&chttps_rest_t)    = len;
    CHTTPS_REST_COMMIT(&chttps_rest_t) = NULL_PTR;    

    chttps_rest = (CHTTPS_REST *)clist_search_data_back(g_chttps_rest_list, (void *)&chttps_rest_t, 
                                                        (CLIST_DATA_DATA_CMP)chttps_rest_cmp);

    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_find: not found rest of '%.*s'\n",
                    len, name);
        return (NULL_PTR);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_find: found rest %p of ('%.*s', %p)\n",
                    chttps_rest,
                    CHTTPS_REST_LEN(chttps_rest),CHTTPS_REST_NAME(chttps_rest), 
                    CHTTPS_REST_COMMIT(chttps_rest));

    return (chttps_rest);
}


/*---------------------------------------- REQUEST DEFER QUEUE MANAGEMENT ----------------------------------------*/
EC_BOOL chttps_defer_request_queue_init()
{
    if(EC_FALSE == g_chttps_defer_request_queue_init_flag)
    {
        cqueue_init(&g_chttps_defer_request_queue, MM_CHTTPS_NODE, LOC_CHTTPS_0020);

        if(EC_FALSE == cepoll_set_loop_handler(task_brd_default_get_cepoll(),
                                                (const char *)"chttps_defer_request_queue_launch",
                                               (CEPOLL_LOOP_HANDLER)chttps_defer_request_queue_launch,
                                               chttps_defer_request_commit))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttp_defer_request_queue_init: set cepoll loop handler failed\n");
            return (EC_FALSE);
        }
    }

    g_chttps_defer_request_queue_init_flag = EC_TRUE;
    return (EC_TRUE);
}

EC_BOOL chttps_defer_request_queue_clean()
{
    cqueue_clean(&g_chttps_defer_request_queue, (CQUEUE_DATA_DATA_CLEANER)chttps_node_free);
    return (EC_TRUE);
}

/**
*
* WARNING:
*
*   chttps_defer_request_queue_init is called in RFS module,
*   but chttps_defer_request_queue_is_empty is checked in task_brd_need_slow_down
*   where maybe chttps_defer_request_queue_init is not called or never be called!
*
*   Thus, one cannot call cqueue_is_empty is check whether g_chttps_defer_request_queue
*   is empty or not.
*
**/
EC_BOOL chttps_defer_request_queue_is_empty()
{
    if(EC_FALSE == g_chttps_defer_request_queue_init_flag)
    {
        return (EC_TRUE);
    }
    return cqueue_is_empty(&g_chttps_defer_request_queue);
}

EC_BOOL chttps_defer_request_queue_push(CHTTPS_NODE *chttps_node)
{
    CQUEUE_DATA *cqueue_data;

    cqueue_data = cqueue_push(&g_chttps_defer_request_queue, (void *)chttps_node);
    CHTTPS_NODE_CQUEUE_DATA(chttps_node) = cqueue_data;
    return (EC_TRUE);
}

EC_BOOL chttps_defer_request_queue_erase(CHTTPS_NODE *chttps_node)
{
    CQUEUE_DATA *cqueue_data;
 
    cqueue_data = CHTTPS_NODE_CQUEUE_DATA(chttps_node);
    if(NULL_PTR != cqueue_data)
    {
        cqueue_erase(&g_chttps_defer_request_queue, cqueue_data);
        CHTTPS_NODE_CQUEUE_DATA(chttps_node) = NULL_PTR;
    }
    return (EC_TRUE);
}

CHTTPS_NODE *chttps_defer_request_queue_pop()
{
    CHTTPS_NODE *chttps_node;

    chttps_node = (CHTTPS_NODE *)cqueue_pop(&g_chttps_defer_request_queue);
    CHTTPS_NODE_CQUEUE_DATA(chttps_node) = NULL_PTR;
    return (chttps_node);
}

CHTTPS_NODE *chttps_defer_request_queue_peek()
{
    return (CHTTPS_NODE *)cqueue_front(&g_chttps_defer_request_queue);
}

EC_BOOL chttps_defer_request_commit(CHTTPS_NODE *chttps_node)
{
    const CBUFFER *uri_cbuffer;
    CHTTPS_REST    *chttps_rest;
    const char    *rest_name;
    uint32_t       rest_len;
 
    uri_cbuffer  = CHTTPS_NODE_URI(chttps_node);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_defer_request_commit: uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    rest_name = (char *)CBUFFER_DATA(uri_cbuffer);
    if('/' != rest_name[ 0 ])
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_defer_request_commit: invalid url '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));
        return (EC_FALSE);                    
    }    
    
    for(rest_len = 1; rest_len < CBUFFER_USED(uri_cbuffer); rest_len ++)
    {
        if('/' == rest_name[ rest_len ])
        {
            break;
        }
    }

    if('/' != rest_name[ rest_len ])
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_defer_request_commit: invalid rest '%.*s' [len %d]\n",
                            rest_len, rest_name, rest_len);
        return (EC_FALSE);                    
    }

    chttps_rest = chttps_rest_list_find(rest_name, rest_len);
    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_defer_request_commit: not support rest '%.*s' [len %d]\n",
                            rest_len, rest_name, rest_len);
        return (EC_FALSE);                    
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_defer_request_commit: found rest %p of ('%.*s', %p)\n",
                    chttps_rest,
                    CHTTPS_REST_LEN(chttps_rest),CHTTPS_REST_NAME(chttps_rest), 
                    CHTTPS_REST_COMMIT(chttps_rest));
                    
    return CHTTPS_REST_COMMIT(chttps_rest)(chttps_node);
}

EC_BOOL chttps_defer_request_queue_launch(CHTTPS_NODE_COMMIT_REQUEST chttps_node_commit_request)
{
    CHTTPS_NODE *chttps_node;
    uint32_t    http_req_max_num; /*max http requests could be handled in one loop. 0 means handle all*/
    uint32_t    http_req_idx;

    if(SWITCH_ON == NGX_BGN_SWITCH)
    {
        http_req_max_num = NGX_HTTP_REQ_NUM_PER_LOOP;
    }
    else
    {
        http_req_max_num = RFS_HTTP_REQ_NUM_PER_LOOP;
    }

    if(0 == http_req_max_num)
    {
        http_req_max_num = (uint32_t)~0; /*max uint32_t value*/
    }

    /*
    * note: loop_switch control the loop times:
    *       for NGX BGN (SWITCH_ON == NGX_BGN_SWITCH), handle all http requests in one loop
    *       for RFS (SWITCH_OFF == NGX_BGN_SWITCH), handle one http request only in one loop
    */
    for(http_req_idx = 0; http_req_idx < http_req_max_num; http_req_idx ++)
    {
        EC_BOOL ret;
     
        chttps_node = chttps_defer_request_queue_peek();
        if(NULL_PTR == chttps_node)/*no more*/
        {
            break;
        }

        ret = chttps_defer_request_commit(chttps_node);
        
        /*ret = chttps_node_commit_request(chttps_node);*//*call back*/
        if(EC_BUSY == ret)/*okay, no routine resource to load this task, terminate and wait for next time try*/
        {
            break;
        }

        /*pop it when everything ok or some unknown scenario happen*/
        chttps_defer_request_queue_pop();

        if(EC_FALSE == ret)/*Oops! found unknown request, dicard it now*/
        {
            if(NULL_PTR != CHTTPS_NODE_CSOCKET_CNODE(chttps_node))
            {
                CSOCKET_CNODE *csocket_cnode;
                int            sockfd;
                
                csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
                sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);/*csocket_cnode will be cleanup, save sockfd at first*/

                CHTTPS_NODE_KEEPALIVE(chttps_node) = BIT_FALSE; /*force to close the httpss connection*/

                chttps_node_disconnect(chttps_node);

                cepoll_clear_node(task_brd_default_get_cepoll(), sockfd);                
            }

            chttps_node_free(chttps_node);
        }

        /*handle next request*/
    }
    return (EC_TRUE);
}


/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Send Http Request and Handle Http Response
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_node_encode_req_const_str(CHTTPS_NODE *chttps_node, const uint8_t *str, const UINT32 len)
{
    return chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), str, len);
}

EC_BOOL chttps_node_encode_req_protocol(CHTTPS_NODE *chttps_node, const uint16_t version_major, const uint16_t version_minor)
{
    char protocol[16];
    UINT32 len;

    len = snprintf(protocol, sizeof(protocol)/sizeof(protocol[0]), "HTTP/%d.%d", version_major, version_minor);
    return chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)protocol, len);
}

EC_BOOL chttps_node_encode_req_method(CHTTPS_NODE *chttps_node, const CSTRING *method)
{
    return chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), cstring_get_str(method), cstring_get_len(method));
}

EC_BOOL chttps_node_encode_req_header_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv)
{
    const CSTRING *key;
    const CSTRING *val;

    key = CSTRKV_KEY(kv);
    val = CSTRKV_VAL(kv);
 
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), cstring_get_str(key), cstring_get_len(key)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_kv: encode key of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)":",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_kv: encode seperator of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), cstring_get_str(val), cstring_get_len(val)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_kv: encode val of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)"\r\n",  2))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_kv: encode EOF failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_req_param_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv)
{
    const CSTRING *key;
    const CSTRING *val;

    key = CSTRKV_KEY(kv);
    val = CSTRKV_VAL(kv);

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)"&",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_param_kv: encode prefix of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), cstring_get_str(key), cstring_get_len(key)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_param_kv: encode key of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)"=",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_param_kv: encode seperator of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), cstring_get_str(val), cstring_get_len(val)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_param_kv: encode val of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_req_param(CHTTPS_NODE *chttps_node, const CSTRKV_MGR *param)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(param), clist_data)
    {
        CSTRKV *kv;
     
        kv = (CSTRKV *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == chttps_node_encode_req_param_kv(chttps_node, kv))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_param: encode kv failed\n");
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_req_uri(CHTTPS_NODE *chttps_node , const CSTRING *uri, const CSTRKV_MGR *param)
{
    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), cstring_get_str(uri), cstring_get_len(uri)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_uri: encode uri '%s' failed\n",
                                               cstring_get_str(uri));
        return (EC_FALSE);
    }
 
    if(NULL_PTR != param)
    {
        if(EC_FALSE == chttps_node_encode_req_param(chttps_node, param))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_uri: encode param failed\n");
            return (EC_FALSE);
        }
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_req_header_line(CHTTPS_NODE *chttps_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param,
                                            const uint16_t version_major, const uint16_t version_minor)
{
    if(EC_FALSE == chttps_node_encode_req_method(chttps_node, method))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_line: encode method '%s' failed\n",
                                              cstring_get_str(method));
        return (EC_FALSE);
    }

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)" ",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_uri: encode prefix space failed\n");
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_encode_req_uri(chttps_node, uri, param))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_line: encode uri failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)" ",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_uri: encode prefix space failed\n");
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_encode_req_protocol(chttps_node, CHTTP_VERSION_MAJOR, CHTTP_VERSION_MINOR))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_line: encode protocol failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)"\r\n",  2))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header_line: encode EOF failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_req_header_end(CHTTPS_NODE *chttps_node)
{
    return chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), (uint8_t *)"\r\n",  2);
}

EC_BOOL chttps_node_encode_req_header(CHTTPS_NODE *chttps_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param, const CSTRKV_MGR *header)
{
    CLIST_DATA *clist_data;

    if(EC_FALSE == chttps_node_encode_req_header_line(chttps_node, method, uri, param, CHTTP_VERSION_MAJOR, CHTTP_VERSION_MINOR))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header: encode header line failed\n");
        return (EC_FALSE);
    }

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(header), clist_data)
    {
        CSTRKV *kv;
     
        kv = (CSTRKV *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == chttps_node_encode_req_header_kv(chttps_node, kv))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header: encode kv failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_node_encode_req_header_end(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_req_header: encode header EOF failed\n");
        return (EC_FALSE);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_node_encode_req_header: encoded header is \n");
        chunk_mgr_print_str(LOGSTDOUT, CHTTPS_NODE_SEND_BUF(chttps_node));
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_req_body(CHTTPS_NODE *chttps_node, const CBYTES *req_body)
{
    return chunk_mgr_append_data(CHTTPS_NODE_SEND_BUF(chttps_node), CBYTES_BUF(req_body),  CBYTES_LEN(req_body));
}

EC_BOOL chttps_node_encode_rsp_const_str(CHTTPS_NODE *chttps_node, const uint8_t *str, const UINT32 len, CBYTES *cbytes)
{
    return cbytes_append(cbytes, str, len);
}

EC_BOOL chttps_node_encode_rsp_protocol(CHTTPS_NODE *chttps_node, const uint16_t version_major, const uint16_t version_minor, CBYTES *cbytes)
{
    char protocol[16];
    UINT32 len;

    len = snprintf(protocol, sizeof(protocol)/sizeof(protocol[0]), "HTTP/%d.%d", version_major, version_minor);
    return cbytes_append(cbytes, (uint8_t *)protocol, len);
}

EC_BOOL chttps_node_encode_rsp_method(CHTTPS_NODE *chttps_node, const CSTRING *method, CBYTES *cbytes)
{
    return cbytes_append(cbytes, cstring_get_str(method), cstring_get_len(method));
}

EC_BOOL chttps_node_encode_rsp_status(CHTTPS_NODE *chttps_node, const uint32_t status_code, CBYTES *cbytes)
{
    char status_str[32];
    uint32_t len;

    len = snprintf(status_str, sizeof(status_str)/sizeof(status_str[0]), "Response-Status:%u\r\n", status_code);
 
    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)status_str, len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_kv: encode '%s' failed\n", status_str);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp_header_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv, CBYTES *cbytes)
{
    const CSTRING *key;
    const CSTRING *val;

    key = CSTRKV_KEY(kv);
    val = CSTRKV_VAL(kv);
 
    if(EC_FALSE == cbytes_append(cbytes, cstring_get_str(key), cstring_get_len(key)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_kv: encode key of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)":",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_kv: encode seperator of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == cbytes_append(cbytes, cstring_get_str(val), cstring_get_len(val)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_kv: encode val of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)"\r\n",  2))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_kv: encode EOF failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp_param_kv(CHTTPS_NODE *chttps_node, const CSTRKV *kv, CBYTES *cbytes)
{
    const CSTRING *key;
    const CSTRING *val;

    key = CSTRKV_KEY(kv);
    val = CSTRKV_VAL(kv);

    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)"&",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_param_kv: encode prefix of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == cbytes_append(cbytes, cstring_get_str(key), cstring_get_len(key)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_param_kv: encode key of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)"=",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_param_kv: encode seperator of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    if(EC_FALSE == cbytes_append(cbytes, cstring_get_str(val), cstring_get_len(val)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_param_kv: encode val of ('%s', '%s') failed\n",
                            cstring_get_str(key), cstring_get_str(val));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp_param(CHTTPS_NODE *chttps_node, const CSTRKV_MGR *param, CBYTES *cbytes)
{
    CLIST_DATA *clist_data;

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(param), clist_data)
    {
        CSTRKV *kv;
     
        kv = (CSTRKV *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == chttps_node_encode_rsp_param_kv(chttps_node, kv, cbytes))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_param: encode kv failed\n");
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp_uri(CHTTPS_NODE *chttps_node , const CSTRING *uri, const CSTRKV_MGR *param, CBYTES *cbytes)
{
    if(EC_FALSE == cbytes_append(cbytes, cstring_get_str(uri), cstring_get_len(uri)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_uri: encode uri '%s' failed\n",
                                               cstring_get_str(uri));
        return (EC_FALSE);
    }
 
    if(NULL_PTR != param)
    {
        if(EC_FALSE == chttps_node_encode_rsp_param(chttps_node, param, cbytes))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_uri: encode param failed\n");
            return (EC_FALSE);
        }
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp_header_line(CHTTPS_NODE *chttps_node, const CSTRING *method, const CSTRING *uri, const CSTRKV_MGR *param,
                                            const uint16_t version_major, const uint16_t version_minor, CBYTES *cbytes)
{
    if(EC_FALSE == chttps_node_encode_rsp_method(chttps_node, method, cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_line: encode method '%s' failed\n",
                                              cstring_get_str(method));
        return (EC_FALSE);
    }

    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)" ",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_uri: encode prefix space failed\n");
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_encode_rsp_uri(chttps_node, uri, param, cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_line: encode uri failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)" ",  1))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_uri: encode prefix space failed\n");
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_encode_rsp_protocol(chttps_node, CHTTP_VERSION_MAJOR, CHTTP_VERSION_MINOR, cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_line: encode protocol failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cbytes_append(cbytes, (uint8_t *)"\r\n",  2))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header_line: encode EOF failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp_header_end(CHTTPS_NODE *chttps_node, CBYTES *cbytes)
{
    return cbytes_append(cbytes, (uint8_t *)"\r\n",  2);
}

EC_BOOL chttps_node_encode_rsp_header(CHTTPS_NODE *chttps_node, const UINT32 status_code, const CSTRKV_MGR *header, CBYTES *cbytes)
{
    CLIST_DATA *clist_data;
#if 0
    if(EC_FALSE == chttps_node_encode_rsp_header_line(chttps_node, method, uri, param, CHTTP_VERSION_MAJOR, CHTTP_VERSION_MINOR, cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header: encode header line failed\n");
        return (EC_FALSE);
    }
#endif 

    if(EC_FALSE == chttps_node_encode_rsp_status(chttps_node, (uint32_t)status_code, cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header: encode status code failed\n");
        return (EC_FALSE);
    }

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(header), clist_data)
    {
        CSTRKV *kv;
     
        kv = (CSTRKV *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == chttps_node_encode_rsp_header_kv(chttps_node, kv, cbytes))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header: encode kv failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == chttps_node_encode_rsp_header_end(chttps_node, cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_header: encode header EOF failed\n");
        return (EC_FALSE);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_node_encode_rsp_header: encoded header is \n");
        cbytes_print_str(LOGSTDOUT, cbytes);
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp_body(CHTTPS_NODE *chttps_node, CBYTES *cbytes)
{
    CHUNK_MGR     *recv_chunks;
    uint64_t       body_len;

    recv_chunks = CHTTPS_NODE_RECV_BUF(chttps_node);
    body_len    = chunk_mgr_total_length(recv_chunks);
    if(0 < body_len)
    {
        UINT32         len;
        UINT32         size;
 
        len  = CBYTES_LEN(cbytes);
        size = len + (UINT32)body_len;

        if(EC_FALSE == cbytes_expand_to(cbytes, size))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_body: cbytes expand to size %ld failed\n", size);
            return (EC_FALSE);
        }

        if(EC_FALSE == chunk_mgr_export(recv_chunks, CBYTES_BUF(cbytes) + len , CBYTES_LEN(cbytes), NULL_PTR))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp_body: export recv chunks failed\n", size);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_encode_rsp(CHTTPS_NODE *chttps_node, CBYTES *cbytes)
{
    if(EC_FALSE == chttps_node_encode_rsp_header(chttps_node, CHTTPS_NODE_STATUS_CODE(chttps_node), CHTTPS_NODE_HEADER_IN_KVS(chttps_node), cbytes)
     )
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp: encode header failed\n");
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_encode_rsp_body(chttps_node, cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_encode_rsp: encode body failed\n");
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL chttps_node_set_socket_callback(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    if(CHTTP_TYPE_DO_SRV_REQ == CHTTPS_NODE_TYPE(chttps_node))
    {
        csocket_cnode_push_recv_callback(csocket_cnode, 
                                         (const char *)"chttps_node_handshake_on_server", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_handshake_on_server);

        csocket_cnode_push_recv_callback(csocket_cnode, 
                                         (const char *)"chttps_node_recv_req", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_recv_req);
                                         
        csocket_cnode_push_send_callback(csocket_cnode, 
                                         (const char *)"chttps_node_handshake_on_client", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_send_callback(csocket_cnode, 
                                         (const char *)"chttps_node_send_rsp", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_send_rsp);

        csocket_cnode_push_complete_callback(csocket_cnode, 
                                         (const char *)"chttps_node_complete", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_complete);
                                         
        csocket_cnode_push_close_callback(csocket_cnode, 
                                         (const char *)"chttps_node_close", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_close);

        csocket_cnode_push_timeout_callback(csocket_cnode, 
                                         (const char *)"chttps_node_timeout", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_timeout);

        csocket_cnode_push_shutdown_callback(csocket_cnode, 
                                         (const char *)"chttps_node_shutdown", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_shutdown);     
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node))
    {
        csocket_cnode_push_recv_callback(csocket_cnode, 
                                         (const char *)"chttps_node_handshake_on_client", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_recv_callback(csocket_cnode, 
                                         (const char *)"chttps_node_recv_rsp", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_recv_rsp);
                                         
        csocket_cnode_push_send_callback(csocket_cnode, 
                                         (const char *)"chttps_node_handshake_on_client", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_send_callback(csocket_cnode, 
                                         (const char *)"chttps_node_send_req", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_send_req);
                                         
        csocket_cnode_push_close_callback(csocket_cnode, 
                                         (const char *)"chttps_node_close", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_close);

        csocket_cnode_push_timeout_callback(csocket_cnode, 
                                         (const char *)"chttps_node_timeout", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_timeout);

        csocket_cnode_push_shutdown_callback(csocket_cnode, 
                                         (const char *)"chttps_node_shutdown", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_shutdown);     
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))
    {
#if 0    
        csocket_cnode_push_recv_callback(csocket_cnode, 
                                         (const char *)"chttps_node_handshake_on_client", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_recv_callback(csocket_cnode, 
                                         (const char *)"chttps_node_recv_rsp", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_recv_rsp);
#endif                                         
        csocket_cnode_push_send_callback(csocket_cnode, 
                                         (const char *)"chttps_node_handshake_on_client", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_send_callback(csocket_cnode, 
                                         (const char *)"chttps_node_icheck", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_icheck);
                                         
        csocket_cnode_push_close_callback(csocket_cnode, 
                                         (const char *)"chttps_node_close", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_close);

        csocket_cnode_push_timeout_callback(csocket_cnode, 
                                         (const char *)"chttps_node_timeout", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_timeout);

        csocket_cnode_push_shutdown_callback(csocket_cnode, 
                                         (const char *)"chttps_node_shutdown", 
                                         (UINT32)chttps_node, (UINT32)chttps_node_shutdown);     
        return (EC_TRUE);
    }    

    return (EC_FALSE);
}

EC_BOOL chttps_node_set_socket_epoll(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    if(CHTTP_TYPE_DO_SRV_REQ == CHTTPS_NODE_TYPE(chttps_node))
    {
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_RD_EVENT,
                        (const char *)"csocket_cnode_irecv",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                        (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
        
        cepoll_set_complete(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        (const char *)"csocket_cnode_icomplete",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_icomplete,
                        (void *)csocket_cnode);

        cepoll_set_shutdown(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        (const char *)"csocket_cnode_ishutdown",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_ishutdown,
                        (void *)csocket_cnode);

        cepoll_set_timeout(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        (uint32_t)CONN_TIMEOUT_NSEC,
                        (const char *)"csocket_cnode_itimeout",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                        (void *)csocket_cnode);    
                        
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTPS_NODE_TYPE(chttps_node))
    {
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_WR_EVENT,
                        (const char *)"csocket_cnode_isend",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                        (void *)csocket_cnode);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
        cepoll_set_complete(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        (const char *)"csocket_cnode_iclose",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_iclose,
                        (void *)csocket_cnode);

        cepoll_set_shutdown(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        (const char *)"csocket_cnode_ishutdown",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_ishutdown,
                        (void *)csocket_cnode);

        cepoll_set_timeout(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        (uint32_t)CONN_TIMEOUT_NSEC,
                        (const char *)"csocket_cnode_itimeout",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                        (void *)csocket_cnode);    
                        
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTPS_NODE_TYPE(chttps_node))
    {
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_WR_EVENT,
                        (const char *)"csocket_cnode_isend",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                        (void *)csocket_cnode);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
        cepoll_set_complete(task_brd_default_get_cepoll(),
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       (const char *)"csocket_cnode_iclose",
                       (CEPOLL_EVENT_HANDLER)csocket_cnode_iclose,
                       (void *)csocket_cnode);
                        
        cepoll_set_shutdown(task_brd_default_get_cepoll(),
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       (const char *)"csocket_cnode_ishutdown",
                       (CEPOLL_EVENT_HANDLER)csocket_cnode_ishutdown,
                       (void *)csocket_cnode);

        cepoll_set_timeout(task_brd_default_get_cepoll(),
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       (uint32_t)CONN_TIMEOUT_NSEC,
                       (const char *)"csocket_cnode_itimeout",
                       (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                       (void *)csocket_cnode);    
        return (EC_TRUE);
    }    

    return (EC_FALSE);
}

EC_BOOL chttps_node_connect(CHTTPS_NODE *chttps_node, const UINT32 ipaddr, const UINT32 port)
{
    CSOCKET_CNODE *csocket_cnode;

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_connect: connect server %s:%ld >>>\n",
                        c_word_to_ipv4(ipaddr), port); 

    csocket_cnode = cconnp_mgr_reserve(task_brd_default_get_http_cconnp_mgr(), CMPI_ANY_TCID, ipaddr, port);
    if(NULL_PTR != csocket_cnode)
    {
        /*optimize for the latest loaed config*/
        csocket_optimize(CSOCKET_CNODE_SOCKFD(csocket_cnode));
    }
    else
    {
        int sockfd;
     
        if(EC_FALSE == csocket_connect( ipaddr, port , CSOCKET_IS_NONBLOCK_MODE, &sockfd ))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_connect: connect server %s:%ld failed\n",
                                c_word_to_ipv4(ipaddr), port);
            return (EC_FALSE);
        }

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_connect: socket %d connecting to server %s:%ld\n",
                            sockfd, c_word_to_ipv4(ipaddr), port);

        if(EC_FALSE == csocket_is_connected(sockfd))/*not adaptive to unix domain socket*/
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_connect: socket %d to server %s:%ld is not connected\n",
                            sockfd, c_word_to_ipv4(ipaddr), port);
            csocket_close(sockfd);
            return (EC_FALSE);
        }

        if(do_log(SEC_0157_CHTTPS, 5))
        {
            sys_log(LOGSTDOUT, "[DEBUG] chttps_connect: client tcp stat:\n");
            csocket_tcpi_stat_print(LOGSTDOUT, sockfd);
        }

        csocket_cnode = csocket_cnode_new(CMPI_ERROR_TCID, sockfd, CSOCKET_TYPE_TCP, ipaddr, port);
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_connect:new csocket cnode for socket %d to server %s:%ld failed\n",
                            sockfd, c_word_to_ipv4(ipaddr), port);
            csocket_close(sockfd);
            return (EC_FALSE);
        }     

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE; /*push it to connection pool after used*/
    }

    /*set connection pool callback*/
    csocket_cnode_push_close_callback(csocket_cnode, 
                                 (const char *)"cconnp_mgr_release", 
                                 (UINT32)task_brd_default_get_http_cconnp_mgr(), 
                                 (UINT32)cconnp_mgr_release);

    csocket_cnode_push_complete_callback(csocket_cnode, 
                                 (const char *)"cconnp_mgr_release", 
                                 (UINT32)task_brd_default_get_http_cconnp_mgr(), 
                                 (UINT32)cconnp_mgr_release);                                 
    /* mount */
    CHTTPS_NODE_CSOCKET_CNODE(chttps_node)    = csocket_cnode;

    return (EC_TRUE);
}

/*disconnect socket connection*/
EC_BOOL chttps_node_disconnect(CHTTPS_NODE *chttps_node)
{
    if(NULL_PTR != CHTTPS_NODE_CSOCKET_CNODE(chttps_node))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);

        /*unmount csocket_cnode and chttps_node*/
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node)    = NULL_PTR;

        dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "[DEBUG] chttps_node_disconnect: close socket %d\n", 
                                              CSOCKET_CNODE_SOCKFD(csocket_cnode));
                                              
        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        /*close https connection*/
        csocket_cnode_close(csocket_cnode);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_handshake_on_client(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    EC_BOOL      ret;

    if(CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE & CHTTPS_NODE_STATUS(chttps_node))
    {
        return (EC_TRUE);
    }
    
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_client: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode)); 
     
        return (EC_FALSE);
    }

    /*handshake may be more than once*/
    if(NULL_PTR == CHTTPS_NODE_CSSL_NODE(chttps_node))
    {
        CSSL_NODE *cssl_node;

        cssl_node = cssl_node_make_on_client(CSOCKET_CNODE_SOCKFD(csocket_cnode));
        if(NULL_PTR == cssl_node)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_client: new cssl_node failed\n");
            return (EC_FALSE);
        }

        /*mount chttps_node and cssl_node*/
        CHTTPS_NODE_CSSL_NODE(chttps_node) = cssl_node;

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_client: sockfd %d, bind chttps_node and cssl_node done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
    }
 
    /* handshake */
    ret = cssl_node_handshake(CHTTPS_NODE_CSSL_NODE(chttps_node));
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_client: sockfd %d, ssl connect failed\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
                 
        return (EC_FALSE);
    }

    if(EC_TRUE == ret)
    {
        CHTTPS_NODE_STATUS(chttps_node) = CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE;
        
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_client: sockfd %d, ssl connect done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));

        if(do_log(SEC_0157_CHTTPS, 9))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_client: certificate is\n");
            cssl_node_print_certificate(LOGSTDOUT, CHTTPS_NODE_CSSL_NODE(chttps_node));
        }

        /*delete possible RD event*/
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_WR_EVENT,
                        (const char *)"csocket_cnode_isend",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                        (void *)csocket_cnode);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
        return (EC_TRUE);
    }

    if(EC_AGAIN_SSL_WANT_WRITE == ret)
    {
        /*delete possible RD event*/
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_WR_EVENT,
                        (const char *)"csocket_cnode_isend",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                        (void *)csocket_cnode);  
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
        return (EC_TRUE);
    }

    if(EC_AGAIN_SSL_WANT_READ == ret)
    {
        /*delete possible WRevent*/
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_RD_EVENT,
                        (const char *)"csocket_cnode_irecv",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                        (void *)csocket_cnode); 
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
        return (EC_TRUE);
    }

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_client: sockfd %d, ssl handshake return %ld\n",
                CSOCKET_CNODE_SOCKFD(csocket_cnode), ret);
             
    return (EC_FALSE);
}


EC_BOOL chttps_node_handshake_on_server(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    CSRV        *csrv;
    EC_BOOL      ret;

    if(CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE & CHTTPS_NODE_STATUS(chttps_node))
    {
        return (EC_TRUE);
    }
    
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode)); 
     
        return (EC_FALSE);
    }

    csrv = (CSRV *)CHTTPS_NODE_CSRV(chttps_node);
    if(NULL_PTR == csrv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d, chttps_node => csrv is null\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    /*handshake may be more than once*/
    if(NULL_PTR == CHTTPS_NODE_CSSL_NODE(chttps_node))
    {
        CSSL_NODE *cssl_node;

        cssl_node = cssl_node_make_on_server(CSRV_CSSL_NODE(csrv), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        if(NULL_PTR == cssl_node)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d, make cssl_node on server failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
         
            return (EC_FALSE);
        }

        /*bind chttps_node and cssl_node*/
        CHTTPS_NODE_CSSL_NODE(chttps_node) = cssl_node;

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_server: sockfd %d, bind chttps_node and cssl_node done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
    }
 
    /* handshake */
    ret = cssl_node_handshake(CHTTPS_NODE_CSSL_NODE(chttps_node));
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d, ssl handshake failed\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
                 
        return (EC_FALSE);
    }

    if(EC_TRUE == ret)
    {
        CHTTPS_NODE_STATUS(chttps_node) = CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE;
        
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_server: sockfd %d, ssl handshake done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));

        /*delete possible WR event*/
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          (const char *)"csocket_cnode_irecv",
                          (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;             
        return (EC_TRUE);
    }

    if(EC_AGAIN_SSL_WANT_WRITE == ret)
    {
        /*delete possible RD event*/
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_WR_EVENT,
                        (const char *)"csocket_cnode_isend",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_isend,
                        (void *)csocket_cnode);                       
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
        return (EC_TRUE);
    }

    if(EC_AGAIN_SSL_WANT_READ == ret)
    {
        /*delete possible WRevent*/
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        cepoll_set_event(task_brd_default_get_cepoll(),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CEPOLL_RD_EVENT,
                        (const char *)"csocket_cnode_irecv",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                        (void *)csocket_cnode); 
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
        
        return (EC_TRUE);
    }

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d, ssl handshake return %ld\n",
                CSOCKET_CNODE_SOCKFD(csocket_cnode), ret);
             
    return (EC_FALSE);
}

EC_BOOL chttps_node_send_req(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    if(0 == (CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE & CHTTPS_NODE_STATUS(chttps_node)))
    {
        /*skip*/
        return (EC_TRUE);
    } 
    
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send_req: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode)); 
     
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_send(chttps_node, csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send_req: sockfd %d send req failed\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(EC_TRUE == chttps_node_need_send(chttps_node))
    {
        /*wait for next writing*/

        /**********************************************************************************
        *   note:
        *       assume caller would set WR event when return EC_AGAIN.
        *       we cannot determine who will trigger send op:
        *         if cepoll trigger send op, WR event should not be set,
        *         if chttp trigger send op before WR event was set, chttp should set later
        *       thus, return EC_AGAIN is more safe.
        *
        ***********************************************************************************/
        return (EC_AGAIN);
    }

    chunk_mgr_clean(CHTTPS_NODE_SEND_BUF(chttps_node));/*clean up asap*/

    //CHTTPS_NODE_LOG_TIME_WHEN_SENT(chttps_node);
 
    /*now all data had been sent out, del WR event and set RD event*/
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_send_req: sockfd %d had sent out all req data\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));  

    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    cepoll_set_event(task_brd_default_get_cepoll(), 
                     CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                     CEPOLL_RD_EVENT,
                     (const char *)"csocket_cnode_irecv",
                     (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv, 
                     (void *)csocket_cnode);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
    
    return (EC_TRUE);
}

EC_BOOL chttps_node_recv_rsp(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    EC_BOOL       ret;

    if(0 == (CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE & CHTTPS_NODE_STATUS(chttps_node)))
    {
        /*skip*/
        return (EC_TRUE);
    } 
    
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    ret = chttps_node_recv(chttps_node, csocket_cnode);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: recv rsp on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);                         
    }

    if(EC_DONE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_rsp: sockfd %d, no more data to recv or parse\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
     
        return (EC_DONE); /*fix*/
    }

    if(EC_FALSE == chttps_parse(chttps_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: parse on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);                         
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_rsp: sockfd %d, recv and parse done\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

    return (EC_TRUE);
}

/*basic http flow*/
EC_BOOL chttps_request_basic(const CHTTP_REQ *chttp_req, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    CHTTPS_NODE    *chttps_node;
    CROUTINE_COND  *croutine_cond;
    uint64_t        rsp_body_len;
    UINT8          *data;
    UINT32          data_len;

    chttps_node = chttps_node_new(CHTTP_TYPE_DO_CLT_RSP);
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: new chttps_node failed\n");
        return (EC_FALSE);
    }

    croutine_cond = croutine_cond_new(0/*never timeout*/, LOC_CHTTPS_0021);
    if(NULL_PTR == croutine_cond)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: new croutine_cond failed\n");
     
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }
    CHTTPS_NODE_CROUTINE_COND(chttps_node) = croutine_cond;

    CHTTPS_NODE_LOG_TIME_WHEN_START(chttps_node); /*record start time*/

    if(EC_FALSE == chttps_node_connect(chttps_node, CHTTP_REQ_IPADDR(chttp_req), CHTTP_REQ_PORT(chttp_req)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: connect server %s:%ld failed\n",
                            CHTTP_REQ_IPADDR_STR(chttp_req), CHTTP_REQ_PORT(chttp_req));

        chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_encode_req_header(chttps_node,
                            CHTTP_REQ_METHOD(chttp_req), CHTTP_REQ_URI(chttp_req),
                            CHTTP_REQ_PARAM(chttp_req), CHTTP_REQ_HEADER(chttp_req))
     )
    {
        CSOCKET_CNODE  *csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: encode header failed\n");

        /*unmount csocket_cnode and chttps_node*/
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);

        chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == chttps_node_encode_req_body(chttps_node, CHTTP_REQ_BODY(chttp_req)))
    {
        CSOCKET_CNODE  *csocket_cnode;

        csocket_cnode = CHTTPS_NODE_CSOCKET_CNODE(chttps_node);
        
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: encode body failed\n");

        /*unmount csocket_cnode and chttps_node*/
        CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = NULL_PTR;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);

        chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }

    chttps_node_init_parser(chttps_node);

    CHTTPS_NODE_STATUS(chttps_node) = CHTTPS_NODE_STATUS_HANDSHAKE_ONGOING;

    chttps_node_set_socket_callback(chttps_node, CHTTPS_NODE_CSOCKET_CNODE(chttps_node));
    chttps_node_set_socket_epoll(chttps_node, CHTTPS_NODE_CSOCKET_CNODE(chttps_node));

    croutine_cond_reserve(croutine_cond, 1, LOC_CHTTPS_0022);
    croutine_cond_wait(croutine_cond, LOC_CHTTPS_0023);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: coroutine was cancelled\n"); 

        chttps_node_disconnect(chttps_node);
     } else {/*normal*/
        /*do nothing*/
    }

    ASSERT(NULL_PTR == CHTTPS_NODE_CSOCKET_CNODE(chttps_node));
 
    /**
     *  when come back, check CHTTPS_NODE_RECV_COMPLETE flag.
     *  if false, exception happened. and return false
     **/
    if(BIT_FALSE == CHTTPS_NODE_RECV_COMPLETE(chttps_node))/*exception happened*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: exception happened\n");

        chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);

        /*socket should not be used by others ...*/
        chttps_node_disconnect(chttps_node);
        
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }

    chttps_node_disconnect(chttps_node);
    
    /*get and check body len/content-length*/
    /*rsp_body_len = chttps_node_recv_len(chttps_node);*/
    rsp_body_len = CHTTPS_NODE_BODY_PARSED_LEN(chttps_node);
    if(0 < rsp_body_len && 0 < CHTTPS_NODE_CONTENT_LENGTH(chttps_node))
    {
        uint64_t content_len;
        content_len = CHTTPS_NODE_CONTENT_LENGTH(chttps_node);
     
        if(content_len != rsp_body_len)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: body len %"PRId64" != content len %"PRId64"\n",
                            rsp_body_len, content_len);

            chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
            chttps_node_free(chttps_node);
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_basic: body len %"PRId64", content len %"PRId64"\n",
                    rsp_body_len, CHTTPS_NODE_CONTENT_LENGTH(chttps_node)); 

    /*handover http response*/
    CHTTP_RSP_STATUS(chttp_rsp) = (uint32_t)CHTTPS_NODE_STATUS_CODE(chttps_node);

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_basic: before handover, chttps_node: %p\n", chttps_node);
        chttps_node_print(LOGSTDOUT, chttps_node);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_basic: before handover, chttp_rsp: %p\n", chttp_rsp);
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }
 
    cstrkv_mgr_handover(CHTTPS_NODE_HEADER_IN_KVS(chttps_node), CHTTP_RSP_HEADER(chttp_rsp));

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_basic: after handover, chttps_node: %p\n", chttps_node);
        chttps_node_print(LOGSTDOUT, chttps_node);
    }
 
    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_basic: after handover, chttp_rsp: \n");
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }

    /*Transfer-Encoding: chunked*/
    if(0 == CHTTPS_NODE_CONTENT_LENGTH(chttps_node) && EC_TRUE == chttp_rsp_is_chunked(chttp_rsp))
    {
        CSTRKV *cstrkv;
     
        cstrkv = cstrkv_new((const char *)"Content-Length", c_word_to_str((UINT32)CHTTPS_NODE_BODY_PARSED_LEN(chttps_node)));
        if(NULL_PTR == cstrkv)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: new cstrkv for chunked rsp failed\n");
            /*ignore this exception*/
        }
        else
        {
            cstrkv_mgr_add_kv(CHTTP_RSP_HEADER(chttp_rsp), cstrkv);
        }
     
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_basic: add %s:%s to rsp\n",
                        (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    /*dump body*/
    if(EC_FALSE == chunk_mgr_dump(CHTTPS_NODE_RECV_BUF(chttps_node), &data, &data_len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: dump response body failed\n");

        cstrkv_mgr_clean(CHTTP_RSP_HEADER(chttp_rsp));

        chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_basic: dump response body len %ld\n", data_len);
    cbytes_mount(CHTTP_RSP_BODY(chttp_rsp), data_len, data);

    chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
    chttps_node_free(chttps_node);

    return (EC_TRUE);
}

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Try to connect remote http server to check connectivity (HEALTH CHECKER)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
EC_BOOL chttps_node_icheck(CHTTPS_NODE *chttps_node, CSOCKET_CNODE *csocket_cnode)
{
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_icheck: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode)); 
     
        return (EC_FALSE);
    }
 
    __chttps_on_send_complete(chttps_node);

    /*note: return EC_DONE will trigger connection shutdown*/
    return (EC_DONE);
}

EC_BOOL chttps_node_check(CHTTPS_NODE *chttps_node, const UINT32 ipaddr, const UINT32 port)
{
    CSOCKET_CNODE *csocket_cnode;
    int sockfd;
 
    if(EC_FALSE == csocket_connect( ipaddr, port , CSOCKET_IS_NONBLOCK_MODE, &sockfd ))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_check: connect server %s:%ld failed\n",
                            c_word_to_ipv4(ipaddr), port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_check: socket %d connecting to server %s:%ld\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);

    if(EC_FALSE == csocket_is_connected(sockfd))/*not adaptive to unix domain socket*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_check: socket %d to server %s:%ld is not connected\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);
        csocket_close(sockfd);
        return (EC_FALSE);
    }

    if(do_log(SEC_0157_CHTTPS, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_node_check: client tcp stat:\n");
        csocket_tcpi_stat_print(LOGSTDOUT, sockfd);
    }

    csocket_cnode = csocket_cnode_new(CMPI_ERROR_TCID, sockfd, CSOCKET_TYPE_TCP, ipaddr, port);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_check:new csocket cnode for socket %d to server %s:%ld failed\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);
        csocket_close(sockfd);
        return (EC_FALSE);
    }     

    /* mount */
    CHTTPS_NODE_CSOCKET_CNODE(chttps_node) = csocket_cnode;

    return (EC_TRUE);
}

EC_BOOL chttps_check(const CHTTP_REQ *chttp_req, CHTTP_STAT *chttp_stat)
{
    CHTTPS_NODE    *chttps_node;
    CROUTINE_COND *croutine_cond;
 
    chttps_node = chttps_node_new(CHTTP_TYPE_DO_CLT_CHK);
    if(NULL_PTR == chttps_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: new chttps_node failed\n");
        return (EC_FALSE);
    }

    croutine_cond = croutine_cond_new(0/*never timeout*/, LOC_CHTTPS_0024);
    if(NULL_PTR == croutine_cond)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: new croutine_cond failed\n");
     
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }
    CHTTPS_NODE_CROUTINE_COND(chttps_node) = croutine_cond;

    //CHTTPS_NODE_LOG_TIME_WHEN_START(chttps_node); /*record start time*/

    if(EC_FALSE == chttps_node_check(chttps_node, CHTTP_REQ_IPADDR(chttp_req), CHTTP_REQ_PORT(chttp_req)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: check server %s:%ld failed\n",
                            CHTTP_REQ_IPADDR_STR(chttp_req), CHTTP_REQ_PORT(chttp_req));

        chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }

    chttps_node_init_parser(chttps_node);

    chttps_node_set_socket_callback(chttps_node, CHTTPS_NODE_CSOCKET_CNODE(chttps_node));
    chttps_node_set_socket_epoll(chttps_node, CHTTPS_NODE_CSOCKET_CNODE(chttps_node));

    croutine_cond_reserve(croutine_cond, 1, LOC_CHTTPS_0025);
    croutine_cond_wait(croutine_cond, LOC_CHTTPS_0026);

    __COROUTINE_CATCH_EXCEPTION() { /*exception*/
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: coroutine was cancelled\n");

        chttps_node_disconnect(chttps_node);
        
    }__COROUTINE_HANDLE_EXCEPTION();

    ASSERT(NULL_PTR == CHTTPS_NODE_CSOCKET_CNODE(chttps_node));
 
    /**
     *  when come back, check CHTTPS_NODE_SEND_COMPLETE flag.
     *  if so, exception happened. and return false
     **/
    if(BIT_FALSE == CHTTPS_NODE_SEND_COMPLETE(chttps_node))/*exception happened*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: exception happened\n");

        chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
        chttps_node_free(chttps_node);
        return (EC_FALSE);
    }

    chttps_node_disconnect(chttps_node);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_check: OK\n"); 

    chttp_stat_clone(CHTTPS_NODE_STAT(chttps_node), chttp_stat);
    chttps_node_free(chttps_node);

    return (EC_TRUE);
}

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * General Http Request Entry
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request(const CHTTP_REQ *chttp_req, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    return chttps_request_basic(chttp_req, chttp_rsp, chttp_stat);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

