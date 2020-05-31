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

#include "cmpie.h"

#include "cepoll.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "json.h"
#include "cbase64code.h"
#include "cssl.h"
#include "chttps.inc"
#include "chttps.h"

#include "cdns.h"
#include "coroutine.h"
#include "csrv.h"
#include "cconnp.h"
#include "ccache.h"
#include "ccallback.h"
#include "super.h"
#include "cdnscache.h"
#include "findex.inc"

static CQUEUE g_chttps_defer_request_queue;
static EC_BOOL g_chttps_defer_request_queue_init_flag = EC_FALSE;

static CLIST  *g_chttps_rest_list  = NULL_PTR;

static UINT32  g_chttps_store_seqno = 10000;

#define CHTTPS_STORE_SEQ_NO_GEN(__chttp_store)     do{ CHTTP_STORE_SEQ_NO(__chttp_store) = ++ g_chttps_store_seqno;}while(0)
#define CHTTPS_STORE_SEQ_NO_GET(__chttp_store)     (CHTTP_STORE_SEQ_NO(__chttp_store))

#if 1
#define CHTTPS_ASSERT(condition) do{\
    if(!(condition)) {\
        sys_log(LOGSTDOUT, "error:assert failed at %s:%d\n", __FUNCTION__, __LINE__);\
        exit(EXIT_FAILURE);\
    }\
}while(0)
#endif

STATIC_CAST static EC_BOOL __chttps_request_merge_file_lock(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, const CSTRING *path, const UINT32 expire_nsec, UINT32 *locked_already);
STATIC_CAST static EC_BOOL __chttps_request_merge_file_unlock(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path);

const char *chttps_status_str_get(const uint32_t http_status)
{
    return chttp_status_str_get(http_status);
}

/*---------------------------------------------- FOR SSL  ----------------------------------------------*/

/*write until all data out or no further data can be sent out at present*/
EC_BOOL chttps_ssl_send(CHTTP_NODE *chttp_node, const UINT32 once_max_size, const UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *pos)
{
    CSSL_NODE *cssl_node;

    cssl_node = CHTTP_NODE_CSSL_NODE(chttp_node);
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_ssl_send: cssl_node does not exist\n");
        return (EC_FALSE);
    }

    return cssl_node_send(cssl_node, once_max_size, out_buff, out_buff_max_len, pos);
}

EC_BOOL chttps_ssl_recv(CHTTP_NODE *chttp_node, const UINT32 once_max_size, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    CSSL_NODE *cssl_node;

    cssl_node = CHTTP_NODE_CSSL_NODE(chttp_node);
    if(NULL_PTR == cssl_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_ssl_recv: cssl_node does not exist\n");
        return (EC_FALSE);
    }

    return cssl_node_recv(cssl_node, once_max_size, in_buff, in_buff_expect_len, pos);
}

EC_BOOL chttps_send(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode, const UINT8 * out_buff, const UINT32 out_buff_max_len, UINT32 * pos)
{
    if(CSOCKET_TYPE_TCP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return chttps_ssl_send(chttp_node, CSOCKET_CNODE_SEND_ONCE_MAX_SIZE(csocket_cnode),
                            out_buff, out_buff_max_len, pos);
    }

    dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "error:chttps_send: sockfd %d, invalid type %u \n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_TYPE(csocket_cnode));
    return (EC_FALSE);
}

EC_BOOL chttps_recv(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode, UINT8 *in_buff, const UINT32 in_buff_expect_len, UINT32 *pos)
{
    if(CSOCKET_TYPE_TCP == CSOCKET_CNODE_TYPE(csocket_cnode))
    {
        return chttps_ssl_recv(chttp_node, CSOCKET_CNODE_RECV_ONCE_MAX_SIZE(csocket_cnode),
                            in_buff, in_buff_expect_len, pos);
    }

    dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "error:chttps_recv: sockfd %d, invalid type %u \n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_TYPE(csocket_cnode));
    return (EC_FALSE);
}

/*private interface, not for http parser*/
STATIC_CAST static EC_BOOL __chttps_on_recv_complete(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE *csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_recv_complete: chttp_node %p csocket_cnode is null\n", chttp_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: sockfd %d, body parsed %ld\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode), CHTTP_NODE_BODY_PARSED_LEN(chttp_node));

    CHTTP_NODE_LOG_TIME_WHEN_RCVD(chttp_node);/*record the received or parsed time*/

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE REQ]\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));

        if(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode))
        {
            /*note: http request is ready now. stop read from socket to prevent recving during handling request*/
            cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        }

        if(BIT_TRUE == CHTTP_NODE_HEADER_COMPLETE(chttp_node))
        {
            chttp_pause_parser(CHTTP_NODE_PARSER(chttp_node)); /*pause parser*/

            /*commit*/
            chttps_defer_request_queue_push(chttp_node);

            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE REQ] commit request\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

            CHTTP_NODE_RECV_COMPLETE(chttp_node) = BIT_TRUE;
            return (EC_TRUE);
        }

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_recv_complete: socket %d, [type: HANDLE REQ] header not completed\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE RSP]\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));

        if(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode))
        {
            cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        }

        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0001);
        }

        if(BIT_TRUE == CHTTP_NODE_HEADER_COMPLETE(chttp_node))
        {
            CHTTP_NODE_RECV_COMPLETE(chttp_node) = BIT_TRUE;
        }
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE CHECK]\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));

        if(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode))
        {
            cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        }

        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0002);
        }

        CHTTP_NODE_RECV_COMPLETE(chttp_node) = BIT_TRUE;
        return (EC_TRUE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_recv_complete: socket %d, [type: HANDLE: unknown 0x%lx]\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode), (UINT32)CHTTP_NODE_TYPE(chttp_node));

    if(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode))
    {
        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    }
    return (EC_FALSE);
}

/*private interface, not for http parser*/
STATIC_CAST static EC_BOOL __chttps_on_send_complete(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE *csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    /*note: http request is ready now. stop read from socket to prevent recving during handling request*/
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))
    {
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0003);
        }
    }

    CHTTP_NODE_SEND_COMPLETE(chttp_node) = BIT_TRUE;

    return (EC_TRUE);
}

/*---------------------------------------- HTTP PASER INTERFACE ----------------------------------------*/
STATIC_CAST static int __chttps_on_message_begin(http_parser_t* http_parser)
{
    CHTTP_NODE *chttp_node;

    chttp_node= (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_message_begin: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    ccallback_list_run_not_check(CHTTP_NODE_PARSE_ON_MESSAGE_BEGIN_CALLBACK_LIST(chttp_node), (UINT32)chttp_node);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_message_begin: chttp_node %p, ***MESSAGE BEGIN***\n",
                    chttp_node);

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
STATIC_CAST static int __chttps_on_headers_complete(http_parser_t* http_parser, const char* last, size_t length)
{
    CHTTP_NODE    *chttp_node;

    chttp_node = (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_headers_complete: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))
    {
        chttp_parse_host(chttp_node);
        chttp_parse_uri(chttp_node);
    }

    chttp_parse_content_length(chttp_node);
#if 1
    if(EC_FALSE == chttp_parse_connection_keepalive(chttp_node))
    {
        /*should never reach here due to csocket_cnode was checked before*/
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_headers_complete: chttp_node %p parse connection keepalive failed\n",
                        chttp_node);
        return (-1);/*error*/
    }
#else
    CHTTP_NODE_KEEPALIVE(chttp_node) = BIT_FALSE; /*force to disable keepalive*/
#endif

    CHTTP_NODE_HEADER_COMPLETE(chttp_node) = BIT_TRUE;  /*header is ready*/
    CHTTP_NODE_HEADER_PARSED_LEN(chttp_node) += length; /*the last part of header*/

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
        sys_log(LOGSTDOUT, "[DEBUG] __chttps_on_headers_complete: socket %d, ***HEADERS COMPLETE***\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode));
        chttp_node_print_header(LOGSTDOUT, chttp_node);
    }

    //chttps_node_parse_on_headers_complete(chttp_node);
    ccallback_list_run_not_check(CHTTP_NODE_PARSE_ON_HEADERS_COMPLETE_CALLBACK_LIST(chttp_node), (UINT32)chttp_node);

    /*
    *   note:
    *       when store has high latency, timeout event would happen and trigger timeout handling,
    *   and then trigger chttp_node free!
    *
    */
    if(EC_TRUE == chttp_node_has_error(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_headers_complete: chttp_node %p has error\n",
                            chttp_node);
        return (-1);/*error*/
    }

    return (0);/*succ*/
}

STATIC_CAST static int __chttps_on_message_complete(http_parser_t* http_parser)
{
    CHTTP_NODE    *chttp_node;
     CSOCKET_CNODE  *csocket_cnode;

    chttp_node= (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_message_complete: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_message_complete: http_parser %p -> chttp_node %p -> csocket_cnode is null\n", http_parser, chttp_node);
        return (-1);/*error*/
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT,
            "[DEBUG] __chttps_on_message_complete: sockfd %d, http state %s, header parsed %u, body parsed %"PRId64", errno = %d, name = %s, description = %s\n",
            CSOCKET_CNODE_SOCKFD(csocket_cnode), http_state_str(http_parser->state),
            CHTTP_NODE_HEADER_PARSED_LEN(chttp_node),CHTTP_NODE_BODY_PARSED_LEN(chttp_node),
            HTTP_PARSER_ERRNO(http_parser), http_errno_name(HTTP_PARSER_ERRNO(http_parser)), http_errno_description(HTTP_PARSER_ERRNO(http_parser)));

    if(NULL_PTR != CHTTP_NODE_STORE(chttp_node))
    {
        CHTTP_STORE   *chttp_store;

        chttp_store   = CHTTP_NODE_STORE(chttp_node);

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_message_complete: sockfd %d, seg_id %u, cache_ctrl: 0x%x\n",
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),
                        CHTTP_STORE_SEG_ID(chttp_store), CHTTP_STORE_CACHE_CTRL(chttp_store));
    }

    //chttps_node_parse_on_message_complete(chttp_node);
    ccallback_list_run_not_check(CHTTP_NODE_PARSE_ON_MESSAGE_COMPLETE_CALLBACK_LIST(chttp_node), (UINT32)chttp_node);

    /*
    *   note:
    *       when store has high latency, timeout event would happen and trigger timeout handling,
    *   and then trigger chttp_node free!
    *
    */
    if(EC_TRUE == chttp_node_has_error(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_message_complete: found chttp_node %p has error\n",
                            chttp_node);
        return (-1);/*error*/
    }

    if(EC_FALSE == __chttps_on_recv_complete(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "[DEBUG] __chttps_on_message_complete: chttp_node %p recv complete failed\n", chttp_node);
        return (-1);/*error*/
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_message_complete: sockfd %d, ***MESSAGE COMPLETE***\n",
                    CSOCKET_CNODE_SOCKFD(CHTTP_NODE_CSOCKET_CNODE(chttp_node)));
    return (0);
}

STATIC_CAST static int __chttps_on_url(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_NODE    *chttp_node;

    chttp_node= (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_url: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    cbuffer_set(CHTTP_NODE_URL(chttp_node), (uint8_t *)at, length);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_url: chttp_node %p, url: %.*s\n",
                    chttp_node, (int)length, at);

    return (0);
}

/*only for http response*/
STATIC_CAST static int __chttps_on_status(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_NODE    *chttp_node;
    CSOCKET_CNODE  *csocket_cnode;

    chttp_node= (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_status: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_status: http_parser %p -> chttp_node %p -> csocket_cnode is null\n", http_parser, chttp_node);
        return (-1);/*error*/
    }

    ASSERT(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node));

    CHTTP_NODE_STATUS_CODE(chttp_node) = http_parser->status_code;
    CHTTP_STAT_RSP_STATUS(CHTTP_NODE_STAT(chttp_node)) = CHTTP_NODE_STATUS_CODE(chttp_node);

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        UINT32 status_code;

        status_code = CHTTP_NODE_STATUS_CODE(chttp_node);
        sys_log(LOGSTDOUT, "[DEBUG] __chttps_on_status: sockfd %d, status: %u %.*s ==> %ld\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            http_parser->status_code, (uint32_t)length, at,
                            status_code);
    }

    return (0);
}

STATIC_CAST static int __chttps_on_header_field(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_NODE    *chttp_node;
    CSTRKV *cstrkv;

    chttp_node= (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_field: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    rlog(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_field: http state %s: '%.*s'\n",
                http_state_str(http_parser->state), (uint32_t)length, at);

    if(NULL_PTR == CHTTP_NODE_PARSING_HEADER_KV(chttp_node))
    {
        cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
        if(NULL_PTR == cstrkv)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_field: new cstrkv failed where header field: %.*s\n",
                               (uint32_t)length, at);
            return (-1);
        }
        CHTTP_NODE_PARSING_HEADER_KV(chttp_node) = cstrkv;
    }
    else
    {
        cstrkv = CHTTP_NODE_PARSING_HEADER_KV(chttp_node);
    }

    cstrkv_set_key_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CHTTPS_0004);

    if(s_header_value_discard_ws == http_parser->state)
    {
        rlog(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_field: chttp_node %p, Header field: '%s' => OK\n",
                        chttp_node, CSTRKV_KEY_STR(cstrkv));
    }

    //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_field: chttp_node %p, Header field: '%.*s'\n", chttp_node, (int)length, at);
    return (0);
}

STATIC_CAST static int __chttps_on_header_value(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_NODE    *chttp_node;
    CSTRKV *cstrkv;

    chttp_node= (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_value: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    rlog(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_value: http state %s: '%.*s'\n",
                    http_state_str(http_parser->state), (uint32_t)length, at);

    cstrkv = CHTTP_NODE_PARSING_HEADER_KV(chttp_node);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_header_value: no cstrkv existing where value field: %.*s\n",
                           (uint32_t)length, at);
        return (-1);
    }

    cstrkv_set_val_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CHTTPS_0005);
    //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_value: chttp_node %p, Header value: '%.*s'\n", chttp_node, (uint32_t)length, at);

    if(s_header_almost_done == http_parser->state)
    {
        cstrkv_mgr_add_kv(CHTTP_NODE_HEADER_IN_KVS(chttp_node), cstrkv);
        CHTTP_NODE_PARSING_HEADER_KV(chttp_node) = NULL_PTR;

        rlog(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_header_value: chttp_node %p, Header value: '%s' => OK\n",
                        chttp_node, CSTRKV_VAL_STR(cstrkv));

        dbg_log(SEC_0157_CHTTPS, 6)(LOGSTDOUT, "[DEBUG] __chttps_on_header_value: chttp_node %p, Header '%s': '%s' => OK\n",
                        chttp_node, CSTRKV_KEY_STR(cstrkv), CSTRKV_VAL_STR(cstrkv));
    }
#if 0
    if(do_log(SEC_0157_CHTTPS, 9))
    {
        cstrkv_print(LOGSTDOUT, cstrkv);
    }
#endif

    return (0);
}

STATIC_CAST static int __chttps_on_body(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_NODE    *chttp_node;
    CHUNK_MGR      *recv_chunks;

    chttp_node= (CHTTP_NODE *)http_parser->data;
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_body: http_parser %p -> chttp_node is null\n", http_parser);
        return (-1);/*error*/
    }

    recv_chunks = CHTTP_NODE_RECV_BUF(chttp_node);

    if(EC_FALSE == chunk_mgr_append_data_min(recv_chunks, (uint8_t *)at, length, CHTTP_IN_BUF_SIZE))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_body: append %ld bytes failed\n", length);
        return (-1);
    }
    CHTTP_NODE_BODY_PARSED_LEN(chttp_node) += length;

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_on_body: chttp_node %p, len %ld => body parsed %"PRId64"\n",
                    chttp_node, length, CHTTP_NODE_BODY_PARSED_LEN(chttp_node));

    //chttps_node_parse_on_body(chttp_node, CHTTP_NODE_CSOCKET_CNODE(chttp_node));
    ccallback_list_run_not_check(CHTTP_NODE_PARSE_ON_BODY_CALLBACK_LIST(chttp_node), (UINT32)chttp_node);

    /*
    *   note:
    *       when store has high latency, timeout event would happen and trigger timeout handling,
    *   and then trigger chttp_node free!
    *
    */
    if(EC_TRUE == chttp_node_has_error(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_on_body: found chttp_node %p has error\n",
                            chttp_node);
        return (-1);/*error*/
    }

    return (0);
}

/*---------------------------------------- INTERFACE WITH HTTP PASER  ----------------------------------------*/
STATIC_CAST static void __chttps_parser_init(http_parser_t   *http_parser, const UINT32 type)
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

STATIC_CAST static void __chttps_parser_setting_init(http_parser_settings_t   *http_parser_setting)
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

STATIC_CAST static void __chttps_parser_clean(http_parser_t   *http_parser)
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

STATIC_CAST static void __chttps_parser_setting_clean(http_parser_settings_t   *http_parser_setting)
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
STATIC_CAST static EC_BOOL __chttps_node_parse_on_message_begin_runner(CHTTP_NODE *chttp_node, CCALLBACK_NODE *ccallback_node)
{
    CHTTP_NODE_PARSE_ON_MESSAGE_BEGIN_CALLBACK    on_message_bein_callback;

    on_message_bein_callback = (CHTTP_NODE_PARSE_ON_MESSAGE_BEGIN_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return on_message_bein_callback(chttp_node);
}

STATIC_CAST static EC_BOOL __chttps_node_parse_on_headers_complete_runner(CHTTP_NODE *chttp_node, CCALLBACK_NODE *ccallback_node)
{
    CHTTP_NODE_PARSE_ON_HEADERS_COMPLETE_CALLBACK    on_headers_complete_callback;

    on_headers_complete_callback = (CHTTP_NODE_PARSE_ON_HEADERS_COMPLETE_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return on_headers_complete_callback(chttp_node);
}

STATIC_CAST static EC_BOOL __chttps_node_parse_on_body_runner(CHTTP_NODE *chttp_node, CCALLBACK_NODE *ccallback_node)
{
    CHTTP_NODE_PARSE_ON_BODY_CALLBACK    on_body_callback;

    on_body_callback = (CHTTP_NODE_PARSE_ON_BODY_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return on_body_callback(chttp_node);
}

STATIC_CAST static EC_BOOL __chttps_node_parse_on_message_complete_runner(CHTTP_NODE *chttp_node, CCALLBACK_NODE *ccallback_node)
{
    CHTTP_NODE_PARSE_ON_MESSAGE_COMPLETE_CALLBACK    on_message_complete_callback;

    on_message_complete_callback = (CHTTP_NODE_PARSE_ON_MESSAGE_COMPLETE_CALLBACK)CCALLBACK_NODE_FUNC(ccallback_node);

    return on_message_complete_callback(chttp_node);
}

EC_BOOL chttps_node_recv_req(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    EC_BOOL       ret;

    if(0 == (CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE & CHTTP_NODE_SSL_STATUS(chttp_node)))
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
        CHTTP_NODE_LOG_TIME_WHEN_START(chttp_node); /*record start time*/
    }

    ret = chttps_node_recv(chttp_node, csocket_cnode);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_req: recv req on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(EC_DONE == ret)
    {
        if(BIT_FALSE == CHTTP_NODE_RECV_COMPLETE(chttp_node))
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

    if(EC_FALSE == chttp_parse(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_req: parse on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_req: sockfd %d, recv and parse done\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
    return (EC_TRUE);
}

EC_BOOL chttps_node_send_req(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    if(0 == (CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE & CHTTP_NODE_SSL_STATUS(chttp_node)))
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

    if(EC_FALSE == chttps_node_send(chttp_node, csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send_req: sockfd %d send req failed\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(EC_TRUE == chttp_node_need_send(chttp_node))
    {
        /*wait for next writing*/

        /**********************************************************************************
        *   note:
        *       assume caller would set WR event when return EC_AGAIN.
        *       we cannot determine who will trigger send op:
        *         if cepoll trigger send op, WR event should not be set,
        *         if chttps trigger send op before WR event was set, chttps should set later
        *       thus, return EC_AGAIN is more safe.
        *
        ***********************************************************************************/
        return (EC_AGAIN);
    }

    chunk_mgr_clean(CHTTP_NODE_SEND_BUF(chttp_node));/*clean up asap*/

    //CHTTP_NODE_LOG_TIME_WHEN_SENT(chttp_node);

    /*now all data had been sent out, del WR event and set RD event*/
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_send_req: sockfd %d had sent out all req data\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));

    if(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode))
    {
        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        cepoll_set_event(task_brd_default_get_cepoll(),
                         CSOCKET_CNODE_SOCKFD(csocket_cnode),
                         CEPOLL_RD_EVENT,
                         (const char *)"csocket_cnode_irecv",
                         (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                         (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
    }
    return (EC_TRUE);
}

EC_BOOL chttps_node_recv_rsp(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    EC_BOOL       ret;

    if(0 == (CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE & CHTTP_NODE_SSL_STATUS(chttp_node)))
    {
        /*skip*/
        return (EC_TRUE);
    }

    if(EC_TRUE == chttp_node_has_error(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: chttp_node %p has error\n", chttp_node);

        chttps_node_disconnect(chttp_node);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    chttp_node_reserve(chttp_node);
    /**
      * note : --- a trap ----
      *    if client set connection:close, server will close connection at once after sending data out.
      *    epoll trigger client with RD event, and here checking would found connection broken,
      *    thus no data from server would be recved.
      *
      *    one solution is client set connection:keep-alive.
      *    another solution is to give up checking here.
      *
     **/
    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))
    {
        if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: sockfd %d is not connected [RECV_COMPLETE : %s, srv:%s:%ld, tcpi stat: %s]\n",
                               CSOCKET_CNODE_SOCKFD(csocket_cnode),
                               c_bit_bool_str(CHTTP_NODE_RECV_COMPLETE(chttp_node)),
                               c_word_to_ipv4(CSOCKET_CNODE_IPADDR(csocket_cnode)),
                               CSOCKET_CNODE_SRVPORT(csocket_cnode),
                               csocket_cnode_tcpi_stat_desc(csocket_cnode));

            chttp_node_release(chttp_node);
            return (EC_FALSE);
        }
    }

    ret = chttps_node_recv(chttp_node, csocket_cnode);
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: recv rsp on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

        chttp_node_release(chttp_node);
        return (EC_FALSE);
    }

    if(EC_DONE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_rsp: sockfd %d, no more data to recv or parse\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

        /*
        *   note:
        *       due to store-procedure is blocking mode, we have to
        *   del RD event temporarily. otherwise, before unblocking,
        *   RD event may be triggered, and http parser will parse the
        *   old data which is not be shifted out yet!
        *
        */

        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;

        /*note: when origin return 502, e.g., here is the last chance to save to storage*/
        chttp_node_store_on_message_complete(chttp_node);
#if 0
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          (const char *)"csocket_cnode_irecv",
                          (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
#endif
        chttp_node_release(chttp_node);
        return (EC_DONE); /*fix*/
    }

    ret = chttp_parse(chttp_node);
    if(EC_TRUE == chttp_node_has_error(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: found chttp_node %p has error => free it\n",
                            chttp_node);

        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_recv_rsp: parse on sockfd %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

        chttp_node_release(chttp_node);
        return (EC_FALSE);
    }

    if(EC_AGAIN == ret && BIT_FALSE == CSOCKET_CNODE_NONBLOCK(csocket_cnode)) /*block mode*/
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_rsp: parse on sockfd %d again\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

        chttp_node_release(chttp_node);
        return chttps_node_recv_rsp(chttp_node, csocket_cnode);
    }

    if(BIT_TRUE == CHTTP_NODE_RECV_COMPLETE(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_rsp: sockfd %d, recv and parse complete\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
        chttp_node_release(chttp_node);
        return (EC_DONE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_recv_rsp: sockfd %d, recv and parse done\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));
    chttp_node_release(chttp_node);
    return (EC_TRUE);
}

EC_BOOL chttps_node_send_rsp(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    if(0 == (CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE & CHTTP_NODE_SSL_STATUS(chttp_node)))
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

    if(EC_FALSE == chttps_node_send(chttp_node, csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send_rsp: sockfd %d send rsp failed\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    if(EC_TRUE == chttp_node_need_send(chttp_node))
    {
        /*wait for next writing*/

        /**********************************************************************************
        *   note:
        *       assume caller would set WR event when return EC_AGAIN.
        *       we cannot determine who will trigger send op:
        *         if cepoll trigger send op, WR event should not be set,
        *         if chttps trigger send op before WR event was set, chttps should set later
        *       thus, return EC_AGAIN is more safe.
        *
        ***********************************************************************************/
        return (EC_AGAIN);
    }

    CHTTP_NODE_LOG_TIME_WHEN_END(chttp_node);
    CHTTP_NODE_LOG_PRINT(chttp_node);

    /*now all data had been sent out, del WR event and set RD event*/
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_send_rsp: sockfd %d had sent out all rsp data\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));

    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

    return (EC_DONE);/*return EC_DONE will trigger CEPOLL cleanup*/
}

EC_BOOL chttps_node_icheck(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_icheck: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    __chttps_on_send_complete(chttp_node);

    /*note: return EC_DONE will trigger connection shutdown*/
    return (EC_DONE);
}

EC_BOOL chttps_node_complete(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;

    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))/*on server side*/
    {
        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttp_node);

        /*keep-alive*/
        if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_complete: [server] keep-alive, resume socket %d\n", sockfd);

            /*resume*/
            //CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
            chttp_node_wait_resume(chttp_node);
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_complete: [server] keep-alive, resume socket %d done\n", sockfd);

            return (EC_TRUE);
        }

        /*no keep-alive*/
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_complete: [server] not keep-alive, closing sockfd %d\n", sockfd);

        /* unbind */
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

        /*free*/
        chttp_node_free(chttp_node);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;/*trigger socket closing*/

        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node))/*on client side*/
    {
        /* unbind */
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0006);
        }

        //CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; /*xxx*/
        return (EC_TRUE);

    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))/*on client side*/
    {
        /*not unbind*/

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0007);
        }

        //CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
        return (EC_TRUE);
    }

    /*should never reacher here!*/

    /* unbind */
    CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_complete:should never reach here, release chttp_node and try to close socket %d\n", sockfd);

    /*free*/
    chttp_node_free(chttp_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;

    return (EC_TRUE);
}

EC_BOOL chttps_node_close(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;
    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))/*on server side*/
    {
        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttp_node);

        if(BIT_TRUE == CHTTP_NODE_KEEPALIVE(chttp_node))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_close: [server] keep-alive, resume socket %d\n", sockfd);

            /*resume*/
            //CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
            chttp_node_wait_resume(chttp_node);
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_close: [server] keep-alive, resume sockfd %d done\n", sockfd);

            return (EC_TRUE);
        }

        /* umount */
        CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

        /*free*/
        chttp_node_free(chttp_node);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;/*trigger socket closing*/

        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node))/*on client side*/
    {
        /* umount */
        CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending http request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0008);
        }

        return (EC_TRUE);

    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))/*on client side*/
    {
        /*not umount*/

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending http request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0009);
        }

        return (EC_TRUE);
    }

    /*should never reacher here!*/

    /* umount */
    CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_close:should never reach here, release chttp_node and try to close socket %d\n", sockfd);

    /*free*/
    chttp_node_free(chttp_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;
    return (EC_TRUE);
}

EC_BOOL chttps_node_timeout(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;

    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    chttp_stat_set_rsp_status(CHTTP_NODE_STAT(chttp_node), CHTTP_GATEWAY_TIMEOUT);

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node)) /*server side*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "[DEBUG] chttps_node_timeout: [server] sockfd %d timeout\n", sockfd);

        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttp_node);

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending http request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_NODE(chttp_node))
        {
            croutine_pool_unload(TASK_REQ_CTHREAD_POOL(task_brd_default_get()), CHTTP_NODE_CROUTINE_NODE(chttp_node));
            CHTTP_NODE_CROUTINE_NODE(chttp_node) = NULL_PTR;
        }

        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node))
        {
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0010);
        }

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_LOOPING(csocket_cnode) = BIT_TRUE;

        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node)) /*client side*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "[DEBUG] chttps_node_timeout: [client] sockfd %d timeout\n", sockfd);

        /* unbind */
        CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0011);
        }

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; /*xxx*/
        return (EC_TRUE);

    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))/*client side*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "[DEBUG] chttps_node_timeout: [check] sockfd %d timeout\n", sockfd);
        /*not unbind*/

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0012);
        }

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
        return (EC_TRUE);
    }

    /*should never reacher here!*/

    /* unbind */
    CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_force_close:should never reach here, release chttp_node and try to close socket %d\n", sockfd);

    /*free*/
    chttp_node_free(chttp_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;
    return (EC_TRUE);
}

EC_BOOL chttps_node_shutdown(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    int sockfd;

    sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node)) /*server side*/
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_shutdown: [server] sockfd %d shutdown\n", sockfd);

        /*umount from defer request queue if necessary*/
        chttps_defer_request_queue_erase(chttp_node);

        /* unbind */
        CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

        /*free*/
        chttp_node_free(chttp_node);

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;

        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node)) /*client side*/
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_shutdown: [client] sockfd %d shutdown\n", sockfd);

        /* unbind */
        CHTTP_NODE_CSOCKET_CNODE(chttp_node) = NULL_PTR;

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0013);
        }

        cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE; /*xxx*/
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))/*client side*/
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_shutdown: [check] sockfd %d shutdown\n", sockfd);
        /*not unbind*/

        /**
         * not free chttp_node but release ccond
         * which will pull routine to the starting point of sending https request
         **/
        if(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node) && BIT_FALSE == CHTTP_NODE_COROUTINE_RESTORE(chttp_node))
        {
            CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_TRUE;
            croutine_cond_release(CHTTP_NODE_CROUTINE_COND(chttp_node), LOC_CHTTPS_0014);
        }

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE;
        return (EC_TRUE);
    }

    /*should never reacher here!*/

    /* unbind */
    CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

    dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_shutdown:should never reach here, release chttp_node and try to close sockfd %d\n", sockfd);

    /*free*/
    chttp_node_free(chttp_node);

    cepoll_del_all(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;

    CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_FALSE;
    return (EC_TRUE);
}

EC_BOOL chttps_node_parse_on_headers_complete(CHTTP_NODE *chttp_node)
{
    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node)
    && NULL_PTR != CHTTP_NODE_STORE(chttp_node))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        chttp_node_adjust_seg_id(chttp_node);
        chttp_node_check_cacheable(chttp_node);

        chttp_node_filter_on_header_complete(chttp_node);

        /*
        *   note:
        *       due to store-procedure is blocking mode, we have to
        *   del RD event temporarily. otherwise, before unblocking,
        *   RD event may be triggered, and http parser will parse the
        *   old data which is not be shifted out yet!
        *
        */

        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;

        /*if need to store recved data to storage and the starting seg is 0, i.e., header*/
        chttp_node_store_on_headers_complete(chttp_node);

        /*
        *   note:
        *       when store has high latency, timeout event would happen and trigger timeout handling,
        *   and then trigger chttp_node free!
        *
        */
        if(EC_TRUE == chttp_node_has_error(chttp_node))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_parse_on_headers_complete: found chttp_node %p has error\n",
                                chttp_node);
            return (EC_FALSE);
        }

        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          (const char *)"csocket_cnode_irecv",
                          (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_parse_on_body(CHTTP_NODE *chttp_node)
{
    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node)
    && NULL_PTR != CHTTP_NODE_STORE(chttp_node)
    && NULL_PTR != CHTTP_NODE_CSOCKET_CNODE(chttp_node))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        /*
        *   note:
        *       due to store-procedure is blocking mode, we have to
        *   del RD event temporarily. otherwise, before unblocking,
        *   RD event may be triggered, and http parser will parse the
        *   old data which is not be shifted out yet!
        *
        */

        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;

        /*after body data was appended to recv_chunks, store recv_chunks to storage*/
        chttp_node_store_on_body(chttp_node);

        /*
        *   note:
        *       when store has high latency, timeout event would happen and trigger timeout handling,
        *   and then trigger chttp_node free!
        *
        */
        if(EC_TRUE == chttp_node_has_error(chttp_node))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_parse_on_body: found chttp_node %p has error\n",
                                chttp_node);
            return (EC_FALSE);
        }

        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          (const char *)"csocket_cnode_irecv",
                          (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
    }

    return (EC_TRUE);
}

EC_BOOL chttps_node_parse_on_message_complete(CHTTP_NODE *chttp_node)
{
    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node)
    && NULL_PTR != CHTTP_NODE_STORE(chttp_node))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        /*
        *   note:
        *       due to store-procedure is blocking mode, we have to
        *   del RD event temporarily. otherwise, before unblocking,
        *   RD event may be triggered, and http parser will parse the
        *   old data which is not be shifted out yet!
        *
        */

        cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;

        /*after body data was appended to recv_chunks, store recv_chunks to storage*/
        /*if need to store recved data to storage and the starting seg is 0, i.e., header*/
        chttp_node_store_on_message_complete(chttp_node);

        /*
        *   note:
        *       when store has high latency, timeout event would happen and trigger timeout handling,
        *   and then trigger chttp_node free!
        *
        */
        if(EC_TRUE == chttp_node_has_error(chttp_node))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_parse_on_message_complete: found chttp_node %p has error\n",
                                chttp_node);
            return (EC_FALSE);
        }

        if(EC_TRUE == chttp_node_is_chunked(chttp_node)
        && NULL_PTR != CHTTP_NODE_STORE(chttp_node))
        {
            CHTTP_STORE     *chttp_store;

            chttp_store = CHTTP_NODE_STORE(chttp_node);

            if(CHTTP_STORE_CACHE_HEADER & CHTTP_STORE_CACHE_DONE(chttp_store))
            {
                chttp_node_renew_content_length(chttp_node, chttp_store, CHTTP_NODE_BODY_PARSED_LEN(chttp_node));
            }
        }
#if 0
        cepoll_set_event(task_brd_default_get_cepoll(),
                          CSOCKET_CNODE_SOCKFD(csocket_cnode),
                          CEPOLL_RD_EVENT,
                          (const char *)"csocket_cnode_irecv",
                          (CEPOLL_EVENT_HANDLER)csocket_cnode_irecv,
                          (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
#endif
    }

    return (EC_TRUE);
}
EC_BOOL chttps_node_recv(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    CBUFFER *http_in_buffer;
    UINT32   pos;
    EC_BOOL  ret;

    http_in_buffer = CHTTP_NODE_IN_BUF(chttp_node);

    pos = CBUFFER_USED(http_in_buffer);
    ret = chttps_recv(chttp_node,
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
        __chttps_on_recv_complete(chttp_node);

        if(EC_TRUE == csocket_cnode_is_connected(csocket_cnode))
        {
            if(BIT_TRUE == CSOCKET_CNODE_NONBLOCK(csocket_cnode))
            {
                return (EC_DONE);/*no more data to recv*/
            }
            /*block mode*/
            return (EC_TRUE);/*no more data to recv*/
        }

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                            "warn:chttps_node_recv: read nothing on sockfd %d (%s) where buffer size %d and used %d\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),  csocket_cnode_tcpi_stat_desc(csocket_cnode),
                            CBUFFER_SIZE(http_in_buffer),
                            CBUFFER_USED(http_in_buffer));

        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT,
                        "[DEBUG] chttps_node_recv: read %u bytes on sockfd %d (%s) where buffer size %d and used %d\n",
                        (((uint32_t)pos) - CBUFFER_USED(http_in_buffer)),
                        CSOCKET_CNODE_SOCKFD(csocket_cnode),  csocket_cnode_tcpi_stat_desc(csocket_cnode),
                        CBUFFER_SIZE(http_in_buffer),
                        CBUFFER_USED(http_in_buffer));

    /*statistics*/
    CHTTP_NODE_S_RECV_LEN_INC(chttp_node, (((uint32_t)pos) - CBUFFER_USED(http_in_buffer)));

    CBUFFER_USED(http_in_buffer) = (uint32_t)pos;
    return (EC_TRUE);
}

EC_BOOL chttps_node_send(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    CHUNK_MGR                *send_chunks;
    EC_BOOL                   data_sent_flag;

    send_chunks = CHTTP_NODE_SEND_BUF(chttp_node);

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
        ret = chttps_send(chttp_node, csocket_cnode, CHUNK_DATA(chunk), CHUNK_USED(chunk), &pos);
        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_send: sockfd %d send %d bytes failed\n",
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
        CHTTP_NODE_S_SEND_LEN_INC(chttp_node, (((uint32_t)pos) - CHUNK_OFFSET(chunk)));

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

#if (SWITCH_OFF == NGX_BGN_SWITCH)
    if(EC_FALSE == csocket_listen(srv_ipaddr, srv_port, &srv_sockfd))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDERR, "error:chttps_srv_start: failed to listen on port %s:%ld\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port);
        return (NULL_PTR);
    }
#endif/*(SWITCH_OFF == NGX_BGN_SWITCH)*/

#if (SWITCH_ON == NGX_BGN_SWITCH)
    while(EC_FALSE == csocket_listen(srv_ipaddr, srv_port, &srv_sockfd))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDERR, "error:chttps_srv_start: failed to listen on port %s:%ld, retry again\n",
                            c_word_to_ipv4(srv_ipaddr), srv_port);
        c_usleep(1, LOC_CHTTPS_0015);
    }
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

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
    if(NULL_PTR != csrv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "[DEBUG] chttps_srv_end: close srv sockfd %d on %s:%ld\n",
                                              CSRV_SOCKFD(csrv),
                                              c_word_to_ipv4(CSRV_IPADDR(csrv)),
                                              CSRV_PORT(csrv));

        return csrv_free(csrv);
    }

    return (EC_TRUE);
}

EC_BOOL chttps_srv_bind_modi(CSRV *csrv, const UINT32 modi)
{
    CSRV_MD_ID(csrv) = modi;

    return (EC_TRUE);
}

EC_BOOL chttps_srv_accept_once(CSRV *csrv, EC_BOOL *continue_flag)
{
    UINT32  client_ipaddr;
    UINT32  client_port;
    EC_BOOL ret;
    int     client_conn_sockfd;

    ret = csocket_accept(CSRV_SOCKFD(csrv), &(client_conn_sockfd), CSOCKET_IS_NONBLOCK_MODE, &(client_ipaddr), &(client_port));
    if(EC_TRUE == ret)
    {
        CSOCKET_CNODE  *csocket_cnode;
        CHTTP_NODE    *chttp_node;

        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_srv_accept_once: handle new sockfd %d\n", client_conn_sockfd);

        csocket_cnode = csocket_cnode_new(LOC_CHTTPS_0016);/*here do not know the remote client srv port*/
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_accept_once:failed to alloc csocket cnode for sockfd %d, hence close it\n", client_conn_sockfd);
            csocket_close(client_conn_sockfd);
            return (EC_FALSE);
        }

        CSOCKET_CNODE_SOCKFD(csocket_cnode) = client_conn_sockfd;
        CSOCKET_CNODE_TYPE(csocket_cnode )  = CSOCKET_TYPE_TCP;
        CSOCKET_CNODE_IPADDR(csocket_cnode) = client_ipaddr;
        CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)    = client_port;

        chttp_node = chttp_node_new(CHTTP_TYPE_DO_SRV_REQ);
        if(NULL_PTR == chttp_node)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_srv_accept_once: new chttp_node for sockfd %d failed\n", client_conn_sockfd);
            csocket_cnode_close(csocket_cnode);
            return (EC_FALSE);
        }

        CHTTP_NODE_LOG_TIME_WHEN_START(chttp_node); /*record start time*/

        /*mount csrv*/
        CHTTP_NODE_CSRV(chttp_node) = (void *)csrv;

        /*mount csocket_cnode*/
        CHTTP_NODE_CSOCKET_CNODE(chttp_node) = csocket_cnode;

        chttp_node_init_parser(chttp_node);

        if(SWITCH_ON == HIGH_PRECISION_TIME_SWITCH)
        {
            task_brd_update_time_default();
        }
        CTMV_CLONE(task_brd_default_get_daytime(), CHTTP_NODE_START_TMV(chttp_node));

        CSOCKET_CNODE_MODI(csocket_cnode) = CSRV_MD_ID(csrv);

        chttps_node_set_socket_callback(chttp_node, csocket_cnode);
        chttps_node_set_socket_epoll(chttp_node, csocket_cnode);

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
EC_BOOL chttps_commit_error_response(CHTTP_NODE *chttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_commit_error_response: csocket_cnode of chttp_node %p is null\n", chttp_node);
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

EC_BOOL chttps_commit_error_request(CHTTP_NODE *chttp_node)
{
    /*cleanup request body and response body*/
    chttp_node_recv_clean(chttp_node);
    cbytes_clean(CHTTP_NODE_CONTENT_CBYTES(chttp_node));

    if(EC_FALSE == chttp_make_error_response(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_commit_error_request: make error response failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chttps_commit_error_response(chttp_node))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_commit_error_request: commit error response failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


/*---------------------------------------- REQUEST REST LIST MANAGEMENT ----------------------------------------*/

EC_BOOL chttps_rest_list_push(const char *name, EC_BOOL (*commit)(CHTTP_NODE *))
{
    CHTTP_REST *chttps_rest;
    CHTTP_REST *chttps_rest_t;

    if(NULL_PTR == g_chttps_rest_list)
    {
        g_chttps_rest_list = clist_new(MM_CHTTP_REST, LOC_CHTTPS_0017);
        if(NULL_PTR == g_chttps_rest_list)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_rest_list_push: new rest list failed\n");
            return (NULL_PTR);
        }
    }

    chttps_rest = chttp_rest_new();
    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_rest_list_push: new chttps_rest failed\n");
        return (NULL_PTR);
    }

    CHTTP_REST_NAME(chttps_rest)   = name;
    CHTTP_REST_LEN(chttps_rest)    = strlen(name);
    CHTTP_REST_COMMIT(chttps_rest) = commit;

    chttps_rest_t = (CHTTP_REST *)clist_search_data_back(g_chttps_rest_list, (void *)chttps_rest,
                                                    (CLIST_DATA_DATA_CMP)chttp_rest_cmp);
    if(NULL_PTR != chttps_rest_t)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_push: already exist rest %p ('%.*s', %p)\n",
                    chttps_rest_t,
                    CHTTP_REST_LEN(chttps_rest), CHTTP_REST_NAME(chttps_rest),
                    CHTTP_REST_COMMIT(chttps_rest));
        chttp_rest_free(chttps_rest);
        return (EC_TRUE);
    }

    clist_push_back(g_chttps_rest_list, (void *)chttps_rest);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_push: push rest %p ('%s', %p) done\n",
                    chttps_rest, name, commit);

    return (EC_TRUE);
}

CHTTP_REST *chttps_rest_list_pop(const char *name, const uint32_t len)
{
    CHTTP_REST   chttps_rest_t;
    CHTTP_REST  *chttps_rest;

    if(NULL_PTR == g_chttps_rest_list)
    {
        dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "warn:chttps_rest_list_pop: rest list is null\n");
        return (NULL_PTR);
    }

    CHTTP_REST_NAME(&chttps_rest_t)   = name;
    CHTTP_REST_LEN(&chttps_rest_t)    = len;
    CHTTP_REST_COMMIT(&chttps_rest_t) = NULL_PTR;

    chttps_rest = (CHTTP_REST *)clist_del(g_chttps_rest_list, (void *)&chttps_rest_t,
                                            (CLIST_DATA_DATA_CMP)chttp_rest_cmp);

    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_pop: not found rest of '%.*s'\n",
                    len, name);
        return (NULL_PTR);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_pop: found rest %p of ('%.*s', %p)\n",
                    chttps_rest,
                    CHTTP_REST_LEN(chttps_rest), CHTTP_REST_NAME(chttps_rest),
                    CHTTP_REST_COMMIT(chttps_rest));

    return (chttps_rest);
}

CHTTP_REST *chttps_rest_list_find(const char *name, const uint32_t len)
{
    CHTTP_REST   chttps_rest_t;
    CHTTP_REST  *chttps_rest;

    if(NULL_PTR == g_chttps_rest_list)
    {
        dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "warn:chttps_rest_list_find: rest list is null\n");
        return (NULL_PTR);
    }

    CHTTP_REST_NAME(&chttps_rest_t)   = name;
    CHTTP_REST_LEN(&chttps_rest_t)    = len;
    CHTTP_REST_COMMIT(&chttps_rest_t) = NULL_PTR;

    chttps_rest = (CHTTP_REST *)clist_search_data_back(g_chttps_rest_list, (void *)&chttps_rest_t,
                                                        (CLIST_DATA_DATA_CMP)chttp_rest_cmp);

    if(NULL_PTR == chttps_rest)
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_find: not found rest of '%.*s'\n",
                    len, name);
        return (NULL_PTR);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rest_list_find: found rest %p of ('%.*s', %p)\n",
                    chttps_rest,
                    CHTTP_REST_LEN(chttps_rest),CHTTP_REST_NAME(chttps_rest),
                    CHTTP_REST_COMMIT(chttps_rest));

    return (chttps_rest);
}


/*---------------------------------------- REQUEST DEFER QUEUE MANAGEMENT ----------------------------------------*/
EC_BOOL chttps_defer_request_queue_init()
{
    if(EC_FALSE == g_chttps_defer_request_queue_init_flag)
    {
        cqueue_init(&g_chttps_defer_request_queue, MM_CHTTP_NODE, LOC_CHTTPS_0018);

        if(EC_FALSE == cepoll_set_loop_handler(task_brd_default_get_cepoll(),
                                                (const char *)"chttps_defer_request_queue_launch",
                                               (CEPOLL_LOOP_HANDLER)chttps_defer_request_queue_launch,
                                               chttps_defer_request_commit))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_defer_request_queue_init: set cepoll loop handler failed\n");
            return (EC_FALSE);
        }
    }

    g_chttps_defer_request_queue_init_flag = EC_TRUE;
    return (EC_TRUE);
}

EC_BOOL chttps_defer_request_queue_clean()
{
    cqueue_clean(&g_chttps_defer_request_queue, (CQUEUE_DATA_DATA_CLEANER)chttp_node_free);
    return (EC_TRUE);
}

/**
*
* WARNING:
*
*   chttps_defer_request_queue_init is called in RFS module,
*   but chttps_defer_request_queue_is_empty is checked in task_brd_check_and_notify
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

EC_BOOL chttps_defer_request_queue_push(CHTTP_NODE *chttp_node)
{
    CQUEUE_DATA *cqueue_data;

    cqueue_data = cqueue_push(&g_chttps_defer_request_queue, (void *)chttp_node);
    CHTTP_NODE_CQUEUE_DATA(chttp_node) = cqueue_data;
    return (EC_TRUE);
}

EC_BOOL chttps_defer_request_queue_erase(CHTTP_NODE *chttp_node)
{
    CQUEUE_DATA *cqueue_data;

    cqueue_data = CHTTP_NODE_CQUEUE_DATA(chttp_node);
    if(NULL_PTR != cqueue_data)
    {
        cqueue_erase(&g_chttps_defer_request_queue, cqueue_data);
        CHTTP_NODE_CQUEUE_DATA(chttp_node) = NULL_PTR;
    }
    return (EC_TRUE);
}

CHTTP_NODE *chttps_defer_request_queue_pop()
{
    CHTTP_NODE *chttp_node;

    chttp_node = (CHTTP_NODE *)cqueue_pop(&g_chttps_defer_request_queue);
    CHTTP_NODE_CQUEUE_DATA(chttp_node) = NULL_PTR;
    return (chttp_node);
}

CHTTP_NODE *chttps_defer_request_queue_peek()
{
    return (CHTTP_NODE *)cqueue_front(&g_chttps_defer_request_queue);
}

EC_BOOL chttps_defer_request_commit(CHTTP_NODE *chttp_node)
{
    CBUFFER         *uri_cbuffer;
    CHTTP_REST     *chttps_rest;
    const char      *rest_name;
    uint32_t         rest_len;

    uri_cbuffer  = CHTTP_NODE_URI(chttp_node);

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
                    CHTTP_REST_LEN(chttps_rest),CHTTP_REST_NAME(chttps_rest),
                    CHTTP_REST_COMMIT(chttps_rest));

    /*shift out rest tag*/
    cbuffer_left_shift_out(uri_cbuffer, NULL_PTR, rest_len);
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_defer_request_commit: after left shift out rest tag, uri: '%.*s' [len %d]\n",
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    return CHTTP_REST_COMMIT(chttps_rest)(chttp_node);
}

EC_BOOL chttps_defer_request_queue_launch(CHTTP_NODE_COMMIT_REQUEST chttps_node_commit_request)
{
    CHTTP_NODE *chttp_node;
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

        chttp_node = chttps_defer_request_queue_peek();
        if(NULL_PTR == chttp_node)/*no more*/
        {
            break;
        }

        ret = chttps_defer_request_commit(chttp_node);

        /*ret = chttps_node_commit_request(chttp_node);*//*call back*/
        if(EC_BUSY == ret)/*okay, no routine resource to load this task, terminate and wait for next time try*/
        {
            break;
        }

        /*pop it when everything ok or some unknown scenario happen*/
        chttps_defer_request_queue_pop();

        if(EC_FALSE == ret)/*Oops! found unknown request, dicard it now*/
        {
            if(NULL_PTR != CHTTP_NODE_CSOCKET_CNODE(chttp_node))
            {
                CSOCKET_CNODE *csocket_cnode;
                int            sockfd;

                csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);
                sockfd = CSOCKET_CNODE_SOCKFD(csocket_cnode);/*csocket_cnode will be cleanup, save sockfd at first*/

                CHTTP_NODE_KEEPALIVE(chttp_node) = BIT_FALSE; /*force to close the httpss connection*/

                chttps_node_disconnect(chttp_node);

                cepoll_clear_node(task_brd_default_get_cepoll(), sockfd);
            }

            chttp_node_free(chttp_node);
        }

        /*handle next request*/
    }
    return (EC_TRUE);
}

/*---------------------------------------- HTTP RESPONSE PASER INTERFACE ----------------------------------------*/
STATIC_CAST static int __chttps_rsp_on_message_begin(http_parser_t* http_parser)
{
    CHTTP_RSP *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_message_begin: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_rsp_on_message_begin: chttp_rsp %p, ***MESSAGE BEGIN***\n",
                    chttp_rsp);
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
STATIC_CAST static int __chttps_rsp_on_headers_complete(http_parser_t* http_parser, const char* last, size_t length)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_headers_complete: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    return (0);/*succ*/
}

STATIC_CAST static int __chttps_rsp_on_message_complete(http_parser_t* http_parser)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_message_complete: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_rsp_on_message_complete: ***MESSAGE COMPLETE***\n");
    return (0);
}

STATIC_CAST static int __chttps_rsp_on_url(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_url: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    return (0);
}

/*only for http response*/
STATIC_CAST static int __chttps_rsp_on_status(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP     *chttp_rsp;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_status: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    CHTTP_RSP_STATUS(chttp_rsp) = http_parser->status_code;

    return (0);
}

STATIC_CAST static int __chttps_rsp_on_header_field(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;
    CSTRKV       *cstrkv;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_header_field: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_header_field: new cstrkv failed where header field: %.*s\n",
                           (uint32_t)length, at);
        return (-1);
    }

    cstrkv_set_key_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CHTTPS_0019);
    cstrkv_mgr_add_kv(CHTTP_RSP_HEADER(chttp_rsp), cstrkv);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_rsp_on_header_field: chttp_rsp %p, Header field: '%.*s'\n", chttp_rsp, (uint32_t)length, at);
    return (0);
}

STATIC_CAST static int __chttps_rsp_on_header_value(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;
    CSTRKV       *cstrkv;

    chttp_rsp = (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_header_value: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    cstrkv = cstrkv_mgr_last_kv(CHTTP_RSP_HEADER(chttp_rsp));
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_header_value: no cstrkv existing where value field: %.*s\n",
                           (uint32_t)length, at);
        return (-1);
    }

    cstrkv_set_val_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length, LOC_CHTTPS_0020);
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_rsp_on_header_value: chttp_rsp %p, Header value: '%.*s'\n", chttp_rsp, (uint32_t)length, at);

    return (0);
}

STATIC_CAST static int __chttps_rsp_on_body(http_parser_t* http_parser, const char* at, size_t length)
{
    CHTTP_RSP    *chttp_rsp;

    chttp_rsp= (CHTTP_RSP *)http_parser->data;
    if(NULL_PTR == chttp_rsp)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_body: http_parser %p -> chttp_rsp is null\n", http_parser);
        return (-1);/*error*/
    }

    if(EC_FALSE == cbytes_append(CHTTP_RSP_BODY(chttp_rsp), (uint8_t *)at, length))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_rsp_on_body: append %ld bytes failed\n", length);
        return (-1);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_rsp_on_body: chttp_rsp %p, len %ld => body parsed %ld\n",
                    chttp_rsp, length, CBYTES_LEN(CHTTP_RSP_BODY(chttp_rsp)));
    return (0);
}


/*
*   decode http response from cbytes.
*/
EC_BOOL chttps_rsp_decode(CHTTP_RSP *chttp_rsp, const uint8_t *data, const uint32_t data_len)
{
    http_parser_t           http_parser;
    http_parser_settings_t  http_parser_setting;

    uint8_t                *ch;

    uint32_t                header_len;
    uint32_t                body_len;
    uint32_t                parsed_len;
    uint32_t                flag;

    /*check validity*/
    if(4 >= data_len)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_rsp_decode: invalid data_len %u\n", data_len);
        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rsp_decode: data_len %u\n", data_len);

    flag = BIT_FALSE;
    for(ch = (uint8_t *)data, header_len = 0; header_len <= data_len - 4; ch ++, header_len ++)
    {
        if('\r' == ch[ 0 ] && '\n' == ch[ 1 ] && '\r' == ch[ 2 ] && '\n' == ch[ 3 ])
        {
            flag = BIT_TRUE;
            break;
        }
    }

    if(BIT_FALSE == flag)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_rsp_decode: invalid header '%.*s'\n", data_len, (char *)data);
        return (EC_FALSE);
    }

    header_len += 4;
    body_len    = data_len - header_len;

    http_parser_init(&http_parser, HTTP_RESPONSE);
    http_parser.data  = (void *)chttp_rsp;

    if(5 < data_len
    && 'H' == data[0] && 'T' == data[1] && 'T' == data[2] && 'P' == data[3] && '/' == data[4])
    {
        http_parser.state = s_start_res;
    }
    else
    {
        http_parser.state = s_header_field; /*no heading line likes as 'HTTP/1.1 200 OK'*/
    }

    http_parser_setting.on_message_begin    = __chttps_rsp_on_message_begin;
    http_parser_setting.on_url              = __chttps_rsp_on_url;
    http_parser_setting.on_status           = __chttps_rsp_on_status;
    http_parser_setting.on_header_field     = __chttps_rsp_on_header_field;
    http_parser_setting.on_header_value     = __chttps_rsp_on_header_value;
    http_parser_setting.on_headers_complete = __chttps_rsp_on_headers_complete;
    http_parser_setting.on_body             = __chttps_rsp_on_body;
    http_parser_setting.on_message_complete = __chttps_rsp_on_message_complete;


    parsed_len = http_parser_execute(&http_parser, &http_parser_setting, (char *)data, header_len);
    /*check parser error*/
    if(HPE_OK != HTTP_PARSER_ERRNO(&http_parser)
    && HPE_PAUSED != HTTP_PARSER_ERRNO(&http_parser)
    && HPE_CLOSED_CONNECTION != HTTP_PARSER_ERRNO(&http_parser)
    )
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT,
                            "error:chttps_rsp_decode: http parser encounter error where errno = %d, name = %s, description = %s, [%.*s]\n",
                            HTTP_PARSER_ERRNO(&http_parser),
                            http_errno_name(HTTP_PARSER_ERRNO(&http_parser)),
                            http_errno_description(HTTP_PARSER_ERRNO(&http_parser)),
                            DMIN(data_len, 300), (char *)data
                            );
        return (EC_FALSE);
    }

    if(0 < body_len)
    {
        cbytes_append(CHTTP_RSP_BODY(chttp_rsp), data + header_len, body_len);
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_rsp_decode: parsed_len = %u, header_len %u, body_len %u\n",
                    parsed_len, header_len, body_len);

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_rsp_decode: decoded rsp:\n");
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}


/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Send Http Request and Handle Http Response
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_node_set_parse_callback(CHTTP_NODE *chttp_node)
{
    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))
    {
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node))
    {
        if(NULL_PTR == CHTTP_NODE_STORE(chttp_node))
        {
            return (EC_TRUE);
        }

        ccallback_list_push(CHTTP_NODE_PARSE_ON_HEADERS_COMPLETE_CALLBACK_LIST(chttp_node),
                            (const char *)"chttps_node_parse_on_headers_complete",
                            (UINT32)chttp_node,
                            (UINT32)chttps_node_parse_on_headers_complete);

        ccallback_list_push(CHTTP_NODE_PARSE_ON_BODY_CALLBACK_LIST(chttp_node),
                            (const char *)"chttps_node_parse_on_body",
                            (UINT32)chttp_node,
                            (UINT32)chttps_node_parse_on_body);

        ccallback_list_push(CHTTP_NODE_PARSE_ON_MESSAGE_COMPLETE_CALLBACK_LIST(chttp_node),
                            (const char *)"chttps_node_parse_on_message_complete",
                            (UINT32)chttp_node,
                            (UINT32)chttps_node_parse_on_message_complete);
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}
EC_BOOL chttps_node_set_socket_callback(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))
    {
        csocket_cnode_push_recv_callback(csocket_cnode,
                                         (const char *)"chttps_node_handshake_on_server",
                                         (UINT32)chttp_node, (UINT32)chttps_node_handshake_on_server);

        csocket_cnode_push_recv_callback(csocket_cnode,
                                         (const char *)"chttps_node_recv_req",
                                         (UINT32)chttp_node, (UINT32)chttps_node_recv_req);

        csocket_cnode_push_send_callback(csocket_cnode,
                                         (const char *)"chttps_node_handshake_on_client",
                                         (UINT32)chttp_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_send_callback(csocket_cnode,
                                         (const char *)"chttps_node_send_rsp",
                                         (UINT32)chttp_node, (UINT32)chttps_node_send_rsp);

        csocket_cnode_push_complete_callback(csocket_cnode,
                                         (const char *)"chttps_node_complete",
                                         (UINT32)chttp_node, (UINT32)chttps_node_complete);

        csocket_cnode_push_close_callback(csocket_cnode,
                                         (const char *)"chttps_node_close",
                                         (UINT32)chttp_node, (UINT32)chttps_node_close);

        csocket_cnode_push_timeout_callback(csocket_cnode,
                                         (const char *)"chttps_node_timeout",
                                         (UINT32)chttp_node, (UINT32)chttps_node_timeout);

        csocket_cnode_push_shutdown_callback(csocket_cnode,
                                         (const char *)"chttps_node_shutdown",
                                         (UINT32)chttp_node, (UINT32)chttps_node_shutdown);
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node))
    {
        csocket_cnode_push_recv_callback(csocket_cnode,
                                         (const char *)"chttps_node_handshake_on_client",
                                         (UINT32)chttp_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_recv_callback(csocket_cnode,
                                         (const char *)"chttps_node_recv_rsp",
                                         (UINT32)chttp_node, (UINT32)chttps_node_recv_rsp);

        csocket_cnode_push_send_callback(csocket_cnode,
                                         (const char *)"chttps_node_handshake_on_client",
                                         (UINT32)chttp_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_send_callback(csocket_cnode,
                                         (const char *)"chttps_node_send_req",
                                         (UINT32)chttp_node, (UINT32)chttps_node_send_req);

        csocket_cnode_push_complete_callback(csocket_cnode,
                                         (const char *)"chttps_node_complete",
                                         (UINT32)chttp_node, (UINT32)chttps_node_complete);

        csocket_cnode_push_close_callback(csocket_cnode,
                                         (const char *)"chttps_node_close",
                                         (UINT32)chttp_node, (UINT32)chttps_node_close);

        csocket_cnode_push_timeout_callback(csocket_cnode,
                                         (const char *)"chttps_node_timeout",
                                         (UINT32)chttp_node, (UINT32)chttps_node_timeout);

        csocket_cnode_push_shutdown_callback(csocket_cnode,
                                         (const char *)"chttps_node_shutdown",
                                         (UINT32)chttp_node, (UINT32)chttps_node_shutdown);
        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))
    {
#if 0
        csocket_cnode_push_recv_callback(csocket_cnode,
                                         (const char *)"chttps_node_handshake_on_client",
                                         (UINT32)chttp_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_recv_callback(csocket_cnode,
                                         (const char *)"chttps_node_recv_rsp",
                                         (UINT32)chttp_node, (UINT32)chttps_node_recv_rsp);
#endif
        csocket_cnode_push_send_callback(csocket_cnode,
                                         (const char *)"chttps_node_handshake_on_client",
                                         (UINT32)chttp_node, (UINT32)chttps_node_handshake_on_client);

        csocket_cnode_push_send_callback(csocket_cnode,
                                         (const char *)"chttps_node_icheck",
                                         (UINT32)chttp_node, (UINT32)chttps_node_icheck);

        csocket_cnode_push_close_callback(csocket_cnode,
                                         (const char *)"chttps_node_close",
                                         (UINT32)chttp_node, (UINT32)chttps_node_close);

        csocket_cnode_push_timeout_callback(csocket_cnode,
                                         (const char *)"chttps_node_timeout",
                                         (UINT32)chttp_node, (UINT32)chttps_node_timeout);

        csocket_cnode_push_shutdown_callback(csocket_cnode,
                                         (const char *)"chttps_node_shutdown",
                                         (UINT32)chttp_node, (UINT32)chttps_node_shutdown);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chttps_node_set_socket_epoll(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    uint32_t    timeout_nsec;

    if(NULL_PTR != CHTTP_NODE_STORE(chttp_node))
    {
        timeout_nsec = CHTTP_STORE_ORIG_TIMEOUT_NSEC(CHTTP_NODE_STORE(chttp_node));
    }
    else
    {
        timeout_nsec = (uint32_t)CHTTP_SOCKET_TIMEOUT_NSEC;
    }

    if(CHTTP_TYPE_DO_SRV_REQ == CHTTP_NODE_TYPE(chttp_node))
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
                           timeout_nsec,
                        (const char *)"csocket_cnode_itimeout",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                        (void *)csocket_cnode);

        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_RSP == CHTTP_NODE_TYPE(chttp_node))
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
                        timeout_nsec,
                        (const char *)"csocket_cnode_itimeout",
                        (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                        (void *)csocket_cnode);

        return (EC_TRUE);
    }

    if(CHTTP_TYPE_DO_CLT_CHK == CHTTP_NODE_TYPE(chttp_node))
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
                       timeout_nsec,
                       (const char *)"csocket_cnode_itimeout",
                       (CEPOLL_EVENT_HANDLER)csocket_cnode_itimeout,
                       (void *)csocket_cnode);

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL chttps_node_connect(CHTTP_NODE *chttp_node, const UINT32 csocket_block_mode, const UINT32 ipaddr, const UINT32 port)
{
    CSOCKET_CNODE *csocket_cnode;
    CCONNP_MGR    *cconnp_mgr;

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_connect: connect server %s:%ld >>>\n",
                        c_word_to_ipv4(ipaddr), port);

    cconnp_mgr = task_brd_default_get_http_cconnp_mgr();
    if(NULL_PTR != cconnp_mgr
    && NULL_PTR != (csocket_cnode = cconnp_mgr_reserve(cconnp_mgr, CMPI_ANY_TCID, ipaddr, port)))
    {
        /*optimize for the latest loaded config*/
        csocket_optimize(CSOCKET_CNODE_SOCKFD(csocket_cnode), csocket_block_mode);
    }
    else
    {
        UINT32         client_ipaddr;
        UINT32         client_port;
        int            sockfd;

        if(EC_FALSE == csocket_connect(ipaddr, port , csocket_block_mode, &sockfd, &client_ipaddr, &client_port))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_connect: connect server %s:%ld failed\n",
                                c_word_to_ipv4(ipaddr), port);

            chttp_stat_set_rsp_status(CHTTP_NODE_STAT(chttp_node), CHTTP_BAD_GATEWAY);
            return (EC_FALSE);
        }

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_connect: socket %d connecting to server %s:%ld\n",
                            sockfd, c_word_to_ipv4(ipaddr), port);

        if(EC_FALSE == csocket_is_connected(sockfd))/*not adaptive to unix domain socket*/
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_connect: socket %d to server %s:%ld is not connected\n",
                            sockfd, c_word_to_ipv4(ipaddr), port);
            csocket_close(sockfd);

            chttp_stat_set_rsp_status(CHTTP_NODE_STAT(chttp_node), CHTTP_BAD_GATEWAY);
            return (EC_FALSE);
        }

        if(do_log(SEC_0157_CHTTPS, 5))
        {
            sys_log(LOGSTDOUT, "[DEBUG] chttps_connect: client tcp stat:\n");
            csocket_tcpi_stat_print(LOGSTDOUT, sockfd);
        }

        csocket_cnode = csocket_cnode_new(LOC_CHTTPS_0021);
        if(NULL_PTR == csocket_cnode)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_connect:new csocket cnode for socket %d to server %s:%ld failed\n",
                            sockfd, c_word_to_ipv4(ipaddr), port);
            csocket_close(sockfd);

            chttp_stat_set_rsp_status(CHTTP_NODE_STAT(chttp_node), CHTTP_INTERNAL_SERVER_ERROR);
            return (EC_FALSE);
        }
        CSOCKET_CNODE_TCID(csocket_cnode)           = CMPI_ANY_TCID;
        CSOCKET_CNODE_SOCKFD(csocket_cnode)         = sockfd;
        CSOCKET_CNODE_TYPE(csocket_cnode )          = CSOCKET_TYPE_TCP;
        CSOCKET_CNODE_IPADDR(csocket_cnode)         = ipaddr;
        CSOCKET_CNODE_SRVPORT(csocket_cnode)        = port;
        CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode)  = client_ipaddr;
        CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)    = client_port;

        CSOCKET_CNODE_REUSING(csocket_cnode) = BIT_TRUE; /*push it to connection pool after used*/
    }

    if(CSOCKET_IS_BLOCK_MODE == csocket_block_mode)
    {
        CSOCKET_CNODE_NONBLOCK(csocket_cnode) = BIT_FALSE;
    }

    if(CSOCKET_IS_NONBLOCK_MODE == csocket_block_mode)
    {
        /*set connection pool callback*/
        csocket_cnode_push_close_callback(csocket_cnode,
                                     (const char *)"cconnp_mgr_release",
                                     (UINT32)task_brd_default_get_http_cconnp_mgr(),
                                     (UINT32)cconnp_mgr_release);

        csocket_cnode_push_complete_callback(csocket_cnode,
                                     (const char *)"cconnp_mgr_release",
                                     (UINT32)task_brd_default_get_http_cconnp_mgr(),
                                     (UINT32)cconnp_mgr_release);
    }
    /* mount */
    CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = csocket_cnode;

    return (EC_TRUE);
}

/*disconnect socket connection*/
EC_BOOL chttps_node_disconnect(CHTTP_NODE *chttp_node)
{
    if(NULL_PTR != CHTTP_NODE_CSOCKET_CNODE(chttp_node))
    {
        CSOCKET_CNODE *csocket_cnode;

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        /*umount csocket_cnode and chttp_node*/
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

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

EC_BOOL chttps_node_handshake_on_client(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    EC_BOOL      ret;

    if(CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE & CHTTP_NODE_SSL_STATUS(chttp_node))
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
    if(NULL_PTR == CHTTP_NODE_CSSL_NODE(chttp_node))
    {
        CSSL_NODE   *cssl_node;
        const char  *ca_file;
        const char  *client_cert_file;
        const char  *client_privkey_file;

        ca_file             = (const char *)cstring_get_str(CHTTP_NODE_CA_FILE(chttp_node));
        client_cert_file    = (const char *)cstring_get_str(CHTTP_NODE_CLIENT_CERT_FILE(chttp_node));
        client_privkey_file = (const char *)cstring_get_str(CHTTP_NODE_CLIENT_PRIVKEY_FILE(chttp_node));

        cssl_node = cssl_node_make_on_client(CSOCKET_CNODE_SOCKFD(csocket_cnode), ca_file, client_cert_file, client_privkey_file);
        if(NULL_PTR == cssl_node)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_client: new cssl_node failed\n");
            return (EC_FALSE);
        }

        /*mount chttp_node and cssl_node*/
        CHTTP_NODE_CSSL_NODE(chttp_node) = cssl_node;

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_client: sockfd %d, bind chttp_node and cssl_node done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
    }

    /* handshake */
    ret = cssl_node_handshake(CHTTP_NODE_CSSL_NODE(chttp_node));
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_client: sockfd %d, ssl connect failed\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(EC_TRUE == ret)
    {
        CHTTP_NODE_SSL_STATUS(chttp_node) = CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE;

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_client: sockfd %d, ssl connect done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));

        if(do_log(SEC_0157_CHTTPS, 9))
        {
            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_client: certificate is\n");
            cssl_node_print_certificate(LOGSTDOUT, CHTTP_NODE_CSSL_NODE(chttp_node));
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


EC_BOOL chttps_node_handshake_on_server(CHTTP_NODE *chttp_node, CSOCKET_CNODE *csocket_cnode)
{
    CSRV        *csrv;
    EC_BOOL      ret;

    if(CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE & CHTTP_NODE_SSL_STATUS(chttp_node))
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == csocket_cnode_is_connected(csocket_cnode))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    csrv = (CSRV *)CHTTP_NODE_CSRV(chttp_node);
    if(NULL_PTR == csrv)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d, chttp_node => csrv is null\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    /*handshake may be more than once*/
    if(NULL_PTR == CHTTP_NODE_CSSL_NODE(chttp_node))
    {
        CSSL_NODE *cssl_node;

        cssl_node = cssl_node_make_on_server(CSRV_CSSL_NODE(csrv), CSOCKET_CNODE_SOCKFD(csocket_cnode));
        if(NULL_PTR == cssl_node)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d, make cssl_node on server failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode));

            return (EC_FALSE);
        }

        /*bind chttp_node and cssl_node*/
        CHTTP_NODE_CSSL_NODE(chttp_node) = cssl_node;

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_handshake_on_server: sockfd %d, bind chttp_node and cssl_node done\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));
    }

    /* handshake */
    ret = cssl_node_handshake(CHTTP_NODE_CSSL_NODE(chttp_node));
    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_handshake_on_server: sockfd %d, ssl handshake failed\n",
                    CSOCKET_CNODE_SOCKFD(csocket_cnode));

        return (EC_FALSE);
    }

    if(EC_TRUE == ret)
    {
        CHTTP_NODE_SSL_STATUS(chttp_node) = CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE;

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

EC_BOOL chttps_node_detach(CHTTP_NODE *chttp_node)
{
    CROUTINE_COND *croutine_cond;

    uint64_t       rsp_body_len;

    ASSERT(NULL_PTR != CHTTP_NODE_CROUTINE_COND(chttp_node));

    croutine_cond = CHTTP_NODE_CROUTINE_COND(chttp_node);

    ASSERT(0 == COROUTINE_COND_COUNTER(croutine_cond));

    CHTTP_NODE_COROUTINE_RESTORE(chttp_node) = BIT_FALSE; /*reset to false*/

    croutine_cond_reserve(croutine_cond, 1, LOC_CHTTPS_0022);
    croutine_cond_wait(croutine_cond, LOC_CHTTPS_0023);

    /**
     *  when come back, check CHTTP_NODE_RECV_COMPLETE flag.
     *  if false, exception happened. and return false
     **/
    if(BIT_FALSE == CHTTP_NODE_RECV_COMPLETE(chttp_node))/*exception happened*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_detach: exception happened\n");

        /*socket should not be used by others ...*/
        chttps_node_disconnect(chttp_node);

        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    chttps_node_disconnect(chttp_node);

    /*get and check body len/content-length*/
    /*rsp_body_len = chttps_node_recv_len(chttp_node);*/
    rsp_body_len = CHTTP_NODE_BODY_PARSED_LEN(chttp_node);
    if(0 < rsp_body_len && 0 < CHTTP_NODE_CONTENT_LENGTH(chttp_node))
    {
        uint64_t content_len;
        content_len = CHTTP_NODE_CONTENT_LENGTH(chttp_node);

        if(content_len != rsp_body_len)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_detach: body len %"PRId64" != content len %"PRId64"\n",
                            rsp_body_len, content_len);

            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_node_detach: body len %"PRId64", content len %"PRId64"\n",
                    rsp_body_len, CHTTP_NODE_CONTENT_LENGTH(chttp_node));

    /*handover http response*/

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_node_detach: before handover, chttp_node: %p\n", chttp_node);
        chttp_node_print(LOGSTDOUT, chttp_node);
    }

    chttp_node_free(chttp_node);

    return (EC_TRUE);
}

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Block Http Flow
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request_block(const CHTTP_REQ *chttp_req, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    CHTTP_NODE    *chttp_node;
    CSOCKET_CNODE *csocket_cnode;
    uint64_t       rsp_body_len;
    UINT8         *data;
    UINT32         data_len;
    EC_BOOL        ret;

    chttp_node = chttp_node_new(CHTTP_TYPE_DO_CLT_RSP);
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: new chttp_node failed\n");
        return (EC_FALSE);
    }
    chttp_node_import_req(chttp_node, chttp_req);

    CHTTP_NODE_LOG_TIME_WHEN_START(chttp_node); /*record start time*/

    if(EC_FALSE == chttps_node_connect(chttp_node, CSOCKET_IS_BLOCK_MODE,
                            CHTTP_REQ_IPADDR(chttp_req), CHTTP_REQ_PORT(chttp_req)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: connect server %s:%ld failed\n",
                            CHTTP_REQ_IPADDR_STR(chttp_req), CHTTP_REQ_PORT(chttp_req));

#if (SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)
        if(EC_FALSE == cstring_is_empty(CHTTP_REQ_DOMAIN(chttp_req)))
        {
            cdnscache_dns_retire((char *)cstring_get_str(CHTTP_REQ_DOMAIN(chttp_req)),
                                CHTTP_REQ_IPADDR(chttp_req));
        }
#endif/*(SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)*/
        if(NULL_PTR != CHTTP_REQ_CONN_FAIL_CALLBACK_FUNC(chttp_req))
        {
            /*mark ngx upstream peer down*/
            CHTTP_REQ_CONN_FAIL_CALLBACK_FUNC(chttp_req)(CHTTP_REQ_CONN_FAIL_CALLBACK_ARGS(chttp_req));
        }

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

    CHTTP_RSP_CLIENT_IPADDR(chttp_rsp) = CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode);
    CHTTP_RSP_CLIENT_PORT(chttp_rsp)   = CSOCKET_CNODE_CLIENT_PORT(csocket_cnode);

    chttp_node_init_parser(chttp_node);

    chttps_node_set_parse_callback(chttp_node);

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_node_encode_req_header(chttp_node,
                            CHTTP_REQ_METHOD(chttp_req), CHTTP_REQ_URI(chttp_req),
                            CHTTP_REQ_PARAM(chttp_req), CHTTP_REQ_HEADER(chttp_req))
     )
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: encode header failed\n");

        /*unbind csocket_cnode and chttp_node*/
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_node_encode_req_body(chttp_node, CHTTP_REQ_BODY(chttp_req)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: encode body failed\n");

        /*unbind csocket_cnode and chttp_node*/
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    for(;;)
    {
        ret = chttps_node_send_req(chttp_node, csocket_cnode);
        if(EC_AGAIN != ret)
        {
            break;
        }
    }

    if(EC_TRUE == ret || EC_DONE == ret)
    {
        ret = chttps_node_recv_rsp(chttp_node, csocket_cnode);
    }

    /**
     *  when come back, check CHTTP_NODE_RECV_COMPLETE flag.
     *  if false, exception happened. and return false
     **/
    if(EC_FALSE == ret/*BIT_FALSE == CHTTP_NODE_RECV_COMPLETE(chttp_node)*/)/*exception happened*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: exception happened\n");

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);

        /*socket should not be used by others ...*/
        if(NULL_PTR != CHTTP_NODE_CSOCKET_CNODE(chttp_node))
        {
            /*unbind csocket_cnode and chttp_node*/
            CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

            /*close http connection*/
            csocket_cnode_close(csocket_cnode);
        }

        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    if(NULL_PTR != CHTTP_NODE_CSOCKET_CNODE(chttp_node))
    {
        /*unbind csocket_cnode and chttp_node*/
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

        dbg_log(SEC_0157_CHTTPS, 5)(LOGSTDOUT, "[DEBUG] chttps_request_block: try close socket %d\n", CSOCKET_CNODE_SOCKFD(csocket_cnode));
        /*close http connection*/
        csocket_cnode_close(csocket_cnode);
    }

    /*get and check body len/content-length*/
    /*rsp_body_len = chttps_node_recv_len(chttp_node);*/
    rsp_body_len = CHTTP_NODE_BODY_PARSED_LEN(chttp_node);
    if(0 < rsp_body_len && 0 < CHTTP_NODE_CONTENT_LENGTH(chttp_node))
    {
        uint64_t content_len;
        content_len = CHTTP_NODE_CONTENT_LENGTH(chttp_node);

        if(content_len != rsp_body_len)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: body len %"PRId64" != content len %"PRId64"\n",
                            rsp_body_len, content_len);

            chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_block: body len %"PRId64", content len %"PRId64"\n",
                    rsp_body_len, CHTTP_NODE_CONTENT_LENGTH(chttp_node));

    /*handover http response*/
    CHTTP_RSP_STATUS(chttp_rsp) = (uint32_t)CHTTP_NODE_STATUS_CODE(chttp_node);

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_block: before handover, chttp_node: %p\n", chttp_node);
        chttp_node_print(LOGSTDOUT, chttp_node);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_block: before handover, chttp_rsp: %p\n", chttp_rsp);
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }

    cstrkv_mgr_handover(CHTTP_NODE_HEADER_IN_KVS(chttp_node), CHTTP_RSP_HEADER(chttp_rsp));

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_block: after handover, chttp_node: %p\n", chttp_node);
        chttp_node_print(LOGSTDOUT, chttp_node);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_block: after handover, chttp_rsp: \n");
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_block: chttp_rsp: %p\n", chttp_rsp);
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }

    /*Transfer-Encoding: chunked*/
    if(0 == CHTTP_NODE_CONTENT_LENGTH(chttp_node) && EC_TRUE == chttp_rsp_is_chunked(chttp_rsp))
    {
        CSTRKV *cstrkv;

        cstrkv = cstrkv_new((const char *)"Content-Length", c_word_to_str((UINT32)CHTTP_NODE_BODY_PARSED_LEN(chttp_node)));
        if(NULL_PTR == cstrkv)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: new cstrkv for chunked rsp failed\n");
            /*ignore this exception*/
        }
        else
        {
            cstrkv_mgr_add_kv(CHTTP_RSP_HEADER(chttp_rsp), cstrkv);
        }

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_block: add %s:%s to rsp\n",
                        (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    /*dump body*/
    if(EC_FALSE == chunk_mgr_dump(CHTTP_NODE_RECV_BUF(chttp_node), &data, &data_len))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_block: dump response body failed\n");

        cstrkv_mgr_clean(CHTTP_RSP_HEADER(chttp_rsp));

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }
    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_block: dump response body len %ld\n", data_len);
    cbytes_mount(CHTTP_RSP_BODY(chttp_rsp), data_len, data);

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_block: chttp_rsp: %p\n", chttp_rsp);
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
    chttp_node_free(chttp_node);

    return (EC_TRUE);
}

/*basic http flow*/
EC_BOOL chttps_request_basic(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    CHTTP_NODE     *chttp_node;
    CROUTINE_COND  *croutine_cond;
    uint64_t        rsp_body_len;

    chttp_node = chttp_node_new(CHTTP_TYPE_DO_CLT_RSP);
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: new chttp_node failed\n");
        return (EC_FALSE);
    }
    chttp_node_import_req(chttp_node, chttp_req);

    /*set CA file*/
    if(EC_FALSE == cstring_is_empty(CHTTP_REQ_CA_FILE(chttp_req)))
    {
        CSTRING         *ca_file;
        ca_file = cstring_dup(CHTTP_REQ_CA_FILE(chttp_req));
        if(NULL_PTR == ca_file)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: dup ca file '%s' failed\n",
                           (char *)cstring_get_str(CHTTP_REQ_CA_FILE(chttp_req)));

            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }
        CHTTP_NODE_CA_FILE(chttp_node) = ca_file;
    }

    /*set client certificate file and private key file*/
    if(EC_FALSE == cstring_is_empty(CHTTP_REQ_CLIENT_CERT_FILE(chttp_req)))
    {
        CSTRING         *client_cert_file;
        client_cert_file = cstring_dup(CHTTP_REQ_CLIENT_CERT_FILE(chttp_req));
        if(NULL_PTR == client_cert_file)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: dup client certificate file '%s' failed\n",
                           (char *)cstring_get_str(CHTTP_REQ_CLIENT_CERT_FILE(chttp_req)));

            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }
        CHTTP_NODE_CLIENT_CERT_FILE(chttp_node) = client_cert_file;
    }

    if(EC_FALSE == cstring_is_empty(CHTTP_REQ_CLIENT_PRIVKEY_FILE(chttp_req)))
    {
        CSTRING         *client_privkey_file;
        client_privkey_file = cstring_dup(CHTTP_REQ_CLIENT_PRIVKEY_FILE(chttp_req));
        if(NULL_PTR == client_privkey_file)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: dup client certificate file '%s' failed\n",
                           (char *)cstring_get_str(CHTTP_REQ_CLIENT_PRIVKEY_FILE(chttp_req)));

            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }
        CHTTP_NODE_CLIENT_PRIVKEY_FILE(chttp_node) = client_privkey_file;
    }

    if(NULL_PTR != chttp_store)/*store data to storage as long as http recving*/
    {
        CHTTP_STORE *chttps_store_t;
        chttps_store_t = chttp_store_new();
        if(NULL_PTR == chttps_store_t)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: new chttp_store failed\n");

            chttp_node_store_done_nonblocking(chttp_node, chttp_store);/*for merge orign exception*/
            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }

        CHTTP_NODE_STORE(chttp_node) = chttps_store_t;
        chttp_store_clone(chttp_store, CHTTP_NODE_STORE(chttp_node));
    }

    /*ms procedure: lock seg-0 to prevent storage from different client request triggering ddir at near time*/
    chttp_node_store_ddir_after_lock_header(chttp_node, chttp_req);

    if(EC_TRUE == chttp_req_is_head_method(chttp_req))
    {
        CHTTP_NODE_HTTP_REQ_IS_HEAD(chttp_node) = BIT_TRUE;
    }

    croutine_cond = croutine_cond_new(0/*never timeout*/, LOC_CHTTPS_0024);
    if(NULL_PTR == croutine_cond)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: new croutine_cond failed\n");

        chttp_node_store_done_nonblocking(chttp_node, chttp_store);/*for merge orign exception*/
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }
    CHTTP_NODE_CROUTINE_COND(chttp_node) = croutine_cond;

    CHTTP_NODE_LOG_TIME_WHEN_START(chttp_node); /*record start time*/

    if(EC_FALSE == chttps_node_connect(chttp_node, CSOCKET_IS_NONBLOCK_MODE, CHTTP_REQ_IPADDR(chttp_req), CHTTP_REQ_PORT(chttp_req)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: connect server %s:%ld failed\n",
                            CHTTP_REQ_IPADDR_STR(chttp_req), CHTTP_REQ_PORT(chttp_req));

#if (SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)
        if(EC_FALSE == cstring_is_empty(CHTTP_REQ_DOMAIN(chttp_req)))
        {
            cdnscache_dns_retire((char *)cstring_get_str(CHTTP_REQ_DOMAIN(chttp_req)),
                                CHTTP_REQ_IPADDR(chttp_req));
        }
#endif/*(SWITCH_ON == CDNSCACHE_RETIRE_CONN_FAIL_SWITCH)*/
        if(NULL_PTR != CHTTP_REQ_CONN_FAIL_CALLBACK_FUNC(chttp_req))
        {
            /*mark ngx upstream peer down*/
            CHTTP_REQ_CONN_FAIL_CALLBACK_FUNC(chttp_req)(CHTTP_REQ_CONN_FAIL_CALLBACK_ARGS(chttp_req));
        }

        chttp_node_store_done_nonblocking(chttp_node, chttp_store);/*for merge orign exception*/

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_node_encode_req_header(chttp_node,
                            CHTTP_REQ_METHOD(chttp_req), CHTTP_REQ_URI(chttp_req),
                            CHTTP_REQ_PARAM(chttp_req), CHTTP_REQ_HEADER(chttp_req))
     )
    {
        CSOCKET_CNODE  *csocket_cnode;

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: encode header failed\n");

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        /*umount csocket_cnode and chttp_node*/
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);

        chttp_node_store_done_nonblocking(chttp_node, chttp_store);/*for merge orign exception*/

        chttp_stat_set_rsp_status(CHTTP_NODE_STAT(chttp_node), CHTTP_INTERNAL_SERVER_ERROR);

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == chttp_node_encode_req_body(chttp_node, CHTTP_REQ_BODY(chttp_req)))
    {
        CSOCKET_CNODE  *csocket_cnode;

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: encode body failed\n");

        csocket_cnode = CHTTP_NODE_CSOCKET_CNODE(chttp_node);

        /*umount csocket_cnode and chttp_node*/
        CHTTP_NODE_CSOCKET_CNODE(chttp_node)    = NULL_PTR;

        /*close http connection*/
        csocket_cnode_close(csocket_cnode);

        chttp_node_store_done_nonblocking(chttp_node, chttp_store);/*for merge orign exception*/

        chttp_stat_set_rsp_status(CHTTP_NODE_STAT(chttp_node), CHTTP_INTERNAL_SERVER_ERROR);

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    CHTTP_RSP_CLIENT_IPADDR(chttp_rsp) = CSOCKET_CNODE_CLIENT_IPADDR(CHTTP_NODE_CSOCKET_CNODE(chttp_node));
    CHTTP_RSP_CLIENT_PORT(chttp_rsp)   = CSOCKET_CNODE_CLIENT_PORT(CHTTP_NODE_CSOCKET_CNODE(chttp_node));

    chttp_node_init_parser(chttp_node);

    //CHTTP_NODE_SSL_STATUS(chttp_node) = CHTTP_NODE_SSL_STATUS_HANDSHAKE_ONGOING;

    chttps_node_set_parse_callback(chttp_node);

    chttps_node_set_socket_callback(chttp_node, CHTTP_NODE_CSOCKET_CNODE(chttp_node));
    chttps_node_set_socket_epoll(chttp_node, CHTTP_NODE_CSOCKET_CNODE(chttp_node));

    if(NULL_PTR != chttp_stat)
    {
        CHTTP_STAT_S_SEND_LEN(chttp_stat) += chttp_node_send_len(chttp_node);
    }
    //dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_basic: croutine_cond %p reserved\n", croutine_cond);

    croutine_cond_reserve(croutine_cond, 1, LOC_CHTTPS_0025);
    croutine_cond_wait(croutine_cond, LOC_CHTTPS_0026);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: coroutine was cancelled\n");

        chttps_node_disconnect(chttp_node);

        /*when current coroutine was cancelled, blocking-mode is prohibitted*/
        chttp_node_store_done_nonblocking(chttp_node, chttp_store);  /*for merge orign termination in nonblocking mode*/
    } else {/*normal*/

        /*chunk trigger detached http flow*/
        if(BIT_FALSE == CHTTP_NODE_HTTP_REQ_IS_HEAD(chttp_node)
        && EC_TRUE == chttp_node_is_chunked(chttp_node))
        {
            CROUTINE_NODE  *croutine_node;

            croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                               (UINT32)chttps_node_detach, 1, chttp_node);
            if(NULL_PTR == croutine_node)
            {
                dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: croutine load for chttps_node_detach failed\n");

                /*exception*/
                chttp_stat_set_rsp_status(CHTTP_NODE_STAT(chttp_node), CHTTP_INTERNAL_SERVER_ERROR);

                chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);

                /*socket should not be used by others ...*/
                chttps_node_disconnect(chttp_node);

                chttp_node_free(chttp_node);

                return (EC_FALSE);
            }
            CHTTP_NODE_CROUTINE_NODE(chttp_node) = croutine_node;
            CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CHTTPS_0027);

            dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_basic: chunked => detach flow\n");
            chttp_node_clone_rsp_header(chttp_node, chttp_rsp, chttp_stat); /*clone*/

            chttp_rsp_del_header(chttp_rsp, (const char *)"Content-Length");
            chttp_rsp_del_header(chttp_rsp, (const char *)"Content-Range");

            /*note: chttp_node would be re-used in new coroutine, do not free it now*/
            return (EC_TRUE);
        }

        chttp_node_store_done_blocking(chttp_node, chttp_store);  /*for merge orign termination in blocking mode*/
    }

    chttp_node_set_billing(chttp_node, chttp_store); /*set billing in non-blocking mode*/

    ASSERT(NULL_PTR == CHTTP_NODE_CSOCKET_CNODE(chttp_node));

    /**
     *  when come back, check CHTTP_NODE_RECV_COMPLETE flag.
     *  if false, exception happened. and return false
     **/
    if(BIT_FALSE == CHTTP_NODE_RECV_COMPLETE(chttp_node))/*exception happened*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: exception happened\n");

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);

        /*socket should not be used by others ...*/
        chttps_node_disconnect(chttp_node);

        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    chttps_node_disconnect(chttp_node);

    /*get and check body len/content-length*/
    /*rsp_body_len = chttps_node_recv_len(chttp_node);*/
    if(NULL_PTR != chttp_stat)
    {
        CHTTP_STAT_S_RECV_LEN(chttp_stat) += CHTTP_NODE_HEADER_PARSED_LEN(chttp_node);
        CHTTP_STAT_S_RECV_LEN(chttp_stat) += CHTTP_NODE_BODY_PARSED_LEN(chttp_node);
    }
    rsp_body_len = CHTTP_NODE_BODY_PARSED_LEN(chttp_node);
    if(0 < rsp_body_len && 0 < CHTTP_NODE_CONTENT_LENGTH(chttp_node))
    {
        uint64_t content_len;
        content_len = CHTTP_NODE_CONTENT_LENGTH(chttp_node);

        if(content_len != rsp_body_len)
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_basic: body len %"PRId64" != content len %"PRId64"\n",
                            rsp_body_len, content_len);

            chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
            chttp_node_free(chttp_node);
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_basic: body len %"PRId64", content len %"PRId64"\n",
                    rsp_body_len, CHTTP_NODE_CONTENT_LENGTH(chttp_node));

    /*handover http response*/
    if(EC_FALSE == chttp_node_handover_rsp(chttp_node, chttp_rsp, chttp_stat))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request_basic: before handover, chttp_node: %p\n", chttp_node);
        chttp_node_print(LOGSTDOUT, chttp_node);
    }
    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_basic: handover rsp done\n");

#if 0
    /*handover cache_ctrl*/
    if(NULL_PTR != CHTTP_NODE_STORE(chttp_node))
    {
        if(do_log(SEC_0157_CHTTPS, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] chttps_request_basic: chttp_store %p:\n", CHTTP_NODE_STORE(chttp_node));
            chttp_store_print(LOGSTDOUT, CHTTP_NODE_STORE(chttp_node));
        }

        if(NULL_PTR != chttp_store)
        {
            dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_basic: cache_ctrl: %#x -> %#x\n",
                                                  CHTTP_STORE_CACHE_CTRL(chttp_store),
                                                  CHTTP_STORE_CACHE_CTRL(CHTTP_NODE_STORE(chttp_node)));

            CHTTP_STORE_CACHE_CTRL(chttp_store) = CHTTP_STORE_CACHE_CTRL(CHTTP_NODE_STORE(chttp_node));
        }
    }
#endif
    chttp_node_free(chttp_node);

    return (EC_TRUE);
}

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Try to connect remote http server to check connectivity (HEALTH CHECKER)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_node_check(CHTTP_NODE *chttp_node, const UINT32 ipaddr, const UINT32 port)
{
    CSOCKET_CNODE *csocket_cnode;
    UINT32         client_ipaddr;
    UINT32         client_port;
    int            sockfd;

    if(EC_FALSE == csocket_connect( ipaddr, port , CSOCKET_IS_NONBLOCK_MODE, &sockfd, &client_ipaddr, &client_port ))
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

    csocket_cnode = csocket_cnode_new(LOC_CHTTPS_0028);
    if(NULL_PTR == csocket_cnode)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_node_check:new csocket cnode for socket %d to server %s:%ld failed\n",
                        sockfd, c_word_to_ipv4(ipaddr), port);
        csocket_close(sockfd);
        return (EC_FALSE);
    }

    CSOCKET_CNODE_SOCKFD(csocket_cnode)         = sockfd;
    CSOCKET_CNODE_TYPE(csocket_cnode )          = CSOCKET_TYPE_TCP;
    CSOCKET_CNODE_IPADDR(csocket_cnode)         = ipaddr;
    CSOCKET_CNODE_SRVPORT(csocket_cnode)        = port;
    CSOCKET_CNODE_CLIENT_IPADDR(csocket_cnode)  = client_ipaddr;
    CSOCKET_CNODE_CLIENT_PORT(csocket_cnode)    = client_port;

    /* mount */
    CHTTP_NODE_CSOCKET_CNODE(chttp_node) = csocket_cnode;

    return (EC_TRUE);
}

EC_BOOL chttps_check(const CHTTP_REQ *chttp_req, CHTTP_STAT *chttp_stat)
{
    CHTTP_NODE    *chttp_node;
    CROUTINE_COND *croutine_cond;

    chttp_node = chttp_node_new(CHTTP_TYPE_DO_CLT_CHK);
    if(NULL_PTR == chttp_node)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: new chttp_node failed\n");
        return (EC_FALSE);
    }
    chttp_node_import_req(chttp_node, chttp_req);

    croutine_cond = croutine_cond_new(0/*never timeout*/, LOC_CHTTPS_0029);
    if(NULL_PTR == croutine_cond)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: new croutine_cond failed\n");

        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }
    CHTTP_NODE_CROUTINE_COND(chttp_node) = croutine_cond;

    //CHTTP_NODE_LOG_TIME_WHEN_START(chttp_node); /*record start time*/

    if(EC_FALSE == chttps_node_check(chttp_node, CHTTP_REQ_IPADDR(chttp_req), CHTTP_REQ_PORT(chttp_req)))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: check server %s:%ld failed\n",
                            CHTTP_REQ_IPADDR_STR(chttp_req), CHTTP_REQ_PORT(chttp_req));

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    chttp_node_init_parser(chttp_node);

    chttps_node_set_socket_callback(chttp_node, CHTTP_NODE_CSOCKET_CNODE(chttp_node));
    chttps_node_set_socket_epoll(chttp_node, CHTTP_NODE_CSOCKET_CNODE(chttp_node));

    croutine_cond_reserve(croutine_cond, 1, LOC_CHTTPS_0030);
    croutine_cond_wait(croutine_cond, LOC_CHTTPS_0031);

    __COROUTINE_CATCH_EXCEPTION() { /*exception*/
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: coroutine was cancelled\n");

        chttps_node_disconnect(chttp_node);

    }__COROUTINE_HANDLE_EXCEPTION();

    /**
     *  when come back, check CHTTP_NODE_SEND_COMPLETE flag.
     *  if so, exception happened. and return false
     **/
    if(BIT_FALSE == CHTTP_NODE_SEND_COMPLETE(chttp_node))/*exception happened*/
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_check: exception happened\n");

        chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
        chttp_node_free(chttp_node);
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR == CHTTP_NODE_CSOCKET_CNODE(chttp_node));

    chttps_node_disconnect(chttp_node);

    dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_check: OK\n");

    chttp_stat_clone(CHTTP_NODE_STAT(chttp_node), chttp_stat);
    chttp_node_free(chttp_node);

    return (EC_TRUE);
}

/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Merge Http Request (MERGE ORIGIN FLOW)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
STATIC_CAST static EC_BOOL __chttps_request_merge_file_lock(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, const CSTRING *path, const UINT32 expire_nsec, UINT32 *locked_already)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_lock: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    return ccache_file_lock(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                            path, expire_nsec, CHTTP_STORE_AUTH_TOKEN(chttp_store), locked_already);
}

STATIC_CAST static EC_BOOL __chttps_request_merge_file_unlock(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_unlock: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    return ccache_file_unlock(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                              path, CHTTP_STORE_AUTH_TOKEN(chttp_store));
}

STATIC_CAST static EC_BOOL __chttps_request_merge_file_read(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    CBYTES       cbytes;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_read: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);
    if(EC_FALSE == ccache_file_read(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    path, CHTTP_STORE_SEG_S_OFFSET(chttp_store), CHTTP_STORE_SEG_E_OFFSET(chttp_store),
                                    &cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_merge_file_read: [No.%ld] read '%.*s' on %s:%s:%ld failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_merge_file_read: [No.%ld] read '%.*s' on %s:%s:%ld => OK\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    /*make http response*/
    if(EC_FALSE == cbytes_is_empty(&cbytes))
    {
        UINT8          *body_data;
        UINT32          body_len;

        const char     *k;
        const char     *v;

        cbytes_umount(&cbytes, &body_len, &body_data);
        cbytes_mount(CHTTP_RSP_BODY(chttp_rsp), body_len, body_data);

        CHTTP_RSP_STATUS(chttp_rsp) = CHTTP_OK;

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(body_len);
        chttp_rsp_add_header(chttp_rsp, k, v);
    }
    else
    {
        const char     *k;
        const char     *v;

        CHTTP_RSP_STATUS(chttp_rsp) = CHTTP_OK;

        k = (const char *)"Content-Length";
        v = (const char *)"0";
        chttp_rsp_add_header(chttp_rsp, k, v);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chttps_request_merge_file_retire(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_retire: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_file_retire(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    path))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_retire: [No.%ld] file_retire '%.*s' on %s:%s:%ld failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_merge_file_retire: [No.%ld] file_retire '%.*s' on %s:%s:%ld => OK\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chttps_request_merge_file_wait(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat, UINT32 *data_ready)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;
    UINT32       content_length;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_wait: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_file_wait(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    path, CHTTP_SEG_ERR_OFFSET, CHTTP_SEG_ERR_OFFSET, /*wait whole file*/
                                    &content_length, data_ready))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_wait: [No.%ld] file_wait '%.*s' on %s:%s:%ld failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_merge_file_wait: [No.%ld] file_wait '%.*s' on %s:%s:%ld => OK, data_ready: '%s' [%ld]\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    c_bool_str(*data_ready), (*data_ready));

    if(0 < content_length)
    {
        const char     *k;
        const char     *v;

        CHTTP_RSP_STATUS(chttp_rsp) = CHTTP_OK;

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        chttp_rsp_add_header(chttp_rsp, k, v);
    }
    else
    {
        const char     *k;
        const char     *v;

        CHTTP_RSP_STATUS(chttp_rsp) = CHTTP_OK;

        k = (const char *)"Content-Length";
        v = (const char *)"0";
        chttp_rsp_add_header(chttp_rsp, k, v);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chttps_request_merge_file_wait_ready(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    //UINT32       data_ready;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_wait_ready: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }


    if(EC_FALSE == ccache_file_wait_ready(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                          path,
                                          NULL_PTR))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_merge_file_wait_ready: [No.%ld] file_wait '%.*s' on %s:%s:%ld => status %u\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(chttp_rsp));

        return (EC_FALSE);
    }

    return (EC_TRUE);
}


/*(NO WAIT)*/
STATIC_CAST static EC_BOOL __chttps_request_merge_file_orig(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    CHTTP_STORE   *chttps_store_t;
    uint32_t       merge_flag_saved;

    /*trick: we cannot send merge flag to super and we want to reduce chttp_store clone, so ...*/
    chttps_store_t    = (CHTTP_STORE *)chttp_store; /*save*/
    merge_flag_saved = CHTTP_STORE_MERGE_FLAG(chttps_store_t);
    CHTTP_STORE_MERGE_FLAG(chttps_store_t) = BIT_FALSE; /*clean*/

    ccache_trigger_http_request_merge(chttp_req, chttps_store_t, chttp_rsp, chttp_stat);

    CHTTP_STORE_MERGE_FLAG(chttps_store_t) = merge_flag_saved; /*restore*/

    return (EC_TRUE);
}

EC_BOOL chttps_request_merge(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    UINT32         locked_already;

    UINT32         timeout_msec;
    UINT32         expire_nsec;

    UINT32         tag;

    CHTTP_STORE   *chttps_store_t;
    CSTRING        path;

    CHTTP_STAT     chttps_stat_t; /*only for merge procedure statistics*/

    ASSERT(NULL_PTR != chttp_store);
    ASSERT(BIT_TRUE == CHTTP_STORE_MERGE_FLAG(chttp_store));

    chttps_store_t = chttp_store_new();
    if(NULL_PTR == chttps_store_t)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: new chttp_store failed\n");
        return (EC_FALSE);
    }
    chttp_store_clone(chttp_store, chttps_store_t);
    CHTTPS_STORE_SEQ_NO_GEN(chttps_store_t);

    chttp_stat_init(&chttps_stat_t);
    CHTTP_STAT_LOG_MERGE_TIME_WHEN_START(&chttps_stat_t); /*record merge start time*/

    timeout_msec = CHTTP_STORE_MERGE_WAIT_TIMEOUT_NSEC(chttp_store) * 1000;
    expire_nsec  = CHTTP_STORE_MERGE_LOCK_EXPIRES_NSEC(chttp_store);

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        tag = MD_CXFS;
    }
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        tag = MD_CRFS;
    }

    /*make path*/
    cstring_init(&path, NULL_PTR);
    chttp_store_path_get(chttps_store_t, &path);

    /*s1. file lock: acquire auth-token*/
    locked_already = EC_FALSE;

    if(EC_FALSE == __chttps_request_merge_file_lock(chttp_req, chttps_store_t, &path, expire_nsec, &locked_already))
    {
        CHTTP_STAT_LOG_MERGE_TIME_WHEN_LOCKED(&chttps_stat_t); /*record merge locked done time*/
        CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_LOCKED_ERR [No.%ld]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] file lock '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_FALSE);
    }

    CHTTP_STAT_LOG_MERGE_TIME_WHEN_LOCKED(&chttps_stat_t); /*record merge locked done time*/

    if(EC_TRUE == locked_already)
    {
        /*[N] means this is not the auth-token owner*/
        CHTTP_STORE_LOCKED_FLAG(chttps_store_t) = BIT_FALSE;

        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [N] file lock '%.*s' => auth-token: (null)\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));

        if(0 == CHTTP_STORE_SEG_ID(chttps_store_t) && BIT_TRUE == CHTTP_STORE_EXPIRED_FLAG(chttps_store_t))
        {
            if(EC_FALSE == __chttps_request_merge_file_wait_ready(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat))
            {
                CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_ready done time*/
                CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_WAIT_READY_ERR [No.%ld] [N]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
                CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
                CHTTP_STAT_LOG_MERGE_NO_PRINT(&chttps_stat_t);

                dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [N] wait_ready '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
                chttp_store_free(chttps_store_t);
                cstring_clean(&path);
                return (EC_FALSE);
            }

            CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_ready done time*/

            chttp_rsp_clean(chttp_rsp);

            dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [N] wait_ready '%.*s' done\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        }
        else
        {
            UINT32         data_ready;

            data_ready = EC_FALSE;
            if(EC_FALSE == __chttps_request_merge_file_wait(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat, &data_ready))
            {
                CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_data done time*/
                CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_WAIT_DATA_ERR [No.%ld] [N]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
                CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
                CHTTP_STAT_LOG_MERGE_NO_PRINT(&chttps_stat_t);

                dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [N] wait '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
                chttp_store_free(chttps_store_t);
                cstring_clean(&path);
                return (EC_FALSE);
            }

            if(EC_TRUE == data_ready)
            {
                CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_data done time*/
                CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_WAIT_DATA_SUCC [No.%ld] [N]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
                CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "[DEBUG] chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
                CHTTP_STAT_LOG_MERGE_NO_PRINT(&chttps_stat_t);

                dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [N] wait '%.*s' done and data ready\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
                chttp_store_free(chttps_store_t);
                cstring_clean(&path);
                return (EC_TRUE);
            }

            CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_data done time*/

            chttp_rsp_clean(chttp_rsp);

            dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [N] wait '%.*s' done and data not ready\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        }

        /*s3: wait being waken up or timeout*/
        if(EC_FALSE == super_cond_wait(0, tag, &path, timeout_msec))
        {
            CHTTP_STAT_LOG_MERGE_TIME_WHEN_CONDED(&chttps_stat_t); /*record merge cond_wait done time*/
            CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_COND_ERR [No.%ld] [N]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_MERGE_NO_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [N] cond wait '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_FALSE);
        }

        CHTTP_STAT_LOG_MERGE_TIME_WHEN_CONDED(&chttps_stat_t); /*record merge cond_wait done time*/

        /*after come back*/
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [N] cond wait '%.*s' => back\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));

        /*s5: read file from storage*/
        if(EC_FALSE == __chttps_request_merge_file_read(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat))
        {
            CHTTP_STAT_LOG_MERGE_TIME_WHEN_READ(&chttps_stat_t); /*record merge file_read done time*/
            CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_READ_ERR [No.%ld] [N]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_MERGE_NO_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [N] read '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_FALSE);
        }

        CHTTP_STAT_LOG_MERGE_TIME_WHEN_READ(&chttps_stat_t); /*record merge file_read done time*/
        CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_OK [No.%ld] [N]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "[DEBUG] chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_MERGE_NO_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [N] read '%.*s' => succ\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_TRUE);
    }

    CHTTP_STORE_LOCKED_FLAG(chttps_store_t) = BIT_TRUE;

    /*[Y] means this is the auth-token owner*/
    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] file lock '%.*s' => auth-token: %.*s\n",
                CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path),
                (uint32_t)CHTTP_STORE_AUTH_TOKEN_LEN(chttps_store_t), (char *)CHTTP_STORE_AUTH_TOKEN_STR(chttps_store_t));

    if(0 == CHTTP_STORE_SEG_ID(chttps_store_t) && BIT_TRUE == CHTTP_STORE_EXPIRED_FLAG(chttps_store_t))
    {
        if(EC_FALSE == __chttps_request_merge_file_wait_ready(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat))
        {
            CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_ready done time*/
            CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_WAIT_READY_ERR [No.%ld] [Y]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [Y] wait_ready '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_FALSE);
        }

        CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_ready done time*/

        chttp_rsp_clean(chttp_rsp);

        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] wait_ready '%.*s' done\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
    }
    else
    {
        UINT32         data_ready;

        data_ready = EC_FALSE;
        if(EC_FALSE == __chttps_request_merge_file_wait(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat, &data_ready))
        {
            CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_data done time*/
            CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_WAIT_DATA_ERR [No.%ld] [Y]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [Y] wait '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_FALSE);
        }

        if(EC_TRUE == data_ready)
        {
            CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_data done time*/
            CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_WAIT_DATA_SUCC [No.%ld] [Y]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "[DEBUG] chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] wait '%.*s' done and data ready\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_TRUE);
        }

        CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(&chttps_stat_t); /*record merge wait_data done time*/

        chttp_rsp_clean(chttp_rsp);

        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] wait '%.*s' done and data not ready\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
    }
    /*s2: http orig (NO WAIT and only happen on local in order to wakeup later)*/
    if(EC_FALSE == __chttps_request_merge_file_orig(chttp_req, chttps_store_t, chttp_rsp, chttp_stat))
    {
        CHTTP_STAT_LOG_MERGE_TIME_WHEN_ORIGED(&chttps_stat_t); /*record merge orig done time*/
        CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_ORIG_ERR [No.%ld] [Y]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [Y] http orig '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_FALSE);
    }

    CHTTP_STAT_LOG_MERGE_TIME_WHEN_ORIGED(&chttps_stat_t); /*record merge orig done time*/

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] http orig '%.*s' => OK\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));

    /*s3: wait being waken up or timeout*/
    if(EC_FALSE == super_cond_wait(0, tag, &path, timeout_msec))
    {
        CHTTP_STAT_LOG_MERGE_TIME_WHEN_CONDED(&chttps_stat_t); /*record merge cond_wait done time*/
        CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_COND_ERR [No.%ld] [Y]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [Y] cond wait '%.*s' failed\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_FALSE);
    }

    CHTTP_STAT_LOG_MERGE_TIME_WHEN_CONDED(&chttps_stat_t); /*record merge cond_wait done time*/

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] cond wait '%.*s' => back\n",
                CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
#if 0
    /*s4: file unlock: remove the locked-file from remote. despite of response status*/
    if(EC_FALSE == __chttps_request_merge_file_unlock(chttp_req, chttps_store_t, &path))
    {
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "warn:chttps_request_merge: [No.%ld] [Y] file unlock '%.*s', auth-token: '%.*s' => failed\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path),
                    (uint32_t)CHTTP_STORE_AUTH_TOKEN_LEN(chttps_store_t), (char *)CHTTP_STORE_AUTH_TOKEN_STR(chttps_store_t));
    }
    else
    {
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] file unlock '%.*s', auth-token: '%.*s' => OK\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path),
                    (uint32_t)CHTTP_STORE_AUTH_TOKEN_LEN(chttps_store_t), (char *)CHTTP_STORE_AUTH_TOKEN_STR(chttps_store_t));
    }
#endif
    /*s5: read file from storage*/
    if(EC_FALSE == __chttps_request_merge_file_read(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat))
    {
        CHTTP_STAT_LOG_MERGE_TIME_WHEN_READ(&chttps_stat_t); /*record merge file_read done time*/
        CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_READ_ERR [No.%ld] [Y]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_merge: [No.%ld] [Y] read '%.*s' failed\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_FALSE);
    }

    CHTTP_STAT_LOG_MERGE_TIME_WHEN_READ(&chttps_stat_t); /*record merge file_read done time*/
    CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(&chttps_stat_t, "MERGE_OK [No.%ld] [Y]", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
    CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(&chttps_stat_t, "[DEBUG] chttps_request_merge: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
    CHTTP_STAT_LOG_MERGE_YES_PRINT(&chttps_stat_t);

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_merge: [No.%ld] [Y] read '%.*s' => succ\n",
                CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));

    chttp_store_free(chttps_store_t);
    cstring_clean(&path);
    return (EC_TRUE);
}
/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * Header Http Request (only token owner would store header to storage)
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/
STATIC_CAST static EC_BOOL __chttps_request_header_file_read(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    CBYTES       cbytes;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_read: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);
    if(EC_FALSE == ccache_file_read(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    path, CHTTP_STORE_SEG_S_OFFSET(chttp_store), CHTTP_STORE_SEG_E_OFFSET(chttp_store),
                                    &cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_read: [No.%ld] read '%.*s' on %s:%s:%ld failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    if(EC_TRUE == cbytes_is_empty(&cbytes))
    {
        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_read: [No.%ld] read '%.*s' nothing on %s:%s:%ld => FAIL\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_read: [No.%ld] read '%.*s' on %s:%s:%ld => OK\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

    /*parse http response*/
    if(EC_FALSE == ccache_parse_http_header(&cbytes, chttp_rsp))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_read: "
                                              "parse header failed\n");

        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_read: "
                                              "header '\n%.*s\n' => \n",
                                              CBYTES_LEN(&cbytes),
                                              (char *)CBYTES_BUF(&cbytes));

        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    cbytes_clean(&cbytes);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chttps_request_header_file_wait_header(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait_header: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_wait_http_headers(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                            path,
                                            cstrkv_mgr, header_ready))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait_header: [No.%ld] wait headers of '%.*s' on %s:%s:%ld failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), (char *)CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_wait_header: [No.%ld]wait  headers '%.*s' on %s:%s:%ld => OK, header_ready: '%s' [%ld]\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    c_bool_str(*header_ready), (*header_ready));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chttps_request_header_file_wait(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat, UINT32 *data_ready)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;
    UINT32       content_length;
    CBYTES       content_cbytes;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }



    if(EC_FALSE == ccache_file_wait(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                    path, CHTTP_SEG_ERR_OFFSET, CHTTP_SEG_ERR_OFFSET, /*wait whole file*/
                                    &content_length, data_ready))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait: [No.%ld] file_wait '%.*s' on %s:%s:%ld failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        return (EC_FALSE);
    }

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_wait: [No.%ld] file_wait '%.*s' on %s:%s:%ld => OK, data_ready: '%s' [%ld]\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    c_bool_str(*data_ready), (*data_ready));

    cbytes_init(&content_cbytes);

    if(EC_FALSE == (*data_ready))
    {
        UINT32         timeout_msec;

        UINT32         tag;

        timeout_msec = 60 * 1000;

        if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
        {
            tag = MD_CXFS;
        }

        if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
        {
            tag = MD_CRFS;
        }

        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_wait: cond wait '%s' => go\n",
                        (char *)cstring_get_str(path));
        if(EC_FALSE == super_cond_wait(0, tag, path, timeout_msec))
        {
            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait: cond wait '%s' failed\n",
                        (char *)cstring_get_str(path));
            return (EC_FALSE);
        }
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_wait: cond wait '%s' <= back\n",
                        (char *)cstring_get_str(path));
    }

    if(EC_FALSE == ccache_parse_http_header(&content_cbytes, chttp_rsp))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait: "
                                              "parse header failed\n");

        cbytes_clean(&content_cbytes);
        return (EC_FALSE);
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        dbg_log(SEC_0157_CHTTPS, 9)(LOGSTDOUT, "[DEBUG] __chttps_request_header_file_wait: "
                                              "header '\n%.*s\n' => \n",
                                              CBYTES_LEN(&content_cbytes),
                                              (char *)CBYTES_BUF(&content_cbytes));

        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }
    cbytes_clean(&content_cbytes);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chttps_request_header_file_wait_ready(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, const CSTRING *path, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    UINT32       store_srv_tcid;
    UINT32       store_srv_ipaddr;
    UINT32       store_srv_port;

    //UINT32       data_ready;

    /*determine storage server*/
    if(EC_FALSE == chttp_store_srv_get(chttp_store, path, &store_srv_tcid, &store_srv_ipaddr, &store_srv_port))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait_ready: [No.%ld] determine storage server for '%.*s' failed\n",
                            CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path));
        return (EC_FALSE);
    }


    if(EC_FALSE == ccache_file_wait_ready(store_srv_tcid, store_srv_ipaddr, store_srv_port,
                                          path,
                                          NULL_PTR))
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:__chttps_request_header_file_wait_ready: [No.%ld] file_wait '%.*s' on %s:%s:%ld => status %u\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttp_store), (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_tcid), c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                        CHTTP_RSP_STATUS(chttp_rsp));

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*(NO WAIT)*/
STATIC_CAST static EC_BOOL __chttps_request_header_file_orig(const CHTTP_REQ *chttp_req, const CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    CHTTP_STORE   *chttps_store_t;
    uint32_t       header_orig_flag_saved;

    /*trick: we cannot send merge flag to super and we want to reduce chttp_store clone, so ...*/
    chttps_store_t    = (CHTTP_STORE *)chttp_store; /*save*/
    header_orig_flag_saved = CHTTP_STORE_HEADER_ORIG_FLAG(chttps_store_t);
    CHTTP_STORE_HEADER_ORIG_FLAG(chttps_store_t) = BIT_FALSE; /*clean*/

    /*same procedure as merge orig*/
    ccache_trigger_http_request_merge(chttp_req, chttps_store_t, chttp_rsp, chttp_stat);

    CHTTP_STORE_HEADER_ORIG_FLAG(chttps_store_t) = header_orig_flag_saved; /*restore*/

    return (EC_TRUE);
}
/*request header only*/
EC_BOOL chttps_request_header(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    UINT32         timeout_msec;
    UINT32         tag;

    CHTTP_STORE   *chttps_store_t;
    CSTRING        path;

    CHTTP_STAT     chttps_stat_t; /*only for procedure statistics*/
    EC_BOOL        ret;

    ASSERT(NULL_PTR != chttp_store);
    ASSERT(0 == CHTTP_STORE_SEG_ID(chttp_store));
    ASSERT(BIT_FALSE == CHTTP_STORE_MERGE_FLAG(chttp_store));
    ASSERT(BIT_TRUE  == CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store));

    chttps_store_t = chttp_store_new();
    if(NULL_PTR == chttps_store_t)
    {
        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_header: new chttp_store failed\n");
        return (EC_FALSE);
    }
    chttp_store_clone(chttp_store, chttps_store_t);
    CHTTPS_STORE_SEQ_NO_GEN(chttps_store_t);

    chttp_stat_init(&chttps_stat_t);
    CHTTP_STAT_LOG_HEADER_TIME_WHEN_START(&chttps_stat_t); /*record start time*/

    timeout_msec = CHTTP_STORE_MERGE_WAIT_TIMEOUT_NSEC(chttp_store) * 1000;

    if(SWITCH_ON == NGX_BGN_OVER_XFS_SWITCH)
    {
        tag = MD_CXFS;
    }
    if(SWITCH_ON == NGX_BGN_OVER_RFS_SWITCH)
    {
        tag = MD_CRFS;
    }

    /*make path*/
    cstring_init(&path, NULL_PTR);
    chttp_store_path_get(chttps_store_t, &path);

    CHTTP_STORE_LOCKED_FLAG(chttps_store_t) = BIT_TRUE;

    if(BIT_TRUE == CHTTP_STORE_EXPIRED_FLAG(chttps_store_t))
    {
        if(EC_FALSE == __chttps_request_header_file_wait_ready(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat))
        {
            CHTTP_STAT_LOG_HEADER_TIME_WHEN_WAITED(&chttps_stat_t); /*record header wait_ready done time*/
            CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(&chttps_stat_t, "HEADER_WAIT_READY_ERR [No.%ld] ", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_header: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_HEADER_YES_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_header: [No.%ld] wait_ready '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_FALSE);
        }

        CHTTP_STAT_LOG_HEADER_TIME_WHEN_WAITED(&chttps_stat_t); /*record header wait_ready done time*/

        chttp_rsp_clean(chttp_rsp);

        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_header: [No.%ld] wait_ready '%.*s' done\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
    }
    else
    {
        UINT32         data_ready;

        data_ready = EC_FALSE;
        if(EC_FALSE == __chttps_request_header_file_wait(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat, &data_ready))
        {
            CHTTP_STAT_LOG_HEADER_TIME_WHEN_WAITED(&chttps_stat_t); /*record header wait_data done time*/
            CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(&chttps_stat_t, "HEADER_WAIT_DATA_ERR [No.%ld] ", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_header: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_HEADER_YES_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_header: [No.%ld] wait '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_FALSE);
        }

        if(EC_TRUE == data_ready)
        {
            CHTTP_STAT_LOG_HEADER_TIME_WHEN_WAITED(&chttps_stat_t); /*record header wait_data done time*/
            CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(&chttps_stat_t, "HEADER_WAIT_DATA_SUCC [No.%ld] ", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
            CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(&chttps_stat_t, "[DEBUG] chttps_request_header: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            CHTTP_STAT_LOG_HEADER_YES_PRINT(&chttps_stat_t);

            dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_header: [No.%ld] wait '%.*s' done and data ready\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
            chttp_store_free(chttps_store_t);
            cstring_clean(&path);
            return (EC_TRUE);
        }

        CHTTP_STAT_LOG_HEADER_TIME_WHEN_WAITED(&chttps_stat_t); /*record header wait_data done time*/

        chttp_rsp_clean(chttp_rsp);

        dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_header: [No.%ld] wait '%.*s' done and data not ready\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
    }

    /*s2: http orig (NO WAIT and only happen on local in order to wakeup later)*/
    if(EC_FALSE == __chttps_request_header_file_orig(chttp_req, chttps_store_t, chttp_rsp, chttp_stat))
    {
        CHTTP_STAT_LOG_HEADER_TIME_WHEN_ORIGED(&chttps_stat_t); /*record orig done time*/
        CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(&chttps_stat_t, "HEADER_ORIG_ERR [No.%ld] ", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_header: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_HEADER_YES_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_header: [No.%ld] http orig '%.*s' failed\n",
                        CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_FALSE);
    }

    CHTTP_STAT_LOG_HEADER_TIME_WHEN_ORIGED(&chttps_stat_t); /*record orig done time*/

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_header: [No.%ld] http orig '%.*s' => OK\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));

    /*s3: wait being waken up or timeout*/
    ret = super_cond_wait(0, tag, &path, timeout_msec);
    if(EC_FALSE == ret || EC_TERMINATE == ret)
    {
        CHTTP_STAT_LOG_HEADER_TIME_WHEN_CONDED(&chttps_stat_t); /*record header cond_wait done time*/
        CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(&chttps_stat_t, "HEADER_COND_ERR [No.%ld] ", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_header: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_HEADER_YES_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_header: [No.%ld] cond wait '%.*s' failed\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_FALSE);
    }

    CHTTP_STAT_LOG_HEADER_TIME_WHEN_CONDED(&chttps_stat_t); /*record header cond_wait done time*/

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_header: [No.%ld] cond wait '%.*s' => back\n",
                CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));

    /*s5: read file from storage*/
    if(EC_FALSE == __chttps_request_header_file_read(chttp_req, chttps_store_t, &path, chttp_rsp, chttp_stat))
    {
        CHTTP_STAT_LOG_HEADER_TIME_WHEN_READ(&chttps_stat_t); /*record header file_read done time*/
        CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(&chttps_stat_t, "HEADER_READ_ERR [No.%ld] ", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
        CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(&chttps_stat_t, "error:chttps_request_header: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        CHTTP_STAT_LOG_HEADER_YES_PRINT(&chttps_stat_t);

        dbg_log(SEC_0157_CHTTPS, 0)(LOGSTDOUT, "error:chttps_request_header: [No.%ld] [Y] read '%.*s' failed\n",
                    CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
        chttp_store_free(chttps_store_t);
        cstring_clean(&path);
        return (EC_FALSE);
    }

    CHTTP_STAT_LOG_HEADER_TIME_WHEN_READ(&chttps_stat_t); /*record header file_read done time*/
    CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(&chttps_stat_t, "HEADER_OK [No.%ld] ", CHTTPS_STORE_SEQ_NO_GET(chttps_store_t));
    CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(&chttps_stat_t, "[DEBUG] chttps_request_header: %.*s", (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));
    CHTTP_STAT_LOG_HEADER_YES_PRINT(&chttps_stat_t);

    dbg_log(SEC_0157_CHTTPS, 1)(LOGSTDOUT, "[DEBUG] chttps_request_header: [No.%ld] read '%.*s' => succ\n",
                CHTTPS_STORE_SEQ_NO_GET(chttps_store_t), (uint32_t)CSTRING_LEN(&path), (char *)CSTRING_STR(&path));

    chttp_store_free(chttps_store_t);
    cstring_clean(&path);
    return (EC_TRUE);
}
/*-------------------------------------------------------------------------------------------------------------------------------------------\
 *
 * General Http Request Entry
 *
\*-------------------------------------------------------------------------------------------------------------------------------------------*/

EC_BOOL chttps_request(const CHTTP_REQ *chttp_req, CHTTP_STORE *chttp_store, CHTTP_RSP *chttp_rsp, CHTTP_STAT *chttp_stat)
{
    if(NULL_PTR == chttp_store)
    {
        return chttps_request_basic(chttp_req, chttp_store, chttp_rsp, chttp_stat); /*normal http request*/
    }

    if(do_log(SEC_0157_CHTTPS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chttps_request: chttp_store %p:\n", chttp_store);
        chttp_store_print(LOGSTDOUT, chttp_store);
    }

    if(BIT_FALSE == CHTTP_STORE_MERGE_FLAG(chttp_store))
    {
        uint64_t s_msec; /*start time in micro-second*/

        uint64_t e_msec; /*end time in micro-second*/

        uint32_t s2e_elapsed_msec;
        uint32_t need_log_flag;

        if(NULL_PTR != chttp_store && BIT_TRUE == CHTTP_STORE_NEED_LOG_FLAG(chttp_store))
        {
            need_log_flag = BIT_TRUE;
        }
        else
        {
            need_log_flag = BIT_FALSE;
        }

        if(BIT_TRUE == need_log_flag)
        {
            CHTTP_STAT_LOG_ORIG_TIME_WHEN_START(s_msec);
        }

        if(BIT_TRUE == need_log_flag
        && NULL_PTR != chttp_stat)
        {
            CHTTP_STAT_REQ_S_MSEC(chttp_stat) = s_msec;
        }

        if(EC_FALSE == chttps_request_basic(chttp_req, chttp_store, chttp_rsp, chttp_stat)) /*need store or not need store (e.g. direct procedure)*/
        {
            if(BIT_TRUE == need_log_flag
            && NULL_PTR != chttp_stat)
            {
                CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_msec);

                CHTTP_STAT_REQ_C_MSEC(chttp_stat) = e_msec;

                s2e_elapsed_msec = CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_msec, s_msec);
                sys_log(LOGUSER06, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u %u %u\n",
                                   (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                                   CHTTP_REQ_PORT(chttp_req),
                                   CHTTP_RSP_STATUS(chttp_rsp),
                                   s2e_elapsed_msec,
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                                   (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                                   ((uint32_t)0), /*redirect times*/
                                   CHTTP_STAT_S_SEND_LEN(chttp_stat),
                                   CHTTP_STAT_S_RECV_LEN(chttp_stat)
                                   );

                CHTTP_STAT_SET_REQ_HOST(chttp_stat,
                        (char *)chttp_req_get_header(chttp_req, (const char *)"Host"));

                CHTTP_STAT_SET_REQ_IPADDR(chttp_stat, CHTTP_REQ_IPADDR(chttp_req));

                chttp_stat_log(chttp_stat, LOGUSER07);
            }

            if(BIT_TRUE == need_log_flag
            && NULL_PTR == chttp_stat)
            {
                CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_msec);
                s2e_elapsed_msec = CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_msec, s_msec);
                sys_log(LOGUSER06, "[FAIL] %s %ld %u %u \"http://%s%s\" %s %u - -\n",
                                   (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                                   CHTTP_REQ_PORT(chttp_req),
                                   CHTTP_RSP_STATUS(chttp_rsp),
                                   s2e_elapsed_msec,
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                                   (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                                   (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                                   ((uint32_t)0) /*redirect times*/
                                   );
            }

            return (EC_FALSE);
        }

        if(BIT_TRUE == need_log_flag
        && NULL_PTR != chttp_stat)
        {
            CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_msec);

            CHTTP_STAT_REQ_C_MSEC(chttp_stat) = e_msec;

            s2e_elapsed_msec = CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_msec, s_msec);
            sys_log(LOGUSER06, "[SUCC] %s %ld %u %u \"http://%s%s\" %s %u %u %u\n",
                               (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                               CHTTP_REQ_PORT(chttp_req),
                               CHTTP_RSP_STATUS(chttp_rsp),
                               s2e_elapsed_msec,
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                               (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                               ((uint32_t)0), /*redirect times*/
                               CHTTP_STAT_S_SEND_LEN(chttp_stat),
                               CHTTP_STAT_S_RECV_LEN(chttp_stat)
                               );

            CHTTP_STAT_SET_REQ_HOST(chttp_stat,
                    (char *)chttp_req_get_header(chttp_req, (const char *)"Host"));

            CHTTP_STAT_SET_REQ_IPADDR(chttp_stat, CHTTP_REQ_IPADDR(chttp_req));

            chttp_stat_log(chttp_stat, LOGUSER07);
        }

        if(BIT_TRUE == need_log_flag
        && NULL_PTR == chttp_stat)
        {
            CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_msec);
            s2e_elapsed_msec = CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_msec, s_msec);
            sys_log(LOGUSER06, "[SUCC] %s %ld %u %u \"http://%s%s\" %s %u - -\n",
                               (char *)CHTTP_REQ_IPADDR_STR(chttp_req),
                               CHTTP_REQ_PORT(chttp_req),
                               CHTTP_RSP_STATUS(chttp_rsp),
                               s2e_elapsed_msec,
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Host"),
                               (char *)cstring_get_str(CHTTP_REQ_URI(chttp_req)),
                               (char *)chttp_req_get_header(chttp_req, (const char *)"Range"),
                               ((uint32_t)0) /*redirect times*/
                               );
        }
        return (EC_TRUE);
    }

    if(0 == CHTTP_STORE_SEG_ID(chttp_store))
    {
        /*should never reach here*/
        return chttps_request_header(chttp_req, chttp_store, chttp_rsp, chttp_stat); /*need store but not merge http request*/
    }

#if (SWITCH_ON == NGX_BGN_SWITCH)
    if(EC_TRUE == task_brd_default_is_ngx_exiting())
    {
        /*when ngx is exiting*/
        return (EC_FALSE);
    }
#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

    /*note: merge must store data in flow*/
    return chttps_request_merge(chttp_req, chttp_store, chttp_rsp, chttp_stat); /*need store and merge http request*/
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

