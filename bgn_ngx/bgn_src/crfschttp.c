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

#include "csocket.h"

#include "cmpie.h"

#include "cepoll.h"

#include "crfsc.h"
#include "crfschttp.h"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "findex.inc"

/**
protocol
=========
    (case sensitive)

    1. Read File
    REQUEST:
        GET /get/<cache_key> HTTP/1.1
        Host: <host ipaddr | hostname>
        //Date: <date in second>
        store_offset: <file offset>
        store_size: <read length>
    RESPONSE:
        status: 200(HTTP_OK), 400(HTTP_BAD_REQUEST), 404(HTTP_NOT_FOUND)
        body: <file content>
         
    2. Write File 
    REQUEST:
        POST /set/<cache_key> HTTP/1.1
        Host: <host ipaddr | hostname>
        Content-Length: <file length>
        Expires: <date in second>
        body: <file content>
    RESPONSE:
        status: 200(HTTP_OK), 400(HTTP_BAD_REQUEST), 404(HTTP_NOT_FOUND, HTTP_ERROR)
        body: <null>

    3. Update File
    REQUEST: 
        POST /update/<cache_key> HTTP/1.1
        Host: <host ipaddr | hostname>
        Content-Length: <file length>
        Expires: <date in second>
        [body: <file content>
    RESPONSE:
        status: 200(HTTP_OK), 400(HTTP_BAD_REQUEST), 404(HTTP_NOT_FOUND, HTTP_ERROR)
        body: <null>

    4. Delete File
    REQUEST: 
        GET /delete/<cache_key> HTTP/1.1
        Host: <host ipaddr | hostname>
        //Date: <date in second>
    RESPONSE:
        status: 200(HTTP_OK), 400(HTTP_BAD_REQUEST), 404(HTTP_NOT_FOUND, HTTP_ERROR)
        body: <null>     
**/

#if 0
#define CRFSCHTTP_PRINT_UINT8(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%02x,", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)

#define CRFSCHTTP_PRINT_CHARS(info, buff, len) do{\
    uint32_t __pos;\
    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "%s: ", info);\
    for(__pos = 0; __pos < len; __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%c", ((uint8_t *)buff)[ __pos ]);\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define CRFSCHTTP_PRINT_UINT8(info, buff, len) do{}while(0)
#define CRFSCHTTP_PRINT_CHARS(info, buff, len) do{}while(0)
#endif

static const CRFSCHTTP_KV g_crfschttp_status_kvs[] = {
    { 100, "Continue" },
    { 101, "Switching Protocols" },
    { 102, "Processing" }, /* WebDAV */
    { 200, "OK" },
    { 201, "Created" },
    { 202, "Accepted" },
    { 203, "Non-Authoritative Information" },
    { 204, "No Content" },
    { 205, "Reset Content" },
    { 206, "Partial Content" },
    { 207, "Multi-status" }, /* WebDAV */
    { 300, "Multiple Choices" },
    { 301, "Moved Permanently" },
    { 302, "Found" },
    { 303, "See Other" },
    { 304, "Not Modified" },
    { 305, "Use Proxy" },
    { 306, "(Unused)" },
    { 307, "Temporary Redirect" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 402, "Payment Required" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 406, "Not Acceptable" },
    { 407, "Proxy Authentication Required" },
    { 408, "Request Timeout" },
    { 409, "Conflict" },
    { 410, "Gone" },
    { 411, "Length Required" },
    { 412, "Precondition Failed" },
    { 413, "Request Entity Too Large" },
    { 414, "Request-URI Too Long" },
    { 415, "Unsupported Media Type" },
    { 416, "Requested Range Not Satisfiable" },
    { 417, "Expectation Failed" },
    { 422, "Unprocessable Entity" }, /* WebDAV */
    { 423, "Locked" }, /* WebDAV */
    { 424, "Failed Dependency" }, /* WebDAV */
    { 426, "Upgrade Required" }, /* TLS */
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Not Available" },
    { 504, "Gateway Timeout" },
    { 505, "HTTP Version Not Supported" },
    { 507, "Insufficient Storage" }, /* WebDAV */

    { -1, NULL }
};

static const uint32_t g_crfschttp_status_kvs_num = sizeof(g_crfschttp_status_kvs)/sizeof(g_crfschttp_status_kvs[0]);

static EC_BOOL g_crfcshttp_log_init = EC_FALSE;

static const char *__crfschttp_status_str_get(const uint32_t http_status)
{
    uint32_t idx;

    for(idx = 0; idx < g_crfschttp_status_kvs_num; idx ++)
    {
        const CRFSCHTTP_KV *crfschttp_kv;
        crfschttp_kv = &(g_crfschttp_status_kvs[ idx ]);
        if(http_status == CRFSCHTTP_KV_KEY(crfschttp_kv))
        {
            return (CRFSCHTTP_KV_VAL(crfschttp_kv));
        }
    }
    return ((const char *)"unknown");
}

static CQUEUE g_crfschttp_defer_request_queue;

static CLIST  g_csocket_cnode_defer_close_list;

static void __crfschttp_print_buf(const char *info, const uint8_t *buf, const UINT32 len)
{
    UINT32   idx;
    const uint8_t *pch;

    pch = buf;
    for(idx = 0; idx < len; idx ++)
    {
        sys_log(LOGSTDOUT, "%s: [%4d] %c %02x\n", info, idx, pch[ idx ], pch[ idx ]);
    }
    return;
}

static int __crfschttp_on_message_begin(http_parser_t* http_parser)
{
    CRFSCHTTP_NODE *crfschttp_node;

    crfschttp_node = (CRFSCHTTP_NODE *)http_parser->data;
    if(NULL_PTR == crfschttp_node)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_on_message_begin: http_parser->data is null\n");
        return (-1);
    }

    CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node) = CRFSCHTTP_NODE_HEADER_PARSING;
    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "\n***MESSAGE BEGIN***\n\n");
    return (0);
}

static int __crfschttp_on_headers_complete(http_parser_t* http_parser, const char* last, size_t length)
{
    CRFSCHTTP_NODE *crfschttp_node;

    crfschttp_node = (CRFSCHTTP_NODE *)http_parser->data;
    if(NULL_PTR == crfschttp_node)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_on_headers_complete: http_parser->data is null\n");
        return (-1);
    }

    CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node) = CRFSCHTTP_NODE_HEADER_PARSED;

    crfschttp_parse_host(crfschttp_node);
    crfschttp_parse_uri(crfschttp_node);
    crfschttp_parse_content_length(crfschttp_node);

    if(do_log(SEC_0145_CRFSCHTTP, 5))
    {
        crfschttp_node_print(LOGSTDOUT, crfschttp_node);
    }
 
    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "\n***HEADERS COMPLETE***\n\n");
    return (0);
}

static int __crfschttp_on_message_complete(http_parser_t* http_parser)
{
    (void)http_parser;
    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "\n***MESSAGE COMPLETE***\n\n");
    return (0);
}

static int __crfschttp_on_url(http_parser_t* http_parser, const char* at, size_t length)
{
    CRFSCHTTP_NODE *crfschttp_node;

    crfschttp_node = (CRFSCHTTP_NODE *)http_parser->data;
    cbuffer_set(CRFSCHTTP_NODE_URL(crfschttp_node), (uint8_t *)at, length);

    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "Url: %.*s\n", (int)length, at);

    return (0);
}

static int __crfschttp_on_header_field(http_parser_t* http_parser, const char* at, size_t length)
{
    CRFSCHTTP_NODE *crfschttp_node;
    CSTRKV *cstrkv;

    crfschttp_node = (CRFSCHTTP_NODE *)(http_parser->data);

    cstrkv = cstrkv_new(NULL_PTR, NULL_PTR);
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_on_header_field: new cstrkv failed where header field: %.*s\n",
                           (int)length, at);
        return (-1);
    }

    cstrkv_set_key_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length);
    cstrkv_mgr_add_kv(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), cstrkv);

    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "Header field: %.*s\n", (int)length, at);
    return (0);
}

static int __crfschttp_on_header_value(http_parser_t* http_parser, const char* at, size_t length)
{
    CRFSCHTTP_NODE *crfschttp_node;
    CSTRKV *cstrkv;

    crfschttp_node = (CRFSCHTTP_NODE *)(http_parser->data);

    cstrkv = cstrkv_mgr_last_kv(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node));
    if(NULL_PTR == cstrkv)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_on_header_value: no cstrkv existing where value field: %.*s\n",
                           (int)length, at);
        return (-1);
    }

    cstrkv_set_val_bytes(cstrkv, (const uint8_t *)at, (uint32_t)length);

    dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "Header value: %.*s\n", (int)length, at);
    return (0);
}

static int __crfschttp_on_body(http_parser_t* http_parser, const char* at, size_t length)
{
    CRFSCHTTP_NODE *crfschttp_node;
    CHUNK_MGR     *body_chunks;

    //dbg_log(SEC_0145_CRFSCHTTP, 5)(LOGSTDOUT, "Body [ignore]: length %d\n\n", length);
 
    crfschttp_node = (CRFSCHTTP_NODE *)(http_parser->data);
    body_chunks   = CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node);

    if(EC_FALSE == chunk_mgr_append_data(body_chunks, (uint8_t *)at, length))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_on_body: append %d bytes failed\n", length);
        return (-1);
    }

    CRFSCHTTP_NODE_BODY_PARSED_LEN(crfschttp_node) += length;
    return (0);
}

static EC_BOOL __crfschttp_uri_is_setsmf_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/setsmf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/setsmf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

static EC_BOOL __crfschttp_uri_is_getrgf_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/getrgf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/getrgf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

static EC_BOOL __crfschttp_uri_is_getsmf_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/getsmf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/getsmf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

static EC_BOOL __crfschttp_uri_is_getbgf_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/getbgf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/getbgf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}


static EC_BOOL __crfschttp_uri_is_update_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/update/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/update/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*renew expires setting*/
static EC_BOOL __crfschttp_uri_is_renew_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/renew/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/renew/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

static EC_BOOL __crfschttp_uri_is_dsmf_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/dsmf/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/dsmf/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

static EC_BOOL __crfschttp_uri_is_ddir_op(const CBUFFER *uri_cbuffer)
{
    const uint8_t *uri_str;
    uint32_t       uri_len;
 
    uri_str      = CBUFFER_DATA(uri_cbuffer);
    uri_len      = CBUFFER_USED(uri_cbuffer);

    if(CONST_STR_LEN("/ddir/") < uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/ddir/")))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void crfschttp_csocket_cnode_close(CSOCKET_CNODE *csocket_cnode)
{
    if(NULL_PTR != csocket_cnode)
    {  
        crfschttp_csocket_cnode_defer_close_list_push(csocket_cnode);
    }
    return;
}

EC_BOOL crfschttp_csocket_cnode_defer_close_list_init()
{
    clist_init(&g_csocket_cnode_defer_close_list, MM_CSOCKET_CNODE, LOC_CRFSCHTTP_0001);
    return (EC_TRUE);
}

EC_BOOL crfschttp_csocket_cnode_defer_close_list_push(CSOCKET_CNODE *csocket_cnode)
{
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;

    CLIST_LOCK(&g_csocket_cnode_defer_close_list, LOC_CRFSCHTTP_0002);
    if(NULL_PTR == clist_search_front_no_lock(&g_csocket_cnode_defer_close_list, (void *)csocket_cnode, NULL_PTR))
    {
        clist_push_back_no_lock(&g_csocket_cnode_defer_close_list, (void *)csocket_cnode);
    }
    CLIST_UNLOCK(&g_csocket_cnode_defer_close_list, LOC_CRFSCHTTP_0003);
    return (EC_TRUE);
}

CSOCKET_CNODE *crfschttp_csocket_cnode_defer_close_list_pop()
{
    return (CSOCKET_CNODE *)clist_pop_front(&g_csocket_cnode_defer_close_list);
}

EC_BOOL crfschttp_csocket_cnode_defer_close_list_is_empty()
{
    return clist_is_empty(&g_csocket_cnode_defer_close_list);
}

EC_BOOL crfschttp_csocket_cnode_defer_close_handle()
{
    while(EC_FALSE == crfschttp_csocket_cnode_defer_close_list_is_empty())
    {
        CSOCKET_CNODE *csocket_cnode;
        CRFSCHTTP_NODE *crfschttp_node;
     
        csocket_cnode = crfschttp_csocket_cnode_defer_close_list_pop();
        crfschttp_node = CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode);
        if(NULL_PTR != crfschttp_node)
        {
            crfschttp_node_free(crfschttp_node);
        }
        else
        {
            csocket_cnode_close(csocket_cnode);
        }
    }
    return (EC_TRUE);
}

void crfschttp_csocket_cnode_epoll_close(CSOCKET_CNODE *csocket_cnode)
{
    CEPOLL *cepoll;
 
    cepoll = task_brd_default_get_cepoll(); 
    cepoll_del_all(cepoll, CSOCKET_CNODE_SOCKFD(csocket_cnode));
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    cepoll_set_not_used(cepoll, CSOCKET_CNODE_SOCKFD(csocket_cnode));
 
    if(NULL_PTR != CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode))
    {
        CRFSCHTTP_NODE *crfschttp_node;     
        crfschttp_node = CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode);
        CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node) = NULL_PTR;/*clean*/
        CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode)  = NULL_PTR;/*clean*/
        crfschttp_node_free(crfschttp_node);
    }
    csocket_cnode_close(csocket_cnode);
    return;
}

void crfschttp_node_defer_close(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE *csocket_cnode;
    CEPOLL *cepoll;
 
    cepoll = task_brd_default_get_cepoll();
    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
 
    CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node) = NULL_PTR;/*clean*/
    CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode)  = NULL_PTR;/*clean*/

    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);                   
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    
    cepoll_set_event(cepoll, 
                     CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                     CEPOLL_WR_EVENT,
                     (const char *)"crfschttp_csocket_cnode_epoll_close",
                     (CEPOLL_EVENT_HANDLER)crfschttp_csocket_cnode_epoll_close,
                     (void *)csocket_cnode); 
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
    
    crfschttp_node_free(crfschttp_node);
    return;
}

void crfschttp_csocket_cnode_timeout(CSOCKET_CNODE *csocket_cnode)
{
    dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "warn:crfschttp_csocket_cnode_timeout: csocket_cnode %p sockfd %d node %p timeout, set defer close\n",
                        csocket_cnode, CSOCKET_CNODE_SOCKFD(csocket_cnode), CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode));
    crfschttp_node_defer_close(CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode));
    return;
}

EC_BOOL crfschttp_defer_request_queue_init()
{
    cqueue_init(&g_crfschttp_defer_request_queue, MM_CRFSCHTTP_NODE, LOC_CRFSCHTTP_0004);

    if(EC_FALSE == cepoll_set_loop_handler(task_brd_default_get_cepoll(),
                                            (const char *)"crfschttp_defer_launch",
                                           (CEPOLL_LOOP_HANDLER)crfschttp_defer_launch,
                                           NULL_PTR))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_defer_request_queue_init: set cepoll loop handler failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_defer_request_queue_clean()
{
    cqueue_clean(&g_crfschttp_defer_request_queue, (CQUEUE_DATA_DATA_CLEANER)crfschttp_node_free);
    return (EC_TRUE);
}

EC_BOOL crfschttp_defer_request_queue_push(CRFSCHTTP_NODE *crfschttp_node)
{
    cqueue_push(&g_crfschttp_defer_request_queue, (void *)crfschttp_node);
    return (EC_TRUE);
}

CRFSCHTTP_NODE *crfschttp_defer_request_queue_pop()
{
    return (CRFSCHTTP_NODE *)cqueue_pop(&g_crfschttp_defer_request_queue);
}

CRFSCHTTP_NODE *crfschttp_defer_request_queue_peek()
{
    return (CRFSCHTTP_NODE *)cqueue_front(&g_crfschttp_defer_request_queue);
}

EC_BOOL crfschttp_defer_request_queue_launch()
{
    CRFSCHTTP_NODE *crfschttp_node;

    for(;;)
    {
        crfschttp_node = crfschttp_defer_request_queue_peek();
        if(NULL_PTR == crfschttp_node)/*no more*/
        {
            break;
        }

        if(EC_FALSE == crfschttp_commit_request(crfschttp_node))
        {
            break;
        }

        crfschttp_defer_request_queue_pop();
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_defer_launch(void *UNUSED(none))
{
    crfschttp_defer_request_queue_launch();
    crfschttp_csocket_cnode_defer_close_handle();
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_protocol(CRFSCHTTP_NODE *crfschttp_node, const uint16_t major, const uint16_t minor, const uint32_t status)
{
    uint8_t  header_protocol[64];
    uint32_t len;

    len = snprintf(((char *)header_protocol), sizeof(header_protocol), "HTTP/%d.%d %d %s\r\n",
                   major, minor, status, __crfschttp_status_str_get(status));
                
    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), (uint8_t *)header_protocol, len))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_protocol: node %p, append '%.*s' to chunks failed\n",
                           crfschttp_node, len, (char *)header_protocol);
        return (EC_FALSE);                         
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_date(CRFSCHTTP_NODE *crfschttp_node)
{
    uint8_t  header_date[64];
    uint32_t len;
    ctime_t  time_in_sec;

    time_in_sec = task_brd_default_get_time();

    /*e.g., Date:Thu, 01 May 2014 12:12:16 GMT*/
	len = strftime(((char *)header_date), sizeof(header_date), "Date:%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&time_in_sec)); 
	//dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_make_response_header_date: [%.*s] len = %u\n", len - 1, (char *)header_date, len - 1);
    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), (uint8_t *)header_date, len))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_date: node %p, append '%.*s' to chunks failed\n",
                            crfschttp_node, len, header_date);
        return (EC_FALSE);
    }  
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_expires(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER *expires;

    expires = CRFSCHTTP_NODE_EXPIRES(crfschttp_node);
     
    if(0 < CBUFFER_USED(expires))
    {
        //dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_make_response_header_expires: [%.*s] len = %u\n", CBUFFER_USED(expires), (char *)CBUFFER_DATA(expires), CBUFFER_USED(expires));
        if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), CBUFFER_DATA(expires), CBUFFER_USED(expires)))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_expires: node %p, append '%.*s' to chunks failed\n",
                               crfschttp_node, CBUFFER_USED(expires), CBUFFER_DATA(expires));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_stale(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER *stale;

    stale = CRFSCHTTP_NODE_STALE(crfschttp_node);
     
    if(0 < CBUFFER_USED(stale))
    {
        //dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_make_response_header_stale: [%.*s] len = %u\n", CBUFFER_USED(stale), (char *)CBUFFER_DATA(stale), CBUFFER_USED(stale));
        if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), CBUFFER_DATA(stale), CBUFFER_USED(stale)))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_stale: node %p, append '%.*s' to chunks failed\n",
                               crfschttp_node, CBUFFER_USED(stale), CBUFFER_DATA(stale));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_elapsed(CRFSCHTTP_NODE *crfschttp_node)
{
    uint8_t  header_date[128];
    uint32_t len;
    CTMV    *s_tmv;
    CTMV    *e_tmv;
 
    uint32_t elapsed_msec;

    s_tmv = CRFSCHTTP_NODE_START_TMV(crfschttp_node);
    e_tmv = task_brd_default_get_daytime();

    ASSERT(CTMV_NSEC(e_tmv) >= CTMV_NSEC(s_tmv));
    elapsed_msec = (CTMV_NSEC(e_tmv) - CTMV_NSEC(s_tmv)) * 1000 + CTMV_MSEC(e_tmv) - CTMV_MSEC(s_tmv);

    len = 0;
    len += snprintf(((char *)header_date) + len, sizeof(header_date) - len, "BegTime:%u.%03u\r\n", (uint32_t)CTMV_NSEC(s_tmv), (uint32_t)CTMV_MSEC(s_tmv));
    len += snprintf(((char *)header_date) + len, sizeof(header_date) - len, "EndTime:%u.%03u\r\n", (uint32_t)CTMV_NSEC(e_tmv), (uint32_t)CTMV_MSEC(e_tmv));
    len += snprintf(((char *)header_date) + len, sizeof(header_date) - len, "Elapsed:%u micro seconds\r\n", elapsed_msec);

    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), (uint8_t *)header_date, len))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_elapsed: node %p, append '%.*s' to chunks failed\n",
                            crfschttp_node, len, header_date);
        return (EC_FALSE);
    }  
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_content_type(CRFSCHTTP_NODE *crfschttp_node, const uint8_t *data, const uint32_t size)
{
    if(NULL_PTR == data || 0 == size)
    {
        return (EC_TRUE);
    }

    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), CONST_UINT8_STR_AND_LEN("Content-Type:")))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_content_type: node %p, append 'Content-Type:' to chunks failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    } 

    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), data, size))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_content_type: node %p, append %d bytes to chunks failed\n",
                            crfschttp_node, size);
        return (EC_FALSE);
    }

    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), CONST_UINT8_STR_AND_LEN("\r\n")))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_content_type: node %p, append EOL to chunks failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_content_length(CRFSCHTTP_NODE *crfschttp_node, const uint64_t size)
{
    uint8_t  content_length[64];
    uint32_t len;

    len = snprintf(((char *)content_length), sizeof(content_length), "Content-Length:%ld\r\n", size);

    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), (uint8_t *)content_length, len))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_content_length: node %p, append '%.*s' to chunks failed\n",
                           crfschttp_node, len, (char *)content_length);
        return (EC_FALSE);                         
    }
/* 
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_make_response_header_content_length: node %p, append '%.*s' to chunks done\n",
                       crfschttp_node, len, (char *)content_length); 
*/                    
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_location(CRFSCHTTP_NODE *crfschttp_node)
{
    TASK_BRD       *task_brd;

    MOD_NODE       *des_mod_node;

    TASKS_CFG      *tasks_cfg;

    CSTRING         location_str;
    CBUFFER        *uri_cbuffer;
    uint8_t        *location;
    uint32_t        len;

    task_brd        = task_brd_default_get(); 
    des_mod_node    = CRFSCHTTP_NODE_MOD_NODE(crfschttp_node);

    tasks_cfg = sys_cfg_search_tasks_cfg_by_csrv(TASK_BRD_SYS_CFG(task_brd), MOD_NODE_TCID(des_mod_node), CMPI_ANY_SRVPORT); 
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_location: node %p, search tasks_cfg of tcid %s\n",
                           crfschttp_node, MOD_NODE_TCID_STR(des_mod_node));
        return (EC_FALSE);                         
    }

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_getsmf: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    cstring_init(&location_str, NULL_PTR);
    cstring_format(&location_str, "Location:http://%s:%ld%.*s\r\n",
                                  TASKS_CFG_SRVIPADDR_STR(tasks_cfg) ,
                                  TASKS_CFG_CSRVPORT(tasks_cfg),
                                  CBUFFER_USED(uri_cbuffer),
                                  CBUFFER_DATA(uri_cbuffer));

    len = (uint32_t)cstring_get_len(&location_str);
    location = cstring_get_str(&location_str);
    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), location, len))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_location: node %p, append '%.*s' to chunks failed\n",
                           crfschttp_node, len, (char *)location);
        cstring_clean(&location_str);
        return (EC_FALSE);                         
    }
    cstring_clean(&location_str);
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header_end(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), CONST_UINT8_STR_AND_LEN("\r\n")))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header_content_length: node %p, append '\r\n' to chunks failed\n",
                            crfschttp_node);
        return (EC_FALSE);                         
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_body(CRFSCHTTP_NODE *crfschttp_node, const uint8_t *data, const uint32_t size)
{
    if(NULL_PTR == data || 0 == size)
    {
        return (EC_TRUE);
    }

    //dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_make_response_body: body: '%.*s'\n", size, data);
    if(EC_FALSE == chunk_mgr_append_data(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), data, size))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_body: node %p, append %d bytes to chunks failed\n",
                            crfschttp_node, size);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_response_header(CRFSCHTTP_NODE *crfschttp_node, const uint64_t body_len)
{
    if(EC_FALSE == crfschttp_make_response_header_protocol(crfschttp_node,
                                                          CRFSCHTTP_VERSION_MAJOR, CRFSCHTTP_VERSION_MINOR,
                                                          CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node)))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header protocol failed\n", crfschttp_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfschttp_make_response_header_date(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header date failed\n", crfschttp_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfschttp_make_response_header_expires(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header expires failed\n", crfschttp_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfschttp_make_response_header_stale(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header stale failed\n", crfschttp_node);
        return (EC_FALSE);
    }  

    if(EC_FALSE == crfschttp_make_response_header_elapsed(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header elapsed failed\n", crfschttp_node);
        return (EC_FALSE);
    }   

    if(EC_FALSE == crfschttp_make_response_header_content_type(crfschttp_node, NULL_PTR, 0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header content type failed\n", crfschttp_node);
        return (EC_FALSE);
    } 

    if(EC_FALSE == crfschttp_make_response_header_content_length(crfschttp_node, body_len))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header content length failed\n", crfschttp_node);     
        return (EC_FALSE);
    }

    if(CRFSCHTTP_MOVED_TEMPORARILY == CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node))/*302*/
    {
        if(EC_FALSE == crfschttp_make_response_header_location(crfschttp_node))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header 302 location failed\n", crfschttp_node);     
            return (EC_FALSE);
        } 
    }

    if(EC_FALSE == crfschttp_make_response_header_end(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_response_header: node %p, make header end failed\n", crfschttp_node);
        return (EC_FALSE);
    }

    if(do_log(SEC_0145_CRFSCHTTP, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] crfschttp_make_response_header: node %p, response header is\n", crfschttp_node);
        chunk_mgr_print_str(LOGSTDOUT, CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node));
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_setsmf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_setsmf_response: node %p, make response header failed\n", crfschttp_node);
     
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_update_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_update_response: node %p, make response header failed\n", crfschttp_node);
     
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_error_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_error_response: node %p, make error response header failed\n", crfschttp_node);
     
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_put_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_put_response: node %p, make response header failed\n", crfschttp_node);
     
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_post_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_post_response: node %p, make response header failed\n", crfschttp_node);
     
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_getrgf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
    uint64_t       store_size;
    
    uri_cbuffer   = CRFSCHTTP_NODE_URI(crfschttp_node);
    store_size    = CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node);

    if(do_log(SEC_0145_CRFSCHTTP, 9))
    {
        uint8_t       *cache_key;
        uint32_t       cache_len;
 
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getrgf");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getrgf");
     
        sys_log(LOGSTDOUT, "[DEBUG] crfschttp_make_getrgf_response: node %p, path %.*s\n", crfschttp_node, cache_len, cache_key);
        sys_log(LOGSTDOUT, "[DEBUG] crfschttp_make_getrgf_response: node %p, store_size %ld\n", crfschttp_node, store_size);
    } 

    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, store_size))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_getrgf_response: node %p, make response header failed\n", crfschttp_node);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_getsmf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;

    CBYTES        *content_cbytes;
    uint64_t       content_len;
 
    uri_cbuffer    = CRFSCHTTP_NODE_URI(crfschttp_node);
    content_cbytes = CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node);
    content_len    = CBYTES_LEN(content_cbytes);

    if(do_log(SEC_0145_CRFSCHTTP, 9))
    {
        uint8_t       *cache_key;
        uint32_t       cache_len;
 
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getsmf");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getsmf");
     
        sys_log(LOGSTDOUT, "[DEBUG] crfschttp_make_getsmf_response: node %p, path %.*s\n", crfschttp_node, cache_len, cache_key);
    }

    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, content_len))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_getsmf_response: node %p, make response header failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == crfschttp_make_response_body(crfschttp_node,
                                              CBYTES_BUF(content_cbytes),
                                              (uint32_t)CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_getsmf_response: node %p, make body with len %d failed\n",
                           crfschttp_node, (uint32_t)CBYTES_LEN(content_cbytes));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_getbgf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
    uint64_t       store_size;
    
    uri_cbuffer   = CRFSCHTTP_NODE_URI(crfschttp_node);
    store_size    = CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node);

    if(do_log(SEC_0145_CRFSCHTTP, 9))
    {
        uint8_t       *cache_key;
        uint32_t       cache_len;
 
        cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getbgf");
        cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getbgf");
     
        sys_log(LOGSTDOUT, "[DEBUG] crfschttp_make_getbgf_response: node %p, path %.*s\n", crfschttp_node, cache_len, cache_key);
        sys_log(LOGSTDOUT, "[DEBUG] crfschttp_make_getbgf_response: node %p, store_size %ld\n", crfschttp_node, store_size);
    } 

    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, store_size))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_getbgf_response: node %p, make response header failed\n", crfschttp_node);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL crfschttp_make_dsmf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_dsmf_response: node %p, make response header failed\n", crfschttp_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_ddir_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_ddir_response: node %p, make response header failed\n", crfschttp_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_make_renew_response(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_make_response_header(crfschttp_node, (uint64_t)0))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_make_renew_response: node %p, make response header failed\n", crfschttp_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


EC_BOOL crfschttp_handle_renew_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);
 
    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/renew");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/renew");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_renew_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    if(EC_TRUE == __crfschttp_uri_is_renew_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char    *expired_str;
        uint32_t expired_nsec;

        expired_str  = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expires");
        expired_nsec = c_str_to_uint32_t(expired_str);
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        if(EC_FALSE == crfsc_renew(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, expired_nsec))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_renew_request: node %p, crfsc renew %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
         
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
    } 

    else
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_renew_request: node %p, should never reach here!\n",
                            crfschttp_node);     
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
 
    /*clean body chunks*/
    chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));

    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_setsmf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);
    content_len  = CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node);
    ASSERT((uint64_t)0x100000000 > content_len);/*not consider this scenario yet*/

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_setsmf_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    body_len = chunk_mgr_total_length(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));
    ASSERT((uint64_t)0x100000000 > body_len);/*not consider this scenario yet*/

    if(content_len > body_len)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "warn:crfschttp_handle_setsmf_request: node %p, content_len %lld > body_len %lld\n",
                            crfschttp_node, content_len, body_len);

        //chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));/*recycle space asap*/
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_PARTIAL_CONTENT;
     
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new((UINT32)body_len);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_setsmf_request: node %p, new cbytes with len %d failed\n",
                            crfschttp_node, (UINT32)body_len);
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chunk_mgr_export(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node), CBYTES_BUF(content_cbytes), CBYTES_LEN(content_cbytes), &CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_setsmf_request: node %p, export body with len %ld to cbytes failed\n",
                            crfschttp_node, cbytes_len(content_cbytes));
                         
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INTERNAL_SERVER_ERROR;
     
        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    } 
 
    if(EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char    *expired_str;
        uint32_t expired_nsec;

        expired_str  = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expires");
        expired_nsec = c_str_to_uint32_t(expired_str);
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        if(EC_FALSE == crfsc_write(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_setsmf_request: node %p, crfsc write %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
         
            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
         
            return (EC_TRUE);
        }
    }
 
    else
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_setsmf_request: node %p, should never reach here!\n",
                            crfschttp_node);     
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);
 
    /*clean body chunks*/
    chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));

    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_update_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);
    content_len  = CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node);
    ASSERT((uint64_t)0x100000000 > content_len);/*not consider this scenario yet*/

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/update");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/update");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_update_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    body_len = chunk_mgr_total_length(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));
    ASSERT((uint64_t)0x100000000 > body_len);/*not consider this scenario yet*/

    if(content_len > body_len)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "warn:crfschttp_handle_update_request: node %p, content_len %lld > body_len %lld\n",
                            crfschttp_node, content_len, body_len);

        //chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));/*recycle space asap*/
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_PARTIAL_CONTENT;
     
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new((UINT32)body_len);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_update_request: node %p, new cbytes with len %d failed\n",
                            crfschttp_node, (UINT32)body_len);
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chunk_mgr_export(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node), CBYTES_BUF(content_cbytes), CBYTES_LEN(content_cbytes), &CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_update_request: node %p, export body with len %ld to cbytes failed\n",
                            crfschttp_node, cbytes_len(content_cbytes));
                         
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INTERNAL_SERVER_ERROR;
     
        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    } 

    else if(EC_TRUE == __crfschttp_uri_is_update_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char    *expired_str;
        uint32_t expired_nsec;

        expired_str  = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expires");
        expired_nsec = c_str_to_uint32_t(expired_str);
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        if(EC_FALSE == crfsc_update(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_update_request: node %p, crfsc update %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
         
            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
    } 
    else
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_update_request: node %p, should never reach here!\n",
                            crfschttp_node);     
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);
 
    /*clean body chunks*/
    chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));

    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_put_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);
    content_len  = CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node);
    ASSERT((uint64_t)0x100000000 > content_len);/*not consider this scenario yet*/

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_put_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    body_len = chunk_mgr_total_length(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));
    ASSERT((uint64_t)0x100000000 > body_len);/*not consider this scenario yet*/

    if(content_len > body_len)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "warn:crfschttp_handle_put_request: node %p, content_len %lld > body_len %lld\n",
                            crfschttp_node, content_len, body_len);

        //chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));/*recycle space asap*/
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_PARTIAL_CONTENT;
     
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new((UINT32)body_len);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_put_request: node %p, new cbytes with len %d failed\n",
                            crfschttp_node, (UINT32)body_len);
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chunk_mgr_export(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node), CBYTES_BUF(content_cbytes), CBYTES_LEN(content_cbytes), &CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_put_request: node %p, export body with len %ld to cbytes failed\n",
                            crfschttp_node, cbytes_len(content_cbytes));
                         
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INTERNAL_SERVER_ERROR;
     
        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    } 
 
    if(EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char    *expired_str;
        uint32_t expired_nsec;

        expired_str  = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expires");
        expired_nsec = c_str_to_uint32_t(expired_str);
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        //if(EC_FALSE == crfsc_write_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec, CRFSC_MAX_REPLICA_NUM))
        if(EC_FALSE == crfsc_write(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_put_request: node %p, crfsc write %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
         
            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
    }

    else if(EC_TRUE == __crfschttp_uri_is_update_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char    *expired_str;
        uint32_t expired_nsec;

        expired_str  = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expires");
        expired_nsec = c_str_to_uint32_t(expired_str);
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        if(EC_FALSE == crfsc_update(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_put_request: node %p, crfsc update %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
         
            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
    } 
    else
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_put_request: node %p, should never reach here!\n",
                            crfschttp_node);     
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);
 
    /*clean body chunks*/
    chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));

    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_post_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    uint64_t       body_len;
    uint64_t       content_len;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);
    content_len  = CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node);
    ASSERT((uint64_t)0x100000000 > content_len);/*not consider this scenario yet*/

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_post_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    body_len = chunk_mgr_total_length(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));
    ASSERT((uint64_t)0x100000000 > body_len);/*not consider this scenario yet*/

    if(content_len > body_len)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "warn:crfschttp_handle_post_request: node %p, content_len %lld > body_len %lld\n",
                            crfschttp_node, content_len, body_len);

        //chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));/*recycle space asap*/
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_PARTIAL_CONTENT;
     
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    content_cbytes = cbytes_new((UINT32)body_len);
    if(NULL_PTR == content_cbytes)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_post_request: node %p, new cbytes with len %d failed\n",
                            crfschttp_node, (UINT32)body_len);
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INSUFFICIENT_STORAGE;
        cstring_clean(&path_cstr);
        return (EC_TRUE);
    }

    if(EC_FALSE == chunk_mgr_export(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node), CBYTES_BUF(content_cbytes), CBYTES_LEN(content_cbytes), &CBYTES_LEN(content_cbytes)))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_post_request: node %p, export body with len %ld to cbytes failed\n",
                            crfschttp_node, cbytes_len(content_cbytes));
                         
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INTERNAL_SERVER_ERROR;
     
        cstring_clean(&path_cstr);
        cbytes_free(content_cbytes);
        return (EC_TRUE);
    } 
 
    if(EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char    *expired_str;
        uint32_t expired_nsec;

        expired_str  = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expires");
        expired_nsec = c_str_to_uint32_t(expired_str);
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        //if(EC_FALSE == crfsc_write_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec, CRFSC_MAX_REPLICA_NUM))
        if(EC_FALSE == crfsc_write(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_post_request: node %p, crfsc write %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
         
            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
    }

    else if(EC_TRUE == __crfschttp_uri_is_update_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        char    *expired_str;
        uint32_t expired_nsec;

        expired_str  = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expires");
        expired_nsec = c_str_to_uint32_t(expired_str);
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        if(EC_FALSE == crfsc_update(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, expired_nsec))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_post_request: node %p, crfsc update %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
         
            cstring_clean(&path_cstr);
            cbytes_free(content_cbytes);
            return (EC_TRUE);
        }
    }
 
    else
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_post_request: node %p, should never reach here!\n",
                            crfschttp_node);     
        task_brd_default_abort();
    }
 
    cstring_clean(&path_cstr);
    cbytes_free(content_cbytes);
 
    /*clean body chunks*/
    chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));

    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getrgf_request_send_block(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);

    if(CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node) < CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node))
    { 
        UINT32 pos;

        pos = CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node);
        if(EC_FALSE == csocket_sendfile(CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                   CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node),
                                   CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node),
                                   &pos))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getrgf_request_send_block: node %p, sockfd %d sendfile %ld bytes failed\n",
                               crfschttp_node,
                               CSOCKET_CNODE_SOCKFD(csocket_cnode),
                               CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node) - CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)
                               );
            return (EC_FALSE);                        
        }
#if 0
        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getrgf_request_send_body: write %ld bytes from %ld to %ld\n",
                           pos - CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node),
                           CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node), pos);
#endif
        CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) += (pos - CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node));
        CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)    = pos;
    }

    if(CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node) < CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node))
    {
        /*wait for next writing*/
        return (EC_TRUE);
    }

    CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node) = 0;
    CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)  = 0;

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getrgf_request_send_block: node %p, write offset reach %ld\n",
                       crfschttp_node, CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node));
    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getrgf_request_send_block_more(CRFSCHTTP_NODE *crfschttp_node)
{
    /*send data*/
    if(EC_FALSE == __crfschttp_handle_getrgf_request_send_block(crfschttp_node))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
 
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getrgf_request_send_block_more: node %p, sockfd %d send body failed where store [%ld, %ld) and reached %ld\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node)
                           );
        return (EC_FALSE);                        
    }

    if(CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) >= CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);

        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getrgf_request_send_block_more: node %p, sockfd %d send [%ld, %ld) and len %ld done\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node)
                           );

        if(ERR_FD != CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node))
        {
            c_file_close(CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node));
            CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node) = ERR_FD;
        }
     
        return (EC_TRUE);                        
    }

    /*wait for next sending*/

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getrgf_request_fetch_path(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
    CSTRING       *store_path; 
    uint8_t       *cache_key;
    uint32_t       cache_len;

    uri_cbuffer   = CRFSCHTTP_NODE_URI(crfschttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getrgf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getrgf");
 
    store_path = cstring_new(NULL_PTR, LOC_CRFSCHTTP_0005);
    if(NULL_PTR == store_path)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getrgf_request_fetch_path: node %p, new cstring for store path %.*s failed\n",
                            crfschttp_node, cache_len, cache_key);
        return (EC_FALSE);
    }
    cstring_append_chars(store_path, cache_len, cache_key);
    CRFSCHTTP_NODE_STORE_PATH(crfschttp_node) = store_path;

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_getrgf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE *csocket_cnode;

    CSTRING       *store_path;

    CBYTES        *content_cbytes;

    char          *data_offset_str;
    char          *data_size_str;

    uint64_t       store_size_of_file;

    int            fd;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    if(EC_FALSE == __crfschttp_handle_getrgf_request_fetch_path(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getrgf_request: node %p, fetch store path failed\n",
                            crfschttp_node);

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
                          
        //return (EC_FALSE);
        return (EC_TRUE);
    }
    store_path = CRFSCHTTP_NODE_STORE_PATH(crfschttp_node);
 
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getrgf_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(store_path));

    /*clean content which will never be used*/
    ASSERT(0 == chunk_mgr_count_chunks(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)));
    content_cbytes = CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node);
    cbytes_clean(content_cbytes);

    /*open file*/
    fd = c_file_open((char *)cstring_get_str(store_path), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getrgf_request: node %p, open file %s failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path));

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
    
        //return (EC_FALSE);
        return (EC_TRUE);
    }

    /*get file size*/
    if(EC_FALSE == c_file_size_b(fd, &store_size_of_file))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getrgf_request: node %p, get size of file %s failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path));

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
        c_file_close(fd);
        //return (EC_FALSE);
        return (EC_TRUE);
    }

    CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node)   = fd;

    /*set default [beg, end)*/
    CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) = 0;
    CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) = store_size_of_file;
#if 0
    /*check validity: only support < 4G regural file*/
    if(0 < (store_size_of_file >> 32))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getrgf_request: file %s size %ld overflow\n",
                            (char *)cstring_get_str(store_path), store_size_of_file);

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
        c_file_close(fd);
        //return (EC_FALSE);
        return (EC_TRUE);
    }
#endif 
    data_offset_str = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"store_offset");
    data_size_str   = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"store_size");

    if(NULL_PTR != data_offset_str)
    {
        uint64_t   data_offset;
     
        data_offset = c_str_to_uint64_t(data_offset_str);
        if(data_offset >= store_size_of_file) /*invalid offset*/
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getrgf_request: node %p, crfsc file %s, data_offset %ld >= store_size_of_file %ld\n",
                                crfschttp_node, (char *)cstring_get_str(store_path), data_offset, store_size_of_file);

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
        
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) = data_offset;
    }

    if(NULL_PTR != data_size_str)
    {
        uint64_t  data_len;
     
        data_len  = c_str_to_uint64_t(data_size_str);/*note: when data_size_str is null, data_len is zero*/

        /*if 0 == data_len, from offset to end of file*/
        /*else if data_len + beg > end, from offset to end of file*/
        /*else, from offset to beg + end*/

        if(0 == data_len) /*ok, from offset to end of file*/
        {
            /*nothing to do*/
        }

        else if (data_len + CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) > CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node))
        {
            /*nothing to do*/
        }

        else
        {
            CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) = CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) + data_len;
        }
    }

    /*set cur*/
    CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) = CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node);
 
    /*set http status code: OK*/
    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;

    CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node)      = __crfschttp_handle_getrgf_request_send_block_more;
    CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node)      = NULL_PTR;
    CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)  = 0;

    CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)      = (UINT32)CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node);
    CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node)     = (UINT32)CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getrgf_request: node %p, to read file %s in range [%ld, %ld) and len %ld\n",
                       crfschttp_node,
                       (char *)cstring_get_str(store_path),
                       CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                       CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                       CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node));

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_getsmf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;
    CBYTES        *content_cbytes;

    char          *expired_body_str;
    char          *store_offset_str;
    char          *store_size_str;

    EC_BOOL        expired_body_needed;
    UINT32         expires_timestamp;
    char           expires_str[64];
    uint32_t       expires_str_len;
    CTIMET         cur_time;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getsmf");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getsmf_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    ASSERT(0 == chunk_mgr_count_chunks(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)));

    content_cbytes = CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node);
    cbytes_clean(content_cbytes);

    expired_body_str = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expired_body");
    if(NULL_PTR == expired_body_str || 0 == c_str_to_uint32_t(expired_body_str))
    {
        expired_body_needed = EC_TRUE;/*even if file expired, return file content*/
    }
    else
    {
        expired_body_needed = EC_FALSE;/*if file expired, NOT return file content*/
    }

    store_offset_str = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"store_offset");
    if(NULL_PTR != store_offset_str)
    {
        CSOCKET_CNODE * csocket_cnode;
     
        uint32_t store_offset;
        uint32_t store_size;
     
        UINT32   offset;
        UINT32   max_len;
     
        store_size_str   = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"store_size");

        store_offset = c_str_to_uint32_t(store_offset_str);
        store_size   = c_str_to_uint32_t(store_size_str);/*note: when store_size_str is null, store_size is zero*/

        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        offset        = store_offset;
        max_len       = store_size;
     
        if(EC_FALSE == crfsc_read_e(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, &offset, max_len, content_cbytes, &expires_timestamp, expired_body_needed))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "warn:crfschttp_handle_getsmf_request: node %p, crfsc read %s with offset %u, size %u failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr), store_offset, store_size);

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
         
            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            return (EC_TRUE);
        }
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;     
     
    }
    else/*read whole file content*/
    {
        CSOCKET_CNODE * csocket_cnode;     
     
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        if(EC_FALSE == crfsc_read(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, content_cbytes, &expires_timestamp, expired_body_needed))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "warn:crfschttp_handle_getsmf_request: node %p, crfsc read %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
         
            cstring_clean(&path_cstr);
            cbytes_clean(content_cbytes);
            return (EC_TRUE);
        }
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;
    }

    expires_str_len = snprintf(expires_str, sizeof(expires_str), "Expires:%ld\r\n", expires_timestamp);
    cbuffer_set(CRFSCHTTP_NODE_EXPIRES(crfschttp_node), (uint8_t *)expires_str, expires_str_len);

    cur_time = task_brd_default_get_time();
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getsmf_request: node %p, file '%s', expires_timestamp %ld, current time %ld\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr), expires_timestamp, cur_time);

    if(0 < expires_timestamp && expires_timestamp < cur_time)
    {
        cbuffer_set(CRFSCHTTP_NODE_STALE(crfschttp_node), CONST_UINT8_STR_AND_LEN("Stale:1\r\n")); 
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getbgf_request_read_body(CRFSCHTTP_NODE *crfschttp_node)
{    
    CSOCKET_CNODE *csocket_cnode;

    uint64_t   offset;
    uint64_t   offset_save;
    UINT32     max_len;

    EC_BOOL    expires_timestamp;
    EC_BOOL    expired_body_needed;

    CSTRING   *store_path;
    CBYTES     data_cbytes;
 
    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node); 

    offset        = CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node);
    offset_save   = offset;  
    max_len       = CPGB_CACHE_MAX_BYTE_SIZE;/*adjust later*/

    store_path    = CRFSCHTTP_NODE_STORE_PATH(crfschttp_node);
 
    if(NULL_PTR == CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node))
    {
        uint8_t *data_buff;

        data_buff = safe_malloc(max_len, LOC_CRFSCHTTP_0006);
        if(NULL_PTR == data_buff)
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_read_body: node %p, malloc %ld bytes failed before read path %s from offset %ld\n",
                                crfschttp_node, max_len, (char *)cstring_get_str(store_path), offset_save);

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INTERNAL_SERVER_ERROR;
         
            //return (EC_FALSE);
            return (EC_TRUE);
        } 
        CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node) = data_buff;
    }

    /*adjust max_len*/
    if(CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) < CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) + CPGB_CACHE_MAX_BYTE_SIZE)
    {
        max_len = (UINT32)(CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) - CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node));
    }
    cbytes_init(&data_cbytes);
    cbytes_mount(&data_cbytes, max_len, CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node));
 

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_read_body: node %p, read offset reach %ld\n",
                        crfschttp_node, offset);

    expired_body_needed = CRFSCHTTP_NODE_EXPIRED_BODY_NEED(crfschttp_node);
    if(EC_FALSE == crfsc_read_b(CSOCKET_CNODE_MODI(csocket_cnode), store_path, &offset, max_len, &data_cbytes, &expires_timestamp, expired_body_needed))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_read_body: node %p, crfsc read %s from offset %ld, max_len %u failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path), offset_save, max_len);

        return (EC_FALSE);
    }

    CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node)      = cbytes_buf(&data_cbytes);
    CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) = (offset - offset_save);
    CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)  = 0;

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getbgf_request_send_body(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);

    if(CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node) < CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node))
    { 
        UINT32 pos;

        pos = CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node);
        if(EC_FALSE == csocket_cnode_send(csocket_cnode,
                                   CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node),
                                   CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node),
                                   &pos))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_send_body: node %p, sockfd %d send %ld bytes failed\n",
                               crfschttp_node,
                               CSOCKET_CNODE_SOCKFD(csocket_cnode),
                               CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) - CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)
                               );
            return (EC_FALSE);                        
        }
#if 0
        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_send_body: write %ld bytes from %ld to %ld\n",
                           pos - CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node),
                           CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node), pos);
#endif
        CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node)  += (pos - CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node));
        CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node) = pos;
    }

    if(CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node) < CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node))
    {
        /*wait for next writing*/
        return (EC_TRUE);
    }

    CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)  = 0;

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_send_body: node %p, write offset reach %ld\n",
                       crfschttp_node, CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node));
    return (EC_TRUE);
}
static EC_BOOL __crfschttp_handle_getbgf_request_send_body_more(CRFSCHTTP_NODE *crfschttp_node)
{
    /*send data*/
    if(EC_FALSE == __crfschttp_handle_getbgf_request_send_body(crfschttp_node))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
 
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_send_body_more: node %p, sockfd %d send body failed where store [%ld, %ld) and reached %ld\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node)
                           );
        return (EC_FALSE);                        
    }

    if(CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) >= CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);

        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_send_body_more: node %p, sockfd %d send [%ld, %ld) and len %ld done\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node)
                           );

        /*cleanup possible WR epoll event*/
        crfschttp_node_defer_close(crfschttp_node);
        return (EC_TRUE);                        
    }

    /*read data for next sending*/
    if(EC_FALSE ==__crfschttp_handle_getbgf_request_read_body(crfschttp_node))
    {
        CSTRING *store_path;

        store_path = CRFSCHTTP_NODE_STORE_PATH(crfschttp_node);
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_send_body_more: node %p, crfsc read %s failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path));
    
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*get block fd and pos*/
static EC_BOOL __crfschttp_handle_getbgf_request_read_block(CRFSCHTTP_NODE *crfschttp_node)
{    
    CSOCKET_CNODE *csocket_cnode;

    uint64_t   offset;
    uint32_t   max_len;

    EC_BOOL    expires_timestamp;
    EC_BOOL    expired_body_needed;

    CSTRING   *store_path;

    uint32_t   block_size;
    int        block_fd;
 
    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node); 

    offset        = CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node);
    max_len       = CPGB_CACHE_MAX_BYTE_SIZE;/*adjust later*/

    store_path    = CRFSCHTTP_NODE_STORE_PATH(crfschttp_node);

    /*adjust max_len*/
    if(CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) < CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) + CPGB_CACHE_MAX_BYTE_SIZE)
    {
        max_len = (UINT32)(CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) - CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node));
    }

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_read_block: node %p, read offset reach %ld\n",
                        crfschttp_node, offset);

    expired_body_needed = CRFSCHTTP_NODE_EXPIRED_BODY_NEED(crfschttp_node);
 
    if(EC_FALSE == crfsc_fetch_block_fd_b_ep(CSOCKET_CNODE_MODI(csocket_cnode), store_path,
                                          offset, &expires_timestamp, expired_body_needed,
                                          &block_size, &block_fd))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_read_block: node %p, crfsc fetch %s from offset %ld, max_len %u failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path), offset, max_len);
    
        return (EC_FALSE);
    }

    CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node)   = block_fd;
    CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node) = block_size;
    CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)  = (UINT32)(offset % CPGB_CACHE_MAX_BYTE_SIZE);

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getbgf_request_send_block(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);

    if(CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node) < CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node))
    { 
        UINT32 pos;

        pos = CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node);
        if(EC_FALSE == csocket_sendfile(CSOCKET_CNODE_SOCKFD(csocket_cnode),
                                   CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node),
                                   CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node),
                                   &pos))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_send_block: node %p, sockfd %d sendfile %ld bytes failed\n",
                               crfschttp_node,
                               CSOCKET_CNODE_SOCKFD(csocket_cnode),
                               CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node) - CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)
                               );
            return (EC_FALSE);
        }

        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_send_body: node %p, sockfd %d write %ld (%ld -> %ld) bytes from %ld to %ld\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           pos - CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node),
                           CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node), pos,
                           CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) + (pos - CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)));

        CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) += (pos - CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node));
        CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)    = pos;
    }

    if(CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node) < CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node))
    {
        /*wait for next writing*/
        return (EC_TRUE);
    }

    CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node) = 0;
    CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)  = 0;

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_send_block: node %p, write offset reach %ld\n",
                       crfschttp_node, CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node));
    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getbgf_request_send_block_more(CRFSCHTTP_NODE *crfschttp_node)
{
    /*send data*/
    if(EC_FALSE == __crfschttp_handle_getbgf_request_send_block(crfschttp_node))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
 
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_send_block_more: node %p, sockfd %d send body failed where store [%ld, %ld) and reached %ld\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node)
                           );
        return (EC_FALSE);                        
    }

    if(CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) >= CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node))
    {
        CSOCKET_CNODE * csocket_cnode;

        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);

        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_handle_getbgf_request_send_block_more: node %p, sockfd %d send [%ld, %ld) and len %ld done\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                           CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node)
                           );

        /*cleanup possible WR epoll event*/
        crfschttp_node_defer_close(crfschttp_node);
        return (EC_TRUE);                        
    }

    /*read block (fd) for next sending*/
    if(EC_FALSE ==__crfschttp_handle_getbgf_request_read_block(crfschttp_node))
    {
        CSTRING *store_path;

        store_path = CRFSCHTTP_NODE_STORE_PATH(crfschttp_node);
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_send_block_more: node %p, crfsc read %s failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path));
    
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getbgf_request_fetch_path(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
    CSTRING       *store_path; 
    uint8_t       *cache_key;
    uint32_t       cache_len;

    uri_cbuffer   = CRFSCHTTP_NODE_URI(crfschttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/getbgf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/getbgf");
 
    store_path = cstring_new(NULL_PTR, LOC_CRFSCHTTP_0007);
    if(NULL_PTR == store_path)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_handle_getbgf_request_fetch_path: node %p, new cstring for store path %.*s failed\n",
                            crfschttp_node, cache_len, cache_key);
        return (EC_FALSE);
    }
    cstring_append_chars(store_path, cache_len, cache_key);
    CRFSCHTTP_NODE_STORE_PATH(crfschttp_node) = store_path;

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_handle_getbgf_request_fetch_expired_body_need(CRFSCHTTP_NODE *crfschttp_node)
{
    char          *expired_body_str;
    EC_BOOL        expired_body_needed;
 
    expired_body_str = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"Expired_body");
    if(NULL_PTR == expired_body_str || 0 == c_str_to_uint32_t(expired_body_str))
    {
        expired_body_needed = EC_TRUE;/*even if file expired, return file content*/
    }
    else
    {
        expired_body_needed = EC_FALSE;/*if file expired, NOT return file content*/
    }
    CRFSCHTTP_NODE_EXPIRED_BODY_NEED(crfschttp_node) = expired_body_needed;

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_getbgf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE *csocket_cnode;

    CSTRING       *store_path;

    CBYTES        *content_cbytes;

    char          *data_offset_str;
    char          *data_size_str;

    EC_BOOL        expired_body_needed;
    UINT32         expires_timestamp;
    char           expires_str[64];
    uint32_t       expires_str_len;
    //int            sock_sendbuf_size;
    uint64_t       store_size_of_file;
    MOD_NODE      *des_mod_node;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    if(EC_FALSE == __crfschttp_handle_getbgf_request_fetch_path(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getbgf_request: node %p, fetch store path failed\n",
                            crfschttp_node);

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
                          
        //return (EC_FALSE);
        return (EC_TRUE);
    }
    store_path = CRFSCHTTP_NODE_STORE_PATH(crfschttp_node);
 
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getbgf_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(store_path));

    des_mod_node = CRFSCHTTP_NODE_MOD_NODE(crfschttp_node);
    if(EC_FALSE == crfsc_file_mod_node(CSOCKET_CNODE_MODI(csocket_cnode), store_path, des_mod_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getbgf_request: node %p, crfsc get mod_node of file %s failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path));

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
    
        //return (EC_FALSE);
        return (EC_TRUE);
    }

    if(EC_FALSE == mod_node_is_local(des_mod_node))
    {
        /*302*/
        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getbgf_request: node %p, crfsc redirect to %s for file %s\n",
                            crfschttp_node, MOD_NODE_TCID_STR(des_mod_node), (char *)cstring_get_str(store_path));     
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_MOVED_TEMPORARILY;
        return (EC_TRUE);
    }
 
#if 0
    sock_sendbuf_size = 128 * 1024;
    if(EC_FALSE == csocket_set_sendbuf_size(CSOCKET_CNODE_SOCKFD(csocket_cnode), sock_sendbuf_size))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getbgf_request: sockfd %d set sendbuf size %d failed\n",
                            CSOCKET_CNODE_SOCKFD(csocket_cnode), sock_sendbuf_size);

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_INTERNAL_SERVER_ERROR;
                          
        //return (EC_FALSE);
        return (EC_TRUE);
    }
#endif
    /*clean content which will never be used*/
    ASSERT(0 == chunk_mgr_count_chunks(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)));
    content_cbytes = CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node);
    cbytes_clean(content_cbytes);

    /*get expired_body_need flag*/
    __crfschttp_handle_getbgf_request_fetch_expired_body_need(crfschttp_node);
    expired_body_needed = CRFSCHTTP_NODE_EXPIRED_BODY_NEED(crfschttp_node);

    /*get file store_size*/
    if(EC_FALSE == crfsc_store_size_b(CSOCKET_CNODE_MODI(csocket_cnode), store_path, &store_size_of_file, &expires_timestamp))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getbgf_request: node %p, crfsc get store size of file %s failed\n",
                            crfschttp_node, (char *)cstring_get_str(store_path));

        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
    
        //return (EC_FALSE);
        return (EC_TRUE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getbgf_request: node %p, crfsc get store size of file %s is %ld\n",
                        crfschttp_node, (char *)cstring_get_str(store_path), store_size_of_file); 

    /*set default [beg, end)*/
    CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) = 0;
    CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) = store_size_of_file;
 
    data_offset_str = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"store_offset");
    data_size_str   = cstrkv_mgr_get_val_str(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), (const char *)"store_size");

    if(NULL_PTR != data_offset_str)
    {
        uint64_t   data_offset;
     
        data_offset = c_str_to_uint64_t(data_offset_str);
        if(data_offset >= store_size_of_file) /*invalid offset*/
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_getbgf_request: node %p, crfsc file %s, data_offset %ld >= store_size_of_file %ld\n",
                                crfschttp_node, (char *)cstring_get_str(store_path), data_offset, store_size_of_file);

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
        
            //return (EC_FALSE);
            return (EC_TRUE);
        }

        CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) = data_offset;
    }

    if(NULL_PTR != data_size_str)
    {
        uint64_t  data_len;
     
        data_len  = c_str_to_uint64_t(data_size_str);/*note: when data_size_str is null, data_len is zero*/

        /*if 0 == data_len, from offset to end of file*/
        /*else if data_len + beg > end, from offset to end of file*/
        /*else, from offset to beg + end*/

        if(0 == data_len) /*ok, from offset to end of file*/
        {
            /*nothing to do*/
        }

        else if (data_len + CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) > CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node))
        {
            /*nothing to do*/
        }

        else
        {
            CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) = CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node) + data_len;
        }
    }

    /*set cur*/
    CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node) = CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node);
 
    /*set http status code: OK*/
    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;

    /*set Expires header*/
    expires_str_len = snprintf(expires_str, sizeof(expires_str), "Expires:%ld\r\n", expires_timestamp);
    cbuffer_set(CRFSCHTTP_NODE_EXPIRES(crfschttp_node), (uint8_t *)expires_str, expires_str_len);

    if(0 < expires_timestamp && expires_timestamp < task_brd_default_get_time())
    {
        cbuffer_set(CRFSCHTTP_NODE_STALE(crfschttp_node), CONST_UINT8_STR_AND_LEN("Stale:1\r\n")); 
    }

    CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node)      = __crfschttp_handle_getbgf_request_send_block_more;
    //CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node)      = __crfschttp_handle_getbgf_request_send_body_more;
    CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node)      = NULL_PTR;
    CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)  = 0;

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_getbgf_request: node %p, to read file %s in range [%ld, %ld) and len %ld\n",
                       crfschttp_node,
                       (char *)cstring_get_str(store_path),
                       CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node),
                       CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node),
                       CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node));

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_dsmf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/dsmf");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/dsmf");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_dsmf_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    ASSERT(0 == chunk_mgr_count_chunks(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)));

    if(EC_TRUE == __crfschttp_uri_is_dsmf_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        //if(EC_FALSE == crfsc_delete_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSCNP_ITEM_FILE_IS_REG, CRFSC_MAX_REPLICA_NUM))
        if(EC_FALSE == crfsc_delete_file(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_dsmf_request: node %p, crfsc delete file %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
         
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_dsmf_request: node %p, should never reach here!\n",
                            crfschttp_node);     
        task_brd_default_abort();
    }

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfschttp_handle_ddir_request(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *uri_cbuffer;
     
    uint8_t       *cache_key;
    uint32_t       cache_len;

    CSTRING        path_cstr;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/ddir");
    cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/ddir");
 
    cstring_init(&path_cstr, NULL_PTR);
    cstring_append_chars(&path_cstr, cache_len, cache_key);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_handle_ddir_request: node %p, path %s\n",
                        crfschttp_node, (char *)cstring_get_str(&path_cstr));

    ASSERT(0 == chunk_mgr_count_chunks(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)));

    if(EC_TRUE == __crfschttp_uri_is_ddir_op(uri_cbuffer))
    {
        CSOCKET_CNODE * csocket_cnode;
        csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
        //if(EC_FALSE == crfsc_delete_r(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr, CRFSCNP_ITEM_FILE_IS_DIR, CRFSC_MAX_REPLICA_NUM))
        if(EC_FALSE == crfsc_delete_dir(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_ddir_request: node %p, crfsc delete dir %s failed\n",
                                crfschttp_node, (char *)cstring_get_str(&path_cstr));

            CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_FOUND;
         
            cstring_clean(&path_cstr);
            return (EC_TRUE);
        }
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_OK;
    }
    else
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_handle_ddir_request: node %p, should never reach here!\n",
                            crfschttp_node);     
        task_brd_default_abort();
    } 

    cstring_clean(&path_cstr);

    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_error_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    if(NULL_PTR == csocket_cnode)/*fix*/
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_error_response: crfschttp_node %p => csocket_cnode is null\n",
                            crfschttp_node);
        return (EC_FALSE);                         
    }
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_put_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    //dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_commit_put_response: chunks are\n");
    //chunk_mgr_print_str(LOGSTDOUT, CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_post_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_getrgf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_getsmf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_getbgf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_dsmf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_ddir_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_renew_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_setsmf_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_update_response(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE * csocket_cnode;

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    return crfschttp_send_on_csocket_cnode(csocket_cnode);
}

EC_BOOL crfschttp_commit_error_request(CRFSCHTTP_NODE *crfschttp_node)
{ 
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_commit_error_request: crfschttp_node %p enter\n",
                       crfschttp_node);
                    
    /*cleanup request body and response body*/
    chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));
    cbytes_clean(CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node));

    if(EC_FALSE == crfschttp_make_error_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_error_request: node %p, make error response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_commit_error_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_error_request: node %p, commit error response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_setsmf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_setsmf_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_setsmf_request: node %p, handle 'SET' request failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_setsmf_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_setsmf_request: node %p, make 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_commit_setsmf_request: node %p, make 'SET' response done\n",
                        crfschttp_node);

    if(EC_FALSE == crfschttp_commit_setsmf_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_setsmf_request: node %p, commit 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_update_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_update_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_update_request: node %p, handle 'SET' request failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_update_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_update_request: node %p, make 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_commit_update_request: node %p, make 'SET' response done\n",
                        crfschttp_node);

    if(EC_FALSE == crfschttp_commit_update_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_update_request: node %p, commit 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_put_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_put_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_put_request: node %p, handle 'SET' request failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_put_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_put_request: node %p, make 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_commit_put_request: node %p, make 'SET' response done\n",
                        crfschttp_node);

    if(EC_FALSE == crfschttp_commit_put_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_put_request: node %p, commit 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_post_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_post_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_post_request: node %p, handle 'SET' request failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_post_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_post_request: node %p, make 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_commit_post_request: node %p, make 'SET' response done\n",
                        crfschttp_node);

    if(EC_FALSE == crfschttp_commit_post_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_post_request: node %p, commit 'SET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_getrgf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_getrgf_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getrgf_request: node %p, handle 'GET' request failed\n",
                            crfschttp_node);     
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_getrgf_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getrgf_request: node %p, make 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_commit_getrgf_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getrgf_request: node %p, commit 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_getsmf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_getsmf_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getsmf_request: node %p, handle 'GET' request failed\n",
                            crfschttp_node);     
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_getsmf_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getsmf_request: node %p, make 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_commit_getsmf_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getsmf_request: node %p, commit 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_getbgf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_getbgf_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getbgf_request: node %p, handle 'GET' request failed\n",
                            crfschttp_node);     
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_getbgf_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getbgf_request: node %p, make 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_commit_getbgf_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_getbgf_request: node %p, commit 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}


EC_BOOL crfschttp_commit_dsmf_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_dsmf_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_dsmf_request: node %p, handle 'GET' request failed\n",
                            crfschttp_node);     
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_dsmf_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_dsmf_request: node %p, make 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_commit_dsmf_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_dsmf_request: node %p, commit 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_ddir_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_ddir_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_ddir_request: node %p, handle 'GET' request failed\n",
                            crfschttp_node);     
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_ddir_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_ddir_request: node %p, make 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_commit_ddir_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_ddir_request: node %p, commit 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_commit_renew_request(CRFSCHTTP_NODE *crfschttp_node)
{
    if(EC_FALSE == crfschttp_handle_renew_request(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_renew_request: node %p, handle 'GET' request failed\n",
                            crfschttp_node);     
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_make_renew_response(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_renew_request: node %p, make 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == crfschttp_commit_renew_response(crfschttp_node))
    {
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_SEND_RSP_FAILED;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_renew_request: node %p, commit 'GET' response failed\n",
                            crfschttp_node);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_is_http_put(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node); 

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_put: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfschttp_uri_is_update_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

EC_BOOL crfschttp_is_http_post(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node); 

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_post: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));
                     
    if(EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfschttp_uri_is_update_op(uri_cbuffer))
    {
        return (EC_TRUE);
    } 

    return (EC_FALSE);
}

EC_BOOL crfschttp_is_http_get(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node); 

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_get: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));
                     
    if(EC_TRUE == __crfschttp_uri_is_getsmf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    if(EC_TRUE == __crfschttp_uri_is_getbgf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    } 

    if(EC_TRUE == __crfschttp_uri_is_getrgf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }
 
    if(EC_TRUE == __crfschttp_uri_is_renew_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*regular file*/
EC_BOOL crfschttp_is_http_getrgf(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_getrgf: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_getrgf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

EC_BOOL crfschttp_is_http_getsmf(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_getsmf: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_getsmf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

EC_BOOL crfschttp_is_http_getbgf(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_getbgf: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_getbgf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

/*delete small/regular file*/
EC_BOOL crfschttp_is_http_dsmf(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;

    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node); 

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_dsmf: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_dsmf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    } 

    return (EC_FALSE);
}

/*delete dir*/
EC_BOOL crfschttp_is_http_ddir(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_ddir: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_ddir_op(uri_cbuffer))
    {
        return (EC_TRUE);
    } 

    return (EC_FALSE);
}

/*renew expires*/
EC_BOOL crfschttp_is_http_renew(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_renew: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_renew_op(uri_cbuffer))
    {
        return (EC_TRUE);
    } 

    return (EC_FALSE);
}

EC_BOOL crfschttp_is_http_setsmf(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_setsmf: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

EC_BOOL crfschttp_is_http_update(const CRFSCHTTP_NODE *crfschttp_node)
{
    const CBUFFER *uri_cbuffer;
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_is_http_update: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer),
                        CBUFFER_USED(uri_cbuffer));

    if(EC_TRUE == __crfschttp_uri_is_update_op(uri_cbuffer))
    {
        return (EC_TRUE);
    }
 
    return (EC_FALSE);
}

EC_BOOL crfschttp_commit_http_put(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER *uri_cbuffer;
 
    if(EC_TRUE == crfschttp_is_http_setsmf(crfschttp_node))
    {
        return crfschttp_commit_setsmf_request(crfschttp_node);
    }

    if(EC_TRUE == crfschttp_is_http_update(crfschttp_node))
    {
        return crfschttp_commit_update_request(crfschttp_node);
    } 
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node); 
    dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_http_put: node %p, invalid uri %.*s\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer));

    return crfschttp_commit_error_request(crfschttp_node);
}

EC_BOOL crfschttp_commit_http_post(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER *uri_cbuffer;
 
    if(EC_TRUE == crfschttp_is_http_post(crfschttp_node))
    {
        return crfschttp_commit_post_request(crfschttp_node);
    }
 
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node); 
    dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_http_post: node %p, invalid uri %.*s\n",
                        crfschttp_node,
                        CBUFFER_USED(uri_cbuffer),
                        CBUFFER_DATA(uri_cbuffer));

    return crfschttp_commit_error_request(crfschttp_node);
}

EC_BOOL crfschttp_commit_http_get(CRFSCHTTP_NODE *crfschttp_node)
{
    EC_BOOL ret;

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_commit_http_get: node %p, uri: '%.*s' [len %d]\n",
                        crfschttp_node,
                        CBUFFER_USED(CRFSCHTTP_NODE_URI(crfschttp_node)),
                        CBUFFER_DATA(CRFSCHTTP_NODE_URI(crfschttp_node)),
                        CBUFFER_USED(CRFSCHTTP_NODE_URI(crfschttp_node)));
                     
    if(EC_TRUE == crfschttp_is_http_getsmf(crfschttp_node))
    {
        ret = crfschttp_commit_getsmf_request(crfschttp_node);
    }
    else if(EC_TRUE == crfschttp_is_http_getbgf(crfschttp_node))
    {
        ret = crfschttp_commit_getbgf_request(crfschttp_node);
    }   
    else if (EC_TRUE == crfschttp_is_http_dsmf(crfschttp_node))
    {
        ret = crfschttp_commit_dsmf_request(crfschttp_node);
    }
    else if (EC_TRUE == crfschttp_is_http_ddir(crfschttp_node))
    {
        ret = crfschttp_commit_ddir_request(crfschttp_node);
    }
    else if (EC_TRUE == crfschttp_is_http_getrgf(crfschttp_node))
    {
        ret = crfschttp_commit_getrgf_request(crfschttp_node);
    }
    else if (EC_TRUE == crfschttp_is_http_renew(crfschttp_node))
    {
        ret = crfschttp_commit_renew_request(crfschttp_node);
    }  
    else
    {
        CBUFFER *uri_cbuffer;
     
        uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node); 
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_http_get: node %p, invalid uri %.*s\n",
                            crfschttp_node,
                            CBUFFER_USED(uri_cbuffer),
                            CBUFFER_DATA(uri_cbuffer));

        /*trigger to send error info*/
        CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_NOT_ACCEPTABLE;
        ret = EC_FALSE;
    }

    if(EC_TRUE == ret)
    {
        return (EC_TRUE);
    }

    /*failed when rsp send, thus not need to send error info again...*/
    if(CRFSCHTTP_SEND_RSP_FAILED == CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node))
    {
        crfschttp_node_defer_close(crfschttp_node);
        return (EC_FALSE);
    } 

    if(EC_FALSE == crfschttp_commit_error_request(crfschttp_node))
    {
        crfschttp_node_defer_close(crfschttp_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_parse_host(CRFSCHTTP_NODE *crfschttp_node)
{
    CSTRING       *host_cstr;
    CBUFFER       *url;
    uint8_t       *data;
    uint8_t       *host_str;
    uint32_t       offset;
    uint32_t       host_len;
 
    host_cstr = cstrkv_mgr_get_val_cstr(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), "Host");
    if(NULL_PTR != host_cstr)
    {
        cbuffer_set(CRFSCHTTP_NODE_HOST(crfschttp_node), cstring_get_str(host_cstr), (uint32_t)cstring_get_len(host_cstr));
        return (EC_TRUE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 3)(LOGSTDOUT, "info:crfschttp_parse_host: node %p, not found 'Host' in http header\n",
                        crfschttp_node);

    url  = CRFSCHTTP_NODE_URL(crfschttp_node);
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

    dbg_log(SEC_0145_CRFSCHTTP, 3)(LOGSTDOUT, "info:crfschttp_parse_host: node %p, fetch domain %.*s as 'Host' in http header\n",
                        crfschttp_node, host_len, host_str);
 
    cbuffer_set(CRFSCHTTP_NODE_HOST(crfschttp_node), host_str, host_len); 

    return (EC_TRUE);
}

EC_BOOL crfschttp_parse_content_length(CRFSCHTTP_NODE *crfschttp_node)
{
    CSTRING       *content_length_cstr;
 
    content_length_cstr = cstrkv_mgr_get_val_cstr(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node), "Content-Length");
    if(NULL_PTR == content_length_cstr)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 3)(LOGSTDOUT, "info:crfschttp_parse_content_length: node %p, not found 'Content-Length' in http header\n",
                            crfschttp_node);
        CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node) = 0;
        return (EC_TRUE);
    }
    CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node) = c_chars_to_uint64_t((char *)cstring_get_str(content_length_cstr),
                                                                    (uint32_t)cstring_get_len(content_length_cstr));

    return (EC_TRUE);
}

EC_BOOL crfschttp_parse_uri(CRFSCHTTP_NODE *crfschttp_node)
{
    CBUFFER       *url_cbuffer;
    CBUFFER       *host_cbuffer;
    CBUFFER       *uri_cbuffer;

    uint8_t       *uri_str; 
    uint32_t       uri_len;
    uint32_t       skip_len;
 
    url_cbuffer  = CRFSCHTTP_NODE_URL(crfschttp_node);
    host_cbuffer = CRFSCHTTP_NODE_HOST(crfschttp_node);
    uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);

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
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_parse_uri: node %p, set uri %.*s failed\n",
                            crfschttp_node, uri_len, uri_str);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_log_start()
{
    if(EC_TRUE == g_crfcshttp_log_init)
    {
        return (EC_TRUE);
    }

    g_crfcshttp_log_init = EC_TRUE;
    return (EC_TRUE);
}


EC_BOOL crfschttp_commit_request(CRFSCHTTP_NODE *crfschttp_node)
{
    http_parser_t *http_parser;
    CSOCKET_CNODE *csocket_cnode;
 
    http_parser   = CRFSCHTTP_NODE_PARSER(crfschttp_node);
    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);

    if(HTTP_GET == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;
             
        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)crfschttp_commit_http_get, 1, crfschttp_node);
        if(NULL_PTR == croutine_node)
        {
            CSOCKET_CNODE_RETRIES(csocket_cnode) ++;
         
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_request: node %p, cthread load for HTTP_GET failed where retried %ld\n",
                                crfschttp_node, CSOCKET_CNODE_RETRIES(csocket_cnode));

            if(CRFSCHTTP_OVERLOAD_MAX_RETIRES <= CSOCKET_CNODE_RETRIES(csocket_cnode))
            {
                crfschttp_node_defer_close(crfschttp_node);
                return (EC_FALSE);
            }
         
            /*commit later*/         
            cepoll_set_event(task_brd_default_get_cepoll(), 
                            CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                            CEPOLL_RD_EVENT,
                            (const char *)"crfschttp_commit_request",
                            (CEPOLL_EVENT_HANDLER)crfschttp_commit_request, 
                            (void *)crfschttp_node); 
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
            
            return (EC_FALSE);
        }
        CSOCKET_CNODE_RETRIES(csocket_cnode) = 0;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSCHTTP_0008); 
     
        return (EC_TRUE);
    }

    if(HTTP_PUT == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;
     
        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)crfschttp_commit_http_put, 1, crfschttp_node);
        if(NULL_PTR == croutine_node)
        {
            CSOCKET_CNODE_RETRIES(csocket_cnode) ++;
         
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_request: node %p, cthread load for HTTP_PUT failed where retried %ld\n",
                                crfschttp_node, CSOCKET_CNODE_RETRIES(csocket_cnode));

            if(CRFSCHTTP_OVERLOAD_MAX_RETIRES <= CSOCKET_CNODE_RETRIES(csocket_cnode))
            {
                crfschttp_node_defer_close(crfschttp_node);
                return (EC_FALSE);
            }

            /*commit later*/
            cepoll_set_event(task_brd_default_get_cepoll(), 
                             CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                             CEPOLL_RD_EVENT,
                             (const char *)"crfschttp_commit_request",
                             (CEPOLL_EVENT_HANDLER)crfschttp_commit_request, 
                             (void *)crfschttp_node);
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
            
            return (EC_TRUE);
        }
        CSOCKET_CNODE_RETRIES(csocket_cnode) = 0;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSCHTTP_0009); 
     
        return (EC_TRUE);
    } 

    if(HTTP_POST == http_parser->method)
    {
        CROUTINE_NODE  *croutine_node;
     
        croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                           (UINT32)crfschttp_commit_http_post, 1, crfschttp_node);
        if(NULL_PTR == croutine_node)
        {
            CSOCKET_CNODE_RETRIES(csocket_cnode) ++;
         
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_request: node %p, cthread load for HTTP_POST failed where retried %ld\n",
                                crfschttp_node, CSOCKET_CNODE_RETRIES(csocket_cnode));

            if(CRFSCHTTP_OVERLOAD_MAX_RETIRES <= CSOCKET_CNODE_RETRIES(csocket_cnode))
            {
                crfschttp_node_defer_close(crfschttp_node);
                return (EC_FALSE);
            }
         
            /*commit later*/
            cepoll_set_event(task_brd_default_get_cepoll(), 
                             CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                             CEPOLL_RD_EVENT,
                             (const char *)"crfschttp_commit_request",
                             (CEPOLL_EVENT_HANDLER)crfschttp_commit_request, 
                             (void *)crfschttp_node);                                
            CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
            
            return (EC_FALSE);
        }
        CSOCKET_CNODE_RETRIES(csocket_cnode) = 0;
        CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSCHTTP_0010); 

 
        return (EC_TRUE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_commit_request: node %p, not support http method %d yet\n",
                        crfschttp_node, http_parser->method);

    crfschttp_node_defer_close(crfschttp_node);
    return (EC_FALSE);
}

static void __crfschttp_parser_setting_init(http_parser_settings_t   *http_parser_setting)
{
    BSET(http_parser_setting, 0, sizeof(http_parser_settings_t));
 
    http_parser_setting->on_message_begin    = __crfschttp_on_message_begin;
    http_parser_setting->on_url              = __crfschttp_on_url;
    http_parser_setting->on_header_field     = __crfschttp_on_header_field;
    http_parser_setting->on_header_value     = __crfschttp_on_header_value;
    http_parser_setting->on_headers_complete = __crfschttp_on_headers_complete;
    http_parser_setting->on_body             = __crfschttp_on_body;
    http_parser_setting->on_message_complete = __crfschttp_on_message_complete;

    return;
}

CRFSCHTTP_NODE *crfschttp_node_new(const uint32_t size)
{
    CRFSCHTTP_NODE *crfschttp_node;

    //dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_node_new: size = %d\n", size);
    alloc_static_mem(MM_CRFSCHTTP_NODE, &crfschttp_node, LOC_CRFSCHTTP_0011);
    if(NULL_PTR == crfschttp_node)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_node_new: new crfschttp_node failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == crfschttp_node_init(crfschttp_node, size))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_node_new: init crfschttp_node failed\n");
        free_static_mem(MM_CRFSCHTTP_NODE, crfschttp_node, LOC_CRFSCHTTP_0012);
        return (NULL_PTR);
    }
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_node_new: node %p, size = %d\n", crfschttp_node, size);

    return (crfschttp_node);
}

EC_BOOL crfschttp_node_init(CRFSCHTTP_NODE *crfschttp_node, const uint32_t size)
{
    if(EC_FALSE == cbuffer_init(CRFSCHTTP_NODE_CBUFFER(crfschttp_node), size))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_node_init: init cbuffer with size %d failed\n", size);
        return (EC_FALSE);
    }

    CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node)        = CRFSCHTTP_NODE_HEADER_UNDEF;
    CRFSCHTTP_NODE_HEADER_OP(crfschttp_node)         = CRFSCHTTP_NODE_UNDEF_OP;
    CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node)     = NULL_PTR;

    CRFSCHTTP_NODE_RECV_ATIME_TS(crfschttp_node)     = 0;
    CRFSCHTTP_NODE_SEND_ATIME_TS(crfschttp_node)     = 0;
    CRFSCHTTP_NODE_RECV_SIZE(crfschttp_node)         = 0;
    CRFSCHTTP_NODE_SEND_SIZE(crfschttp_node)         = 0; 

    cbuffer_init(CRFSCHTTP_NODE_URL(crfschttp_node) , 0);
    cbuffer_init(CRFSCHTTP_NODE_HOST(crfschttp_node), 0);
    cbuffer_init(CRFSCHTTP_NODE_URI(crfschttp_node) , 0);
    cbuffer_init(CRFSCHTTP_NODE_EXPIRES(crfschttp_node) , 0);
    cbuffer_init(CRFSCHTTP_NODE_STALE(crfschttp_node) , 0);

    cstrkv_mgr_init(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node));
    chunk_mgr_init(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));
    chunk_mgr_init(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node));

    cbytes_init(CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node));

    CRFSCHTTP_NODE_CREATE_TIME(crfschttp_node) = 0;
    CRFSCHTTP_NODE_EXPIRE_TIME(crfschttp_node) = 0;

    CTMV_INIT(CRFSCHTTP_NODE_START_TMV(crfschttp_node));

    CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node)      = 0;
    CRFSCHTTP_NODE_BODY_PARSED_LEN(crfschttp_node)     = 0;
    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node)          = CRFSCHTTP_STATUS_NONE;

    CRFSCHTTP_NODE_STORE_PATH(crfschttp_node)          = NULL_PTR;
    CRFSCHTTP_NODE_EXPIRED_BODY_NEED(crfschttp_node)   = EC_TRUE;

    CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node)      = NULL_PTR;
    CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node)      = NULL_PTR;
    CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)  = 0;

    CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node)       = ERR_FD;
    CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node)     = 0;
    CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)      = 0;

    CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node)    = 0;
    CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node)    = 0;
    CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node)    = 0;

    http_parser_init(CRFSCHTTP_NODE_PARSER(crfschttp_node), HTTP_REQUEST); 
    __crfschttp_parser_setting_init(CRFSCHTTP_NODE_SETTING(crfschttp_node));

    return (EC_TRUE);
}

EC_BOOL crfschttp_node_clean(CRFSCHTTP_NODE *crfschttp_node)
{
    CSOCKET_CNODE *csocket_cnode;

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_node_clean: try to clean node %p\n", crfschttp_node);

    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node);
    if(NULL_PTR != csocket_cnode)
    {
        CEPOLL *cepoll;

        cepoll = task_brd_default_get_cepoll();
        cepoll_del_all(cepoll, CSOCKET_CNODE_SOCKFD(csocket_cnode));
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
        
        cepoll_set_not_used(cepoll, CSOCKET_CNODE_SOCKFD(csocket_cnode));
    }
 
    cbuffer_clean(CRFSCHTTP_NODE_CBUFFER(crfschttp_node));

    CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node)        = CRFSCHTTP_NODE_HEADER_UNDEF;
    CRFSCHTTP_NODE_HEADER_OP(crfschttp_node)         = CRFSCHTTP_NODE_UNDEF_OP;
    CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node)     = NULL_PTR;

    CRFSCHTTP_NODE_RECV_ATIME_TS(crfschttp_node)     = 0;
    CRFSCHTTP_NODE_SEND_ATIME_TS(crfschttp_node)     = 0;
    CRFSCHTTP_NODE_RECV_SIZE(crfschttp_node)         = 0;
    CRFSCHTTP_NODE_SEND_SIZE(crfschttp_node)         = 0;
 
    cbuffer_clean(CRFSCHTTP_NODE_URL(crfschttp_node));
    cbuffer_clean(CRFSCHTTP_NODE_HOST(crfschttp_node));
    cbuffer_clean(CRFSCHTTP_NODE_URI(crfschttp_node));
    cbuffer_clean(CRFSCHTTP_NODE_EXPIRES(crfschttp_node));
    cbuffer_clean(CRFSCHTTP_NODE_STALE(crfschttp_node));

    cstrkv_mgr_clean(CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node));
    chunk_mgr_clean(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)); 
    chunk_mgr_clean(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node)); 

    cbytes_clean(CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node));

    CRFSCHTTP_NODE_CREATE_TIME(crfschttp_node) = 0;
    CRFSCHTTP_NODE_EXPIRE_TIME(crfschttp_node) = 0;

    CTMV_CLEAN(CRFSCHTTP_NODE_START_TMV(crfschttp_node));

    CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node)  = 0;
    CRFSCHTTP_NODE_BODY_PARSED_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node)      = CRFSCHTTP_STATUS_NONE;

    if(NULL_PTR != CRFSCHTTP_NODE_STORE_PATH(crfschttp_node))
    {
        cstring_free(CRFSCHTTP_NODE_STORE_PATH(crfschttp_node));
        CRFSCHTTP_NODE_STORE_PATH(crfschttp_node) = NULL_PTR;
    }
    CRFSCHTTP_NODE_STORE_PATH(crfschttp_node) = EC_TRUE;

    CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node) = NULL_PTR;
    if(NULL_PTR != CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node))
    {
        safe_free(CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node), LOC_CRFSCHTTP_0013);
        CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node) = NULL_PTR;
    }
    CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) = 0;
    CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)  = 0;

    CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node)       = ERR_FD;
    CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node)     = 0;
    CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)      = 0;
 
    CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node)    = 0;
    CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node)    = 0;
    CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node)    = 0; 

    if(NULL_PTR != csocket_cnode)
    {
        //not sure ....
        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_node_clean: node %p, try to close socket %d\n",
                            crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode));
        csocket_cnode_close(csocket_cnode);/*when socket is closed, it may be reused at once*/
    }

    return (EC_TRUE);
}

EC_BOOL crfschttp_node_free(CRFSCHTTP_NODE *crfschttp_node)
{
    if(NULL_PTR != crfschttp_node)
    {
        dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "[DEBUG] crfschttp_node_free: node %p\n", crfschttp_node);
        crfschttp_node_clean(crfschttp_node);
        free_static_mem(MM_CRFSCHTTP_NODE, crfschttp_node, LOC_CRFSCHTTP_0014);
    }

    return (EC_TRUE);
}

void crfschttp_node_print(LOG *log, const CRFSCHTTP_NODE *crfschttp_node)
{
    sys_log(LOGSTDOUT, "crfschttp_node_print: node %p, url : ", crfschttp_node);
    cbuffer_print_str(LOGSTDOUT, CRFSCHTTP_NODE_URL(crfschttp_node));
 
    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, host : ", crfschttp_node);
    cbuffer_print_str(LOGSTDOUT, CRFSCHTTP_NODE_HOST(crfschttp_node));

    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, uri : ", crfschttp_node);
    cbuffer_print_str(LOGSTDOUT, CRFSCHTTP_NODE_URI(crfschttp_node));

    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, header kvs: \n", crfschttp_node);
    cstrkv_mgr_print(LOGSTDOUT, CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node));

    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, header content length: %"PRId64"\n", crfschttp_node,
                       CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node));

    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, req body chunks: total length %"PRId64"\n", crfschttp_node,
                       chunk_mgr_total_length(CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)));
                    
    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, rsp body chunks: total length %"PRId64"\n", crfschttp_node,
                       chunk_mgr_total_length(CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node)));
    //chunk_mgr_print_str(LOGSTDOUT, CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));
    //chunk_mgr_print_info(LOGSTDOUT, CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node));

    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, create time: %d\n", crfschttp_node, CRFSCHTTP_NODE_CREATE_TIME(crfschttp_node));
    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, expire time: %d\n", crfschttp_node, CRFSCHTTP_NODE_EXPIRE_TIME(crfschttp_node));
    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, header fsm : %u\n", crfschttp_node, CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node));

    sys_log(LOGSTDOUT, "crfschttp_node_print:node %p, store url : %s\n", crfschttp_node, (char *)cstring_get_str(CRFSCHTTP_NODE_STORE_PATH(crfschttp_node)));

    return;
}

static EC_BOOL __crfschttp_node_recv_is_in_low_bps(CRFSCHTTP_NODE  *crfschttp_node)
{
    return (EC_FALSE);
}

static EC_BOOL __crfschttp_node_send_is_in_low_bps(CRFSCHTTP_NODE  *crfschttp_node)
{
    return (EC_FALSE);
}

static EC_BOOL __crfschttp_node_prepare_for_csocket_cnode(CSOCKET_CNODE *csocket_cnode)
{
    CRFSCHTTP_NODE *crfschttp_node;

    crfschttp_node = CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode);
    if(NULL_PTR == crfschttp_node)
    {
        http_parser_t  *http_parser;
     
        crfschttp_node = crfschttp_node_new(CRFSCHTTP_CBUFFER_SIZE);
        if(NULL_PTR == crfschttp_node)
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_node_prepare_for_csocket_cnode: new crfschttp_node for sockfd %d failed\n",
                               CSOCKET_CNODE_SOCKFD(csocket_cnode));
            return (EC_FALSE);
        }

        dbg_log(SEC_0145_CRFSCHTTP, 1)(LOGSTDOUT, "__crfschttp_node_prepare_for_csocket_cnode: new crfschttp_node %p rsp_body %p req_body %p for sockfd %d done\n",
                           crfschttp_node, CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node), CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node), CSOCKET_CNODE_SOCKFD(csocket_cnode));     
     
        CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode)  = crfschttp_node;
        CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node) = csocket_cnode;

        CTMV_CLONE(task_brd_default_get_daytime(), CRFSCHTTP_NODE_START_TMV(crfschttp_node));

        /*init start time*/
        CRFSCHTTP_NODE_RECV_ATIME_TS(crfschttp_node) = task_brd_default_get_time();
     
        http_parser = CRFSCHTTP_NODE_PARSER(crfschttp_node);
        http_parser->data = (void *)crfschttp_node;/*xxx*/
     
        return (EC_TRUE);
    }


    /*check timeout*/
    if(CRFSCHTTP_NODE_RECV_ATIME_TS(crfschttp_node) + CRFSCHTTP_SOCKET_TIMEOUT_NSEC < task_brd_default_get_time())
    {
        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "error:__crfschttp_node_prepare_for_csocket_cnode: node %p, sockfd %d timeout!\n",
                           crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode));
 
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

static EC_BOOL __crfschttp_node_pre_handle_header(CRFSCHTTP_NODE  *crfschttp_node)
{
    CSOCKET_CNODE *csocket_cnode;
 
    csocket_cnode = CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node); 
 
    /*check header validity*/
    if(CRFSCHTTP_HEADER_MAX_SIZE < CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:__crfschttp_node_pre_handle_header: node %p, sockfd %d header too large where pased len %d\n",
                           crfschttp_node,
                           CSOCKET_CNODE_SOCKFD(csocket_cnode),
                           CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node));
        crfschttp_csocket_cnode_epoll_close(csocket_cnode);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_node_pre_handle_header: FSM = %u\n", CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node));

    /*FSM transition*/
    if(CRFSCHTTP_NODE_HEADER_HANDLING == CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node))
    {
        CBUFFER        *uri_cbuffer;
        http_parser_t  *http_parser;     
     
        CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node) = CRFSCHTTP_NODE_HEADER_HANDLED;

        uri_cbuffer  = CRFSCHTTP_NODE_URI(crfschttp_node);     
        http_parser = CRFSCHTTP_NODE_PARSER(crfschttp_node);

        if(HTTP_PUT == http_parser->method && EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
        {
            uint8_t       *cache_key;
            uint32_t       cache_len;

            CSTRING        path_cstr;

            cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf");
            cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf");
         
            cstring_init(&path_cstr, NULL_PTR);
            cstring_append_chars(&path_cstr, cache_len, cache_key);         
         
            if(EC_TRUE == crfsc_is_file(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
            {
                dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_node_pre_handle_header: node %p, file '%s' already exist\n",
                                   crfschttp_node, (char *)cstring_get_str(&path_cstr));
                cstring_clean(&path_cstr);

                CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;

                crfschttp_commit_error_request(crfschttp_node);
                return (EC_FALSE);/*return false to terminate recv*/
            }
         
            cstring_clean(&path_cstr);
        }     

        else if(HTTP_POST == http_parser->method && EC_TRUE == __crfschttp_uri_is_setsmf_op(uri_cbuffer))
        {        
            uint8_t       *cache_key;
            uint32_t       cache_len;

            CSTRING        path_cstr;

            cache_key = CBUFFER_DATA(uri_cbuffer) + CONST_STR_LEN("/setsmf");
            cache_len = CBUFFER_USED(uri_cbuffer) - CONST_STR_LEN("/setsmf");
         
            cstring_init(&path_cstr, NULL_PTR);
            cstring_append_chars(&path_cstr, cache_len, cache_key);         
         
            if(EC_TRUE == crfsc_is_file(CSOCKET_CNODE_MODI(csocket_cnode), &path_cstr))
            {
                dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] __crfschttp_node_pre_handle_header: node %p, file '%s' already exist\n",
                                   crfschttp_node, (char *)cstring_get_str(&path_cstr));
                cstring_clean(&path_cstr);

                CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node) = CRFSCHTTP_FORBIDDEN;
                crfschttp_commit_error_request(crfschttp_node);
                return (EC_FALSE);/*return false to terminate recv*/
            }
         
            cstring_clean(&path_cstr);
        }     
    } 

    return (EC_TRUE);
}

EC_BOOL crfschttp_recv_on_csocket_cnode(CSOCKET_CNODE *csocket_cnode)
{
    CRFSCHTTP_NODE           *crfschttp_node;
    http_parser_t            *http_parser;
    http_parser_settings_t   *http_parser_setting;
    CBUFFER                  *http_buffer;
 
    UINT32   pos;
    UINT32   recv_len;
    uint32_t parsed_len;

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_recv_on_csocket_cnode: sockfd %d enter\n",
                       CSOCKET_CNODE_SOCKFD(csocket_cnode));
 
    if(EC_FALSE == CSOCKET_CNODE_IS_CONNECTED(csocket_cnode))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_recv_on_csocket_cnode: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));
        crfschttp_csocket_cnode_epoll_close(csocket_cnode);
        return (EC_FALSE);
    }

    if(EC_FALSE == __crfschttp_node_prepare_for_csocket_cnode(csocket_cnode))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_recv_on_csocket_cnode: sockfd %d prepare crfschttp_node failed\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));
        crfschttp_csocket_cnode_epoll_close(csocket_cnode);
        return (EC_FALSE);
    }

    crfschttp_node      = CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode);
    http_parser         = CRFSCHTTP_NODE_PARSER(crfschttp_node);
    http_parser_setting = CRFSCHTTP_NODE_SETTING(crfschttp_node);
    http_buffer         = CRFSCHTTP_NODE_CBUFFER(crfschttp_node);

    pos = CBUFFER_USED(http_buffer);
    if(EC_FALSE == csocket_cnode_recv(csocket_cnode,
                                CBUFFER_DATA(http_buffer),
                                CBUFFER_SIZE(http_buffer),
                                &pos))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_recv_on_csocket_cnode: node %p, read on sockfd %d failed where size %d and used %d\n",
                            crfschttp_node,
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CBUFFER_SIZE(http_buffer),
                            CBUFFER_USED(http_buffer));
                         
        crfschttp_csocket_cnode_epoll_close(csocket_cnode);
        return (EC_FALSE);                         
    }

    recv_len = (pos - CBUFFER_USED(http_buffer));
    CRFSCHTTP_NODE_RECV_SIZE(crfschttp_node) += recv_len;
    CBUFFER_USED(http_buffer) = (uint32_t)pos;

    if(0 == recv_len)
    {
        /*wait for next reading*/
        cepoll_set_event(task_brd_default_get_cepoll(), 
                         CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                         CEPOLL_RD_EVENT,
                         (const char *)"crfschttp_recv_on_csocket_cnode_thread",
                         (CEPOLL_EVENT_HANDLER)crfschttp_recv_on_csocket_cnode_thread, 
                         (void *)csocket_cnode);
        CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
        
        return (EC_TRUE);
    }

    parsed_len = http_parser_execute(http_parser, http_parser_setting, (char *)CBUFFER_DATA(http_buffer), CBUFFER_USED(http_buffer));
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_recv_on_csocket_cnode: node %p, sockfd %d, parsed_len = %u, http state %s\n",
                       crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode), parsed_len, http_state_str(http_parser->state));
    cbuffer_left_shift_out(http_buffer, NULL_PTR, parsed_len);

    if(0 != parsed_len)
    {
        CRFSCHTTP_NODE_RECV_ATIME_TS(crfschttp_node) = task_brd_default_get_time();
    }

    /*count header len*/
    switch(CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node))
    {
        case CRFSCHTTP_NODE_HEADER_PARSING:
            CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node) += parsed_len;
            break;
        case CRFSCHTTP_NODE_HEADER_PARSED:
            CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node) += parsed_len;
            CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node) = CRFSCHTTP_NODE_HEADER_HANDLING;
            break;
        default:
            /*do nothing*/
            break;
    }

    if(EC_FALSE == __crfschttp_node_pre_handle_header(crfschttp_node))
    {
        /*************************************************************
         * note: __crfschttp_node_pre_handle_header
         *    -> crfschttp_commit_error_request
         *    -> crfschttp_commit_error_response
         *    -> crfschttp_send_on_csocket_cnode
         *    -> crfschttp_node_defer_close
         *    
         *    crfschttp_node_defer_close will set close
        *************************************************************/
        dbg_log(SEC_0145_CRFSCHTTP, 2)(LOGSTDOUT, "warn:crfschttp_recv_on_csocket_cnode: node %p, sockfd %d header pre-handle failed\n",
                           crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_recv_on_csocket_cnode: node %p, sockfd %d parsed_len %d "
                        "=> header parsed %d, body parsed %ld\n",
                       crfschttp_node,
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       parsed_len,
                       CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node), CRFSCHTTP_NODE_BODY_PARSED_LEN(crfschttp_node));
    dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_recv_on_csocket_cnode: node %p, sockfd %d http state %s\n",
                       crfschttp_node,
                       CSOCKET_CNODE_SOCKFD(csocket_cnode),
                       http_state_str(http_parser->state));

    if(s_start_req == http_parser->state || s_dead == http_parser->state)
    {
        /*note: http request is ready now. stop read from socket to prevent recving during handling request*/
        /*      RD_EVENT was deleted in crfschttp_recv_on_csocket_cnode_thread*/
        /*commit*/
        return crfschttp_commit_request(crfschttp_node);
    }
 
    /*TODO: other scenarios*/
    cepoll_set_event(task_brd_default_get_cepoll(), 
                     CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                     CEPOLL_RD_EVENT,
                     (const char *)"crfschttp_recv_on_csocket_cnode_thread",
                     (CEPOLL_EVENT_HANDLER)crfschttp_recv_on_csocket_cnode_thread, 
                     (void *)csocket_cnode); 
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_TRUE;
    
    return (EC_TRUE);
}

EC_BOOL crfschttp_send_on_csocket_cnode(CSOCKET_CNODE *csocket_cnode)
{
    CRFSCHTTP_NODE   *crfschttp_node;
    CHUNK_MGR        *body_chunks;
    UINT32            send_len;
 
    if(EC_FALSE == CSOCKET_CNODE_IS_CONNECTED(csocket_cnode))
    {
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_send_on_csocket_cnode: sockfd %d is not connected\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode)); 
        crfschttp_csocket_cnode_epoll_close(csocket_cnode);
        return (EC_FALSE);
    }

    crfschttp_node = CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode);
    if(NULL_PTR == crfschttp_node)
    {
        /*nothing to do ??*/ 
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_send_on_csocket_cnode: sockfd %d find node is null\n",
                           CSOCKET_CNODE_SOCKFD(csocket_cnode));
        return (EC_FALSE);
    }

    send_len    = 0;
    body_chunks = CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node);

    while(EC_FALSE == chunk_mgr_is_empty(body_chunks))
    {
        CHUNK *chunk;
        UINT32 pos;
        UINT32 send_len;
     
        chunk = chunk_mgr_first_chunk(body_chunks);
        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_send_on_csocket_cnode: node %p, sockfd %d chunk offset %d, buffer used %d\n",
                            crfschttp_node,
                            CSOCKET_CNODE_SOCKFD(csocket_cnode),
                            CHUNK_OFFSET(chunk), CBUFFER_USED(CHUNK_BUFFER(chunk)));
        if(CHUNK_OFFSET(chunk) >= CBUFFER_USED(CHUNK_BUFFER(chunk)))
        {
            /*send completely*/
            chunk_mgr_pop_first_chunk(body_chunks);
            chunk_free(chunk);
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "[DEBUG] crfschttp_send_on_csocket_cnode: [1] node %p, sockfd %d, chunk_mgr %p free chunk %p\n",
                               crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode), body_chunks, chunk);         
            continue;
        }

        pos = CHUNK_OFFSET(chunk);
        if(EC_FALSE == csocket_cnode_send(csocket_cnode,
                                   CBUFFER_DATA(CHUNK_BUFFER(chunk)),
                                   CBUFFER_USED(CHUNK_BUFFER(chunk)),
                                   &pos))
        {
            dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_send_on_csocket_cnode: node %p, sockfd %d send %ld bytes failed\n",
                               crfschttp_node,
                               CSOCKET_CNODE_SOCKFD(csocket_cnode),
                               CBUFFER_USED(CHUNK_BUFFER(chunk)) - CHUNK_OFFSET(chunk)
                               );
            return (EC_FALSE);                        
        }

        send_len += (pos - CHUNK_OFFSET(chunk));
/*
        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_send_on_csocket_cnode: send [len %ld] '%.*s'\n",
                           pos - CHUNK_OFFSET(chunk),
                           pos - CHUNK_OFFSET(chunk),
                           CBUFFER_DATA(CHUNK_BUFFER(chunk)) + CHUNK_OFFSET(chunk));
*/
        CHUNK_OFFSET(chunk) = (uint32_t)pos;
        if(CHUNK_OFFSET(chunk) < CBUFFER_USED(CHUNK_BUFFER(chunk)))
        {
            /*wait for next writing*/
            cepoll_set_event(task_brd_default_get_cepoll(), 
                             CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                             CEPOLL_WR_EVENT,
                             (const char *)"crfschttp_send_on_csocket_cnode_thread",
                             (CEPOLL_EVENT_HANDLER)crfschttp_send_on_csocket_cnode_thread,
                             (void *)csocket_cnode);          
            CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
            return (EC_TRUE);
        }

        dbg_log(SEC_0145_CRFSCHTTP, 9)(LOGSTDOUT, "[DEBUG] crfschttp_send_on_csocket_cnode: node %p, sockfd %d pop chunk %p and clean it, size %u\n",
                           crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode), chunk, CBUFFER_USED(CHUNK_BUFFER(chunk))); 
     
        /*chunk is sent completely*/
        chunk_mgr_pop_first_chunk(body_chunks);
        chunk_free(chunk);
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "[DEBUG] crfschttp_send_on_csocket_cnode: [2] node %p, sockfd %d, chunk_mgr %p free chunk %p\n",
                           crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode), body_chunks, chunk);       
    }
 
    CRFSCHTTP_NODE_SEND_SIZE(crfschttp_node) += send_len;

    /*now body_chunks is emtpy*/
    if(NULL_PTR != CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node))
    {
        /*wait for next writing more data*/
        cepoll_set_event(task_brd_default_get_cepoll(), 
                         CSOCKET_CNODE_SOCKFD(csocket_cnode), 
                         CEPOLL_WR_EVENT,
                         (const char *)"CRFSCHTTP_NODE_SEND_DATA_MORE",
                         (CEPOLL_EVENT_HANDLER)CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node), 
                         (void *)crfschttp_node);
        CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_TRUE;
        
        return (EC_TRUE);
    }
 
    /*when no more data to send, wait to close*/
    dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "warn: crfschttp_send_on_csocket_cnode: node %p, sockfd %d, no more data\n",
                       crfschttp_node, CSOCKET_CNODE_SOCKFD(csocket_cnode));
    /*cannot close at once because data may be on-flying*/
    crfschttp_node_defer_close(crfschttp_node);
    return (EC_TRUE);
}

EC_BOOL crfschttp_recv_on_csocket_cnode_thread(CSOCKET_CNODE *csocket_cnode)
{
    CROUTINE_NODE  *croutine_node;
 
    croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                       (UINT32)crfschttp_recv_on_csocket_cnode, 1, csocket_cnode);
    if(NULL_PTR == croutine_node)
    {
        CSOCKET_CNODE_RETRIES(csocket_cnode) ++;
     
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "warn:crfschttp_recv_on_csocket_cnode_thread: cthread load failed where retried %ld\n", CSOCKET_CNODE_RETRIES(csocket_cnode));
             
        if(CRFSCHTTP_OVERLOAD_MAX_RETIRES <= CSOCKET_CNODE_RETRIES(csocket_cnode))
        {
            crfschttp_csocket_cnode_epoll_close(csocket_cnode);
            return (EC_FALSE);
        }
     
        return (EC_TRUE);/*wait for next chance to load*/
    }
    CSOCKET_CNODE_RETRIES(csocket_cnode) = 0;
 
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_RD_EVENT);
    CSOCKET_CNODE_READING(csocket_cnode) = BIT_FALSE;
    
    CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSCHTTP_0015); 
 
    return (EC_TRUE);
}

EC_BOOL crfschttp_send_on_csocket_cnode_thread(CSOCKET_CNODE *csocket_cnode)
{
    CROUTINE_NODE  *croutine_node;

    croutine_node = croutine_pool_load(TASK_REQ_CTHREAD_POOL(task_brd_default_get()),
                                       (UINT32)crfschttp_send_on_csocket_cnode, 1, csocket_cnode);
    if(NULL_PTR == croutine_node)
    {
        CSOCKET_CNODE_RETRIES(csocket_cnode) ++;
        dbg_log(SEC_0145_CRFSCHTTP, 0)(LOGSTDOUT, "error:crfschttp_send_on_csocket_cnode: cthread load failed where retried %ld\n", CSOCKET_CNODE_RETRIES(csocket_cnode));

        if(CRFSCHTTP_OVERLOAD_MAX_RETIRES <= CSOCKET_CNODE_RETRIES(csocket_cnode))
        {
            crfschttp_csocket_cnode_epoll_close(csocket_cnode);
            return (EC_FALSE);
        }     
        return (EC_TRUE);/*wait for next chance to load*/
    }
    CSOCKET_CNODE_RETRIES(csocket_cnode) = 0;

    /* note: when load sender in thread, have to prevent same sender was loaded twice.*/
    /* e.g., the previous sender is on-going without return back, WR event was trigger*/
    /*       and try to load the sender again. Thus conflict happen*/
    /*solution: before launch thread, remove WR event, after sender complete, add back*/
    cepoll_del_event(task_brd_default_get_cepoll(), CSOCKET_CNODE_SOCKFD(csocket_cnode), CEPOLL_WR_EVENT);
    CSOCKET_CNODE_WRITING(csocket_cnode) = BIT_FALSE;
    
    CROUTINE_NODE_COND_RELEASE(croutine_node, LOC_CRFSCHTTP_0016); 
 
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

