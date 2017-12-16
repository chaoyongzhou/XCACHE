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

#ifndef _CRFSCHTTP_H
#define _CRFSCHTTP_H

#include "type.h"
#include "debug.h"

#include "cstring.h"

#include "csocket.inc"
#include "task.inc"

#include "cbuffer.h"
#include "cstrkv.h"
#include "chunk.h"

#include "http_parser.h"

/*HTTP 1.1*/
#define CRFSCHTTP_VERSION_MAJOR       ((uint16_t) 1)
#define CRFSCHTTP_VERSION_MINOR       ((uint16_t) 1)

#define CRFSCHTTP_HEADER_MAX_SIZE     ((uint32_t)(4 * 1024))
#define CRFSCHTTP_CBUFFER_SIZE        ((uint32_t)(8 * 1024))


#define CRFSCHTTP_REST_API_NAME            ("/rfsc")

typedef struct 
{
    uint32_t    key;
    const char *val;
}CRFSCHTTP_KV;

#define CRFSCHTTP_KV_KEY(crfschttp_kv)        ((crfschttp_kv)->key)
#define CRFSCHTTP_KV_VAL(crfschttp_kv)        ((crfschttp_kv)->val)

#define CRFSCHTTP_NODE_HEADER_UNDEF          ((uint32_t) 0)
#define CRFSCHTTP_NODE_HEADER_PARSING        ((uint32_t) 1)
#define CRFSCHTTP_NODE_HEADER_PARSED         ((uint32_t) 2)
#define CRFSCHTTP_NODE_HEADER_HANDLING       ((uint32_t) 3)
#define CRFSCHTTP_NODE_HEADER_HANDLED        ((uint32_t) 4)

#define CRFSCHTTP_NODE_UNDEF_OP              ((uint32_t) 1)
#define CRFSCHTTP_NODE_GET_OP                ((uint32_t) 1)
#define CRFSCHTTP_NODE_POST_SET_OP           ((uint32_t) 2)
#define CRFSCHTTP_NODE_POST_UPDATE_OP        ((uint32_t) 3)
#define CRFSCHTTP_NODE_POST_RENEW_OP         ((uint32_t) 4)
#define CRFSCHTTP_NODE_PUT_SET_OP            ((uint32_t) 5)
#define CRFSCHTTP_NODE_PUT_UPDATE_OP         ((uint32_t) 6)
#define CRFSCHTTP_NODE_PUT_RENEW_OP          ((uint32_t) 7)

typedef struct _CRFSCHTTP_NODE
{
    http_parser_t            http_parser;
    http_parser_settings_t   http_parser_setting;
    
    CBUFFER                  cbuffer;
    uint32_t                 http_header_parsed_len;
    uint32_t                 http_rsp_status;
    uint32_t                 http_header_fsm;/*finite state machine*/
    uint32_t                 http_header_op;/*operation*/
    
    CSOCKET_CNODE           *csocket_cnode;
    CTIMET                   recv_atime;  /*last recv in msecond*/
    CTIMET                   send_atime;  /*last send in msecond*/
    uint64_t                 recv_size;   /*total recv bytes*/
    uint64_t                 send_size;   /*total send bytes*/
    
    CBUFFER                  url;   /*string*/
    CBUFFER                  host;  /*string*/
    CBUFFER                  uri;   /*string*/
    CBUFFER                  expires;/*optional header in response, indicate expire timestamp*/
    CBUFFER                  stale;  /*optional header in response, indicate read expired data*/
    CSTRKV_MGR               header_kvs;
    CHUNK_MGR                req_body_chunks;
    CHUNK_MGR                rsp_body_chunks;
    CTIMET                   c_time;/*create time*/
    CTIMET                   e_time;/*expire time*/
    CTMV                     s_tmv;/*timeval when start for debug or stats*/
    //CTMV                     e_tmv;/*timeval when end for debug or stats*/
    CBYTES                   content_cbytes;/*response content*/
    uint64_t                 content_length;
    uint64_t                 http_body_parsed_len;

    CSTRING                 *store_path;
    EC_BOOL                  expired_body_need;/*flag*/
    MOD_NODE                 mod_node; /*bigfile on which mod_node*/
    EC_BOOL                 (*send_data_more)(struct _CRFSCHTTP_NODE *);

    /*buff mode*/
    uint8_t                  *data_buff;
    UINT32                    data_total_len;
    UINT32                    data_sent_len;

    /*sendfile mode*/
    int                       block_fd;
    int                       rsvd1;
    UINT32                    block_size;
    UINT32                    block_pos;
    
    uint64_t                  store_beg_offset;
    uint64_t                  store_end_offset;
    uint64_t                  store_cur_offset;
}CRFSCHTTP_NODE;

#define CRFSCHTTP_NODE_PARSER(crfschttp_node)              (&((crfschttp_node)->http_parser))
#define CRFSCHTTP_NODE_SETTING(crfschttp_node)             (&((crfschttp_node)->http_parser_setting))
#define CRFSCHTTP_NODE_CBUFFER(crfschttp_node)             (&((crfschttp_node)->cbuffer))
#define CRFSCHTTP_NODE_HEADER_PARSED_LEN(crfschttp_node)   ((crfschttp_node)->http_header_parsed_len)
#define CRFSCHTTP_NODE_HEADER_FSM(crfschttp_node)          ((crfschttp_node)->http_header_fsm)
#define CRFSCHTTP_NODE_HEADER_OP(crfschttp_node)           ((crfschttp_node)->http_header_op)
#define CRFSCHTTP_NODE_CSOCKET_CNODE(crfschttp_node)       ((crfschttp_node)->csocket_cnode)
#define CRFSCHTTP_NODE_RECV_ATIME_TS(crfschttp_node)       ((crfschttp_node)->recv_atime)
#define CRFSCHTTP_NODE_SEND_ATIME_TS(crfschttp_node)       ((crfschttp_node)->send_atime)
#define CRFSCHTTP_NODE_RECV_SIZE(crfschttp_node)           ((crfschttp_node)->recv_size)
#define CRFSCHTTP_NODE_SEND_SIZE(crfschttp_node)           ((crfschttp_node)->send_size)
#define CRFSCHTTP_NODE_URL(crfschttp_node)                 (&((crfschttp_node)->url))
#define CRFSCHTTP_NODE_HOST(crfschttp_node)                (&((crfschttp_node)->host))
#define CRFSCHTTP_NODE_URI(crfschttp_node)                 (&((crfschttp_node)->uri))
#define CRFSCHTTP_NODE_EXPIRES(crfschttp_node)             (&((crfschttp_node)->expires))
#define CRFSCHTTP_NODE_STALE(crfschttp_node)               (&((crfschttp_node)->stale))
#define CRFSCHTTP_NODE_HEADER_KVS(crfschttp_node)          (&((crfschttp_node)->header_kvs))
#define CRFSCHTTP_NODE_REQ_BODY_CHUNKS(crfschttp_node)     (&((crfschttp_node)->req_body_chunks))
#define CRFSCHTTP_NODE_RSP_BODY_CHUNKS(crfschttp_node)     (&((crfschttp_node)->rsp_body_chunks))
#define CRFSCHTTP_NODE_CREATE_TIME(crfschttp_node)         ((crfschttp_node)->c_time)
#define CRFSCHTTP_NODE_EXPIRE_TIME(crfschttp_node)         ((crfschttp_node)->e_time)
#define CRFSCHTTP_NODE_START_TMV(crfschttp_node)           (&((crfschttp_node)->s_tmv))
//#define CRFSCHTTP_NODE_END_TMV(crfschttp_node)             (&((crfschttp_node)->e_tmv))
#define CRFSCHTTP_NODE_CONTENT_CBYTES(crfschttp_node)      (&((crfschttp_node)->content_cbytes))
#define CRFSCHTTP_NODE_CONTENT_LENGTH(crfschttp_node)      ((crfschttp_node)->content_length)
#define CRFSCHTTP_NODE_BODY_PARSED_LEN(crfschttp_node)     ((crfschttp_node)->http_body_parsed_len)
#define CRFSCHTTP_NODE_RSP_STATUS(crfschttp_node)          ((crfschttp_node)->http_rsp_status)

#define CRFSCHTTP_NODE_STORE_PATH(crfschttp_node)          ((crfschttp_node)->store_path)
#define CRFSCHTTP_NODE_EXPIRED_BODY_NEED(crfschttp_node)   ((crfschttp_node)->expired_body_need)
#define CRFSCHTTP_NODE_MOD_NODE(crfschttp_node)            (&((crfschttp_node)->mod_node))

#define CRFSCHTTP_NODE_SEND_DATA_MORE(crfschttp_node)      ((crfschttp_node)->send_data_more)
#define CRFSCHTTP_NODE_SEND_DATA_BUFF(crfschttp_node)      ((crfschttp_node)->data_buff)
#define CRFSCHTTP_NODE_SEND_DATA_TOTAL_LEN(crfschttp_node) ((crfschttp_node)->data_total_len)
#define CRFSCHTTP_NODE_SEND_DATA_SENT_LEN(crfschttp_node)  ((crfschttp_node)->data_sent_len)
#define CRFSCHTTP_NODE_SEND_BLOCK_FD(crfschttp_node)       ((crfschttp_node)->block_fd)
#define CRFSCHTTP_NODE_SEND_BLOCK_SIZE(crfschttp_node)     ((crfschttp_node)->block_size)
#define CRFSCHTTP_NODE_SEND_BLOCK_POS(crfschttp_node)      ((crfschttp_node)->block_pos)
#define CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node)    ((crfschttp_node)->store_beg_offset)
#define CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node)    ((crfschttp_node)->store_end_offset)
#define CRFSCHTTP_NODE_STORE_CUR_OFFSET(crfschttp_node)    ((crfschttp_node)->store_cur_offset)
#define CRFSCHTTP_NODE_STORE_SIZE(crfschttp_node)          (CRFSCHTTP_NODE_STORE_END_OFFSET(crfschttp_node) - CRFSCHTTP_NODE_STORE_BEG_OFFSET(crfschttp_node))
                                                         
#define CSOCKET_CNODE_CRFSCHTTP_NODE(csocket_cnode)       (CSOCKET_CNODE_PTR(csocket_cnode))

#define    CRFSCHTTP_STATUS_NONE                          ((uint32_t)   0)
#define    CRFSCHTTP_CONTINUE                             ((uint32_t) 100)
#define    CRFSCHTTP_SWITCHING_PROTOCOLS                  ((uint32_t) 101)
#define    CRFSCHTTP_PROCESSING                           ((uint32_t) 102)   /* RFC2518 section 10.1 */
#define    CRFSCHTTP_OK                                   ((uint32_t) 200)
#define    CRFSCHTTP_CREATED                              ((uint32_t) 201)
#define    CRFSCHTTP_ACCEPTED                             ((uint32_t) 202)
#define    CRFSCHTTP_NON_AUTHORITATIVE_INFORMATION        ((uint32_t) 203)
#define    CRFSCHTTP_NO_CONTENT                           ((uint32_t) 204)
#define    CRFSCHTTP_RESET_CONTENT                        ((uint32_t) 205)
#define    CRFSCHTTP_PARTIAL_CONTENT                      ((uint32_t) 206)
#define    CRFSCHTTP_MULTI_STATUS                         ((uint32_t) 207)    /* RFC2518 section 10.2 */
#define    CRFSCHTTP_MULTIPLE_CHOICES                     ((uint32_t) 300)
#define    CRFSCHTTP_MOVED_PERMANENTLY                    ((uint32_t) 301)
#define    CRFSCHTTP_MOVED_TEMPORARILY                    ((uint32_t) 302)
#define    CRFSCHTTP_SEE_OTHER                            ((uint32_t) 303)
#define    CRFSCHTTP_NOT_MODIFIED                         ((uint32_t) 304)
#define    CRFSCHTTP_USE_PROXY                            ((uint32_t) 305)
#define    CRFSCHTTP_TEMPORARY_REDIRECT                   ((uint32_t) 307)
#define    CRFSCHTTP_BAD_REQUEST                          ((uint32_t) 400)
#define    CRFSCHTTP_UNAUTHORIZED                         ((uint32_t) 401)
#define    CRFSCHTTP_PAYMENT_REQUIRED                     ((uint32_t) 402)
#define    CRFSCHTTP_FORBIDDEN                            ((uint32_t) 403)
#define    CRFSCHTTP_NOT_FOUND                            ((uint32_t) 404)
#define    CRFSCHTTP_METHOD_NOT_ALLOWED                   ((uint32_t) 405)
#define    CRFSCHTTP_NOT_ACCEPTABLE                       ((uint32_t) 406)
#define    CRFSCHTTP_PROXY_AUTHENTICATION_REQUIRED        ((uint32_t) 407)
#define    CRFSCHTTP_REQUEST_TIMEOUT                      ((uint32_t) 408)
#define    CRFSCHTTP_CONFLICT                             ((uint32_t) 409)
#define    CRFSCHTTP_GONE                                 ((uint32_t) 410)
#define    CRFSCHTTP_LENGTH_REQUIRED                      ((uint32_t) 411)
#define    CRFSCHTTP_PRECONDITION_FAILED                  ((uint32_t) 412)
#define    CRFSCHTTP_REQUEST_ENTITY_TOO_LARGE             ((uint32_t) 413)
#define    CRFSCHTTP_REQUEST_URI_TOO_LONG                 ((uint32_t) 414)
#define    CRFSCHTTP_UNSUPPORTED_MEDIA_TYPE               ((uint32_t) 415)
#define    CRFSCHTTP_EXPECTATION_FAILED                   ((uint32_t) 417)
#define    CRFSCHTTP_UNPROCESSABLE_ENTITY                 ((uint32_t) 422)    /* RFC2518 section 10.3 */
#define    CRFSCHTTP_LOCKED                               ((uint32_t) 423)    /* RFC2518 section 10.4 */
#define    CRFSCHTTP_FAILED_DEPENDENCY                    ((uint32_t) 424)    /* RFC2518 section 10.5 */
                                                              
#define    CRFSCHTTP_INTERNAL_SERVER_ERROR                ((uint32_t) 500)
#define    CRFSCHTTP_NOT_IMPLEMENTED                      ((uint32_t) 501)
#define    CRFSCHTTP_BAD_GATEWAY                          ((uint32_t) 502)
#define    CRFSCHTTP_SERVICE_UNAVAILABLE                  ((uint32_t) 503)
#define    CRFSCHTTP_GATEWAY_TIMEOUT                      ((uint32_t) 504)
#define    CRFSCHTTP_VERSION_NOT_SUPPORTED                ((uint32_t) 505)
#define    CRFSCHTTP_INSUFFICIENT_STORAGE                 ((uint32_t) 507)   /* RFC2518 section 10.6 */
#define    CRFSCHTTP_INVALID_HEADER                       ((uint32_t) 600)   /* Squid header parsing error */
#define    CRFSCHTTP_HEADER_TOO_LARGE                     ((uint32_t) 601)   /* Header too large to process */

#define    CRFSCHTTP_SEND_RSP_FAILED                      ((uint32_t) 999)   /* Header too large to process */

void crfschttp_csocket_cnode_close(CSOCKET_CNODE *csocket_cnode);

EC_BOOL crfschttp_csocket_cnode_defer_close_list_init();

EC_BOOL crfschttp_csocket_cnode_defer_close_list_push(CSOCKET_CNODE *csocket_cnode);

CSOCKET_CNODE *crfschttp_csocket_cnode_defer_close_list_pop();

EC_BOOL crfschttp_csocket_cnode_defer_close_list_is_empty();

EC_BOOL crfschttp_csocket_cnode_defer_close_handle();

void crfschttp_csocket_cnode_epoll_close(CSOCKET_CNODE *csocket_cnode);

void crfschttp_node_defer_close(CRFSCHTTP_NODE *crfschttp_node);

void crfschttp_csocket_cnode_timeout(CSOCKET_CNODE *csocket_cnode);

EC_BOOL crfschttp_defer_request_queue_init();

EC_BOOL crfschttp_defer_request_queue_clean();

EC_BOOL crfschttp_defer_request_queue_push(CRFSCHTTP_NODE *crfschttp_node);

CRFSCHTTP_NODE *crfschttp_defer_request_queue_pop();

CRFSCHTTP_NODE *crfschttp_defer_request_queue_peek();

EC_BOOL crfschttp_defer_request_queue_launch();

EC_BOOL crfschttp_defer_launch(void *UNUSED(none));

EC_BOOL crfschttp_make_response_header_protocol(CRFSCHTTP_NODE *crfschttp_node, const uint16_t major, const uint16_t minor, const uint32_t status);

EC_BOOL crfschttp_make_response_header_date(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_response_header_elapsed(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_response_header_content_type(CRFSCHTTP_NODE *crfschttp_node, const uint8_t *data, const uint32_t size);

EC_BOOL crfschttp_make_response_header_content_length(CRFSCHTTP_NODE *crfschttp_node, const uint64_t size);

EC_BOOL crfschttp_make_response_header_location(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_response_header_end(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_response_body(CRFSCHTTP_NODE *crfschttp_node, const uint8_t *data, const uint32_t size);

EC_BOOL crfschttp_make_response_header(CRFSCHTTP_NODE *crfschttp_node, const uint64_t body_len);

EC_BOOL crfschttp_make_error_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_put_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_post_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_getrgf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_getsmf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_getbgf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_dsmf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_ddir_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_renew_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_setsmf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_make_update_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_renew_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_setsmf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_update_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_put_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_post_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_getrgf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_getsmf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_getbgf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_dsmf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_handle_ddir_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_error_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_put_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_post_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_getrgf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_getsmf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_getbgf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_dsmf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_ddir_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_renew_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_setsmf_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_update_response(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_error_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_put_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_post_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_getrgf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_getsmf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_getbgf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_dsmf_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_ddir_request(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_put(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_post(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_get(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_getrgf(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_getsmf(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_getbgf(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_dsmf(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_ddir(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_is_http_renew(const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_http_put(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_http_post(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_commit_http_get(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_parse_host(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_parse_content_length(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_parse_uri(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_log_start();

EC_BOOL crfschttp_commit_request(CRFSCHTTP_NODE *crfschttp_node);

CRFSCHTTP_NODE *crfschttp_node_new(const uint32_t size);

EC_BOOL crfschttp_node_init(CRFSCHTTP_NODE *crfschttp_node, const uint32_t size);

EC_BOOL crfschttp_node_clean(CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_node_free(CRFSCHTTP_NODE *crfschttp_node);

void    crfschttp_node_print(LOG *log, const CRFSCHTTP_NODE *crfschttp_node);

EC_BOOL crfschttp_recv_on_csocket_cnode(CSOCKET_CNODE *csocket_cnode);

EC_BOOL crfschttp_send_on_csocket_cnode(CSOCKET_CNODE *csocket_cnode);

EC_BOOL crfschttp_recv_on_csocket_cnode_thread(CSOCKET_CNODE *csocket_cnode);

EC_BOOL crfschttp_send_on_csocket_cnode_thread(CSOCKET_CNODE *csocket_cnode);


#endif /*_CRFSCHTTP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

