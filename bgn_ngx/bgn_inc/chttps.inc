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

#ifndef _CHTTPS_INC
#define _CHTTPS_INC

#include "type.h"
#include "debug.h"

#include "cbuffer.h"
#include "chunk.h"
#include "cstrkv.h"

#include "csocket.inc"

#include "cssl.inc"

#include "croutine.h"

#include "http_parser.h"

#include "chttp.inc"


#define  CHTTPS_NODE_STATUS_UNDEF                 ((UINT32)0)
#define  CHTTPS_NODE_STATUS_HANDSHAKE_ONGOING     ((UINT32)1)
#define  CHTTPS_NODE_STATUS_HANDSHAKE_IS_DONE     ((UINT32)2)

struct _CSOCKET_CNODE;

typedef struct _CHTTPS_NODE
{
    UINT32                    status;               /*ONGOING or IS_DONE*/
    CSSL_NODE                *cssl_node;            /* for ssl */    
    CSTRING                  *ca_file;              /* for ssl */
    CSTRING                  *client_cert_file;     /* for ssl */
    CSTRING                  *client_privkey_file;  /* for ssl */

    void                     *csrv;          /*mount point*/
    
    CROUTINE_NODE            *croutine_node; /*croutine mounted point*/

    CROUTINE_COND            *croutine_cond;/*croutine condition lock, used when trigger http request */

    UINT32                    http_type:32;   /*CHTTP_TYPE_xxx*/
    UINT32                    status_code:32; /*for http response only*/
    
    http_parser_t             http_parser;
    http_parser_settings_t    http_parser_settings;

    CBUFFER                   i_buf;   /*io buffer used by http. socket read buff, and the input buff of http_parser*/ 
    CHUNK_MGR                 send_buf; /*io buffer used by http*/    
    CHUNK_MGR                 recv_buf; /*io buffer used by http*/    
    
    struct _CSOCKET_CNODE    *csocket_cnode;
    CQUEUE_DATA              *cqueue_data; /*crfshttp_node mounted point in request defer queue*/
    
    CBUFFER                   url;   /*string*/
    CBUFFER                   host;  /*string*/
    CBUFFER                   uri;   /*string*/
    CBUFFER                   expires;/*optional header in response*/
    CSTRKV_MGR                header_in_kvs;
    CSTRKV_MGR                header_out_kvs;

    CTMV                      s_tmv;/*timeval when start for debug or stats*/
    CBYTES                    content_cbytes;/*response content*/
    uint64_t                  content_length;
    uint64_t                  body_parsed_len;
    uint64_t                  body_stored_len;

    uint32_t                  http_rsp_status  :10;
    uint32_t                  header_complete  :1;/*flag, header is completed or not*/
    uint32_t                  keepalive        :1;/*set true if http client ask for*/
    uint32_t                  rsvd_01          :1;/*flag, used by expired_body_need*/
    uint32_t                  recv_complete    :1;/*flag*/
    uint32_t                  send_complete    :1;/*flag*/
    uint32_t                  coroutine_restore:1;/*flag*/
    uint32_t                  header_parsed_len:16;
  
    /*statistics*/
    CHTTP_STAT                chttp_stat;/*mount point*/
}CHTTPS_NODE;

#define CHTTPS_NODE_STATUS(chttps_node)                      ((chttps_node)->status)
#define CHTTPS_NODE_CSSL_NODE(chttps_node)                   ((chttps_node)->cssl_node)
#define CHTTPS_NODE_CA_FILE(chttps_node)                     ((chttps_node)->ca_file)
#define CHTTPS_NODE_CLIENT_CERT_FILE(chttps_node)            ((chttps_node)->client_cert_file)
#define CHTTPS_NODE_CLIENT_PRIVKEY_FILE(chttps_node)         ((chttps_node)->client_privkey_file)

#define CHTTPS_NODE_CSRV(chttps_node)                        ((chttps_node)->csrv)

#define CHTTPS_NODE_CROUTINE_NODE(chttps_node)               ((chttps_node)->croutine_node)
#define CHTTPS_NODE_CROUTINE_COND(chttps_node)               ((chttps_node)->croutine_cond)

#define CHTTPS_NODE_TYPE(chttps_node)                        ((chttps_node)->http_type)
#define CHTTPS_NODE_STATUS_CODE(chttps_node)                 ((chttps_node)->status_code)

#define CHTTPS_NODE_PARSER(chttps_node)                      (&((chttps_node)->http_parser))
#define CHTTPS_NODE_SETTING(chttps_node)                     (&((chttps_node)->http_parser_settings))
#define CHTTPS_NODE_IN_BUF(chttps_node)                      (&((chttps_node)->i_buf))
#define CHTTPS_NODE_SEND_BUF(chttps_node)                    (&((chttps_node)->send_buf))
#define CHTTPS_NODE_RECV_BUF(chttps_node)                    (&((chttps_node)->recv_buf))

#define CHTTPS_NODE_CSOCKET_CNODE(chttps_node)               ((chttps_node)->csocket_cnode)
#define CHTTPS_NODE_CQUEUE_DATA(chttps_node)                 ((chttps_node)->cqueue_data)
#define CHTTPS_NODE_URL(chttps_node)                         (&((chttps_node)->url))
#define CHTTPS_NODE_HOST(chttps_node)                        (&((chttps_node)->host))
#define CHTTPS_NODE_URI(chttps_node)                         (&((chttps_node)->uri))
#define CHTTPS_NODE_EXPIRES(chttps_node)                     (&((chttps_node)->expires))
#define CHTTPS_NODE_HEADER_IN_KVS(chttps_node)               (&((chttps_node)->header_in_kvs))
#define CHTTPS_NODE_HEADER_OUT_KVS(chttps_node)              (&((chttps_node)->header_out_kvs))

#define CHTTPS_NODE_START_TMV(chttps_node)                   (&((chttps_node)->s_tmv))
#define CHTTPS_NODE_CONTENT_CBYTES(chttps_node)              (&((chttps_node)->content_cbytes))
#define CHTTPS_NODE_CONTENT_LENGTH(chttps_node)              ((chttps_node)->content_length)
#define CHTTPS_NODE_BODY_PARSED_LEN(chttps_node)             ((chttps_node)->body_parsed_len)
#define CHTTPS_NODE_BODY_STORED_LEN(chttps_node)             ((chttps_node)->body_stored_len)
#define CHTTPS_NODE_HEADER_PARSED_LEN(chttps_node)           ((chttps_node)->header_parsed_len)

#define CHTTPS_NODE_RSP_STATUS(chttps_node)                  ((chttps_node)->http_rsp_status)
#define CHTTPS_NODE_HEADER_COMPLETE(chttps_node)             ((chttps_node)->header_complete)
#define CHTTPS_NODE_EXPIRED_BODY_NEED(chttps_node)           ((chttps_node)->rsvd_01)
#define CHTTPS_NODE_KEEPALIVE(chttps_node)                   ((chttps_node)->keepalive)
#define CHTTPS_NODE_RECV_COMPLETE(chttps_node)               ((chttps_node)->recv_complete)
#define CHTTPS_NODE_SEND_COMPLETE(chttps_node)               ((chttps_node)->send_complete)
#define CHTTPS_NODE_COROUTINE_RESTORE(chttps_node)           ((chttps_node)->coroutine_restore)

#define CHTTPS_NODE_STAT(chttps_node)                        (&((chttps_node)->chttp_stat))

/* --- shortcut ---*/
#define CHTTPS_NODE_S_SEND_LEN(chttps_node)                  (CHTTP_STAT_S_SEND_LEN(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_S_RECV_LEN(chttps_node)                  (CHTTP_STAT_S_RECV_LEN(CHTTPS_NODE_STAT(chttps_node)))

#define CHTTPS_NODE_S_NSEC(chttps_node)                      (CHTTP_STAT_BASIC_S_NSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_S_MSEC(chttps_node)                      (CHTTP_STAT_BASIC_S_MSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_R_NSEC(chttps_node)                      (CHTTP_STAT_BASIC_R_NSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_R_MSEC(chttps_node)                      (CHTTP_STAT_BASIC_R_MSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_L_NSEC(chttps_node)                      (CHTTP_STAT_BASIC_L_NSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_L_MSEC(chttps_node)                      (CHTTP_STAT_BASIC_L_MSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_H_NSEC(chttps_node)                      (CHTTP_STAT_BASIC_H_NSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_H_MSEC(chttps_node)                      (CHTTP_STAT_BASIC_H_MSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_D_NSEC(chttps_node)                      (CHTTP_STAT_BASIC_D_NSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_D_MSEC(chttps_node)                      (CHTTP_STAT_BASIC_D_MSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_E_NSEC(chttps_node)                      (CHTTP_STAT_BASIC_E_NSEC(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_E_MSEC(chttps_node)                      (CHTTP_STAT_BASIC_E_MSEC(CHTTPS_NODE_STAT(chttps_node)))

#define CHTTPS_NODE_STAT_STR(chttps_node)                    (CHTTP_STAT_STAT_STR(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_DESC_STR(chttps_node)                    (CHTTP_STAT_DESC_STR(CHTTPS_NODE_STAT(chttps_node)))

#define CHTTPS_NODE_STAT_STR_INIT(chttps_node)               (CHTTP_STAT_STAT_STR_INIT(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_STAT_STR_CLEAN(chttps_node)              (CHTTP_STAT_STAT_STR_CLEAN(CHTTPS_NODE_STAT(chttps_node)))

#define CHTTPS_NODE_DESC_STR_INIT(chttps_node)               (CHTTP_STAT_DESC_STR_INIT(CHTTPS_NODE_STAT(chttps_node)))
#define CHTTPS_NODE_DESC_STR_CLEAN(chttps_node)              (CHTTP_STAT_DESC_STR_CLEAN(CHTTPS_NODE_STAT(chttps_node)))

/*----------------------------- CHTTPS_NODE interface for statistics -----------------------------*/
#define CHTTPS_NODE_S_SEND_LEN_INC(chttps_node, num) do{                                       \
    CHTTPS_NODE_S_SEND_LEN(chttps_node) += (num);                                              \
}while(0)

#define CHTTPS_NODE_S_RECV_LEN_INC(chttps_node, num) do{                                       \
    CHTTPS_NODE_S_RECV_LEN(chttps_node) += (num);                                              \
}while(0)

#define CHTTPS_NODE_LOG_STAT_WHEN_DONE(chttps_node, stat_format...) do{                        \
    snprintf((char *)CHTTPS_NODE_STAT_STR(chttps_node), CHTTP_STAT_STR_MAX_SIZE, stat_format); \
}while(0)

#define CHTTPS_NODE_LOG_INFO_WHEN_DONE(chttps_node, info_format...) do{                        \
    snprintf((char *)CHTTPS_NODE_DESC_STR(chttps_node), CHTTP_DESC_STR_MAX_SIZE, info_format); \
}while(0)

#define CHTTPS_NODE_LOG_TIME_WHEN_START(chttps_node) do{                                       \
    CHTTPS_NODE_S_NSEC(chttps_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CHTTPS_NODE_S_MSEC(chttps_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)


#define CHTTPS_NODE_LOG_TIME_WHEN_RCVD(chttps_node) do{                                        \
    CHTTPS_NODE_R_NSEC(chttps_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CHTTPS_NODE_R_MSEC(chttps_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)

#define CHTTPS_NODE_LOG_TIME_WHEN_LOADED(chttps_node) do{                                      \
    CHTTPS_NODE_L_NSEC(chttps_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CHTTPS_NODE_L_MSEC(chttps_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)

#define CHTTPS_NODE_LOG_TIME_WHEN_HANDLE(chttps_node) do{                                      \
    CHTTPS_NODE_H_NSEC(chttps_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CHTTPS_NODE_H_MSEC(chttps_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)

#define CHTTPS_NODE_LOG_TIME_WHEN_DONE(chttps_node) do{                                        \
    CHTTPS_NODE_D_NSEC(chttps_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CHTTPS_NODE_D_MSEC(chttps_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)

#define CHTTPS_NODE_LOG_TIME_WHEN_END(chttps_node) do{                                         \
    CHTTPS_NODE_E_NSEC(chttps_node) = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());     \
    CHTTPS_NODE_E_MSEC(chttps_node) = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());     \
}while(0)

#define CHTTPS_NODE_LOG_PRINT(chttps_node) do{                                                 \
    uint32_t s2r_elapsed_msec;                                                               \
    uint32_t s2l_elapsed_msec;                                                               \
    uint32_t s2h_elapsed_msec;                                                               \
    uint32_t s2d_elapsed_msec;                                                               \
    uint32_t s2e_elapsed_msec;                                                               \
    s2r_elapsed_msec = (uint32_t)((CHTTPS_NODE_R_NSEC(chttps_node) - CHTTPS_NODE_S_NSEC(chttps_node)) * 1000 + CHTTPS_NODE_R_MSEC(chttps_node) - CHTTPS_NODE_S_MSEC(chttps_node)); \
    s2l_elapsed_msec = (uint32_t)((CHTTPS_NODE_L_NSEC(chttps_node) - CHTTPS_NODE_S_NSEC(chttps_node)) * 1000 + CHTTPS_NODE_L_MSEC(chttps_node) - CHTTPS_NODE_S_MSEC(chttps_node)); \
    s2h_elapsed_msec = (uint32_t)((CHTTPS_NODE_H_NSEC(chttps_node) - CHTTPS_NODE_S_NSEC(chttps_node)) * 1000 + CHTTPS_NODE_H_MSEC(chttps_node) - CHTTPS_NODE_S_MSEC(chttps_node)); \
    s2d_elapsed_msec = (uint32_t)((CHTTPS_NODE_D_NSEC(chttps_node) - CHTTPS_NODE_S_NSEC(chttps_node)) * 1000 + CHTTPS_NODE_D_MSEC(chttps_node) - CHTTPS_NODE_S_MSEC(chttps_node)); \
    s2e_elapsed_msec = (uint32_t)((CHTTPS_NODE_E_NSEC(chttps_node) - CHTTPS_NODE_S_NSEC(chttps_node)) * 1000 + CHTTPS_NODE_E_MSEC(chttps_node) - CHTTPS_NODE_S_MSEC(chttps_node)); \
    sys_log(LOGUSER08,                                                                       \
            "%s %u.%03u %u.%03u %u %u.%03u %u %u.%03u %u %u.%03u %u %u.%03u %u %s\n",        \
            (char *)CHTTPS_NODE_STAT_STR(chttps_node),                                       \
            CHTTPS_NODE_S_NSEC(chttps_node), CHTTPS_NODE_S_MSEC(chttps_node),                \
            CHTTPS_NODE_R_NSEC(chttps_node), CHTTPS_NODE_R_MSEC(chttps_node),                \
            s2r_elapsed_msec,                                                                \
            CHTTPS_NODE_L_NSEC(chttps_node), CHTTPS_NODE_L_MSEC(chttps_node),                \
            s2l_elapsed_msec,                                                                \
            CHTTPS_NODE_H_NSEC(chttps_node), CHTTPS_NODE_H_MSEC(chttps_node),                \
            s2h_elapsed_msec,                                                                \
            CHTTPS_NODE_D_NSEC(chttps_node), CHTTPS_NODE_D_MSEC(chttps_node),                \
            s2d_elapsed_msec,                                                                \
            CHTTPS_NODE_E_NSEC(chttps_node), CHTTPS_NODE_E_MSEC(chttps_node),                \
            s2e_elapsed_msec,                                                                \
            (char *)CHTTPS_NODE_DESC_STR(chttps_node)                                        \
           );                                                                                \
}while(0)


typedef EC_BOOL (*CHTTPS_NODE_COMMIT_REQUEST)(CHTTPS_NODE *);

/*restful api */
typedef struct
{
    const char    *name;
    uint32_t       len; /*name length*/
    uint32_t       rsvd;

    EC_BOOL (*commit)(CHTTPS_NODE *); /*commit request handler*/
}CHTTPS_REST;

#define CHTTPS_REST_NAME(chttps_rest)       ((chttps_rest)->name)
#define CHTTPS_REST_LEN(chttps_rest)        ((chttps_rest)->len)
#define CHTTPS_REST_COMMIT(chttps_rest)     ((chttps_rest)->commit)


#endif /*_CHTTP_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

