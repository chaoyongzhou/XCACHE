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

#ifndef _CHTTP_INC
#define _CHTTP_INC

#include "type.h"
#include "debug.h"

#include "croutine.h"

#include "http_parser.h"
#include "cbuffer.h"
#include "chunk.h"
#include "csocket.inc"
#include "cstrkv.h"

#include "ccallback.h"

/*HTTP 1.1*/
#define CHTTP_VERSION_MAJOR       ((uint16_t) 1)
#define CHTTP_VERSION_MINOR       ((uint16_t) 1)


#define CHTTP_TYPE_DO_SRV_REQ     ((UINT32) 0x00000001) /*server accept request and handle it          */
#define CHTTP_TYPE_DO_CLT_RSP     ((UINT32) 0x00000002) /*client send request and handle response      */
#define CHTTP_TYPE_DO_CLT_CHK     ((UINT32) 0x00000010) /*client send check request and handle response*/
#define CHTTP_TYPE_DO_REQ_RSP     (CHTTP_TYPE_DO_SRV_REQ | CHTTP_TYPE_DO_CLT_RSP)/*0x00000003*/
#define CHTTP_TYPE_DO_NOTHING     ((UINT32) 0xFFFFFFFF)/*for 64-bits: high 32 bits are zero*/

#define CHTTP_RSP_X_CACHE_CONTROL ("X_CACHE_CONTROL")
#define CHTTP_STORE_GZIP_POSTFIX  ("/@gzip")

/*HTTP Parser Control*/
#define CHTTP_PASER_PAUSED        ((int) 1)
#define CHTTP_PASER_RESUME        ((int) 0)

#define CHTTP_HEADER_MAX_SIZE     ((uint32_t)(4 * 1024))     /*4KB*/
#define CHTTP_BODY_MAX_SIZE       ((uint32_t)(1024 * 1024))  /*1MB*/

#define CHTTP_TIMEOUT_NSEC        (300) /*5 min*/

#define CHTTP_STAT_STR_MAX_SIZE   (128)
#define CHTTP_DESC_STR_MAX_SIZE   (384)

#define CHTTP_SEG_ERR_ID          ((uint32_t)~0)
#define CHTTP_SEG_ERR_SIZE        ((uint32_t)~0)
#define CHTTP_SEG_ERR_OFFSET      ((uint32_t)~0)

/*2 bits*/
#define CHTTP_STORE_USE_GZIP_TRUE  ((uint32_t)0x00)
#define CHTTP_STORE_USE_GZIP_FALSE ((uint32_t)0x01)
#define CHTTP_STORE_USE_GZIP_UNDEF ((uint32_t)0x02)

/*8 bits*/
#define CHTTP_STORE_CACHE_ERR      ((uint32_t)0x00)/*bitmap: 0000 0000*/
#define CHTTP_STORE_CACHE_NONE     ((uint32_t)0x01)/*bitmap: 0000 0001*/
#define CHTTP_STORE_CACHE_HEADER   ((uint32_t)0x10)/*bitmap: 0001 0000, cache header to storage as single file*/
#define CHTTP_STORE_CACHE_BODY     ((uint32_t)0x20)/*bitmap: 0010 0000, cache body to storage as single file*/
#define CHTTP_STORE_CACHE_BOTH     ((uint32_t)0x30)/*bitmap: 0011 0000, cache header and body to storage as two different files*/
#define CHTTP_STORE_CACHE_WHOLE    ((uint32_t)0x40)/*bitmap: 0100 0000, cache header and body to storage as single file*/

#define CHTTP_STORE_ERR_LAST_MODIFIED ((uint64_t)(~((uint64_t)0)))

/*store recved data to storage*/
typedef struct
{
    uint32_t                  seg_id;
    uint32_t                  seg_size;
    uint32_t                  seg_s_offset;
    uint32_t                  seg_e_offset;

    CSTRING                   basedir;                  /*${basedir}/0: store http header, ${basedir}/1: the 1st seg, ...*/

    CSTRING                   billing_flags;            /*billing control flags, used when set billing*/
    CSTRING                   billing_domain;           /*billing domain, used when set billing*/
    CSTRING                   billing_client_type;      /*billing client type domain, used when set billing*/

    CSTRING                   auth_token;               /*locked auth-token for owner*/

    CSTRING                   etag;
    CSTRING                   last_modified;
    uint64_t                  content_length;           /*lua get content length from previous response header*/

    /*cache control from configuration*/

    CSTRING                   cache_http_codes;         /*seperated by semicolon or space. cache if in http codes. format likes as 200;206*/
    CSTRING                   ncache_http_codes;        /*seperated by semicolon or space. not cache if in http codes. format likes as 404;504*/
    CSTRING                   cache_rsp_headers;        /*if http response has specific header(s), then cache it*/
    CSTRING                   ncache_rsp_headers;       /*if http response has specific header(s), then NOT cache it*/
    CSTRING                   cache_if_http_codes;      /*seperated by semicolon. cache if in http codes and renew Expires. format likes as 404=60;504=50*/

    uint32_t                  cache_allow:1;            /*orig or storage at first*/
    uint32_t                  cache_control:8;          /*cache in storage or not*/
    uint32_t                  merge_flag:1;             /*trigger merge flow*/
    uint32_t                  locked_flag:1;            /*file locked flag*/
    uint32_t                  expired_flag:1;           /*(merge) origin reasone: due to absence or due to expired*/
    uint32_t                  chunk_flag:1;             /*process flow control determined by lua*/
    uint32_t                  use_gzip_flag:2;          /*lua get use gzip flag from previouse response header. note when nil, set to EC_OBSCURE*/
    uint32_t                  last_modified_switch:1;   /*switch is on, check etag and last modified*/
    uint32_t                  override_expires_flag:1;  /*override orig expires switch*/
    uint32_t                  redirect_control:1;       /*redirect location control from configuration*/
    uint32_t                  header_orig_flag:1;       /*set it when seg 0 orig at first time*/
    uint32_t                  direct_orig_flag:1;       /*set it if direct orig*/
    uint32_t                  need_log_flag:1;          /*set it if need http log*/
    uint32_t                  cache_done:8;             /*stored or not. refer to cache_control flag*/
    uint32_t                  rsvd01:3;

    uint32_t                  orig_timeout_nsec;

    uint32_t                  merge_lock_expires_nsec;  /*lock storage will expires in seconds*/
    uint32_t                  merge_wait_timeout_nsec;  /*merge procedure wait response and will resume in seconds*/

    uint32_t                  override_expires_nsec;    /*override orig expires in seconds*/
    uint32_t                  seg_max_id;

    uint32_t                  default_expires_nsec;     /*default orig expires in seconds*/
    uint32_t                  rsvd02;

    UINT32                    redirect_max_times;/*redirect location control from configuration*/

    /*when header_orig_flag is set (ms orig procedure) or direct_orig_flag is set (direct orig procedure)*/
    UINT32                    bgn_modi;                  /*module of ms orig procedure*/
    UINT32                    bgn_import_header_callback;/*prototype: CHTTP_NODE_IMPORT_HEADER_CALLBACK*/
    UINT32                    bgn_send_header_callback;  /*prototype: CHTTP_NODE_SEND_HEADER_CALLBACK*/
    UINT32                    bgn_send_body_callback;    /*prototype: CHTTP_NODE_SEND_BODY_CALLBACK*/

    UINT32                    seq_no; /*for debug only!*/
}CHTTP_STORE;

#define CHTTP_STORE_SEG_MAX_ID(chttp_store)                   ((chttp_store)->seg_max_id)
#define CHTTP_STORE_SEG_ID(chttp_store)                       ((chttp_store)->seg_id)
#define CHTTP_STORE_SEG_SIZE(chttp_store)                     ((chttp_store)->seg_size)
#define CHTTP_STORE_SEG_S_OFFSET(chttp_store)                 ((chttp_store)->seg_s_offset)
#define CHTTP_STORE_SEG_E_OFFSET(chttp_store)                 ((chttp_store)->seg_e_offset)
#define CHTTP_STORE_BASEDIR(chttp_store)                      (&((chttp_store)->basedir))
#define CHTTP_STORE_BILLING_FLAGS(chttp_store)                (&((chttp_store)->billing_flags))
#define CHTTP_STORE_BILLING_DOMAIN(chttp_store)               (&((chttp_store)->billing_domain))
#define CHTTP_STORE_BILLING_CLIENT_TYPE(chttp_store)          (&((chttp_store)->billing_client_type))
#define CHTTP_STORE_CACHE_CTRL(chttp_store)                   ((chttp_store)->cache_control)
#define CHTTP_STORE_CACHE_DONE(chttp_store)                   ((chttp_store)->cache_done)
#define CHTTP_STORE_MERGE_FLAG(chttp_store)                   ((chttp_store)->merge_flag)
#define CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store)             ((chttp_store)->header_orig_flag)
#define CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store)             ((chttp_store)->direct_orig_flag)
#define CHTTP_STORE_NEED_LOG_FLAG(chttp_store)                ((chttp_store)->need_log_flag)
#define CHTTP_STORE_LOCKED_FLAG(chttp_store)                  ((chttp_store)->locked_flag)
#define CHTTP_STORE_EXPIRED_FLAG(chttp_store)                 ((chttp_store)->expired_flag)
#define CHTTP_STORE_CHUNK_FLAG(chttp_store)                   ((chttp_store)->chunk_flag)
#define CHTTP_STORE_AUTH_TOKEN(chttp_store)                   (&((chttp_store)->auth_token))

#define CHTTP_STORE_LAST_MODIFIED_SWITCH(chttp_store)         ((chttp_store)->last_modified_switch)
#define CHTTP_STORE_ETAG(chttp_store)                         (&((chttp_store)->etag))
#define CHTTP_STORE_LAST_MODIFIED(chttp_store)                (&((chttp_store)->last_modified))
#define CHTTP_STORE_CONTENT_LENGTH(chttp_store)               ((chttp_store)->content_length)
#define CHTTP_STORE_USE_GZIP_FLAG(chttp_store)                ((chttp_store)->use_gzip_flag)

#define CHTTP_STORE_CACHE_ALLOW(chttp_store)                  ((chttp_store)->cache_allow)

#define CHTTP_STORE_CACHE_HTTP_CODES(chttp_store)             (&((chttp_store)->cache_http_codes))
#define CHTTP_STORE_NCACHE_HTTP_CODES(chttp_store)            (&((chttp_store)->ncache_http_codes))
#define CHTTP_STORE_CACHE_RSP_HEADERS(chttp_store)            (&((chttp_store)->cache_rsp_headers))
#define CHTTP_STORE_NCACHE_RSP_HEADERS(chttp_store)           (&((chttp_store)->ncache_rsp_headers))
#define CHTTP_STORE_CACHE_IF_HTTP_CODES(chttp_store)          (&((chttp_store)->cache_if_http_codes))

#define CHTTP_STORE_OVERRIDE_EXPIRES_FLAG(chttp_store)        ((chttp_store)->override_expires_flag)
#define CHTTP_STORE_OVERRIDE_EXPIRES_NSEC(chttp_store)        ((chttp_store)->override_expires_nsec)

#define CHTTP_STORE_DEFAULT_EXPIRES_NSEC(chttp_store)         ((chttp_store)->default_expires_nsec)

#define CHTTP_STORE_ORIG_TIMEOUT_NSEC(chttp_store)            ((chttp_store)->orig_timeout_nsec)

#define CHTTP_STORE_MERGE_LOCK_EXPIRES_NSEC(chttp_store)      ((chttp_store)->merge_lock_expires_nsec)
#define CHTTP_STORE_MERGE_WAIT_TIMEOUT_NSEC(chttp_store)      ((chttp_store)->merge_wait_timeout_nsec)

#define CHTTP_STORE_REDIRECT_CTRL(chttp_store)                ((chttp_store)->redirect_control)
#define CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store)           ((chttp_store)->redirect_max_times)

#define CHTTP_STORE_BGN_ORIG_MODI(chttp_store)                ((chttp_store)->bgn_modi)
#define CHTTP_STORE_BGN_IMPORT_HEADER_CALLBACK(chttp_store)   ((chttp_store)->bgn_import_header_callback)
#define CHTTP_STORE_BGN_SEND_HEADER_CALLBACK(chttp_store)     ((chttp_store)->bgn_send_header_callback)
#define CHTTP_STORE_BGN_SEND_BODY_CALLBACK(chttp_store)       ((chttp_store)->bgn_send_body_callback)

#define CHTTP_STORE_SEQ_NO(chttp_store)                       ((chttp_store)->seq_no)

#define CHTTP_STORE_BASEDIR_STR(chttp_store)                  (CSTRING_STR(CHTTP_STORE_BASEDIR(chttp_store)))
#define CHTTP_STORE_BASEDIR_LEN(chttp_store)                  (CSTRING_LEN(CHTTP_STORE_BASEDIR(chttp_store)))

#define CHTTP_STORE_BILLING_DOMAIN_STR(chttp_store)           (CSTRING_STR(CHTTP_STORE_BILLING_DOMAIN(chttp_store)))
#define CHTTP_STORE_BILLING_DOMAIN_LEN(chttp_store)           (CSTRING_LEN(CHTTP_STORE_BILLING_DOMAIN(chttp_store)))

#define CHTTP_STORE_AUTH_TOKEN_STR(chttp_store)               (CSTRING_STR(CHTTP_STORE_AUTH_TOKEN(chttp_store)))
#define CHTTP_STORE_AUTH_TOKEN_LEN(chttp_store)               (CSTRING_LEN(CHTTP_STORE_AUTH_TOKEN(chttp_store)))

#define CHTTP_STORE_ETAG_STR(chttp_store)                     (CSTRING_STR(CHTTP_STORE_ETAG(chttp_store)))
#define CHTTP_STORE_ETAG_LEN(chttp_store)                     (CSTRING_LEN(CHTTP_STORE_ETAG(chttp_store)))

#define CHTTP_STORE_LAST_MODIFIED_STR(chttp_store)            (CSTRING_STR(CHTTP_STORE_LAST_MODIFIED(chttp_store)))
#define CHTTP_STORE_LAST_MODIFIED_LEN(chttp_store)            (CSTRING_LEN(CHTTP_STORE_LAST_MODIFIED(chttp_store)))


#define CHTTP_STAT_LOG_BUFF_MAX_SIZE                          (4 * 1024) /*4K*/

/*statistics*/
typedef struct
{
    uint32_t                  rsp_status;
    uint32_t                  rsvd01;

    /*transfer statistics*/
    uint32_t                  send_len;
    uint32_t                  recv_len;

    uint64_t                  req_s_msec; /*orig request send out time in msec*/
    uint64_t                  req_e_msec; /*orig request end time in msec*/
    uint64_t                  req_c_msec; /*orig request return (or complete) time in msec*/

    uint64_t                  rsp_s_msec; /*orig rsp recv start time in msec*/
    uint64_t                  rsp_e_msec; /*orig rsp recv complete time in msec*/

    uint32_t                  ssl_shakehand_msec; /*not used yet*/
    uint32_t                  ssl_send_len;       /*not used yet*/
    uint32_t                  client_rtt_msec;    /*not used yet*/
    uint32_t                  rsvd02;

    uint8_t                   device_name[ CHTTP_STAT_STR_MAX_SIZE ];
    uint8_t                   trace_id   [ CHTTP_STAT_STR_MAX_SIZE ];
    uint8_t                   req_host   [ CHTTP_STAT_STR_MAX_SIZE ];
    uint64_t                  req_ipaddr;

    uint64_t                  log_bitmap;

    /*time statistics*/
    union
    {
        struct/*for http basic procedure*/
        {
            /*start time means the connection setup time or parser resumed time*/
            uint64_t                  s_msec; /*start time in micro-second*/

            /*recv time means the whole http request including body received or parsed time*/
            uint64_t                  r_msec; /*received time in micro-second*/

            /*load time means the http request was loaded time in coroutine*/
            uint64_t                  l_msec;

            /*handle time means the xfs beg to handle time*/
            uint64_t                  h_msec;

            /*done time means the xfs handle done time*/
            uint64_t                  d_msec; /*done time in micro-second*/

            /*end time means all data sent out time*/
            uint64_t                  e_msec; /*end time in micro-second*/
        }basic;
        struct /*for http merge orig procedure*/
        {
            /*[merge] start time means the merge orig procedure starting time*/
            uint64_t                  s_msec; /*start time in micro-second*/

            /*[merge] locked time means after locked/before wait_ready/wait_data time*/
            uint64_t                  l_msec; /*locked done time in micro-second*/

            /*[merge] wait done time, wait_ready or wait_data*/
            uint64_t                  w_msec; /*wait_ready or wait_data done time in micro-second*/

            /*[merge] origin done time, for origin procedure owner only*/
            uint64_t                  o_msec; /*origin done time in micro-second*/

            /*[merge] cond_wait done time*/
            uint64_t                  c_msec; /*cond_wait done time in micro-second*/

            /*[merge] file read done time*/
            uint64_t                  r_msec; /*read done time in micro-second*/
        }merge;
        struct/*for http header orig procedure*/
        {
            /*[header] start time means the header orig procedure starting time*/
            uint64_t                  s_msec; /*start time in micro-second*/

            /*unsed*/
            uint64_t                  u_msec;

            /*[header] wait done time, wait_ready or wait_data*/
            uint64_t                  w_msec; /*wait_ready or wait_header done time in micro-second*/

            /*[header] origin done time, for origin procedure owner only*/
            uint64_t                  o_msec; /*origin done time in micro-second*/

            /*[header] cond_wait done time*/
            uint64_t                  c_msec; /*cond_wait done time in micro-second*/

            /*[header] file read done time*/
            uint64_t                  r_msec; /*read done time in micro-second*/
        }header;
    }u;

    uint8_t                   status_str[ CHTTP_STAT_STR_MAX_SIZE ];
    uint8_t                   desc_str  [ CHTTP_DESC_STR_MAX_SIZE ];
}CHTTP_STAT;

#define CHTTP_STAT_RSP_STATUS(chttp_stat)          ((chttp_stat)->rsp_status)

#define CHTTP_STAT_S_SEND_LEN(chttp_stat)          ((chttp_stat)->send_len)
#define CHTTP_STAT_S_RECV_LEN(chttp_stat)          ((chttp_stat)->recv_len)

#define CHTTP_STAT_REQ_S_MSEC(chttp_stat)          ((chttp_stat)->req_s_msec)
#define CHTTP_STAT_REQ_E_MSEC(chttp_stat)          ((chttp_stat)->req_e_msec)
#define CHTTP_STAT_REQ_C_MSEC(chttp_stat)          ((chttp_stat)->req_c_msec)

#define CHTTP_STAT_RSP_S_MSEC(chttp_stat)          ((chttp_stat)->rsp_s_msec)
#define CHTTP_STAT_RSP_E_MSEC(chttp_stat)          ((chttp_stat)->rsp_e_msec)

#define CHTTP_STAT_SSL_SHAKEHAND_MSEC(chttp_stat)  ((chttp_stat)->ssl_shakehand_msec)
#define CHTTP_STAT_SSL_SEND_LEN(chttp_stat)        ((chttp_stat)->ssl_send_len)
#define CHTTP_STAT_CLIENT_RTT_MSEC(chttp_stat)     ((chttp_stat)->client_rtt_msec)

#define CHTTP_STAT_DEVICE_NAME(chttp_stat)         ((chttp_stat)->device_name)
#define CHTTP_STAT_TRACE_ID(chttp_stat)            ((chttp_stat)->trace_id)
#define CHTTP_STAT_REQ_HOST(chttp_stat)            ((chttp_stat)->req_host)
#define CHTTP_STAT_REQ_IPADDR(chttp_stat)          ((chttp_stat)->req_ipaddr)

#define CHTTP_STAT_REQ_IPADDR_STR(chttp_stat)      (c_word_to_ipv4((UINT32)CHTTP_STAT_REQ_IPADDR(chttp_stat)))

#define CHTTP_STAT_LOG_BITMAP(chttp_stat)          ((chttp_stat)->log_bitmap)

#define CHTTP_STAT_BASIC_S_MSEC(chttp_stat)        ((chttp_stat)->u.basic.s_msec)
#define CHTTP_STAT_BASIC_R_MSEC(chttp_stat)        ((chttp_stat)->u.basic.r_msec)
#define CHTTP_STAT_BASIC_L_MSEC(chttp_stat)        ((chttp_stat)->u.basic.l_msec)
#define CHTTP_STAT_BASIC_H_MSEC(chttp_stat)        ((chttp_stat)->u.basic.h_msec)
#define CHTTP_STAT_BASIC_D_MSEC(chttp_stat)        ((chttp_stat)->u.basic.d_msec)
#define CHTTP_STAT_BASIC_E_MSEC(chttp_stat)        ((chttp_stat)->u.basic.e_msec)
//#define CHTTP_STAT_BASIC_U_MSEC(chttp_stat)        ((chttp_stat)->u.basic.u_msec)
//#define CHTTP_STAT_BASIC_V_MSEC(chttp_stat)        ((chttp_stat)->u.basic.v_msec)

#define CHTTP_STAT_MERGE_S_MSEC(chttp_stat)        ((chttp_stat)->u.merge.s_msec)
#define CHTTP_STAT_MERGE_L_MSEC(chttp_stat)        ((chttp_stat)->u.merge.l_msec)
#define CHTTP_STAT_MERGE_W_MSEC(chttp_stat)        ((chttp_stat)->u.merge.w_msec)
#define CHTTP_STAT_MERGE_O_MSEC(chttp_stat)        ((chttp_stat)->u.merge.o_msec)
#define CHTTP_STAT_MERGE_C_MSEC(chttp_stat)        ((chttp_stat)->u.merge.c_msec)
#define CHTTP_STAT_MERGE_R_MSEC(chttp_stat)        ((chttp_stat)->u.merge.r_msec)

#define CHTTP_STAT_HEADER_S_MSEC(chttp_stat)       ((chttp_stat)->u.header.s_msec)
#define CHTTP_STAT_HEADER_W_MSEC(chttp_stat)       ((chttp_stat)->u.header.w_msec)
#define CHTTP_STAT_HEADER_O_MSEC(chttp_stat)       ((chttp_stat)->u.header.o_msec)
#define CHTTP_STAT_HEADER_C_MSEC(chttp_stat)       ((chttp_stat)->u.header.c_msec)
#define CHTTP_STAT_HEADER_R_MSEC(chttp_stat)       ((chttp_stat)->u.header.r_msec)

#define CHTTP_STAT_ORIG_S_MSEC(chttp_stat)         ((chttp_stat)->u.orig.s_msec)
#define CHTTP_STAT_ORIG_E_MSEC(chttp_stat)         ((chttp_stat)->u.orig.e_msec)

#define CHTTP_STAT_STAT_STR(chttp_stat)            ((chttp_stat)->status_str)
#define CHTTP_STAT_DESC_STR(chttp_stat)            ((chttp_stat)->desc_str)

#define CHTTP_STAT_STAT_STR_INIT(chttp_stat)       do{(chttp_stat)->status_str[0] = 0x00;}while(0)
#define CHTTP_STAT_STAT_STR_CLEAN(chttp_stat)      do{(chttp_stat)->status_str[0] = 0x00;}while(0)

#define CHTTP_STAT_DESC_STR_INIT(chttp_stat)       do{(chttp_stat)->desc_str[0] = 0x00;}while(0)
#define CHTTP_STAT_DESC_STR_CLEAN(chttp_stat)      do{(chttp_stat)->desc_str[0] = 0x00;}while(0)

#define CHTTP_STAT_S_SEND_LEN_INC(chttp_stat, num) (CHTTP_STAT_S_SEND_LEN(chttp_stat) += (num))
#define CHTTP_STAT_S_RECV_LEN_INC(chttp_stat, num) (CHTTP_STAT_S_RECV_LEN(chttp_stat) += (num))

#define CHTTP_STAT_SET_DEVICE_NAME(chttp_stat, device_name) do {                                          \
    snprintf((char *)CHTTP_STAT_DEVICE_NAME(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, "%s", (device_name));   \
}while(0)

#define CHTTP_STAT_SET_REQ_HOST(chttp_stat, host_name) do {                                               \
    snprintf((char *)CHTTP_STAT_REQ_HOST(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, "%s", (host_name));        \
}while(0)

#define CHTTP_STAT_SET_REQ_IPADDR(chttp_stat, ipaddr) do {                                                \
    CHTTP_STAT_REQ_IPADDR(chttp_stat) = (ipaddr);                                                         \
}while(0)

#define CHTTP_STAT_SET_TRACE_ID(chttp_stat, trace_id) do {                                                \
    snprintf((char *)CHTTP_STAT_TRACE_ID(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, "%s", (trace_id));         \
}while(0)

#define CHTTP_STAT_LOG_000_RSVD                               ((uint64_t)(1 <<  0)) /*-*/
#define CHTTP_STAT_LOG_001_NODE_LAYER                         ((uint64_t)(1 <<  1)) /*proxy*/
#define CHTTP_STAT_LOG_002_ORIG_S_TIMESTAMP                   ((uint64_t)(1 <<  2))
#define CHTTP_STAT_LOG_003_CLIENT_IPADDR                      ((uint64_t)(1 <<  3)) /*127.0.0.1*/
#define CHTTP_STAT_LOG_004_CACHE_STATUS                       ((uint64_t)(1 <<  4)) /*TCPMISS*/
#define CHTTP_STAT_LOG_005_ORIG_RSP_STATUS                    ((uint64_t)(1 <<  5))
#define CHTTP_STAT_LOG_006_ORIG_PROTOCOL                      ((uint64_t)(1 <<  6)) /*http(s)*/
#define CHTTP_STAT_LOG_007_ORIG_HOST                          ((uint64_t)(1 <<  7))
#define CHTTP_STAT_LOG_008_ORIG_REQ_LEN                       ((uint64_t)(1 <<  8)) /*0*/
#define CHTTP_STAT_LOG_009_LOCAL_IPADDR                       ((uint64_t)(1 <<  9)) /*127.0.0.1*/
#define CHTTP_STAT_LOG_010_ORIG_RSP_TIME_MSEC                 ((uint64_t)(1 << 10)) /*0*/
#define CHTTP_STAT_LOG_011_ORIG_RSP_REACH_MSEC                ((uint64_t)(1 << 11))
#define CHTTP_STAT_LOG_012_DEV_NAME                           ((uint64_t)(1 << 12))
#define CHTTP_STAT_LOG_013_LOCAL_PORT                         ((uint64_t)(1 << 13)) /*18080*/
#define CHTTP_STAT_LOG_014_SERVICE_TYPE                       ((uint64_t)(1 << 14)) /*video*/
#define CHTTP_STAT_LOG_015_ORIG_IPADDR                        ((uint64_t)(1 << 15))
#define CHTTP_STAT_LOG_016_ORIG_C_TIME_NSEC                   ((uint64_t)(1 << 16)) /*xx.xxx*/
#define CHTTP_STAT_LOG_017_ORIG_SENT_NBYTES                   ((uint64_t)(1 << 17)) /*0*/
#define CHTTP_STAT_LOG_018_SSL_HANDSHAKE_MSEC                 ((uint64_t)(1 << 18)) /*0*/
#define CHTTP_STAT_LOG_019_SSL_SENT_NBYTES                    ((uint64_t)(1 << 19)) /*0*/
#define CHTTP_STAT_LOG_020_CLIENT_RTT                         ((uint64_t)(1 << 20)) /*0*/
#define CHTTP_STAT_LOG_021_ORIG_RECV_NBYTES                   ((uint64_t)(1 << 21)) /*header + body*/
#define CHTTP_STAT_LOG_022_ORIG_SENT_NBYTES                   ((uint64_t)(1 << 22)) /*header + body*/
#define CHTTP_STAT_LOG_023_TRACE_ID                           ((uint64_t)(1 << 23))

typedef struct
{
    uint32_t    key;
    const char *val;
}CHTTP_KV;

#define CHTTP_KV_KEY(chttp_kv)        ((chttp_kv)->key)
#define CHTTP_KV_VAL(chttp_kv)        ((chttp_kv)->val)

typedef EC_BOOL (*CHTTP_NODE_SEND_MORE_FUNC)(void *);

#define  CHTTP_NODE_SSL_STATUS_UNDEF                 ((UINT32)0)
#define  CHTTP_NODE_SSL_STATUS_HANDSHAKE_ONGOING     ((UINT32)1)
#define  CHTTP_NODE_SSL_STATUS_HANDSHAKE_IS_DONE     ((UINT32)2)

typedef struct _CHTTP_NODE
{
    uint32_t                  is_error:1;
    uint32_t                  counter :4;     /*reference counting*/
    uint32_t                  rsvd01  :27;
    uint32_t                  parsed;        /*used by http parser to mark the parsed position in single cbuffer*/

    void                     *csrv;          /*mount point*/

    CROUTINE_NODE            *croutine_node; /*croutine mounted point*/

    CROUTINE_COND            *croutine_cond;/*croutine condition lock, used when trigger http request */

    UINT32                    http_type:32;   /*CHTTP_TYPE_xxx*/
    UINT32                    status_code:32; /*for http response only*/

    http_parser_t             http_parser;
    http_parser_settings_t    http_parser_settings;

    CSTRKV                   *http_parsing_header_kv;/*temporary header kv during parsing header field*/

    CCALLBACK_NODE            parse_on_message_begin_cb;
    CCALLBACK_NODE            parse_on_headers_complete_cb;
    CCALLBACK_NODE            parse_on_body_cb;
    CCALLBACK_NODE            parse_on_message_complete_cb;

    CBUFFER                   i_buf;   /*io buffer used by http. socket read buff, and the input buff of http_parser*/
    CHUNK_MGR                 send_buf; /*io buffer used by http*/
    CHUNK_MGR                 recv_buf; /*io buffer used by http*/

    CSOCKET_CNODE            *csocket_cnode;
    CQUEUE_DATA              *cqueue_data; /*cxfshttp_node mounted point in request defer queue*/

    CBUFFER                   url;   /*string*/
    CBUFFER                   host;  /*string*/
    CBUFFER                   uri;   /*string*/
    CBUFFER                   expires;/*optional header in response*/
    CBUFFER                   args;
    CSTRKV_MGR                arg_kvs;
    CSTRKV_MGR                header_in_kvs;
    CSTRKV_MGR                header_out_kvs;

    CSTRKV_MGR                header_renew_kvs;
    EC_BOOL                   header_renew_flag;
    EC_BOOL                   header_expired_flag;

    CTMV                      s_tmv;/*timeval when start for debug or stats*/
    CBYTES                    content_cbytes;/*response content*/
    uint64_t                  content_length;
    uint64_t                  body_parsed_len;
    uint64_t                  body_stored_len;

    CSTRING                  *store_path;

    CHTTP_NODE_SEND_MORE_FUNC send_data_more_func;
    UINT32                    send_data_more_aux; /*for private purpose, e.g., transfer something*/

    /*buff mode*/
    uint8_t                  *data_buff;
    UINT32                    data_total_len;
    UINT32                    data_sent_len;

    uint32_t                  http_rsp_status  :10;
    uint32_t                  header_complete  :1;/*flag, header is completed or not*/
    uint32_t                  keepalive        :1;/*set true if http client ask for*/
    uint32_t                  http_req_is_head :1;/*HEAD request flag*/
    uint32_t                  recv_complete    :1;/*flag*/
    uint32_t                  send_complete    :1;/*flag*/
    uint32_t                  coroutine_restore:1;/*flag*/
    uint32_t                  is_chunked       :1;/*http rsp is chunked*/
    uint32_t                  header_parsed_len:15;

    /*sendfile mode*/
    int                       block_fd;
    UINT32                    block_size;
    UINT32                    block_pos;

    uint64_t                  store_beg_offset;
    uint64_t                  store_end_offset;
    uint64_t                  store_cur_offset;

    /*[optional] store http data to storage*/
    CHTTP_STORE              *chttp_store;

    /*statistics*/
    CHTTP_STAT                chttp_stat;/*mount point*/

    /*beg: for ssl only*/
    UINT32                    ssl_status;           /*ONGOING or IS_DONE*/
    CSSL_NODE                *cssl_node;            /* for ssl */
    CSTRING                  *ca_file;              /* for ssl */
    CSTRING                  *client_cert_file;     /* for ssl */
    CSTRING                  *client_privkey_file;  /* for ssl */
    /*end: for ssl only*/
}CHTTP_NODE;

#define CHTTP_NODE_IS_ERROR(chttp_node)                    ((chttp_node)->is_error)
#define CHTTP_NODE_COUNTER(chttp_node)                     ((chttp_node)->counter)

#define CHTTP_NODE_PARSED(chttp_node)                      ((chttp_node)->parsed)

#define CHTTP_NODE_CSRV(chttp_node)                        ((chttp_node)->csrv)

#define CHTTP_NODE_CROUTINE_NODE(chttp_node)               ((chttp_node)->croutine_node)
#define CHTTP_NODE_CROUTINE_COND(chttp_node)               ((chttp_node)->croutine_cond)

#define CHTTP_NODE_TYPE(chttp_node)                        ((chttp_node)->http_type)
#define CHTTP_NODE_STATUS_CODE(chttp_node)                 ((chttp_node)->status_code)

#define CHTTP_NODE_PARSER(chttp_node)                      (&((chttp_node)->http_parser))
#define CHTTP_NODE_SETTING(chttp_node)                     (&((chttp_node)->http_parser_settings))

#define CHTTP_NODE_PARSING_HEADER_KV(chttp_node)           ((chttp_node)->http_parsing_header_kv)

#define CHTTP_NODE_PARSE_ON_MESSAGE_BEGIN_CB(chttp_node)       (&((chttp_node)->parse_on_message_begin_cb))
#define CHTTP_NODE_PARSE_ON_HEADERS_COMPLETE_CB(chttp_node)    (&((chttp_node)->parse_on_headers_complete_cb))
#define CHTTP_NODE_PARSE_ON_BODY_CB(chttp_node)                (&((chttp_node)->parse_on_body_cb))
#define CHTTP_NODE_PARSE_ON_MESSAGE_COMPLETE_CB(chttp_node)    (&((chttp_node)->parse_on_message_complete_cb))

#define CHTTP_NODE_IN_BUF(chttp_node)                      (&((chttp_node)->i_buf))
#define CHTTP_NODE_SEND_BUF(chttp_node)                    (&((chttp_node)->send_buf))
#define CHTTP_NODE_RECV_BUF(chttp_node)                    (&((chttp_node)->recv_buf))

#define CHTTP_NODE_CSOCKET_CNODE(chttp_node)               ((chttp_node)->csocket_cnode)
#define CHTTP_NODE_CQUEUE_DATA(chttp_node)                 ((chttp_node)->cqueue_data)
#define CHTTP_NODE_URL(chttp_node)                         (&((chttp_node)->url))
#define CHTTP_NODE_HOST(chttp_node)                        (&((chttp_node)->host))
#define CHTTP_NODE_URI(chttp_node)                         (&((chttp_node)->uri))
#define CHTTP_NODE_EXPIRES(chttp_node)                     (&((chttp_node)->expires))
#define CHTTP_NODE_ARGS(chttp_node)                        (&((chttp_node)->args))
#define CHTTP_NODE_ARG_KVS(chttp_node)                     (&((chttp_node)->arg_kvs))
#define CHTTP_NODE_HEADER_IN_KVS(chttp_node)               (&((chttp_node)->header_in_kvs))
#define CHTTP_NODE_HEADER_OUT_KVS(chttp_node)              (&((chttp_node)->header_out_kvs))

#define CHTTP_NODE_HEADER_MODIFIED_KVS(chttp_node)         (&((chttp_node)->header_renew_kvs))
#define CHTTP_NODE_HEADER_MODIFIED_FLAG(chttp_node)        ((chttp_node)->header_renew_flag)
#define CHTTP_NODE_HEADER_EXPIRED_FLAG(chttp_node)         ((chttp_node)->header_expired_flag)

#define CHTTP_NODE_START_TMV(chttp_node)                   (&((chttp_node)->s_tmv))
#define CHTTP_NODE_CONTENT_CBYTES(chttp_node)              (&((chttp_node)->content_cbytes))
#define CHTTP_NODE_CONTENT_LENGTH(chttp_node)              ((chttp_node)->content_length)
#define CHTTP_NODE_BODY_PARSED_LEN(chttp_node)             ((chttp_node)->body_parsed_len)
#define CHTTP_NODE_BODY_STORED_LEN(chttp_node)             ((chttp_node)->body_stored_len)
#define CHTTP_NODE_HEADER_PARSED_LEN(chttp_node)           ((chttp_node)->header_parsed_len)

#define CHTTP_NODE_RSP_STATUS(chttp_node)                  ((chttp_node)->http_rsp_status)
#define CHTTP_NODE_HEADER_COMPLETE(chttp_node)             ((chttp_node)->header_complete)
#define CHTTP_NODE_HTTP_REQ_IS_HEAD(chttp_node)            ((chttp_node)->http_req_is_head)
#define CHTTP_NODE_KEEPALIVE(chttp_node)                   ((chttp_node)->keepalive)
#define CHTTP_NODE_RECV_COMPLETE(chttp_node)               ((chttp_node)->recv_complete)
#define CHTTP_NODE_SEND_COMPLETE(chttp_node)               ((chttp_node)->send_complete)
#define CHTTP_NODE_COROUTINE_RESTORE(chttp_node)           ((chttp_node)->coroutine_restore)
#define CHTTP_NODE_IS_CHUNKED(chttp_node)                  ((chttp_node)->is_chunked)

#define CHTTP_NODE_STORE_PATH(chttp_node)                  ((chttp_node)->store_path)

#define CHTTP_NODE_SEND_DATA_MORE_FUNC(chttp_node)         ((chttp_node)->send_data_more_func)
#define CHTTP_NODE_SEND_DATA_MORE_AUX(chttp_node)          ((chttp_node)->send_data_more_aux)
#define CHTTP_NODE_SEND_DATA_BUFF(chttp_node)              ((chttp_node)->data_buff)
#define CHTTP_NODE_SEND_DATA_TOTAL_LEN(chttp_node)         ((chttp_node)->data_total_len)
#define CHTTP_NODE_SEND_DATA_SENT_LEN(chttp_node)          ((chttp_node)->data_sent_len)

#define CHTTP_NODE_SEND_BLOCK_FD(chttp_node)               ((chttp_node)->block_fd)
#define CHTTP_NODE_SEND_BLOCK_SIZE(chttp_node)             ((chttp_node)->block_size)
#define CHTTP_NODE_SEND_BLOCK_POS(chttp_node)              ((chttp_node)->block_pos)

#define CHTTP_NODE_STORE_BEG_OFFSET(chttp_node)            ((chttp_node)->store_beg_offset)
#define CHTTP_NODE_STORE_END_OFFSET(chttp_node)            ((chttp_node)->store_end_offset)
#define CHTTP_NODE_STORE_CUR_OFFSET(chttp_node)            ((chttp_node)->store_cur_offset)
#define CHTTP_NODE_STORE_SIZE(chttp_node)                  (CHTTP_NODE_STORE_END_OFFSET(chttp_node) - CHTTP_NODE_STORE_BEG_OFFSET(chttp_node))

#define CHTTP_NODE_STORE(chttp_node)                       ((chttp_node)->chttp_store)

#define CHTTP_NODE_STAT(chttp_node)                        (&((chttp_node)->chttp_stat))

#define CHTTP_NODE_SSL_STATUS(chttp_node)                  ((chttp_node)->ssl_status)
#define CHTTP_NODE_CSSL_NODE(chttp_node)                   ((chttp_node)->cssl_node)
#define CHTTP_NODE_CA_FILE(chttp_node)                     ((chttp_node)->ca_file)
#define CHTTP_NODE_CLIENT_CERT_FILE(chttp_node)            ((chttp_node)->client_cert_file)
#define CHTTP_NODE_CLIENT_PRIVKEY_FILE(chttp_node)         ((chttp_node)->client_privkey_file)

/*use when ms orig procedure*/
typedef EC_BOOL (*CHTTP_NODE_IMPORT_HEADER_CALLBACK)(const UINT32, const CHTTP_NODE *);
typedef EC_BOOL (*CHTTP_NODE_SEND_HEADER_CALLBACK)(const UINT32);
typedef EC_BOOL (*CHTTP_NODE_SEND_BODY_CALLBACK)(const UINT32, const UINT32, const UINT8 *, const UINT32);


/* --- shortcut ---*/
#define CHTTP_NODE_S_SEND_LEN(chttp_node)                  (CHTTP_STAT_S_SEND_LEN(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_S_RECV_LEN(chttp_node)                  (CHTTP_STAT_S_RECV_LEN(CHTTP_NODE_STAT(chttp_node)))

#define CHTTP_NODE_S_MSEC(chttp_node)                      (CHTTP_STAT_BASIC_S_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_R_MSEC(chttp_node)                      (CHTTP_STAT_BASIC_R_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_L_MSEC(chttp_node)                      (CHTTP_STAT_BASIC_L_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_H_MSEC(chttp_node)                      (CHTTP_STAT_BASIC_H_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_D_MSEC(chttp_node)                      (CHTTP_STAT_BASIC_D_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_E_MSEC(chttp_node)                      (CHTTP_STAT_BASIC_E_MSEC(CHTTP_NODE_STAT(chttp_node)))

#define CHTTP_NODE_STAT_STR(chttp_node)                    (CHTTP_STAT_STAT_STR(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_DESC_STR(chttp_node)                    (CHTTP_STAT_DESC_STR(CHTTP_NODE_STAT(chttp_node)))

#define CHTTP_NODE_STAT_STR_INIT(chttp_node)               (CHTTP_STAT_STAT_STR_INIT(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_STAT_STR_CLEAN(chttp_node)              (CHTTP_STAT_STAT_STR_CLEAN(CHTTP_NODE_STAT(chttp_node)))

#define CHTTP_NODE_DESC_STR_INIT(chttp_node)               (CHTTP_STAT_DESC_STR_INIT(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_DESC_STR_CLEAN(chttp_node)              (CHTTP_STAT_DESC_STR_CLEAN(CHTTP_NODE_STAT(chttp_node)))

/*more statistics*/
#define CHTTP_NODE_REQ_S_MSEC(chttp_node)                  (CHTTP_STAT_REQ_S_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_REQ_E_MSEC(chttp_node)                  (CHTTP_STAT_REQ_E_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_REQ_C_MSEC(chttp_node)                  (CHTTP_STAT_REQ_C_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_RSP_S_MSEC(chttp_node)                  (CHTTP_STAT_RSP_S_MSEC(CHTTP_NODE_STAT(chttp_node)))
#define CHTTP_NODE_RSP_E_MSEC(chttp_node)                  (CHTTP_STAT_RSP_E_MSEC(CHTTP_NODE_STAT(chttp_node)))

/*----------------------------- CHTTP_NODE interface for statistics -----------------------------*/
#define CHTTP_NODE_S_SEND_LEN_INC(chttp_node, num) do{                                       \
    CHTTP_NODE_S_SEND_LEN(chttp_node) += (num);                                              \
}while(0)

#define CHTTP_NODE_S_RECV_LEN_INC(chttp_node, num) do{                                       \
    CHTTP_NODE_S_RECV_LEN(chttp_node) += (num);                                              \
}while(0)

#define CHTTP_NODE_LOG_STAT_WHEN_DONE(chttp_node, stat_format...) do{                        \
    snprintf((char *)CHTTP_NODE_STAT_STR(chttp_node), CHTTP_STAT_STR_MAX_SIZE, stat_format); \
}while(0)

#define CHTTP_NODE_LOG_INFO_WHEN_DONE(chttp_node, info_format...) do{                        \
    snprintf((char *)CHTTP_NODE_DESC_STR(chttp_node), CHTTP_DESC_STR_MAX_SIZE, info_format); \
}while(0)

#define CHTTP_NODE_LOG_TIME_WHEN_START(chttp_node) do{                                       \
    CHTTP_NODE_S_MSEC(chttp_node) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_NODE_LOG_TIME_WHEN_RCVD(chttp_node) do{                                        \
    CHTTP_NODE_R_MSEC(chttp_node) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_NODE_LOG_TIME_WHEN_LOADED(chttp_node) do{                                      \
    CHTTP_NODE_L_MSEC(chttp_node) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_NODE_LOG_TIME_WHEN_HANDLE(chttp_node) do{                                      \
    CHTTP_NODE_H_MSEC(chttp_node) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_NODE_LOG_TIME_WHEN_DONE(chttp_node) do{                                        \
    CHTTP_NODE_D_MSEC(chttp_node) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_NODE_LOG_TIME_WHEN_END(chttp_node) do{                                         \
    CHTTP_NODE_E_MSEC(chttp_node) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_NODE_LOG_PRINT(chttp_node) do{                                                 \
    uint32_t s2r_elapsed_msec;                                                               \
    uint32_t s2l_elapsed_msec;                                                               \
    uint32_t s2h_elapsed_msec;                                                               \
    uint32_t s2d_elapsed_msec;                                                               \
    uint32_t s2e_elapsed_msec;                                                               \
    s2r_elapsed_msec = (uint32_t)(CHTTP_NODE_R_MSEC(chttp_node) - CHTTP_NODE_S_MSEC(chttp_node)); \
    s2l_elapsed_msec = (uint32_t)(CHTTP_NODE_L_MSEC(chttp_node) - CHTTP_NODE_S_MSEC(chttp_node)); \
    s2h_elapsed_msec = (uint32_t)(CHTTP_NODE_H_MSEC(chttp_node) - CHTTP_NODE_S_MSEC(chttp_node)); \
    s2d_elapsed_msec = (uint32_t)(CHTTP_NODE_D_MSEC(chttp_node) - CHTTP_NODE_S_MSEC(chttp_node)); \
    s2e_elapsed_msec = (uint32_t)(CHTTP_NODE_E_MSEC(chttp_node) - CHTTP_NODE_S_MSEC(chttp_node)); \
    sys_log(LOGUSER08,                                                                       \
            "%s S2R:%u S2L:%u S2H:%u S2D:%u S2E:%u %s\n",                                    \
            (char *)CHTTP_NODE_STAT_STR(chttp_node),                                         \
            s2r_elapsed_msec,                                                                \
            s2l_elapsed_msec,                                                                \
            s2h_elapsed_msec,                                                                \
            s2d_elapsed_msec,                                                                \
            s2e_elapsed_msec,                                                                \
            (char *)CHTTP_NODE_DESC_STR(chttp_node)                                          \
           );                                                                                \
}while(0)

#define CHTTP_NODE_LOG_REQ_S_TIME(chttp_node) do{                                           \
    CHTTP_NODE_REQ_S_MSEC(chttp_node) = c_get_cur_time_msec();                               \
}while(0)

#define CHTTP_NODE_LOG_REQ_E_TIME(chttp_node) do{                                           \
    CHTTP_NODE_REQ_E_MSEC(chttp_node) = c_get_cur_time_msec();                               \
}while(0)

#define CHTTP_NODE_LOG_REQ_C_TIME(chttp_node) do{                                           \
    CHTTP_NODE_REQ_C_MSEC(chttp_node) = c_get_cur_time_msec();                               \
}while(0)

#define CHTTP_NODE_LOG_RSP_S_TIME(chttp_node) do{                                           \
    CHTTP_NODE_RSP_S_MSEC(chttp_node) = c_get_cur_time_msec();                               \
}while(0)

#define CHTTP_NODE_LOG_RSP_E_TIME(chttp_node) do{                                           \
    CHTTP_NODE_RSP_E_MSEC(chttp_node) = c_get_cur_time_msec();                               \
}while(0)

/*----------------------------- CHTTP_STAT interface for merge statistics -----------------------------*/

#define CHTTP_STAT_LOG_MERGE_STAT_WHEN_DONE(chttp_stat, stat_format...) do{                        \
    snprintf((char *)CHTTP_STAT_STAT_STR(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, stat_format);       \
}while(0)

#define CHTTP_STAT_LOG_MERGE_INFO_WHEN_DONE(chttp_stat, info_format...) do{                        \
    snprintf((char *)CHTTP_STAT_DESC_STR(chttp_stat), CHTTP_DESC_STR_MAX_SIZE, info_format);       \
}while(0)

#define CHTTP_STAT_LOG_MERGE_TIME_WHEN_START(chttp_stat) do{                                       \
    CHTTP_STAT_MERGE_S_MSEC(chttp_stat) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_STAT_LOG_MERGE_TIME_WHEN_LOCKED(chttp_stat) do{                                      \
    CHTTP_STAT_MERGE_L_MSEC(chttp_stat) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_STAT_LOG_MERGE_TIME_WHEN_WAITED(chttp_stat) do{                                      \
    CHTTP_STAT_MERGE_W_MSEC(chttp_stat) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_STAT_LOG_MERGE_TIME_WHEN_ORIGED(chttp_stat) do{                                      \
    CHTTP_STAT_MERGE_O_MSEC(chttp_stat) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_STAT_LOG_MERGE_TIME_WHEN_CONDED(chttp_stat) do{                                      \
    CHTTP_STAT_MERGE_C_MSEC(chttp_stat) = c_get_cur_time_msec();                                   \
}while(0)

#define CHTTP_STAT_LOG_MERGE_TIME_WHEN_READ(chttp_stat) do{                                        \
    CHTTP_STAT_MERGE_R_MSEC(chttp_stat) = c_get_cur_time_msec();                                   \
}while(0)

/*for merge orig procedure owner*/
#define CHTTP_STAT_LOG_MERGE_YES_PRINT(chttp_stat) do{                                             \
    uint32_t s2l_elapsed_msec;                                                                     \
    uint32_t s2w_elapsed_msec;                                                                     \
    uint32_t s2o_elapsed_msec;                                                                     \
    uint32_t s2c_elapsed_msec;                                                                     \
    uint32_t s2r_elapsed_msec;                                                                     \
    s2l_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_L_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    s2w_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_W_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    s2o_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_O_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    s2c_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_C_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    s2r_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_R_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    sys_log(LOGUSER08,                                                                              \
            "%s S2L:%u S2W:%u S2O:%u S2C:%u S2R:%u %s\n",   \
            (char *)CHTTP_STAT_STAT_STR(chttp_stat),                                                \
            s2l_elapsed_msec,                                                                       \
            s2w_elapsed_msec,                                                                       \
            s2o_elapsed_msec,                                                                       \
            s2c_elapsed_msec,                                                                       \
            s2r_elapsed_msec,                                                                       \
            (char *)CHTTP_STAT_DESC_STR(chttp_stat)                                                 \
           );                                                                                       \
}while(0)

/*for merge orig procedure not owner*/
#define CHTTP_STAT_LOG_MERGE_NO_PRINT(chttp_stat) do{                                              \
    uint32_t s2l_elapsed_msec;                                                                     \
    uint32_t s2w_elapsed_msec;                                                                     \
    uint32_t s2c_elapsed_msec;                                                                     \
    uint32_t s2r_elapsed_msec;                                                                     \
    s2l_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_L_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    s2w_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_W_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    s2c_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_C_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    s2r_elapsed_msec = (uint32_t)(CHTTP_STAT_MERGE_R_MSEC(chttp_stat) - CHTTP_STAT_MERGE_S_MSEC(chttp_stat)); \
    sys_log(LOGUSER08,                                                                             \
            "%s S2L:%u S2W:%u - - S2C:%u S2R:%u %s\n",         \
            (char *)CHTTP_STAT_STAT_STR(chttp_stat),                                               \
            s2l_elapsed_msec,                                                                      \
            s2w_elapsed_msec,                                                                      \
            s2c_elapsed_msec,                                                                      \
            s2r_elapsed_msec,                                                                      \
            (char *)CHTTP_STAT_DESC_STR(chttp_stat)                                                \
           );                                                                                      \
}while(0)

/*----------------------------- CHTTP_STAT interface for merge statistics -----------------------------*/

#define CHTTP_STAT_LOG_HEADER_STAT_WHEN_DONE(chttp_stat, stat_format...) do{                       \
    snprintf((char *)CHTTP_STAT_STAT_STR(chttp_stat), CHTTP_STAT_STR_MAX_SIZE, stat_format);       \
}while(0)

#define CHTTP_STAT_LOG_HEADER_INFO_WHEN_DONE(chttp_stat, info_format...) do{                       \
    snprintf((char *)CHTTP_STAT_DESC_STR(chttp_stat), CHTTP_DESC_STR_MAX_SIZE, info_format);       \
}while(0)

#define CHTTP_STAT_LOG_HEADER_TIME_WHEN_START(chttp_stat) do{                                      \
    CHTTP_STAT_HEADER_S_MSEC(chttp_stat) = c_get_cur_time_msec();                                  \
}while(0)

#define CHTTP_STAT_LOG_HEADER_TIME_WHEN_WAITED(chttp_stat) do{                                     \
    CHTTP_STAT_HEADER_W_MSEC(chttp_stat) = c_get_cur_time_msec();                                  \
}while(0)

#define CHTTP_STAT_LOG_HEADER_TIME_WHEN_ORIGED(chttp_stat) do{                                     \
    CHTTP_STAT_HEADER_O_MSEC(chttp_stat) = c_get_cur_time_msec();                                  \
}while(0)

#define CHTTP_STAT_LOG_HEADER_TIME_WHEN_CONDED(chttp_stat) do{                                     \
    CHTTP_STAT_HEADER_C_MSEC(chttp_stat) = c_get_cur_time_msec();                                  \
}while(0)

#define CHTTP_STAT_LOG_HEADER_TIME_WHEN_READ(chttp_stat) do{                                       \
    CHTTP_STAT_HEADER_R_MSEC(chttp_stat) = c_get_cur_time_msec();                                  \
}while(0)

/*for header orig procedure owner*/
#define CHTTP_STAT_LOG_HEADER_YES_PRINT(chttp_stat) do{                                            \
    uint32_t s2w_elapsed_msec;                                                                     \
    uint32_t s2o_elapsed_msec;                                                                     \
    uint32_t s2c_elapsed_msec;                                                                     \
    uint32_t s2r_elapsed_msec;                                                                     \
    s2w_elapsed_msec = (uint32_t)(CHTTP_STAT_HEADER_W_MSEC(chttp_stat) - CHTTP_STAT_HEADER_S_MSEC(chttp_stat)); \
    s2o_elapsed_msec = (uint32_t)(CHTTP_STAT_HEADER_O_MSEC(chttp_stat) - CHTTP_STAT_HEADER_S_MSEC(chttp_stat)); \
    s2c_elapsed_msec = (uint32_t)(CHTTP_STAT_HEADER_C_MSEC(chttp_stat) - CHTTP_STAT_HEADER_S_MSEC(chttp_stat)); \
    s2r_elapsed_msec = (uint32_t)(CHTTP_STAT_HEADER_R_MSEC(chttp_stat) - CHTTP_STAT_HEADER_S_MSEC(chttp_stat)); \
    sys_log(LOGUSER08,                                                                             \
            "%s S2W:%u S2O:%u S2C:%u S2R:u %s\n",               \
            (char *)CHTTP_STAT_STAT_STR(chttp_stat),                                               \
            s2w_elapsed_msec,                                                                      \
            s2o_elapsed_msec,                                                                      \
            s2c_elapsed_msec,                                                                      \
            s2r_elapsed_msec,                                                                      \
            (char *)CHTTP_STAT_DESC_STR(chttp_stat)                                                \
           );                                                                                      \
}while(0)

/*----------------------------- CHTTP_STAT interface for orig statistics -----------------------------*/

#define CHTTP_STAT_LOG_ORIG_TIME_WHEN_START(s_msec) do{                                            \
    (s_msec) = c_get_cur_time_msec();                                                              \
}while(0)

#define CHTTP_STAT_LOG_ORIG_TIME_WHEN_END(e_msec) do{                                              \
    (e_msec) = c_get_cur_time_msec();                                                              \
}while(0)

#define CHTTP_STAT_LOG_ORIG_TIME_ELAPSED_MSEC(e_msec, s_msec)                                      \
    ((uint32_t)((e_msec) - (s_msec)))

typedef EC_BOOL (*CHTTP_NODE_COMMIT_REQUEST)(CHTTP_NODE *);
typedef EC_BOOL (*CHTTP_REQ_CONN_FAIL_CALLBACK)(void *);

typedef struct
{
    /*http server*/
    UINT32              ipaddr;
    UINT32              port;

    CSTRING             domain; /* domain optional. for dns cache only */
                                /* if domain is set, and http(s) connect failed, */
                                /* dns cache would kick off the ip. */
                                /* actually we can ignore such handling */
                                /* and ask orig detector takes responsibility of ip working*/

    CSTRING             device_name;    /*carry on for http stat*/
    CSTRING             trace_id;       /*carry on for http stat*/

    EC_BOOL             ssl_flag;

    CSTRING             method;
    CSTRING             uri;
    CSTRKV_MGR          param;
    CSTRKV_MGR          header;

    CSTRING             ca_file;                /*ca file name. used for https*/
    CSTRING             client_cert_file;       /*client certificate file file name. used for https and server check client validity*/
    CSTRING             client_privkey_file;    /*client private key file name. used for https and server check client validity*/

    CBYTES              body;

    /*extension for to mark ngx upstream peer down when connection failure happen*/
    CHTTP_REQ_CONN_FAIL_CALLBACK  conn_fail_callback;
    void                         *conn_fail_callback_args;
}CHTTP_REQ;

#define CHTTP_REQ_IPADDR(chttp_req)                 ((chttp_req)->ipaddr)
#define CHTTP_REQ_IPADDR_STR(chttp_req)             (c_word_to_ipv4(CHTTP_REQ_IPADDR(chttp_req)))
#define CHTTP_REQ_PORT(chttp_req)                   ((chttp_req)->port)
#define CHTTP_REQ_DOMAIN(chttp_req)                 (&((chttp_req)->domain))
#define CHTTP_REQ_DOMAIN_STR(chttp_req)             (cstring_get_str(CHTTP_REQ_DOMAIN(chttp_req)))
#define CHTTP_REQ_DEVICE_NAME(chttp_req)            (&((chttp_req)->device_name))
#define CHTTP_REQ_DEVICE_NAME_STR(chttp_req)        (cstring_get_str(CHTTP_REQ_DEVICE_NAME(chttp_req)))
#define CHTTP_REQ_TRACE_ID(chttp_req)               (&((chttp_req)->trace_id))
#define CHTTP_REQ_TRACE_ID_STR(chttp_req)           (cstring_get_str(CHTTP_REQ_TRACE_ID(chttp_req)))
#define CHTTP_REQ_SSL_FLAG(chttp_req)               ((chttp_req)->ssl_flag)
#define CHTTP_REQ_METHOD(chttp_req)                 (&((chttp_req)->method))
#define CHTTP_REQ_URI(chttp_req)                    (&((chttp_req)->uri))
#define CHTTP_REQ_PARAM(chttp_req)                  (&((chttp_req)->param))
#define CHTTP_REQ_HEADER(chttp_req)                 (&((chttp_req)->header))
#define CHTTP_REQ_CA_FILE(chttp_req)                (&((chttp_req)->ca_file))
#define CHTTP_REQ_CLIENT_CERT_FILE(chttp_req)       (&((chttp_req)->client_cert_file))
#define CHTTP_REQ_CLIENT_PRIVKEY_FILE(chttp_req)    (&((chttp_req)->client_privkey_file))
#define CHTTP_REQ_BODY(chttp_req)                   (&((chttp_req)->body))

#define CHTTP_REQ_CONN_FAIL_CALLBACK_FUNC(chttp_req)      ((chttp_req)->conn_fail_callback)
#define CHTTP_REQ_CONN_FAIL_CALLBACK_ARGS(chttp_req)      ((chttp_req)->conn_fail_callback_args)

typedef struct
{
    uint32_t    status;
    uint32_t    logged:1;
    uint32_t    rsvd:31;
    CSTRKV_MGR  header;
    CBYTES      body;

    /*client socket ipaddr and port*/
    UINT32      client_ipaddr;
    UINT32      client_port;
}CHTTP_RSP;

#define CHTTP_RSP_STATUS(chttp_rsp)                 ((chttp_rsp)->status)
#define CHTTP_RSP_LOGGED(chttp_rsp)                 ((chttp_rsp)->logged)
#define CHTTP_RSP_HEADER(chttp_rsp)                 (&((chttp_rsp)->header))
#define CHTTP_RSP_BODY(chttp_rsp)                   (&((chttp_rsp)->body))
#define CHTTP_RSP_CLIENT_IPADDR(chttp_rsp)          ((chttp_rsp)->client_ipaddr)
#define CHTTP_RSP_CLIENT_PORT(chttp_rsp)            ((chttp_rsp)->client_port)

/*restful api */
typedef struct
{
    const char    *name;
    uint32_t       len; /*name length*/
    uint32_t       rsvd;

    EC_BOOL (*commit)(CHTTP_NODE *); /*commit request handler*/
}CHTTP_REST;

#define CHTTP_REST_NAME(chttp_rest)       ((chttp_rest)->name)
#define CHTTP_REST_LEN(chttp_rest)        ((chttp_rest)->len)
#define CHTTP_REST_COMMIT(chttp_rest)     ((chttp_rest)->commit)

typedef struct
{
    const char      *name;           /*api op name string*/
    uint32_t         len;            /*api op name length*/
    uint32_t         method;
    EC_BOOL (*commit)(CHTTP_NODE *); /*api handler*/
}CHTTP_API;

#define CHTTP_API_NAME(chttp_api)         ((chttp_api)->name)
#define CHTTP_API_LEN(chttp_api)          ((chttp_api)->len)
#define CHTTP_API_METHOD(chttp_api)       ((chttp_api)->method)
#define CHTTP_API_COMMIT(chttp_api)       ((chttp_api)->commit)

#define CHTTP_STATUS_NONE                          ((uint32_t)   0)
#define CHTTP_CONTINUE                             ((uint32_t) 100)
#define CHTTP_SWITCHING_PROTOCOLS                  ((uint32_t) 101)
#define CHTTP_PROCESSING                           ((uint32_t) 102)   /* RFC2518 section 10.1 */
#define CHTTP_OK                                   ((uint32_t) 200)
#define CHTTP_CREATED                              ((uint32_t) 201)
#define CHTTP_ACCEPTED                             ((uint32_t) 202)
#define CHTTP_NON_AUTHORITATIVE_INFORMATION        ((uint32_t) 203)
#define CHTTP_NO_CONTENT                           ((uint32_t) 204)
#define CHTTP_RESET_CONTENT                        ((uint32_t) 205)
#define CHTTP_PARTIAL_CONTENT                      ((uint32_t) 206)
#define CHTTP_MULTI_STATUS                         ((uint32_t) 207)    /* RFC2518 section 10.2 */
#define CHTTP_MULTIPLE_CHOICES                     ((uint32_t) 300)
#define CHTTP_MOVED_PERMANENTLY                    ((uint32_t) 301)
#define CHTTP_MOVED_TEMPORARILY                    ((uint32_t) 302)
#define CHTTP_SEE_OTHER                            ((uint32_t) 303)
#define CHTTP_NOT_MODIFIED                         ((uint32_t) 304)
#define CHTTP_USE_PROXY                            ((uint32_t) 305)
#define CHTTP_TEMPORARY_REDIRECT                   ((uint32_t) 307)
#define CHTTP_BAD_REQUEST                          ((uint32_t) 400)
#define CHTTP_UNAUTHORIZED                         ((uint32_t) 401)
#define CHTTP_PAYMENT_REQUIRED                     ((uint32_t) 402)
#define CHTTP_FORBIDDEN                            ((uint32_t) 403)
#define CHTTP_NOT_FOUND                            ((uint32_t) 404)
#define CHTTP_METHOD_NOT_ALLOWED                   ((uint32_t) 405)
#define CHTTP_NOT_ACCEPTABLE                       ((uint32_t) 406)
#define CHTTP_PROXY_AUTHENTICATION_REQUIRED        ((uint32_t) 407)
#define CHTTP_REQUEST_TIMEOUT                      ((uint32_t) 408)
#define CHTTP_CONFLICT                             ((uint32_t) 409)
#define CHTTP_GONE                                 ((uint32_t) 410)
#define CHTTP_LENGTH_REQUIRED                      ((uint32_t) 411)
#define CHTTP_PRECONDITION_FAILED                  ((uint32_t) 412)
#define CHTTP_REQUEST_ENTITY_TOO_LARGE             ((uint32_t) 413)
#define CHTTP_REQUEST_URI_TOO_LONG                 ((uint32_t) 414)
#define CHTTP_UNSUPPORTED_MEDIA_TYPE               ((uint32_t) 415)
#define CHTTP_REQUESTEDR_RANGE_NOT_SATISFIABLE     ((uint32_t) 416)
#define CHTTP_EXPECTATION_FAILED                   ((uint32_t) 417)
#define CHTTP_UNPROCESSABLE_ENTITY                 ((uint32_t) 422)    /* RFC2518 section 10.3 */
#define CHTTP_LOCKED                               ((uint32_t) 423)    /* RFC2518 section 10.4 */
#define CHTTP_FAILED_DEPENDENCY                    ((uint32_t) 424)    /* RFC2518 section 10.5 */

#define CHTTP_INTERNAL_SERVER_ERROR                ((uint32_t) 500)
#define CHTTP_NOT_IMPLEMENTED                      ((uint32_t) 501)
#define CHTTP_BAD_GATEWAY                          ((uint32_t) 502)
#define CHTTP_SERVICE_UNAVAILABLE                  ((uint32_t) 503)
#define CHTTP_GATEWAY_TIMEOUT                      ((uint32_t) 504)
#define CHTTP_VERSION_NOT_SUPPORTED                ((uint32_t) 505)
#define CHTTP_INSUFFICIENT_STORAGE                 ((uint32_t) 507)   /* RFC2518 section 10.6 */
#define CHTTP_INVALID_HEADER                       ((uint32_t) 600)   /* Squid header parsing error */
#define CHTTP_HEADER_TOO_LARGE                     ((uint32_t) 601)   /* Header too large to process */

#define CHTTP_METHOD_UNKNOWN                       ((uint32_t)0xFFFF)
#define CHTTP_METHOD_GET                           ((uint32_t)0x0002)
#define CHTTP_METHOD_HEAD                          ((uint32_t)0x0004)
#define CHTTP_METHOD_POST                          ((uint32_t)0x0008)
#define CHTTP_METHOD_PUT                           ((uint32_t)0x0010)
#define CHTTP_METHOD_DELETE                        ((uint32_t)0x0020)
#define CHTTP_METHOD_MKCOL                         ((uint32_t)0x0040)
#define CHTTP_METHOD_COPY                          ((uint32_t)0x0080)
#define CHTTP_METHOD_MOVE                          ((uint32_t)0x0100)
#define CHTTP_METHOD_OPTIONS                       ((uint32_t)0x0200)
#define CHTTP_METHOD_PROPFIND                      ((uint32_t)0x0400)
#define CHTTP_METHOD_PROPPATCH                     ((uint32_t)0x0800)
#define CHTTP_METHOD_LOCK                          ((uint32_t)0x1000)
#define CHTTP_METHOD_UNLOCK                        ((uint32_t)0x2000)
#define CHTTP_METHOD_PATCH                         ((uint32_t)0x4000)
#define CHTTP_METHOD_TRACE                         ((uint32_t)0x8000)
#define CHTTP_METHOD_PURGE                         ((uint32_t)0x0001)


#endif /*_CHTTP_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

