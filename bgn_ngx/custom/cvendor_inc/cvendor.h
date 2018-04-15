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

#if (SWITCH_ON == NGX_BGN_SWITCH)

#ifndef _CVENDOR_H
#define _CVENDOR_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "csocket.h"
#include "mod.inc"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"
#include "crange.h"

#define CVENDOR_MODULE_NAME           ("cvendor")

#define CVENDOR_ERR_SEG_NO            ((UINT32)~0)

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    UINT32               cache_seg_max_num;
    UINT32               cache_seg_size;
    CSTRING              cache_path;
    const char          *cache_status;  /*TCP_HIT, TCP_MISS, TCP_REFRESH_HIT, TCP_REFRESH_MISS*/

    ngx_http_request_t  *ngx_http_req;
    CNGX_OPTION          cngx_option;
    
    /*--- parse from cngx http request ---*/
    uint32_t             cngx_debug_switch_on_flag          :1; /*if debug mode indicated in cngx http req*/
    uint32_t             cngx_range_exist_flag              :1; /*exist field 'Range' in request header*/
    uint32_t             cngx_range_multiple_flag           :1; /*multiple ranges in request header*/
    uint32_t             cngx_range_adjusted_flag           :1; /*if range is adjust or split*/
    uint32_t             cngx_range_filtered_flag           :1; /*if range is adjust or split*/
    uint32_t             cngx_range_start_zero_endless_flag :1; /*range is "0-"*/
    uint32_t             cngx_use_gzip_flag                 :1; /*exist header 'Accept-Encoding':'gzip'*/
    uint32_t             cache_use_gzip_flag                :1; /*use gzip path for cache reading/writing*/
    uint32_t             cache_expired_flag                 :1; /*if cache is expired*/
    uint32_t             content_length_exist_flag          :1; /*exist field 'Content-Length' in response header*/
    uint32_t             orig_chunk_flag                    :1; /*orig is chunk*/
    uint32_t             orig_force_flag                    :1; /*force to orig*/
    uint32_t             orig_no_cache_flag                 :1; /*orig indicate no-cache or 404 etc*/
    uint32_t             rsvd01                             :19;
    uint32_t             rsvd02;

    CRANGE_MGR           cngx_range_mgr; 

    UINT32               content_length;

    CSTRING              header_expires;   

    /*---- debug ----*/
    UINT32               depth;                   /*recursive depth*/

    CHTTP_REQ           *chttp_req;
    CHTTP_RSP           *chttp_rsp;
    CHTTP_STORE         *chttp_store;
    CHTTP_STAT          *chttp_stat;

    UINT32               absent_seg_no;
    UINT32               sent_body_size;

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/ 
}CVENDOR_MD;

#define CVENDOR_MD_TERMINATE_FLAG(cvendor_md)                     ((cvendor_md)->terminate_flag)

#define CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md)                  ((cvendor_md)->cache_seg_max_num)
#define CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)                     ((cvendor_md)->cache_seg_size)
#define CVENDOR_MD_CACHE_PATH(cvendor_md)                         (&((cvendor_md)->cache_path))
#define CVENDOR_MD_CACHE_STATUS(cvendor_md)                       ((cvendor_md)->cache_status)

#define CVENDOR_MD_NGX_HTTP_REQ(cvendor_md)                       ((cvendor_md)->ngx_http_req)
#define CVENDOR_MD_CNGX_OPTION(cvendor_md)                        (&((cvendor_md)->cngx_option))

#define CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md)          ((cvendor_md)->cngx_debug_switch_on_flag)
#define CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)              ((cvendor_md)->cngx_range_exist_flag)
#define CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG(cvendor_md)           ((cvendor_md)->cngx_range_multiple_flag)
#define CVENDOR_MD_CNGX_RANGE_ADJUSTED_FLAG(cvendor_md)           ((cvendor_md)->cngx_range_adjusted_flag)
#define CVENDOR_MD_CNGX_RANGE_FILTERED_FLAG(cvendor_md)           ((cvendor_md)->cngx_range_filtered_flag)
#define CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md) ((cvendor_md)->cngx_range_start_zero_endless_flag)
#define CVENDOR_MD_CNGX_USE_GZIP_FLAG(cvendor_md)                 ((cvendor_md)->cngx_use_gzip_flag)
#define CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md)                ((cvendor_md)->cache_use_gzip_flag)
#define CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md)                 ((cvendor_md)->cache_expired_flag)
#define CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md)          ((cvendor_md)->content_length_exist_flag) 
#define CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)                    ((cvendor_md)->orig_chunk_flag) 
#define CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md)                    ((cvendor_md)->orig_force_flag)
#define CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md)                 ((cvendor_md)->orig_no_cache_flag)

#define CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)                     (&((cvendor_md)->cngx_range_mgr)) 

#define CVENDOR_MD_CONTENT_LENGTH(cvendor_md)                     ((cvendor_md)->content_length)

#define CVENDOR_MD_HEADER_EXPIRES(cvendor_md)                     (&((cvendor_md)->header_expires))
#define CVENDOR_MD_DEPTH(cvendor_md)                              ((cvendor_md)->depth)

#define CVENDOR_MD_CHTTP_REQ(cvendor_md)                          ((cvendor_md)->chttp_req)
#define CVENDOR_MD_CHTTP_RSP(cvendor_md)                          ((cvendor_md)->chttp_rsp)
#define CVENDOR_MD_CHTTP_STORE(cvendor_md)                        ((cvendor_md)->chttp_store)
#define CVENDOR_MD_CHTTP_STAT(cvendor_md)                         ((cvendor_md)->chttp_stat)
#define CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)                      ((cvendor_md)->absent_seg_no)
#define CVENDOR_MD_SENT_BODY_SIZE(cvendor_md)                     ((cvendor_md)->sent_body_size)

#define CVENDOR_MD_NGX_LOC(cvendor_md)                            ((cvendor_md)->ngx_loc)
#define CVENDOR_MD_NGX_RC(cvendor_md)                             ((cvendor_md)->ngx_rc)

/**
*   for test only
*
*   to query the status of CVENDOR Module
*
**/
void cvendor_print_module_status(const UINT32 cvendor_md_id, LOG *log);

/**
*
* register CVENDOR module
*
**/
EC_BOOL cvendor_reg();

/**
*
* unregister CVENDOR module
*
**/
EC_BOOL cvendor_unreg();

/**
*
* start CVENDOR module
*
**/
UINT32 cvendor_start(ngx_http_request_t *r);

/**
*
* end CVENDOR module
*
**/
void cvendor_end(const UINT32 cvendor_md_id);

EC_BOOL cvendor_get_ngx_rc(const UINT32 cvendor_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cvendor_set_ngx_rc(const UINT32 cvendor_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cvendor_override_ngx_rc(const UINT32 cvendor_md_id, const ngx_int_t rc, const UINT32 location);

EC_BOOL cvendor_get_cache_seg_uri(const UINT32 cvendor_md_id, const UINT32 seg_no, CSTRING *cache_uri);

EC_BOOL cvendor_get_cache_seg(const UINT32 cvendor_md_id, const UINT32 seg_no, CBYTES *seg_cbytes);

EC_BOOL cvendor_get_cache_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *range_seg, CBYTES *seg_cbytes);

EC_BOOL cvendor_get_req_range_segs(const UINT32 cvendor_md_id, const UINT32 seg_size);

EC_BOOL cvendor_get_rsp_length_segs(const UINT32 cvendor_md_id, const UINT32 seg_size);

EC_BOOL cvendor_filter_rsp_range(const UINT32 cvendor_md_id);

EC_BOOL cvendor_filter_header_in_common(const UINT32 cvendor_md_id);

#if 0
EC_BOOL cvendor_filter_header_out_debug(const UINT32 cvendor_md_id);
#endif
EC_BOOL cvendor_filter_header_out_common(const UINT32 cvendor_md_id, const char *procedure);

EC_BOOL cvendor_filter_header_out_cache_control(const UINT32 cvendor_md_id);

EC_BOOL cvendor_filter_header_out_single_range(const UINT32 cvendor_md_id);

EC_BOOL cvendor_filter_header_out_multi_range(const UINT32 cvendor_md_id);

EC_BOOL cvendor_filter_header_out_range(const UINT32 cvendor_md_id);

EC_BOOL cvendor_renew_header_cache(const UINT32 cvendor_md_id, const char *k, const char *v);

EC_BOOL cvendor_content_handler(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_direct_header_in_filter_port(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_direct_header_in_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_direct_header_out_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_direct_body_out_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_direct_send_request(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_direct_send_response(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_direct_procedure(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_chunk_header_out_length_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_chunk_header_out_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_chunk_body_out_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_chunk_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg);

EC_BOOL cvendor_content_chunk_send_end(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_chunk_send_response(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_chunk_procedure(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_header_in_filter_port(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_header_in_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_header_out_range_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_header_out_status_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_header_out_cache_control_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_header_out_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_body_out_filter(const UINT32 cvendor_md_id, const UINT32 seg_no, uint8_t **data, uint32_t *len);

EC_BOOL cvendor_content_orig_set_store(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_send_request(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg);

EC_BOOL cvendor_content_orig_send_response(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_orig_procedure(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_redirect_procedure(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_cache_parse_header(const UINT32 cvendor_md_id, const CBYTES *header_cbytes);

EC_BOOL cvendor_content_cache_header_out_range_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_cache_header_out_status_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_cache_header_out_filter(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_cache_body_out_filter(const UINT32 cvendor_md_id, const UINT32 seg_no, uint8_t **data, uint32_t *len);

EC_BOOL cvendor_content_cache_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg);

EC_BOOL cvendor_content_cache_send_node(const UINT32 cvendor_md_id, CRANGE_NODE *crange_node);

EC_BOOL cvendor_content_cache_send_response(const UINT32 cvendor_md_id);

EC_BOOL cvendor_content_cache_procedure(const UINT32 cvendor_md_id);

#endif /*_CVENDOR_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


