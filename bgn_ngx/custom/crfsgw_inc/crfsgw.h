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

#ifndef _CRFSGW_H
#define _CRFSGW_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "csocket.h"
#include "mod.inc"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"
#include "crange.h"

#define CRFSGW_MODULE_NAME           ("crfsgw")

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    ngx_http_request_t  *ngx_http_req;

    /*--- parse from cngx http request ---*/
    uint32_t             cngx_debug_switch_on_flag :1; /*if debug mode indicated in cngx http req*/
    uint32_t             rsvd01                    :31;
    uint32_t             rsvd02;

    CHTTP_RSP            chttp_rsp;

    UINT32               content_length;
    UINT32               sent_body_size;

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/
}CRFSGW_MD;

#define CRFSGW_MD_TERMINATE_FLAG(crfsgw_md)               ((crfsgw_md)->terminate_flag)

#define CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md)                 ((crfsgw_md)->ngx_http_req)

#define CRFSGW_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crfsgw_md)    ((crfsgw_md)->cngx_debug_switch_on_flag)

#define CRFSGW_MD_CHTTP_RSP(crfsgw_md)                    (&((crfsgw_md)->chttp_rsp))

#define CRFSGW_MD_CONTENT_LENGTH(crfsgw_md)               ((crfsgw_md)->content_length)

#define CRFSGW_MD_SENT_BODY_SIZE(crfsgw_md)               ((crfsgw_md)->sent_body_size)

#define CRFSGW_MD_NGX_LOC(crfsgw_md)                      ((crfsgw_md)->ngx_loc)
#define CRFSGW_MD_NGX_RC(crfsgw_md)                       ((crfsgw_md)->ngx_rc)

/**
*   for test only
*
*   to query the status of CRFSGW Module
*
**/
void crfsgw_print_module_status(const UINT32 crfsgw_md_id, LOG *log);

/**
*
* register CRFSGW module
*
**/
EC_BOOL crfsgw_reg();

/**
*
* unregister CRFSGW module
*
**/
EC_BOOL crfsgw_unreg();

/**
*
* start CRFSGW module
*
**/
UINT32 crfsgw_start(ngx_http_request_t *r);

/**
*
* end CRFSGW module
*
**/
void crfsgw_end(const UINT32 crfsgw_md_id);

EC_BOOL crfsgw_get_ngx_rc(const UINT32 crfsgw_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL crfsgw_set_ngx_rc(const UINT32 crfsgw_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL crfsgw_override_ngx_rc(const UINT32 crfsgw_md_id, const ngx_int_t rc, const UINT32 location);

EC_BOOL crfsgw_get_rfs_server(const UINT32 crfsgw_md_id, const CSTRING *cache_uri_cstr, UINT32 *cache_srv_tcid, UINT32 *cache_srv_ipaddr, UINT32 *cache_srv_port);

EC_BOOL crfsgw_content_handler(const UINT32 crfsgw_md_id);

EC_BOOL crfsgw_content_dispatch(const UINT32 crfsgw_md_id, const char *method_str, const char *uri_str);

EC_BOOL crfsgw_content_dispatch_get_request(const UINT32 crfsgw_md_id, const char *uri_str);

EC_BOOL crfsgw_content_dispatch_get_request_getsmf(const UINT32 crfsgw_md_id, const char *path);

EC_BOOL crfsgw_content_dispatch_get_request_dsmf(const UINT32 crfsgw_md_id, const char *path);

EC_BOOL crfsgw_content_dispatch_get_request_ddir(const UINT32 crfsgw_md_id, const char *path);

EC_BOOL crfsgw_content_header_out_filter(const UINT32 crfsgw_md_id);

EC_BOOL crfsgw_content_send_response(const UINT32 crfsgw_md_id);


#endif /*_CRFSGW_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


