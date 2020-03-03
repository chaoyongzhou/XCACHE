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

#ifndef _CLOOPBACK_H
#define _CLOOPBACK_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "mod.inc"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"

#define CLOOPBACK_MODULE_NAME           ("cloopback")

#define CLOOPBACK_VAR_HOSTNAME          ("c_visible_hostname")
#define CLOOPBACK_ENABLED_HEADER        ("X-LOOPBACK-ENABLED")
#define CLOOPBACK_VIA_HEADER            ("X-VIA")


typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    ngx_http_request_t  *ngx_http_req;

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/
}CLOOPBACK_MD;

#define CLOOPBACK_MD_TERMINATE_FLAG(cloopback_md)                     ((cloopback_md)->terminate_flag)

#define CLOOPBACK_MD_NGX_HTTP_REQ(cloopback_md)                       ((cloopback_md)->ngx_http_req)

#define CLOOPBACK_MD_NGX_LOC(cloopback_md)                            ((cloopback_md)->ngx_loc)
#define CLOOPBACK_MD_NGX_RC(cloopback_md)                             ((cloopback_md)->ngx_rc)

/**
*   for test only
*
*   to query the status of CLOOPBACK Module
*
**/
void cloopback_print_module_status(const UINT32 cloopback_md_id, LOG *log);

/**
*
* register CLOOPBACK module
*
**/
EC_BOOL cloopback_reg();

/**
*
* unregister CLOOPBACK module
*
**/
EC_BOOL cloopback_unreg();

/**
*
* start CLOOPBACK module
*
**/
UINT32 cloopback_start(ngx_http_request_t *r);

/**
*
* end CLOOPBACK module
*
**/
void cloopback_end(const UINT32 cloopback_md_id);

EC_BOOL cloopback_get_ngx_rc(const UINT32 cloopback_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cloopback_set_ngx_rc(const UINT32 cloopback_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cloopback_override_ngx_rc(const UINT32 cloopback_md_id, const ngx_int_t rc, const UINT32 location);

EC_BOOL cloopback_access_filter(const UINT32 cloopback_md_id);

#endif /*_CLOOPBACK_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


