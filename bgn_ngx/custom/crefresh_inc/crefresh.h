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

#ifndef _CREFRESH_H
#define _CREFRESH_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "csocket.h"
#include "mod.inc"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"
#include "crange.h"

#define CREFRESH_MODULE_NAME           ("crefresh")

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CLIST                cache_path_list;

    ngx_http_request_t  *ngx_http_req;

    /*--- parse from cngx http request ---*/
    uint32_t             cngx_debug_switch_on_flag :1; /*if debug mode indicated in cngx http req*/
    uint32_t             rsvd01                    :31;
    uint32_t             rsvd02;

    UINT32               content_length;
    UINT32               sent_body_size;

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/
}CREFRESH_MD;

#define CREFRESH_MD_TERMINATE_FLAG(crefresh_md)               ((crefresh_md)->terminate_flag)

#define CREFRESH_MD_CACHE_PATH_LIST(crefresh_md)              (&((crefresh_md)->cache_path_list))

#define CREFRESH_MD_NGX_HTTP_REQ(crefresh_md)                 ((crefresh_md)->ngx_http_req)

#define CREFRESH_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crefresh_md)    ((crefresh_md)->cngx_debug_switch_on_flag)

#define CREFRESH_MD_CONTENT_LENGTH(crefresh_md)               ((crefresh_md)->content_length)

#define CREFRESH_MD_SENT_BODY_SIZE(crefresh_md)               ((crefresh_md)->sent_body_size)

#define CREFRESH_MD_NGX_LOC(crefresh_md)                      ((crefresh_md)->ngx_loc)
#define CREFRESH_MD_NGX_RC(crefresh_md)                       ((crefresh_md)->ngx_rc)


/**
*   for test only
*
*   to query the status of CREFRESH Module
*
**/
void crefresh_print_module_status(const UINT32 crefresh_md_id, LOG *log);

/**
*
* register CREFRESH module
*
**/
EC_BOOL crefresh_reg();

/**
*
* unregister CREFRESH module
*
**/
EC_BOOL crefresh_unreg();

/**
*
* start CREFRESH module
*
**/
UINT32 crefresh_start(ngx_http_request_t *r);

/**
*
* end CREFRESH module
*
**/
void crefresh_end(const UINT32 crefresh_md_id);

EC_BOOL crefresh_get_ngx_rc(const UINT32 crefresh_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL crefresh_set_ngx_rc(const UINT32 crefresh_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL crefresh_override_ngx_rc(const UINT32 crefresh_md_id, const ngx_int_t rc, const UINT32 location);

EC_BOOL crefresh_parse_cache_path_list(const UINT32 crefresh_md_id, CBYTES *cbytes);

EC_BOOL crefresh_get_cache_path_list(const UINT32 crefresh_md_id);

EC_BOOL crefresh_content_handler(const UINT32 crefresh_md_id);

EC_BOOL crefresh_content_send_request(const UINT32 crefresh_md_id);

EC_BOOL crefresh_content_send_response(const UINT32 crefresh_md_id);


#endif /*_CREFRESH_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


