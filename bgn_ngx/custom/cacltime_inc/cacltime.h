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

#ifndef _CACLTIME_H
#define _CACLTIME_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "ctimeout.h"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"

#define CACLTIME_MODULE_NAME                 ("cacltime")

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

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/
}CACLTIME_MD;

#define CACLTIME_MD_TERMINATE_FLAG(cacltime_md)               ((cacltime_md)->terminate_flag)

#define CACLTIME_MD_NGX_HTTP_REQ(cacltime_md)                 ((cacltime_md)->ngx_http_req)

#define CACLTIME_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cacltime_md)    ((cacltime_md)->cngx_debug_switch_on_flag)

#define CACLTIME_MD_NGX_LOC(cacltime_md)                      ((cacltime_md)->ngx_loc)
#define CACLTIME_MD_NGX_RC(cacltime_md)                       ((cacltime_md)->ngx_rc)

typedef struct
{
    char        *op;
    char        *path;
    char        *time;
    char        *sig;
}CACLTIME_ACCESS_NODE;

#define CACLTIME_ACCESS_NODE_OP(cacltime_access_node)                ((cacltime_access_node)->op)
#define CACLTIME_ACCESS_NODE_PATH(cacltime_access_node)              ((cacltime_access_node)->path)
#define CACLTIME_ACCESS_NODE_TIME(cacltime_access_node)              ((cacltime_access_node)->time)
#define CACLTIME_ACCESS_NODE_SIG(cacltime_access_node)               ((cacltime_access_node)->sig)

/**
*   for test only
*
*   to query the status of CACLTIME Module
*
**/
void cacltime_print_module_status(const UINT32 cacltime_md_id, LOG *log);

/**
*
* register CACLTIME module
*
**/
EC_BOOL cacltime_reg();

/**
*
* unregister CACLTIME module
*
**/
EC_BOOL cacltime_unreg();

/**
*
* start CACLTIME module
*
**/
UINT32 cacltime_start(ngx_http_request_t *r);

/**
*
* end CACLTIME module
*
**/
void cacltime_end(const UINT32 cacltime_md_id);

EC_BOOL cacltime_get_ngx_rc(const UINT32 cacltime_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cacltime_set_ngx_rc(const UINT32 cacltime_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cacltime_override_ngx_rc(const UINT32 cacltime_md_id, const ngx_int_t rc, const UINT32 location);

/**
*
* access filter
*
**/
EC_BOOL cacltime_access_filter(const UINT32 cacltime_md_id);

EC_BOOL cacltime_access_check(const UINT32 cacltime_md_id, const CACLTIME_ACCESS_NODE *cacltime_access_node);

EC_BOOL cacltime_access_filter_node(const UINT32 cacltime_md_id, const char *uri, const char *arg,
                                            CACLTIME_ACCESS_NODE *cacltime_access_node);

EC_BOOL cacltime_access_filter_path(const UINT32 cacltime_md_id, const char *uri, char **path);

EC_BOOL cacltime_access_filter_op(const UINT32 cacltime_md_id, const char *arg, char **op);

EC_BOOL cacltime_access_filter_sig(const UINT32 cacltime_md_id, const char *arg, char **sig);

EC_BOOL cacltime_access_filter_time(const UINT32 cacltime_md_id, const char *arg, char **time);

EC_BOOL cacltime_access_node_init(CACLTIME_ACCESS_NODE *cacltime_access_node);

EC_BOOL cacltime_access_node_clean(CACLTIME_ACCESS_NODE *cacltime_access_node);

#endif /*_CACLTIME_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


