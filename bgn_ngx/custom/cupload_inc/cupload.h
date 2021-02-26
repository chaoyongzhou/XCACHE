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

#ifndef _CUPLOAD_H
#define _CUPLOAD_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "ctimeout.h"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"

#define CUPLOAD_MODULE_NAME                 ("cupload")

#define CUPLOAD_FILE_UPLOAD_OP              ("/upload")
#define CUPLOAD_FILE_EMPTY_OP               ("/empty")
#define CUPLOAD_FILE_MERGE_OP               ("/merge")
#define CUPLOAD_FILE_OVERRIDE_OP            ("/override")
#define CUPLOAD_FILE_CHECK_OP               ("/check")
#define CUPLOAD_FILE_DELETE_OP              ("/delete")
#define CUPLOAD_FILE_SIZE_OP                ("/size")
#define CUPLOAD_FILE_MD5_OP                 ("/md5")

#define CUPLOAD_FILE_MERGE_SEG_SIZE         (32 << 20) /*32MB*/

#define CUPLOAD_PART_FILE_EXPIRED_NSEC      (10 * 60)  /*10min*/

#define CUPLOAD_FILE_NAME_MAX_DEPTH         (64)       /*file name max depth*/
#define CUPLOAD_FILE_NAME_SEG_MAX_SIZE      (255)      /*posix compatiblity*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *file_op;
    CSTRING             *file_path;
    CSTRING             *file_md5;
    CBYTES              *file_body;
    UINT32               file_size;
    UINT32               file_s_offset;
    UINT32               file_e_offset;

    ngx_http_request_t  *ngx_http_req;

    /*--- parse from cngx http request ---*/
    uint32_t             cngx_debug_switch_on_flag :1; /*if debug mode indicated in cngx http req*/
    uint32_t             rsvd01                    :31;
    uint32_t             rsvd02;

    CBYTES              *ngx_rsp_body;

    UINT32               content_length;
    UINT32               sent_body_size;

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/
}CUPLOAD_MD;

#define CUPLOAD_MD_TERMINATE_FLAG(cupload_md)               ((cupload_md)->terminate_flag)

#define CUPLOAD_MD_FILE_OP(cupload_md)                      ((cupload_md)->file_op)
#define CUPLOAD_MD_FILE_OP_STR(cupload_md)                  (cstring_get_str(CUPLOAD_MD_FILE_OP(cupload_md)))
#define CUPLOAD_MD_FILE_PATH(cupload_md)                    ((cupload_md)->file_path)
#define CUPLOAD_MD_FILE_PATH_STR(cupload_md)                (cstring_get_str(CUPLOAD_MD_FILE_PATH(cupload_md)))
#define CUPLOAD_MD_FILE_MD5(cupload_md)                     ((cupload_md)->file_md5)
#define CUPLOAD_MD_FILE_MD5_STR(cupload_md)                 (cstring_get_str(CUPLOAD_MD_FILE_MD5(cupload_md)))
#define CUPLOAD_MD_FILE_BODY(cupload_md)                    ((cupload_md)->file_body)
#define CUPLOAD_MD_FILE_SIZE(cupload_md)                    ((cupload_md)->file_size)
#define CUPLOAD_MD_FILE_S_OFFSET(cupload_md)                ((cupload_md)->file_s_offset)
#define CUPLOAD_MD_FILE_E_OFFSET(cupload_md)                ((cupload_md)->file_e_offset)

#define CUPLOAD_MD_NGX_HTTP_REQ(cupload_md)                 ((cupload_md)->ngx_http_req)

#define CUPLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cupload_md)    ((cupload_md)->cngx_debug_switch_on_flag)

#define CUPLOAD_MD_NGX_RSP_BODY(cupload_md)                 ((cupload_md)->ngx_rsp_body)

#define CUPLOAD_MD_CONTENT_LENGTH(cupload_md)               ((cupload_md)->content_length)

#define CUPLOAD_MD_SENT_BODY_SIZE(cupload_md)               ((cupload_md)->sent_body_size)

#define CUPLOAD_MD_NGX_LOC(cupload_md)                      ((cupload_md)->ngx_loc)
#define CUPLOAD_MD_NGX_RC(cupload_md)                       ((cupload_md)->ngx_rc)

typedef struct
{
    CTIMEOUT_NODE       on_expired_cb;
    CSTRING             part_file_path;
}CUPLOAD_NODE;

#define CUPLOAD_NODE_ON_EXPIRED_CB(cupload_node)            (&((cupload_node)->on_expired_cb))
#define CUPLOAD_NODE_PART_FILE_PATH(cupload_node)           (&((cupload_node)->part_file_path))

/**
*   for test only
*
*   to query the status of CUPLOAD Module
*
**/
void cupload_print_module_status(const UINT32 cupload_md_id, LOG *log);

/**
*
* register CUPLOAD module
*
**/
EC_BOOL cupload_reg();

/**
*
* unregister CUPLOAD module
*
**/
EC_BOOL cupload_unreg();

/**
*
* start CUPLOAD module
*
**/
UINT32 cupload_start(ngx_http_request_t *r);

/**
*
* end CUPLOAD module
*
**/
void cupload_end(const UINT32 cupload_md_id);

EC_BOOL cupload_get_ngx_rc(const UINT32 cupload_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cupload_set_ngx_rc(const UINT32 cupload_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cupload_override_ngx_rc(const UINT32 cupload_md_id, const ngx_int_t rc, const UINT32 location);

CUPLOAD_NODE *cupload_node_new();

EC_BOOL cupload_node_init(CUPLOAD_NODE *cupload_node);

EC_BOOL cupload_node_clean(CUPLOAD_NODE *cupload_node);

EC_BOOL cupload_node_free(CUPLOAD_NODE *cupload_node);

EC_BOOL cupload_node_expired(CUPLOAD_NODE *cupload_node);

EC_BOOL cupload_parse_uri(const UINT32 cupload_md_id);

EC_BOOL cupload_parse_file_range(const UINT32 cupload_md_id);

EC_BOOL cupload_parse_file_md5(const UINT32 cupload_md_id);

EC_BOOL cupload_write_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_empty_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_merge_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_override_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_check_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_delete_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_size_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_md5_file_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_content_handler(const UINT32 cupload_md_id);

EC_BOOL cupload_content_send_response(const UINT32 cupload_md_id);

#endif /*_CUPLOAD_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


