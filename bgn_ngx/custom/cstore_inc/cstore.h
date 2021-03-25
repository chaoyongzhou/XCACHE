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

#ifndef _CSTORE_H
#define _CSTORE_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "ctimeout.h"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"

#define CSTORE_MODULE_NAME                 ("cstore")

#define CSTORE_FILE_UPLOAD_OP              ("upload")
#define CSTORE_FILE_EMPTY_OP               ("empty")
#define CSTORE_FILE_MERGE_OP               ("merge")
#define CSTORE_FILE_OVERRIDE_OP            ("override")
#define CSTORE_FILE_CHECK_OP               ("check")
#define CSTORE_FILE_DELETE_OP              ("delete")
#define CSTORE_FILE_SIZE_OP                ("size")
#define CSTORE_FILE_MD5_OP                 ("md5")

#define CSTORE_FILE_DOWNLOAD_OP            ("download")
#define CSTORE_FILE_BACKUP_OP              ("backup")
#define CSTORE_DIR_DELETE_OP               ("ddir")
#define CSTORE_DIR_FINGER_OP               ("finger")

#define CSTORE_CNGX_VAR_BACKUP_DIR         ("c_store_backup_dir")

#define CSTORE_FILE_MERGE_SEG_SIZE         (32 << 20) /*32MB*/

#define CSTORE_PART_FILE_EXPIRED_NSEC      (10 * 60)  /*10min*/

#define CSTORE_FILE_NAME_MAX_DEPTH         (64)       /*file name max depth*/
#define CSTORE_FILE_NAME_SEG_MAX_SIZE      (255)      /*posix compatiblity*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *method;

    CSTRING             *root_path;

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
}CSTORE_MD;

#define CSTORE_MD_TERMINATE_FLAG(cstore_md)               ((cstore_md)->terminate_flag)

#define CSTORE_MD_METHOD(cstore_md)                       ((cstore_md)->method)
#define CSTORE_MD_METHOD_STR(cstore_md)                   (cstring_get_str(CSTORE_MD_METHOD(cstore_md)))

#define CSTORE_MD_ROOT_PATH(cstore_md)                    ((cstore_md)->root_path)
#define CSTORE_MD_ROOT_PATH_STR(cstore_md)                (cstring_get_str(CSTORE_MD_ROOT_PATH(cstore_md)))

#define CSTORE_MD_FILE_OP(cstore_md)                      ((cstore_md)->file_op)
#define CSTORE_MD_FILE_OP_STR(cstore_md)                  (cstring_get_str(CSTORE_MD_FILE_OP(cstore_md)))
#define CSTORE_MD_FILE_PATH(cstore_md)                    ((cstore_md)->file_path)
#define CSTORE_MD_FILE_PATH_STR(cstore_md)                (cstring_get_str(CSTORE_MD_FILE_PATH(cstore_md)))
#define CSTORE_MD_FILE_MD5(cstore_md)                     ((cstore_md)->file_md5)
#define CSTORE_MD_FILE_MD5_STR(cstore_md)                 (cstring_get_str(CSTORE_MD_FILE_MD5(cstore_md)))
#define CSTORE_MD_FILE_BODY(cstore_md)                    ((cstore_md)->file_body)
#define CSTORE_MD_FILE_SIZE(cstore_md)                    ((cstore_md)->file_size)
#define CSTORE_MD_FILE_S_OFFSET(cstore_md)                ((cstore_md)->file_s_offset)
#define CSTORE_MD_FILE_E_OFFSET(cstore_md)                ((cstore_md)->file_e_offset)

#define CSTORE_MD_NGX_HTTP_REQ(cstore_md)                 ((cstore_md)->ngx_http_req)

#define CSTORE_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstore_md)    ((cstore_md)->cngx_debug_switch_on_flag)

#define CSTORE_MD_NGX_RSP_BODY(cstore_md)                 ((cstore_md)->ngx_rsp_body)

#define CSTORE_MD_CONTENT_LENGTH(cstore_md)               ((cstore_md)->content_length)

#define CSTORE_MD_SENT_BODY_SIZE(cstore_md)               ((cstore_md)->sent_body_size)

#define CSTORE_MD_NGX_LOC(cstore_md)                      ((cstore_md)->ngx_loc)
#define CSTORE_MD_NGX_RC(cstore_md)                       ((cstore_md)->ngx_rc)

typedef struct
{
    CTIMEOUT_NODE       on_expired_cb;
    CSTRING             part_file_path;
}CSTORE_NODE;

#define CSTORE_NODE_ON_EXPIRED_CB(cstore_node)            (&((cstore_node)->on_expired_cb))
#define CSTORE_NODE_PART_FILE_PATH(cstore_node)           (&((cstore_node)->part_file_path))

/**
*   for test only
*
*   to query the status of CSTORE Module
*
**/
void cstore_print_module_status(const UINT32 cstore_md_id, LOG *log);

/**
*
* register CSTORE module
*
**/
EC_BOOL cstore_reg();

/**
*
* unregister CSTORE module
*
**/
EC_BOOL cstore_unreg();

/**
*
* start CSTORE module
*
**/
UINT32 cstore_start(ngx_http_request_t *r);

/**
*
* end CSTORE module
*
**/
void cstore_end(const UINT32 cstore_md_id);

EC_BOOL cstore_get_ngx_rc(const UINT32 cstore_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cstore_set_ngx_rc(const UINT32 cstore_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cstore_override_ngx_rc(const UINT32 cstore_md_id, const ngx_int_t rc, const UINT32 location);

CSTORE_NODE *cstore_node_new();

EC_BOOL cstore_node_init(CSTORE_NODE *cstore_node);

EC_BOOL cstore_node_clean(CSTORE_NODE *cstore_node);

EC_BOOL cstore_node_free(CSTORE_NODE *cstore_node);

EC_BOOL cstore_node_expired(CSTORE_NODE *cstore_node);

EC_BOOL cstore_parse_file_path(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_op(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_range(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_md5(const UINT32 cstore_md_id);

EC_BOOL cstore_write_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_empty_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_merge_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_override_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_check_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_delete_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_size_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_md5_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_content_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_content_send_response(const UINT32 cstore_md_id);

#endif /*_CSTORE_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


