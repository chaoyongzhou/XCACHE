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

#define CSTORE_MODULE_NAME                          ("cstore")

#define CSTORE_FILE_UPLOAD_OP                       ("upload")      /*method: POST*/
#define CSTORE_FILE_EMPTY_OP                        ("empty")       /*method: PUT*/
#define CSTORE_FILE_MERGE_OP                        ("merge")       /*method: PUT*/
#define CSTORE_FILE_COMBINE_OP                      ("combine")     /*method: PUT*/
#define CSTORE_FILE_COMPLETE_OP                     ("complete")    /*method: GET*/
#define CSTORE_FILE_OVERRIDE_OP                     ("override")    /*method: PUT*/
#define CSTORE_FILE_CHECK_OP                        ("check")       /*method: GET*/
#define CSTORE_FILE_DELETE_OP                       ("delete")      /*method: DELETE*/
#define CSTORE_FILE_SIZE_OP                         ("size")        /*method: GET*/
#define CSTORE_FILE_MD5_OP                          ("md5")         /*method: GET*/
#define CSTORE_FILE_UNZIP_OP                        ("unzip")       /*method: PUT*/

#define CSTORE_FILE_DOWNLOAD_OP                     ("download")    /*method: GET*/
#define CSTORE_DIR_MAKE_OP                          ("mkdir")       /*method: PUT*/
#define CSTORE_DIR_DELETE_OP                        ("ddir")        /*method: DELETE*/
#define CSTORE_DIR_LIST_OP                          ("ldir")        /*method: GET*/

/*op of backend storage*/
#define CSTORE_FILE_PUSH_OP                         ("push")        /*method: PUT*/
#define CSTORE_FILE_PULL_OP                         ("pull")        /*method: GET*/
#define CSTORE_FILE_LIST_OP                         ("list")        /*method: GET*/
#define CSTORE_FILE_PURGE_OP                        ("purge")       /*method: DELETE*/


#define CSTORE_CNGX_VAR_MKDIR_BACKEND_CMD           ("c_store_mkdir_backend_cmd")
#define CSTORE_CNGX_VAR_PUSH_BACKEND_CMD            ("c_store_push_backend_cmd")
#define CSTORE_CNGX_VAR_PULL_BACKEND_CMD            ("c_store_pull_backend_cmd")
#define CSTORE_CNGX_VAR_PURGE_BACKEND_CMD           ("c_store_purge_backend_cmd")
#define CSTORE_CNGX_VAR_LIST_BACKEND_CMD            ("c_store_list_backend_cmd")

#define CSTORE_FILE_MERGE_SEG_SIZE                  (32 << 20) /*32MB*/
#define CSTORE_FILE_NAME_MAX_DEPTH                  (64)       /*file name max depth*/
#define CSTORE_FILE_NAME_SEG_MAX_SIZE               (255)      /*posix compatiblity*/

#define CSTORE_CACHE_MAX_SIZE                       (4 << 20) /*4MB*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *method;


    CSTRING             *root_path;     /* e.g. /tmp/upload */
    CSTRING             *bucket_path;   /* e.g. /bucket01/a/b/c.log */

    CSTRING             *file_op;
    CSTRING             *file_path;     /* e.g. /tmp/upload/bucket01/a/b/c.log, i.e. {root_path}/{bucket_path} */
    CSTRING             *file_md5;
    CBYTES              *file_body;
    UINT32               file_size;
    UINT32               file_s_offset;
    UINT32               file_e_offset;
    UINT32               segment_size;

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

#define CSTORE_MD_BUCKET_PATH(cstore_md)                  ((cstore_md)->bucket_path)
#define CSTORE_MD_BUCKET_PATH_STR(cstore_md)              (cstring_get_str(CSTORE_MD_BUCKET_PATH(cstore_md)))

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
#define CSTORE_MD_SEGMENT_SIZE(cstore_md)                 ((cstore_md)->segment_size)

#define CSTORE_MD_NGX_HTTP_REQ(cstore_md)                 ((cstore_md)->ngx_http_req)

#define CSTORE_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstore_md)    ((cstore_md)->cngx_debug_switch_on_flag)

#define CSTORE_MD_NGX_RSP_BODY(cstore_md)                 ((cstore_md)->ngx_rsp_body)

#define CSTORE_MD_CONTENT_LENGTH(cstore_md)               ((cstore_md)->content_length)

#define CSTORE_MD_SENT_BODY_SIZE(cstore_md)               ((cstore_md)->sent_body_size)

#define CSTORE_MD_NGX_LOC(cstore_md)                      ((cstore_md)->ngx_loc)
#define CSTORE_MD_NGX_RC(cstore_md)                       ((cstore_md)->ngx_rc)

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

EC_BOOL cstore_parse_dir_path(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_path(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_op(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_range(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_size(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_segment_size(const UINT32 cstore_md_id);

EC_BOOL cstore_parse_file_md5(const UINT32 cstore_md_id);

EC_BOOL cstore_upload_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_empty_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_merge_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_combine_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_override_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_check_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_delete_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_size_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_md5_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_download_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_complete_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_make_dir_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_push_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_pull_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_list_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_unzip_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_purge_file_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_delete_dir_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_list_dir_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_content_handler(const UINT32 cstore_md_id);

EC_BOOL cstore_content_send_response(const UINT32 cstore_md_id);

#endif /*_CSTORE_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


