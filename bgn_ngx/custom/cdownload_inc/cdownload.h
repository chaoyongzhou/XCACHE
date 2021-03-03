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

#ifndef _CDOWNLOAD_H
#define _CDOWNLOAD_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"

#define CDOWNLOAD_MODULE_NAME                 ("cdownload")

#define CDOWNLOAD_FILE_CHECK_OP               ("/check")
#define CDOWNLOAD_FILE_DELETE_OP              ("/delete")
#define CDOWNLOAD_FILE_SIZE_OP                ("/size")
#define CDOWNLOAD_FILE_MD5_OP                 ("/md5")
#define CDOWNLOAD_FILE_DOWNLOAD_OP            ("/download")
#define CDOWNLOAD_FILE_BACKUP_OP              ("/backup")
#define CDOWNLOAD_DIR_DELETE_OP               ("/ddir")
#define CDOWNLOAD_DIR_FINGER_OP               ("/finger")


#define CDOWNLOAD_CNGX_VAR_BACKUP_DIR         ("c_download_backup_dir")

#define CDOWNLOAD_FILE_NAME_MAX_DEPTH         (64)       /*file name max depth*/
#define CDOWNLOAD_FILE_NAME_SEG_MAX_SIZE      (255)      /*posix compatiblity*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *root_path;
    CSTRING             *file_op;
    CSTRING             *file_relative_path;
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
}CDOWNLOAD_MD;

#define CDOWNLOAD_MD_TERMINATE_FLAG(cdownload_md)               ((cdownload_md)->terminate_flag)

#define CDOWNLOAD_MD_ROOT_PATH(cdownload_md)                    ((cdownload_md)->root_path)
#define CDOWNLOAD_MD_ROOT_PATH_STR(cdownload_md)                (cstring_get_str(CDOWNLOAD_MD_ROOT_PATH(cdownload_md)))

#define CDOWNLOAD_MD_FILE_OP(cdownload_md)                      ((cdownload_md)->file_op)
#define CDOWNLOAD_MD_FILE_OP_STR(cdownload_md)                  (cstring_get_str(CDOWNLOAD_MD_FILE_OP(cdownload_md)))
#define CDOWNLOAD_MD_FILE_RELATIVE_PATH(cdownload_md)           ((cdownload_md)->file_relative_path)
#define CDOWNLOAD_MD_FILE_RELATIVE_PATH_STR(cdownload_md)       (cstring_get_str(CDOWNLOAD_MD_FILE_RELATIVE_PATH(cdownload_md)))
#define CDOWNLOAD_MD_FILE_PATH(cdownload_md)                    ((cdownload_md)->file_path)
#define CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md)                (cstring_get_str(CDOWNLOAD_MD_FILE_PATH(cdownload_md)))
#define CDOWNLOAD_MD_FILE_MD5(cdownload_md)                     ((cdownload_md)->file_md5)
#define CDOWNLOAD_MD_FILE_MD5_STR(cdownload_md)                 (cstring_get_str(CDOWNLOAD_MD_FILE_MD5(cdownload_md)))
#define CDOWNLOAD_MD_FILE_BODY(cdownload_md)                    ((cdownload_md)->file_body)
#define CDOWNLOAD_MD_FILE_SIZE(cdownload_md)                    ((cdownload_md)->file_size)
#define CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md)                ((cdownload_md)->file_s_offset)
#define CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md)                ((cdownload_md)->file_e_offset)

#define CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md)                 ((cdownload_md)->ngx_http_req)

#define CDOWNLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cdownload_md)    ((cdownload_md)->cngx_debug_switch_on_flag)

#define CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md)                 ((cdownload_md)->ngx_rsp_body)

#define CDOWNLOAD_MD_CONTENT_LENGTH(cdownload_md)               ((cdownload_md)->content_length)

#define CDOWNLOAD_MD_SENT_BODY_SIZE(cdownload_md)               ((cdownload_md)->sent_body_size)

#define CDOWNLOAD_MD_NGX_LOC(cdownload_md)                      ((cdownload_md)->ngx_loc)
#define CDOWNLOAD_MD_NGX_RC(cdownload_md)                       ((cdownload_md)->ngx_rc)


/**
*   for test only
*
*   to query the status of CDOWNLOAD Module
*
**/
void cdownload_print_module_status(const UINT32 cdownload_md_id, LOG *log);

/**
*
* register CDOWNLOAD module
*
**/
EC_BOOL cdownload_reg();

/**
*
* unregister CDOWNLOAD module
*
**/
EC_BOOL cdownload_unreg();

/**
*
* start CDOWNLOAD module
*
**/
UINT32 cdownload_start(ngx_http_request_t *r);

/**
*
* end CDOWNLOAD module
*
**/
void cdownload_end(const UINT32 cdownload_md_id);

EC_BOOL cdownload_get_ngx_rc(const UINT32 cdownload_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cdownload_set_ngx_rc(const UINT32 cdownload_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cdownload_override_ngx_rc(const UINT32 cdownload_md_id, const ngx_int_t rc, const UINT32 location);

EC_BOOL cdownload_parse_uri(const UINT32 cdownload_md_id);

EC_BOOL cdownload_parse_file_range(const UINT32 cdownload_md_id);

EC_BOOL cdownload_parse_file_md5(const UINT32 cdownload_md_id);

EC_BOOL cdownload_check_file_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_delete_file_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_size_file_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_md5_file_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_read_file_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_backup_file_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_delete_dir_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_finger_dir_handler(const UINT32 cdownload_md_id);



EC_BOOL cdownload_content_handler(const UINT32 cdownload_md_id);

EC_BOOL cdownload_content_send_response(const UINT32 cdownload_md_id);

#endif /*_CDOWNLOAD_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


