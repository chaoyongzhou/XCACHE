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

#ifndef _CSTORECFG_H
#define _CSTORECFG_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "cngx.h"
#include "chttp.h"

#define CSTORECFG_MODULE_NAME                 ("cstorecfg")

#define CSTORECFG_BUCKET_ADD_OP               ("add")
#define CSTORECFG_BUCKET_DELETE_OP            ("delete")
#define CSTORECFG_BUCKET_MODIFY_OP            ("modify")
#define CSTORECFG_BUCKET_ACTIVATE_OP          ("activate")

#define CSTORECFG_CONF_PATH                   ("/usr/local/xcache/conf/other_server_conf.d")
#define CSTORECFG_CROSSPLANE                  ("/usr/local/bin/crossplane")

#define CSTORECFG_CACHE_MAX_SIZE              (1 << 20) /*1MB*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *method;
    CSTRING             *host;

    CSTRING             *bucket_name;
    CSTRING             *bucket_op;

    CSTRING             *cfg_file_name;
    CSTRING             *tmp_file_name;

    CSTRING             *minify_cmd_line;
    CSTRING             *format_cmd_line;

    CBYTES              *ngx_req_body;

    ngx_http_request_t  *ngx_http_req;

    char                *buf_cache;
    char                *cfg_cache;

    /*--- parse from cngx http request ---*/
    uint32_t             cngx_debug_switch_on_flag :1; /*if debug mode indicated in cngx http req*/
    uint32_t             rsvd01                    :31;
    uint32_t             rsvd02;

    CBYTES              *ngx_rsp_body;

    UINT32               content_length;
    UINT32               sent_body_size;

    UINT32               ngx_loc;  /*ngx rc report at location*/
    ngx_int_t            ngx_rc;   /*save ngx calling result*/
}CSTORECFG_MD;

#define CSTORECFG_MD_TERMINATE_FLAG(cstorecfg_md)               ((cstorecfg_md)->terminate_flag)

#define CSTORECFG_MD_METHOD(cstorecfg_md)                       ((cstorecfg_md)->method)
#define CSTORECFG_MD_METHOD_STR(cstorecfg_md)                   (cstring_get_str(CSTORECFG_MD_METHOD(cstorecfg_md)))

#define CSTORECFG_MD_HOST(cstorecfg_md)                         ((cstorecfg_md)->host)
#define CSTORECFG_MD_HOST_STR(cstorecfg_md)                     (cstring_get_str(CSTORECFG_MD_HOST(cstorecfg_md)))

#define CSTORECFG_MD_BUCKET_NAME(cstorecfg_md)                  ((cstorecfg_md)->bucket_name)
#define CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md)              (cstring_get_str(CSTORECFG_MD_BUCKET_NAME(cstorecfg_md)))

#define CSTORECFG_MD_BUCKET_OP(cstorecfg_md)                    ((cstorecfg_md)->bucket_op)
#define CSTORECFG_MD_BUCKET_OP_STR(cstorecfg_md)                (cstring_get_str(CSTORECFG_MD_BUCKET_OP(cstorecfg_md)))

#define CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md)                ((cstorecfg_md)->cfg_file_name)
#define CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md)            (cstring_get_str(CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md)))

#define CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md)                ((cstorecfg_md)->tmp_file_name)
#define CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md)            (cstring_get_str(CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md)))

#define CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md)              ((cstorecfg_md)->minify_cmd_line)
#define CSTORECFG_MD_MINIFY_CMD_LINE_STR(cstorecfg_md)          (cstring_get_str(CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md)))

#define CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md)              ((cstorecfg_md)->format_cmd_line)
#define CSTORECFG_MD_FORMAT_CMD_LINE_STR(cstorecfg_md)          (cstring_get_str(CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md)))

#define CSTORECFG_MD_BUF_CACHE(cstorecfg_md)                    ((cstorecfg_md)->buf_cache)
#define CSTORECFG_MD_CFG_CACHE(cstorecfg_md)                    ((cstorecfg_md)->cfg_cache)

#define CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md)                 ((cstorecfg_md)->ngx_req_body)

#define CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md)                 ((cstorecfg_md)->ngx_http_req)

#define CSTORECFG_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstorecfg_md)    ((cstorecfg_md)->cngx_debug_switch_on_flag)

#define CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md)                 ((cstorecfg_md)->ngx_rsp_body)

#define CSTORECFG_MD_CONTENT_LENGTH(cstorecfg_md)               ((cstorecfg_md)->content_length)

#define CSTORECFG_MD_SENT_BODY_SIZE(cstorecfg_md)               ((cstorecfg_md)->sent_body_size)

#define CSTORECFG_MD_NGX_LOC(cstorecfg_md)                      ((cstorecfg_md)->ngx_loc)
#define CSTORECFG_MD_NGX_RC(cstorecfg_md)                       ((cstorecfg_md)->ngx_rc)

typedef struct
{
    uint32_t       cfg_len;
    uint32_t       rsvd;
    char          *cfg_str;
}CSTORECFG_NODE;

#define CSTORECFG_NODE_CFG_LEN(cstorecfg_node)                  ((cstorecfg_node)->cfg_len)
#define CSTORECFG_NODE_CFG_STR(cstorecfg_node)                  ((cstorecfg_node)->cfg_str)

/**
*   for test only
*
*   to query the status of CSTORECFG Module
*
**/
void cstorecfg_print_module_status(const UINT32 cstorecfg_md_id, LOG *log);

/**
*
* register CSTORECFG module
*
**/
EC_BOOL cstorecfg_reg();

/**
*
* unregister CSTORECFG module
*
**/
EC_BOOL cstorecfg_unreg();

/**
*
* start CSTORECFG module
*
**/
UINT32 cstorecfg_start(ngx_http_request_t *r);

/**
*
* end CSTORECFG module
*
**/
void cstorecfg_end(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_get_ngx_rc(const UINT32 cstorecfg_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cstorecfg_set_ngx_rc(const UINT32 cstorecfg_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cstorecfg_override_ngx_rc(const UINT32 cstorecfg_md_id, const ngx_int_t rc, const UINT32 location);

EC_BOOL cstorecfg_parse_method(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_parse_host(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_parse_file_name(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_parse_cmd_line(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_parse_cache(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_parse_bucket_name(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_parse_bucket_op(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_parse_req_body(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_bucket_add_handler(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_bucket_delete_handler(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_bucket_modify_handler(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_content_handler(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_content_send_response(const UINT32 cstorecfg_md_id);

EC_BOOL cstorecfg_node_init(CSTORECFG_NODE *cstorecfg_node);

EC_BOOL cstorecfg_node_clean(CSTORECFG_NODE *cstorecfg_node);

void cstorecfg_node_print(LOG *log, const CSTORECFG_NODE *cstorecfg_node);

#endif /*_CSTORECFG_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/



