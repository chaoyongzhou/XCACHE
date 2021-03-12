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

#ifndef _CSHELL_H
#define _CSHELL_H

#include "type.h"
#include "cstring.h"
#include "clist.h"

#include "ctimeout.h"

#include "cngx.h"
#include "chttp.h"

#include "cbytes.h"

#define CSHELL_MODULE_NAME                 ("cshell")

#define CSHELL_CNGX_VAR_CMD                ("c_shell_cmd")
#define CSHELL_CNGX_VAR_OUTPUT_SIZE        ("c_shell_output_size")

#define CSHELL_CNGX_OUTPUT_SIZE_DEFAULT    (1 * 1024 * 1024)/*default output max size is 1MB*/

typedef struct
{
    /* used counter >= 0 */
    UINT32               usedcounter;
    EC_BOOL              terminate_flag;

    CSTRING             *cmd_line;
    UINT32               cmd_output_max_size;
    //UINT8               *cmd_output_buff;

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
}CSHELL_MD;

#define CSHELL_MD_TERMINATE_FLAG(cshell_md)               ((cshell_md)->terminate_flag)

#define CSHELL_MD_CMD_LINE(cshell_md)                     ((cshell_md)->cmd_line)
#define CSHELL_MD_CMD_LINE_STR(cshell_md)                 (cstring_get_str(CSHELL_MD_CMD_LINE(cshell_md)))

#define CSHELL_MD_CMD_OUTPUT_MAX_SIZE(cshell_md)          ((cshell_md)->cmd_output_max_size)

#define CSHELL_MD_NGX_HTTP_REQ(cshell_md)                 ((cshell_md)->ngx_http_req)

#define CSHELL_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cshell_md)    ((cshell_md)->cngx_debug_switch_on_flag)

#define CSHELL_MD_NGX_RSP_BODY(cshell_md)                 ((cshell_md)->ngx_rsp_body)

#define CSHELL_MD_CONTENT_LENGTH(cshell_md)               ((cshell_md)->content_length)

#define CSHELL_MD_SENT_BODY_SIZE(cshell_md)               ((cshell_md)->sent_body_size)

#define CSHELL_MD_NGX_LOC(cshell_md)                      ((cshell_md)->ngx_loc)
#define CSHELL_MD_NGX_RC(cshell_md)                       ((cshell_md)->ngx_rc)

/**
*   for test only
*
*   to query the status of CSHELL Module
*
**/
void cshell_print_module_status(const UINT32 cshell_md_id, LOG *log);

/**
*
* register CSHELL module
*
**/
EC_BOOL cshell_reg();

/**
*
* unregister CSHELL module
*
**/
EC_BOOL cshell_unreg();

/**
*
* start CSHELL module
*
**/
UINT32 cshell_start(ngx_http_request_t *r);

/**
*
* end CSHELL module
*
**/
void cshell_end(const UINT32 cshell_md_id);

EC_BOOL cshell_get_ngx_rc(const UINT32 cshell_md_id, ngx_int_t *rc, UINT32 *location);

/*only for failure!*/
EC_BOOL cshell_set_ngx_rc(const UINT32 cshell_md_id, const ngx_int_t rc, const UINT32 location);

/*only for failure!*/
EC_BOOL cshell_override_ngx_rc(const UINT32 cshell_md_id, const ngx_int_t rc, const UINT32 location);

EC_BOOL cshell_parse_cmd_output_size(const UINT32 cshell_md_id);

EC_BOOL cshell_parse_cmd(const UINT32 cshell_md_id);

EC_BOOL cshell_parse_cmd_default(const UINT32 cshell_md_id);

EC_BOOL cshell_cmd_handler(const UINT32 cshell_md_id);

/**
*
* content handler
*
**/
EC_BOOL cshell_content_handler(const UINT32 cshell_md_id);

EC_BOOL cshell_content_send_response(const UINT32 cshell_md_id);

#endif /*_CSHELL_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


