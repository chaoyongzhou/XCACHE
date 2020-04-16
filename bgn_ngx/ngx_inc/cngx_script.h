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

#ifndef _CNGX_SCRIPT_H
#define _CNGX_SCRIPT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "type.h"

EC_BOOL cngx_script_dir0_filter(ngx_http_request_t *r);

EC_BOOL cngx_script_dir1_filter(ngx_http_request_t *r);

EC_BOOL cngx_script_dir2_filter(ngx_http_request_t *r);

EC_BOOL cngx_script_dir3_filter(ngx_http_request_t *r);

#endif /*_CNGX_SCRIPT_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/
#ifdef __cplusplus
}
#endif/*__cplusplus*/