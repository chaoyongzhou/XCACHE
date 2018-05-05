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

#ifndef _CNGX_HEADERS_H
#define _CNGX_HEADERS_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "type.h"

#include "chttp.h"


extern ngx_module_t ngx_http_bgn_module;

EC_BOOL cngx_headers_dir0_filter(ngx_http_request_t *r);

EC_BOOL cngx_headers_dir1_filter(ngx_http_request_t *r, CHTTP_REQ *chttp_req);

EC_BOOL cngx_headers_dir2_filter(ngx_http_request_t *r, CHTTP_RSP *chttp_rsp);

EC_BOOL cngx_headers_dir3_filter(ngx_http_request_t *r, CHTTP_RSP *chttp_rsp);

#endif /*_CNGX_HEADERS_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
