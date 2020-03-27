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

#ifndef _CNGX_UPSTREAM_H
#define _CNGX_UPSTREAM_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_request.h>

#include "type.h"

EC_BOOL cngx_upstream_exist(ngx_http_request_t *r);

EC_BOOL cngx_upstream_get_name(ngx_http_request_t *r, u_char **str, uint32_t *len);

EC_BOOL cngx_upstream_get_location(ngx_http_request_t *r, u_char **str, uint32_t *len);

EC_BOOL cngx_upstream_fetch(ngx_http_request_t *r, UINT32 *ipaddr, UINT32 *port);

EC_BOOL cngx_upstream_set_down(ngx_http_request_t *r);

EC_BOOL cngx_upstream_set_up(ngx_http_request_t *r);

#endif /*_CNGX_UPSTREAM_H*/

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

