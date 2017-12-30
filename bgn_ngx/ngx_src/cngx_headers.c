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

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_request.h>

#include "ngx_http_bgn_headers_in.h"
#include "ngx_http_bgn_headers_out.h"
#include "ngx_http_bgn_variable.h"

#include "type.h"
#include "mm.h"
#include "log.h"

#include "chttp.h"

#include "cngx_headers.h"


EC_BOOL cngx_headers_dir0_filter(ngx_http_request_t *r)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *headers;
    ngx_int_t                    idx;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_ADD][NGX_HTTP_BGN_HEADERS_DIR_0];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            ngx_http_bgn_set_header_in(r, kv->key, kv->value, 1 /*override*/);
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir0_filter: add header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_0];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            ngx_http_bgn_del_header_in(r, kv->key);
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir0_filter: del header '%s'\n",
                                        (const char *)(kv->key.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_0];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            ngx_http_bgn_renew_header_in(r, kv->key, kv->value);
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir0_filter: renew header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }
    
    return (EC_TRUE);
}

EC_BOOL cngx_headers_dir1_filter(ngx_http_request_t *r, CHTTP_REQ *chttp_req)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *headers;
    ngx_int_t                   idx;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_ADD][NGX_HTTP_BGN_HEADERS_DIR_1];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_req_renew_header(chttp_req, (const char *)(kv->key.data), (const char *)(kv->value.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: add header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_1];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_req_del_header(chttp_req, (const char *)(kv->key.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: del header '%s'\n",
                                        (const char *)(kv->key.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_1];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_req_renew_header(chttp_req, (const char *)(kv->key.data), (const char *)(kv->value.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: renew header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }
    
    return (EC_TRUE);
}

EC_BOOL cngx_headers_dir2_filter(ngx_http_request_t *r, CHTTP_RSP *chttp_rsp)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *headers;
    ngx_int_t                   idx;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_ADD][NGX_HTTP_BGN_HEADERS_DIR_2];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_rsp_renew_header(chttp_rsp, (const char *)(kv->key.data), (const char *)(kv->value.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: add header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_2];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_rsp_del_header(chttp_rsp, (const char *)(kv->key.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: del header '%s'\n",
                                        (const char *)(kv->key.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_2];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_rsp_renew_header(chttp_rsp, (const char *)(kv->key.data), (const char *)(kv->value.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: renew header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }
    
    return (EC_TRUE);
}

EC_BOOL cngx_headers_dir3_filter(ngx_http_request_t *r, CHTTP_RSP *chttp_rsp)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *headers;
    ngx_int_t                   idx;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_ADD][NGX_HTTP_BGN_HEADERS_DIR_3];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_rsp_renew_header(chttp_rsp, (const char *)(kv->key.data), (const char *)(kv->value.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: add header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_3];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_rsp_del_header(chttp_rsp, (const char *)(kv->key.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: del header '%s'\n",
                                        (const char *)(kv->key.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_3];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++) 
        {
            ngx_http_bgn_header_kv_t         *kv;
            
            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            chttp_rsp_renew_header(chttp_rsp, (const char *)(kv->key.data), (const char *)(kv->value.data));
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: renew header '%s':'%s'\n",
                                        (const char *)(kv->key.data),
                                        (const char *)(kv->value.data));
        }
    }
    
    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/



