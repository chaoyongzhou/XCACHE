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

EC_BOOL cngx_headers_kv_wash_k(ngx_http_request_t *r, ngx_http_bgn_header_kv_t *kv, ngx_str_t *k)
{
    if(0 != kv->k_final.len && NULL_PTR != kv->k_final.data)
    {
        (*k) = kv->k_final; /*link*/
        return (EC_TRUE);
    }

    if(0 == kv->complex_k_source.len || NULL_PTR == kv->complex_k_source.data)
    {
        return (EC_FALSE); /*give up*/
    }

    if(NULL_PTR == kv->complex_k_lengths || NULL_PTR == kv->complex_k_values)
    {
        return (EC_FALSE); /*give up*/
    }

    if(NULL_PTR == ngx_http_script_run(r, k, kv->complex_k_lengths->elts, 0, kv->complex_k_values->elts))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_kv_wash_k: "
                                "'%.*s' => '%.*s'\n",
                                (size_t)(kv->complex_k_source.len), (const char *)(kv->complex_k_source.data),
                                (size_t)(k->len), (const char *)(k->data));

    return (EC_TRUE);
}

EC_BOOL cngx_headers_kv_wash_v(ngx_http_request_t *r, ngx_http_bgn_header_kv_t *kv, ngx_str_t *v)
{
    if(0 != kv->v_final.len && NULL_PTR != kv->v_final.data)
    {
        (*v) = kv->v_final; /*link*/
        return (EC_TRUE);
    }

    if(0 == kv->complex_v_source.len || NULL_PTR == kv->complex_v_source.data)
    {
        return (EC_FALSE); /*give up*/
    }

    if(NULL_PTR == kv->complex_v_lengths || NULL_PTR == kv->complex_v_values)
    {
        return (EC_FALSE); /*give up*/
    }

    if(NULL_PTR == ngx_http_script_run(r, v, kv->complex_v_lengths->elts, 0, kv->complex_v_values->elts))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_kv_wash_v: "
                                "'%.*s' => '%.*s'\n",
                                (size_t)(kv->complex_v_source.len), (const char *)(kv->complex_v_source.data),
                                (size_t)(v->len), (const char *)(v->data));

    return (EC_TRUE);
}

static ngx_str_t *cngx_headers_kv_get_k(ngx_http_bgn_header_kv_t *kv)
{
    if(0 != kv->k_final.len && NULL_PTR != kv->k_final.data)
    {
        return &(kv->k_final);
    }

    if(0 == kv->complex_k_source.len || NULL_PTR == kv->complex_k_source.data)
    {
        return (NULL_PTR); /*give up*/
    }


    return &(kv->complex_k_source);
}

static ngx_str_t *cngx_headers_kv_get_v(ngx_http_bgn_header_kv_t *kv)
{
    if(0 != kv->v_final.len && NULL_PTR != kv->v_final.data)
    {
        return &(kv->v_final);
    }

    if(0 == kv->complex_v_source.len || NULL_PTR == kv->complex_v_source.data)
    {
        return (NULL_PTR); /*give up*/
    }


    return &(kv->complex_v_source);
}

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
            ngx_str_t                         k;
            ngx_str_t                         v;

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir0_filter: "
                                            "add header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            ngx_http_bgn_set_header_in(r, k, v, 1 /*override*/);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir0_filter: "
                                        "add header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_0];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k))
            {
                ngx_str_t   *__k;

                __k = cngx_headers_kv_get_k(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir0_filter: "
                                            "del header '%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data));
                return (EC_FALSE);
            }

            ngx_http_bgn_del_header_in(r, k);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir0_filter: "
                                        "del header '%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_0];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            ngx_str_t                         v;

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir0_filter: "
                                            "renew header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            ngx_http_bgn_renew_header_in(r, k, v);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir0_filter: "
                                        "renew header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    return (EC_TRUE);
}

EC_BOOL cngx_headers_dir1_filter(ngx_http_request_t *r, CHTTP_REQ *chttp_req)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *headers;
    ngx_int_t                    idx;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_ADD][NGX_HTTP_BGN_HEADERS_DIR_1];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            ngx_str_t                         v;
            char                             *k_str; /*string with null char terminal*/
            char                             *v_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

             /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir1_filter: "
                                            "add header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);
            v_str = c_str_n_dup((char *)v.data, (uint32_t)v.len);

            if(NULL_PTR == k_str
            || NULL_PTR == v_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: "
                                            "add header '%.*s':'%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data),
                                            (size_t)(v.len), (const char *)(v.data));

                c_str_free(k_str);
                c_str_free(v_str);
                return (EC_FALSE);
            }

            chttp_req_renew_header(chttp_req, k_str, v_str);

            c_str_free(k_str);
            c_str_free(v_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: "
                                        "add header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_1];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            char                             *k_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k))
            {
                ngx_str_t   *__k;

                __k = cngx_headers_kv_get_k(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir1_filter: "
                                            "del header '%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);

            if(NULL_PTR == k_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: "
                                            "del header '%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data));

                c_str_free(k_str);
                return (EC_FALSE);
            }

            chttp_req_del_header(chttp_req, k_str);

            c_str_free(k_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: "
                                        "del header '%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_1];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            ngx_str_t                         v;
            char                             *k_str; /*string with null char terminal*/
            char                             *v_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir1_filter: "
                                            "renew header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);
            v_str = c_str_n_dup((char *)v.data, (uint32_t)v.len);

            if(NULL_PTR == k_str
            || NULL_PTR == v_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: "
                                            "renew header '%.*s':'%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data),
                                            (size_t)(v.len), (const char *)(v.data));

                c_str_free(k_str);
                c_str_free(v_str);
                return (EC_FALSE);
            }

            chttp_req_renew_header(chttp_req, k_str, v_str);

            c_str_free(k_str);
            c_str_free(v_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir1_filter: "
                                        "renew header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    return (EC_TRUE);
}

EC_BOOL cngx_headers_dir2_filter(ngx_http_request_t *r, CHTTP_RSP *chttp_rsp)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *headers;
    ngx_int_t                    idx;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_ADD][NGX_HTTP_BGN_HEADERS_DIR_2];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            ngx_str_t                         v;
            char                             *k_str; /*string with null char terminal*/
            char                             *v_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir2_filter: "
                                            "add header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);
            v_str = c_str_n_dup((char *)v.data, (uint32_t)v.len);

            if(NULL_PTR == k_str
            || NULL_PTR == v_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: "
                                            "add header '%.*s':'%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data),
                                            (size_t)(v.len), (const char *)(v.data));

                c_str_free(k_str);
                c_str_free(v_str);
                return (EC_FALSE);
            }

            chttp_rsp_renew_header(chttp_rsp, k_str, v_str);

            c_str_free(k_str);
            c_str_free(v_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: "
                                        "add header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_2];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            char                             *k_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key*/
            if (EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k))
            {
                ngx_str_t   *__k;

                __k = cngx_headers_kv_get_k(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir2_filter: "
                                            "del header '%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);

            if(NULL_PTR == k_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: "
                                            "del header '%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data));

                c_str_free(k_str);
                return (EC_FALSE);
            }

            chttp_rsp_del_header(chttp_rsp, k_str);

            c_str_free(k_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: "
                                        "del header '%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_2];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            ngx_str_t                         v;
            char                             *k_str; /*string with null char terminal*/
            char                             *v_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir2_filter: "
                                            "renew header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);
            v_str = c_str_n_dup((char *)v.data, (uint32_t)v.len);

            if(NULL_PTR == k_str
            || NULL_PTR == v_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: "
                                            "renew header '%.*s':'%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data),
                                            (size_t)(v.len), (const char *)(v.data));

                c_str_free(k_str);
                c_str_free(v_str);
                return (EC_FALSE);
            }

            chttp_rsp_renew_header(chttp_rsp, k_str, v_str);

            c_str_free(k_str);
            c_str_free(v_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir2_filter: "
                                        "renew header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    return (EC_TRUE);
}

EC_BOOL cngx_headers_dir3_filter(ngx_http_request_t *r, CHTTP_RSP *chttp_rsp)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *headers;
    ngx_int_t                    idx;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_ADD][NGX_HTTP_BGN_HEADERS_DIR_3];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            ngx_str_t                         v;
            char                             *k_str; /*string with null char terminal*/
            char                             *v_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir3_filter: "
                                            "add header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);
            v_str = c_str_n_dup((char *)v.data, (uint32_t)v.len);

            if(NULL_PTR == k_str
            || NULL_PTR == v_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: "
                                            "add header '%.*s':'%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data),
                                            (size_t)(v.len), (const char *)(v.data));

                c_str_free(k_str);
                c_str_free(v_str);
                return (EC_FALSE);
            }

            chttp_rsp_renew_header(chttp_rsp, k_str, v_str);

            c_str_free(k_str);
            c_str_free(v_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: "
                                        "add header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_DEL][NGX_HTTP_BGN_HEADERS_DIR_3];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            char                             *k_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key*/
            if (EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k))
            {
                ngx_str_t   *__k;

                __k = cngx_headers_kv_get_k(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir3_filter: "
                                            "del header '%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);

            if(NULL_PTR == k_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: "
                                            "del header '%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data));

                c_str_free(k_str);
                return (EC_FALSE);
            }

            chttp_rsp_del_header(chttp_rsp, k_str);

            c_str_free(k_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: "
                                        "del header '%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data));
        }
    }

    headers = blcf->headers[NGX_HTTP_BGN_HEADERS_OP_RENEW][NGX_HTTP_BGN_HEADERS_DIR_3];
    if(NULL_PTR != headers)
    {
        for (idx = 0; idx < headers->nelts; idx ++)
        {
            ngx_http_bgn_header_kv_t         *kv;
            ngx_str_t                         k;
            ngx_str_t                         v;
            char                             *k_str; /*string with null char terminal*/
            char                             *v_str; /*string with null char terminal*/

            kv = (ngx_http_bgn_header_kv_t *)(headers->elts + idx * headers->size);

            /*wash complex key and value*/
            if(EC_FALSE == cngx_headers_kv_wash_k(r, kv, &k)
            || EC_FALSE == cngx_headers_kv_wash_v(r, kv, &v))
            {
                ngx_str_t   *__k;
                ngx_str_t   *__v;

                __k = cngx_headers_kv_get_k(kv);
                __v = cngx_headers_kv_get_v(kv);

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_headers_dir3_filter: "
                                            "renew header '%.*s':'%.*s' but wash failed\n",
                                            (size_t)(__k->len), (const char *)(__k->data),
                                            (size_t)(__v->len), (const char *)(__v->data));
                return (EC_FALSE);
            }

            k_str = c_str_n_dup((char *)k.data, (uint32_t)k.len);
            v_str = c_str_n_dup((char *)v.data, (uint32_t)v.len);

            if(NULL_PTR == k_str
            || NULL_PTR == v_str)
            {
                dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: "
                                            "renew header '%.*s':'%.*s' but no more memory\n",
                                            (size_t)(k.len), (const char *)(k.data),
                                            (size_t)(v.len), (const char *)(v.data));

                c_str_free(k_str);
                c_str_free(v_str);
                return (EC_FALSE);
            }

            chttp_rsp_renew_header(chttp_rsp, k_str, v_str);

            c_str_free(k_str);
            c_str_free(v_str);

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_headers_dir3_filter: "
                                        "renew header '%.*s':'%.*s'\n",
                                        (size_t)(k.len), (const char *)(k.data),
                                        (size_t)(v.len), (const char *)(v.data));
        }
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/



