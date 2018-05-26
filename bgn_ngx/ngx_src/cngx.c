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

#include "ngx_http_bgn_headers_out.h"
#include "ngx_http_bgn_variable.h"

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"
#include "cmisc.h"

#include "carray.h"
#include "cvector.h"

#include "crb.h"

#include "csocket.h"

#include "chttp.h"
#include "cngx.h"


static CRB_TREE  g_cngx_http_bgn_mod_tree;
static EC_BOOL   g_cngx_http_bgn_mod_tree_init_flag = EC_FALSE;

static const char *g_cngx_default_cache_http_codes_str = "200 203 206 301 401";

static const uint32_t g_cngx_default_cache_http_codes[] = {200, 203, 206, 301, 401};
static UINT32         g_cngx_default_cache_http_codes_num =
      sizeof(g_cngx_default_cache_http_codes)/sizeof(g_cngx_default_cache_http_codes[0]);

CNGX_RANGE *cngx_range_new()
{
    CNGX_RANGE *cngx_range;
    alloc_static_mem(MM_CNGX_RANGE, &cngx_range, LOC_CNGX_0003);
    if(NULL_PTR != cngx_range)
    {
        cngx_range_init(cngx_range);
    }
    return (cngx_range);
}

EC_BOOL cngx_range_init(CNGX_RANGE *cngx_range)
{
    CNGX_RANGE_START(cngx_range)  = 0;
    CNGX_RANGE_END(cngx_range)    = 0;
    return (EC_TRUE);
}

EC_BOOL cngx_range_clean(CNGX_RANGE *cngx_range)
{
    CNGX_RANGE_START(cngx_range)  = 0;
    CNGX_RANGE_END(cngx_range)    = 0;
    return (EC_TRUE);
}

EC_BOOL cngx_range_free(CNGX_RANGE *cngx_range)
{
    if(NULL_PTR != cngx_range)
    {
        cngx_range_clean(cngx_range);
        free_static_mem(MM_CNGX_RANGE, cngx_range, LOC_CNGX_0004);
    }
    return (EC_TRUE);
}

/* --- common interface ----*/
/*copy and revise from ngx_http_range_parse*/
static ngx_int_t __cngx_range_parse(const uint8_t *data, const off_t content_length, const uint32_t max_ranges, CLIST *cngx_ranges)
{
    const uint8_t                *p;
    off_t                         start;
    off_t                         end;
    off_t                         size;
    off_t                         cutoff;
    off_t                         cutlim;

    ngx_uint_t                    suffix;
    uint32_t                      left_ranges;

    p           = data + 6;
    left_ranges = max_ranges;
    size        = 0;

    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;

    for ( ;; ) {
        start = 0;
        end = 0;
        suffix = 0;

        while (*p == ' ') { p++; }

        if (*p != '-') {
            if (*p < '0' || *p > '9') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p >= '0' && *p <= '9') {
                if (start >= cutoff && (start > cutoff || *p - '0' > cutlim)) {
                    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                }

                start = start * 10 + *p++ - '0';
            }

            while (*p == ' ') { p++; }

            if (*p++ != '-') {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while (*p == ' ') { p++; }

            if (*p == ',' || *p == '\0') {
                end = content_length;
                goto found;
            }

        } else {
            suffix = 1;
            p++;
        }

        if (*p < '0' || *p > '9') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        while (*p >= '0' && *p <= '9') {
            if (end >= cutoff && (end > cutoff || *p - '0' > cutlim)) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            end = end * 10 + *p++ - '0';
        }

        while (*p == ' ') { p++; }

        if (*p != ',' && *p != '\0') {
            return NGX_HTTP_RANGE_NOT_SATISFIABLE;
        }

        if (suffix) {
            start = content_length - end;
            end = content_length - 1;
        }

        if (end >= content_length) {
            end = content_length;

        } else {
            end++;
        }

    found:

        if (start < end) {
            CNGX_RANGE      *range;

            range = cngx_range_new();
            if (range == NULL) {
                return NGX_ERROR;
            }

            range->start = start;
            range->end = end;

            clist_push_back(cngx_ranges, (void *)range);

            size += end - start;

            if (left_ranges -- == 0) {
                return NGX_DECLINED;
            }
        }

        if (*p++ != ',') {
            break;
        }
    }

    if (EC_TRUE == clist_is_empty(cngx_ranges)) {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (size > content_length) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/*refer: ngx_http_range_header_filter()*/
EC_BOOL cngx_range_parse(ngx_http_request_t *r, const off_t content_length, CLIST *cngx_ranges)
{
    ngx_http_core_loc_conf_t     *clcf;
    ngx_uint_t                    max_ranges;
    uint8_t                      *ranges_str;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->max_ranges == 0) {
        return (EC_TRUE);
    }

    max_ranges = r->single_range ? 1 : clcf->max_ranges;
    ranges_str = r->headers_in.range->value.data;

    switch (__cngx_range_parse(ranges_str, content_length, max_ranges, cngx_ranges))
    {
        case NGX_OK:
        {
            if (1 == clist_size(cngx_ranges))
            {
                return (EC_TRUE);
            }

            return (EC_TRUE);
        }
        case NGX_HTTP_RANGE_NOT_SATISFIABLE:
        {
            return (EC_FALSE);
        }
        case NGX_ERROR:
        {
            return (EC_FALSE);
        }
        default: /* NGX_DECLINED */
        {
            break;
        }
    }
    return (EC_FALSE);
}

void cngx_range_print(LOG *log, const CNGX_RANGE *cngx_range)
{
    sys_log(log, "cngx_range_print: cngx_range %p: [%ld, %ld)\n",
                 cngx_range, CNGX_RANGE_START(cngx_range), CNGX_RANGE_END(cngx_range));
    return;
}

EC_BOOL cngx_set_header_out_status(ngx_http_request_t *r, const ngx_uint_t status)
{
    r->headers_out.status = status;
    return (EC_TRUE);
}

EC_BOOL cngx_set_header_out_content_length(ngx_http_request_t *r, const uint32_t content_length)
{
    r->headers_out.content_length_n = (off_t)content_length;
    return (EC_TRUE);
}

EC_BOOL cngx_set_header_out_kv(ngx_http_request_t *r, const char *key, const char *val)
{
    ngx_str_t                    ngx_key;
    ngx_str_t                    ngx_val;
    ngx_int_t                    rc;

    ngx_key.data = (u_char *)key;
    ngx_key.len  = CONST_STR_LEN(key);

    ngx_val.data = (u_char *)val;
    ngx_val.len  = CONST_STR_LEN(val);

    rc = ngx_http_bgn_set_header_out(r, ngx_key, ngx_val, 0 /* not override */);
    if(NGX_ERROR == rc)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_header_out_kv: set header %s:%s (error: %d) failed\n",
                          key, val, (int) rc);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_set_header_out_cstrkv(ngx_http_request_t *r, const CSTRKV *cstrkv)
{
    if(EC_FALSE == cngx_set_header_out_kv(r, (const char *)CSTRKV_KEY_STR(cstrkv), (const char *)CSTRKV_VAL_STR(cstrkv)))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT,"error:cngx_set_header_out_cstrkv: set header '%s' = '%s' failed\n",
                    (const char *)CSTRKV_KEY_STR(cstrkv), (const char *)CSTRKV_VAL_STR(cstrkv));
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT,"[DEBUG] cngx_set_header_out_cstrkv: set header '%s' = '%s' done\n",
                (const char *)CSTRKV_KEY_STR(cstrkv), (const char *)CSTRKV_VAL_STR(cstrkv));
    return (EC_TRUE);
}

EC_BOOL cngx_add_header_out_kv(ngx_http_request_t *r, const char *key, const char *val)
{
    ngx_str_t                    ngx_key;
    ngx_str_t                    ngx_val;
    ngx_int_t                    rc;

    ngx_key.data = (u_char *)key;
    ngx_key.len  = CONST_STR_LEN(key);

    ngx_val.data = (u_char *)val;
    ngx_val.len  = CONST_STR_LEN(val);

    rc = ngx_http_bgn_set_header_out(r, ngx_key, ngx_val, 0 /* not override */);
    if(NGX_ERROR == rc)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error: cngx_add_header_out_kv: add header %s:%s (error: %d) failed\n",
                          key, val, (int) rc);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_add_header_out_cstrkv(ngx_http_request_t *r, const CSTRKV *cstrkv)
{
    if(EC_FALSE == cngx_add_header_out_kv(r, (const char *)CSTRKV_KEY_STR(cstrkv), (const char *)CSTRKV_VAL_STR(cstrkv)))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT,"error:cngx_add_header_out_cstrkv: add header '%s' = '%s' failed\n",
                    (const char *)CSTRKV_KEY_STR(cstrkv), (const char *)CSTRKV_VAL_STR(cstrkv));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_del_header_out_key(ngx_http_request_t *r, const char *key)
{
    ngx_str_t                    ngx_key;
    ngx_str_t                    ngx_val;
    ngx_int_t                    rc;

    ngx_key.data = (u_char *)key;
    ngx_key.len  = CONST_STR_LEN(key);

    ngx_val.data = NULL_PTR;
    ngx_val.len  = 0;

    rc = ngx_http_bgn_set_header_out(r, ngx_key, ngx_val, 1 /* override */);
    if(NGX_ERROR == rc)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_del_header_out_key: del header '%s' failed (error: %d)\n",
                          key, (int) rc);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_del_header_out_key: del header '%s'\n", key);

    return (EC_TRUE);
}

/*data will send out without delay*/
EC_BOOL cngx_disable_write_delayed(ngx_http_request_t *r)
{
    r->connection->write->delayed = 0;
    return (EC_TRUE);
}

/*data would send out with delay*/
EC_BOOL cngx_enable_write_delayed(ngx_http_request_t *r)
{
    r->connection->write->delayed = 1;
    return (EC_TRUE);
}

EC_BOOL cngx_disable_postpone_output(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    clcf->postpone_output = 0;
    return (EC_TRUE);
}

EC_BOOL cngx_need_header_only(ngx_http_request_t *r)
{
    if(0 == r->header_only)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*set only header would be sent out without body*/
EC_BOOL cngx_set_header_only(ngx_http_request_t *r)
{
    r->header_only = 1;

    return (EC_TRUE);
}

EC_BOOL cngx_get_var_uint32_t(ngx_http_request_t *r, const char *key, uint32_t *val, const uint32_t def)
{
    ngx_http_variable_value_t   *vv;
    uint32_t                     klen;

    klen = CONST_STR_LEN(key);
    vv = ngx_http_bgn_var_get(r, (const u_char *)key, (size_t)klen);
    if(NULL_PTR == vv || 0 == vv->len || NULL_PTR == vv->data)
    {
        dbg_log(SEC_0176_CNGX, 5)(LOGSTDOUT, "[DEBUG] cngx_get_var_uint32_t: not found var '%s', set to default '%u'\n",
                    key, def);
        (*val) = def;
        return (EC_TRUE);
    }

    (*val) = c_chars_to_uint32_t((const char *) vv->data, (uint32_t)vv->len);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_var_uint32_t: var '%s' = %u\n",
                    key, (*val));

    return (EC_TRUE);
}

EC_BOOL cngx_set_var_uint32_t(ngx_http_request_t *r, const char *key, const uint32_t val)
{
    uint32_t klen;
    uint32_t vlen;
    char    *value;

    klen  = CONST_STR_LEN(key);
    value = c_uint32_t_to_str(val);
    vlen  = CONST_STR_LEN(value);

    if(NGX_OK != ngx_http_bgn_var_set(r, (const u_char *)key, (size_t)klen, (const u_char *)value, (size_t)vlen))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_var_uint32_t: set var '%s' = %u failed\n",
                    key, val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_var_uint32_t: set var '%s' = %u done\n",
                    key, val);

    return (EC_TRUE);
}

EC_BOOL cngx_get_var_size(ngx_http_request_t *r, const char *key, ssize_t *val, const ssize_t def)
{
    ngx_http_variable_value_t   *vv;
    ngx_str_t                    str;
    uint32_t                     klen;

    klen = CONST_STR_LEN(key);
    vv = ngx_http_bgn_var_get(r, (const u_char *)key, (size_t)klen);
    if(NULL_PTR == vv || 0 == vv->len || NULL_PTR == vv->data)
    {
        dbg_log(SEC_0176_CNGX, 5)(LOGSTDOUT, "[DEBUG] cngx_get_var_size: not found var '%s', set to default '%ld'\n",
                    key, def);
        (*val) = def;
        return (EC_TRUE);
    }

    str.len  = vv->len;
    str.data = vv->data;
    (*val) = ngx_parse_size(&str);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_var_size: var '%s' = %ld\n",
                    key, (*val));

    return (EC_TRUE);
}

EC_BOOL cngx_set_var_size(ngx_http_request_t *r, const char *key, const ssize_t val)
{
    uint32_t klen;
    uint32_t vlen;
    char    *value;

    klen  = CONST_STR_LEN(key);
    value = c_int_to_str(val);
    vlen  = CONST_STR_LEN(value);

    if(NGX_OK != ngx_http_bgn_var_set(r, (const u_char *)key, (size_t)klen, (const u_char *)value, (size_t)vlen))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_var_size: set var '%s' = %ld failed\n",
                    key, val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_var_size: set var '%s' = %ld done\n",
                    key, val);

    return (EC_TRUE);
}

EC_BOOL cngx_get_var_switch(ngx_http_request_t *r, const char *key, UINT32 *val, const UINT32 def)
{
    ngx_http_variable_value_t   *vv;

    vv = ngx_http_bgn_var_get(r, (const u_char *)key, (size_t)CONST_STR_LEN(key));
    if(NULL_PTR == vv)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_var_switch: not found var '%s'\n",
                    key);
        (*val) = def;
        return (EC_TRUE);
    }

    if(2 == vv->len && 0 == STRNCASECMP("on", (const char *)vv->data, 2))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_var_switch: var '%s' was switch on\n",
                    key);

        (*val) = SWITCH_ON;
        return (EC_TRUE);
    }

    if(3 == vv->len && 0 == STRNCASECMP("off", (const char *)vv->data, 3))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_var_switch: var '%s' was switch off\n",
                    key);

        (*val) = SWITCH_OFF;
        return (EC_TRUE);
    }

     dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "error:cngx_get_var_switch: var '%s' was set to invalid '%.*s', reset to %s\n",
                    key, vv->len, vv->data, c_switch_to_str(def));

    (*val) = def;
    return (EC_TRUE);
}

EC_BOOL cngx_set_var_switch(ngx_http_request_t *r, const char *key, const UINT32 val)
{
    uint32_t klen;
    uint32_t vlen;
    char    *value;

    klen  = CONST_STR_LEN(key);
    value = c_switch_to_str(val);
    vlen  = CONST_STR_LEN(value);

    if(NGX_OK != ngx_http_bgn_var_set(r, (const u_char *)key, (size_t)klen, (const u_char *)value, (size_t)vlen))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_var_switch: set var '%s' = %s failed\n",
                    key, value);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_var_switch: set var '%s' = %s done\n",
                    key, value);

    return (EC_TRUE);
}

EC_BOOL cngx_get_var_str(ngx_http_request_t *r, const char *key, char **val, const char *def)
{
    ngx_http_variable_value_t   *vv;

    vv = ngx_http_bgn_var_get(r, (const u_char *)key, (size_t)CONST_STR_LEN(key));
    if (NULL_PTR == vv || 0 == vv->len)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_var_str: not found var '%s'\n",
                    key);

        if(NULL_PTR == def)
        {
            (*val) = NULL_PTR;
            return (EC_TRUE);
        }

        (*val) = c_str_dup(def);
        if(NULL_PTR == (*val))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_var_str: get var '%s' failed and dup '%s' failed\n",
                    key, def);
            return (EC_FALSE);
        }

        return (EC_TRUE);
    }

    (*val) = safe_malloc(vv->len + 1, LOC_CNGX_0005);
    if(NULL_PTR == (*val))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_var_str: get var '%s' but malloc %d bytes failed\n",
                    key, vv->len + 1);
        return (EC_FALSE);
    }

    BCOPY(vv->data, (*val), vv->len);
    (*val)[ vv->len ] = 0x00;/*terminate*/

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_var_str: var '%s' = '%s'\n",
                    key, (*val));

    return (EC_TRUE);
}

EC_BOOL cngx_set_var_str(ngx_http_request_t *r, const char *key, const char *val)
{
    uint32_t klen;
    uint32_t vlen;

    klen  = CONST_STR_LEN(key);
    vlen  = CONST_STR_LEN(val);

    if(NGX_OK != ngx_http_bgn_var_set(r, (const u_char *)key, (size_t)klen, (const u_char *)val, (size_t)vlen))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_var_str: set var '%s' = %s failed\n",
                    key, val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_var_str: set var '%s' = %s done\n",
                    key, val);

    return (EC_TRUE);
}

EC_BOOL cngx_del_var_str(ngx_http_request_t *r, const char *key)
{
    uint32_t klen;

    klen  = CONST_STR_LEN(key);

    if(NGX_OK != ngx_http_bgn_var_set(r, (const u_char *)key, (size_t)klen, NULL_PTR, 0))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_del_var_str: del var '%s' failed\n",
                    key);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_del_var_str: set var '%s'done\n",
                    key);

    return (EC_TRUE);
}

EC_BOOL cngx_get_cache_seg_size(ngx_http_request_t *r, uint32_t *cache_seg_size)
{
    const char      *k;
    ssize_t          val;

    k = (const char *)CNGX_VAR_CACHE_SEG_SIZE;
    if(EC_FALSE == cngx_get_var_size(r, k, &val, (ssize_t)CNGX_CACHE_SEG_SIZE_DEFAULT))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_cache_seg_size: "
                                             "get var size of '%s' failed\n",
                                             k);
        (*cache_seg_size) = (uint32_t)CNGX_CACHE_SEG_SIZE_DEFAULT;
        return (EC_FALSE);
    }

    (*cache_seg_size) = (uint32_t)val;
    return (EC_TRUE);
}

EC_BOOL cngx_get_cache_seg_max_num(ngx_http_request_t *r, uint32_t *cache_seg_max_num)
{
    const char      *k;
    uint32_t         val;

    k = (const char *)CNGX_VAR_CACHE_SEG_MAX_NUM;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &val, (uint32_t)CNGX_CACHE_SEG_MAX_NUM_DEFAULT))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_cache_seg_max_num: "
                                             "get var '%s' failed\n",
                                             k);
        (*cache_seg_max_num) = (uint32_t)CNGX_CACHE_SEG_MAX_NUM_DEFAULT;
        return (EC_FALSE);
    }

    (*cache_seg_max_num) = val;
    return (EC_TRUE);
}

EC_BOOL cngx_get_req_method_str(const ngx_http_request_t *r, char **val)
{
    if(0 < r->method_name.len && NULL_PTR != r->method_name.data)
    {
        (*val) = safe_malloc(r->method_name.len + 1, LOC_CNGX_0006);
        if(NULL_PTR == (*val))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_method_str: no memory\n");

            return (EC_FALSE);
        }

        BCOPY(r->method_name.data, (*val), r->method_name.len);
        (*val)[ r->method_name.len ] = 0x00;/*terminate*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_method_str: copy method '%s'\n", (*val));

        return (EC_TRUE);
    }

    switch (r->method)
    {
        case NGX_HTTP_GET:
            (*val) = c_str_dup((const char *)"GET");
            break;

        case NGX_HTTP_POST:
            (*val) = c_str_dup((const char *)"POST");
            break;

        case NGX_HTTP_PUT:
            (*val) = c_str_dup((const char *)"PUT");
            break;

        case NGX_HTTP_HEAD:
            (*val) = c_str_dup((const char *)"HEAD");
            break;

        case NGX_HTTP_DELETE:
            (*val) = c_str_dup((const char *)"DELETE");
            break;

        case NGX_HTTP_OPTIONS:
            (*val) = c_str_dup((const char *)"OPTIONS");
            break;

        case NGX_HTTP_MKCOL:
            (*val) = c_str_dup((const char *)"MKCOL");
            break;

        case NGX_HTTP_COPY:
            (*val) = c_str_dup((const char *)"COPY");
            break;

        case NGX_HTTP_MOVE:
            (*val) = c_str_dup((const char *)"MOVE");
            break;

        case NGX_HTTP_PROPFIND:
            (*val) = c_str_dup((const char *)"PROPFIND");
            break;

        case NGX_HTTP_PROPPATCH:
            (*val) = c_str_dup((const char *)"PROPPATCH");
            break;

        case NGX_HTTP_LOCK:
            (*val) = c_str_dup((const char *)"LOCK");
            break;

        case NGX_HTTP_UNLOCK:
            (*val) = c_str_dup((const char *)"UNLOCK");
            break;

        case NGX_HTTP_PATCH:
            (*val) = c_str_dup((const char *)"PATCH");
            break;

        case NGX_HTTP_TRACE:
            (*val) = c_str_dup((const char *)"TRACE");
            break;

        default:
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_method_str: unsupported HTTP method: %ld\n", r->method);
            (*val) = NULL_PTR;
            return (EC_FALSE);
    }

    if(NULL_PTR == (*val))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_method_str: dup str of method %ld failed\n", r->method);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_get_req_info_debug(ngx_http_request_t *r)
{
    char *v;

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"host", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: host: %s\n", v);
        safe_free(v, LOC_CNGX_0007);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"remote_addr", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: remote_addr: %s\n", v);
        safe_free(v, LOC_CNGX_0008);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"remote_port", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: remote_port: %s\n", v);
        safe_free(v, LOC_CNGX_0009);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_addr", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_addr: %s\n", v);
        safe_free(v, LOC_CNGX_0010);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_port", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_port: %s\n", v);
        safe_free(v, LOC_CNGX_0011);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_protocol", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_protocol: %s\n", v);
        safe_free(v, LOC_CNGX_0012);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_name", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_name: %s\n", v);
        safe_free(v, LOC_CNGX_0013);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"hostname", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: hostname: %s\n", v);
        safe_free(v, LOC_CNGX_0014);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_get_req_uri(const ngx_http_request_t *r, char **val)
{
    if(0 < r->uri.len && NULL_PTR != r->uri.data)
    {
        (*val) = safe_malloc(r->uri.len + 1, LOC_CNGX_0015);
        if(NULL_PTR == (*val))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_uri: no memory\n");

            return (EC_FALSE);
        }

        BCOPY(r->uri.data, (*val), r->uri.len);
        (*val)[ r->uri.len ] = 0x00;/*terminate*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_uri: copy uri '%s'\n", (*val));

        return (EC_TRUE);
    }

    (*val) = NULL_PTR;
    dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_uri: no uri\n");
    return (EC_FALSE);
}

EC_BOOL cngx_get_req_arg(const ngx_http_request_t *r, char **val)
{
    if(0 < r->args.len && NULL_PTR != r->args.data)
    {
        (*val) = safe_malloc(r->args.len + 1, LOC_CNGX_0016);
        if(NULL_PTR == (*val))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_arg: no memory\n");

            return (EC_FALSE);
        }

        BCOPY(r->args.data, (*val), r->args.len);
        (*val)[ r->args.len ] = 0x00;/*terminate*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_arg: copy args '%s'\n", (*val));

        return (EC_TRUE);
    }

    (*val) = NULL_PTR;
    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_arg: no args\n");

    return (EC_TRUE);
}

EC_BOOL cngx_get_req_url(ngx_http_request_t *r, CSTRING *req_url, EC_BOOL need_args)
{
    const char                  *k;
    char                        *v;

    char                        *uri_str;
    char                        *host_str;

    k = (const char *)CNGX_VAR_CACHE_PATH;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                             "get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                             "get var '%s':'%s' done\n",
                                             k, v);

        if('/' == v[0])
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                                 "set store_path to '%s'\n",
                                                 v);
            /*reuse v: move v to cstring without memory allocation*/
            cstring_set_str(req_url, (const uint8_t *)v);
            return (EC_TRUE);
        }

        if(7 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"http://", 7))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                                 "convert 'http://' to '/' and set store_path to '%s'\n",
                                                 v + 6);

            cstring_append_str(req_url, (const uint8_t *)(v + 6));

            safe_free(v, LOC_CNGX_0017);
            return (EC_TRUE);
        }

        if(8 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"https://", 8))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                                 "convert 'https://' to '/' and set store_path to '%s'\n",
                                                 v + 7);

            cstring_append_str(req_url, (const uint8_t *)(v + 7));

            safe_free(v, LOC_CNGX_0018);
            return (EC_TRUE);
        }

        if(EC_FALSE == cstring_format(req_url, "/%s", v))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                                 "format store_path '/%s' failed\n",
                                                 v);
            safe_free(v, LOC_CNGX_0019);
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                             "format store_path '/%s' done\n",
                                             v);
        safe_free(v, LOC_CNGX_0020);

        return (EC_TRUE);
    }


    if(EC_FALSE == cngx_get_req_uri(r, &uri_str))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                             "fetch req uri failed\n");
        return (EC_FALSE);
    }

    //k = (const char *)"server_name";
    k = (const char *)"http_host";
    if(EC_FALSE == cngx_get_var_str(r, k, &host_str, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                             "fetch '%s' failed\n",
                                             k);
        safe_free(uri_str, LOC_CNGX_0021);
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_format(req_url, "/%s%s", host_str, uri_str))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                             "format req_url '/%s%s' failed\n",
                                             host_str, uri_str);
        safe_free(host_str, LOC_CNGX_0022);
        safe_free(uri_str, LOC_CNGX_0023);
        return (EC_FALSE);
    }
    safe_free(host_str, LOC_CNGX_0024);
    safe_free(uri_str, LOC_CNGX_0025);

    if(EC_TRUE == need_args && EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                             "[cngx] get args '%s'\n",
                                             v);

        if(EC_FALSE == cstring_append_str(req_url, (const UINT8 *)"?"))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                                 "[cngx] append '?' failed\n");
            safe_free(v, LOC_CNGX_0026);
            return (EC_FALSE);
        }

        if(EC_FALSE == cstring_append_str(req_url, (const UINT8 *)v))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                                 "[cngx] append args '%s' failed\n",
                                                 v);
            safe_free(v, LOC_CNGX_0027);
            return (EC_FALSE);
        }
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                             "[cngx] append args '%s' done\n",
                                             v);
        safe_free(v, LOC_CNGX_0028);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                         "set req_url '%s' done\n",
                                         (char *)cstring_get_str(req_url));

    return (EC_TRUE);
}

EC_BOOL cngx_rearm_req_uri(ngx_http_request_t *r)
{
    CSTRING    req_url;

    cstring_init(&req_url, NULL_PTR);
    if(EC_FALSE == cngx_get_req_url(r, &req_url, EC_FALSE))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_rearm_req_uri: "
                                             "[cngx] get req url failed\n");
        return (EC_FALSE);
    }

    r->uri.len = (size_t)cstring_get_len(&req_url);

    r->uri.data = ngx_pnalloc(r->pool, r->uri.len);
    if (NULL_PTR == r->uri.data)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_rearm_req_uri: "
                                             "[cngx] ngx_pnalloc (size = %ld) failed\n",
                                             r->uri.len);

        cstring_clean(&req_url);
        return (EC_FALSE);
    }

    ngx_memcpy(r->uri.data, cstring_get_str(&req_url), r->uri.len);

    cstring_clean(&req_url);

    return (EC_TRUE);
}

EC_BOOL cngx_get_req_port(const ngx_http_request_t *r, char **val)
{
    char    *port_start;
    char    *port_end;
    char    *v;

    port_start = NULL_PTR;

    if (NULL_PTR != r->port_start)
    {
        port_start = (char *)(r->port_start);
    }
    else if (NULL_PTR != r->host_end)
    {
        port_start = (char *)(r->host_end + 1);
    }
    else
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_port: "
                                             "not found port_start or host_end\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == r->port_end)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_port: "
                                             "not found port_end\n");
        return (EC_FALSE);
    }

    port_end = (char *)(r->port_end);

    v = c_str_n_dup(port_start, (uint32_t)(port_end - port_start));
    if (NULL_PTR == v)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_port: "
                                             "dup port '%.*s' failed\n",
                                             (uint32_t)(port_end - port_start),
                                             port_start);

        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_port: "
                                         "dup port '%s' done\n",
                                         v);
    (*val) = v;

    return (EC_TRUE);
}

EC_BOOL cngx_discard_req_body(ngx_http_request_t *r)
{
    if(NGX_OK != ngx_http_discard_request_body(r))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

static void __cngx_read_req_body_post(ngx_http_request_t *r)
{
    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] __cngx_read_req_body_post: enter\n");

    if (r->connection->read->timer_set)
    {
        ngx_del_timer(r->connection->read);
    }

    r->main->count --;
    return;
}

EC_BOOL cngx_read_req_body(ngx_http_request_t *r)
{
    ngx_int_t                    rc;

    r->request_body_in_single_buf      = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file      = 1;

    rc = ngx_http_read_client_request_body(r, __cngx_read_req_body_post);

    if(rc >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        return (EC_FALSE);
    }

    if(rc == NGX_AGAIN)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_read_req_body: not support 'NGX_AGAIN' yet\n");
        return (EC_FALSE);
    }

    if(rc == NGX_OK)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_read_req_body: 'NGX_OK'\n");

        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_read_req_body: unknown rc '%ld'\n", rc);

    return (EC_FALSE);
}

EC_BOOL cngx_get_req_body(ngx_http_request_t *r, CBYTES *body)
{
    ngx_chain_t                 *cl;

    if (r->request_body == NULL || r->request_body->temp_file || r->request_body->bufs == NULL)
    {
        return (EC_TRUE);
    }

    for (cl = r->request_body->bufs; cl; cl = cl->next)
    {
        if(EC_FALSE == cbytes_append(body, (const UINT8 *)cl->buf->pos, (UINT32)(cl->buf->last - cl->buf->pos)))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_body: append %ld bytes to body failed\n",
                                (UINT32)(cl->buf->last - cl->buf->pos));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cngx_is_debug_switch_on(ngx_http_request_t *r)
{
    return cngx_has_header_in(r, (const char *)CNGX_BGN_MOD_DBG_SWITCH_HDR, (const char *)"on");
}

EC_BOOL cngx_is_method(ngx_http_request_t *r, const char *method)
{
    char *req_method;

    if(EC_FALSE == cngx_get_req_method_str(r, &req_method))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_is_method: get req method str failed\n");
        return (EC_FALSE);
    }

    if(0 == STRCASECMP(req_method, method))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_method: method is '%s'\n",
                        req_method);

        safe_free(req_method, LOC_CNGX_0029);
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_method: method '%s' != '%s'\n",
                    req_method, method);

    safe_free(req_method, LOC_CNGX_0030);
    return (EC_FALSE);
}

EC_BOOL cngx_is_head_method(ngx_http_request_t *r)
{
    if(NGX_HTTP_HEAD == r->method)
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cngx_is_cacheable_method(ngx_http_request_t *r)
{
    char *cache_http_method;
    char *req_method;

    if(EC_FALSE == cngx_get_req_method_str(r, &req_method))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_is_cacheable_method: get req method str failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_get_var_str(r, (const char *)CNGX_VAR_CACHE_HTTP_METHOD, &cache_http_method, NULL_PTR)
    || NULL_PTR == cache_http_method)
    {
        const char      *cache_http_method_default;

        dbg_log(SEC_0176_CNGX, 5)(LOGSTDOUT, "warn:cngx_is_cacheable_method: not set variable '%s'\n",
                    (const char *)CNGX_VAR_CACHE_HTTP_METHOD);

        /*default GET is cacheable*/
        cache_http_method_default = (const char *)"GET";
        if(EC_FALSE == c_str_is_in(req_method, (const char *)":;, ", cache_http_method_default))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_cacheable_method: '%s' not in '%s' => not cachable\n",
                        req_method, cache_http_method_default);

            safe_free(req_method, LOC_CNGX_0031);
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_cacheable_method: '%s' is in '%s' => cachable\n",
                        req_method, cache_http_method_default);
        safe_free(req_method, LOC_CNGX_0032);
        return (EC_TRUE);
    }

    if(EC_FALSE == c_str_is_in(req_method, (const char *)":;, ", cache_http_method))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_cacheable_method: '%s' not in '%s' => not cachable\n",
                    req_method, cache_http_method);

        safe_free(req_method, LOC_CNGX_0033);
        safe_free(cache_http_method, LOC_CNGX_0034);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_cacheable_method: '%s' in '%s' => cachable\n",
                    req_method, cache_http_method);

    safe_free(req_method, LOC_CNGX_0035);
    safe_free(cache_http_method, LOC_CNGX_0036);

    return (EC_TRUE);
}

EC_BOOL cngx_is_direct_orig_switch_on(ngx_http_request_t *r)
{
    const char                  *k;
    UINT32                       v;

    k = (const char *)CNGX_VAR_DIRECT_ORIG_SWITCH;
    cngx_get_var_switch(r, k, &v, SWITCH_OFF);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_direct_orig_switch_on: "
                                         "get var '%s':'%s' done\n",
                                         k, c_switch_to_str(v));

    return (SWITCH_OFF == v) ? EC_FALSE : EC_TRUE;
}

/*force to orig*/
EC_BOOL cngx_is_force_orig_switch_on(ngx_http_request_t *r)
{
    const char                  *k;
    UINT32                       v;

    k = (const char *)CNGX_VAR_ORIG_FORCE_SWITCH;
    cngx_get_var_switch(r, k, &v, SWITCH_OFF);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_force_orig_switch_on: "
                                         "get var '%s':'%s' done\n",
                                         k, c_switch_to_str(v));

    return (SWITCH_OFF == v) ? EC_FALSE : EC_TRUE;
}

/*direct to orig for ims request*/
EC_BOOL cngx_is_direct_ims_switch_on(ngx_http_request_t *r)
{
    const char                  *k;
    UINT32                       v;

    k = (const char *)CNGX_VAR_DIRECT_IMS_SWITCH;
    cngx_get_var_switch(r, k, &v, SWITCH_OFF);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_direct_ims_switch_on: "
                                         "get var '%s':'%s' done\n",
                                         k, c_switch_to_str(v));

    return (SWITCH_OFF == v) ? EC_FALSE : EC_TRUE;
}

/*merge rsp header to client*/
EC_BOOL cngx_is_merge_header_switch_on(ngx_http_request_t *r)
{
    const char                  *k;
    UINT32                       v;

    k = (const char *)CNGX_VAR_HEADER_MERGE_SWITCH;
    cngx_get_var_switch(r, k, &v, SWITCH_OFF);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_merge_header_switch_on: "
                                         "get var '%s':'%s' done\n",
                                         k, c_switch_to_str(v));

    return (SWITCH_OFF == v) ? EC_FALSE : EC_TRUE;
}

/*carry on header Connection:keep-alive or not in http request to orig server*/
EC_BOOL cngx_is_orig_keepalive_switch_on(ngx_http_request_t *r)
{
    const char                  *k;
    UINT32                       v;

    k = (const char *)CNGX_VAR_ORIG_KEEPALIVE_SWITCH;
    cngx_get_var_switch(r, k, &v, SWITCH_ON);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_orig_keepalive_switch_on: "
                                         "get var '%s':'%s' done\n",
                                         k, c_switch_to_str(v));

    return (SWITCH_ON == v) ? EC_TRUE : EC_FALSE;
}

EC_BOOL cngx_set_chunked(ngx_http_request_t *r)
{
    r->chunked = 1;
    return (EC_TRUE);
}

EC_BOOL cngx_set_keepalive(ngx_http_request_t *r)
{
    r->keepalive = 1;
    return (EC_TRUE);
}

EC_BOOL cngx_disable_keepalive(ngx_http_request_t *r)
{
    r->keepalive = 0;
    return (EC_TRUE);
}

EC_BOOL cngx_get_flv_start(ngx_http_request_t *r, UINT32 *flv_start)
{
    if(r->args.len)
    {
        ngx_str_t           value;

        if(ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK)
        {
            off_t           start;

            start = ngx_atoof(value.data, value.len);

            if(start == NGX_ERROR)
            {
                start = 0;
            }

            if(0 < start)
            {
                (*flv_start) = (UINT32)(start);
                return (EC_TRUE);
            }
        }
    }

    (*flv_start) = 0;

    return (EC_TRUE);
}

EC_BOOL cngx_get_mp4_start_length(ngx_http_request_t *r, UINT32 *mp4_start, UINT32 *mp4_length)
{
    ngx_int_t                  start;
    ngx_uint_t                 length;

    start  = -1;
    length = 0;

    if (r->args.len)
    {
        ngx_str_t                  value;

        if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK)
        {
            /*
             * A Flash player may send start value with a lot of digits
             * after dot so strtod() is used instead of atofp().  NaNs and
             * infinities become negative numbers after (int) conversion.
             */

            ngx_set_errno(0);
            start = (int) (strtod((char *) value.data, NULL) * 1000);

            if (ngx_errno != 0)
            {
                start = -1;
            }
        }

        if (ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK)
        {
            ngx_int_t                  end;

            ngx_set_errno(0);
            end = (int) (strtod((char *) value.data, NULL) * 1000);

            if (ngx_errno != 0)
            {
                end = -1;
            }

            if (end > 0)
            {
                if (start < 0)
                {
                    start = 0;
                }

                if (end > start)
                {
                    length = end - start;
                }
            }
        }
    }

    if(start < 0)
    {
        return (EC_FALSE);
    }

    (*mp4_start)  = (UINT32)start;
    (*mp4_length) = (UINT32)length;

    return (EC_TRUE);
}

EC_BOOL cngx_get_redirect_specific(ngx_http_request_t *r, const uint32_t src_rsp_status, uint32_t *des_rsp_status, char **des_redirect_url)
{
    const char      *k;
    char            *v;
    char            *spec[ 8 ];
    UINT32           spec_num;
    UINT32           spec_idx;

    k = (const char *)CNGX_VAR_ORIG_REDIRECT_SPECIFIC;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_redirect_specific: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_redirect_specific: "
                                             "cngx not found '%s'\n",
                                             k);

        (*des_rsp_status)   = CHTTP_STATUS_NONE;
        (*des_redirect_url) = NULL_PTR;

        return (EC_TRUE);
    }

    spec_num = c_str_split(v, (const char *)" \t|", (char **)spec, sizeof(spec)/sizeof(spec[0]));
    if(0 == spec_num)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_redirect_specific: "
                                             "cngx found '%s':'%s' but it is empty\n",
                                             k, v);

        (*des_rsp_status)   = CHTTP_STATUS_NONE;
        (*des_redirect_url) = NULL_PTR;

        safe_free(v, LOC_CNGX_0037);
        return (EC_TRUE);
    }

    for(spec_idx = 0; spec_idx < spec_num; spec_idx ++)
    {
        char        *field[ 3 ];

        if(3 != c_str_split(spec[ spec_idx ], (const char *)" \t=>", (char **)field, 3))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_redirect_specific: "
                                                 "cngx found '%s':'%s' invalid => ignore\n",
                                                 k, spec[ spec_idx ]);

            (*des_rsp_status)   = CHTTP_STATUS_NONE;
            (*des_redirect_url) = NULL_PTR;

            safe_free(v, LOC_CNGX_0038);
            return (EC_TRUE);
        }

      dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_redirect_specific: "
                                             "cngx '%s' => '%s','%s','%s' \n",
                                             k, field[0], field[1], field[2]);

        if(src_rsp_status == c_str_to_uint32_t(field[ 0 ]))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_redirect_specific: "
                                                 "cngx '%s' matched status %u\n",
                                                 k, src_rsp_status);

            (*des_rsp_status)   = c_str_to_uint32_t(field[ 1 ]);
            if(0 == (*des_rsp_status))
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_redirect_specific: "
                                                     "cngx '%s' => des status %u is invalid => ignore\n",
                                                     k, (*des_rsp_status));
                (*des_rsp_status)   = CHTTP_STATUS_NONE;
                (*des_redirect_url) = NULL_PTR;

                safe_free(v, LOC_CNGX_0039);
                return (EC_TRUE);
            }

            (*des_redirect_url) = c_str_dup(field[ 2 ]);
            if(NULL_PTR == (*des_redirect_url))
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_redirect_specific: "
                                                     "cngx '%s' => dup str '%s' failed\n",
                                                     k, field[ 2 ]);
                (*des_rsp_status)   = CHTTP_STATUS_NONE;
                (*des_redirect_url) = NULL_PTR;

                safe_free(v, LOC_CNGX_0040);
                return (EC_FALSE);
            }

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG]cngx_get_redirect_specific: "
                                                 "cngx '%s' => status %u, redirect url '%s'\n",
                                                 k, (*des_rsp_status), (*des_redirect_url));
            safe_free(v, LOC_CNGX_0041);
            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_redirect_specific: "
                                         "cngx '%s' => no matched => ignore\n",
                                         k);

    (*des_rsp_status)   = CHTTP_STATUS_NONE;
    (*des_redirect_url) = NULL_PTR;

    safe_free(v, LOC_CNGX_0042);

    return (EC_TRUE);
}

/*copy response status and headers from chttp_rsp to r*/
EC_BOOL cngx_import_header_out(ngx_http_request_t *r, const CHTTP_RSP *chttp_rsp)
{
    cngx_set_header_out_status(r, (const ngx_uint_t)CHTTP_RSP_STATUS(chttp_rsp));

    if(EC_FALSE == cstrkv_mgr_walk(CHTTP_RSP_HEADER(chttp_rsp), (void *)r,
                            (CSTRKV_MGR_WALKER)cngx_set_header_out_cstrkv))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_import_header_out: import headers failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*for debug*/
EC_BOOL cngx_export_method(const ngx_http_request_t *r, CHTTP_REQ *chttp_req)
{
    char *req_method;

    if(EC_FALSE == cngx_get_req_method_str(r, &req_method))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_export_method: get req method str failed\n");
        return (EC_FALSE);
    }

    chttp_req_set_method(chttp_req, req_method);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_export_method: set chttp_req method: '%s'\n",
                    req_method);

    safe_free(req_method, LOC_CNGX_0043);

    return (EC_TRUE);
}

/*for debug*/
EC_BOOL cngx_export_uri(const ngx_http_request_t *r, CHTTP_REQ *chttp_req)
{
    char *req_uri;
    char *req_arg;

    if(EC_FALSE == cngx_get_req_uri(r, &req_uri) || NULL_PTR == req_uri)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_export_uri: get req uri str failed\n");
        return (EC_FALSE);
    }

    chttp_req_set_uri(chttp_req, req_uri);
    safe_free(req_uri, LOC_CNGX_0044);

    if(EC_FALSE == cngx_get_req_arg(r, &req_arg))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_export_uri: get req arg str failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != req_arg)
    {
        chttp_req_set_uri(chttp_req, (const char *)"?");
        chttp_req_set_uri(chttp_req, req_arg);
        safe_free(req_arg, LOC_CNGX_0045);
    }

    return (EC_TRUE);
}


/*ref: ngx_http_lua_ngx_req_get_headers()*/
/*copy header from r to chttp_req*/
EC_BOOL cngx_export_header_in(const ngx_http_request_t *r, CHTTP_REQ *chttp_req)
{
    const ngx_list_part_t        *part;
    const ngx_table_elt_t        *header;
    ngx_uint_t                    i;
    int                           count = 0;

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    while(part->next)
    {
        part   = part->next;
        count += part->nelts;
    }

    part   = &(r->headers_in.headers.part);
    header = part->elts;

    for(i = 0; /* void */; i++)
    {
        if(i >= part->nelts)
        {
            if(NULL_PTR == part->next)
            {
                break;
            }

            part   = part->next;
            header = part->elts;
            i = 0;
        }

        if(NULL_PTR != header[i].key.data   && 0 < header[i].key.len
        && NULL_PTR != header[i].value.data && 0 < header[i].value.len)
        {
            if(EC_FALSE == chttp_req_add_header_chars(chttp_req,
                                (const char *)header[i].key.data  , (uint32_t)header[i].key.len,
                                (const char *)header[i].value.data, (uint32_t)header[i].value.len))
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_export_header_in: add request header: '%.*s': '%.*s' failed\n",
                        (uint32_t)header[i].key.len, (const char *)header[i].key.data,
                        (uint32_t)header[i].value.len, (const char *)header[i].value.data);
                return (EC_FALSE);
            }

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_export_header_in: add request header: '%.*s': '%.*s'\n",
                        (uint32_t)header[i].key.len, (const char *)header[i].key.data,
                        (uint32_t)header[i].value.len, (const char *)header[i].value.data);
        }

        if(0 == --count)
        {
            return (EC_TRUE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cngx_has_header_in_key(const ngx_http_request_t *r, const char *k)
{
    const ngx_list_part_t        *part;
    const ngx_table_elt_t        *header;

    uint32_t                      klen;

    ngx_uint_t                    i;
    int                           count = 0;

    klen  = strlen(k);

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    while(part->next)
    {
        part   = part->next;
        count += part->nelts;
    }

    part   = &(r->headers_in.headers.part);
    header = part->elts;

    for(i = 0; /* void */; i++)
    {
        if(i >= part->nelts)
        {
            if(NULL_PTR == part->next)
            {
                break;
            }

            part   = part->next;
            header = part->elts;
            i = 0;
        }

        if(klen == (uint32_t)header[i].key.len
        && 0 == STRNCASECMP(k, (const char *)header[i].key.data, klen))
        {
            return (EC_TRUE);
        }

        if(0 == --count)
        {
            return (EC_FALSE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cngx_has_header_in(const ngx_http_request_t *r, const char *k, const char *v)
{
    const ngx_list_part_t        *part;
    const ngx_table_elt_t        *header;

    uint32_t                      klen;
    uint32_t                      vlen;

    ngx_uint_t                    i;
    int                           count = 0;

    klen  = strlen(k);
    vlen  = strlen(v);

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    while(part->next)
    {
        part   = part->next;
        count += part->nelts;
    }

    part   = &(r->headers_in.headers.part);
    header = part->elts;

    for(i = 0; /* void */; i++)
    {
        if(i >= part->nelts)
        {
            if(NULL_PTR == part->next)
            {
                break;
            }

            part   = part->next;
            header = part->elts;
            i = 0;
        }

        if(klen == (uint32_t)header[i].key.len
        && vlen == (uint32_t)header[i].value.len
        && 0 == STRNCASECMP(k, (const char *)header[i].key.data, klen)
        && 0 == STRNCASECMP(v, (const char *)header[i].value.data, vlen)
        )
        {
            return (EC_TRUE);
        }

        if(0 == --count)
        {
            return (EC_FALSE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cngx_get_header_in(const ngx_http_request_t *r, const char *k, char **v)
{
    const ngx_list_part_t        *part;
    const ngx_table_elt_t        *header;

    uint32_t                      klen;
    uint32_t                      vlen;

    ngx_uint_t                    i;
    int                           count = 0;

    klen  = strlen(k);
    (*v)  = NULL_PTR;

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    while(part->next)
    {
        part   = part->next;
        count += part->nelts;
    }

    part   = &(r->headers_in.headers.part);
    header = part->elts;

    for(i = 0; /* void */; i++)
    {
        if(i >= part->nelts)
        {
            if(NULL_PTR == part->next)
            {
                break;
            }

            part   = part->next;
            header = part->elts;
            i = 0;
        }

        if(klen == (uint32_t)header[i].key.len
        && 0 == STRNCASECMP(k, (const char *)header[i].key.data, klen))
        {
            vlen = (uint32_t)header[i].value.len;
            (*v) = safe_malloc(vlen + 1, LOC_CNGX_0046);
            if(NULL_PTR == (*v))
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_header_in: "
                                                     "get header_in '%s' but malloc %d bytes failed\n",
                                                     k, vlen + 1);
                return (EC_FALSE);
            }

            BCOPY(header[i].value.data, (*v), vlen);
            (*v)[ vlen ] = 0x00;/*terminate*/
            return (EC_TRUE);
        }

        if(0 == --count)
        {
            return (EC_TRUE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cngx_set_cache_status(ngx_http_request_t *r, const char *cache_status)
{
    const char                  *k;
    const char                  *v;

    k = (const char *)CNGX_VAR_CACHE_STATUS;
    v = (const char *)cache_status;

    if(EC_FALSE == cngx_set_var_str(r, k, v))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_cache_status: "
                                             "cngx set var '%s':'%s' failed\n",
                                             k, v);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_cache_status: "
                                         "cngx set var '%s':'%s' done\n",
                                         k, v);
    return (EC_TRUE);
}

EC_BOOL cngx_finalize(ngx_http_request_t *r, ngx_int_t status)
{
    ngx_http_finalize_request(r, status);
    return (EC_TRUE);
}

EC_BOOL cngx_send_wait(ngx_http_request_t *r, ngx_msec_t send_timeout)
{
    ngx_connection_t          *c;
    ngx_event_t               *wev;

    COROUTINE_COND            *coroutine_cond;
    EC_BOOL                    ret;

    c = r->connection;
    wev = c->write;
#if 0
    if(0 == send_timeout)
    {
        return (EC_TRUE);
    }
#endif
    coroutine_cond = coroutine_cond_new((UINT32)send_timeout, LOC_CNGX_0047);
    if(NULL_PTR == coroutine_cond)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_wait: "
                                             "new coroutine_cond failed\n");
        return (EC_FALSE);
    }

    NGX_W_COROUTINE_COND(wev) = coroutine_cond;

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_send_wait: "
                                         "coroutine_cond %p on r:%p, c:%p, wev:%p <= start\n",
                                         coroutine_cond, r, c, wev);

    coroutine_cond_reserve(coroutine_cond, 1, LOC_CNGX_0048);
    ret = coroutine_cond_wait(coroutine_cond, LOC_CNGX_0049);

    __COROUTINE_CATCH_EXCEPTION() { /*exception*/
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_wait: "
                                             "coroutine_cond %p on r:%p, c:%p, wev:%p => cancelled\n",
                                             coroutine_cond, r, c, wev);
        coroutine_cond_free(coroutine_cond, LOC_CNGX_0050);
        NGX_W_COROUTINE_COND(wev) = NULL_PTR;
    }__COROUTINE_TERMINATE();

    if(NULL_PTR != NGX_W_COROUTINE_COND(wev))/*double confirm its validity for safe reason*/
    {
        coroutine_cond_free(coroutine_cond, LOC_CNGX_0051);
        NGX_W_COROUTINE_COND(wev) = NULL_PTR;
    }

    if(EC_TRUE != ret) /*ret maybe EC_TRUE, EC_FALSE, EC_TIMEOUT, EC_TERMINATE, etc.*/
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_wait: "
                                             "coroutine_cond %p on r:%p, c:%p, wev:%p => back but ret = %ld\n",
                                             coroutine_cond, r, c, wev, ret);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_wait: "
                                         "coroutine_cond %p on r:%p, c:%p, wev:%p => back\n",
                                         coroutine_cond, r, c, wev);
    return (EC_TRUE);
}

void cngx_send_again(ngx_http_request_t *r)
{
    ngx_connection_t          *c;
    ngx_event_t               *wev;

    ngx_int_t                  rc;

    c = r->connection;
    wev = c->write;

    rc = ngx_http_output_filter(r, NULL_PTR);

    NGX_W_RC(wev) = rc;

    if(NULL_PTR != NGX_W_COROUTINE_COND(wev))
    {
        coroutine_cond_release_all(NGX_W_COROUTINE_COND(wev), LOC_CNGX_0052);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_again: "
                                         "r %p, rc = %ld, timer_set = %d, delayed = %d, sent bytes = %ld\n",
                                         r, rc, wev->timer_set, wev->delayed, r->connection->sent);
    return;
}

EC_BOOL cngx_send_blocking(ngx_http_request_t *r)
{
    ngx_connection_t          *c;
    ngx_event_t               *wev;

    ngx_http_core_loc_conf_t  *clcf;
    ngx_msec_t                 send_timeout;

    c = r->connection;
    wev = c->write;

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_blocking: "
                                         "r:%p, c:%p, wev:%p\n",
                                         r, r->connection, r->connection->write);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if(0 < clcf->send_timeout)
    {
        send_timeout = clcf->send_timeout; /*default is 60s*/
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_blocking: "
                                             "set send_timeout to clcf->send_timeout %ld ms\n",
                                             clcf->send_timeout);
    }
    else
    {
        /*should never reach here due to ngx would set clcf->send_timeout to default 60s*/
        send_timeout = 60 * 1000; /*set to default 60s */
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_blocking: "
                                             "set send_timeout to default %ld ms\n",
                                             clcf->send_timeout);    
    }
    
    r->write_event_handler = cngx_send_again;

    NGX_W_RC(wev) = NGX_AGAIN;
    while(NGX_AGAIN == NGX_W_RC(wev))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_blocking: "
                                             "[delayed: %d, timer_set: %d, active %d, ready: %d]\n",
                                             wev->delayed, wev->timer_set, wev->active, wev->ready);

        wev->delayed = 0; /*clear*/

        if(0 == wev->timer_set)/*if no timer, set WR event*/
        {
            /*clear active flag and ready flag. otherwise, WR event would not be set to epoll*/

            wev->active = 0;
            wev->ready  = 0;

            if(ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK)
            {
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_blocking: "
                                                     "add write event failed\n");

                if(wev->timer_set)
                {
                    wev->delayed = 0;
                    ngx_del_timer(wev);
                }

                return (EC_FALSE);
            }
            wev->ready  = 1;

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_blocking: "
                                                 "add write event done\n");
        }

        /*--- blocking ---*/
        if(EC_FALSE == cngx_send_wait(r, send_timeout))
        {
            NGX_W_RC(wev) = NGX_ERROR;

            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_blocking: "
                                                 "wait back, connection error: %d, reset rc to %ld\n",
                                                 c->error, NGX_W_RC(wev));
            break;
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_blocking: "
                                             "wait back, connection error: %d, rc: %ld\n",
                                             c->error, NGX_W_RC(wev));
    }

    if(wev->timer_set)
    {
        wev->delayed = 0;
        ngx_del_timer(wev);
    }

    if(NGX_ERROR == NGX_W_RC(wev))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_blocking: "
                                             "send failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_blocking: "
                                         "send done\n");
    return (EC_TRUE);
}

EC_BOOL cngx_send_header(ngx_http_request_t *r, ngx_int_t *ngx_rc)
{
    ngx_int_t rc;

    cngx_disable_postpone_output(r);/*dangerous?*/

    rc = ngx_http_send_header(r);
    (*ngx_rc) = rc;
    if (rc == NGX_ERROR || rc > NGX_OK || r->post_action)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_header: send header failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_header: send header done\n");
    return (EC_TRUE);
}

EC_BOOL cngx_need_send_header(ngx_http_request_t *r)
{
    if(r->header_sent)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

static EC_BOOL __cngx_set_buf_flags(ngx_buf_t *b, const unsigned flags)
{
    if(CNGX_SEND_BODY_IN_MEM_FLAG & flags)
    {
        b->memory = 1;
    }

    if(CNGX_SEND_BODY_NO_MORE_FLAG & flags)
    {
        b->last_buf = 1;
    }

    if(CNGX_SEND_BODY_FLUSH_FLAG & flags)
    {
        b->flush = 1;
    }

    if(CNGX_SEND_BODY_RECYCLED_FLAG & flags)
    {
        b->recycled = 1;
    }
    //b->last_in_chain = 1; /*xxx*/

    return (EC_TRUE);
}

EC_BOOL cngx_send_body(ngx_http_request_t *r, const uint8_t *body, const uint32_t len, const unsigned flags, ngx_int_t *ngx_rc)
{
    ngx_chain_t                  cl;
    ngx_buf_t                   *b;
    ngx_int_t                    rc;

    if(NULL_PTR == body || 0 == len)
    {
        ngx_buf_t   empty_buf;

        b = &empty_buf;

        /*refer HPCC-40 in cs_chimney3.txt*/

        memset(b, 0, sizeof(ngx_buf_t));
        /*all flags are cleared*/

        /*set flags*/
        __cngx_set_buf_flags(b, flags);

        cl.buf  = b;
        cl.next = NULL_PTR;

        rc = ngx_http_output_filter(r, &cl);
        (*ngx_rc) = rc;

        if (rc == NGX_ERROR || rc > NGX_OK)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body: send body failed, rc = %ld\n", rc);
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: send none body done\n");
        return (EC_TRUE);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (NULL_PTR == b)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body: alloc %u bytes failed\n", len);

        (*ngx_rc) = NGX_ERROR;
        return (EC_FALSE);
    }

    b->last = ngx_cpymem(b->last, (u_char *) body, len);

    /*set flags*/
    __cngx_set_buf_flags(b, flags);

    cl.buf  = b;
    cl.next = NULL_PTR;

    rc = ngx_http_output_filter(r, &cl);
    (*ngx_rc) = rc;

    if (rc == NGX_ERROR || rc > NGX_OK)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body: send body failed\n");
        return (EC_FALSE);
    }

    if(rc == NGX_AGAIN/* || b->last > b->pos + NGX_LUA_OUTPUT_BLOCKING_LOWAT*/)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: sent bytes = %ld, need send body again\n",
                    r->connection->sent);

        return cngx_send_blocking(r);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: send body done\n");

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_cache_rsp_headers(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    char            *v;

    k = (const char *)CNGX_VAR_CACHE_RSP_HEADERS;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_rsp_headers: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_rsp_headers: "
                                             "cngx var '%s' not found => ignore\n",
                                             k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_rsp_headers: "
                                         "cngx var '%s':'%s' done\n",
                                         k, v);
    cstring_set_str(CHTTP_STORE_CACHE_RSP_HEADERS(chttp_store), (const uint8_t *)v);

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_ncache_rsp_headers(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    char            *v;

    k = (const char *)CNGX_VAR_NCACHE_RSP_HEADERS;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_ncache_rsp_headers: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_ncache_rsp_headers: "
                                             "cngx var '%s' not found => ignore\n",
                                             k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_ncache_rsp_headers: "
                                         "cngx var '%s':'%s' done\n",
                                         k, v);
    cstring_set_str(CHTTP_STORE_NCACHE_RSP_HEADERS(chttp_store), (const uint8_t *)v);

    return (EC_TRUE);
}

static EC_BOOL __cngx_status_code_is_in_strs(const uint32_t status_code, const char **cache_http_codes, const UINT32 num)
{
    UINT32 pos;

    for(pos = 0; pos < num; pos ++)
    {
        const char *cache_http_code;

        cache_http_code = cache_http_codes[ pos ];

        if(EC_FALSE == c_char_is_in_ignore_case('X', cache_http_code, strlen(cache_http_code)))
        {
            if(c_str_to_uint32_t(cache_http_code) == status_code)
            {
                return (EC_TRUE);
            }

            continue;
        }

        /*else*/

        if(c_str_to_uint32_t_ireplace(cache_http_code, 'X', 0) <= status_code /*replace 'X' or 'x' with 0*/
        && c_str_to_uint32_t_ireplace(cache_http_code, 'X', 9) >= status_code /*replace 'X' or 'x' with 9*/
        )
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

EC_BOOL cngx_set_store_cache_http_codes(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    char            *v;

    char            *cache_http_codes_str;
    char            *cache_http_codes[ 32 ];

    char             lost_codes_str[ 32 ];
    UINT32           lost_codes_pos;

    UINT32           num;
    UINT32           idx;

    k = (const char *)CNGX_VAR_CACHE_HTTP_CODES;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_http_codes: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }
    if(NULL_PTR == v)
    {
        const char *def;

        def = g_cngx_default_cache_http_codes_str;
        cstring_append_str(CHTTP_STORE_CACHE_HTTP_CODES(chttp_store), (const uint8_t *)def);

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_http_codes: "
                                             "cngx var '%s' not found => set default '%s' by force\n",
                                             k, def);
        return (EC_TRUE);
    }

    /*append default cache http codes to var if necessary*/

    cache_http_codes_str = c_str_dup(v);
    if(NULL_PTR == cache_http_codes_str)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_http_codes: "
                                             "dup str '%s' failed\n",
                                             v);
        safe_free(v, LOC_CNGX_0053);
        return (EC_FALSE);
    }

    num = sizeof(cache_http_codes)/sizeof(cache_http_codes[0]);
    num = c_str_split(cache_http_codes_str, (const char *)"; ", (char **)cache_http_codes, num);

    lost_codes_pos = 0;
    for(idx = 0; idx < g_cngx_default_cache_http_codes_num; idx ++)
    {
        uint32_t status_code;

        status_code = g_cngx_default_cache_http_codes[ idx ];

        if(EC_FALSE == __cngx_status_code_is_in_strs(status_code, (const char **)cache_http_codes, num))
        {
            lost_codes_pos += snprintf((char *)lost_codes_str + lost_codes_pos,
                                        sizeof(lost_codes_str) - lost_codes_pos,
                                        " %u", status_code);
        }
    }
    safe_free(cache_http_codes_str, LOC_CNGX_0054);

    if(0 == lost_codes_pos)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_http_codes: "
                                             "cngx var '%s':'%s' done\n",
                                             k, v);
        cstring_set_str(CHTTP_STORE_CACHE_HTTP_CODES(chttp_store), (const uint8_t *)v);

        return (EC_TRUE);
    }

    cache_http_codes_str = c_str_cat(v, (const char *)lost_codes_str);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_http_codes: "
                                         "cngx var '%s':'%s', add lost default '%s' => '%s' done\n",
                                         k, v, (char *)lost_codes_str, cache_http_codes_str);

    safe_free(v, LOC_CNGX_0055);

    cstring_set_str(CHTTP_STORE_CACHE_HTTP_CODES(chttp_store), (const uint8_t *)cache_http_codes_str);

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_ncache_http_codes(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    char            *v;

    k = (const char *)CNGX_VAR_NCACHE_HTTP_CODES;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_ncache_http_codes: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_ncache_http_codes: "
                                             "cngx var '%s' not found => ignore\n",
                                             k);
        return (EC_TRUE);
    }
    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_ncache_http_codes: "
                                         "cngx var '%s':'%s' done\n",
                                         k, v);
    cstring_set_str(CHTTP_STORE_NCACHE_HTTP_CODES(chttp_store), (const uint8_t *)v);

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_expires_cache_code(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    char            *v;

    /*e.g., 200=3600*/
    k = (const char *)CNGX_VAR_ORIG_EXPIRES_CACHE_CODE;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_expires_cache_code: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_expires_cache_code: "
                                             "cngx var '%s' not found => ignore\n",
                                             k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_expires_cache_code: "
                                         "cngx var '%s':'%s' done\n",
                                         k, v);
    cstring_set_str(CHTTP_STORE_CACHE_IF_HTTP_CODES(chttp_store), (const uint8_t *)v);

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_expires_override(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    uint32_t         n;

    k = (const char *)CNGX_VAR_ORIG_EXPIRES_OVERRIDE_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, 0))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_expires_override: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }
    if(0 != n)
    {
        CHTTP_STORE_OVERRIDE_EXPIRES_FLAG(chttp_store) = BIT_TRUE; /*not override header 'Expires'*/
        CHTTP_STORE_OVERRIDE_EXPIRES_NSEC(chttp_store) = n;
    }
    else
    {
        CHTTP_STORE_OVERRIDE_EXPIRES_FLAG(chttp_store) = BIT_FALSE; /*override header 'Expires'*/
        CHTTP_STORE_OVERRIDE_EXPIRES_NSEC(chttp_store) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_expires_default(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    uint32_t         n;
    uint32_t         m;

    m = 1 * 24 * 60; /*default: one day*/
    k = (const char *)CNGX_VAR_ORIG_EXPIRES_DEFAULT_NMIN;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, m))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_expires_default: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    CHTTP_STORE_DEFAULT_EXPIRES_NSEC(chttp_store) = n * 60; /*convert minutes to seconds*/

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_orig_timeout: "
                                         "cngx var '%s':'%u' done\n",
                                         k, n);
    return (EC_TRUE);
}

EC_BOOL cngx_set_store_orig_timeout(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    uint32_t         n;

    k = (const char *)CNGX_VAR_ORIG_TIMEOUT_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, (uint32_t)CHTTP_SOCKET_TIMEOUT_NSEC))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_orig_timeout: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    CHTTP_STORE_ORIG_TIMEOUT_NSEC(chttp_store) = n;

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_orig_timeout: "
                                         "cngx var '%s':'%u' done\n",
                                         k, n);

    return (EC_TRUE);
}

#if 0
EC_BOOL cngx_set_store_merge_lock_expires(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    uint32_t         n;

    k = (const char *)CNGX_VAR_MERGE_LOCK_EXPIRES_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, (uint32_t)60))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_merge_lock_expires: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    CHTTP_STORE_MERGE_LOCK_EXPIRES_NSEC(chttp_store) = n;

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_merge_lock_expires: "
                                         "cngx var '%s':'%u' done\n",
                                         k, n);

    return (EC_TRUE);
}
#endif
EC_BOOL cngx_set_store_merge_wait_timeout(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    uint32_t         n;

    k = (const char *)CNGX_VAR_MERGE_WAIT_TIMEOUT_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, (uint32_t)60))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_merge_wait_timeout: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    CHTTP_STORE_MERGE_WAIT_TIMEOUT_NSEC(chttp_store) = n;
    CHTTP_STORE_MERGE_LOCK_EXPIRES_NSEC(chttp_store) = n + 1; /*add one more second*/

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_merge_wait_timeout: "
                                         "cngx var '%s':'%u' done\n",
                                         k, n);

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_redirect_max_times(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    const char      *k;
    uint32_t         n;

    k = (const char *)CNGX_VAR_ORIG_REDIRECT_MAX_TIMES;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, CNGX_ORIG_REDIRECT_TIMES_DEFAULT))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_redirect_max_times: "
                                             "cngx get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }
    if(0 != n)
    {
        CHTTP_STORE_REDIRECT_CTRL(chttp_store)      = BIT_TRUE;
        CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store) = n;
    }
    else
    {
        CHTTP_STORE_REDIRECT_CTRL(chttp_store)      = BIT_FALSE;
        CHTTP_STORE_REDIRECT_MAX_TIMES(chttp_store) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_set_store_cache_path(ngx_http_request_t *r, CSTRING *store_path)
{
    const char                  *k;
    char                        *v;

    char                        *uri_str;
    char                        *host_str;

    k = (const char *)CNGX_VAR_CACHE_PATH;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                             "get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                             "get var '%s':'%s' done\n",
                                             k, v);

        if('/' == v[0])
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                                 "set store_path to '%s'\n",
                                                 v);
            /*reuse v: move v to cstring without memory allocation*/
            cstring_set_str(store_path, (const uint8_t *)v);
            return (EC_TRUE);
        }

        if(7 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"http://", 7))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                                 "convert 'http://' to '/' and set store_path to '%s'\n",
                                                 v + 6);

            cstring_append_str(store_path, (const uint8_t *)(v + 6));

            safe_free(v, LOC_CNGX_0056);
            return (EC_TRUE);
        }

        if(8 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"https://", 8))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                                 "convert 'https://' to '/' and set store_path to '%s'\n",
                                                 v + 7);

            cstring_append_str(store_path, (const uint8_t *)(v + 7));

            safe_free(v, LOC_CNGX_0057);
            return (EC_TRUE);
        }

        if(EC_FALSE == cstring_format(store_path, "/%s", v))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                                 "format store_path '/%s' failed\n",
                                                 v);
            safe_free(v, LOC_CNGX_0058);
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                             "format store_path '/%s' done\n",
                                             v);
        safe_free(v, LOC_CNGX_0059);

        return (EC_TRUE);
    }

    if(EC_FALSE == cngx_get_req_uri(r, &uri_str))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                             "fetch req uri failed\n");
        return (EC_FALSE);
    }

    /*uri len is 0 or 1, i.e. uri is empty or uri == '/'*/
    if((0x00 == uri_str[ 0 ]) || (0x00 == uri_str[ 1 ]))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                             "fetched req uri is '%s'\n",
                                             uri_str);
        safe_free(uri_str, LOC_CNGX_0060);
        return (EC_FALSE);
    }

    //k = (const char *)"server_name";
    k = (const char *)"http_host";
    if(EC_FALSE == cngx_get_var_str(r, k, &host_str, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                             "fetch '%s' failed\n",
                                             k);
        safe_free(uri_str, LOC_CNGX_0061);
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_format(store_path, "/%s%s", host_str, uri_str))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                             "format store_path '/%s%s' failed\n",
                                             host_str, uri_str);
        safe_free(host_str, LOC_CNGX_0062);
        safe_free(uri_str, LOC_CNGX_0063);
        return (EC_FALSE);
    }
    safe_free(host_str, LOC_CNGX_0064);
    safe_free(uri_str, LOC_CNGX_0065);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                         "set store_path '%s' done\n",
                                         (char *)cstring_get_str(store_path));

    return (EC_TRUE);
}

/*config store*/
EC_BOOL cngx_set_store(ngx_http_request_t *r, CHTTP_STORE *chttp_store)
{
    if(EC_FALSE == cngx_set_store_cache_http_codes(r, chttp_store)
    || EC_FALSE == cngx_set_store_ncache_http_codes(r, chttp_store)
    || EC_FALSE == cngx_set_store_cache_rsp_headers(r, chttp_store)
    || EC_FALSE == cngx_set_store_ncache_rsp_headers(r, chttp_store)
    || EC_FALSE == cngx_set_store_expires_cache_code(r, chttp_store)
    || EC_FALSE == cngx_set_store_expires_override(r, chttp_store)
    || EC_FALSE == cngx_set_store_expires_default(r, chttp_store)
    || EC_FALSE == cngx_set_store_orig_timeout(r, chttp_store)
    //|| EC_FALSE == cngx_set_store_merge_lock_expires(r, chttp_store)
    || EC_FALSE == cngx_set_store_merge_wait_timeout(r, chttp_store)
    || EC_FALSE == cngx_set_store_redirect_max_times(r, chttp_store)
    )
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_option_init(CNGX_OPTION *cngx_option)
{
    BSET(cngx_option, 0, sizeof(CNGX_OPTION));
    return (EC_TRUE);
}

EC_BOOL cngx_option_clean(CNGX_OPTION *cngx_option)
{
    BSET(cngx_option, 0, sizeof(CNGX_OPTION));
    return (EC_TRUE);
}

EC_BOOL cngx_option_set_cacheable_method(ngx_http_request_t *r, CNGX_OPTION *cngx_option)
{
    /*cache for GET or HEAD only*/
    if(NGX_HTTP_GET != r->method && NGX_HTTP_HEAD != r->method)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_get_cacheable_method: not acceptable method '%ld' => set false\n",
                    r->method);

        CNGX_OPTION_CACHEABLE_METHOD(cngx_option) = BIT_FALSE;
        return (EC_TRUE);
    }

    /*check ngx conf*/
    if(EC_FALSE == cngx_is_cacheable_method(r))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_get_cacheable_method: not cachable method => set false\n");

        CNGX_OPTION_CACHEABLE_METHOD(cngx_option) = BIT_FALSE;
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_get_cacheable_method: OK, cachable method => set true\n");

    CNGX_OPTION_CACHEABLE_METHOD(cngx_option) = BIT_TRUE;
    return (EC_TRUE);
}

EC_BOOL cngx_option_set_only_if_cached(ngx_http_request_t *r, CNGX_OPTION *cngx_option)
{
    if(EC_TRUE == cngx_has_header_in(r, (const char *)"Cache-Control", (const char *)"only-if-cached"))
    {
        CNGX_OPTION_ONLY_IF_CACHED(cngx_option)  = BIT_TRUE;

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_set_only_if_cached: "
                                             "found only-if-cached => true\n");
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_set_only_if_cached: "
                                         "not found only-if-cached => false\n");
    return (EC_TRUE);
}

/*------------------------------ NGX BGN MODULE MANAGEMENT ------------------------------*/
CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_new()
{
    CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod;
    alloc_static_mem(MM_CNGX_HTTP_BGN_MOD, &cngx_http_bgn_mod, LOC_CNGX_0066);
    if(NULL_PTR != cngx_http_bgn_mod)
    {
        cngx_http_bgn_mod_init(cngx_http_bgn_mod);
    }
    return (cngx_http_bgn_mod);
}

EC_BOOL cngx_http_bgn_mod_init(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod)
{
    CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod) = NULL_PTR;
    cstring_init(CNGX_HTTP_BGN_MOD_DL_PATH(cngx_http_bgn_mod), NULL_PTR);

    cstring_init(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod), NULL_PTR);
    CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod)   = MD_END;

    CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod)   = 0;

    CNGX_HTTP_BGN_MOD_REG(cngx_http_bgn_mod)    = NULL_PTR;
    CNGX_HTTP_BGN_MOD_UNREG(cngx_http_bgn_mod)  = NULL_PTR;
    CNGX_HTTP_BGN_MOD_START(cngx_http_bgn_mod)  = NULL_PTR;
    CNGX_HTTP_BGN_MOD_END(cngx_http_bgn_mod)    = NULL_PTR;
    CNGX_HTTP_BGN_MOD_GETRC(cngx_http_bgn_mod)  = NULL_PTR;
    CNGX_HTTP_BGN_MOD_HANDLE(cngx_http_bgn_mod) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL cngx_http_bgn_mod_clean(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod)
{
    if(NULL_PTR != CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod))
    {
        dlclose(CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod));
        CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod) = NULL_PTR;
    }
    cstring_clean(CNGX_HTTP_BGN_MOD_DL_PATH(cngx_http_bgn_mod));

    cstring_clean(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod));
    CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod)   = MD_END;

    CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod)   = 0;

    CNGX_HTTP_BGN_MOD_REG(cngx_http_bgn_mod)    = NULL_PTR;
    CNGX_HTTP_BGN_MOD_UNREG(cngx_http_bgn_mod)  = NULL_PTR;
    CNGX_HTTP_BGN_MOD_START(cngx_http_bgn_mod)  = NULL_PTR;
    CNGX_HTTP_BGN_MOD_END(cngx_http_bgn_mod)    = NULL_PTR;
    CNGX_HTTP_BGN_MOD_GETRC(cngx_http_bgn_mod)  = NULL_PTR;
    CNGX_HTTP_BGN_MOD_HANDLE(cngx_http_bgn_mod) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL cngx_http_bgn_mod_free(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod)
{
    if(NULL_PTR != cngx_http_bgn_mod)
    {
        cngx_http_bgn_mod_clean(cngx_http_bgn_mod);
        free_static_mem(MM_CNGX_HTTP_BGN_MOD, cngx_http_bgn_mod, LOC_CNGX_0067);
    }
    return (EC_TRUE);
}

EC_BOOL cngx_http_bgn_mod_hash(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod)
{
    if(0 == CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod))
    {
        CSTRING     *name;
        UINT32       hash;

        name = CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod);
        hash = CNGX_HTTP_BGN_MOD_NAME_HASH(CSTRING_STR(name), CSTRING_LEN(name));

        CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod) = hash;
    }
    return (EC_TRUE);
}

EC_BOOL cngx_http_bgn_mod_set_name(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod, const char *name, const uint32_t len)
{
    if(EC_FALSE == cstring_set_chars(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod), (const UINT8 *)name, (UINT32)len))
    {
        dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "warn:cngx_http_bgn_mod_set_name: set '%.*s'failed\n",
                                             len, name);
        return (EC_FALSE);
    }

    cngx_http_bgn_mod_hash(cngx_http_bgn_mod);

    return (EC_TRUE);
}

void cngx_http_bgn_mod_print(LOG *log, const CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod)
{
    sys_log(log, "cngx_http_bgn_mod_print: cngx_http_bgn_mod %p: type %ld, name '%s', hash %ld\n",
                 cngx_http_bgn_mod,
                 CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod),
                 (char *)cstring_get_str(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod)),
                 CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod));
    return;
}

int cngx_http_bgn_mod_cmp(const CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_1st, const CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_2nd)
{
#if 0
    if(CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod_1st) > CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod_2nd))
    {
        return (1);
    }

    if(CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod_1st) < CNGX_HTTP_BGN_MOD_TYPE(cngx_http_bgn_mod_2nd))
    {
        return (-1);
    }
#endif
    if(CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod_1st) > CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod_2nd))
    {
        return (1);
    }

    if(CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod_1st) < CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod_2nd))
    {
        return (-1);
    }

    return cstring_cmp(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod_1st), CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod_1st));
}

EC_BOOL cngx_http_bgn_mod_table_init()
{
    if(EC_FALSE == g_cngx_http_bgn_mod_tree_init_flag)
    {
        crb_tree_init(&g_cngx_http_bgn_mod_tree,
                      (CRB_DATA_CMP  )cngx_http_bgn_mod_cmp,
                      (CRB_DATA_FREE )cngx_http_bgn_mod_free,
                      (CRB_DATA_PRINT)cngx_http_bgn_mod_print);

        g_cngx_http_bgn_mod_tree_init_flag = EC_TRUE;
    }
    return (EC_TRUE);
}

EC_BOOL cngx_http_bgn_mod_table_add(CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod)
{
    CRB_NODE    *crb_node;

    cngx_http_bgn_mod_table_init();/*trick*/

    ASSERT(0 < CNGX_HTTP_BGN_MOD_HASH(cngx_http_bgn_mod));

    crb_node = crb_tree_insert_data(&g_cngx_http_bgn_mod_tree, (void *)cngx_http_bgn_mod);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_add: add mod '%s' failed\n",
                                (char *)cstring_get_str(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod)));
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cngx_http_bgn_mod)/*found duplicate*/
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_add: duplicate mod '%s'\n",
                                (char *)cstring_get_str(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod)));
        return (EC_FALSE);/*xxx*/
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_http_bgn_mod_table_add: add mod '%s' done\n",
                            (char *)cstring_get_str(CNGX_HTTP_BGN_MOD_NAME(cngx_http_bgn_mod)));
    return (EC_TRUE);
}

CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_table_search(const char *name, const uint32_t len)
{
    CRB_NODE          *crb_node;

    CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod;
    CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_searched;

    cngx_http_bgn_mod_table_init();/*trick*/

    cngx_http_bgn_mod = cngx_http_bgn_mod_new();
    if(NULL_PTR == cngx_http_bgn_mod)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_search: new cngx_http_bgn_mod failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cngx_http_bgn_mod_set_name(cngx_http_bgn_mod, name, len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_search: set mod '%.*s' failed\n",
                                             len, name);
        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*searched by name*/
    crb_node = crb_tree_search_data(&g_cngx_http_bgn_mod_tree, (void *)cngx_http_bgn_mod);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    cngx_http_bgn_mod_free(cngx_http_bgn_mod);

    cngx_http_bgn_mod_searched = CRB_NODE_DATA(crb_node);
    return (cngx_http_bgn_mod_searched);
}

CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_table_get(const char *name, const uint32_t len)
{
    CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod;

    cngx_http_bgn_mod = cngx_http_bgn_mod_table_search(name, len);
    if(NULL_PTR == cngx_http_bgn_mod)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_get: not found mod '%.*s'\n",
                                            len, name);
        return (NULL_PTR);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_http_bgn_mod_table_get: get mod '%.*s' done\n",
                                        len, name);
    return (cngx_http_bgn_mod);
}

EC_BOOL cngx_http_bgn_mod_table_del(const char *name, const uint32_t len)
{
    CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod;

    cngx_http_bgn_mod_table_init();/*trick*/

    cngx_http_bgn_mod = cngx_http_bgn_mod_new();
    if(NULL_PTR == cngx_http_bgn_mod)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_del: new cngx_http_bgn_mod failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_bgn_mod_set_name(cngx_http_bgn_mod, name, len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_del: set mod '%.*s' failed\n",
                                             len, name);
        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (EC_FALSE);
    }

    /*search and delete by name*/
    if(EC_FALSE == crb_tree_delete_data(&g_cngx_http_bgn_mod_tree, (void *)cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_table_del: del mod '%.*s' failed\n",
                                             len, name);
        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (EC_FALSE);
    }

    cngx_http_bgn_mod_free(cngx_http_bgn_mod);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_http_bgn_mod_table_del: del mod '%.*s' done\n",
                                         len, name);
    return (EC_TRUE);
}

void cngx_http_bgn_mod_table_print(LOG *log)
{
    sys_log(log, "cngx_http_bgn_mod_table_print: g_cngx_http_bgn_mod_tree:\n");
    crb_tree_print(log, &g_cngx_http_bgn_mod_tree);

    return;
}

CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod_dl_load(const char *so_path, const uint32_t so_path_len, const char *mod_name, const uint32_t mod_name_len)
{
    CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod;

    CSTRING           *dl_path;
    char               func_name[ CNGX_HTTP_BGN_MOD_FUNC_NAME_MAX_SIZE ];

    cngx_http_bgn_mod = cngx_http_bgn_mod_table_search(mod_name, mod_name_len);
    if(NULL_PTR != cngx_http_bgn_mod)
    {
        dbg_log(SEC_0176_CNGX, 5)(LOGSTDOUT, "info:cngx_http_bgn_mod_dl_load: module '%.*s' exist already\n",
                                            mod_name_len, mod_name);
        return (cngx_http_bgn_mod);
    }

    cngx_http_bgn_mod = cngx_http_bgn_mod_new();
    if(NULL_PTR == cngx_http_bgn_mod)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: new cngx_http_bgn_mod failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cngx_http_bgn_mod_set_name(cngx_http_bgn_mod, mod_name, mod_name_len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: set '%.*s' to cngx_http_bgn_mod failed\n",
                                             mod_name_len, mod_name);
        return (NULL_PTR);
    }

    /* load */
    if(NULL_PTR == so_path || 0 == so_path_len)
    {
        dl_path = CNGX_HTTP_BGN_MOD_DL_PATH(cngx_http_bgn_mod);

        if(EC_FALSE == cstring_format(dl_path, (const char *)"%s/lib%.*s.so",
                                      (char *)CNGX_BGN_MOD_SO_PATH_DEFAULT,
                                      mod_name_len, mod_name))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: format string '%s/%.*s.so' failed\n",
                                                (char *)CNGX_BGN_MOD_SO_PATH_DEFAULT,
                                                mod_name_len, mod_name);
            cngx_http_bgn_mod_free(cngx_http_bgn_mod);
            return (NULL_PTR);
        }
    }
    else
    {
        dl_path = CNGX_HTTP_BGN_MOD_DL_PATH(cngx_http_bgn_mod);

        if(EC_FALSE == cstring_format(dl_path, (const char *)"%.*s/lib%.*s.so",
                                      so_path_len, so_path,
                                      mod_name_len, mod_name))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: format string '%.*s/%.*s.so' failed\n",
                                                so_path_len, so_path,
                                                mod_name_len, mod_name);
            cngx_http_bgn_mod_free(cngx_http_bgn_mod);
            return (NULL_PTR);
        }
    }

    CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod) = dlopen((char *)cstring_get_str(dl_path), RTLD_LAZY);
    if(NULL_PTR == CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: load '%s' failed, err = '%s'\n",
                                            (char *)cstring_get_str(dl_path),
                                            dlerror());

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*load reg interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_reg", mod_name_len, mod_name);
    CNGX_HTTP_BGN_MOD_REG(cngx_http_bgn_mod) = (CNGX_HTTP_BGN_MOD_REG_FUNC)dlsym(
                                                    CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod),
                                                    (const char *)func_name);

    if(NULL_PTR == CNGX_HTTP_BGN_MOD_REG(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: not found '%s' in '%s', err = '%s'\n",
                                            (char *)func_name,
                                            (char *)cstring_get_str(dl_path),
                                            dlerror());

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*load unreg interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_unreg", mod_name_len, mod_name);
    CNGX_HTTP_BGN_MOD_UNREG(cngx_http_bgn_mod) = (CNGX_HTTP_BGN_MOD_REG_FUNC)dlsym(
                                                      CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod),
                                                      (const char *)func_name);

    if(NULL_PTR == CNGX_HTTP_BGN_MOD_UNREG(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: not found '%s' in '%s', err = '%s'\n",
                                            (char *)func_name,
                                            (char *)cstring_get_str(dl_path),
                                            dlerror());

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*load start interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_start", mod_name_len, mod_name);
    CNGX_HTTP_BGN_MOD_START(cngx_http_bgn_mod) = (CNGX_HTTP_BGN_MOD_START_FUNC)dlsym(
                                                        CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_HTTP_BGN_MOD_START(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: not found '%s' in '%s', err = '%s'\n",
                                            (char *)func_name,
                                            (char *)cstring_get_str(dl_path),
                                            dlerror());

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*load end interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_end", mod_name_len, mod_name);
    CNGX_HTTP_BGN_MOD_END(cngx_http_bgn_mod) = (CNGX_HTTP_BGN_MOD_END_FUNC)dlsym(
                                                        CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_HTTP_BGN_MOD_END(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: not found '%s' in '%s', err = '%s'\n",
                                            (char *)func_name,
                                            (char *)cstring_get_str(dl_path),
                                            dlerror());

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*load get_ngx_rc interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_get_ngx_rc", mod_name_len, mod_name);
    CNGX_HTTP_BGN_MOD_GETRC(cngx_http_bgn_mod) = (CNGX_HTTP_BGN_MOD_GETRC_FUNC)dlsym(
                                                        CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_HTTP_BGN_MOD_GETRC(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: not found '%s' in '%s', err = '%s'\n",
                                            (char *)func_name,
                                            (char *)cstring_get_str(dl_path),
                                            dlerror());

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*load content_handler interface*/
    snprintf(func_name, sizeof(func_name), "%.*s""_content_handler", mod_name_len, mod_name);
    CNGX_HTTP_BGN_MOD_HANDLE(cngx_http_bgn_mod) = (CNGX_HTTP_BGN_MOD_HANDLE_FUNC)dlsym(
                                                        CNGX_HTTP_BGN_MOD_DL_LIB(cngx_http_bgn_mod),
                                                        (const char *)func_name);

    if(NULL_PTR == CNGX_HTTP_BGN_MOD_HANDLE(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: not found '%s' in '%s', err = '%s'\n",
                                            (char *)func_name,
                                            (char *)cstring_get_str(dl_path),
                                            dlerror());

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    /*register module*/
    if(EC_FALSE == CNGX_HTTP_BGN_MOD_REG(cngx_http_bgn_mod)())
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: call reg in '%s' failed\n",
                                            (char *)cstring_get_str(dl_path));

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    if(EC_FALSE == cngx_http_bgn_mod_table_add(cngx_http_bgn_mod))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_load: add bgn module '%.*s' to table failed\n",
                                            mod_name_len, mod_name);

        cngx_http_bgn_mod_free(cngx_http_bgn_mod);
        return (NULL_PTR);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_http_bgn_mod_dl_load: load bgn module '%.*s' done\n",
                                        mod_name_len, mod_name);
    return (cngx_http_bgn_mod);
}

EC_BOOL cngx_http_bgn_mod_dl_unload(const char *name, const uint32_t len)
{
    CNGX_HTTP_BGN_MOD *cngx_http_bgn_mod;

    /*for debug reason, check it*/
    cngx_http_bgn_mod = cngx_http_bgn_mod_table_search(name, len);
    if(NULL_PTR != cngx_http_bgn_mod)
    {
        dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "warn:cngx_http_bgn_mod_dl_unload: module '%.*s' not exist\n",
                                             len, name);
        return (EC_TRUE);
    }

    /*unregister module*/
    if(NULL_PTR != CNGX_HTTP_BGN_MOD_UNREG(cngx_http_bgn_mod)
    && EC_FALSE == CNGX_HTTP_BGN_MOD_UNREG(cngx_http_bgn_mod)())
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_unload: call unreg of '%s' failed\n",
                                            (char *)name);

        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_http_bgn_mod_table_del(name, len))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_http_bgn_mod_dl_unload: unload mod '%.*s' failed\n",
                                             len, name);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_http_bgn_mod_dl_unload: unload mod '%.*s' done\n",
                                         len, name);
    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
