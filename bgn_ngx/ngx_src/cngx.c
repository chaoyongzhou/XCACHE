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
#include "cbytes.h"

#include "crb.h"

#include "csocket.h"

#include "chttp.h"
#include "cngx.h"


static const char *g_cngx_default_cache_http_codes_str = "200 203 206 301 401";

static const uint32_t g_cngx_default_cache_http_codes[] = {200, 203, 206, 301, 401};
static UINT32         g_cngx_default_cache_http_codes_num =
      sizeof(g_cngx_default_cache_http_codes)/sizeof(g_cngx_default_cache_http_codes[0]);

CNGX_RANGE *cngx_range_new()
{
    CNGX_RANGE *cngx_range;
    alloc_static_mem(MM_CNGX_RANGE, &cngx_range, LOC_CNGX_0001);
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
        free_static_mem(MM_CNGX_RANGE, cngx_range, LOC_CNGX_0002);
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

EC_BOOL cngx_set_ngx_str(ngx_http_request_t *r, const char *str, const uint32_t len, ngx_str_t *des)
{
    if(r != NULL && r->pool != NULL
    && str != NULL && len > 0
    && des != NULL)
    {
        des->data = ngx_pcalloc(r->pool, len);
        if(des->data == NULL)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_ngx_str: alloc %u bytes failed\n",
                                                 len);
            return (EC_FALSE);
        }
        ngx_memcpy(des->data, (u_char *)str, len);
        des->len  = len;

        return (EC_TRUE);
    }

    return (EC_FALSE);
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

    /*clone key*/
    if(EC_FALSE == cngx_set_ngx_str(r, key, CONST_STR_LEN(key), &ngx_key))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_header_out_kv: clone key of '%s:%s' failed\n",
                                             key, val);
        return (EC_FALSE);
    }

    /*clone val*/
    if(EC_FALSE == cngx_set_ngx_str(r, val, CONST_STR_LEN(val), &ngx_val))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_header_out_kv: clone val of '%s:%s' failed\n",
                                             key, val);
        return (EC_FALSE);
    }

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

    /*clone key*/
    if(EC_FALSE == cngx_set_ngx_str(r, key, CONST_STR_LEN(key), &ngx_key))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_add_header_out_kv: clone key of '%s:%s' failed\n",
                                             key, val);
        return (EC_FALSE);
    }

    /*clone val*/
    if(EC_FALSE == cngx_set_ngx_str(r, val, CONST_STR_LEN(val), &ngx_val))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_add_header_out_kv: clone val of '%s:%s' failed\n",
                                             key, val);
        return (EC_FALSE);
    }

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

    /*clone key*/
    if(EC_FALSE == cngx_set_ngx_str(r, key, CONST_STR_LEN(key), &ngx_key))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_add_header_out_kv: clone key '%s' failed\n",
                                             key);
        return (EC_FALSE);
    }

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

    (*val) = c_str_n_dup((char *)vv->data, vv->len);
    if(NULL_PTR == (*val))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_var_str: get var '%s' but dup '.*s' failed\n",
                    key, vv->len, (char *)vv->data);
        return (EC_FALSE);
    }

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

EC_BOOL cngx_has_var(ngx_http_request_t *r, const char *key)
{
    ngx_http_variable_value_t   *vv;

    vv = ngx_http_bgn_var_get(r, (const u_char *)key, (size_t)CONST_STR_LEN(key));
    if (NULL_PTR == vv || 0 == vv->len)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_has_var: not found var '%s'\n",
                                             key);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_has_var: found var '%s'\n",
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

EC_BOOL cngx_get_client_body_max_size(ngx_http_request_t *r, uint32_t *client_body_max_size)
{
    const char      *k;
    ssize_t          val;

    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    k = (const char *)CNGX_VAR_SEND_BODY_MAX_SIZE_NBYTES;
    if(EC_TRUE == cngx_get_var_size(r, k, &val, (ssize_t)(clcf->client_max_body_size)))
    {
        (*client_body_max_size) = (uint32_t)val;
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_client_body_max_size: "
                                         "not configure '%s', set as default %u\n",
                                         k, (uint32_t)CNGX_SEND_BODY_MAX_SIZE_DEFAULT);
    (*client_body_max_size) = (uint32_t)CNGX_SEND_BODY_MAX_SIZE_DEFAULT;
    return (EC_FALSE);
}

EC_BOOL cngx_get_req_method_str(const ngx_http_request_t *r, char **val)
{
    if(0 < r->method_name.len && NULL_PTR != r->method_name.data)
    {
        (*val) = safe_malloc(r->method_name.len + 1, LOC_CNGX_0003);
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
        safe_free(v, LOC_CNGX_0004);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"remote_addr", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: remote_addr: %s\n", v);
        safe_free(v, LOC_CNGX_0005);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"remote_port", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: remote_port: %s\n", v);
        safe_free(v, LOC_CNGX_0006);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_addr", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_addr: %s\n", v);
        safe_free(v, LOC_CNGX_0007);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_port", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_port: %s\n", v);
        safe_free(v, LOC_CNGX_0008);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_protocol", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_protocol: %s\n", v);
        safe_free(v, LOC_CNGX_0009);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"server_name", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: server_name: %s\n", v);
        safe_free(v, LOC_CNGX_0010);
    }

    if(EC_TRUE == cngx_get_var_str(r, (const char *)"hostname", &v, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_info_debug: hostname: %s\n", v);
        safe_free(v, LOC_CNGX_0011);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_get_root(const ngx_http_request_t *r, char **val)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if(0 < clcf->root.len && NULL_PTR != clcf->root.data)
    {
        (*val) = safe_malloc(clcf->root.len + 1, LOC_CNGX_0012);
        if(NULL_PTR == (*val))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_root: no memory\n");

            return (EC_FALSE);
        }

        BCOPY(clcf->root.data, (*val), clcf->root.len);
        (*val)[ clcf->root.len ] = 0x00;/*terminate*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_root: copy root '%s'\n", (*val));

        return (EC_TRUE);
    }

    (*val) = NULL_PTR;
    dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_root: no root\n");
    return (EC_FALSE);
}

EC_BOOL cngx_get_req_host(const ngx_http_request_t *r, char **val)
{
    const char                  *k;

    if(NULL_PTR != r->host_start
    && NULL_PTR != r->host_end
    && r->host_start < r->host_end)
    {
        uint32_t        vlen;

        vlen = r->host_end - r->host_start;
        (*val) = safe_malloc(vlen, LOC_CNGX_0013);
        if(NULL_PTR == (*val))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_host: no memory\n");

            return (EC_FALSE);
        }

        BCOPY(r->host_start, (*val), vlen);
        (*val)[ vlen ] = 0x00;/*terminate*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_host: "
                                             "copy host '%s'\n", (*val));

        return (EC_TRUE);
    }

    k = (const char *)"Host";
    if(EC_FALSE == cngx_get_header_in(r, k, val))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_host: "
                                             "get '%s' failed\n",
                                             k);
        (*val) = NULL_PTR;
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_host: "
                                         "get '%s':'%s'\n", k, (*val));
    return (EC_TRUE);
}

EC_BOOL cngx_get_req_uri(const ngx_http_request_t *r, char **val)
{
    if(0 < r->uri.len && NULL_PTR != r->uri.data)
    {
        (*val) = safe_malloc(r->uri.len + 1, LOC_CNGX_0014);
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
        (*val) = safe_malloc(r->args.len + 1, LOC_CNGX_0015);
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

EC_BOOL cngx_get_req_argv(const ngx_http_request_t *r, const char *key, char **val)
{
    char       *k;
    char       *s;
    char       *e;
    uint32_t    klen;

    if(0 == r->args.len || NULL_PTR == r->args.data)
    {
        (*val) = NULL_PTR;
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_argv: no args\n");

        return (EC_TRUE);
    }

    klen = strlen(key);
    if(0 == klen)
    {
        (*val) = NULL_PTR;
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_argv: no key\n");

        return (EC_FALSE);
    }

    if('=' == key[ klen - 1 ])
    {
        k = (char *)key;

        s = strstr((char *)(r->args.data), k);
        if(NULL_PTR == s)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "[DEBUG] cngx_get_req_argv: "
                                                 "not found '%s' in req arg '%.*s'\n",
                                                 k, r->args.len, (char *)r->args.data);
            (*val) = NULL_PTR;
            return (EC_TRUE);
        }

        s += klen;

        for(e = s; '\0' != (*e) && '&' != (*e) && ' ' != (*e); e ++)
        {
            /*do nothing*/
        }

        (*val) = c_str_n_dup(s, (uint32_t)(e - s));

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_argv: "
                                             "dup args '%s'\n",
                                             (*val));
        return (EC_TRUE);
    }
    else
    {
        k = c_str_make("%s=", key);
        if(NULL_PTR == k)
        {
            (*val) = NULL_PTR;
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_argv: "
                                                 "make key '%s='\n",
                                                 key);

            return (EC_FALSE);
        }

        s = strstr((char *)(r->args.data), k);
        if(NULL_PTR == s)
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_argv: "
                                                 "not found '%s' in req arg '%.*s'\n",
                                                 k, r->args.len, (char *)r->args.data);
            (*val) = NULL_PTR;
            c_str_free(k);
            return (EC_TRUE);
        }

        c_str_free(k);

        s += klen + 1;

        for(e = s; '\0' != (*e) && '&' != (*e) && ' ' != (*e); e ++)
        {
            /*do nothing*/
        }

        (*val) = c_str_n_dup(s, (uint32_t)(e - s));

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_argv: "
                                             "dup args '%s'\n",
                                             (*val));
        return (EC_TRUE);
    }

    /*should never reach here*/
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

            safe_free(v, LOC_CNGX_0016);
            return (EC_TRUE);
        }

        if(8 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"https://", 8))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                                 "convert 'https://' to '/' and set store_path to '%s'\n",
                                                 v + 7);

            cstring_append_str(req_url, (const uint8_t *)(v + 7));

            safe_free(v, LOC_CNGX_0017);
            return (EC_TRUE);
        }

        if(EC_FALSE == cstring_format(req_url, "/%s", v))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                                 "format store_path '/%s' failed\n",
                                                 v);
            safe_free(v, LOC_CNGX_0018);
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                             "format store_path '/%s' done\n",
                                             v);
        safe_free(v, LOC_CNGX_0019);

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
        safe_free(uri_str, LOC_CNGX_0020);
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_format(req_url, "/%s%s", host_str, uri_str))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                             "format req_url '/%s%s' failed\n",
                                             host_str, uri_str);
        safe_free(host_str, LOC_CNGX_0021);
        safe_free(uri_str, LOC_CNGX_0022);
        return (EC_FALSE);
    }
    safe_free(host_str, LOC_CNGX_0023);
    safe_free(uri_str, LOC_CNGX_0024);

    if(EC_TRUE == need_args && EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                             "[cngx] get args '%s'\n",
                                             v);

        if(EC_FALSE == cstring_append_str(req_url, (const UINT8 *)"?"))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                                 "[cngx] append '?' failed\n");
            safe_free(v, LOC_CNGX_0025);
            return (EC_FALSE);
        }

        if(EC_FALSE == cstring_append_str(req_url, (const UINT8 *)v))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_req_url: "
                                                 "[cngx] append args '%s' failed\n",
                                                 v);
            safe_free(v, LOC_CNGX_0026);
            return (EC_FALSE);
        }
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_req_url: "
                                             "[cngx] append args '%s' done\n",
                                             v);
        safe_free(v, LOC_CNGX_0027);
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

EC_BOOL cngx_drain_req_body(ngx_http_request_t *r, CBYTES *body, UINT32 pos, UINT32 size, ngx_int_t *ngx_rc)
{
    ngx_connection_t            *c;
    ngx_http_core_loc_conf_t    *clcf;

    c = r->connection;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    while(pos < size)
    {
        ssize_t             n;

        n = c->recv(c, CBYTES_BUF(body) + pos, (size_t)(size - pos));

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_drain_req_body: "
                                             "[recv] r %p, "
                                             "recvd %ld / %ld, n %ld\n",
                                             r, pos, (UINT32)size, (UINT32)n);

        if(n == NGX_AGAIN)
        {
            EC_BOOL          ret;

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_drain_req_body: "
                                                 "[again] r %p, "
                                                 "recvd %ld / %ld\n",
                                                 r, pos, (UINT32)size);

            c->read->handler = cngx_recv_again;

            ngx_add_timer(c->read, clcf->client_body_timeout);

            if(ngx_handle_read_event(c->read, 0) != NGX_OK)
            {
                if(c->read->timer_set)
                {
                    ngx_del_timer(c->read);
                }

                r->read_event_handler = ngx_http_block_reading;
                c->read->handler      = ngx_http_empty_handler;

                (*ngx_rc) = NGX_HTTP_INTERNAL_SERVER_ERROR;
                NGX_W_RC(c->read) = NGX_ERROR;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_drain_req_body: "
                                                     "[event] r %p, "
                                                     "recvd %ld / %ld, add RD event failed, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, pos, (UINT32)size,
                                                     c->error, NGX_W_RC(c->read));
                return (EC_FALSE);
            }

            ret = cngx_recv_wait(r, 0/*never timeout*/);

            if(c->error)
            {
                (*ngx_rc) = NGX_HTTP_CLIENT_CLOSED_REQUEST;
                NGX_W_RC(c->read) = NGX_ERROR;

                if(c->read->timer_set)
                {
                    ngx_del_timer(c->read);
                }

                r->read_event_handler = ngx_http_block_reading;
                c->read->handler      = ngx_http_empty_handler;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_drain_req_body: "
                                                     "[broken] r %p, "
                                                     "recvd %ld / %ld, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, pos, (UINT32)size,
                                                     c->error, NGX_W_RC(c->read));
                return (EC_FALSE);
            }

            if(EC_FALSE == ret)
            {
                (*ngx_rc) = NGX_HTTP_INTERNAL_SERVER_ERROR;
                NGX_W_RC(c->read) = NGX_ERROR;

                if(c->read->timer_set)
                {
                    ngx_del_timer(c->read);
                }

                r->read_event_handler = ngx_http_block_reading;
                c->read->handler      = ngx_http_empty_handler;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_drain_req_body: "
                                                     "[fail] r %p, wait back, "
                                                     "recvd %ld / %ld, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, pos, (UINT32)size,
                                                     c->error, NGX_W_RC(c->read));
                return (EC_FALSE);
            }

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_drain_req_body: "
                                                 "[next] r %p, wait back, "
                                                 "recvd %ld / %ld, "
                                                 "connection error: %d, rc: %ld\n",
                                                 r, pos, (UINT32)size,
                                                 c->error, NGX_W_RC(c->read));

            continue;
        }

        if(n == 0)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed prematurely connection");
        }

        if(n == 0 || n == NGX_ERROR)
        {
            c->error = 1;
            (*ngx_rc) = NGX_HTTP_BAD_REQUEST;
            NGX_W_RC(c->read) = NGX_ERROR;
            return (EC_FALSE);
        }

        pos               += n;
        r->request_length += n;
    }

    if(c->read->timer_set)
    {
        ngx_del_timer(c->read);
    }

    r->read_event_handler = ngx_http_block_reading;

    NGX_W_RC(c->read) = NGX_OK;
    return (EC_TRUE);
}

EC_BOOL cngx_read_req_body(ngx_http_request_t *r, CBYTES *body, ngx_int_t *ngx_rc)
{
    //ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_http_core_loc_conf_t    *clcf;
    off_t                        size;      /*body total size*/
    ssize_t                      preread;   /*body preread size*/

    if(r->discard_body || r->headers_in.content_length_n <= 0)
    {
        return (EC_TRUE);
    }

    c = r->connection;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (clcf->client_body_in_file_only)
    {
        r->request_body_in_file_only       = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file      = 1;
        r->request_body_file_log_level     = NGX_LOG_NOTICE;
    }

    size    = r->headers_in.content_length_n;
    preread = r->header_in->last - r->header_in->pos;

    /*preread*/
    if(preread > 0)
    {
        if(EC_FALSE == cbytes_append(body, (const UINT8 *)r->header_in->pos, (UINT32)(preread)))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_read_req_body: "
                                                 "[preread] append %ld bytes to body failed\n",
                                                 (UINT32)(preread));
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_read_req_body: "
                                             "[preread] append %ld bytes to body done\n",
                                             (UINT32)(preread));

        /* the whole request body was pre-read */
        if(preread >= r->headers_in.content_length_n)
        {
            r->header_in->pos += r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;

            if(c->read->timer_set)
            {
                ngx_del_timer(c->read);
            }

            r->read_event_handler = ngx_http_block_reading;

            return (EC_TRUE);
        }

        r->header_in->pos  = r->header_in->last;
        r->request_length += preread;
    }

    if(size > preread)
    {
        UINT32                       pos;

        pos = CBYTES_LEN(body); /*record the starting position to recv*/

        if(EC_FALSE == cbytes_expand_to(body, (UINT32)size))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_read_req_body: "
                                                 "expand body to %ld bytes failed\n",
                                                 (UINT32)(size));
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_read_req_body: "
                                             "expand body to %ld bytes done\n",
                                             (UINT32)(size));

        if(EC_FALSE == cngx_drain_req_body(r, body, pos, (UINT32)size, ngx_rc))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_read_req_body: "
                                                 "drain body %ld/%ld failed\n",
                                                 pos, (UINT32)(size));
            return (EC_FALSE);
        }

        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_read_req_body: "
                                         "should never reach here\n");

    return (EC_FALSE);
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

        safe_free(req_method, LOC_CNGX_0028);
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_method: method '%s' != '%s'\n",
                    req_method, method);

    safe_free(req_method, LOC_CNGX_0029);
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

            safe_free(req_method, LOC_CNGX_0030);
            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_cacheable_method: '%s' is in '%s' => cachable\n",
                        req_method, cache_http_method_default);
        safe_free(req_method, LOC_CNGX_0031);
        return (EC_TRUE);
    }

    if(EC_FALSE == c_str_is_in(req_method, (const char *)":;, ", cache_http_method))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_cacheable_method: '%s' not in '%s' => not cachable\n",
                    req_method, cache_http_method);

        safe_free(req_method, LOC_CNGX_0032);
        safe_free(cache_http_method, LOC_CNGX_0033);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_cacheable_method: '%s' in '%s' => cachable\n",
                    req_method, cache_http_method);

    safe_free(req_method, LOC_CNGX_0034);
    safe_free(cache_http_method, LOC_CNGX_0035);

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

/*orig merge switch*/
EC_BOOL cngx_is_orig_merge_switch_off(ngx_http_request_t *r)
{
    const char                  *k;
    UINT32                       v;

    k = (const char *)CNGX_VAR_ORIG_MERGE_SWITCH;
    cngx_get_var_switch(r, k, &v, SWITCH_ON);

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_is_orig_merge_switch_off: "
                                         "get var '%s':'%s' done\n",
                                         k, c_switch_to_str(v));

    return (SWITCH_ON == v) ? EC_FALSE : EC_TRUE;
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
            start = (int) (strtod((char *) value.data, NULL_PTR) * 1000);

            if (ngx_errno != 0)
            {
                start = -1;
            }
        }

        if (ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK)
        {
            ngx_int_t                  end;

            ngx_set_errno(0);
            end = (int) (strtod((char *) value.data, NULL_PTR) * 1000);

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

        safe_free(v, LOC_CNGX_0036);
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

            safe_free(v, LOC_CNGX_0037);
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

                safe_free(v, LOC_CNGX_0038);
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

                safe_free(v, LOC_CNGX_0039);
                return (EC_FALSE);
            }

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG]cngx_get_redirect_specific: "
                                                 "cngx '%s' => status %u, redirect url '%s'\n",
                                                 k, (*des_rsp_status), (*des_redirect_url));
            safe_free(v, LOC_CNGX_0040);
            return (EC_TRUE);
        }
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_redirect_specific: "
                                         "cngx '%s' => no matched => ignore\n",
                                         k);

    (*des_rsp_status)   = CHTTP_STATUS_NONE;
    (*des_redirect_url) = NULL_PTR;

    safe_free(v, LOC_CNGX_0041);

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
    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_import_header_out: import headers done\n");
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

    safe_free(req_method, LOC_CNGX_0042);

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
    safe_free(req_uri, LOC_CNGX_0043);

    if(EC_FALSE == cngx_get_req_arg(r, &req_arg))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_export_uri: get req arg str failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != req_arg)
    {
        chttp_req_set_uri(chttp_req, (const char *)"?");
        chttp_req_set_uri(chttp_req, req_arg);
        safe_free(req_arg, LOC_CNGX_0044);
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
    int                           count;

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    if(0 >= count)
    {
        return (EC_TRUE);
    }

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
    int                           count;

    klen  = strlen(k);

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    if(0 >= count)
    {
        return (EC_FALSE);
    }

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
    int                           count;

    klen  = strlen(k);
    vlen  = strlen(v);

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    if(0 >= count)
    {
        return (EC_FALSE);
    }

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
    int                           count;

    klen  = strlen(k);
    (*v)  = NULL_PTR;

    part  = &(r->headers_in.headers.part);
    count = part->nelts;
    if(0 >= count)
    {
        return (EC_TRUE);
    }

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
            (*v) = safe_malloc(vlen + 1, LOC_CNGX_0045);
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

EC_BOOL cngx_set_deny_reason(ngx_http_request_t *r, const UINT32 deny_reason)
{
    const char                  *k;
    char                         v[16];

    k = (const char *)CNGX_VAR_DENY_REASON;
    snprintf((char *)v, 16, "%08ld", deny_reason);

    if(EC_FALSE == cngx_set_var_str(r, k, v))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_deny_reason: "
                                             "cngx set var '%s':'%s' failed\n",
                                             k, v);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_deny_reason: "
                                         "cngx set var '%s':'%s' done\n",
                                         k, v);
    return (EC_TRUE);
}

EC_BOOL cngx_need_intercept_errors(ngx_http_request_t *r, const uint32_t status)
{
    UINT32                       intercept_errors_switch;
    const char                  *k;

    if(NGX_HTTP_SPECIAL_RESPONSE > status)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_need_intercept_errors: "
                                             "rsp status %u => not intercept\n",
                                             status);

        return (EC_FALSE);
    }

    /*
     * if cngx switch intercept errors on,
     * then set rc and back to ngx procedure (ngx_http_finalize_request)
     *
     */
    k = (const char *)CNGX_VAR_ORIG_INTERCEPT_ERRORS_SWITCH;
    cngx_get_var_switch(r, k, &intercept_errors_switch, SWITCH_OFF);
    if(SWITCH_ON == intercept_errors_switch)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_need_intercept_errors: "
                                             "rsp status %u => intercept\n",
                                             status);
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_need_intercept_errors: "
                                         "rsp status %u and switch off => not intercept\n",
                                         status);

    return (EC_FALSE);
}

EC_BOOL cngx_finalize(ngx_http_request_t *r, ngx_int_t status)
{
    ngx_http_finalize_request(r, status);
    return (EC_TRUE);
}

EC_BOOL cngx_get_send_lowat(ngx_http_request_t *r, size_t *send_lowat)
{
    if(NULL_PTR != send_lowat)
    {
        ngx_http_core_loc_conf_t  *clcf;

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        (*send_lowat) = clcf->send_lowat;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_get_send_timeout_msec(ngx_http_request_t *r, ngx_msec_t *timeout_msec)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_msec_t                 send_timeout;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if(0 < clcf->send_timeout)
    {
        send_timeout = clcf->send_timeout; /*default is 60s*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_send_timeout_msec: "
                                             "set send_timeout to clcf->send_timeout %ld ms\n",
                                             clcf->send_timeout);
    }
    else
    {
        /*should never reach here due to ngx would set clcf->send_timeout to default 60s*/
        send_timeout = 60 * 1000; /*set to default 60s */

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_send_timeout_msec: "
                                             "set send_timeout to default %ld ms\n",
                                             clcf->send_timeout);
    }

    if(NULL_PTR != timeout_msec)
    {
        (*timeout_msec) = send_timeout;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_get_client_body_timeout_msec(ngx_http_request_t *r, ngx_msec_t *timeout_msec)
{
    ngx_http_core_loc_conf_t  *clcf;
    ngx_msec_t                 client_body_timeout;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if(0 < clcf->client_body_timeout)
    {
        client_body_timeout = clcf->client_body_timeout; /*default is 30s*/

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_client_body_timeout_msec: "
                                             "set client_body_timeout to clcf->client_body_timeout %ld ms\n",
                                             clcf->client_body_timeout);
    }
    else
    {
        /*should never reach here due to ngx would set clcf->client_body_timeout to default 30s*/
        client_body_timeout = 30 * 1000; /*set to default 30s */

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_client_body_timeout_msec: "
                                             "set client_body_timeout to default %ld ms\n",
                                             clcf->client_body_timeout);
    }

    if(NULL_PTR != timeout_msec)
    {
        (*timeout_msec) = client_body_timeout;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_get_send_timeout_event_msec(ngx_http_request_t *r, ngx_msec_t *timeout_msec)
{
    const char      *k;
    uint32_t         n;

    k = (const char *)CNGX_VAR_SEND_TIMEOUT_EVENT_MSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, (uint32_t)1000))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_send_timeout_event_msec: "
                                             "cngx get var '%s' failed\n",
                                             k);
        /*set by force*/
        n = 1000;/*one second*/
    }
    else
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_send_timeout_event_msec: "
                                             "cngx var '%s':'%u' done\n",
                                             k, n);
    }

    if(NULL_PTR != timeout_msec)
    {
        (*timeout_msec) = n;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_get_recv_timeout_event_msec(ngx_http_request_t *r, ngx_msec_t *timeout_msec)
{
    const char      *k;
    uint32_t         n;

    k = (const char *)CNGX_VAR_RECV_TIMEOUT_EVENT_MSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &n, (uint32_t)30*1000))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_get_recv_timeout_event_msec: "
                                             "cngx get var '%s' failed\n",
                                             k);
        /*set by force*/
        n = 30*1000;/*30s*/
    }
    else
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_get_recv_timeout_event_msec: "
                                             "cngx var '%s':'%u' done\n",
                                             k, n);
    }

    if(NULL_PTR != timeout_msec)
    {
        (*timeout_msec) = n;
    }

    return (EC_TRUE);
}

EC_BOOL cngx_recv_wait(ngx_http_request_t *r, ngx_msec_t recv_timeout)
{
    ngx_connection_t          *c;
    ngx_event_t               *rev;

    COROUTINE_COND            *coroutine_cond;
    EC_BOOL                    ret;

    c = r->connection;
    rev = c->read;
#if 0
    if(0 == recv_timeout)
    {
        return (EC_TRUE);
    }
#endif
    coroutine_cond = coroutine_cond_new((UINT32)recv_timeout, LOC_CNGX_0046);
    if(NULL_PTR == coroutine_cond)
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_recv_wait: "
                                             "new coroutine_cond failed\n");
        return (EC_FALSE);
    }

    NGX_W_COROUTINE_COND(rev) = coroutine_cond;

    dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "[DEBUG] cngx_recv_wait: "
                                         "coroutine_cond %p on r:%p, c:%p, rev:%p <= start\n",
                                         coroutine_cond, r, c, rev);

    coroutine_cond_reserve(coroutine_cond, 1, LOC_CNGX_0047);
    ret = coroutine_cond_wait(coroutine_cond, LOC_CNGX_0048);

    __COROUTINE_CATCH_EXCEPTION() { /*exception*/
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_recv_wait: "
                                             "coroutine_cond %p on r:%p, c:%p, rev:%p => cancelled\n",
                                             coroutine_cond, r, c, rev);
        coroutine_cond_free(coroutine_cond, LOC_CNGX_0049);
        NGX_W_COROUTINE_COND(rev) = NULL_PTR;
    }__COROUTINE_TERMINATE();

    if(NULL_PTR != NGX_W_COROUTINE_COND(rev))/*double confirm its validity for safe reason*/
    {
        coroutine_cond_free(coroutine_cond, LOC_CNGX_0050);
        NGX_W_COROUTINE_COND(rev) = NULL_PTR;
    }

    if(EC_TRUE != ret) /*ret maybe EC_TRUE, EC_FALSE, EC_TIMEOUT, EC_TERMINATE, etc.*/
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_recv_wait: "
                                             "coroutine_cond %p on r:%p, c:%p, rev:%p "
                                             "=> back but ret = %ld (recv_timeout %ld)\n",
                                             coroutine_cond, r, c, rev, ret, recv_timeout);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_recv_wait: "
                                         "coroutine_cond %p on r:%p, c:%p, rev:%p => back\n",
                                         coroutine_cond, r, c, rev);
    return (EC_TRUE);
}

void cngx_recv_again(ngx_event_t *rev)
{
    if(rev->timer_set)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_recv_again: "
                                             "rev %p, ready %d, co T: %p, cond W:%p, "
                                             "trigger read event\n",
                                             rev, rev->ready,
                                             NGX_T_EVENT_COROUTINE_NODE(rev),
                                             NGX_W_COROUTINE_COND(rev));
        ngx_del_timer(rev);
        //ASSERT(1 == rev->ready);
    }
    else
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_recv_again: "
                                             "rev %p, ready %d, co T: %p, cond W:%p, "
                                             "trigger timeout event\n",
                                             rev, rev->ready,
                                             NGX_T_EVENT_COROUTINE_NODE(rev),
                                             NGX_W_COROUTINE_COND(rev));
        //ASSERT(0 == rev->ready);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_recv_again: "
                                         "rev %p, co T: %p, cond W:%p, "
                                         "timer_set %d, timeout %d, delayed %d, ready %d\n",
                                         rev,
                                         NGX_T_EVENT_COROUTINE_NODE(rev),
                                         NGX_W_COROUTINE_COND(rev),
                                         rev->timer_set, rev->timedout, rev->delayed, rev->ready);

    if(NULL_PTR != NGX_W_COROUTINE_COND(rev))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_recv_again: enter\n");
        coroutine_cond_release_all(NGX_W_COROUTINE_COND(rev), LOC_CNGX_0051);
    }

    return;
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
    coroutine_cond = coroutine_cond_new((UINT32)send_timeout, LOC_CNGX_0052);
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

    coroutine_cond_reserve(coroutine_cond, 1, LOC_CNGX_0053);
    ret = coroutine_cond_wait(coroutine_cond, LOC_CNGX_0054);

    __COROUTINE_CATCH_EXCEPTION() { /*exception*/
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_wait: "
                                             "coroutine_cond %p on r:%p, c:%p, wev:%p => cancelled\n",
                                             coroutine_cond, r, c, wev);
        coroutine_cond_free(coroutine_cond, LOC_CNGX_0055);
        NGX_W_COROUTINE_COND(wev) = NULL_PTR;
    }__COROUTINE_TERMINATE();

    if(NULL_PTR != NGX_W_COROUTINE_COND(wev))/*double confirm its validity for safe reason*/
    {
        coroutine_cond_free(coroutine_cond, LOC_CNGX_0056);
        NGX_W_COROUTINE_COND(wev) = NULL_PTR;
    }

    if(EC_TRUE != ret) /*ret maybe EC_TRUE, EC_FALSE, EC_TIMEOUT, EC_TERMINATE, etc.*/
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_wait: "
                                             "coroutine_cond %p on r:%p, c:%p, wev:%p "
                                             "=> back but ret = %ld (send_timeout %ld)\n",
                                             coroutine_cond, r, c, wev, ret, send_timeout);
        return (EC_FALSE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_wait: "
                                         "coroutine_cond %p on r:%p, c:%p, wev:%p => back\n",
                                         coroutine_cond, r, c, wev);
    return (EC_TRUE);
}

void cngx_send_again(ngx_event_t *wev)
{
    if(wev->timer_set)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_again: "
                                             "wev %p, ready %d, co T: %p, cond W:%p, "
                                             "trigger write event\n",
                                             wev, wev->ready,
                                             NGX_T_EVENT_COROUTINE_NODE(wev),
                                             NGX_W_COROUTINE_COND(wev));
        ngx_del_timer(wev);
        //ASSERT(1 == wev->ready);
    }
    else
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_again: "
                                             "wev %p, ready %d, co T: %p, cond W:%p, "
                                             "trigger timeout event\n",
                                             wev, wev->ready,
                                             NGX_T_EVENT_COROUTINE_NODE(wev),
                                             NGX_W_COROUTINE_COND(wev));
        //ASSERT(0 == wev->ready);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_again: "
                                         "wev %p, co T: %p, cond W:%p, "
                                         "timer_set %d, timeout %d, delayed %d, ready %d\n",
                                         wev,
                                         NGX_T_EVENT_COROUTINE_NODE(wev),
                                         NGX_W_COROUTINE_COND(wev),
                                         wev->timer_set, wev->timedout, wev->delayed, wev->ready);

    if(NULL_PTR != NGX_W_COROUTINE_COND(wev))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_again: enter\n");
        coroutine_cond_release_all(NGX_W_COROUTINE_COND(wev), LOC_CNGX_0057);
    }

    return;
}

EC_BOOL cngx_send_header(ngx_http_request_t *r, ngx_int_t *ngx_rc)
{
    ngx_int_t rc;

    cngx_disable_postpone_output(r);/*dangerous?*/

    rc = ngx_http_send_header(r);
    (*ngx_rc) = rc;

    if (rc == NGX_ERROR || rc > NGX_OK || r->post_action)
    {
        if(r->connection->error)
        {
            (*ngx_rc) = NGX_HTTP_CLIENT_CLOSED_REQUEST; /*reset*/
        }
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_header: "
                                             "send header failed (rc %ld => %ld)\n",
                                             rc, (*ngx_rc));
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

EC_BOOL cngx_disable_send_header(ngx_http_request_t *r)
{
    r->header_sent = 1;
    return (EC_TRUE);
}

EC_BOOL cngx_enable_send_header(ngx_http_request_t *r)
{
    r->header_sent = 0;
    return (EC_TRUE);
}

EC_BOOL cngx_send_body(ngx_http_request_t *r, const uint8_t *body, const uint32_t len, const uint32_t flags, ngx_int_t *ngx_rc)
{
    ngx_http_core_loc_conf_t    *clcf;
    ngx_connection_t            *c;
    ssize_t                      n;
    uint32_t                     sent_len;

    if(CNGX_SEND_BODY_PRELOAD_FLAG & flags)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == body || 0 == len)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: send none body done\n");
        return (EC_TRUE);
    }

    c = r->connection;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    sent_len = 0;

    while(sent_len < len)
    {
        n = c->send(c, (u_char *)(body + sent_len), (size_t)(len - sent_len));
        if(n == 0)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed prematurely connection");
        }

        if(n == 0 || n == NGX_ERROR)
        {
            c->error = 1;
            (*ngx_rc) = NGX_ERROR;
            NGX_W_RC(c->write) = NGX_ERROR;

            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "error:cngx_send_body: "
                                                 "send body failed\n");
            return (EC_FALSE);
        }

        if(n == NGX_AGAIN)
        {
            EC_BOOL          ret;

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: "
                                                 "[again] r %p, "
                                                 "sent %u / %u\n",
                                                 r, sent_len, len);

            if(r->stream)
            {
                /*TODO:*/
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "fatal error:cngx_send_body: "
                                                     "http/2 should never reach here! "
                                                     "you MUST check configuration !!\n");
                return (EC_TRUE);
            }

            c->write->handler = cngx_send_again;

            ngx_add_timer(c->write, clcf->client_body_timeout);

            if(ngx_handle_write_event(c->write, 0) != NGX_OK)
            {
                if(c->write->timer_set)
                {
                    ngx_del_timer(c->write);
                }

                r->write_event_handler = ngx_http_request_empty_handler;
                c->write->handler      = ngx_http_empty_handler;

                (*ngx_rc) = NGX_HTTP_INTERNAL_SERVER_ERROR;
                NGX_W_RC(c->write) = NGX_ERROR;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body: "
                                                     "[event] r %p, "
                                                     "sent %u / %u, add WR event failed, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, sent_len, len,
                                                     c->error, NGX_W_RC(c->write));
                return (EC_FALSE);
            }

            ret = cngx_send_wait(r, 0/*never timeout*/);

            if(c->error)
            {
                (*ngx_rc) = NGX_HTTP_CLIENT_CLOSED_REQUEST;
                NGX_W_RC(c->write) = NGX_ERROR;

                if(c->write->timer_set)
                {
                    ngx_del_timer(c->write);
                }

                r->write_event_handler = ngx_http_request_empty_handler;
                c->write->handler      = ngx_http_empty_handler;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body: "
                                                     "[broken] r %p, "
                                                     "sent %u / %u, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, sent_len, len,
                                                     c->error, NGX_W_RC(c->write));
                return (EC_FALSE);
            }

            if(EC_FALSE == ret)
            {
                (*ngx_rc) = NGX_HTTP_INTERNAL_SERVER_ERROR;
                NGX_W_RC(c->write) = NGX_ERROR;

                if(c->write->timer_set)
                {
                    ngx_del_timer(c->write);
                }

                r->write_event_handler = ngx_http_request_empty_handler;
                c->write->handler      = ngx_http_empty_handler;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body: "
                                                     "[fail] r %p, wait back, "
                                                     "sent %u / %u, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, sent_len, len,
                                                     c->error, NGX_W_RC(c->write));
                return (EC_FALSE);
            }

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: "
                                                 "[next] r %p, wait back, "
                                                 "sent %u / %u, "
                                                 "connection error: %d, rc: %ld\n",
                                                 r, sent_len, len,
                                                 c->error, NGX_W_RC(c->write));

            continue;
        }

        sent_len += (uint32_t)n;

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: send body %u => %u / %u\n",
                                             (uint32_t)n, sent_len, len);
    }

    if(c->write->timer_set)
    {
        ngx_del_timer(c->write);
    }

    r->write_event_handler = ngx_http_request_empty_handler;
    c->write->handler      = ngx_http_empty_handler;

    NGX_W_RC(c->write) = NGX_OK;

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body: send body done\n");

    return (EC_TRUE);
}

EC_BOOL cngx_send_body_chain(ngx_http_request_t *r, ngx_chain_t *body, ngx_int_t *ngx_rc)
{
    ngx_http_core_loc_conf_t    *clcf;
    ngx_connection_t            *c;
    ngx_chain_t                 *chain;

    if(NULL_PTR == body)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body_chain: send none body done\n");
        return (EC_TRUE);
    }

    c = r->connection;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    chain = body;

    while(NULL_PTR != chain)
    {
        chain = c->send_chain(c, chain, 0);
        if (chain == NGX_CHAIN_ERROR)
        {
            c->error = 1;
            (*ngx_rc) = NGX_ERROR;
            NGX_W_RC(c->write) = NGX_ERROR;

            dbg_log(SEC_0176_CNGX, 1)(LOGSTDOUT, "error:cngx_send_body_chain: "
                                                 "send body failed\n");
            return (EC_FALSE);
        }
        else
        {
            EC_BOOL          ret;

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body_chain: "
                                                 "[again] r %p, "
                                                 "sent %ld\n",
                                                 r, c->sent);

            if(r->stream)
            {
                /*TODO:*/
                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "fatal error:cngx_send_body_chain: "
                                                     "http/2 should never reach here! "
                                                     "you MUST check configuration !!\n");
                return (EC_TRUE);
            }

            c->write->handler = cngx_send_again;

            ngx_add_timer(c->write, clcf->client_body_timeout);

            if(ngx_handle_write_event(c->write, 0) != NGX_OK)
            {
                if(c->write->timer_set)
                {
                    ngx_del_timer(c->write);
                }

                r->write_event_handler = ngx_http_request_empty_handler;
                c->write->handler      = ngx_http_empty_handler;

                (*ngx_rc) = NGX_HTTP_INTERNAL_SERVER_ERROR;
                NGX_W_RC(c->write) = NGX_ERROR;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body_chain: "
                                                     "[event] r %p, "
                                                     "sent %ld, add WR event failed, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, c->sent,
                                                     c->error, NGX_W_RC(c->write));
                return (EC_FALSE);
            }

            ret = cngx_send_wait(r, 0/*never timeout*/);

            if(c->error)
            {
                (*ngx_rc) = NGX_HTTP_CLIENT_CLOSED_REQUEST;
                NGX_W_RC(c->write) = NGX_ERROR;

                if(c->write->timer_set)
                {
                    ngx_del_timer(c->write);
                }

                r->write_event_handler = ngx_http_request_empty_handler;
                c->write->handler      = ngx_http_empty_handler;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body_chain: "
                                                     "[broken] r %p, "
                                                     "sent %ld, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, c->sent,
                                                     c->error, NGX_W_RC(c->write));
                return (EC_FALSE);
            }

            if(EC_FALSE == ret)
            {
                (*ngx_rc) = NGX_HTTP_INTERNAL_SERVER_ERROR;
                NGX_W_RC(c->write) = NGX_ERROR;

                if(c->write->timer_set)
                {
                    ngx_del_timer(c->write);
                }

                r->write_event_handler = ngx_http_request_empty_handler;
                c->write->handler      = ngx_http_empty_handler;

                dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_send_body_chain: "
                                                     "[fail] r %p, wait back, "
                                                     "sent %ld, "
                                                     "connection error: %d, reset rc to %ld\n",
                                                     r, c->sent,
                                                     c->error, NGX_W_RC(c->write));
                return (EC_FALSE);
            }

            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body_chain: "
                                                 "[next] r %p, wait back, "
                                                 "sent %ld, "
                                                 "connection error: %d, rc: %ld\n",
                                                 r, c->sent,
                                                 c->error, NGX_W_RC(c->write));

            continue;
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body_chain: sent %ld\n",
                                             c->sent);
    }

    if(c->write->timer_set)
    {
        ngx_del_timer(c->write);
    }

    r->write_event_handler = ngx_http_request_empty_handler;
    c->write->handler      = ngx_http_empty_handler;

    NGX_W_RC(c->write) = NGX_OK;

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_send_body_chain: send body done\n");

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
        safe_free(v, LOC_CNGX_0058);
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
    safe_free(cache_http_codes_str, LOC_CNGX_0059);

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

    safe_free(v, LOC_CNGX_0060);

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
            cstring_rtrim(store_path, (const UINT8)'/');
            return (EC_TRUE);
        }

        if(7 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"http://", 7))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                                 "convert 'http://' to '/' and set store_path to '%s'\n",
                                                 v + 6);

            cstring_append_str(store_path, (const uint8_t *)(v + 6));
            cstring_rtrim(store_path, (const UINT8)'/');

            safe_free(v, LOC_CNGX_0061);
            return (EC_TRUE);
        }

        if(8 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"https://", 8))
        {
            dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                                 "convert 'https://' to '/' and set store_path to '%s'\n",
                                                 v + 7);

            cstring_append_str(store_path, (const uint8_t *)(v + 7));
            cstring_rtrim(store_path, (const UINT8)'/');

            safe_free(v, LOC_CNGX_0062);
            return (EC_TRUE);
        }

        if(EC_FALSE == cstring_format(store_path, "/%s", v))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                                 "format store_path '/%s' failed\n",
                                                 v);
            safe_free(v, LOC_CNGX_0063);
            return (EC_FALSE);
        }
        cstring_rtrim(store_path, (const UINT8)'/');

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_set_store_cache_path: "
                                             "format store_path '/%s' done\n",
                                             v);
        safe_free(v, LOC_CNGX_0064);

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
        safe_free(uri_str, LOC_CNGX_0065);
        return (EC_FALSE);
    }

    //k = (const char *)"server_name";
    k = (const char *)"http_host";
    if(EC_FALSE == cngx_get_var_str(r, k, &host_str, NULL_PTR))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                             "fetch '%s' failed\n",
                                             k);
        safe_free(uri_str, LOC_CNGX_0066);
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_format(store_path, "/%s%s", host_str, uri_str))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_set_store_cache_path: "
                                             "format store_path '/%s%s' failed\n",
                                             host_str, uri_str);
        safe_free(host_str, LOC_CNGX_0067);
        safe_free(uri_str, LOC_CNGX_0068);
        return (EC_FALSE);
    }
    cstring_rtrim(store_path, (const UINT8)'/');

    safe_free(host_str, LOC_CNGX_0069);
    safe_free(uri_str, LOC_CNGX_0070);

    /*set cache path variable*/
    k = (const char *)CNGX_VAR_CACHE_PATH;
    v = (char *)cstring_get_str(store_path);
    if(EC_FALSE == cngx_set_var_str(r, k, v))
    {
        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "warn:cngx_set_store_cache_path: "
                                             "set var %s to '%s' failed\n",
                                             k, v);
        /*ignore error and fall through*/
    }

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
    if(NGX_HTTP_PUT == r->method)
    {
        if(3 != r->method_name.len || NULL_PTR == r->method_name.data)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_option_set_cacheable_method: invalid r->method_name: len %ld, data %p\n",
                            r->method_name.len, r->method_name.data);

            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_set_cacheable_method: r->method_name: len %ld, data %p\n",
                        r->method_name.len, r->method_name.data);

        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_set_cacheable_method: modify method 'PUT' to 'GET' => set true\n");

        r->method = NGX_HTTP_GET;
        r->method_name.data[ 0 ] = 'G';
        r->method_name.data[ 1 ] = 'E';
        r->method_name.data[ 2 ] = 'T';
        r->method_name.len       = 3;

        //BCOPY("GET", r->method_name.data, 3);

        CNGX_OPTION_CACHEABLE_METHOD(cngx_option) = BIT_TRUE;
        return (EC_TRUE);
    }

    /*cache for GET or HEAD only*/
    if(NGX_HTTP_GET != r->method && NGX_HTTP_HEAD != r->method)
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_set_cacheable_method: not acceptable method '%ld' => set false\n",
                    r->method);

        CNGX_OPTION_CACHEABLE_METHOD(cngx_option) = BIT_FALSE;
        return (EC_TRUE);
    }

    /*check ngx conf*/
    if(EC_FALSE == cngx_is_cacheable_method(r))
    {
        dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_set_cacheable_method: not cachable method => set false\n");

        CNGX_OPTION_CACHEABLE_METHOD(cngx_option) = BIT_FALSE;
        return (EC_TRUE);
    }

    dbg_log(SEC_0176_CNGX, 9)(LOGSTDOUT, "[DEBUG] cngx_option_set_cacheable_method: OK, cachable method => set true\n");

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

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
