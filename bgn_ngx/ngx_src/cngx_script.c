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

#include "ngx_http_bgn_common.h"
#include "ngx_http_bgn_headers_in.h"
#include "ngx_http_bgn_headers_out.h"
#include "ngx_http_bgn_variable.h"

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cngx_script.h"

static EC_BOOL __cngx_script_filter(ngx_http_request_t *r, ngx_array_t *lua_blocks)
{
    ngx_int_t                    idx;

    for (idx = 0; idx < lua_blocks->nelts; idx ++)
    {
        ngx_http_bgn_lua_block_kv_t      *kv;
        ngx_http_bgn_rewrite_loc_conf_t  *rlcf;

        ngx_http_script_code_pt           code;
        ngx_http_script_engine_t         *e;
        ngx_uint_t                        stack_size;

        kv = (ngx_http_bgn_lua_block_kv_t *)(lua_blocks->elts + idx * lua_blocks->size);
        rlcf = &(kv->complex_v_rlcf);

        e = ngx_pcalloc(r->pool, sizeof(ngx_http_script_engine_t));
        if(NULL_PTR == e)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_script_filter: "
                                                 "calloc script engine failed\n");
            return (EC_FALSE);
        }

        /*fix rlcf->stack_size = 0*/
        stack_size = rlcf->stack_size;
        if(16 > stack_size)
        {
            stack_size = 16;
        }

        e->sp = ngx_pcalloc(r->pool, stack_size * sizeof(ngx_http_variable_value_t));
        if(NULL_PTR == e->sp)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_script_filter: "
                                                 "calloc sp with stack size %ld failed\n",
                                                 rlcf->stack_size);
            return (EC_FALSE);
        }

        e->ip       = rlcf->codes->elts;
        e->request  = r;
        e->quote    = 1;
        e->log      = rlcf->log;
        e->status   = NGX_DECLINED;

        while (*(uintptr_t *) e->ip)
        {
            code = *(ngx_http_script_code_pt *) e->ip;
            code(e);
        }

        if(NGX_OK != e->status)
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:__cngx_script_filter: "
                                                 "status %ld\n",
                                                 e->status);
            return (EC_FALSE);
        }
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_script_dir0_filter(ngx_http_request_t *r)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *lua_blocks;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    lua_blocks = blcf->lua_blocks[NGX_HTTP_BGN_LUA_BLOCK_DIR_0];
    if(NULL_PTR != lua_blocks)
    {
        if(EC_FALSE == __cngx_script_filter(r, lua_blocks))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_script_dir0_filter: "
                                                 "filter dir0 script failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "[DEBUG] cngx_script_dir0_filter: "
                                             "filter dir0 script done\n");
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_script_dir1_filter(ngx_http_request_t *r)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *lua_blocks;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    lua_blocks = blcf->lua_blocks[NGX_HTTP_BGN_LUA_BLOCK_DIR_1];
    if(NULL_PTR != lua_blocks)
    {
        if(EC_FALSE == __cngx_script_filter(r, lua_blocks))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_script_dir1_filter: "
                                                 "filter dir1 script failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "[DEBUG] cngx_script_dir1_filter: "
                                             "filter dir1 script done\n");
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_script_dir2_filter(ngx_http_request_t *r)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *lua_blocks;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    lua_blocks = blcf->lua_blocks[NGX_HTTP_BGN_LUA_BLOCK_DIR_2];
    if(NULL_PTR != lua_blocks)
    {
        if(EC_FALSE == __cngx_script_filter(r, lua_blocks))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_script_dir2_filter: "
                                                 "filter dir2 script failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "[DEBUG] cngx_script_dir2_filter: "
                                             "filter dir2 script done\n");
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cngx_script_dir3_filter(ngx_http_request_t *r)
{
    ngx_http_bgn_loc_conf_t     *blcf;
    ngx_array_t                 *lua_blocks;

    blcf = ngx_http_get_module_loc_conf(r, ngx_http_bgn_module);

    lua_blocks = blcf->lua_blocks[NGX_HTTP_BGN_LUA_BLOCK_DIR_3];
    if(NULL_PTR != lua_blocks)
    {
        if(EC_FALSE == __cngx_script_filter(r, lua_blocks))
        {
            dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "error:cngx_script_dir3_filter: "
                                                 "filter dir3 script failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0176_CNGX, 0)(LOGSTDOUT, "[DEBUG] cngx_script_dir3_filter: "
                                             "filter dir3 script done\n");
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
