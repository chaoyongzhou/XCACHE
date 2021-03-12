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

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"

#include "cbc.h"
#include "cmisc.h"

#include "ctimeout.h"

#include "task.h"

#include "cngx.h"
#include "chttp.h"

#include "cacltime.h"

#include "findex.inc"

#define CACLTIME_MD_CAPACITY()                  (cbc_md_capacity(MD_CACLTIME))

#define CACLTIME_MD_GET(cacltime_md_id)     ((CACLTIME_MD *)cbc_md_get(MD_CACLTIME, (cacltime_md_id)))

#define CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id)  \
    ((CMPI_ANY_MODI != (cacltime_md_id)) && ((NULL_PTR == CACLTIME_MD_GET(cacltime_md_id)) || (0 == (CACLTIME_MD_GET(cacltime_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CACLTIME Module
*
**/
void cacltime_print_module_status(const UINT32 cacltime_md_id, LOG *log)
{
    CACLTIME_MD *cacltime_md;
    UINT32      this_cacltime_md_id;

    for( this_cacltime_md_id = 0; this_cacltime_md_id < CACLTIME_MD_CAPACITY(); this_cacltime_md_id ++ )
    {
        cacltime_md = CACLTIME_MD_GET(this_cacltime_md_id);

        if(NULL_PTR != cacltime_md && 0 < cacltime_md->usedcounter )
        {
            sys_log(log,"CACLTIME Module # %u : %u refered\n",
                    this_cacltime_md_id,
                    cacltime_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CACLTIME module
*
**/
EC_BOOL cacltime_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CACLTIME , 1);
}

/**
*
* unregister CACLTIME module
*
**/
EC_BOOL cacltime_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CACLTIME);
}

/**
*
* start CACLTIME module
*
**/
UINT32 cacltime_start(ngx_http_request_t *r)
{
    CACLTIME_MD *cacltime_md;
    UINT32       cacltime_md_id;

    cacltime_md_id = cbc_md_new(MD_CACLTIME, sizeof(CACLTIME_MD));
    if(CMPI_ERROR_MODI == cacltime_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CACLTIME module */
    cacltime_md = (CACLTIME_MD *)cbc_md_get(MD_CACLTIME, cacltime_md_id);
    cacltime_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */
    CACLTIME_MD_NGX_HTTP_REQ(cacltime_md)     = r;

    /*TODO: load all variables into module*/

    CACLTIME_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cacltime_md) = BIT_FALSE;

    CACLTIME_MD_NGX_LOC(cacltime_md)          = LOC_NONE_END;
    CACLTIME_MD_NGX_RC(cacltime_md)           = NGX_OK;

    cacltime_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cacltime_end, cacltime_md_id);

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_start: start CACLTIME module #%ld\n", cacltime_md_id);

    return ( cacltime_md_id );
}

/**
*
* end CACLTIME module
*
**/
void cacltime_end(const UINT32 cacltime_md_id)
{
    CACLTIME_MD *cacltime_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cacltime_end, cacltime_md_id);

    cacltime_md = CACLTIME_MD_GET(cacltime_md_id);
    if(NULL_PTR == cacltime_md)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_end: "
                                                 "cacltime_md_id = %ld not exist.\n",
                                                 cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cacltime_md->usedcounter )
    {
        cacltime_md->usedcounter --;
        return ;
    }

    if ( 0 == cacltime_md->usedcounter )
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_end: "
                                                 "cacltime_md_id = %ld is not started.\n",
                                                 cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }

    CACLTIME_MD_NGX_HTTP_REQ(cacltime_md) = NULL_PTR;

    CACLTIME_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cacltime_md) = BIT_FALSE;

    CACLTIME_MD_NGX_LOC(cacltime_md)        = LOC_NONE_END;
    CACLTIME_MD_NGX_RC(cacltime_md)         = NGX_OK;

    /* free module */
    cacltime_md->usedcounter = 0;

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "cacltime_end: stop CACLTIME module #%ld\n", cacltime_md_id);
    cbc_md_free(MD_CACLTIME, cacltime_md_id);

    return ;
}

EC_BOOL cacltime_get_ngx_rc(const UINT32 cacltime_md_id, ngx_int_t *rc, UINT32 *location)
{
    CACLTIME_MD                  *cacltime_md;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_get_ngx_rc: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    cacltime_md = CACLTIME_MD_GET(cacltime_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CACLTIME_MD_NGX_RC(cacltime_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CACLTIME_MD_NGX_LOC(cacltime_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cacltime_set_ngx_rc(const UINT32 cacltime_md_id, const ngx_int_t rc, const UINT32 location)
{
    CACLTIME_MD                  *cacltime_md;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_set_ngx_rc: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    cacltime_md = CACLTIME_MD_GET(cacltime_md_id);

    /*do not override*/
    if(NGX_OK != CACLTIME_MD_NGX_RC(cacltime_md))
    {
        dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_override_ngx_rc: "
                                                 "ignore rc %ld due to its %ld now\n",
                                                 rc, CACLTIME_MD_NGX_RC(cacltime_md));
        return (EC_TRUE);
    }

    CACLTIME_MD_NGX_RC(cacltime_md)  = rc;
    CACLTIME_MD_NGX_LOC(cacltime_md) = location;

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_set_ngx_rc: "
                                             "set rc %ld\n",
                                             rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cacltime_override_ngx_rc(const UINT32 cacltime_md_id, const ngx_int_t rc, const UINT32 location)
{
    CACLTIME_MD                  *cacltime_md;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_override_ngx_rc: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    cacltime_md = CACLTIME_MD_GET(cacltime_md_id);

    if(rc == CACLTIME_MD_NGX_RC(cacltime_md))
    {
        dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_override_ngx_rc: "
                                                 "ignore same rc %ld\n",
                                                 rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CACLTIME_MD_NGX_RC(cacltime_md))
    {
        dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_override_ngx_rc: "
                                                 "modify rc %ld => %ld\n",
                                                 CACLTIME_MD_NGX_RC(cacltime_md), rc);
        CACLTIME_MD_NGX_RC(cacltime_md)  = rc;
        CACLTIME_MD_NGX_LOC(cacltime_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_override_ngx_rc: "
                                             "set rc %ld\n",
                                             rc);

    CACLTIME_MD_NGX_RC(cacltime_md)  = rc;
    CACLTIME_MD_NGX_LOC(cacltime_md) = location;

    return (EC_TRUE);
}

/**
*
* access filter
*
**/
EC_BOOL cacltime_access_filter(const UINT32 cacltime_md_id)
{
    CACLTIME_MD                 *cacltime_md;

    ngx_http_request_t          *r;

    char                        *uri;
    char                        *arg;
    CACLTIME_ACCESS_NODE         cacltime_access_node;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_access_filter: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    cacltime_md = CACLTIME_MD_GET(cacltime_md_id);

    r = CACLTIME_MD_NGX_HTTP_REQ(cacltime_md);

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter: enter\n");

    if(do_log(SEC_0171_CACLTIME, 9))
    {
        CHTTP_REQ       chttp_req_t;

        chttp_req_init(&chttp_req_t);

        cngx_export_header_in(r, &chttp_req_t);

        cngx_export_method(r, &chttp_req_t);
        cngx_export_uri(r, &chttp_req_t);

        dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter: cngx req is -------------------------\n");
        chttp_req_print_plain(LOGSTDOUT, &chttp_req_t);
        dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter: -------------------------------------\n");

        chttp_req_clean(&chttp_req_t);
    }

    /*uri*/
    if(EC_FALSE == cngx_get_req_uri(r, &uri))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter: "
                                                 "get req uri failed\n");

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CACLTIME_0001);
        return (EC_FALSE);
    }

    if(NULL_PTR == uri)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter: "
                                                 "uri is null\n");

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_FORBIDDEN, LOC_CACLTIME_0002);

        return (EC_FALSE);
    }

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter: "
                                             "uri: %s\n",
                                             uri);

    /*arg*/
    if(EC_FALSE == cngx_get_req_arg(r, &arg))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter: "
                                                 "get req arg failed\n");
        safe_free(uri, LOC_CACLTIME_0003);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CACLTIME_0004);
        return (EC_FALSE);
    }

    if(NULL_PTR == arg)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter: "
                                                 "arg is null\n");

        safe_free(uri, LOC_CACLTIME_0005);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_FORBIDDEN, LOC_CACLTIME_0006);

        return (EC_FALSE);
    }

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter: "
                                             "arg: %s\n",
                                             arg);

    /*filter node*/
    cacltime_access_node_init(&cacltime_access_node);
    if(EC_FALSE == cacltime_access_filter_node(cacltime_md_id, uri, arg, &cacltime_access_node))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter: "
                                                 "filter node from uri '%s' and arg '%s' failed\n",
                                                 uri, arg);
        safe_free(uri, LOC_CACLTIME_0007);
        safe_free(arg, LOC_CACLTIME_0008);

        cacltime_access_node_clean(&cacltime_access_node);
        return (EC_FALSE);
    }

    safe_free(uri, LOC_CACLTIME_0009);
    safe_free(arg, LOC_CACLTIME_0010);

    if(EC_FALSE == cacltime_access_filter_check(cacltime_md_id, &cacltime_access_node))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter: "
                                                 "check failed\n");

        cacltime_access_node_clean(&cacltime_access_node);
        return (EC_FALSE);
    }

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter: "
                                             "check passed\n");

    cacltime_access_node_clean(&cacltime_access_node);

    return (EC_TRUE);
}

/*sig = md5( key . file-op . file-name . time)*/
EC_BOOL cacltime_access_filter_check(const UINT32 cacltime_md_id, const CACLTIME_ACCESS_NODE *cacltime_access_node)
{
    CACLTIME_MD                 *cacltime_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;
    char                        *key_str;

    uint8_t                      digest[ CMD5_DIGEST_LEN ];
    char                        *digest_str;

    uint8_t                     *cur;
    uint8_t                     *data;
    uint32_t                     data_len;

    uint32_t                     op_len;
    uint32_t                     path_len;
    uint32_t                     key_len;
    uint32_t                     time_len;

    uint64_t                     cur_time_nsec;
    uint64_t                     arg_time_nsec;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_access_filter: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    cacltime_md = CACLTIME_MD_GET(cacltime_md_id);

    r = CACLTIME_MD_NGX_HTTP_REQ(cacltime_md);

    /*check timestamp*/
    cur_time_nsec  = c_get_cur_time_nsec();
    arg_time_nsec  = c_str_to_uint64_t(CACLTIME_ACCESS_NODE_TIME(cacltime_access_node));
    if(cur_time_nsec > arg_time_nsec)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_check: "
                                                 "cur time '%"PRId64"' > arg time '%"PRId64"'\n",
                                                 cur_time_nsec, arg_time_nsec);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_FORBIDDEN, LOC_CACLTIME_0011);
        return (EC_FALSE);
    }

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter_check: "
                                             "cur time '%"PRId64"' <= arg time '%"PRId64"'\n",
                                             cur_time_nsec, arg_time_nsec);

    k = (const char *)CNGX_VAR_ACL_TOKEN;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_check: "
                                                 "get var '%s' failed\n",
                                                 k);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CACLTIME_0012);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_check: "
                                                 "not configure '%s'\n",
                                                 k);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_NOT_ALLOWED, LOC_CACLTIME_0013);
        return (EC_FALSE);
    }

    key_str = v;

    /*chekc md5*/
    op_len    = strlen(CACLTIME_ACCESS_NODE_OP(cacltime_access_node));
    path_len  = strlen(CACLTIME_ACCESS_NODE_PATH(cacltime_access_node));
    key_len   = strlen((char *)key_str);
    time_len  = strlen(CACLTIME_ACCESS_NODE_TIME(cacltime_access_node));

    data_len = key_len + op_len + path_len + time_len;

    data = safe_malloc(data_len, LOC_CACLTIME_0014);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_check: "
                                                 "malloc %u bytes failed\n",
                                                 data_len);

        c_str_free(key_str);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CACLTIME_0015);
        return (EC_FALSE);
    }

    cur = data;

    BCOPY(key_str, cur, key_len);
    cur += key_len;
    c_str_free(key_str);

    BCOPY(CACLTIME_ACCESS_NODE_OP(cacltime_access_node), cur, op_len);
    cur += op_len;

    BCOPY(CACLTIME_ACCESS_NODE_PATH(cacltime_access_node), cur, path_len);
    cur += path_len;

    BCOPY(CACLTIME_ACCESS_NODE_TIME(cacltime_access_node), cur, time_len);
    cur += time_len;

    cmd5_sum(data_len, data, digest);
    safe_free(data, LOC_CACLTIME_0016);

    digest_str = c_md5_to_hex_str(digest);
    if(0 != STRNCASECMP(digest_str, CACLTIME_ACCESS_NODE_SIG(cacltime_access_node), CMD5_DIGEST_LEN * 2))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_check: "
                                                 "mismatched md5: '%.*s' != '%.*s'\n",
                                                 CMD5_DIGEST_LEN * 2, digest_str,
                                                 CMD5_DIGEST_LEN * 2, CACLTIME_ACCESS_NODE_SIG(cacltime_access_node));

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_FORBIDDEN, LOC_CACLTIME_0017);
        return (EC_FALSE);
    }

    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter_check: "
                                             "matched md5: '%.*s'\n",
                                             CMD5_DIGEST_LEN * 2, digest_str);

    return (EC_TRUE);
}

EC_BOOL cacltime_access_filter_node(const UINT32 cacltime_md_id, const char *uri, const char *arg,
                                            CACLTIME_ACCESS_NODE *cacltime_access_node)
{
    char                         *uri_end;
    char                         *v;
    char                         *file_op_str;
    char                         *file_path_str;
    char                         *des;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_access_filter_node: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    uri_end             = (char *)uri + strlen(uri);
    file_op_str         = NULL_PTR;
    file_path_str       = NULL_PTR;

    for(v = (char *)uri; v < uri_end; v ++)
    {
        if('/' != (*v))
        {
            continue;
        }

        /*first slash*/
        if(NULL_PTR == file_op_str)
        {
            file_op_str = v;
            continue;
        }

        /*second slash*/
        if(NULL_PTR != file_op_str)
        {
            file_path_str = v;
            break;
        }
    }

    if(NULL_PTR == file_op_str || NULL_PTR == file_path_str)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_node: "
                                                 "invalid uri %s\n",
                                                 uri);

        return (EC_FALSE);
    }

    /*file op*/
    des  = c_str_n_dup(file_op_str, file_path_str - file_op_str);
    if(NULL_PTR == des)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_node: "
                                                 "dup op '%.*s' failed\n",
                                                 file_path_str - file_op_str, file_op_str);
        return (EC_FALSE);
    }
    CACLTIME_ACCESS_NODE_OP(cacltime_access_node) = des;
    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter_node: "
                                             "dup op '%s'\n",
                                             (char *)CACLTIME_ACCESS_NODE_OP(cacltime_access_node));

    /*file path*/
    des = c_str_dup(file_path_str);
    if(NULL_PTR == des)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_node: "
                                                 "dup path '%s' failed\n",
                                                 file_path_str);
        return (EC_FALSE);
    }
    CACLTIME_ACCESS_NODE_PATH(cacltime_access_node) = des;
    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter_node: "
                                             "dup path '%s'\n",
                                             (char *)CACLTIME_ACCESS_NODE_PATH(cacltime_access_node));

    if(EC_FALSE == cacltime_access_filter_time(cacltime_md_id, arg,
                                &CACLTIME_ACCESS_NODE_TIME(cacltime_access_node)))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_node: "
                                                 "filter time from arg '%s' failed\n",
                                                 arg);
        return (EC_FALSE);
    }

    if(EC_FALSE == cacltime_access_filter_sig(cacltime_md_id, arg,
                                &CACLTIME_ACCESS_NODE_SIG(cacltime_access_node)))
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_node: "
                                                 "filter sig from arg '%s' failed\n",
                                                 arg);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cacltime_access_filter_sig(const UINT32 cacltime_md_id, const char *arg, char **sig)
{
    char                        *start;
    char                        *end;
    char                        *des;

    const char                  *k;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_access_filter_sig: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    k = (const char *)"sig=";
    start = strstr((char *)arg, k);
    if(NULL_PTR == start)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_sig: "
                                                 "not found '%s' in req arg '%s'\n",
                                                 k, arg);
        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_FORBIDDEN, LOC_CACLTIME_0018);
        return (EC_FALSE);
    }
    start += sizeof("sig=") - 1;

    for(end = start; '\0' != (*end) && '&' != (*end); end ++)
    {
        /*do nothing*/
    }

    des = c_str_n_dup(start, (uint32_t)(end - start));
    if(NULL_PTR == des)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_sig: "
                                                 "dup '%.*s' failed\n",
                                                 end - start, start);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CACLTIME_0019);
        return (EC_FALSE);
    }


    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter_sig: "
                                             "sig: %s\n",
                                             des);
    (*sig) = des;

    return (EC_TRUE);
}

EC_BOOL cacltime_access_filter_time(const UINT32 cacltime_md_id, const char *arg, char **time)
{
    char                        *start;
    char                        *end;
    char                        *des;

    const char                  *k;

#if ( SWITCH_ON == CACLTIME_DEBUG_SWITCH )
    if ( CACLTIME_MD_ID_CHECK_INVALID(cacltime_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cacltime_access_filter_time: cacltime module #0x%lx not started.\n",
                cacltime_md_id);
        dbg_exit(MD_CACLTIME, cacltime_md_id);
    }
#endif/*CACLTIME_DEBUG_SWITCH*/

    k = (const char *)"t=";
    start = strstr((char *)arg, k);
    if(NULL_PTR == start)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_time: "
                                                 "not found '%s' in req arg '%s'\n",
                                                 k, arg);
        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_FORBIDDEN, LOC_CACLTIME_0020);
        return (EC_FALSE);
    }
    start += sizeof("t=") - 1;

    for(end = start; '\0' != (*end) && '&' != (*end); end ++)
    {
        /*do nothing*/
    }

    des = c_str_n_dup(start, (uint32_t)(end - start));
    if(NULL_PTR == des)
    {
        dbg_log(SEC_0171_CACLTIME, 0)(LOGSTDOUT, "error:cacltime_access_filter_time: "
                                                 "dup '%.*s' failed\n",
                                                 end - start, start);

        cacltime_set_ngx_rc(cacltime_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CACLTIME_0021);
        return (EC_FALSE);
    }


    dbg_log(SEC_0171_CACLTIME, 9)(LOGSTDOUT, "[DEBUG] cacltime_access_filter_time: "
                                             "t: %s\n",
                                             des);
    (*time) = des;

    return (EC_TRUE);
}

EC_BOOL cacltime_access_node_init(CACLTIME_ACCESS_NODE *cacltime_access_node)
{
    CACLTIME_ACCESS_NODE_OP(cacltime_access_node)   = NULL_PTR;
    CACLTIME_ACCESS_NODE_PATH(cacltime_access_node) = NULL_PTR;
    CACLTIME_ACCESS_NODE_TIME(cacltime_access_node) = NULL_PTR;
    CACLTIME_ACCESS_NODE_SIG(cacltime_access_node)  = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cacltime_access_node_clean(CACLTIME_ACCESS_NODE *cacltime_access_node)
{
    if(NULL_PTR != CACLTIME_ACCESS_NODE_OP(cacltime_access_node))
    {
        safe_free(CACLTIME_ACCESS_NODE_OP(cacltime_access_node), LOC_CACLTIME_0022);
        CACLTIME_ACCESS_NODE_OP(cacltime_access_node) = NULL_PTR;
    }

    if(NULL_PTR != CACLTIME_ACCESS_NODE_PATH(cacltime_access_node))
    {
        safe_free(CACLTIME_ACCESS_NODE_PATH(cacltime_access_node), LOC_CACLTIME_0023);
        CACLTIME_ACCESS_NODE_PATH(cacltime_access_node) = NULL_PTR;
    }

    if(NULL_PTR != CACLTIME_ACCESS_NODE_TIME(cacltime_access_node))
    {
        safe_free(CACLTIME_ACCESS_NODE_TIME(cacltime_access_node), LOC_CACLTIME_0024);
        CACLTIME_ACCESS_NODE_TIME(cacltime_access_node) = NULL_PTR;
    }

    if(NULL_PTR != CACLTIME_ACCESS_NODE_SIG(cacltime_access_node))
    {
        safe_free(CACLTIME_ACCESS_NODE_SIG(cacltime_access_node), LOC_CACLTIME_0025);
        CACLTIME_ACCESS_NODE_SIG(cacltime_access_node) = NULL_PTR;
    }

    return (EC_TRUE);
}



#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


