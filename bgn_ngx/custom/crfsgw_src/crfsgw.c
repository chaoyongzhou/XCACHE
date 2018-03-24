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

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "crb.h"

#include "cload.h"

#include "cbc.h"

#include "ccache.h"

#include "crfsmon.h"

#include "crfsgw.h"

#include "cngx.h"
#include "chttp.h"

#include "findex.inc"

#define CRFSGW_MD_CAPACITY()                  (cbc_md_capacity(MD_CRFSGW))

#define CRFSGW_MD_GET(crfsgw_md_id)     ((CRFSGW_MD *)cbc_md_get(MD_CRFSGW, (crfsgw_md_id)))

#define CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id)  \
    ((CMPI_ANY_MODI != (crfsgw_md_id)) && ((NULL_PTR == CRFSGW_MD_GET(crfsgw_md_id)) || (0 == (CRFSGW_MD_GET(crfsgw_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CRFSGW Module
*
**/
void crfsgw_print_module_status(const UINT32 crfsgw_md_id, LOG *log)
{
    CRFSGW_MD *crfsgw_md;
    UINT32      this_crfsgw_md_id;

    for( this_crfsgw_md_id = 0; this_crfsgw_md_id < CRFSGW_MD_CAPACITY(); this_crfsgw_md_id ++ )
    {
        crfsgw_md = CRFSGW_MD_GET(this_crfsgw_md_id);

        if(NULL_PTR != crfsgw_md && 0 < crfsgw_md->usedcounter )
        {
            sys_log(log,"CRFSGW Module # %u : %u refered\n",
                    this_crfsgw_md_id,
                    crfsgw_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CRFSGW module
*
**/
EC_BOOL crfsgw_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CRFSGW , 1);
}

/**
*
* unregister CRFSGW module
*
**/
EC_BOOL crfsgw_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CRFSGW);
}

/**
*
* start CRFSGW module
*
**/
UINT32 crfsgw_start(ngx_http_request_t *r)
{
    CRFSGW_MD *crfsgw_md;
    UINT32      crfsgw_md_id;

    TASK_BRD   *task_brd;

    task_brd = task_brd_default_get();

    crfsgw_md_id = cbc_md_new(MD_CRFSGW, sizeof(CRFSGW_MD));
    if(CMPI_ERROR_MODI == crfsgw_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CRFSGW module */
    crfsgw_md = (CRFSGW_MD *)cbc_md_get(MD_CRFSGW, crfsgw_md_id);
    crfsgw_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */

    CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md) = r;

    /*TODO: load all variables into module*/

    CRFSGW_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crfsgw_md) = BIT_FALSE;

    chttp_rsp_init(CRFSGW_MD_CHTTP_RSP(crfsgw_md));

    CRFSGW_MD_CONTENT_LENGTH(crfsgw_md)   = 0;

    CRFSGW_MD_SENT_BODY_SIZE(crfsgw_md)   = 0;

    CRFSGW_MD_NGX_LOC(crfsgw_md)          = LOC_NONE_END;
    CRFSGW_MD_NGX_RC(crfsgw_md)           = NGX_OK;

    crfsgw_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)crfsgw_end, crfsgw_md_id);

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_start: start CRFSGW module #%u\n", crfsgw_md_id);

    return ( crfsgw_md_id );
}

/**
*
* end CRFSGW module
*
**/
void crfsgw_end(const UINT32 crfsgw_md_id)
{
    CRFSGW_MD *crfsgw_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)crfsgw_end, crfsgw_md_id);

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);
    if(NULL_PTR == crfsgw_md)
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_end: crfsgw_md_id = %u not exist.\n", crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < crfsgw_md->usedcounter )
    {
        crfsgw_md->usedcounter --;
        return ;
    }

    if ( 0 == crfsgw_md->usedcounter )
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_end: crfsgw_md_id = %u is not started.\n", crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }

    CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md) = NULL_PTR;

    CRFSGW_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crfsgw_md) = BIT_FALSE;

    chttp_rsp_clean(CRFSGW_MD_CHTTP_RSP(crfsgw_md));

    CRFSGW_MD_CONTENT_LENGTH(crfsgw_md) = 0;

    CRFSGW_MD_SENT_BODY_SIZE(crfsgw_md) = 0;

    CRFSGW_MD_NGX_LOC(crfsgw_md)        = LOC_NONE_END;
    CRFSGW_MD_NGX_RC(crfsgw_md)         = NGX_OK;

    /* free module */
    crfsgw_md->usedcounter = 0;

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "crfsgw_end: stop CRFSGW module #%u\n", crfsgw_md_id);
    cbc_md_free(MD_CRFSGW, crfsgw_md_id);

    return ;
}

EC_BOOL crfsgw_get_ngx_rc(const UINT32 crfsgw_md_id, ngx_int_t *rc, UINT32 *location)
{
    CRFSGW_MD                  *crfsgw_md;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_get_ngx_rc: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CRFSGW_MD_NGX_RC(crfsgw_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CRFSGW_MD_NGX_LOC(crfsgw_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL crfsgw_set_ngx_rc(const UINT32 crfsgw_md_id, const ngx_int_t rc, const UINT32 location)
{
    CRFSGW_MD                  *crfsgw_md;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_set_ngx_rc: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    /*do not override*/
    if(NGX_OK != CRFSGW_MD_NGX_RC(crfsgw_md))
    {
        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_override_ngx_rc: "
                                                "ignore rc %d due to its %d now\n",
                                                rc, CRFSGW_MD_NGX_RC(crfsgw_md));
        return (EC_TRUE);
    }

    CRFSGW_MD_NGX_RC(crfsgw_md)  = rc;
    CRFSGW_MD_NGX_LOC(crfsgw_md) = location;

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_set_ngx_rc: "
                                            "set rc %d\n",
                                            rc);

    return (EC_TRUE);
}


/*only for failure!*/
EC_BOOL crfsgw_override_ngx_rc(const UINT32 crfsgw_md_id, const ngx_int_t rc, const UINT32 location)
{
    CRFSGW_MD                  *crfsgw_md;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_override_ngx_rc: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    if(rc == CRFSGW_MD_NGX_RC(crfsgw_md))
    {
        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_override_ngx_rc: "
                                                "ignore same rc %d\n",
                                                rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CRFSGW_MD_NGX_RC(crfsgw_md))
    {
        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_override_ngx_rc: "
                                                "modify rc %d => %d\n",
                                                CRFSGW_MD_NGX_RC(crfsgw_md), rc);
        CRFSGW_MD_NGX_RC(crfsgw_md)  = rc;
        CRFSGW_MD_NGX_LOC(crfsgw_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_override_ngx_rc: "
                                            "set rc %d\n",
                                            rc);

    CRFSGW_MD_NGX_RC(crfsgw_md)  = rc;
    CRFSGW_MD_NGX_LOC(crfsgw_md) = location;

    return (EC_TRUE);
}


EC_BOOL crfsgw_get_rfs_server(const UINT32 crfsgw_md_id, const CSTRING *cache_uri_cstr, UINT32 *cache_srv_tcid, UINT32 *cache_srv_ipaddr, UINT32 *cache_srv_port)
{
    CRFSGW_MD                  *crfsgw_md;

    const char                 *k;
    char                       *v;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_get_rfs_server: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    if(EC_FALSE == crfsmon_crfs_store_http_srv_get(task_brd_default_get_crfsmon_id(),
                                                cache_uri_cstr,
                                                cache_srv_tcid, cache_srv_ipaddr, cache_srv_port))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_get_rfs_server: "
                                               "fetch cache server of '%s' failed\n",
                                               (char *)cstring_get_str(cache_uri_cstr));
        return (EC_FALSE);
    }

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_get_rfs_server: "
                                           "fetch cache server (tcid %s, http %s:%ld) of '%s' done\n",
                                           c_word_to_ipv4(*cache_srv_tcid),
                                           c_word_to_ipv4(*cache_srv_ipaddr), (*cache_srv_port),
                                           (char *)cstring_get_str(cache_uri_cstr));

    k = (const char *)"cache_srv_tcid";
    v = c_word_to_ipv4(*cache_srv_tcid);
    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md), k, v);

    k = (const char *)"cache_srv_ipaddr";
    v = c_word_to_ipv4(*cache_srv_ipaddr);
    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md), k, v);

    k = (const char *)"cache_srv_port";
    v = c_word_to_str(*cache_srv_port);
    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md), k, v);

    return (EC_TRUE);
}

EC_BOOL crfsgw_get_cache_path(const UINT32 crfsgw_md_id, CSTRING *cache_path)
{
    CRFSGW_MD                   *crfsgw_md;

    ngx_http_request_t          *r;

    char                        *v;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_get_cache_path: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    r = CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md);

    if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_get_cache_path: "
                                               "fetch req uri failed\n");

        return (EC_FALSE);
    }

    cstring_append_str(cache_path, (const UINT8 *)v);

    safe_free(v, LOC_CRFSGW_0001);

    if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
    {
        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_get_cache_path: "
                                               "[cngx] get args '%s'\n",
                                               v);

        if(EC_FALSE == cstring_append_str(cache_path, (const UINT8 *)"?"))
        {
            dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_get_cache_path: "
                                                   "append '?' failed\n");
            safe_free(v, LOC_CRFSGW_0002);
            return (EC_FALSE);
        }

        if(EC_FALSE == cstring_append_str(cache_path, (const UINT8 *)v))
        {
            dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_get_cache_path: "
                                                   "append args '%s' failed\n",
                                                   v);
            safe_free(v, LOC_CRFSGW_0003);
            return (EC_FALSE);
        }
        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_get_cache_path: "
                                               "append args '%s' to cache_path done\n",
                                               v);
        safe_free(v, LOC_CRFSGW_0004);
    }

    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL crfsgw_content_handler(const UINT32 crfsgw_md_id)
{
    CRFSGW_MD                   *crfsgw_md;

    ngx_http_request_t          *r;

    char                        *method_str;
    char                        *uri_str;
    CSTRING                      cache_path;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_handler: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    r = CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md);

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CRFSGW_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crfsgw_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CRFSGW_MD_CNGX_DEBUG_SWITCH_ON_FLAG(crfsgw_md) = BIT_TRUE;
    }

    if(EC_FALSE == cngx_get_req_method_str(r, &method_str) || NULL_PTR == method_str)
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_handler: "
                                               "fetch req method failed\n");

        crfsgw_set_ngx_rc(crfsgw_md_id, NGX_HTTP_BAD_REQUEST, LOC_CRFSGW_0005);
        return (EC_FALSE);
    }

    cstring_init(&cache_path, NULL_PTR);

    if(EC_FALSE == crfsgw_get_cache_path(crfsgw_md_id, &cache_path))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_handler: "
                                               "get cahce_path failed\n");

        crfsgw_set_ngx_rc(crfsgw_md_id, NGX_HTTP_BAD_REQUEST, LOC_CRFSGW_0006);

        safe_free(method_str, LOC_CRFSGW_0007);
        cstring_clean(&cache_path);
        return (EC_FALSE);
    }

    uri_str = (char *)cstring_get_str(&cache_path);

    if(EC_FALSE == crfsgw_content_dispatch(crfsgw_md_id, method_str, uri_str))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_handler: "
                                               "dispatch ('%s', '%s') failed\n",
                                               method_str, uri_str);

        crfsgw_set_ngx_rc(crfsgw_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CRFSGW_0008);

        safe_free(method_str, LOC_CRFSGW_0009);
        cstring_clean(&cache_path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_handler: "
                                           "dispatch ('%s', '%s') done\n",
                                           method_str, uri_str);
    safe_free(method_str, LOC_CRFSGW_0010);
    cstring_clean(&cache_path);

    return (EC_TRUE);
}

EC_BOOL crfsgw_content_dispatch(const UINT32 crfsgw_md_id, const char *method_str, const char *uri_str)
{
    CRFSGW_MD                   *crfsgw_md;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_dispatch: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    if(0 == STRCASECMP(method_str, (const char *)"GET"))
    {
        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_dispatch: "
                                               "dispatch method '%s'\n",
                                               method_str);
        return crfsgw_content_dispatch_get_request(crfsgw_md_id, uri_str);
    }

    dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_dispatch: "
                                           "reject to dispatch method '%s'\n",
                                           method_str);
    return (EC_FALSE);
}

EC_BOOL crfsgw_content_dispatch_get_request(const UINT32 crfsgw_md_id, const char *uri_str)
{
    CRFSGW_MD                   *crfsgw_md;

    ngx_http_request_t          *r;
    uint32_t                     uri_len;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_dispatch_get_request: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    r = CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md);

    uri_len = (uint32_t)strlen(uri_str);

    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                        (const char *)"cache_uri",
                        (const char *)uri_str);

    if(CONST_STR_LEN("/getsmf/") < uri_len
    && EC_TRUE == c_memcmp((const uint8_t *)uri_str, CONST_UINT8_STR_AND_LEN("/getsmf/")))
    {
        const char          *path;

        path = uri_str + CONST_STR_LEN("/getsmf/") - 1;
        return crfsgw_content_dispatch_get_request_getsmf(crfsgw_md_id, path);
    }

    if(CONST_STR_LEN("/dsmf/") < uri_len
    && EC_TRUE == c_memcmp((const uint8_t *)uri_str, CONST_UINT8_STR_AND_LEN("/dsmf/")))
    {
        const char          *path;

        path = uri_str + CONST_STR_LEN("/dsmf/") - 1;
        return crfsgw_content_dispatch_get_request_dsmf(crfsgw_md_id, path);
    }

    if(CONST_STR_LEN("/ddir/") < uri_len
    && EC_TRUE == c_memcmp((const uint8_t *)uri_str, CONST_UINT8_STR_AND_LEN("/ddir/")))
    {
        const char          *path;

        path = uri_str + CONST_STR_LEN("/ddir/") - 1;
        return crfsgw_content_dispatch_get_request_ddir(crfsgw_md_id, path);
    }
#if 0
    if(CONST_STR_LEN("/qtree") <= uri_len
    && EC_TRUE == c_memcmp(uri_str, CONST_UINT8_STR_AND_LEN("/qtree")))
    {
        const char          *path;

        path = uri_str + CONST_STR_LEN("/qtree");
        return crfsgw_content_dispatch_get_request_qtree(crfsgw_md_id, path);
    }
#endif
    dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_dispatch_get_request: "
                                           "reject to dispatch uri '%s'\n",
                                           uri_str);

    CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_NOT_IMPLEMENTED;

    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                        (const char *)"error",
                        (const char *)"reject to dispatch");

    return crfsgw_content_send_response(crfsgw_md_id);
}

EC_BOOL crfsgw_content_dispatch_get_request_getsmf(const UINT32 crfsgw_md_id, const char *path)
{
    CRFSGW_MD                   *crfsgw_md;

    ngx_http_request_t          *r;

    CBYTES                       seg_cbytes;

    CSTRING                      cache_uri_cstr;
    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;/*http port*/

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_dispatch_get_request_getsmf: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    r = CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md);

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_dispatch_get_request_getsmf: "
                                           "path = '%s'\n",
                                           path);


    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                        (const char *)"cache_path",
                        (const char *)path);

    cstring_set_str(&cache_uri_cstr, (const UINT8 *)path);

    if(EC_FALSE == crfsgw_get_rfs_server(crfsgw_md_id,
                                        &cache_uri_cstr,
                                        &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_dispatch_get_request_getsmf: "
                                               "fetch cache server of '%s' failed\n",
                                               (char *)cstring_get_str(&cache_uri_cstr));

        CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_BAD_GATEWAY;

        chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                            (const char *)"error",
                            (const char *)"fetch cache server failed");

        cstring_unset(&cache_uri_cstr);

        return crfsgw_content_send_response(crfsgw_md_id);
    }

    cbytes_init(&seg_cbytes);

    if(EC_FALSE == ccache_file_read(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                    &cache_uri_cstr,
                                    CHTTP_SEG_ERR_OFFSET, CHTTP_SEG_ERR_OFFSET, /*whole seg file*/
                                    &seg_cbytes))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_dispatch_get_request_getsmf: "
                                               "read '%s' from cache failed\n",
                                               (char *)cstring_get_str(&cache_uri_cstr));

        CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_NOT_FOUND;

        chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                            (const char *)"error",
                            (const char *)"read cache failed");

        cstring_unset(&cache_uri_cstr);
        cbytes_clean(&seg_cbytes);

        return crfsgw_content_send_response(crfsgw_md_id);
    }

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_dispatch_get_request_getsmf: "
                                            "read '%s', %ld bytes from cache done\n",
                                            (char *)cstring_get_str(&cache_uri_cstr),
                                            cbytes_len(&seg_cbytes));

    CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_OK;

    /*handover body*/
    cbytes_handover(&seg_cbytes, CHTTP_RSP_BODY(CRFSGW_MD_CHTTP_RSP(crfsgw_md)));

    cstring_unset(&cache_uri_cstr);
    cbytes_clean(&seg_cbytes);

    return crfsgw_content_send_response(crfsgw_md_id);
}

EC_BOOL crfsgw_content_dispatch_get_request_dsmf(const UINT32 crfsgw_md_id, const char *path)
{
    CRFSGW_MD                   *crfsgw_md;

    ngx_http_request_t          *r;

    CSTRING                      cache_uri_cstr;
    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;/*http port*/

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_dispatch_get_request_dsmf: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    r = CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md);

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_dispatch_get_request_dsmf: "
                                           "path = '%s'\n",
                                           path);

    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                        (const char *)"cache_path",
                        (const char *)path);

    cstring_set_str(&cache_uri_cstr, (const UINT8 *)path);

    if(EC_FALSE == crfsgw_get_rfs_server(crfsgw_md_id,
                                        &cache_uri_cstr,
                                        &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_dispatch_get_request_dsmf: "
                                               "fetch cache server of '%s' failed\n",
                                               (char *)cstring_get_str(&cache_uri_cstr));

        CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_BAD_GATEWAY;

        chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                            (const char *)"error",
                            (const char *)"fetch cache server failed");

        cstring_unset(&cache_uri_cstr);

        return crfsgw_content_send_response(crfsgw_md_id);
    }

    if(EC_FALSE == ccache_file_retire(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                    &cache_uri_cstr))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_dispatch_get_request_dsmf: "
                                               "retire '%s' from cache failed\n",
                                               (char *)cstring_get_str(&cache_uri_cstr));

        CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_FORBIDDEN;

        chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                            (const char *)"error",
                            (const char *)"retire cache failed");

        cstring_unset(&cache_uri_cstr);

        return crfsgw_content_send_response(crfsgw_md_id);
    }

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_dispatch_get_request_dsmf: "
                                            "retire '%s' from cache done\n",
                                            (char *)cstring_get_str(&cache_uri_cstr));

    CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_OK;

    cstring_unset(&cache_uri_cstr);

    return crfsgw_content_send_response(crfsgw_md_id);
}

EC_BOOL crfsgw_content_dispatch_get_request_ddir(const UINT32 crfsgw_md_id, const char *path)
{
    CRFSGW_MD                   *crfsgw_md;

    ngx_http_request_t          *r;

    CSTRING                      cache_uri_cstr;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_dispatch_get_request_ddir: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    r = CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md);

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_dispatch_get_request_ddir: "
                                           "path = '%s'\n",
                                           path);

    chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                        (const char *)"cache_path",
                        (const char *)path);

    cstring_set_str(&cache_uri_cstr, (const UINT8 *)path);

    if(EC_FALSE == ccache_dir_delete(&cache_uri_cstr))
    {
        dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_dispatch_get_request_ddir: "
                                               "ddir '%s' from cache failed\n",
                                               (char *)cstring_get_str(&cache_uri_cstr));

        CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_FORBIDDEN;

        chttp_rsp_add_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md),
                            (const char *)"error",
                            (const char *)"ddir cache failed");

        cstring_unset(&cache_uri_cstr);

        return crfsgw_content_send_response(crfsgw_md_id);
    }

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_dispatch_get_request_ddir: "
                                            "ddir '%s' from cache done\n",
                                            (char *)cstring_get_str(&cache_uri_cstr));

    CHTTP_RSP_STATUS(CRFSGW_MD_CHTTP_RSP(crfsgw_md)) = CHTTP_OK;

    cstring_unset(&cache_uri_cstr);

    return crfsgw_content_send_response(crfsgw_md_id);
}

EC_BOOL crfsgw_content_header_out_filter(const UINT32 crfsgw_md_id)
{
    CRFSGW_MD                   *crfsgw_md;

    CBYTES                      *body;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_header_out_filter: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    body = CHTTP_RSP_BODY(CRFSGW_MD_CHTTP_RSP(crfsgw_md));

    k = (const char *)"Content-Length";
    v = c_word_to_str(CBYTES_LEN(body));
    chttp_rsp_renew_header(CRFSGW_MD_CHTTP_RSP(crfsgw_md), k, v);

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_header_out_filter: "
                                           "renew header '%s':'%s' done\n",
                                           k, v);
    return (EC_TRUE);
}

EC_BOOL crfsgw_content_send_response(const UINT32 crfsgw_md_id)
{
    CRFSGW_MD                 *crfsgw_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CRFSGW_DEBUG_SWITCH )
    if ( CRFSGW_MD_ID_CHECK_INVALID(crfsgw_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:crfsgw_content_send_response: crfsgw module #0x%lx not started.\n",
                crfsgw_md_id);
        dbg_exit(MD_CRFSGW, crfsgw_md_id);
    }
#endif/*CRFSGW_DEBUG_SWITCH*/

    crfsgw_md = CRFSGW_MD_GET(crfsgw_md_id);

    r = CRFSGW_MD_NGX_HTTP_REQ(crfsgw_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(EC_FALSE == crfsgw_content_header_out_filter(crfsgw_md_id))
        {
            dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_send_response: "
                                                   "header_out filter failed\n");
            crfsgw_set_ngx_rc(crfsgw_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CRFSGW_0011);
            return (EC_FALSE);
        }

        cngx_import_header_out(r, CRFSGW_MD_CHTTP_RSP(crfsgw_md));

        cngx_disable_write_delayed(r);

        if(EC_FALSE == chttp_rsp_has_body(CRFSGW_MD_CHTTP_RSP(crfsgw_md)))
        {
            cngx_set_header_only(r);
        }

        if(EC_FALSE == cngx_send_header(r, &(CRFSGW_MD_NGX_RC(crfsgw_md))))
        {
            dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_send_response: "
                                                   "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_send_response: "
                                               "send header done\n");
    }

    /*send body*/
    if(EC_TRUE == chttp_rsp_has_body(CRFSGW_MD_CHTTP_RSP(crfsgw_md)))
    {
        CBYTES          *body;
        uint8_t         *data;
        uint32_t         len;

        body = CHTTP_RSP_BODY(CRFSGW_MD_CHTTP_RSP(crfsgw_md));

        data = CBYTES_BUF(body);
        len  = (uint32_t)CBYTES_LEN(body);
        if(EC_FALSE == cngx_send_body(r, data, len,
                                       CNGX_SEND_BODY_NO_MORE_FLAG | CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                                       &(CRFSGW_MD_NGX_RC(crfsgw_md))))
        {
            dbg_log(SEC_0034_CRFSGW, 0)(LOGSTDOUT, "error:crfsgw_content_send_response: "
                                                    "send body failed\n");

            return (EC_FALSE);
        }

        CRFSGW_MD_SENT_BODY_SIZE(crfsgw_md) += len;

        dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_send_response: "
                                               "send body done => complete %ld bytes\n",
                                               CRFSGW_MD_SENT_BODY_SIZE(crfsgw_md));
    }

    dbg_log(SEC_0034_CRFSGW, 9)(LOGSTDOUT, "[DEBUG] crfsgw_content_send_response: "
                                           "send response done\n");
    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


