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

#include "cbc.h"
#include "cmisc.h"

#include "task.h"

#include "cmpie.h"

#include "crange.h"

#include "ccache.h"

#include "chttp.h"

#include "cngx.h"
#include "cngx_headers.h"
#include "cngx_script.h"
#include "cngx_upstream.h"
#include "cvendor.h"

#include "findex.inc"

#define CVENDOR_MD_CAPACITY()                  (cbc_md_capacity(MD_CVENDOR))

#define CVENDOR_MD_GET(cvendor_md_id)     ((CVENDOR_MD *)cbc_md_get(MD_CVENDOR, (cvendor_md_id)))

#define CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id)  \
    ((CMPI_ANY_MODI != (cvendor_md_id)) && ((NULL_PTR == CVENDOR_MD_GET(cvendor_md_id)) || (0 == (CVENDOR_MD_GET(cvendor_md_id)->usedcounter))))

static const char *g_cvendor_304_headers[ ] = {
    (const char *)"Connection",
    (const char *)"ETag",
    (const char *)"Date",
    (const char *)"Last-Modified",
    (const char *)"Expires",
    (const char *)"Age",
};
static const UINT32 g_cvendor_304_headers_num = sizeof(g_cvendor_304_headers)/sizeof(g_cvendor_304_headers[0]);

/**
*   for test only
*
*   to query the status of CVENDOR Module
*
**/
void cvendor_print_module_status(const UINT32 cvendor_md_id, LOG *log)
{
    CVENDOR_MD *cvendor_md;
    UINT32      this_cvendor_md_id;

    for( this_cvendor_md_id = 0; this_cvendor_md_id < CVENDOR_MD_CAPACITY(); this_cvendor_md_id ++ )
    {
        cvendor_md = CVENDOR_MD_GET(this_cvendor_md_id);

        if(NULL_PTR != cvendor_md && 0 < cvendor_md->usedcounter )
        {
            sys_log(log,"CVENDOR Module # %u : %u refered\n",
                    this_cvendor_md_id,
                    cvendor_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CVENDOR module
*
**/
EC_BOOL cvendor_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CVENDOR , 1024);
}

/**
*
* unregister CVENDOR module
*
**/
EC_BOOL cvendor_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CVENDOR);
}

/**
*
* start CVENDOR module
*
**/
UINT32 cvendor_start(ngx_http_request_t *r)
{
    CVENDOR_MD *cvendor_md;
    UINT32      cvendor_md_id;

    //TASK_BRD   *task_brd;

    uint32_t    cache_seg_max_num;
    uint32_t    cache_seg_size;

    //task_brd = task_brd_default_get();

    cvendor_md_id = cbc_md_new(MD_CVENDOR, sizeof(CVENDOR_MD));
    if(CMPI_ERROR_MODI == cvendor_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CVENDOR module */
    cvendor_md = (CVENDOR_MD *)cbc_md_get(MD_CVENDOR, cvendor_md_id);
    cvendor_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */
    cngx_get_cache_seg_max_num(r, &cache_seg_max_num);
    CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) = cache_seg_max_num;

    cngx_get_cache_seg_size(r, &cache_seg_size);
    CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) = cache_seg_size;

    cstring_init(CVENDOR_MD_CACHE_PATH(cvendor_md), NULL_PTR);
    CVENDOR_MD_CACHE_STATUS(cvendor_md) = CNGX_CACHE_STATUS_MISS;/*default*/

    CVENDOR_MD_NGX_HTTP_REQ(cvendor_md) = r;

    /*TODO: load all variables into module*/
    cngx_option_init(CVENDOR_MD_CNGX_OPTION(cvendor_md));

    CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md)          = BIT_FALSE;
    CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md)        = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)              = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG(cvendor_md)           = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_ADJUSTED_FLAG(cvendor_md)           = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_FILTERED_FLAG(cvendor_md)           = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md) = BIT_FALSE;
    CVENDOR_MD_CNGX_USE_GZIP_FLAG(cvendor_md)                 = BIT_FALSE;
    CVENDOR_MD_CNGX_DIRECT_IMS_FLAG(cvendor_md)               = BIT_FALSE;
    CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md)                = BIT_FALSE;
    CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md)                 = BIT_FALSE;
    CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md)          = BIT_FALSE;
    CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)                    = BIT_FALSE;
    CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md)                    = BIT_FALSE;
    CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md)                 = BIT_FALSE;

    crange_mgr_init(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    CVENDOR_MD_CONTENT_LENGTH(cvendor_md)   = 0;
    cstring_init(CVENDOR_MD_CACHED_ETAG(cvendor_md), NULL_PTR);
    cstring_init(CVENDOR_MD_CACHED_LAST_MODIFED(cvendor_md), NULL_PTR);

    cstring_init(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), NULL_PTR);
    cstring_init(CVENDOR_MD_HEADER_ETAG(cvendor_md), NULL_PTR);

    CVENDOR_MD_DEPTH(cvendor_md)            = 0;

    CVENDOR_MD_CHTTP_REQ(cvendor_md)        = NULL_PTR;
    CVENDOR_MD_CHTTP_RSP(cvendor_md)        = NULL_PTR;
    CVENDOR_MD_CHTTP_STORE(cvendor_md)      = NULL_PTR;
    CVENDOR_MD_CHTTP_STAT(cvendor_md)       = NULL_PTR;

    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)    = CVENDOR_ERR_SEG_NO;
    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md)   = 0;

    CVENDOR_MD_NGX_LOC(cvendor_md)          = LOC_NONE_END;
    CVENDOR_MD_NGX_RC(cvendor_md)           = NGX_OK;

    cvendor_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cvendor_end, cvendor_md_id);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_start: start CVENDOR module #%ld\n", cvendor_md_id);

    return ( cvendor_md_id );
}

/**
*
* end CVENDOR module
*
**/
void cvendor_end(const UINT32 cvendor_md_id)
{
    CVENDOR_MD *cvendor_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cvendor_end, cvendor_md_id);

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);
    if(NULL_PTR == cvendor_md)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_end: cvendor_md_id = %ld not exist.\n", cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cvendor_md->usedcounter )
    {
        cvendor_md->usedcounter --;
        return ;
    }

    if ( 0 == cvendor_md->usedcounter )
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_end: cvendor_md_id = %ld is not started.\n", cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }

    CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) = 0;
    cstring_clean(CVENDOR_MD_CACHE_PATH(cvendor_md));
    CVENDOR_MD_CACHE_STATUS(cvendor_md) = NULL_PTR;

    CVENDOR_MD_NGX_HTTP_REQ(cvendor_md) = NULL_PTR;
    cngx_option_clean(CVENDOR_MD_CNGX_OPTION(cvendor_md));

    CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md)          = BIT_FALSE;
    CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md)        = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)              = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG(cvendor_md)           = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_ADJUSTED_FLAG(cvendor_md)           = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_FILTERED_FLAG(cvendor_md)           = BIT_FALSE;
    CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md) = BIT_FALSE;
    CVENDOR_MD_CNGX_USE_GZIP_FLAG(cvendor_md)                 = BIT_FALSE;
    CVENDOR_MD_CNGX_DIRECT_IMS_FLAG(cvendor_md)               = BIT_FALSE;
    CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md)                = BIT_FALSE;
    CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md)                 = BIT_FALSE;
    CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md)          = BIT_FALSE;
    CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)                    = BIT_FALSE;
    CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md)                    = BIT_FALSE;
    CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md)                 = BIT_FALSE;

    crange_mgr_clean(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    CVENDOR_MD_CONTENT_LENGTH(cvendor_md)   = 0;
    cstring_clean(CVENDOR_MD_CACHED_ETAG(cvendor_md));
    cstring_clean(CVENDOR_MD_CACHED_LAST_MODIFED(cvendor_md));

    cstring_clean(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md));
    cstring_clean(CVENDOR_MD_HEADER_ETAG(cvendor_md));

    CVENDOR_MD_DEPTH(cvendor_md)            = 0;

    if(NULL_PTR != CVENDOR_MD_CHTTP_REQ(cvendor_md))
    {
        chttp_req_free(CVENDOR_MD_CHTTP_REQ(cvendor_md));
        CVENDOR_MD_CHTTP_REQ(cvendor_md) = NULL_PTR;
    }

    if(NULL_PTR != CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        chttp_rsp_free(CVENDOR_MD_CHTTP_RSP(cvendor_md));
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = NULL_PTR;
    }

    if(NULL_PTR != CVENDOR_MD_CHTTP_STORE(cvendor_md))
    {
        chttp_store_free(CVENDOR_MD_CHTTP_STORE(cvendor_md));
        CVENDOR_MD_CHTTP_STORE(cvendor_md) = NULL_PTR;
    }

    if(NULL_PTR != CVENDOR_MD_CHTTP_STAT(cvendor_md))
    {
        chttp_stat_free(CVENDOR_MD_CHTTP_STAT(cvendor_md));
        CVENDOR_MD_CHTTP_STAT(cvendor_md) = NULL_PTR;
    }

    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)    = CVENDOR_ERR_SEG_NO;
    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md)   = 0;

    CVENDOR_MD_NGX_LOC(cvendor_md)          = LOC_NONE_END;
    CVENDOR_MD_NGX_RC(cvendor_md)           = NGX_OK;

    /* free module */
    cvendor_md->usedcounter = 0;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "cvendor_end: stop CVENDOR module #%ld\n", cvendor_md_id);
    cbc_md_free(MD_CVENDOR, cvendor_md_id);

    return ;
}

EC_BOOL cvendor_get_ngx_rc(const UINT32 cvendor_md_id, ngx_int_t *rc, UINT32 *location)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_get_ngx_rc: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CVENDOR_MD_NGX_RC(cvendor_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CVENDOR_MD_NGX_LOC(cvendor_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cvendor_set_ngx_rc(const UINT32 cvendor_md_id, const ngx_int_t rc, const UINT32 location)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_set_ngx_rc: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    /*do not override*/
    if(NGX_OK != CVENDOR_MD_NGX_RC(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_set_ngx_rc: "
                                                "ignore rc %ld due to its %ld now\n",
                                                rc, CVENDOR_MD_NGX_RC(cvendor_md));
        return (EC_TRUE);
    }

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);
    if(EC_FALSE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_set_ngx_rc: "
                                                "ignore rc %ld due to header had sent out\n",
                                                rc);
        cngx_disable_keepalive(r);
        return (EC_TRUE);
    }

    CVENDOR_MD_NGX_RC(cvendor_md)  = rc;
    CVENDOR_MD_NGX_LOC(cvendor_md) = location;

    cngx_disable_keepalive(r);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_set_ngx_rc: "
                                            "set rc %ld\n",
                                            rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cvendor_override_ngx_rc(const UINT32 cvendor_md_id, const ngx_int_t rc, const UINT32 location)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_override_ngx_rc: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(rc == CVENDOR_MD_NGX_RC(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_override_ngx_rc: "
                                                "ignore same rc %ld\n",
                                                rc);
        return (EC_TRUE);
    }

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);
    if(EC_FALSE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_override_ngx_rc: "
                                                "ignore rc %ld due to header had sent out\n",
                                                rc);
        cngx_disable_keepalive(r);
        return (EC_TRUE);
    }

    if(NGX_OK != CVENDOR_MD_NGX_RC(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_override_ngx_rc: "
                                                "modify rc %ld => %ld\n",
                                                CVENDOR_MD_NGX_RC(cvendor_md), rc);
        CVENDOR_MD_NGX_RC(cvendor_md)  = rc;
        CVENDOR_MD_NGX_LOC(cvendor_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_override_ngx_rc: "
                                            "set rc %ld\n",
                                            rc);

    CVENDOR_MD_NGX_RC(cvendor_md)  = rc;
    CVENDOR_MD_NGX_LOC(cvendor_md) = location;

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cvendor_handover_ngx_rc(const UINT32 cvendor_md_id, const UINT32 location)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_handover_ngx_rc: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(NULL_PTR != CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        CHTTP_RSP                   *chttp_rsp;

        chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

        if(CHTTP_STATUS_NONE != CHTTP_RSP_STATUS(chttp_rsp))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_handover_ngx_rc: "
                                                    "set rc to rsp status %u\n",
                                                    CHTTP_RSP_STATUS(chttp_rsp));

            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_RSP_STATUS(chttp_rsp), location);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_set_store_cache_path(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_set_store_cache_path: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_set_store_cache_path(r, CVENDOR_MD_CACHE_PATH(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_set_store_cache_path: set store_path failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_set_store_cache_path: set store_path '%s'\n",
                    (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)));
    return (EC_TRUE);
}

EC_BOOL cvendor_set_hot_path_flag(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    ngx_http_request_t          *r;

    const char                  *k;
    const char                  *v;

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"is-hot-path";
    v = (const char *)"true";

    if(EC_TRUE == cngx_has_header_in(r, k, v))
    {
        CVENDOR_MD_CNGX_HOT_PATH_FLAG(cvendor_md) = EC_TRUE;
    }
    else
    {
        CVENDOR_MD_CNGX_HOT_PATH_FLAG(cvendor_md) = EC_FALSE;
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_get_cache_seg_uri(const UINT32 cvendor_md_id, const UINT32 seg_no, CSTRING *cache_uri)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_get_cache_seg_uri: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(BIT_TRUE == CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md))
    {
        if(EC_FALSE == cstring_format(cache_uri, "%s%s/%ld",
                                                  (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)),
                                                  (char *)CHTTP_STORE_GZIP_POSTFIX,
                                                  seg_no))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg_uri: "
                                                     "gen string '%s%s/%ld' failed\n",
                                                    (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)),
                                                    (char *)CHTTP_STORE_GZIP_POSTFIX,
                                                     seg_no);
            return (EC_FALSE);
        }
    }
    else
    {
        if(EC_FALSE == cstring_format(cache_uri, "%s/%ld",
                                                  (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)),
                                                  seg_no))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg_uri: "
                                                     "gen string '%s/%ld' failed\n",
                                                    (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)),
                                                     seg_no);
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_cache_seg_uri: cache_uri '%s'\n",
                    (char *)cstring_get_str(cache_uri));

    return (EC_TRUE);
}

/*get whole seg*/
EC_BOOL cvendor_get_cache_seg(const UINT32 cvendor_md_id, const UINT32 seg_no, CBYTES *seg_cbytes)
{
    CVENDOR_MD                  *cvendor_md;

    CSTRING                      cache_uri_cstr;
    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;/*http port*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_get_cache_seg: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    /*check seg num*/
    if(CVENDOR_ERR_SEG_NO != seg_no
    && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < seg_no)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg: seg no %ld overflow!\n",
                                                seg_no);
        return (EC_FALSE);
    }

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cvendor_get_cache_seg_uri(cvendor_md_id, seg_no, &cache_uri_cstr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_cache_seg: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if (EC_TRUE == CVENDOR_MD_CNGX_HOT_PATH_FLAG(cvendor_md))
    {
        task_brd_default_add_hot_path(&cache_uri_cstr);
    }

    if(EC_FALSE == task_brd_default_get_store_http_srv(
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg: "
                                                "fetch cache server of '%s' failed\n",
                                                (char *)cstring_get_str(&cache_uri_cstr));
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_file_read(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                    &cache_uri_cstr,
                                    CHTTP_SEG_ERR_OFFSET, CHTTP_SEG_ERR_OFFSET, /*whole seg file*/
                                    seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_get_cache_seg: "
                                                "read '%s' from cache failed\n",
                                                (char *)cstring_get_str(&cache_uri_cstr));

        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_cache_seg: "
                                            "read '%s', %ld bytes from cache done\n",
                                            (char *)cstring_get_str(&cache_uri_cstr),
                                            cbytes_len(seg_cbytes));

    cstring_clean(&cache_uri_cstr);

    return (EC_TRUE);
}

EC_BOOL cvendor_get_cache_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *range_seg, CBYTES *seg_cbytes)
{
    CVENDOR_MD                  *cvendor_md;

    CSTRING                      cache_uri_cstr;

    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_get_cache_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    /*check seg num*/
    if(CVENDOR_ERR_SEG_NO != CRANGE_SEG_NO(range_seg)
    && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CRANGE_SEG_NO(range_seg))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg_n: seg no %ld overflow!\n",
                                                CRANGE_SEG_NO(range_seg));
        return (EC_FALSE);
    }

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cvendor_get_cache_seg_uri(cvendor_md_id, CRANGE_SEG_NO(range_seg), &cache_uri_cstr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg_n: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_cache_seg_n: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if (EC_TRUE == CVENDOR_MD_CNGX_HOT_PATH_FLAG(cvendor_md))
    {
        task_brd_default_add_hot_path(&cache_uri_cstr);
    }

    if(EC_FALSE == task_brd_default_get_store_http_srv(
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_cache_seg_n: "
                                                "fetch cache server of '%s' failed\n",
                                                (char *)cstring_get_str(&cache_uri_cstr));
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_file_read(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                    &cache_uri_cstr,
                                    CRANGE_SEG_S_OFFSET(range_seg),
                                    CRANGE_SEG_E_OFFSET(range_seg),
                                    seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_get_cache_seg_n: "
                                                "read '%s' from cache failed\n",
                                                (char *)cstring_get_str(&cache_uri_cstr));

        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_cache_seg_n: "
                                            "read '%s', %ld bytes from cache done\n",
                                            (char *)cstring_get_str(&cache_uri_cstr),
                                            cbytes_len(seg_cbytes));

    cstring_clean(&cache_uri_cstr);

    return (EC_TRUE);
}

EC_BOOL cvendor_wait_cache_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *range_seg, CBYTES *seg_cbytes)
{
    CVENDOR_MD                  *cvendor_md;

    CSTRING                      cache_uri_cstr;

    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_wait_cache_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    /*check seg num*/
    if(CVENDOR_ERR_SEG_NO != CRANGE_SEG_NO(range_seg)
    && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CRANGE_SEG_NO(range_seg))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_wait_cache_seg_n: seg no %ld overflow!\n",
                                                CRANGE_SEG_NO(range_seg));
        return (EC_FALSE);
    }

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cvendor_get_cache_seg_uri(cvendor_md_id, CRANGE_SEG_NO(range_seg), &cache_uri_cstr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_wait_cache_seg_n: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_wait_cache_seg_n: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if(EC_FALSE == task_brd_default_get_store_http_srv(
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_wait_cache_seg_n: "
                                                "fetch cache server of '%s' failed\n",
                                                (char *)cstring_get_str(&cache_uri_cstr));
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_file_wait_and_read(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                             &cache_uri_cstr,
                                             CRANGE_SEG_S_OFFSET(range_seg),
                                             CRANGE_SEG_E_OFFSET(range_seg),
                                             seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_wait_cache_seg_n: "
                                                "read '%s' from cache failed\n",
                                                (char *)cstring_get_str(&cache_uri_cstr));

        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_wait_cache_seg_n: "
                                            "read '%s', %ld bytes from cache done\n",
                                            (char *)cstring_get_str(&cache_uri_cstr),
                                            cbytes_len(seg_cbytes));

    cstring_clean(&cache_uri_cstr);

    return (EC_TRUE);
}

EC_BOOL cvendor_get_req_range_segs(const UINT32 cvendor_md_id, const UINT32 seg_size)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_get_req_range_segs: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(NULL_PTR != r->headers_in.range)
    {
        char       *range_str;

        range_str = (char *)(r->headers_in.range->value.data);
        ASSERT('\0' == range_str[ r->headers_in.range->value.len ]);

        if(EC_FALSE == crange_parse_range(range_str, CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_req_range_segs: "
                                                    "invalid Range '%s'\n",
                                                    range_str);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_RANGE_NOT_SATISFIABLE, LOC_CVENDOR_0001);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_req_range_segs: "
                                                "parse Range '%s' done\n",
                                                range_str);

        CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)  = BIT_TRUE;

        if(1 < crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
        {
            CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG(cvendor_md) = BIT_TRUE;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_req_range_segs: "
                                                    "set CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG flag to %s\n",
                                                    c_bit_bool_str(CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG(cvendor_md)));
        }

        if(EC_TRUE == crange_mgr_is_start_zero_endless(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
        {
            CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md) = BIT_TRUE;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_req_range_segs: "
                                                    "set CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG flag to %s\n",
                                                    c_bit_bool_str(CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md)));
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_req_range_segs: "
                                                "split Range '%s' into segs done\n",
                                                range_str);
        return (EC_TRUE);
    }

    /*support extensible Request-Range*/
    k = (const char *)"Request-Range";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
         dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_req_range_segs: "
                                                 "[cngx] fetch header '%s' failed\n",
                                                 k);
         return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        if(EC_FALSE == crange_parse_range(v, CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_req_range_segs: "
                                                    "invalid %s '%s'\n",
                                                    k, v);
            safe_free(v, LOC_CVENDOR_0002);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_req_range_segs: "
                                                "parse %s '%s' done\n",
                                                k, v);

        CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)  = BIT_TRUE;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_req_range_segs: "
                                                "split %s '%s' into segs done\n",
                                                k, v);
        safe_free(v, LOC_CVENDOR_0003);
        return (EC_TRUE);
    }

    CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)  = BIT_FALSE;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_req_range_segs: no Range\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_get_rsp_length_segs(const UINT32 cvendor_md_id, const UINT32 seg_size)
{
    CVENDOR_MD                  *cvendor_md;

    UINT32                       content_length;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_get_rsp_length_segs: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    ASSERT(EC_TRUE == crange_mgr_is_empty(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)));

    content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

    while(0 == content_length)
    {
        char       *content_range_str;
        char       *content_length_str;

        content_range_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Range");
        if(NULL_PTR != content_range_str)
        {
            UINT32      range_start;
            UINT32      range_end;

            if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_rsp_length_segs: "
                                                        "invalid Content-Range '%s'\n",
                                                        content_range_str);
                return (EC_FALSE);
            }

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_rsp_length_segs: "
                                                    "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                    content_range_str,
                                                    range_start, range_end, content_length);
            /*fall through*/
            break;
        }

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR != content_length_str)
        {
            content_length = c_str_to_word(content_length_str);

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_rsp_length_segs: "
                                                    "parse Content-Length '%s' to %ld\n",
                                                    content_length_str,
                                                    content_length);
            /*fall through*/
            break;
        }

        /*fall through*/
        break;
    }

    if(0 < content_length)
    {
        if(EC_FALSE == crange_mgr_add_range(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md),
                                            0,
                                            content_length - 1,
                                            seg_size))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_get_rsp_length_segs: "
                                                    "split content_length '%ld' into segs failed\n",
                                                    content_length);

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_get_rsp_length_segs: "
                                                "split content_length '%ld' into segs done\n",
                                                content_length);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_is_redirect_rsp(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;
    uint32_t                     status;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_is_redirect_rsp: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_is_redirect_rsp: rsp status %u\n",
                        status);

    if(CHTTP_MOVED_PERMANENTLY == status
    || CHTTP_MOVED_TEMPORARILY == status)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cvendor_is_specific_redirect_rsp(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    uint32_t                     status;
    uint32_t                     des_status;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_is_specific_redirect_rsp: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_is_specific_redirect_rsp: "
                                            "rsp status %u\n",
                                            status);

    if(EC_FALSE == cngx_get_redirect_specific(r, status, &des_status, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_is_specific_redirect_rsp: "
                                                "got fialed\n");
        return (EC_FALSE);
    }

    if(CHTTP_STATUS_NONE == des_status || NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_is_specific_redirect_rsp: "
                                                "no spec => ignore\n");
        return (EC_FALSE);
    }

    if(CHTTP_MOVED_PERMANENTLY != des_status
    && CHTTP_MOVED_TEMPORARILY != des_status)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_is_specific_redirect_rsp: "
                                                "unsupported status %u\n",
                                                des_status);

        if(NULL_PTR != v)
        {
            safe_free(v, LOC_CVENDOR_0004);
        }
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_is_specific_redirect_rsp: "
                                                "status %u, but redirect url is null\n",
                                                des_status);
        return (EC_FALSE);
    }

    /*set to rsp header*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = des_status;
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_is_specific_redirect_rsp: "
                                            "modify rsp status: %u => %u\n",
                                            status, des_status);
    k = (const char *)"Location";
    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_is_specific_redirect_rsp: "
                                            "add rsp header '%s':'%s'\n",
                                            k, v);

    safe_free(v, LOC_CVENDOR_0005);
    return (EC_TRUE);
}

EC_BOOL cvendor_filter_rsp_range(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

    UINT32                       content_length;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_filter_rsp_range: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

    if(0 == content_length)
    {
        char                       *content_range_str;

        UINT32                      range_start;
        UINT32                      range_end;

        content_range_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Range");
        if(NULL_PTR == content_range_str)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_rsp_range: no 'Content-Range'\n");

            /*we always send rang request to orig. if no 'Content-Range', that may be chunked response*/
            //return cvendor_content_chunk_procedure(cvendor_md_id);
            return (EC_TRUE);
        }

        if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_rsp_range: "
                                                    "invalid Content-Range '%s'\n",
                                                    content_range_str);
            return (EC_FALSE);
        }

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_rsp_range: "
                                                "Content-Range '%s' => content_length %ld\n",
                                                content_range_str,
                                                CVENDOR_MD_CONTENT_LENGTH(cvendor_md));
    }

    /*adjust range_start and range_end*/
    if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)
    && BIT_FALSE == CVENDOR_MD_CNGX_RANGE_ADJUSTED_FLAG(cvendor_md))
    {
        if(EC_FALSE == crange_mgr_adjust(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md),
                                         CVENDOR_MD_CONTENT_LENGTH(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_rsp_range: "
                                                    "crange_mgr_adjust with content_length %ld failed\n",
                                                    CVENDOR_MD_CONTENT_LENGTH(cvendor_md));
            return (EC_FALSE);
        }

        if(do_log(SEC_0175_CVENDOR, 9))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_rsp_range: "
                                                    "after crange_nodes adjust with content_length %ld =>\n",
                                                    CVENDOR_MD_CONTENT_LENGTH(cvendor_md));
            crange_mgr_print_no_seg(LOGSTDOUT, CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));
        }

        if(0 == crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_rsp_range: "
                                                    "crange_mgr_adjust with content_length %ld and no valid returned\n",
                                                    CVENDOR_MD_CONTENT_LENGTH(cvendor_md));

            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_RANGE_NOT_SATISFIABLE, LOC_CVENDOR_0006);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_rsp_range: "
                                                "crange_nodes adjust with content_length %ld done\n",
                                                CVENDOR_MD_CONTENT_LENGTH(cvendor_md));

        if(EC_FALSE == crange_mgr_split(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md), CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_rsp_range: "
                                                    "crange_nodes split with seg size %ld failed\n",
                                                    CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md));
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_rsp_range: "
                                                "crange_nodes split with seg size %ld done\n",
                                                CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md));

        CVENDOR_MD_CNGX_RANGE_ADJUSTED_FLAG(cvendor_md) = BIT_TRUE;
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_FILTERED_FLAG(cvendor_md))
    {
        /*filter req range_segs*/
        if(0 < content_length)
        {
            crange_mgr_filter(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md), 0, content_length - 1, content_length);
        }
        CVENDOR_MD_CNGX_RANGE_FILTERED_FLAG(cvendor_md) = BIT_TRUE;
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_rsp_range: done\n");

    return (EC_TRUE);
}

/*for chttp_req to orig server*/
EC_BOOL cvendor_filter_header_in_common(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_filter_header_in_common: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*del debug headers*/
    chttp_req_del_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)CNGX_BGN_MOD_DBG_SWITCH_HDR);
    chttp_req_del_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)CNGX_BGN_MOD_DBG_NAME_HDR);
    chttp_req_del_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)CNGX_BGN_MOD_DBG_ERROR_HDR);
    chttp_req_del_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)CNGX_BGN_MOD_DBG_INFO_HDR);
    chttp_req_del_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)CNGX_BGN_MOD_DBG_EXPIRE_HDR);

    chttp_req_del_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)"Proxy-Connection");

    if(1)
    {
        const char *k;
        char       *v;

        k = (const char *)CNGX_VAR_VISIABLE_HOSTNAME;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, (const char *)"UNKNOWN_HOST"))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_in_common: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            cstring_set_str(CHTTP_REQ_DEVICE_NAME(CVENDOR_MD_CHTTP_REQ(cvendor_md)), (const UINT8 *)v);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_in_common: "
                                                    "get var '%s' val '%s'\n",
                                                    k, v);
        }
    }

    if(1)
    {
        const char *k;
        char       *v;

        k = (const char *)CNGX_VAR_TRACE_ID;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, (const char *)"UNKNOWN_TRACE"))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_in_common: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            cstring_set_str(CHTTP_REQ_TRACE_ID(CVENDOR_MD_CHTTP_REQ(cvendor_md)), (const UINT8 *)v);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_in_common: "
                                                    "get var '%s' val '%s'\n",
                                                    k, v);
        }
    }

    if(EC_FALSE == cngx_script_dir1_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_in_common: "
                                                "script dir1 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_in_common: "
                                            "script dir1 filter done\n");

    if(EC_FALSE == cngx_headers_dir1_filter(r, CVENDOR_MD_CHTTP_REQ(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_in_common: "
                                                "headers dir1 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_in_common: "
                                            "headers dir1 filter done\n");
    return (EC_TRUE);
}

/*before sending response to client*/
EC_BOOL cvendor_filter_header_out_common(const UINT32 cvendor_md_id, const char *procedure)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_filter_header_out_common: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    cvendor_filter_header_out_cache_control(cvendor_md_id);

    if(NULL_PTR != procedure && 0 == STRCASECMP(procedure, (const char *)"cache"))
    {
        const char                  *v;

        v = (const char *)CNGX_CACHE_STATUS_HIT;

        CVENDOR_MD_CACHE_STATUS(cvendor_md) = v;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_common: "
                                                "set cache status to '%s' done\n",
                                                v);
    }

    if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        k = (const char *)CNGX_BGN_MOD_DBG_X_PROCEDURE_TAG;
        v = (const char *)procedure;
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_common: "
                                                    "add header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }

        k = (const char *)CNGX_BGN_MOD_DBG_X_PROXY_TAG;
        v = (const char *)CNGX_BGN_MOD_DBG_X_PROXY_VAL;
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_common: "
                                                    "add header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }

        k = (const char *)CNGX_BGN_MOD_DBG_X_MODULE_TAG;
        v = (const char *)CVENDOR_MODULE_NAME;
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_common: "
                                                    "add header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
    }

    /*renew Date*/
    if(0)
    {
        const char                  *k;
        const char                  *v;

        k = (const char *)"Date";
        v = (const char *)c_http_time(task_brd_default_get_time());
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_common: "
                                                    "renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
    }

    /*renew Age*/
    do
    {
        const char                  *k;
        const char                  *v;

        uint32_t                     age;
        time_t                       date_time;
        time_t                       cur_time;

        k = (const char *)"Age";
        v = (const char *)chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            break; /*terminate*/
        }
        age = c_str_to_uint32_t(v);

        k = (const char *)"Date";
        v = (const char *)chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            break; /*terminate*/
        }
        date_time = c_parse_http_time((uint8_t *)v, strlen(v));

        cur_time  = task_brd_default_get_time();

        if(cur_time <= date_time)
        {
            break; /*terminate*/
        }

        k = (const char *)"Age";
        v = (const char *)c_uint32_t_to_str(age + (cur_time - date_time));
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_common: "
                                                    "renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_common: "
                                                "renew header %s:%s done\n",
                                                k, v);
    }while(0);

    cngx_set_cache_status(r, CVENDOR_MD_CACHE_STATUS(cvendor_md));

    /*merge header function. it should be optional function*/
    if(EC_TRUE == cngx_is_merge_header_switch_on(r))
    {
        chttp_rsp_merge_header(CVENDOR_MD_CHTTP_RSP(cvendor_md));
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_common: "
                                                "merge header done\n");
    }

    if(EC_FALSE == cngx_script_dir3_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_common: "
                                                "script dir3 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_common: "
                                            "script dir3 filter done\n");

    if(EC_FALSE == cngx_headers_dir3_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_common: "
                                                "headers dir3 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_common: "
                                            "headers dir3 filter done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_filter_header_out_cache_control(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;
    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_filter_header_out_cache_control: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(BIT_FALSE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
    {

        const char                  *k;
        //char                        *v;

        k = (const char *)CHTTP_RSP_X_CACHE_CONTROL;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_filter_header_out_single_range(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    CRANGE_MGR                  *crange_mgr;
    CRANGE_NODE                 *crange_node;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_filter_header_out_single_range: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);

    ASSERT(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md));
    ASSERT(1 == crange_mgr_node_num(crange_mgr));

    /*only one crange_node*/
    crange_node = crange_mgr_first_node(crange_mgr);

    if(0 != CRANGE_NODE_RANGE_START(crange_node)
     || CRANGE_NODE_RANGE_END(crange_node) + 1 != CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];
        UINT32                       content_length; /*rsp body length*/

        content_length = (CRANGE_NODE_RANGE_END(crange_node) + 1 - CRANGE_NODE_RANGE_START(crange_node));

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_single_range: "
                                                    "renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "renew header %s:%s done\n",
                                                k, v);

        snprintf(header_buf, sizeof(header_buf), "bytes %ld-%ld/%ld",
                             CRANGE_NODE_RANGE_START(crange_node),
                             CRANGE_NODE_RANGE_END(crange_node),
                             CVENDOR_MD_CONTENT_LENGTH(cvendor_md));
        k = (const char *)"Content-Range";
        v = (const char *)header_buf;
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_single_range: "
                                                    "renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "renew header %s:%s done\n",
                                                k, v);
    }
    else if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];
        UINT32                       content_length; /*rsp body length*/

        content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_single_range: "
                                                    "[ZERO_ENDLESS] renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "[ZERO_ENDLESS] renew header %s:%s done\n",
                                                k, v);

        snprintf(header_buf, sizeof(header_buf), "bytes %ld-%ld/%ld",
                             (UINT32)0,
                             content_length - 1,
                             content_length);
        k = (const char *)"Content-Range";
        v = (const char *)header_buf;
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_single_range: "
                                                    "[ZERO_ENDLESS] renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "[ZERO_ENDLESS] renew header %s:%s done\n",
                                                k, v);
    }
    else if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];
        UINT32                       content_length; /*whole content length*/

        content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

        snprintf(header_buf, sizeof(header_buf), "bytes %ld-%ld/%ld",
                             (UINT32)0,
                             content_length - 1,
                             content_length);

        k = (const char *)"Content-Range";
        v = (const char *)header_buf;
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "error:cvendor_filter_header_out_single_range: "
                                                    "[cngx] range exist and covers whole content => renew header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "[cngx] range exist and covers whole content => renew header '%s':'%s' done\n",
                                                k, v);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "error:cvendor_filter_header_out_single_range: "
                                                    "[cngx] range exist and covers whole content => renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "[cngx] range exist and covers whole content => renew header %s:%s done\n",
                                                k, v);
    }
    else
    {
        const char                  *k;
        const char                  *v;

        UINT32                       content_length; /*whole content length*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "range covers whole content => delete header '%s' done\n",
                                                k);

        content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_single_range: "
                                                    "renew header %s:%s failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                                "renew header %s:%s done\n",
                                                k, v);

    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_single_range: "
                                            "done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_filter_header_out_multi_range(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    CRANGE_MGR                  *crange_mgr;
    CLIST                       *crange_nodes;
    CLIST_DATA                  *clist_data;

    UINT32                       content_length;
    UINT32                       body_size;
    char                        *boundary;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_filter_header_out_multi_range: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    ASSERT(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md));
    ASSERT(1 < crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)));

    content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);
    boundary       = c_get_day_time_str();

    crange_mgr     = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);
    crange_nodes   = CRANGE_MGR_RANGE_NODES(crange_mgr);

    body_size      = 0;

    CLIST_LOOP_NEXT(crange_nodes, clist_data)
    {
        CRANGE_NODE                 *crange_node;

        crange_node = (CRANGE_NODE *)CLIST_DATA_DATA(clist_data);

        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));

        if(EC_FALSE == cstring_format(CRANGE_NODE_BOUNDARY(crange_node),
                                       (const char *)""
                                       "\n"
                                       "--%s\n"
                                       "Content-Type: application/octet-stream\n"
                                       "Content-Range: bytes %ld-%ld/%ld\n"
                                       "\n",
                                       boundary,
                                       CRANGE_NODE_RANGE_START(crange_node),
                                       CRANGE_NODE_RANGE_END(crange_node),
                                       content_length))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_multi_range:"
                                                    "format boundary '"
                                                    "\n"
                                                    "--%s\n"
                                                    "Content-Type: application/octet-stream\n"
                                                    "Content-Range: bytes %ld-%ld/%ld\n"
                                                    "\n"
                                                    "' failed\n",
                                                    boundary,
                                                    CRANGE_NODE_RANGE_START(crange_node),
                                                    CRANGE_NODE_RANGE_END(crange_node),
                                                    content_length);
            return (EC_FALSE);
        }

        body_size += cstring_get_len(CRANGE_NODE_BOUNDARY(crange_node));
        body_size += CRANGE_NODE_RANGE_END(crange_node) + 1 - CRANGE_NODE_RANGE_START(crange_node);
    }

    /*last boundary*/
    cstring_clean(CRANGE_MGR_BOUNDARY(crange_mgr));
    if(EC_FALSE == cstring_format(CRANGE_MGR_BOUNDARY(crange_mgr),
                                   (const char *)""
                                   "\n"
                                   "--%s--\n",
                                   boundary))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_filter_header_out_multi_range:"
                                                "format last boundary '"
                                                "\n"
                                                "--%s\n"
                                                "' failed\n",
                                                boundary);
        return (EC_FALSE);
    }

    body_size += cstring_get_len(CRANGE_MGR_BOUNDARY(crange_mgr));

    CRANGE_MGR_BODY_SIZE(crange_mgr) = body_size;

    /*handle rsp heander*/

    if(1)
    {
        const char                  *k;

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    }

    if(1)
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];

        char                        *boundary_str;
        uint32_t                     boundary_len;

        crange_mgr_get_naked_boundary(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md), &boundary_str, &boundary_len);

        snprintf(header_buf, sizeof(header_buf), "multipart/byteranges; boundary=%.*s",
                                                 boundary_len, boundary_str);

        k = (const char *)"Content-Type";
        v = (const char *)header_buf;
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_multi_range: "
                                                "renew '%s':'%s' done\n",
                                                k, v);
    }

    if(1)
    {
        const char                  *k;
        const char                  *v;

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(body_size);

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_multi_range: "
                                                "renew header %s:%s done\n",
                                                k, v);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_filter_header_out_range(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    UINT32                       crange_node_num;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_filter_header_out_range: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    ASSERT(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md));

    crange_node_num = crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    if(1 == crange_node_num)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_range: "
                                                "crange_node_num = %ld => single range\n",
                                                crange_node_num);
        return cvendor_filter_header_out_single_range(cvendor_md_id);
    }

    if(1 < crange_node_num)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_range: "
                                                "crange_node_num = %ld => multi range\n",
                                                crange_node_num);
        return cvendor_filter_header_out_multi_range(cvendor_md_id);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_filter_header_out_range: "
                                            "no range, done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_renew_header_cache(const UINT32 cvendor_md_id, const char *k, const char *v)
{
    //CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

    UINT32                       seg_no;
    CSTRING                      cache_uri_cstr;

    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;

    CSTRKV_MGR                  *cstrkv_mgr;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_renew_header_cache: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    seg_no = 0;

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cvendor_get_cache_seg_uri(cvendor_md_id, seg_no, &cache_uri_cstr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_renew_header_cache: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_renew_header_cache: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if(EC_FALSE == task_brd_default_get_store_http_srv(
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_renew_header_cache: "
                                                "fetch cache server of '%s' failed\n",
                                                (char *)cstring_get_str(&cache_uri_cstr));
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    cstrkv_mgr = cstrkv_mgr_new();
    if(NULL_PTR == cstrkv_mgr)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_renew_header_cache: "
                                                "new cstrkv_mgr failed\n");
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == cstrkv_mgr_add_kv_str(cstrkv_mgr, k, v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_renew_header_cache: "
                                                "add '%s':'%s' to cstrkv_mgr failed\n",
                                                k, v);
        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_renew_headers(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                         &cache_uri_cstr, cstrkv_mgr, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_renew_header_cache: "
                                                "renew header '%s':'%s' in cache '%s' failed\n",
                                                k, v,
                                                (char *)cstring_get_str(&cache_uri_cstr));

        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_renew_header_cache: "
                                            "renew header '%s':'%s' in cache '%s' done\n",
                                            k, v,
                                            (char *)cstring_get_str(&cache_uri_cstr));

    cstrkv_mgr_free(cstrkv_mgr);
    cstring_clean(&cache_uri_cstr);

    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL cvendor_content_handler(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_handler: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: enter\n");


    if(EC_FALSE == cngx_script_dir0_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_handler: "
                                                "script dir0 filter failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0007);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                            "script dir0 filter done\n");

    if(EC_FALSE == cngx_headers_dir0_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_handler: "
                                                "headers dir0 filter failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0008);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                            "headers dir0 filter done\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md) = BIT_TRUE;
    }

    /*preload mode*/
    if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md)
    && EC_TRUE == cngx_is_method(r, (const char *)"PUT"))
    {
        CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md) = BIT_TRUE;
    }

    if(EC_FALSE == cngx_option_set_cacheable_method(r, CVENDOR_MD_CNGX_OPTION(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_handler: set cachable method failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_REQUEST, LOC_CVENDOR_0009);
        return (EC_FALSE);
    }

    if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
    {
        if(BIT_TRUE == CNGX_OPTION_CACHEABLE_METHOD(CVENDOR_MD_CNGX_OPTION(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: method cachable\n");
            cngx_set_header_out_kv(r, (const char *)CNGX_BGN_MOD_DBG_X_METHOD_CACHABLE_TAG, (const char *)"yes");
        }
        else
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: method not cachable\n");
            cngx_set_header_out_kv(r, (const char *)CNGX_BGN_MOD_DBG_X_METHOD_CACHABLE_TAG, (const char *)"no");
        }
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        CHTTP_REQ       chttp_req_t;

        chttp_req_init(&chttp_req_t);

        cngx_export_header_in(r, &chttp_req_t);

        cngx_export_method(r, &chttp_req_t);
        cngx_export_uri(r, &chttp_req_t);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: cngx req is -------------------------\n");
        chttp_req_print_plain(LOGSTDOUT, &chttp_req_t);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: -------------------------------------\n");

        chttp_req_clean(&chttp_req_t);
    }

    /*parse 'Range' in cngx http req header*/
    if(EC_FALSE == cvendor_get_req_range_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_handler: "
                                                "get Range from cngx req failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_REQUEST, LOC_CVENDOR_0010);
        return (EC_FALSE);
    }

    if(EC_TRUE == cngx_is_direct_orig_switch_on(r))
    {
        /*direct orig would cache none, preload need cache everthing => conflict*/
        if(BIT_TRUE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_handler: "
                                                    "direct orig and preload procedure conflict\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_REQUEST, LOC_CVENDOR_0011);
            return (EC_FALSE);
        }

        /*direct procedure to orig server*/
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                                "direct orig switch on => direct procedure\n");

        return cvendor_content_direct_procedure(cvendor_md_id);
    }

    /*note: clear pragma header in conf if not support it*/
    k = (const char *)"Pragma";
    v = (const char *)"no-cache";
    if(EC_TRUE == cngx_has_header_in(r, k, v))
    {
        /*direct procedure to orig server*/
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                                "%s:%s => direct procedure\n",
                                                k, v);
        return cvendor_content_direct_procedure(cvendor_md_id);
    }

    /*note: clear cache control header in conf if not support it*/
    k = (const char *)"Cache-Control";
    v = (const char *)"no-cache";
    if(EC_TRUE == cngx_has_header_in(r, k, v))
    {
        /*direct procedure to orig server*/
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                                "%s:%s => direct procedure\n",
                                                k, v);
        return cvendor_content_direct_procedure(cvendor_md_id);
    }

    cngx_option_set_only_if_cached(r, CVENDOR_MD_CNGX_OPTION(cvendor_md));
    if(BIT_FALSE == CNGX_OPTION_ONLY_IF_CACHED(CVENDOR_MD_CNGX_OPTION(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                                "only_if_cached is false\n");

        /*note: for HEAD request, not direct orig now but check cache*/
        if(EC_FALSE == cngx_is_head_method(r))
        {
            if(BIT_FALSE == CNGX_OPTION_CACHEABLE_METHOD(CVENDOR_MD_CNGX_OPTION(cvendor_md)))
            {
                /*direct procedure to orig server*/
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                                        "not cacheable method => direct procedure\n");
                return cvendor_content_direct_procedure(cvendor_md_id);
            }
        }
    }

    /*else fall through*/

    /*check gzip header*/
    if(EC_TRUE == cngx_has_header_in(r, (const char *)"Accept-Encoding", (const char *)"gzip"))
    {
        CVENDOR_MD_CNGX_USE_GZIP_FLAG(cvendor_md)  = BIT_TRUE;
        CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md) = BIT_TRUE; /*set same as CNGX at present*/

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: "
                                                "set use-gzip\n");
    }

    if(EC_FALSE == cvendor_set_store_cache_path(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_handler: set store_path failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0012);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_handler: set store_path '%s'\n",
                    (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)));

    if(EC_TRUE == cngx_is_force_orig_switch_on(r))
    {
        CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md) = BIT_TRUE;
    }
    else
    {
        CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md) = BIT_FALSE;
    }

    /*check if this url is hot_path */
    cvendor_set_hot_path_flag(cvendor_md_id);

    if(EC_TRUE == cvendor_content_cache_procedure(cvendor_md_id))
    {
        if(BIT_TRUE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            return cvendor_content_preload_procedure(cvendor_md_id);
        }
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cvendor_content_head_header_in_filter_upstream(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CHTTP_REQ                   *chttp_req;

    UINT32                       upstream_peer_ipaddr;
    UINT32                       upstream_peer_port;

    uint8_t                     *upstream_name_str;
    uint32_t                     upstream_name_len;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_in_filter_upstream: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_upstream_get_name(r, &upstream_name_str, &upstream_name_len))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_upstream: "
                                                "get upstream name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_upstream_fetch(r, &upstream_peer_ipaddr, &upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_upstream: "
                                                "upstream '%.*s' fetch server failed\n",
                                                upstream_name_len, upstream_name_str);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_upstream: "
                                            "upstream '%.*s' fetch server %s:%ld\n",
                                            upstream_name_len, upstream_name_str,
                                            c_word_to_ipv4(upstream_peer_ipaddr), upstream_peer_port);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    if(EC_FALSE == chttp_req_set_ipaddr_word(chttp_req, upstream_peer_ipaddr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_upstream: "
                                                "[conf] set ipaddr '%s' of upsteam '%.*s' to http req failed\n",
                                                c_word_to_ipv4(upstream_peer_ipaddr),
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0013);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_upstream: "
                                            "[conf] set ipaddr '%s' of upsteam '%.*s' to http req done\n",
                                            c_word_to_ipv4(upstream_peer_ipaddr),
                                            upstream_name_len, upstream_name_str);

    if(EC_FALSE == chttp_req_set_port_word(chttp_req, upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_upstream: "
                                                "[cngx] set port '%ld' of upsteam '%.*s' to http req failed\n",
                                                upstream_peer_port,
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0014);
        return (EC_FALSE);
    }

    chttp_req_set_conn_fail_callback(chttp_req,
                                     (CHTTP_REQ_CONN_FAIL_CALLBACK)cngx_upstream_set_down,
                                     (void *)r);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_upstream: "
                                            "[cngx] set port '%ld' of upsteam '%.*s' to http req done\n",
                                            upstream_peer_port,
                                            upstream_name_len, upstream_name_str);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_header_in_filter_server(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_in_filter_server: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_head_header_in_filter_server: "
                                                    "get '%s' failed\n",
                                                    k);
            continue;
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_server: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            c_str_split(v, ":", segs, 2);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, segs[ 0 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_head_header_in_filter_server: "
                                                        "[cngx] set host of '%s' failed\n",
                                                        segs[ 0 ]);
                safe_free(v, LOC_CVENDOR_0015);

                continue;
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_server: "
                                                    "[cngx] set host '%s' to http req done\n",
                                                    segs[ 0 ]);
            safe_free(v, LOC_CVENDOR_0016);

            return (EC_TRUE);
        }
    }

    cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0017);
    return (EC_FALSE);
}

EC_BOOL cvendor_content_head_header_in_filter_host(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_in_filter_host: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config head host and port*/
    k = (const char *)CNGX_VAR_ORIG_HOST;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_host: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_host: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_host: "
                                                    "[conf] set ipaddr of host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0018);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0019);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_host: "
                                                "[conf] set ipaddr of host '%s' to http req done\n",
                                                v);

        if(EC_FALSE == chttp_req_renew_header(chttp_req, (const char *)"Host", v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_host: "
                                                    "[conf] set host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0020);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0021);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_host: "
                                                "[conf] set host '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0022);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_header_in_filter_port(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_in_filter_port: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config head port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_port: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_port: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0023);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_port: "
                                                "[conf] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0024);
        return (EC_TRUE);
    }

    if(EC_TRUE == chttp_req_is_local(chttp_req))
    {
        /*set default head port*/
        if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[default] set default port '%d' to http req done\n",
                                                    CNGX_ORIG_HTTP_PORT_DEFAULT);
        }
        else
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[default] set default port '%d' to https req done\n",
                                                    CNGX_ORIG_HTTPS_PORT_DEFAULT);
        }
        return (EC_TRUE);
    }

    /*when cngx NOT config head port*/
    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_port: "
                                                    "get '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_port: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            if(2 == c_str_split(v, ":", segs, 2))
            {
                /*set port*/
                if(EC_FALSE == chttp_req_set_port(chttp_req, segs[ 1 ]))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_port: "
                                                            "[cngx] set port '%s' to http req failed\n",
                                                            segs[ 1 ]);
                    safe_free(v, LOC_CVENDOR_0025);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_port: "
                                                        "[cngx] set port '%s' to http req done\n",
                                                        segs[ 1 ]);
                safe_free(v, LOC_CVENDOR_0026);

                return (EC_TRUE);
            }

            safe_free(v, LOC_CVENDOR_0027);

            /*continue*/
        }
    }

    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0028);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0029);

        return (EC_TRUE);
    }

    /*should never reach here*/

    /*set default head port*/
    if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                "[default] set default port '%d' to http req done\n",
                                                CNGX_ORIG_HTTP_PORT_DEFAULT);
    }
    else
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                "[default] set default port '%d' to https req done\n",
                                                CNGX_ORIG_HTTPS_PORT_DEFAULT);
    }
    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_header_in_filter_ipaddr(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_in_filter_ipaddr: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig ipaddr*/
    k = (const char *)CNGX_VAR_ORIG_IPADDR;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_ipaddr: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_ipaddr: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter_ipaddr: "
                                                    "[conf] set ipaddr '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0030);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0031);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter_ipaddr: "
                                                "[conf] set ipaddr  '%s' to http req done\n",
                                                v);

        safe_free(v, LOC_CVENDOR_0032);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_header_in_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_in_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*set ssl flag*/
    do
    {
        UINT32  ssl_flag;

        /*when cngx switch ssl on, then orig over https*/
        k = (const char *)CNGX_VAR_SSL_ORIG_SWITCH;
        cngx_get_var_switch(r, k, &ssl_flag, SWITCH_OFF);
        if(SWITCH_OFF == ssl_flag)
        {
            break;
        }

        /*ssl on*/
        chttp_req_enable_ssl(CVENDOR_MD_CHTTP_REQ(cvendor_md));

        /*[optional] cngx configure CA*/
        k = (const char *)CNGX_VAR_SSL_CA;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_ca_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "[conf] set ca '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0033);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0034);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] set ca '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0035);

            /*fall through*/
        }

        /*cngx configure certificate*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_certificate_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "[conf] set certificate '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0036);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0037);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] set certificate '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0038);

            /*fall through*/
        }

        /*cngx configure certificate key*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE_KEY;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_private_key_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "[conf] set certificate key '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0039);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0040);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] set certificate key '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0041);

            /*fall through*/
        }
    }while(0);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config head server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_server(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "[conf] set server '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0042);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0043);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] set server '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0044);

            /*set or overwrite ipaddr*/
            if(EC_FALSE == cvendor_content_head_header_in_filter_ipaddr(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "filter ipaddr failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] filter ipaddr '%s' done\n",
                                                    chttp_req_get_ipaddr_str(CVENDOR_MD_CHTTP_REQ(cvendor_md)));


            /*set or overwrite port*/
            if(EC_FALSE == cvendor_content_head_header_in_filter_port(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "filter port failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] filter port %ld done\n",
                                                    chttp_req_get_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)));

            break; /*ok*/
        }

        /*set host*/
        if(EC_FALSE == cvendor_content_head_header_in_filter_host(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "filter host failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite ipaddr*/
        if(EC_FALSE == cvendor_content_head_header_in_filter_ipaddr(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "filter ipaddr failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite port*/
        if(EC_FALSE == cvendor_content_head_header_in_filter_port(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "filter port failed\n");
            return (EC_FALSE);
        }

        if(EC_TRUE == chttp_req_has_ipaddr(CVENDOR_MD_CHTTP_REQ(cvendor_md))
        && EC_TRUE == chttp_req_has_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)))
        {
            break; /*ok*/
        }

        if(EC_TRUE == cngx_upstream_exist(r))
        {
            /*upstream*/
            if(EC_FALSE == cvendor_content_head_header_in_filter_upstream(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "filter upstream failed\n");
                return (EC_FALSE);
            }
        }
        else
        {
            /*try best!*/
            if(EC_FALSE == cvendor_content_head_header_in_filter_server(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "filter server failed\n");
                return (EC_FALSE);
            }
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                "set method '%s' failed\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0045);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CVENDOR_0046);

    /*set http request uri*/
    do
    {
        /*when cngx config head uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "[conf] set uri '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0047);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[conf] set uri '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0048);

            break; /*ok*/
        }

        /*when cngx NOT config head uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "[cngx] set uri '%s' failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0049);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                "[cngx] set uri '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0050);

        if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[cngx] get args '%s'\n",
                                                    v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)"?"))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "[cngx] set '?' failed\n");
                safe_free(v, LOC_CVENDOR_0205);
                return (EC_FALSE);
            }

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                        "[cngx] set args '%s' failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0206);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_in_filter: "
                                                    "[cngx] set args '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0207);
        }
    }while(0);

    /*set range*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            range_start = 0;
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }
        else
        {
            range_start = (CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) - 1) * CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }

        if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md) && range_end >= CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
        {
            range_end = CVENDOR_MD_CONTENT_LENGTH(cvendor_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
    }

    return cvendor_filter_header_in_common(cvendor_md_id);
}

EC_BOOL cvendor_content_head_header_out_rsp_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    char                        *v;
    uint32_t                     status;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_out_rsp_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0051);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_rsp_status_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }

    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_rsp_status_filter: "
                                            "response status = %u [before]\n",
                                            status);

    if(CHTTP_OK != status && CHTTP_PARTIAL_CONTENT != status)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_rsp_status_filter: "
                                                "unchangeable => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_rsp_status_filter: "
                                                "range exist => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_rsp_status_filter: "
                                            "response status = %u [after]\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_header_out_connection_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_out_connection_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Connection";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_connection_filter: "
                                            "del rsp header '%s' done\n",
                                            k);
    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_header_out_filter(const UINT32 cvendor_md_id)
{
    //CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"head";
    cvendor_filter_header_out_common(cvendor_md_id, k);

    if(EC_FALSE == cvendor_content_head_header_out_rsp_status_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_out_filter: "
                                                "status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_filter: "
                                            "status filter done\n");

    /*Connection*/
    if(EC_FALSE == cvendor_content_head_header_out_connection_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_header_out_filter: "
                                                "connection filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_filter: "
                                            "connection filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_send_request(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_send_request: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chttp_req*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_REQ(cvendor_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_send_request: "
                                                    "new chttp_req failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0052);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_REQ(cvendor_md) = chttp_req;
    }
    else
    {
        chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_send_request: "
                                                    "new chttp_rsp failed\n");
            chttp_req_free(chttp_req);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0053);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);
        chttp_rsp_clean(chttp_rsp);
    }

    /*chttp_stat*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STAT(cvendor_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_send_request: "
                                                    "new chttp_stat failed\n");
            chttp_req_free(chttp_req);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0054);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STAT(cvendor_md) = chttp_stat;
    }
    else
    {
        chttp_stat = CVENDOR_MD_CHTTP_STAT(cvendor_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_send_request: "
                                                "export headers_in to http req failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0055);
        return (EC_FALSE);
    }
    if(EC_FALSE == cvendor_content_head_header_in_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_send_request: "
                                                "header_in filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0056);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_head_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, NULL_PTR, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_send_request: "
                                                "http request failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CVENDOR_0057);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_head_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);
    chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(EC_FALSE == cvendor_content_head_header_out_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_send_response: "
                                                    "header_out filter failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0058);
            return (EC_FALSE);
        }

        cngx_import_header_out(r, chttp_rsp);

        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_send_response: "
                                                "set header only\n");

        if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_head_send_response: "
                                                    "send header failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_send_response: "
                                                "send header done\n");

        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_send_response: "
                                            "header had been sent\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_head_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     status; /*response status*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_head_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cvendor_content_head_send_request(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_procedure: "
                                                "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_procedure: "
                                            "send request done\n");

    /*check and intercept error pages*/
    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    if(EC_TRUE == cngx_need_intercept_errors(r, status))
    {
        cvendor_set_ngx_rc(cvendor_md_id, status, LOC_CVENDOR_0059);

        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "warn:cvendor_content_head_procedure: "
                                                "intercept rsp status %u done\n",
                                                status);
        return (EC_FALSE); /*terminate and back to ngx procedure*/
    }

    if(EC_FALSE == cngx_script_dir2_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_procedure: "
                                                "script dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_procedure: "
                                            "script dir2 filter done\n");

    if(EC_FALSE == cngx_headers_dir2_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_procedure: "
                                                "headers dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_procedure: "
                                            "headers dir2 filter done\n");

    if(EC_FALSE == cvendor_content_head_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_head_procedure: "
                                                "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_head_procedure: "
                                            "send response done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_in_filter_upstream(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CHTTP_REQ                   *chttp_req;

    UINT32                       upstream_peer_ipaddr;
    UINT32                       upstream_peer_port;

    uint8_t                     *upstream_name_str;
    uint32_t                     upstream_name_len;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_in_filter_upstream: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_upstream_get_name(r, &upstream_name_str, &upstream_name_len))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_upstream: "
                                                "get upstream name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_upstream_fetch(r, &upstream_peer_ipaddr, &upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_upstream: "
                                                "upstream '%.*s' fetch server failed\n",
                                                upstream_name_len, upstream_name_str);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_upstream: "
                                            "upstream '%.*s' fetch server %s:%ld\n",
                                            upstream_name_len, upstream_name_str,
                                            c_word_to_ipv4(upstream_peer_ipaddr), upstream_peer_port);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    if(EC_FALSE == chttp_req_set_ipaddr_word(chttp_req, upstream_peer_ipaddr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_upstream: "
                                                "[conf] set ipaddr '%s' of upsteam '%.*s' to http req failed\n",
                                                c_word_to_ipv4(upstream_peer_ipaddr),
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0060);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_upstream: "
                                            "[conf] set ipaddr '%s' of upsteam '%.*s' to http req done\n",
                                            c_word_to_ipv4(upstream_peer_ipaddr),
                                            upstream_name_len, upstream_name_str);

    if(EC_FALSE == chttp_req_set_port_word(chttp_req, upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_upstream: "
                                                "[cngx] set port '%ld' of upsteam '%.*s' to http req failed\n",
                                                upstream_peer_port,
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0061);
        return (EC_FALSE);
    }

    chttp_req_set_conn_fail_callback(chttp_req,
                                     (CHTTP_REQ_CONN_FAIL_CALLBACK)cngx_upstream_set_down,
                                     (void *)r);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_upstream: "
                                            "[cngx] set port '%ld' of upsteam '%.*s' to http req done\n",
                                            upstream_peer_port,
                                            upstream_name_len, upstream_name_str);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_in_filter_server(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_in_filter_server: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_direct_header_in_filter_server: "
                                                    "get '%s' failed\n",
                                                    k);
            continue;
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_server: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            c_str_split(v, ":", segs, 2);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, segs[ 0 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_direct_header_in_filter_server: "
                                                        "[cngx] set host of '%s' failed\n",
                                                        segs[ 0 ]);
                safe_free(v, LOC_CVENDOR_0062);

                continue;
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_server: "
                                                    "[cngx] set host '%s' to http req done\n",
                                                    segs[ 0 ]);
            safe_free(v, LOC_CVENDOR_0063);

            return (EC_TRUE);
        }
    }

    cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0064);
    return (EC_FALSE);
}

EC_BOOL cvendor_content_direct_header_in_filter_host(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_in_filter_host: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config direct host and port*/
    k = (const char *)CNGX_VAR_ORIG_HOST;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_host: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_host: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_host: "
                                                    "[conf] set ipaddr of host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0065);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0066);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_host: "
                                                "[conf] set ipaddr of host '%s' to http req done\n",
                                                v);

        if(EC_FALSE == chttp_req_renew_header(chttp_req, (const char *)"Host", v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_host: "
                                                    "[conf] set host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0067);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0068);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_host: "
                                                "[conf] set host '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0069);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_in_filter_port(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_in_filter_port: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config direct port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_port: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_port: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0070);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_port: "
                                                "[conf] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0071);
        return (EC_TRUE);
    }

    if(EC_TRUE == chttp_req_is_local(chttp_req))
    {
        /*set default direct port*/
        if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[default] set default port '%d' to http req done\n",
                                                    CNGX_ORIG_HTTP_PORT_DEFAULT);
        }
        else
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[default] set default port '%d' to https req done\n",
                                                    CNGX_ORIG_HTTPS_PORT_DEFAULT);
        }
        return (EC_TRUE);
    }

    /*when cngx NOT config direct port*/
    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_port: "
                                                    "get '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_port: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            if(2 == c_str_split(v, ":", segs, 2))
            {
                /*set port*/
                if(EC_FALSE == chttp_req_set_port(chttp_req, segs[ 1 ]))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_port: "
                                                            "[cngx] set port '%s' to http req failed\n",
                                                            segs[ 1 ]);
                    safe_free(v, LOC_CVENDOR_0072);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_port: "
                                                        "[cngx] set port '%s' to http req done\n",
                                                        segs[ 1 ]);
                safe_free(v, LOC_CVENDOR_0073);

                return (EC_TRUE);
            }

            safe_free(v, LOC_CVENDOR_0074);

            /*continue*/
        }
    }

    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0075);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0076);

        return (EC_TRUE);
    }

    /*should never reach here*/

    /*set default direct port*/
    if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                "[default] set default port '%d' to http req done\n",
                                                CNGX_ORIG_HTTP_PORT_DEFAULT);
    }
    else
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                "[default] set default port '%d' to https req done\n",
                                                CNGX_ORIG_HTTPS_PORT_DEFAULT);
    }
    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_in_filter_ipaddr(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_in_filter_ipaddr: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig ipaddr*/
    k = (const char *)CNGX_VAR_ORIG_IPADDR;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_ipaddr: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_ipaddr: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter_ipaddr: "
                                                    "[conf] set ipaddr '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0077);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0078);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter_ipaddr: "
                                                "[conf] set ipaddr  '%s' to http req done\n",
                                                v);

        safe_free(v, LOC_CVENDOR_0079);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_in_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_in_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*set ssl flag*/
    do
    {
        UINT32  ssl_flag;

        /*when cngx switch ssl on, then orig over https*/
        k = (const char *)CNGX_VAR_SSL_ORIG_SWITCH;
        cngx_get_var_switch(r, k, &ssl_flag, SWITCH_OFF);
        if(SWITCH_OFF == ssl_flag)
        {
            break;
        }

        /*ssl on*/
        chttp_req_enable_ssl(CVENDOR_MD_CHTTP_REQ(cvendor_md));

        /*[optional] cngx configure CA*/
        k = (const char *)CNGX_VAR_SSL_CA;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_ca_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "[conf] set ca '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0080);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0081);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] set ca '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0082);

            /*fall through*/
        }

        /*cngx configure certificate*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_certificate_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "[conf] set certificate '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0083);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0084);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] set certificate '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0085);

            /*fall through*/
        }

        /*cngx configure certificate key*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE_KEY;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_private_key_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "[conf] set certificate key '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0086);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0087);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] set certificate key '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0088);

            /*fall through*/
        }
    }while(0);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config direct server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_server(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "[conf] set server '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0089);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0090);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] set server '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0091);

            /*set or overwrite ipaddr*/
            if(EC_FALSE == cvendor_content_direct_header_in_filter_ipaddr(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "filter ipaddr failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] filter ipaddr '%s' done\n",
                                                    chttp_req_get_ipaddr_str(CVENDOR_MD_CHTTP_REQ(cvendor_md)));


            /*set or overwrite port*/
            if(EC_FALSE == cvendor_content_direct_header_in_filter_port(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "filter port failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] filter port %ld done\n",
                                                    chttp_req_get_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)));
            break; /*ok*/
        }

        /*set host*/
        if(EC_FALSE == cvendor_content_direct_header_in_filter_host(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                    "filter host failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite ipaddr*/
        if(EC_FALSE == cvendor_content_direct_header_in_filter_ipaddr(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                    "filter ipaddr failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite port*/
        if(EC_FALSE == cvendor_content_direct_header_in_filter_port(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                    "filter port failed\n");
            return (EC_FALSE);
        }

        if(EC_TRUE == chttp_req_has_ipaddr(CVENDOR_MD_CHTTP_REQ(cvendor_md))
        && EC_TRUE == chttp_req_has_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)))
        {
            break; /*ok*/
        }

        if(EC_TRUE == cngx_upstream_exist(r))
        {
            /*upstream*/
            if(EC_FALSE == cvendor_content_direct_header_in_filter_upstream(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "filter upstream failed\n");
                return (EC_FALSE);
            }
        }
        else
        {
            /*try best!*/
            if(EC_FALSE == cvendor_content_direct_header_in_filter_server(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "filter server failed\n");
                return (EC_FALSE);
            }
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                "set method '%s' failed\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0092);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CVENDOR_0093);

    /*set http request uri*/
    do
    {
        /*when cngx config direct uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                 "get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "[conf] set uri '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0094);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[conf] set uri '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0095);

            break; /*ok*/
        }

        /*when cngx NOT config direct uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                    "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                    "[cngx] set uri '%s' failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0096);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                "[cngx] set uri '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0097);

        if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[cngx] get args '%s'\n",
                                                    v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)"?"))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "[cngx] set '?' failed\n");
                safe_free(v, LOC_CVENDOR_0205);
                return (EC_FALSE);
            }

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                        "[cngx] set args '%s' failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0206);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_in_filter: "
                                                    "[cngx] set args '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0207);
        }
    }while(0);

    /*set range*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            range_start = 0;
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }
        else
        {
            range_start = (CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) - 1) * CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }

        if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md) && range_end >= CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
        {
            range_end = CVENDOR_MD_CONTENT_LENGTH(cvendor_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
    }

    return cvendor_filter_header_in_common(cvendor_md_id);
}

EC_BOOL cvendor_content_direct_header_out_length_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_out_length_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        char       *content_length_str;
        UINT32      content_length;

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR == content_length_str)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_length_filter: "
                                                    "no 'Content-Length'\n");
            return (EC_FALSE);
        }

        content_length = c_str_to_word(content_length_str);

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_length_filter: "
                                                "parse Content-Length '%s' to %ld\n",
                                                content_length_str,
                                                content_length);
    }

    if(BIT_TRUE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md)
    && BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)
    && EC_TRUE == crange_mgr_is_empty(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_length_filter: "
                                                    "split content_length to segs failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_length_filter: "
                                                "split content_length to segs done\n");
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_length_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_out_range_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_out_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CHTTP_NO_CONTENT == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                                "status 204 (no content) => done\n");

        return (EC_TRUE);
    }

    while(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        char       *content_range_str;
        char       *content_length_str;

        content_range_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Range");
        if(NULL_PTR != content_range_str)
        {
            UINT32      range_start;
            UINT32      range_end;
            UINT32      content_length;

            if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_range_filter: "
                                                        "invalid Content-Range '%s'\n",
                                                        content_range_str);
                return (EC_FALSE);
            }

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                                    "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                    content_range_str,
                                                    range_start, range_end, content_length);
            /*fall through*/
            break;
        }

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR != content_length_str)
        {
            UINT32      content_length;

            content_length = c_str_to_word(content_length_str);

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                                    "parse Content-Length '%s' to %ld\n",
                                                    content_length_str,
                                                    content_length);
            /*fall through*/
            break;
        }

        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_direct_header_out_range_filter: "
                                                "no 'Content-Range' => chunk\n");
        /*maybe chunk*/
        return cvendor_content_chunk_header_out_filter(cvendor_md_id);
    }

    if(EC_FALSE == cvendor_content_direct_header_out_length_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_range_filter: "
                                                "filter length failed\n");
        return(EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                            "filter length done\n");

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                                "del rsp header %s done\n",
                                                k);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(CVENDOR_MD_CONTENT_LENGTH(cvendor_md));
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k, v);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                                "renew rsp header %s:%s done\n",
                                                k, v);

        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(EC_FALSE == cvendor_filter_header_out_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_range_filter: "
                                                "filter range failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                            "filter range done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_range_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_out_rsp_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    char                        *v;
    uint32_t                     status;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_out_rsp_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0098);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_rsp_status_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }

    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_rsp_status_filter: "
                                            "response status = %u [before]\n",
                                            status);

    if(CHTTP_OK != status && CHTTP_PARTIAL_CONTENT != status)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_rsp_status_filter: "
                                                "unchangeable => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_rsp_status_filter: "
                                                "range exist => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_rsp_status_filter: "
                                            "response status = %u [after]\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_out_connection_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_out_connection_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Connection";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_connection_filter: "
                                            "del rsp header '%s' done\n",
                                            k);

    k = (const char *)"Proxy-Connection";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_connection_filter: "
                                            "del rsp header '%s' done\n",
                                            k);

    k = (const char *)"Keep-alive";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_connection_filter: "
                                            "del rsp header '%s' done\n",
                                            k);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_header_out_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"direct";
    cvendor_filter_header_out_common(cvendor_md_id, k);

    if(BIT_FALSE == CVENDOR_MD_CNGX_DIRECT_IMS_FLAG(cvendor_md))
    {
        if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_filter: "
                                                    "chttp rsp header_in range filter failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_RANGE_NOT_SATISFIABLE, LOC_CVENDOR_0099);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_filter: "
                                                "chttp rsp header_in range filter done\n");

        /*Content-Length and Content-Range*/
        if(EC_FALSE == cvendor_content_direct_header_out_range_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_filter: "
                                                    "range filter failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_filter: "
                                                "range filter done\n");
    }

    if(EC_FALSE == cvendor_content_direct_header_out_rsp_status_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_filter: "
                                                "status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_filter: "
                                            "status filter done\n");

    /*Connection*/
    if(EC_FALSE == cvendor_content_direct_header_out_connection_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_header_out_filter: "
                                                "connection filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_filter: "
                                            "connection filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_body_out_filter(const UINT32 cvendor_md_id)
{
    //CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_body_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_set_store(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_STORE                 *chttp_store;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_set_store: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_store = CVENDOR_MD_CHTTP_STORE(cvendor_md);

    /*--- chttp_store settting --- BEG ---*/
    CHTTP_STORE_SEG_MAX_ID(chttp_store) = (uint32_t)CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md);

    if(CVENDOR_ERR_SEG_NO == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        CHTTP_STORE_SEG_ID(chttp_store) = 0;
    }
    else
    {
        CHTTP_STORE_SEG_ID(chttp_store) = (uint32_t)CVENDOR_MD_ABSENT_SEG_NO(cvendor_md);
    }

    CHTTP_STORE_SEG_SIZE(chttp_store)     = CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
    CHTTP_STORE_SEG_S_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;
    CHTTP_STORE_SEG_E_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;

    cstring_clone(CVENDOR_MD_CACHE_PATH(cvendor_md), CHTTP_STORE_BASEDIR(chttp_store));

    if(0 == CHTTP_STORE_SEG_ID(chttp_store))
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)       = BIT_FALSE;
        CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store) = BIT_FALSE;
        CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store) = BIT_TRUE;
        CHTTP_STORE_NEED_LOG_FLAG(chttp_store)    = BIT_TRUE;
    }
    else
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)       = BIT_FALSE;
        CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store) = BIT_FALSE;
        CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store) = BIT_TRUE;
        CHTTP_STORE_NEED_LOG_FLAG(chttp_store)    = BIT_TRUE;
    }

    /*note: disable data sending in orig procedure*/
    if(0 && BIT_TRUE == CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store))
    {
        CHTTP_STORE_BGN_ORIG_MODI(chttp_store)              = cvendor_md_id;
        CHTTP_STORE_BGN_IMPORT_HEADER_CALLBACK(chttp_store) = (UINT32)cvendor_content_direct_import_header;
        CHTTP_STORE_BGN_SEND_HEADER_CALLBACK(chttp_store)   = (UINT32)cvendor_content_direct_send_header;
        CHTTP_STORE_BGN_SEND_BODY_CALLBACK(chttp_store)     = (UINT32)cvendor_content_direct_send_body;
    }

    if(EC_FALSE == cngx_set_store(r, chttp_store))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_set_store: "
                                                "fetch ngx cfg to chttp_store failed\n");
        return (EC_FALSE);
    }

    CHTTP_STORE_CACHE_CTRL(chttp_store) = CHTTP_STORE_CACHE_NONE;/*cache nothing*/

    if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
    {
        CHTTP_STORE_CONTENT_LENGTH(chttp_store) = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);
    }

    /*--- chttp_store settting --- END ---*/

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_send_request(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STORE                 *chttp_store;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_send_request: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chttp_req*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_REQ(cvendor_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                    "new chttp_req failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0100);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_REQ(cvendor_md) = chttp_req;
    }
    else
    {
        chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                    "new chttp_rsp failed\n");
            chttp_req_free(chttp_req);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0101);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);
        chttp_rsp_clean(chttp_rsp);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                "export headers_in to http req failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0102);
        return (EC_FALSE);
    }
    if(EC_FALSE == cvendor_content_direct_header_in_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                "header_in filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0103);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    /*chttp_store*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STORE(cvendor_md))
    {
        chttp_store = chttp_store_new();
        if(NULL_PTR == chttp_store)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                    "new chttp_store failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0104);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STORE(cvendor_md) = chttp_store;
    }
    else
    {
        chttp_store = CVENDOR_MD_CHTTP_STORE(cvendor_md);
        chttp_store_clean(chttp_store);
    }

    /*chttp_stat*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STAT(cvendor_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                    "new chttp_stat failed\n");
            chttp_req_free(chttp_req);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0105);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STAT(cvendor_md) = chttp_stat;
    }
    else
    {
        chttp_stat = CVENDOR_MD_CHTTP_STAT(cvendor_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cvendor_content_direct_set_store(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                "set chttp_store failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0106);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_request: "
                                                "chttp_store is\n");
        chttp_store_print(LOGSTDOUT, chttp_store);
    }

    if(EC_FALSE == chttp_request(chttp_req, chttp_store, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_request: "
                                                "http request failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CVENDOR_0107);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;
    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_send_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);
    chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

    ASSERT(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md));

    /*check seg num*/
    if(CVENDOR_ERR_SEG_NO != CRANGE_SEG_NO(crange_seg)
    && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CRANGE_SEG_NO(crange_seg))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_seg_n: seg no %ld overflow!\n",
                                                CRANGE_SEG_NO(crange_seg));
        return (EC_FALSE);
    }

    /*no-direct*/
    if(CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) == CRANGE_SEG_NO(crange_seg))
    {
        uint8_t         *data;
        uint32_t         len;
        uint32_t         flags;

        cvendor_content_direct_body_out_filter(cvendor_md_id);

        data = CBYTES_BUF(CHTTP_RSP_BODY(chttp_rsp)) + CRANGE_SEG_S_OFFSET(crange_seg);
        len  = (uint32_t)(CRANGE_SEG_E_OFFSET(crange_seg) + 1 - CRANGE_SEG_S_OFFSET(crange_seg));

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
              | CNGX_SEND_BODY_FLUSH_FLAG
              | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_seg_n: "
                                                    "send body seg %ld failed\n",
                                                    CRANGE_SEG_NO(crange_seg));

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_seg_n: "
                                                "send body seg %ld: %u bytes done\n",
                                                CRANGE_SEG_NO(crange_seg), len);

        chttp_rsp_clean(chttp_rsp);
        return (EC_TRUE);
    }

    /*else*/

    chttp_rsp_clean(chttp_rsp);

    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

    /*check seg num*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
    && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_seg_n: seg no %ld overflow!\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_seg_n: "
                                            "set absent_seg_no = %ld\n",
                                            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

    /*recursively*/
    return cvendor_content_direct_procedure(cvendor_md_id);
}

EC_BOOL cvendor_content_direct_send_node(const UINT32 cvendor_md_id, CRANGE_NODE *crange_node)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

    CRANGE_SEG                  *crange_seg;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_send_node: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*boundary*/
    if(EC_FALSE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;
        uint32_t     flags;

        boundary = CRANGE_NODE_BOUNDARY(crange_node);

        cvendor_content_direct_body_out_filter(cvendor_md_id);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_node: "
                                                    "send body boundary failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_node: "
                                                "send body boundary: %ld bytes done\n",
                                                CSTRING_LEN(boundary));

        /*clean boundary which was sent out*/
        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    }

    while(NULL_PTR != (crange_seg = crange_node_first_seg(crange_node)))
    {
        UINT32      seg_no;

        seg_no = CRANGE_SEG_NO(crange_seg); /*range_seg may be free at other place, save it here*/

        if(EC_FALSE == cvendor_content_direct_send_seg_n(cvendor_md_id, crange_seg))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_node: "
                                                    "send direct seg %ld failed\n",
                                                    seg_no);

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_node: "
                                                "send direct seg %ld done => sent body %ld bytes\n",
                                                seg_no,
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_node: "
                                                    "pop seg %ld\n",
                                                    CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_import_header(const UINT32 cvendor_md_id, const CHTTP_NODE *chttp_node)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_import_header: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

    /*clone rsp*/
    CHTTP_RSP_STATUS(chttp_rsp) = (uint32_t)CHTTP_NODE_STATUS_CODE(chttp_node);
    cstrkv_mgr_clone(CHTTP_NODE_HEADER_IN_KVS(chttp_node), CHTTP_RSP_HEADER(chttp_rsp));

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_direct_import_header: cloned chttp_rsp: \n");
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}

/*shortcut in http orig procedure*/
EC_BOOL cvendor_content_direct_send_header(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_send_header: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_header: "
                                                "header had already sent\n");
        return (EC_FALSE);
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
    {
        /*send header*/
        if(EC_FALSE == cvendor_content_direct_header_out_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_header: "
                                                    "header_out filter failed\n");

            return (EC_FALSE);
        }

        /*not need save header in module*/

        cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

        cngx_disable_write_delayed(r);

        if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_header: "
                                                    "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_header: "
                                                "send header done\n");

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_header: done\n");
    }
    return (EC_TRUE);
}

/*shortcut in http orig procedure*/
EC_BOOL cvendor_content_direct_send_body(const UINT32 cvendor_md_id, const UINT32 seg_no, const UINT8 *data, const UINT32 len)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_send_body: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    ASSERT(0 < seg_no);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_TRUE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_body: "
                                                "header was not sent yet\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cngx_need_header_only(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_body: "
                                                "need header only => give up body sending\n");
        return (EC_TRUE);
    }

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG;

    if(EC_FALSE == cngx_send_body(r, data, (uint32_t)len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_body: "
                                                "send body %ld bytes failed\n",
                                                len);

        return (EC_FALSE);
    }

    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_body: "
                                            "send body %ld bytes done\n",
                                            len);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_body: "
                                            "send recved seg %ld done => sent body %ld bytes\n",
                                            seg_no,
                                            CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));
    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_send_end(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_send_end: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_NO_MORE_FLAG
            /*
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            */
            ;

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_end: "
                                                "send body end failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_end: "
                                            "send body end done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);
    chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            if(EC_FALSE == cvendor_content_direct_header_out_filter(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_response: "
                                                        "header_out filter failed\n");
                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0108);
                return (EC_FALSE);
            }

            cngx_import_header_out(r, chttp_rsp);

            cngx_disable_write_delayed(r);

            if(0 == CBYTES_LEN(CHTTP_RSP_BODY(chttp_rsp)))
            {
                cngx_set_header_only(r);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                        "set header only\n");
            }

            if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_response: "
                                                        "send header failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                    "send header done\n");
        }

        if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) ++;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                    "inc absent_seg_no to %ld\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
        }
    }

    /*direct is not triggered by seg loss, but by ngx cfg => send chttp rsp only*/
    if(BIT_FALSE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md)
    && CVENDOR_ERR_SEG_NO == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        uint8_t         *data;
        uint32_t         len;
        uint32_t         flags;

        cvendor_content_direct_body_out_filter(cvendor_md_id);

        data = CBYTES_BUF(CHTTP_RSP_BODY(chttp_rsp));
        len  = (uint32_t)CBYTES_LEN(CHTTP_RSP_BODY(chttp_rsp));

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_response: "
                                                    "send body failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                "send body %u bytes done\n",
                                                len);

        chttp_rsp_clean(chttp_rsp);
        return (EC_TRUE);
    }

    if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_response: "
                                                "chttp rsp header_in range filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_RANGE_NOT_SATISFIABLE, LOC_CVENDOR_0109);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                            "chttp rsp header_in range filter done\n");

    /*send body: direct*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        CRANGE_MGR                  *crange_mgr;
        CRANGE_NODE                 *crange_node;

        crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);
        if(do_log(SEC_0175_CVENDOR, 9))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                    "before send body, crange_mgr:\n");
            crange_mgr_print(LOGSTDOUT, crange_mgr);
        }

        /*send body: ranges*/
        while(NULL_PTR != (crange_node = crange_mgr_first_node(crange_mgr)))
        {
            if(EC_FALSE == cvendor_content_direct_send_node(cvendor_md_id, crange_node))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_response: "
                                                        "send node (%ld:%s, %ld:%s) failed\n",
                                                        CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                        CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                    "send node (%ld:%s, %ld:%s) done => sent body %ld bytes\n",
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                                    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

            if(crange_mgr_first_node(crange_mgr) == crange_node)
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                        "pop node (%ld:%s, %ld:%s)\n",
                                                        CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                        CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));
                crange_mgr_first_node_pop(crange_mgr);
                crange_node_free(crange_node);
            }
        }

        /*send body: last boundary*/
        if(EC_FALSE == cstring_is_empty(CRANGE_MGR_BOUNDARY(crange_mgr)))
        {
            CSTRING     *boundary;
            uint8_t     *data;
            uint32_t     len;
            uint32_t     flags;

            boundary = CRANGE_MGR_BOUNDARY(crange_mgr);

            cvendor_content_direct_body_out_filter(cvendor_md_id);
            data = (uint8_t *)CSTRING_STR(boundary);
            len  = (uint32_t)CSTRING_LEN(boundary);

            flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                    | CNGX_SEND_BODY_FLUSH_FLAG
                    | CNGX_SEND_BODY_RECYCLED_FLAG;

            if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_send_response: "
                                                        "send body boundary failed\n");

                return (EC_FALSE);
            }

            CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                    "send body boundary: %ld bytes done\n",
                                                    CSTRING_LEN(boundary));
        }

        /*send body end*/
        if(EC_FALSE == cvendor_content_direct_send_end(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_send_response: "
                                                    "send body end failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                "send body end done\n");

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_send_response: "
                                                "send body done => complete %ld bytes\n",
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_direct_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     status; /*response status*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_direct_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cvendor_content_direct_send_request(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_procedure: "
                                                "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_procedure: "
                                            "send request done\n");

    /*check and intercept error pages*/
    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    if(EC_TRUE == cngx_need_intercept_errors(r, status))
    {
        cvendor_set_ngx_rc(cvendor_md_id, status, LOC_CVENDOR_0110);

        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "warn:cvendor_content_direct_procedure: "
                                                "intercept rsp status %u done\n",
                                                status);
        return (EC_FALSE); /*terminate and back to ngx procedure*/
    }

    if(EC_FALSE == cngx_script_dir2_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_procedure: "
                                                "script dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_procedure: "
                                            "script dir2 filter done\n");

    if(EC_FALSE == cngx_headers_dir2_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_direct_procedure: "
                                                "headers dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_procedure: "
                                            "headers dir2 filter done\n");

    if(EC_FALSE == cvendor_content_direct_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_direct_procedure: "
                                                "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_direct_procedure: "
                                            "send response done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_in_filter_upstream(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CHTTP_REQ                   *chttp_req;

    UINT32                       upstream_peer_ipaddr;
    UINT32                       upstream_peer_port;

    uint8_t                     *upstream_name_str;
    uint32_t                     upstream_name_len;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_in_filter_upstream: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_upstream_get_name(r, &upstream_name_str, &upstream_name_len))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_upstream: "
                                                "get upstream name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_upstream_fetch(r, &upstream_peer_ipaddr, &upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_upstream: "
                                                "upstream '%.*s' fetch server failed\n",
                                                upstream_name_len, upstream_name_str);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_upstream: "
                                            "upstream '%.*s' fetch server %s:%ld\n",
                                            upstream_name_len, upstream_name_str,
                                            c_word_to_ipv4(upstream_peer_ipaddr), upstream_peer_port);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    if(EC_FALSE == chttp_req_set_ipaddr_word(chttp_req, upstream_peer_ipaddr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_upstream: "
                                                "[conf] set ipaddr '%s' of upsteam '%.*s' to http req failed\n",
                                                c_word_to_ipv4(upstream_peer_ipaddr),
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0111);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_upstream: "
                                            "[conf] set ipaddr '%s' of upsteam '%.*s' to http req done\n",
                                            c_word_to_ipv4(upstream_peer_ipaddr),
                                            upstream_name_len, upstream_name_str);

    if(EC_FALSE == chttp_req_set_port_word(chttp_req, upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_upstream: "
                                                "[cngx] set port '%ld' of upsteam '%.*s' to http req failed\n",
                                                upstream_peer_port,
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0112);
        return (EC_FALSE);
    }

    chttp_req_set_conn_fail_callback(chttp_req,
                                     (CHTTP_REQ_CONN_FAIL_CALLBACK)cngx_upstream_set_down,
                                     (void *)r);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_upstream: "
                                            "[cngx] set port '%ld' of upsteam '%.*s' to http req done\n",
                                            upstream_peer_port,
                                            upstream_name_len, upstream_name_str);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_in_filter_server(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_in_filter_server: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_repair_header_in_filter_server: "
                                                    "get '%s' failed\n",
                                                    k);
            continue;
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_server: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            c_str_split(v, ":", segs, 2);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, segs[ 0 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_repair_header_in_filter_server: "
                                                        "[cngx] set host of '%s' failed\n",
                                                        segs[ 0 ]);
                safe_free(v, LOC_CVENDOR_0113);

                continue;
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_server: "
                                                    "[cngx] set host '%s' to http req done\n",
                                                    segs[ 0 ]);
            safe_free(v, LOC_CVENDOR_0114);

            return (EC_TRUE);
        }
    }

    cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0115);
    return (EC_FALSE);
}

EC_BOOL cvendor_content_repair_header_in_filter_host(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_in_filter_host: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config direct host and port*/
    k = (const char *)CNGX_VAR_ORIG_HOST;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_host: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_host: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_host: "
                                                    "[conf] set ipaddr of host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0116);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0117);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_host: "
                                                "[conf] set ipaddr of host '%s' to http req done\n",
                                                v);

        if(EC_FALSE == chttp_req_renew_header(chttp_req, (const char *)"Host", v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_host: "
                                                    "[conf] set host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0118);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0119);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_host: "
                                                "[conf] set host '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0120);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_in_filter_port(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_in_filter_port: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config direct port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_port: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_port: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0121);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_port: "
                                                "[conf] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0122);
        return (EC_TRUE);
    }

    if(EC_TRUE == chttp_req_is_local(chttp_req))
    {
        /*set default direct port*/
        if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[default] set default port '%d' to http req done\n",
                                                    CNGX_ORIG_HTTP_PORT_DEFAULT);
        }
        else
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[default] set default port '%d' to https req done\n",
                                                    CNGX_ORIG_HTTPS_PORT_DEFAULT);
        }
        return (EC_TRUE);
    }

    /*when cngx NOT config direct port*/
    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_port: "
                                                    "get '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_port: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            if(2 == c_str_split(v, ":", segs, 2))
            {
                /*set port*/
                if(EC_FALSE == chttp_req_set_port(chttp_req, segs[ 1 ]))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_port: "
                                                            "[cngx] set port '%s' to http req failed\n",
                                                            segs[ 1 ]);
                    safe_free(v, LOC_CVENDOR_0123);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_port: "
                                                        "[cngx] set port '%s' to http req done\n",
                                                        segs[ 1 ]);
                safe_free(v, LOC_CVENDOR_0124);

                return (EC_TRUE);
            }

            safe_free(v, LOC_CVENDOR_0125);

            /*continue*/
        }
    }

    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0126);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0127);

        return (EC_TRUE);
    }

    /*should never reach here*/

    /*set default direct port*/
    if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                "[default] set default port '%d' to http req done\n",
                                                CNGX_ORIG_HTTP_PORT_DEFAULT);
    }
    else
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                "[default] set default port '%d' to https req done\n",
                                                CNGX_ORIG_HTTPS_PORT_DEFAULT);
    }
    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_in_filter_ipaddr(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_in_filter_ipaddr: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig ipaddr*/
    k = (const char *)CNGX_VAR_ORIG_IPADDR;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_ipaddr: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_ipaddr: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter_ipaddr: "
                                                    "[conf] set ipaddr '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0128);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0129);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter_ipaddr: "
                                                "[conf] set ipaddr  '%s' to http req done\n",
                                                v);

        safe_free(v, LOC_CVENDOR_0130);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_in_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_in_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*set ssl flag*/
    do
    {
        UINT32  ssl_flag;

        /*when cngx switch ssl on, then orig over https*/
        k = (const char *)CNGX_VAR_SSL_ORIG_SWITCH;
        cngx_get_var_switch(r, k, &ssl_flag, SWITCH_OFF);
        if(SWITCH_OFF == ssl_flag)
        {
            break;
        }

        /*ssl on*/
        chttp_req_enable_ssl(CVENDOR_MD_CHTTP_REQ(cvendor_md));

        /*[optional] cngx configure CA*/
        k = (const char *)CNGX_VAR_SSL_CA;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_ca_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "[conf] set ca '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0131);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0132);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] set ca '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0133);

            /*fall through*/
        }

        /*cngx configure certificate*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_certificate_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "[conf] set certificate '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0134);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0135);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] set certificate '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0136);

            /*fall through*/
        }

        /*cngx configure certificate key*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE_KEY;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_private_key_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "[conf] set certificate key '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0137);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0138);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] set certificate key '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0139);

            /*fall through*/
        }
    }while(0);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config orig server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_server(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "[conf] set server '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0140);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0141);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] set server '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0142);

            /*set or overwrite ipaddr*/
            if(EC_FALSE == cvendor_content_repair_header_in_filter_ipaddr(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "filter ipaddr failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] filter ipaddr '%s' done\n",
                                                    chttp_req_get_ipaddr_str(CVENDOR_MD_CHTTP_REQ(cvendor_md)));


            /*set or overwrite port*/
            if(EC_FALSE == cvendor_content_repair_header_in_filter_port(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "filter port failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] filter port %ld done\n",
                                                    chttp_req_get_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)));
            break; /*ok*/
        }

        /*set host*/
        if(EC_FALSE == cvendor_content_repair_header_in_filter_host(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                    "filter host failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite ipaddr*/
        if(EC_FALSE == cvendor_content_repair_header_in_filter_ipaddr(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                    "filter ipaddr failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite port*/
        if(EC_FALSE == cvendor_content_repair_header_in_filter_port(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                    "filter port failed\n");
            return (EC_FALSE);
        }

        if(EC_TRUE == chttp_req_has_ipaddr(CVENDOR_MD_CHTTP_REQ(cvendor_md))
        && EC_TRUE == chttp_req_has_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)))
        {
            break; /*ok*/
        }

        if(EC_TRUE == cngx_upstream_exist(r))
        {
            /*upstream*/
            if(EC_FALSE == cvendor_content_repair_header_in_filter_upstream(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "filter upstream failed\n");
                return (EC_FALSE);
            }
        }
        else
        {
            /*try best!*/
            if(EC_FALSE == cvendor_content_repair_header_in_filter_server(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "filter server failed\n");
                return (EC_FALSE);
            }
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                "set method '%s' failed\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0143);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CVENDOR_0144);

    /*set http request uri*/
    do
    {
        /*when cngx config direct uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                 "get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "[conf] set uri '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0145);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[conf] set uri '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0146);

            break; /*ok*/
        }

        /*when cngx NOT config direct uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                    "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                    "[cngx] set uri '%s' failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0147);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                "[cngx] set uri '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0148);

        if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[cngx] get args '%s'\n",
                                                    v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)"?"))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "[cngx] set '?' failed\n");
                safe_free(v, LOC_CVENDOR_0205);
                return (EC_FALSE);
            }

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                        "[cngx] set args '%s' failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0206);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_in_filter: "
                                                    "[cngx] set args '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0207);
        }
    }while(0);

    /*set range*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            range_start = 0;
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }
        else
        {
            range_start = (CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) - 1) * CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }

        if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md) && range_end >= CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
        {
            range_end = CVENDOR_MD_CONTENT_LENGTH(cvendor_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
    }

    return cvendor_filter_header_in_common(cvendor_md_id);
}

EC_BOOL cvendor_content_repair_header_out_length_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_out_length_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        char       *content_length_str;
        UINT32      content_length;

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR == content_length_str)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_length_filter: "
                                                    "no 'Content-Length'\n");
            return (EC_FALSE);
        }

        content_length = c_str_to_word(content_length_str);

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_length_filter: "
                                                "parse Content-Length '%s' to %ld\n",
                                                content_length_str,
                                                content_length);
    }

    if(BIT_TRUE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md)
    && BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)
    && EC_TRUE == crange_mgr_is_empty(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_length_filter: "
                                                    "split content_length to segs failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_length_filter: "
                                                "split content_length to segs done\n");
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_length_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_out_range_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_out_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CHTTP_NO_CONTENT == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_range_filter: "
                                                "status 204 (no content) => done\n");

        return (EC_TRUE);
    }

    while(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        char       *content_range_str;
        char       *content_length_str;

        content_range_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Range");
        if(NULL_PTR != content_range_str)
        {
            UINT32      range_start;
            UINT32      range_end;
            UINT32      content_length;

            if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_range_filter: "
                                                        "invalid Content-Range '%s'\n",
                                                        content_range_str);
                return (EC_FALSE);
            }

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_range_filter: "
                                                    "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                    content_range_str,
                                                    range_start, range_end, content_length);
            /*fall through*/
            break;
        }

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR != content_length_str)
        {
            UINT32      content_length;

            content_length = c_str_to_word(content_length_str);

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_range_filter: "
                                                    "parse Content-Length '%s' to %ld\n",
                                                    content_length_str,
                                                    content_length);
            /*fall through*/
            break;
        }

        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_repair_header_out_range_filter: "
                                                "no 'Content-Range' => chunk\n");
        /*maybe chunk*/
        return cvendor_content_chunk_header_out_filter(cvendor_md_id);
    }

    if(EC_FALSE == cvendor_content_repair_header_out_length_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_range_filter: "
                                                "filter length failed\n");
        return(EC_FALSE);
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_range_filter: "
                                                "del rsp header %s done\n",
                                                k);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(CVENDOR_MD_CONTENT_LENGTH(cvendor_md));
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k, v);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_range_filter: "
                                                "renew rsp header %s:%s done\n",
                                                k, v);

        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(EC_FALSE == cvendor_filter_header_out_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_range_filter: "
                                                "filter range failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_range_filter: "
                                            "filter range done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_range_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_out_rsp_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    char                        *v;
    uint32_t                     status;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_out_rsp_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0149);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_rsp_status_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }

    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_rsp_status_filter: "
                                            "response status = %u [before]\n",
                                            status);

    if(CHTTP_OK != status && CHTTP_PARTIAL_CONTENT != status)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_rsp_status_filter: "
                                                "unchangeable => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_rsp_status_filter: "
                                                "range exist => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_rsp_status_filter: "
                                            "response status = %u [after]\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_out_connection_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    uint32_t                     status;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_out_connection_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));

    if(CHTTP_NOT_FOUND == status)
    {
        k = (const char *)"Connection";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_connection_filter: "
                                                "404 => del %s\n",
                                                k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_connection_filter: "
                                            "not 404\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_header_out_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"direct";
    cvendor_filter_header_out_common(cvendor_md_id, k);

    if(BIT_FALSE == CVENDOR_MD_CNGX_DIRECT_IMS_FLAG(cvendor_md))
    {
        /*Content-Length and Content-Range*/
        if(EC_FALSE == cvendor_content_repair_header_out_range_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_filter: "
                                                    "range filter failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_filter: "
                                                "range filter done\n");
    }

    if(EC_FALSE == cvendor_content_repair_header_out_rsp_status_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_filter: "
                                                "status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_filter: "
                                            "status filter done\n");

    /*Connection*/
    if(EC_FALSE == cvendor_content_repair_header_out_connection_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_header_out_filter: "
                                                "connection filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_filter: "
                                            "connection filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_body_out_filter(const UINT32 cvendor_md_id)
{
    //CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_body_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_send_request(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_send_request: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chttp_req*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_REQ(cvendor_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_request: "
                                                    "new chttp_req failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0150);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_REQ(cvendor_md) = chttp_req;
    }
    else
    {
        chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_request: "
                                                    "new chttp_rsp failed\n");
            chttp_req_free(chttp_req);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0151);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);
        chttp_rsp_clean(chttp_rsp);
    }

    /*chttp_stat*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STAT(cvendor_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_request: "
                                                    "new chttp_stat failed\n");
            chttp_req_free(chttp_req);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0152);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STAT(cvendor_md) = chttp_stat;
    }
    else
    {
        chttp_stat = CVENDOR_MD_CHTTP_STAT(cvendor_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_request: "
                                                "export headers_in to http req failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0153);
        return (EC_FALSE);
    }
    if(EC_FALSE == cvendor_content_repair_header_in_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_request: "
                                                "header_in filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0154);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, NULL_PTR, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_request: "
                                                "http request failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CVENDOR_0155);
        return (EC_FALSE);
    }
    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;
    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_send_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);
    chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

    ASSERT(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md));

    /*check seg num*/
    if(CVENDOR_ERR_SEG_NO != CRANGE_SEG_NO(crange_seg)
    && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CRANGE_SEG_NO(crange_seg))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_seg_n: seg no %ld overflow!\n",
                                                CRANGE_SEG_NO(crange_seg));
        return (EC_FALSE);
    }

    /*no-direct*/
    if(CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) == CRANGE_SEG_NO(crange_seg))
    {
        uint8_t         *data;
        uint32_t         len;
        uint32_t         flags;

        cvendor_content_repair_body_out_filter(cvendor_md_id);

        data = CBYTES_BUF(CHTTP_RSP_BODY(chttp_rsp)) + CRANGE_SEG_S_OFFSET(crange_seg);
        len  = (uint32_t)(CRANGE_SEG_E_OFFSET(crange_seg) + 1 - CRANGE_SEG_S_OFFSET(crange_seg));

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_seg_n: "
                                                    "send body seg %ld failed\n",
                                                    CRANGE_SEG_NO(crange_seg));

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_seg_n: "
                                                "send body seg %ld: %u bytes done\n",
                                                CRANGE_SEG_NO(crange_seg), len);

        chttp_rsp_clean(chttp_rsp);
        return (EC_TRUE);
    }

    /*else*/

    chttp_rsp_clean(chttp_rsp);

    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

    /*check seg num*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
    && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_seg_n: seg no %ld overflow!\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_seg_n: "
                                            "set absent_seg_no = %ld\n",
                                            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

    /*recursively*/
    return cvendor_content_repair_procedure(cvendor_md_id);
}

EC_BOOL cvendor_content_repair_send_node(const UINT32 cvendor_md_id, CRANGE_NODE *crange_node)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

    CRANGE_SEG                  *crange_seg;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_send_node: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*boundary*/
    if(EC_FALSE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;
        uint32_t     flags;

        boundary = CRANGE_NODE_BOUNDARY(crange_node);

        cvendor_content_repair_body_out_filter(cvendor_md_id);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_node: "
                                                    "send body boundary failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_node: "
                                                "send body boundary: %ld bytes done\n",
                                                CSTRING_LEN(boundary));

        /*clean boundary which was sent out*/
        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    }

    while(NULL_PTR != (crange_seg = crange_node_first_seg(crange_node)))
    {
        UINT32      seg_no;

        seg_no = CRANGE_SEG_NO(crange_seg); /*range_seg may be free at other place, save it here*/

        if(EC_FALSE == cvendor_content_repair_send_seg_n(cvendor_md_id, crange_seg))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_node: "
                                                    "send direct seg %ld failed\n",
                                                    seg_no);

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_node: "
                                                "send direct seg %ld done => sent body %ld bytes\n",
                                                seg_no,
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_node: "
                                                    "pop seg %ld\n",
                                                    CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_send_end(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_send_end: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_NO_MORE_FLAG
            /*
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            */
            ;

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_end: "
                                                "send body end failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_end: "
                                            "send body end done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);
    chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            if(EC_FALSE == cvendor_content_repair_header_out_filter(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_response: "
                                                        "header_out filter failed\n");
                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0156);
                return (EC_FALSE);
            }

            cngx_import_header_out(r, chttp_rsp);

            cngx_disable_write_delayed(r);

            if(0 == CBYTES_LEN(CHTTP_RSP_BODY(chttp_rsp)))
            {
                cngx_set_header_only(r);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                        "set header only\n");
            }

            if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_response: "
                                                        "send header failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                    "send header done\n");
        }

        if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) ++;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                    "inc absent_seg_no to %ld\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
        }
    }

    /*direct is not triggered by seg loss, but by ngx cfg => send chttp rsp only*/
    if(BIT_FALSE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md)
    && CVENDOR_ERR_SEG_NO == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        uint8_t         *data;
        uint32_t         len;
        uint32_t         flags;

        cvendor_content_repair_body_out_filter(cvendor_md_id);

        data = CBYTES_BUF(CHTTP_RSP_BODY(chttp_rsp));
        len  = (uint32_t)CBYTES_LEN(CHTTP_RSP_BODY(chttp_rsp));

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_response: "
                                                    "send body failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                "send body %u bytes done\n",
                                                len);

        chttp_rsp_clean(chttp_rsp);
        return (EC_TRUE);
    }

    if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_response: "
                                                "chttp rsp header_in range filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_RANGE_NOT_SATISFIABLE, LOC_CVENDOR_0157);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                            "chttp rsp header_in range filter done\n");

    /*send body: direct*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        CRANGE_MGR                  *crange_mgr;
        CRANGE_NODE                 *crange_node;

        crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);
        if(do_log(SEC_0175_CVENDOR, 9))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                    "before send body, crange_mgr:\n");
            crange_mgr_print(LOGSTDOUT, crange_mgr);
        }

        /*send body: ranges*/
        while(NULL_PTR != (crange_node = crange_mgr_first_node(crange_mgr)))
        {
            if(EC_FALSE == cvendor_content_repair_send_node(cvendor_md_id, crange_node))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_response: "
                                                        "send node (%ld:%s, %ld:%s) failed\n",
                                                        CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                        CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                    "send node (%ld:%s, %ld:%s) done => sent body %ld bytes\n",
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                                    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

            if(crange_mgr_first_node(crange_mgr) == crange_node)
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                        "pop node (%ld:%s, %ld:%s)\n",
                                                        CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                        CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));
                crange_mgr_first_node_pop(crange_mgr);
                crange_node_free(crange_node);
            }
        }

        /*send body: last boundary*/
        if(EC_FALSE == cstring_is_empty(CRANGE_MGR_BOUNDARY(crange_mgr)))
        {
            CSTRING     *boundary;
            uint8_t     *data;
            uint32_t     len;
            uint32_t     flags;

            boundary = CRANGE_MGR_BOUNDARY(crange_mgr);

            cvendor_content_repair_body_out_filter(cvendor_md_id);
            data = (uint8_t *)CSTRING_STR(boundary);
            len  = (uint32_t)CSTRING_LEN(boundary);

            flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                    | CNGX_SEND_BODY_FLUSH_FLAG
                    | CNGX_SEND_BODY_RECYCLED_FLAG;

            if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_repair_send_response: "
                                                        "send body boundary failed\n");

                return (EC_FALSE);
            }

            CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                    "send body boundary: %ld bytes done\n",
                                                    CSTRING_LEN(boundary));
        }

        /*send body end*/
        if(EC_FALSE == cvendor_content_repair_send_end(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_send_response: "
                                                    "send body end failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                "send body end done\n");

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_send_response: "
                                                "send body done => complete %ld bytes\n",
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_repair_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     status; /*response status*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_repair_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cvendor_content_repair_send_request(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_procedure: "
                                                "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_procedure: "
                                            "send request done\n");

    /*check and intercept error pages*/
    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    if(EC_TRUE == cngx_need_intercept_errors(r, status))
    {
        cvendor_set_ngx_rc(cvendor_md_id, status, LOC_CVENDOR_0158);

        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "warn:cvendor_content_repair_procedure: "
                                                "intercept rsp status %u done\n",
                                                status);
        return (EC_FALSE); /*terminate and back to ngx procedure*/
    }

    if(EC_FALSE == cngx_script_dir2_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_procedure: "
                                                "script dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_procedure: "
                                            "script dir2 filter done\n");

    if(EC_FALSE == cngx_headers_dir2_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_procedure: "
                                                "headers dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_procedure: "
                                            "headers dir2 filter done\n");

    if(EC_FALSE == cvendor_content_repair_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_repair_procedure: "
                                                "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_repair_procedure: "
                                            "send response done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_chunk_header_out_length_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_chunk_header_out_length_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        char       *content_length_str;
        UINT32      content_length;

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR == content_length_str)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_header_out_length_filter: "
                                                    "no 'Content-Length'\n");
            return (EC_FALSE);
        }

        content_length = c_str_to_word(content_length_str);

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_header_out_length_filter: "
                                                "parse Content-Length '%s' to %ld\n",
                                                content_length_str,
                                                content_length);

        if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_header_out_length_filter: "
                                                    "split content_length to segs failed\n");
            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_header_out_length_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_chunk_header_out_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_chunk_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_header_out_filter: "
                                                "not chunked rsp\n");
        return (EC_FALSE);
    }

    k = (const char *)"chunk";
    cvendor_filter_header_out_common(cvendor_md_id, k);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_header_out_filter: "
                                            "set chunked\n");

    /*set ngx flag*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

    k = (const char *)"Transfer-Encoding";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

    k = (const char *)"Connection";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0159);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_header_out_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_header_out_filter: "
                                                "after filter, rsp is\n");
        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md));
    }

    CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md) = BIT_TRUE;/*set flag*/

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_header_out_filter: done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_chunk_body_out_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_chunk_body_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    cngx_set_keepalive(r);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_chunk_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_chunk_send_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    cbytes_init(&seg_cbytes);

    if(EC_FALSE == cvendor_wait_cache_seg_n(cvendor_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_send_seg_n: "
                                                "wait cache seg %ld failed => no more data\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_TRUE);/*no more data*/
    }

    cvendor_content_chunk_body_out_filter(cvendor_md_id);

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG;

    if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_chunk_send_seg_n: "
                                                "send body seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_seg_n: "
                                            "send seg %ld [%ld, %ld], %u bytes\n",
                                            CRANGE_SEG_NO(crange_seg),
                                            CRANGE_SEG_S_OFFSET(crange_seg),
                                            CRANGE_SEG_E_OFFSET(crange_seg),
                                            len);

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_chunk_send_end(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_chunk_send_end: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_NO_MORE_FLAG
            /*
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            */
            ;

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_chunk_send_end: "
                                                "send body chunk-end failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_end: "
                                            "send chunk-end done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_chunk_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_chunk_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            /*check validity*/
            if(EC_FALSE == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_send_response: "
                                                        "not chunk rsp:\n");
                chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md));

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0160);
                return (EC_FALSE);
            }

            if(EC_FALSE == cvendor_content_chunk_header_out_filter(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_send_response: "
                                                        "chunk header_out filter failed\n");

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0161);
                return (EC_FALSE);
            }

            cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

            cngx_disable_write_delayed(r);

            if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_chunk_send_response: "
                                                        "send header failed\n");

                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_response: "
                                                    "send header done\n");
        }
    }

    /*send body: chunk*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md))
    {
        CRANGE_SEG      *crange_seg;

        crange_seg = crange_seg_new();
        if(NULL_PTR == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_response: "
                                                    "before send body, chunk [Y], new crange_seg failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0162);
            return (EC_FALSE);
        }

        CRANGE_SEG_SIZE(crange_seg)     = CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
        CRANGE_SEG_S_OFFSET(crange_seg) = 0;
        CRANGE_SEG_E_OFFSET(crange_seg) = CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;

        for(CRANGE_SEG_NO(crange_seg) = 1; ;CRANGE_SEG_NO(crange_seg) ++)
        {
            UINT32               seg_no;
            UINT32               sent_body_size;

            seg_no = CRANGE_SEG_NO(crange_seg);

            sent_body_size = CVENDOR_MD_SENT_BODY_SIZE(cvendor_md);

            if(EC_FALSE == cvendor_content_chunk_send_seg_n(cvendor_md_id, crange_seg))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_chunk_send_response: "
                                                        "chunk [Y], send cache seg %ld failed\n",
                                                        seg_no);

                crange_seg_free(crange_seg);
                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0163);
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_response: "
                                                    "chunk [Y], send cache seg %ld done => sent body %ld bytes\n",
                                                    seg_no,
                                                    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));
            /*no change => no more data*/
            if(CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) == sent_body_size /*the last chunked file with zero length*/
            || (CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) - sent_body_size < CRANGE_SEG_SIZE(crange_seg)) /*the last chunked file with length < seg size*/
            )
            {
                break;
            }
        }

        crange_seg_free(crange_seg);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_response: "
                                                "chunk [Y], send segs done => sent %ld bytes\n",
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));
    }

    if(EC_FALSE == cvendor_content_chunk_send_end(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_send_response: "
                                                "send body end failed\n");

        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_response: "
                                            "send body end done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_response: "
                                            "chunk [Y], send body done => complete %ld bytes\n",
                                            CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_send_response: done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_chunk_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_chunk_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"Transfer-Encoding";
    v = (const char *)"chunked";
    if(EC_FALSE == chttp_rsp_has_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_procedure: "
                                                "no '%s':'%s' found\n",
                                                k, v);
        return (EC_FALSE);
    }

    if(EC_FALSE == cvendor_content_orig_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_chunk_procedure: "
                                                "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_chunk_procedure: "
                                            "send response done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_in_filter_upstream(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CHTTP_REQ                   *chttp_req;

    UINT32                       upstream_peer_ipaddr;
    UINT32                       upstream_peer_port;

    uint8_t                     *upstream_name_str;
    uint32_t                     upstream_name_len;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_in_filter_upstream: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_upstream_get_name(r, &upstream_name_str, &upstream_name_len))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_upstream: "
                                                "get upstream name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_upstream_fetch(r, &upstream_peer_ipaddr, &upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_upstream: "
                                                "upstream '%.*s' fetch server failed\n",
                                                upstream_name_len, upstream_name_str);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_upstream: "
                                            "upstream '%.*s' fetch server %s:%ld\n",
                                            upstream_name_len, upstream_name_str,
                                            c_word_to_ipv4(upstream_peer_ipaddr), upstream_peer_port);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    if(EC_FALSE == chttp_req_set_ipaddr_word(chttp_req, upstream_peer_ipaddr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_upstream: "
                                                "[conf] set ipaddr '%s' of upsteam '%.*s' to http req failed\n",
                                                c_word_to_ipv4(upstream_peer_ipaddr),
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0164);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_upstream: "
                                            "[conf] set ipaddr '%s' of upsteam '%.*s' to http req done\n",
                                            c_word_to_ipv4(upstream_peer_ipaddr),
                                            upstream_name_len, upstream_name_str);

    if(EC_FALSE == chttp_req_set_port_word(chttp_req, upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_upstream: "
                                                "[cngx] set port '%ld' of upsteam '%.*s' to http req failed\n",
                                                upstream_peer_port,
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0165);
        return (EC_FALSE);
    }

    chttp_req_set_conn_fail_callback(chttp_req,
                                     (CHTTP_REQ_CONN_FAIL_CALLBACK)cngx_upstream_set_down,
                                     (void *)r);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_upstream: "
                                            "[cngx] set port '%ld' of upsteam '%.*s' to http req done\n",
                                            upstream_peer_port,
                                            upstream_name_len, upstream_name_str);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_in_filter_server(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_in_filter_server: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_orig_header_in_filter_server: "
                                                    "get '%s' failed\n",
                                                    k);
            continue;
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_server: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            c_str_split(v, ":", segs, 2);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, segs[ 0 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_orig_header_in_filter_server: "
                                                        "[cngx] set host of '%s' failed\n",
                                                        segs[ 0 ]);
                safe_free(v, LOC_CVENDOR_0166);

                continue;
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_server: "
                                                    "[cngx] set host '%s' to http req done\n",
                                                    segs[ 0 ]);
            safe_free(v, LOC_CVENDOR_0167);

            return (EC_TRUE);
        }
    }

    cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0168);
    return (EC_FALSE);
}

EC_BOOL cvendor_content_orig_header_in_filter_host(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_in_filter_host: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig host and port*/
    k = (const char *)CNGX_VAR_ORIG_HOST;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_host: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_host: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_host: "
                                                    "[conf] set ipaddr of host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0169);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0170);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_host: "
                                                "[conf] set ipaddr of host '%s' to http req done\n",
                                                v);

        if(EC_FALSE == chttp_req_renew_header(chttp_req, (const char *)"Host", v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_host: "
                                                    "[conf] set host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0171);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0172);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_host: "
                                                "[conf] set host '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0173);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_in_filter_port(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_in_filter_port: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_port: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_port: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0174);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_port: "
                                                "[conf] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0175);
        return (EC_TRUE);
    }

    if(EC_TRUE == chttp_req_is_local(chttp_req))
    {
        /*set default orig port*/
        if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[default] set default port '%d' to http req done\n",
                                                    CNGX_ORIG_HTTP_PORT_DEFAULT);
        }
        else
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[default] set default port '%d' to https req done\n",
                                                    CNGX_ORIG_HTTPS_PORT_DEFAULT);
        }
        return (EC_TRUE);
    }

    /*extract request port from request line*/
    if(EC_TRUE == cngx_get_req_port(r, &v) && NULL_PTR != v)
    {
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0176);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0177);
        return (EC_TRUE);
    }

    /*extract request port from Host header*/
    k = (const char *)"http_host";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        char   *segs[ 2 ];

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(2 == c_str_split(v, ":", segs, 2))
        {
            /*set port*/
            if(EC_FALSE == chttp_req_set_port(chttp_req, segs[ 1 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_port: "
                                                        "[cngx] set port '%s' to http req failed\n",
                                                        segs[ 1 ]);
                safe_free(v, LOC_CVENDOR_0178);
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req done\n",
                                                    segs[ 1 ]);
            safe_free(v, LOC_CVENDOR_0179);

            return (EC_TRUE);
        }

        safe_free(v, LOC_CVENDOR_0180);

        /*continue*/
    }

    /*use $server_port as the port connecting to origin*/
    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0181);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0182);

        return (EC_TRUE);
    }

    /*should never reach here*/

    /*set default orig port*/
    if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                "[default] set default port '%d' to http req done\n",
                                                CNGX_ORIG_HTTP_PORT_DEFAULT);
    }
    else
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                "[default] set default port '%d' to https req done\n",
                                                CNGX_ORIG_HTTPS_PORT_DEFAULT);
    }
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_in_filter_ipaddr(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_in_filter_ipaddr: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig ipaddr*/
    k = (const char *)CNGX_VAR_ORIG_IPADDR;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_ipaddr: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_ipaddr: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter_ipaddr: "
                                                    "[conf] set ipaddr '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0183);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0184);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter_ipaddr: "
                                                "[conf] set ipaddr  '%s' to http req done\n",
                                                v);

        safe_free(v, LOC_CVENDOR_0185);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_in_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_in_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*set ssl flag*/
    do
    {
        UINT32  ssl_flag;

        /*when cngx switch ssl on, then orig over https*/
        k = (const char *)CNGX_VAR_SSL_ORIG_SWITCH;
        cngx_get_var_switch(r, k, &ssl_flag, SWITCH_OFF);
        if(SWITCH_OFF == ssl_flag)
        {
            break;
        }

        /*ssl on*/
        chttp_req_enable_ssl(chttp_req);

        /*[optional] cngx configure CA*/
        k = (const char *)CNGX_VAR_SSL_CA;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_ca_file(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "[conf] set ca '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0186);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0187);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] set ca '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0188);

            /*fall through*/
        }

        /*cngx configure certificate*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_certificate_file(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "[conf] set certificate '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0189);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0190);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] set certificate '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0191);

            /*fall through*/
        }

        /*cngx configure certificate key*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE_KEY;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_private_key_file(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "[conf] set certificate key '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0192);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0193);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] set certificate key '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0194);

            /*fall through*/
        }
    }while(0);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config orig server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_server(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "[conf] set server '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0195);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0196);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] set server '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0197);

            /*set or overwrite ipaddr*/
            if(EC_FALSE == cvendor_content_orig_header_in_filter_ipaddr(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "filter ipaddr failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] filter ipaddr '%s' done\n",
                                                    chttp_req_get_ipaddr_str(chttp_req));


            /*set or overwrite port*/
            if(EC_FALSE == cvendor_content_orig_header_in_filter_port(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "filter port failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] filter port %ld done\n",
                                                    chttp_req_get_port(chttp_req));

            break; /*ok*/
        }

        /*set host*/
        if(EC_FALSE == cvendor_content_orig_header_in_filter_host(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "filter host failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite ipaddr*/
        if(EC_FALSE == cvendor_content_orig_header_in_filter_ipaddr(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "filter ipaddr failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite port*/
        if(EC_FALSE == cvendor_content_orig_header_in_filter_port(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "filter port failed\n");
            return (EC_FALSE);
        }

        if(EC_TRUE == chttp_req_has_ipaddr(chttp_req)
        && EC_TRUE == chttp_req_has_port(chttp_req))
        {
            break; /*ok*/
        }

        if(EC_TRUE == cngx_upstream_exist(r))
        {
            /*upstream*/
            if(EC_FALSE == cvendor_content_orig_header_in_filter_upstream(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "filter upstream failed\n");
                return (EC_FALSE);
            }
        }
        else
        {
            /*try best!*/
            if(EC_FALSE == cvendor_content_orig_header_in_filter_server(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "filter server failed\n");
                return (EC_FALSE);
            }
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(chttp_req, v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                "set method '%s' failed\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0198);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CVENDOR_0199);

    /*set http request uri*/
    do
    {
        /*when cngx config orig uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "get var '%s':'%s' done\n",
                                                    k, v);

            while('/' != v[ 0 ])
            {
                if(7 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"http://", 7))
                {
                    break;
                }

                if(8 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"https://", 8))
                {
                    break;
                }

                if(EC_FALSE == chttp_req_set_uri(chttp_req, (const char *)"/"))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                            "[cngx] append '/' failed\n");
                    safe_free(v, LOC_CVENDOR_0200);
                    return (EC_FALSE);
                }
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                        "[cngx] append '/' done\n");
                break; /*fall through*/
            }

            if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "[conf] set uri '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0201);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[conf] set uri '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0202);

            break; /*ok*/
        }

        /*when cngx NOT config orig uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "[cngx] set uri '%s' failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0203);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                "[cngx] set uri '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0204);

        if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[cngx] get args '%s'\n",
                                                    v);

            if(EC_FALSE == chttp_req_set_uri(chttp_req, (const char *)"?"))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "[cngx] set '?' failed\n");
                safe_free(v, LOC_CVENDOR_0205);
                return (EC_FALSE);
            }

            if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                        "[cngx] set args '%s' failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0206);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "[cngx] set args '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0207);
        }
    }while(0);

    /*set keep-alive*/
    do
    {
        if(EC_TRUE == cngx_is_orig_keepalive_switch_on(r))
        {
            k = (const char *)"Connection";
            v = (char       *)"keep-alive";
            chttp_req_renew_header(chttp_req, k, v);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "renew req header '%s':'%s' done\n",
                                                    k, v);

            k = (const char *)"Proxy-Connection";
            chttp_req_del_header(chttp_req, k);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "del req header '%s' done\n",
                                                    k);
        }
        else
        {
            k = (const char *)"Connection";
            chttp_req_del_header(chttp_req, k);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "del req header '%s' done\n",
                                                    k);

            k = (const char *)"Proxy-Connection";
            chttp_req_del_header(chttp_req, k);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                    "del req header '%s' done\n",
                                                    k);
        }
    }while(0);

    /*delete If-Modified-Since*/
    do
    {
        k = (const char *)"If-Modified-Since";
        chttp_req_del_header(chttp_req, k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                "del req header '%s' done\n",
                                                k);
    }while(0);

    /*delete If-None-Match*/
    do
    {
        k = (const char *)"If-None-Match";
        chttp_req_del_header(chttp_req, k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                "del req header '%s' done\n",
                                                k);
    }while(0);

    /*set range*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            range_start = 0;
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }
        else
        {
            range_start = (CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) - 1) * CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }

        if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md) && range_end >= CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
        {
            range_end = CVENDOR_MD_CONTENT_LENGTH(cvendor_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(chttp_req, k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_in_filter: "
                                                "set header '%s':'%s' done\n",
                                                k, v);
    }

    return cvendor_filter_header_in_common(cvendor_md_id);
}

EC_BOOL cvendor_content_orig_header_out_if_modified_since_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    time_t                       ims_1st; /*if-modifed-since in cngx http req*/
    time_t                       ims_2nd; /*last-modified in response (seg-0 in storage)*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_out_if_modified_since_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"If-Modified-Since";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_if_modified_since_filter: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_modified_since_filter: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    ims_1st = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    safe_free(v, LOC_CVENDOR_0208);

    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_modified_since_filter: "
                                                "[rsp] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    ims_2nd = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    if(ims_1st < ims_2nd)
    {
        if(CHTTP_PARTIAL_CONTENT != CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
        {
            /*set rsp status to 200*/
            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_modified_since_filter: "
                                                    "set rsp status = %u\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        }

        return (EC_TRUE);
    }

    /*set rsp status to 304*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_NOT_MODIFIED;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_modified_since_filter: "
                                            "set rsp status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    crange_mgr_clean(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_modified_since_filter: "
                                            "clean cngx range mgr\n");

    chttp_rsp_only_headers(CVENDOR_MD_CHTTP_RSP(cvendor_md), g_cvendor_304_headers, g_cvendor_304_headers_num);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_modified_since_filter: "
                                            "reset rsp headers\n");

    cngx_set_header_only(r);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_modified_since_filter: "
                                            "set header only\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_out_if_none_match_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    char                        *etag_src; /*ETag on cache side*/
    char                        *etag_des; /*ETag on client side*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_out_if_none_match_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"If-None-Match";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_if_none_match_filter: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_none_match_filter: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    etag_des = v;

    k = (const char *)"ETag";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_none_match_filter: "
                                                "[rsp] no '%s'\n",
                                                k);
        safe_free(etag_des, LOC_CVENDOR_0209);
        return (EC_TRUE);
    }
    etag_src = v;

    if(0 != STRCASECMP(etag_src, etag_des)) /*not match*/
    {
        /*set rsp status to 200*/
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_none_match_filter: "
                                                "set rsp status = %u\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

        return (EC_TRUE);
    }

    /*set rsp status to 304*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_NOT_MODIFIED;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_none_match_filter: "
                                            "set rsp status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    crange_mgr_clean(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_none_match_filter: "
                                            "clean cngx range mgr\n");

    chttp_rsp_only_headers(CVENDOR_MD_CHTTP_RSP(cvendor_md), g_cvendor_304_headers, g_cvendor_304_headers_num);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_none_match_filter: "
                                            "reset rsp headers\n");

    cngx_set_header_only(r);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_if_none_match_filter: "
                                            "set header only\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_out_range_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_out_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CHTTP_NO_CONTENT == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                                "status 204 (no content) => done\n");

        return (EC_TRUE);
    }

    while(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        char       *content_length_str;
        char       *content_range_str;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR != content_length_str)
        {
            content_length = c_str_to_word(content_length_str);

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                                    "parse Content-Length '%s' to  %ld\n",
                                                    content_length_str,
                                                    content_length);
            break; /*fall through*/
        }

        content_range_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Range");
        if(NULL_PTR == content_range_str)
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_orig_header_out_range_filter: "
                                                    "no 'Content-Range' => chunk\n");
            /*maybe chunk*/
            return cvendor_content_chunk_header_out_filter(cvendor_md_id);
        }

        if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_range_filter: "
                                                    "invalid Content-Range '%s'\n",
                                                    content_range_str);
            return (EC_FALSE);
        }

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                                "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                content_range_str,
                                                range_start, range_end, content_length);
        break;/*fall through*/
    }

    if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG(cvendor_md)
    && 1 == crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        UINT32                       content_length;

        content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

        if(EC_TRUE == crange_mgr_is_range(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md), 0, content_length - 1))
        {
            const char                  *k;
            const char                  *v;

            k = (const char *)"Content-Range";

            chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                                    "only one range which cover whole content => delete header '%s' done\n",
                                                    k);

            k = (const char *)"Content-Length";
            v = (const char *)c_word_to_str(content_length);

            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                                    "only one range which cover whole content => renew header '%s':'%s' done\n",
                                                    k, v);
        }
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        UINT32                       content_length;

        content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                                 "delete '%s' done\n",
                                                 k);

        /*whole Content*/
        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                                 "renew '%s':'%s' done\n",
                                                 k, v);
        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(EC_FALSE == cvendor_filter_header_out_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_range_filter: "
                                                "filter range failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                            "filter range done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_range_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_out_rsp_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_out_rsp_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0210);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }

    if(CHTTP_NOT_FOUND == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                                "[cngx] 404 keep unchanged => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                            "response status = %u [before]\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    if(CHTTP_MOVED_PERMANENTLY == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md))
    || CHTTP_MOVED_TEMPORARILY == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                                "[cngx] 301/302 keep unchanged => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                                "[cngx] no range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                            "CVENDOR_MD_CONTENT_LENGTH = %ld\n",
                                            CVENDOR_MD_CONTENT_LENGTH(cvendor_md));

    k = (const char *)"Content-Range";
    if(EC_TRUE == chttp_rsp_has_header_key(CVENDOR_MD_CHTTP_RSP(cvendor_md), k))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                                "'%s' exist => response status = %u [after]\n",
                                                k, CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(1 < crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                                "[cngx] multi range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_rsp_status_filter: "
                                            "response status = %u [after]\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_out_cache_control_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_out_cache_control_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(BIT_FALSE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        const char      *k;
        const char      *v;

        k = (const char *)CHTTP_RSP_X_CACHE_CONTROL;
        v = (const char *)"no-cache";

        if(EC_TRUE == chttp_rsp_has_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_cache_control_filter: "
                                                    "found '%s':'%s' => set orig_no_cache_flag = true\n",
                                                    k, v);
            CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md) = BIT_TRUE;
            return (EC_TRUE);
        }

        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_cache_control_filter: "
                                            "found orig_no_cache_flag is true\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_out_gzip_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_out_gzip_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(BIT_TRUE == CVENDOR_MD_CNGX_USE_GZIP_FLAG(cvendor_md)
    && BIT_TRUE == CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        k = (const char *)"Content-Encoding";
        v = (const char *)"gzip";

        if(EC_FALSE == chttp_rsp_has_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            /*note: the cache gzip flag will impact on cache_uri generation*/
            CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md) = BIT_FALSE; /*reset to false*/

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_gzip_filter: "
                                                    "orig not given '%s':'%s' => reset cache gzip flag to false\n",
                                                    k, v);
        }

        k = (const char *)"Content-Length";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_gzip_filter: "
                                                "gzip => del rsp header '%s'\n",
                                                k);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_gzip_filter: "
                                            "gzip filter done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_header_out_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"orig";
    cvendor_filter_header_out_common(cvendor_md_id, k);

    v = (const char *)CNGX_CACHE_STATUS_MISS;
    CVENDOR_MD_CACHE_STATUS(cvendor_md) = v;

    /*Content-Length and Content-Range*/
    if(EC_FALSE == cvendor_content_orig_header_out_range_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_filter: "
                                                "range filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_filter: "
                                            "range filter done\n");
    /*gzip*/
    if(EC_FALSE == cvendor_content_orig_header_out_gzip_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_filter: "
                                                "gzip filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_filter: "
                                            "gzip filter done\n");

    if(BIT_FALSE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        if(EC_FALSE == cvendor_content_orig_header_out_rsp_status_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_filter: "
                                                    "status filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_filter: "
                                                "status filter done\n");
    }

    if(EC_FALSE == cvendor_content_orig_header_out_if_modified_since_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_filter: "
                                                "if-modified-since filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_filter: "
                                            "if-modified-since filter done\n");

    if(EC_FALSE == cvendor_content_orig_header_out_if_none_match_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_header_out_filter: "
                                                "if-none-match filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_filter: "
                                            "if-none-match filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_header_out_filter: done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_body_out_filter(const UINT32 cvendor_md_id, const UINT32 seg_no, uint8_t **data, uint32_t *len)
{
    //CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_body_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_set_store(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_STORE                 *chttp_store;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_set_store: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_store = CVENDOR_MD_CHTTP_STORE(cvendor_md);

    /*--- chttp_store settting --- BEG ---*/
    CHTTP_STORE_SEG_MAX_ID(chttp_store) = (uint32_t)CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md);

    if(CVENDOR_ERR_SEG_NO == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        CHTTP_STORE_SEG_ID(chttp_store) = 0;
    }
    else
    {
        CHTTP_STORE_SEG_ID(chttp_store) = (uint32_t)CVENDOR_MD_ABSENT_SEG_NO(cvendor_md);
    }

    CHTTP_STORE_SEG_SIZE(chttp_store)     = CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
    CHTTP_STORE_SEG_S_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;
    CHTTP_STORE_SEG_E_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;

    cstring_clone(CVENDOR_MD_CACHE_PATH(cvendor_md), CHTTP_STORE_BASEDIR(chttp_store));

    if(0 == CHTTP_STORE_SEG_ID(chttp_store))
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)       = BIT_FALSE;
        CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store) = BIT_FALSE;/*refer: ms procedure*/
        CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store) = BIT_FALSE;/*refer: direct procedure*/
        CHTTP_STORE_NEED_LOG_FLAG(chttp_store)    = BIT_TRUE;
    }
    else
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)       = BIT_TRUE;
        CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store) = BIT_FALSE;/*refer: ms procedure*/
        CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store) = BIT_FALSE;/*refer: direct procedure*/
        CHTTP_STORE_NEED_LOG_FLAG(chttp_store)    = BIT_TRUE;
    }

    if(EC_FALSE == cngx_set_store(r, chttp_store))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_set_store: "
                                                "fetch ngx cfg to chttp_store failed\n");
        return (EC_FALSE);
    }

    CHTTP_STORE_CACHE_CTRL(chttp_store) = CHTTP_STORE_CACHE_BOTH;

    cstring_clone(CVENDOR_MD_CACHED_ETAG(cvendor_md)        , CHTTP_STORE_ETAG(chttp_store));
    cstring_clone(CVENDOR_MD_CACHED_LAST_MODIFED(cvendor_md), CHTTP_STORE_LAST_MODIFIED(chttp_store));

    if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
    {
        CHTTP_STORE_CONTENT_LENGTH(chttp_store) = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);
    }

    /*--- chttp_store settting --- END ---*/

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_send_request(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STORE                 *chttp_store;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_send_request: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chttp_req*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_REQ(cvendor_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                    "new chttp_req failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0211);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_REQ(cvendor_md) = chttp_req;
    }
    else
    {
        chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                    "new chttp_rsp failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0212);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);
        chttp_rsp_clean(chttp_rsp);
    }

    /*chttp_store*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STORE(cvendor_md))
    {
        chttp_store = chttp_store_new();
        if(NULL_PTR == chttp_store)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                    "new chttp_store failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0213);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STORE(cvendor_md) = chttp_store;
    }
    else
    {
        chttp_store = CVENDOR_MD_CHTTP_STORE(cvendor_md);
        chttp_store_clean(chttp_store);
    }

    if(EC_FALSE == cvendor_content_orig_set_store(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                "set chttp_store failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0214);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_request: "
                                                "chttp_store is\n");
        chttp_store_print(LOGSTDOUT, chttp_store);
    }

    /*chttp_stat*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STAT(cvendor_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                    "new chttp_stat failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0215);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STAT(cvendor_md)  = chttp_stat;
    }
    else
    {
        chttp_stat = CVENDOR_MD_CHTTP_STAT(cvendor_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                "export headers_in to http req failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0216);
        return (EC_FALSE);
    }

    if(EC_FALSE == cvendor_content_orig_header_in_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                "header_in filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0217);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, chttp_store, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_request: "
                                                "http request failed\n");

        if(0 < CHTTP_STAT_RSP_STATUS(chttp_stat))
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_STAT_RSP_STATUS(chttp_stat), LOC_CVENDOR_0218);
        }
        else
        {
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CVENDOR_0219);
        }

        return (EC_FALSE);
    }
    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_request: "
                                            "send request done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_send_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    cbytes_init(&seg_cbytes);

    if(EC_FALSE == cvendor_get_cache_seg_n(cvendor_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_orig_send_seg_n: "
                                                "get cache seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_NOT_FOUND, LOC_CVENDOR_0220);
        return (EC_FALSE);
    }

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG;

    cvendor_content_orig_body_out_filter(cvendor_md_id, CRANGE_SEG_NO(crange_seg), &data, &len);

    if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_orig_send_seg_n: "
                                                "send body seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_seg_n: "
                                            "send seg %ld [%ld, %ld], %ld bytes\n",
                                            CRANGE_SEG_NO(crange_seg),
                                            CRANGE_SEG_S_OFFSET(crange_seg),
                                            CRANGE_SEG_E_OFFSET(crange_seg),
                                            CBYTES_LEN(&seg_cbytes));

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CRANGE_MGR                  *crange_mgr;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chunk*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
    || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                "orig => chunk procedure\n");

        return cvendor_content_chunk_send_response(cvendor_md_id);
    }

    if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_response: "
                                                "chttp rsp header range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                            "chttp rsp header range filter done\n");

    /*send header*/
    if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        if(EC_FALSE == cvendor_content_orig_header_out_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_response: "
                                                    "header_out filter failed\n");

            cvendor_handover_ngx_rc(cvendor_md_id, LOC_CVENDOR_0221);
            return (EC_FALSE);
        }

        if(EC_FALSE == cvendor_content_cache_save_header(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_response: "
                                                    "save header failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                "save header done\n");

        if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

            cngx_disable_write_delayed(r);
        }
    }
    else
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                "absent_seg_no = %ld != 0 => ignore header_out filter and sending\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
    }

    crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);

    /*note: only after header_out filter with unchanged range segs, we can parse content lengt to segs*/
    /*parse Content-Length and segs from chttp rsp if cngx req has no 'Range'*/
    if(EC_FALSE == cngx_need_header_only(r)
    && EC_TRUE == crange_mgr_is_empty(crange_mgr))
    {
        if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_send_response: "
                                                    "get range segs from chttp rsp failed\n");
            return (EC_FALSE);
        }
    }

    if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                "crange_mgr size = %ld\n",
                                                crange_mgr_node_num(crange_mgr));

        if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            if(EC_FALSE  == cngx_need_header_only(r)
            && BIT_FALSE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md) /*not chunk*/
            && EC_TRUE   == crange_mgr_is_empty(crange_mgr))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                        "set header only\n");
                cngx_set_header_only(r);
            }

            if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_orig_send_response: "
                                                        "send header failed\n");

                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                    "send header done\n");
        }

        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) ++;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                "inc absent_seg_no to %ld\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
    }

    if(EC_TRUE == cngx_need_header_only(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                "need header only => return\n");
        return (EC_TRUE);
    }

    /*send body*/

    /*send one seg only*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
    && EC_FALSE == crange_mgr_is_empty(crange_mgr))
    {
        CRANGE_NODE                *crange_node;
        CRANGE_SEG                 *crange_seg;
        UINT32                      seg_no;

        crange_node = crange_mgr_first_node(crange_mgr);
        crange_seg  = crange_node_first_seg(crange_node);
        seg_no      = CRANGE_SEG_NO(crange_seg);

        if(seg_no != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_orig_send_response: "
                                                    "seg_no %ld != absent_seg_no %ld => return\n",
                                                    seg_no, CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

            return (EC_TRUE);
        }
        ASSERT(seg_no == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        if(EC_FALSE == cvendor_content_orig_send_seg_n(cvendor_md_id, crange_seg))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_orig_send_response: "
                                                    "send cache seg %ld failed\n",
                                                    seg_no);

            return (EC_FALSE);
        }

        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CVENDOR_ERR_SEG_NO;/*clear*/

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                "send cache seg %ld done => sent body %ld bytes\n",
                                                CRANGE_SEG_NO(crange_seg),
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                    "pop seg %ld\n",
                                                    CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }

        if(do_log(SEC_0175_CVENDOR, 9))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: "
                                                    "crange_node %p:\n",
                                                    crange_node);
            crange_node_print(LOGSTDOUT, crange_node);
        }
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_send_response: done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_orig_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     status; /*response status*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_orig_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cvendor_content_orig_send_request(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_procedure: "
                                                "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                            "send request done\n");

    /*check and intercept error pages*/
    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    if(EC_TRUE == cngx_need_intercept_errors(r, status))
    {
        cvendor_set_ngx_rc(cvendor_md_id, status, LOC_CVENDOR_0222);

        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "warn:cvendor_content_orig_procedure: "
                                                "intercept rsp status %u done\n",
                                                status);
        return (EC_FALSE); /*terminate and back to ngx procedure*/
    }

    /*301/302 redirect*/
    if(EC_TRUE == cvendor_is_redirect_rsp(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                                "301/302 => redirect procedure\n");
        /*return cvendor_content_redirect_procedure(cvendor_md_id);*//*TODO*/
        if(EC_FALSE == cvendor_content_redirect_procedure(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_procedure: "
                                                    "301/302 failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                                "301/302 done\n");
    }

    /*specific redirect*/
    if(EC_TRUE == cvendor_is_specific_redirect_rsp(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                                "specific redirect rsp => redirect procedure\n");
        /*return cvendor_content_redirect_procedure(cvendor_md_id);*//*TODO*/
        if(EC_FALSE == cvendor_content_redirect_procedure(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_procedure: "
                                                    "specific redirect rsp failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                                "specific redirect rsp done\n");
    }

    if(EC_FALSE == cngx_script_dir2_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_procedure: "
                                                "script dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                            "script dir2 filter done\n");

    if(EC_FALSE == cngx_headers_dir2_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_procedure: "
                                                "headers dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                            "headers dir2 filter done\n");

    if(EC_FALSE == cvendor_content_orig_header_out_cache_control_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_orig_procedure: "
                                                "filter rsp cache-control failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                            "filter rsp cache-control done\n");

    if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                                "found orig_no_cache_flag is true => direct send response\n");

        return cvendor_content_direct_send_response(cvendor_md_id);
    }

    if(EC_FALSE == cvendor_content_orig_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_orig_procedure: "
                                                "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_orig_procedure: "
                                            "send response done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_in_filter_upstream(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CHTTP_REQ                   *chttp_req;

    UINT32                       upstream_peer_ipaddr;
    UINT32                       upstream_peer_port;

    uint8_t                     *upstream_name_str;
    uint32_t                     upstream_name_len;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_in_filter_upstream: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_upstream_get_name(r, &upstream_name_str, &upstream_name_len))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_upstream: "
                                                "get upstream name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_upstream_fetch(r, &upstream_peer_ipaddr, &upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_upstream: "
                                                "upstream '%.*s' fetch server failed\n",
                                                upstream_name_len, upstream_name_str);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_upstream: "
                                            "upstream '%.*s' fetch server %s:%ld\n",
                                            upstream_name_len, upstream_name_str,
                                            c_word_to_ipv4(upstream_peer_ipaddr), upstream_peer_port);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    if(EC_FALSE == chttp_req_set_ipaddr_word(chttp_req, upstream_peer_ipaddr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_upstream: "
                                                "[conf] set ipaddr '%s' of upsteam '%.*s' to http req failed\n",
                                                c_word_to_ipv4(upstream_peer_ipaddr),
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0223);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_upstream: "
                                            "[conf] set ipaddr '%s' of upsteam '%.*s' to http req done\n",
                                            c_word_to_ipv4(upstream_peer_ipaddr),
                                            upstream_name_len, upstream_name_str);

    if(EC_FALSE == chttp_req_set_port_word(chttp_req, upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_upstream: "
                                                "[cngx] set port '%ld' of upsteam '%.*s' to http req failed\n",
                                                upstream_peer_port,
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0224);
        return (EC_FALSE);
    }

    chttp_req_set_conn_fail_callback(chttp_req,
                                     (CHTTP_REQ_CONN_FAIL_CALLBACK)cngx_upstream_set_down,
                                     (void *)r);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_upstream: "
                                            "[cngx] set port '%ld' of upsteam '%.*s' to http req done\n",
                                            upstream_peer_port,
                                            upstream_name_len, upstream_name_str);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_in_filter_server(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_in_filter_server: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_ms_header_in_filter_server: "
                                                    "get '%s' failed\n",
                                                    k);
            continue;
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_server: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            c_str_split(v, ":", segs, 2);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, segs[ 0 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_ms_header_in_filter_server: "
                                                        "[cngx] set host of '%s' failed\n",
                                                        segs[ 0 ]);
                safe_free(v, LOC_CVENDOR_0225);

                continue;
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_server: "
                                                    "[cngx] set host '%s' to http req done\n",
                                                    segs[ 0 ]);
            safe_free(v, LOC_CVENDOR_0226);

            return (EC_TRUE);
        }
    }

    cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0227);
    return (EC_FALSE);
}

EC_BOOL cvendor_content_ms_header_in_filter_host(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_in_filter_host: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig host and port*/
    k = (const char *)CNGX_VAR_ORIG_HOST;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_host: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_host: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_host: "
                                                    "[conf] set ipaddr of host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0228);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0229);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_host: "
                                                "[conf] set ipaddr of host '%s' to http req done\n",
                                                v);

        if(EC_FALSE == chttp_req_renew_header(chttp_req, (const char *)"Host", v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_host: "
                                                    "[conf] set host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0230);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0231);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_host: "
                                                "[conf] set host '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0232);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_in_filter_port(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_in_filter_port: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_port: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_port: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0233);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_port: "
                                                "[conf] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0234);
        return (EC_TRUE);
    }

    if(EC_TRUE == chttp_req_is_local(chttp_req))
    {
        /*set default orig port*/
        if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[default] set default port '%d' to http req done\n",
                                                    CNGX_ORIG_HTTP_PORT_DEFAULT);
        }
        else
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[default] set default port '%d' to https req done\n",
                                                    CNGX_ORIG_HTTPS_PORT_DEFAULT);
        }
        return (EC_TRUE);
    }

    /*extract request port from request line*/
    if(EC_TRUE == cngx_get_req_port(r, &v) && NULL_PTR != v)
    {
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0235);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0236);
        return (EC_TRUE);
    }

    /*extract request port from Host header*/
    k = (const char *)"http_host";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        char   *segs[ 2 ];

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(2 == c_str_split(v, ":", segs, 2))
        {
            /*set port*/
            if(EC_FALSE == chttp_req_set_port(chttp_req, segs[ 1 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_port: "
                                                        "[cngx] set port '%s' to http req failed\n",
                                                        segs[ 1 ]);
                safe_free(v, LOC_CVENDOR_0237);
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req done\n",
                                                    segs[ 1 ]);
            safe_free(v, LOC_CVENDOR_0238);

            return (EC_TRUE);
        }

        safe_free(v, LOC_CVENDOR_0239);

        /*continue*/
    }

    /*use $server_port as the port connecting to origin*/
    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0240);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0241);

        return (EC_TRUE);
    }

    /*should never reach here*/

    /*set default orig port*/
    if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                "[default] set default port '%d' to http req done\n",
                                                CNGX_ORIG_HTTP_PORT_DEFAULT);
    }
    else
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                "[default] set default port '%d' to https req done\n",
                                                CNGX_ORIG_HTTPS_PORT_DEFAULT);
    }
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_in_filter_ipaddr(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_in_filter_ipaddr: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig ipaddr*/
    k = (const char *)CNGX_VAR_ORIG_IPADDR;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_ipaddr: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_ipaddr: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter_ipaddr: "
                                                    "[conf] set ipaddr '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0242);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0243);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter_ipaddr: "
                                                "[conf] set ipaddr  '%s' to http req done\n",
                                                v);

        safe_free(v, LOC_CVENDOR_0244);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_in_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_in_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*set ssl flag*/
    do
    {
        UINT32  ssl_flag;

        /*when cngx switch ssl on, then orig over https*/
        k = (const char *)CNGX_VAR_SSL_ORIG_SWITCH;
        cngx_get_var_switch(r, k, &ssl_flag, SWITCH_OFF);
        if(SWITCH_OFF == ssl_flag)
        {
            break;
        }

        /*ssl on*/
        chttp_req_enable_ssl(chttp_req);

        /*[optional] cngx configure CA*/
        k = (const char *)CNGX_VAR_SSL_CA;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_ca_file(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "[conf] set ca '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0245);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0246);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] set ca '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0247);

            /*fall through*/
        }

        /*cngx configure certificate*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_certificate_file(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "[conf] set certificate '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0248);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0249);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] set certificate '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0250);

            /*fall through*/
        }

        /*cngx configure certificate key*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE_KEY;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_private_key_file(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "[conf] set certificate key '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0251);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0252);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] set certificate key '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0253);

            /*fall through*/
        }
    }while(0);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config orig server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_server(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "[conf] set server '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0254);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0255);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] set server '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0256);

            /*set or overwrite ipaddr*/
            if(EC_FALSE == cvendor_content_ms_header_in_filter_ipaddr(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "filter ipaddr failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] filter ipaddr '%s' done\n",
                                                    chttp_req_get_ipaddr_str(chttp_req));


            /*set or overwrite port*/
            if(EC_FALSE == cvendor_content_ms_header_in_filter_port(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "filter port failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] filter port %ld done\n",
                                                    chttp_req_get_port(chttp_req));
            break; /*ok*/
        }

        /*set host*/
        if(EC_FALSE == cvendor_content_ms_header_in_filter_host(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "filter host failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite ipaddr*/
        if(EC_FALSE == cvendor_content_ms_header_in_filter_ipaddr(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "filter ipaddr failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite port*/
        if(EC_FALSE == cvendor_content_ms_header_in_filter_port(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "filter port failed\n");
            return (EC_FALSE);
        }

        if(EC_TRUE == chttp_req_has_ipaddr(chttp_req)
        && EC_TRUE == chttp_req_has_port(chttp_req))
        {
            break; /*ok*/
        }

        if(EC_TRUE == cngx_upstream_exist(r))
        {
            /*upstream*/
            if(EC_FALSE == cvendor_content_ms_header_in_filter_upstream(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "filter upstream failed\n");
                return (EC_FALSE);
            }
        }
        else
        {
            /*try best!*/
            if(EC_FALSE == cvendor_content_ms_header_in_filter_server(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "filter server failed\n");
                return (EC_FALSE);
            }
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(chttp_req, v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                "set method '%s' failed\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0257);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CVENDOR_0258);

    /*set http request uri*/
    do
    {
        /*when cngx config orig uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "get var '%s':'%s' done\n",
                                                    k, v);

            while('/' != v[ 0 ])
            {
                if(7 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"http://", 7))
                {
                    break;
                }

                if(8 < strlen(v) && 0 == STRNCASECMP(v, (const char *)"https://", 8))
                {
                    break;
                }

                if(EC_FALSE == chttp_req_set_uri(chttp_req, (const char *)"/"))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                            "[cngx] append '/' failed\n");
                    safe_free(v, LOC_CVENDOR_0259);
                    return (EC_FALSE);
                }
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                        "[cngx] append '/' done\n");
                break; /*fall through*/
            }

            if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "[conf] set uri '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0260);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[conf] set uri '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0261);

            break; /*ok*/
        }

        /*when cngx NOT config orig uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "[cngx] set uri '%s' failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0262);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                "[cngx] set uri '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0263);

        if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[cngx] get args '%s'\n",
                                                    v);

            if(EC_FALSE == chttp_req_set_uri(chttp_req, (const char *)"?"))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "[cngx] set '?' failed\n");
                safe_free(v, LOC_CVENDOR_0264);
                return (EC_FALSE);
            }

            if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                        "[cngx] set args '%s' failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0265);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "[cngx] set args '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0266);
        }
    }while(0);

    /*set keep-alive*/
    do
    {
        if(EC_TRUE == cngx_is_orig_keepalive_switch_on(r))
        {
            k = (const char *)"Connection";
            v = (char       *)"keep-alive";
            chttp_req_renew_header(chttp_req, k, v);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "renew req header '%s':'%s' done\n",
                                                    k, v);

            k = (const char *)"Proxy-Connection";
            chttp_req_del_header(chttp_req, k);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "del req header '%s' done\n",
                                                    k);
        }
        else
        {
            k = (const char *)"Connection";
            chttp_req_del_header(chttp_req, k);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "del req header '%s' done\n",
                                                    k);

            k = (const char *)"Proxy-Connection";
            chttp_req_del_header(chttp_req, k);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                    "del req header '%s' done\n",
                                                    k);
        }
    }while(0);

    /*delete If-Modified-Since*/
    do
    {
        k = (const char *)"If-Modified-Since";
        chttp_req_del_header(chttp_req, k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                "del req header '%s' done\n",
                                                k);
    }while(0);

    /*delete If-None-Match*/
    do
    {
        k = (const char *)"If-None-Match";
        chttp_req_del_header(chttp_req, k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                "del req header '%s' done\n",
                                                k);
    }while(0);

    /*set range*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            range_start = 0;
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }
        else
        {
            range_start = (CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) - 1) * CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
            range_end   = range_start + CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md) - 1;
        }

        if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md) && range_end >= CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
        {
            range_end = CVENDOR_MD_CONTENT_LENGTH(cvendor_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(chttp_req, k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_in_filter: "
                                                "set header '%s':'%s' done\n",
                                                k, v);
    }

    return cvendor_filter_header_in_common(cvendor_md_id);
}

EC_BOOL cvendor_content_ms_header_out_if_modified_since_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    time_t                       ims_1st; /*if-modifed-since in cngx http req*/
    time_t                       ims_2nd; /*last-modified in response (seg-0 in storage)*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_if_modified_since_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"If-Modified-Since";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_if_modified_since_filter: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_modified_since_filter: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    ims_1st = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    safe_free(v, LOC_CVENDOR_0267);

    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_modified_since_filter: "
                                                "[rsp] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    ims_2nd = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    if(ims_1st < ims_2nd)
    {
        if(CHTTP_PARTIAL_CONTENT != CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
        {
            /*set rsp status to 200*/
            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_modified_since_filter: "
                                                    "set rsp status = %u\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        }

        return (EC_TRUE);
    }

    /*set rsp status to 304*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_NOT_MODIFIED;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_modified_since_filter: "
                                            "set rsp status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    crange_mgr_clean(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_modified_since_filter: "
                                            "clean cngx range mgr\n");

    chttp_rsp_only_headers(CVENDOR_MD_CHTTP_RSP(cvendor_md), g_cvendor_304_headers, g_cvendor_304_headers_num);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_modified_since_filter: "
                                            "reset rsp headers\n");

    cngx_set_header_only(r);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_modified_since_filter: "
                                            "set header only\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_out_if_none_match_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    char                        *etag_src; /*ETag on cache side*/
    char                        *etag_des; /*ETag on client side*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_if_none_match_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"If-None-Match";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_if_none_match_filter: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_none_match_filter: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    etag_des = v;

    k = (const char *)"ETag";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_none_match_filter: "
                                                "[rsp] no '%s'\n",
                                                k);
        safe_free(etag_des, LOC_CVENDOR_0268);
        return (EC_TRUE);
    }
    etag_src = v;

    if(0 != STRCASECMP(etag_src, etag_des)) /*not match*/
    {
        /*set rsp status to 200*/
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_none_match_filter: "
                                                "set rsp status = %u\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

        return (EC_TRUE);
    }

    /*set rsp status to 304*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_NOT_MODIFIED;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_none_match_filter: "
                                            "set rsp status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    crange_mgr_clean(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_none_match_filter: "
                                            "clean cngx range mgr\n");

    chttp_rsp_only_headers(CVENDOR_MD_CHTTP_RSP(cvendor_md), g_cvendor_304_headers, g_cvendor_304_headers_num);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_none_match_filter: "
                                            "reset rsp headers\n");

    cngx_set_header_only(r);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_if_none_match_filter: "
                                            "set header only\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_out_range_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CHTTP_NO_CONTENT == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                                "status 204 (no content) => done\n");

        return (EC_TRUE);
    }

    while(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        char       *content_length_str;
        char       *content_range_str;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        content_length_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Length");
        if(NULL_PTR != content_length_str)
        {
            content_length = c_str_to_word(content_length_str);

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                                    "parse Content-Length '%s' to  %ld\n",
                                                    content_length_str,
                                                    content_length);
            break; /*fall through*/
        }

        content_range_str = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Content-Range");
        if(NULL_PTR == content_range_str)
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_ms_header_out_range_filter: "
                                                    "no 'Content-Range' => chunk\n");
            /*maybe chunk*/
            return cvendor_content_chunk_header_out_filter(cvendor_md_id);
        }

        if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_range_filter: "
                                                    "invalid Content-Range '%s'\n",
                                                    content_range_str);
            return (EC_FALSE);
        }

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                                "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                content_range_str,
                                                range_start, range_end, content_length);
        break;/*fall through*/
    }

    if(BIT_TRUE == CVENDOR_MD_CNGX_RANGE_MULTIPLE_FLAG(cvendor_md)
    && 1 == crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        UINT32                       content_length;

        content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

        if(EC_TRUE == crange_mgr_is_range(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md), 0, content_length - 1))
        {
            const char                  *k;
            const char                  *v;

            k = (const char *)"Content-Range";

            chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                                    "only one range which cover whole content => delete header '%s' done\n",
                                                    k);

            k = (const char *)"Content-Length";
            v = (const char *)c_word_to_str(content_length);

            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                                    "only one range which cover whole content => renew header '%s':'%s' done\n",
                                                    k, v);
        }
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        UINT32                       content_length;

        content_length = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                                 "delete '%s' done\n",
                                                 k);

        /*whole Content*/
        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                                 "renew '%s':'%s' done\n",
                                                 k, v);
        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(EC_FALSE == cvendor_filter_header_out_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_range_filter: "
                                                "filter range failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                            "filter range done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_range_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_out_rsp_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_rsp_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0269);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }

    if(CHTTP_NOT_FOUND == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                                "[cngx] 404 keep unchanged => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                            "response status = %u [before]\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    if(CHTTP_MOVED_PERMANENTLY == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md))
    || CHTTP_MOVED_TEMPORARILY == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                                "[cngx] 301/302 keep unchanged => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                                "[cngx] no range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                            "CVENDOR_MD_CONTENT_LENGTH = %ld\n",
                                            CVENDOR_MD_CONTENT_LENGTH(cvendor_md));

    k = (const char *)"Content-Range";
    if(EC_TRUE == chttp_rsp_has_header_key(CVENDOR_MD_CHTTP_RSP(cvendor_md), k))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                                "'%s' exist => response status = %u [after]\n",
                                                k, CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(1 < crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                                "[cngx] multi range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_rsp_status_filter: "
                                            "response status = %u [after]\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_out_cache_control_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_cache_control_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(BIT_FALSE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        const char      *k;
        const char      *v;

        k = (const char *)CHTTP_RSP_X_CACHE_CONTROL;
        v = (const char *)"no-cache";

        if(EC_TRUE == chttp_rsp_has_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_cache_control_filter: "
                                                    "found '%s':'%s' => set orig_no_cache_flag = true\n",
                                                    k, v);
            CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md) = BIT_TRUE;
            return (EC_TRUE);
        }

        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_cache_control_filter: "
                                            "found orig_no_cache_flag is true\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_out_gzip_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_gzip_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(BIT_TRUE == CVENDOR_MD_CNGX_USE_GZIP_FLAG(cvendor_md)
    && BIT_TRUE == CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        k = (const char *)"Content-Encoding";
        v = (const char *)"gzip";

        if(EC_FALSE == chttp_rsp_has_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v))
        {
            /*note: the cache gzip flag will impact on cache_uri generation*/
            CVENDOR_MD_CACHE_USE_GZIP_FLAG(cvendor_md) = BIT_FALSE; /*reset to false*/

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_gzip_filter: "
                                                    "orig not given '%s':'%s' => reset cache gzip flag to false\n",
                                                    k, v);
        }

        k = (const char *)"Content-Length";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_gzip_filter: "
                                                "gzip => del rsp header '%s'\n",
                                                k);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_gzip_filter: "
                                            "gzip filter done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_out_connection_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_connection_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Connection";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_connection_filter: "
                                            "del rsp header '%s' done\n",
                                            k);

    k = (const char *)"Proxy-Connection";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_connection_filter: "
                                            "del rsp header '%s' done\n",
                                            k);

    k = (const char *)"Keep-alive";
    chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_connection_filter: "
                                            "del rsp header '%s' done\n",
                                            k);
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_header_out_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"orig";
    cvendor_filter_header_out_common(cvendor_md_id, k);

    v = (const char *)CNGX_CACHE_STATUS_MISS;
    CVENDOR_MD_CACHE_STATUS(cvendor_md) = v;

    /*Connection*/
    if(EC_FALSE == cvendor_content_ms_header_out_connection_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_filter: "
                                                "connection filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_filter: "
                                            "connection filter done\n");

    /*Content-Length and Content-Range*/
    if(EC_FALSE == cvendor_content_ms_header_out_range_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_filter: "
                                                "range filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_filter: "
                                            "range filter done\n");
    /*gzip*/
    if(EC_FALSE == cvendor_content_ms_header_out_gzip_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_filter: "
                                                "gzip filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_filter: "
                                            "gzip filter done\n");

    if(BIT_FALSE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        if(EC_FALSE == cvendor_content_ms_header_out_rsp_status_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_filter: "
                                                    "status filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_filter: "
                                                "status filter done\n");
    }

    if(EC_FALSE == cvendor_content_ms_header_out_if_modified_since_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_filter: "
                                                "if-modified-since filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_filter: "
                                            "if-modified-since filter done\n");

    if(EC_FALSE == cvendor_content_ms_header_out_if_none_match_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_header_out_filter: "
                                                "if-none-match filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_filter: "
                                            "if-none-match filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_header_out_filter: done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_body_out_filter(const UINT32 cvendor_md_id, const UINT32 seg_no, uint8_t **data, uint32_t *len)
{
    //CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_body_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_set_store(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_STORE                 *chttp_store;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_set_store: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_store = CVENDOR_MD_CHTTP_STORE(cvendor_md);

    ASSERT(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

    /*--- chttp_store settting --- BEG ---*/
    CHTTP_STORE_SEG_MAX_ID(chttp_store) = (uint32_t)CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md);

    if(CVENDOR_ERR_SEG_NO == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        CHTTP_STORE_SEG_ID(chttp_store) = 0;
    }
    else
    {
        CHTTP_STORE_SEG_ID(chttp_store) = (uint32_t)CVENDOR_MD_ABSENT_SEG_NO(cvendor_md);
    }

    CHTTP_STORE_SEG_SIZE(chttp_store)     = CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md);
    CHTTP_STORE_SEG_S_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;
    CHTTP_STORE_SEG_E_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;

    cstring_clone(CVENDOR_MD_CACHE_PATH(cvendor_md), CHTTP_STORE_BASEDIR(chttp_store));

    if(0 == CHTTP_STORE_SEG_ID(chttp_store))
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)       = BIT_FALSE;
        CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store) = BIT_FALSE;
        CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store) = BIT_TRUE;
        CHTTP_STORE_NEED_LOG_FLAG(chttp_store)    = BIT_TRUE;
    }
    else
    {
        /*never reach here*/
        CHTTP_STORE_MERGE_FLAG(chttp_store)       = BIT_FALSE;
        CHTTP_STORE_DIRECT_ORIG_FLAG(chttp_store) = BIT_FALSE;
        CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store) = BIT_FALSE;
        CHTTP_STORE_NEED_LOG_FLAG(chttp_store)    = BIT_TRUE;
    }

    if(BIT_TRUE == CHTTP_STORE_HEADER_ORIG_FLAG(chttp_store))
    {
        CHTTP_STORE_BGN_ORIG_MODI(chttp_store)              = cvendor_md_id;
        CHTTP_STORE_BGN_IMPORT_HEADER_CALLBACK(chttp_store) = (UINT32)cvendor_content_ms_import_header;
        CHTTP_STORE_BGN_SEND_HEADER_CALLBACK(chttp_store)   = (UINT32)cvendor_content_ms_send_header;
        CHTTP_STORE_BGN_SEND_BODY_CALLBACK(chttp_store)     = (UINT32)cvendor_content_ms_send_body;
    }

    if(EC_FALSE == cngx_set_store(r, chttp_store))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_set_store: "
                                                "fetch ngx cfg to chttp_store failed\n");
        return (EC_FALSE);
    }

    CHTTP_STORE_CACHE_CTRL(chttp_store) = CHTTP_STORE_CACHE_BOTH;

    cstring_clone(CVENDOR_MD_CACHED_ETAG(cvendor_md)        , CHTTP_STORE_ETAG(chttp_store));
    cstring_clone(CVENDOR_MD_CACHED_LAST_MODIFED(cvendor_md), CHTTP_STORE_LAST_MODIFIED(chttp_store));

    if(0 < CVENDOR_MD_CONTENT_LENGTH(cvendor_md))
    {
        CHTTP_STORE_CONTENT_LENGTH(chttp_store) = CVENDOR_MD_CONTENT_LENGTH(cvendor_md);
    }

    /*--- chttp_store settting --- END ---*/

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_send_request(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STORE                 *chttp_store;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_send_request: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chttp_req*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_REQ(cvendor_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                    "new chttp_req failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0270);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_REQ(cvendor_md) = chttp_req;
    }
    else
    {
        chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                    "new chttp_rsp failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0271);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);
        chttp_rsp_clean(chttp_rsp);
    }

    /*chttp_store*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STORE(cvendor_md))
    {
        chttp_store = chttp_store_new();
        if(NULL_PTR == chttp_store)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                    "new chttp_store failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0272);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STORE(cvendor_md) = chttp_store;
    }
    else
    {
        chttp_store = CVENDOR_MD_CHTTP_STORE(cvendor_md);
        chttp_store_clean(chttp_store);
    }

    if(EC_FALSE == cvendor_content_ms_set_store(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                "set chttp_store failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0273);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_request: "
                                                "chttp_store is\n");
        chttp_store_print(LOGSTDOUT, chttp_store);
    }

    /*chttp_stat*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STAT(cvendor_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                    "new chttp_stat failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0274);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STAT(cvendor_md)  = chttp_stat;
    }
    else
    {
        chttp_stat = CVENDOR_MD_CHTTP_STAT(cvendor_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                "export headers_in to http req failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0275);
        return (EC_FALSE);
    }

    if(EC_FALSE == cvendor_content_ms_header_in_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                "header_in filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0276);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, chttp_store, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_request: "
                                                "http request failed\n");

        if(0 < CHTTP_STAT_RSP_STATUS(chttp_stat))
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_STAT_RSP_STATUS(chttp_stat), LOC_CVENDOR_0277);
        }
        else
        {
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CVENDOR_0278);
        }

        return (EC_FALSE);
    }
    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_request: "
                                            "send request done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_send_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    cbytes_init(&seg_cbytes);

    if(EC_FALSE == cvendor_get_cache_seg_n(cvendor_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_ms_send_seg_n: "
                                                "get cache seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_NOT_FOUND, LOC_CVENDOR_0279);
        return (EC_FALSE);
    }

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    cvendor_content_ms_body_out_filter(cvendor_md_id, CRANGE_SEG_NO(crange_seg), &data, &len);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG;

    if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_ms_send_seg_n: "
                                                "send body seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_seg_n: "
                                            "send seg %ld [%ld, %ld], %ld bytes\n",
                                            CRANGE_SEG_NO(crange_seg),
                                            CRANGE_SEG_S_OFFSET(crange_seg),
                                            CRANGE_SEG_E_OFFSET(crange_seg),
                                            CBYTES_LEN(&seg_cbytes));

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_import_header(const UINT32 cvendor_md_id, const CHTTP_NODE *chttp_node)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_import_header: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);

    /*clone rsp*/
    CHTTP_RSP_STATUS(chttp_rsp) = (uint32_t)CHTTP_NODE_STATUS_CODE(chttp_node);
    cstrkv_mgr_clone(CHTTP_NODE_HEADER_IN_KVS(chttp_node), CHTTP_RSP_HEADER(chttp_rsp));

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_ms_import_header: cloned chttp_rsp: \n");
        chttp_rsp_print(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}

/*shortcut in http orig procedure*/
EC_BOOL cvendor_content_ms_send_header(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CRANGE_MGR                  *crange_mgr;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_send_header: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    ASSERT(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_header: "
                                                "header had already sent\n");
        return (EC_FALSE);
    }

    /*chunk*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
    || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: "
                                                "orig => chunked\n");

        return (EC_TRUE);
    }

    if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_header: "
                                                "chttp rsp header range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: "
                                            "chttp rsp header range filter done\n");

    /*send header*/
    if(EC_FALSE == cvendor_content_ms_header_out_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_header: "
                                                "header_out filter failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == cvendor_content_cache_save_header(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_header: "
                                                "save header failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: "
                                            "save header done\n");

    cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

    cngx_disable_write_delayed(r);

    crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);

    /*note: only after header_out filter with unchanged range segs, we can parse content lengt to segs*/
    /*parse Content-Length and segs from chttp rsp if cngx req has no 'Range'*/
    if(EC_FALSE == cngx_need_header_only(r)
    && EC_TRUE == crange_mgr_is_empty(crange_mgr))
    {
        if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_header: "
                                                    "get range segs from chttp rsp failed\n");
            return (EC_FALSE);
        }
    }

   dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: "
                                           "crange_mgr size = %ld\n",
                                           crange_mgr_node_num(crange_mgr));

    if(EC_FALSE  == cngx_need_header_only(r)
    && BIT_FALSE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md) /*not chunk*/
    && EC_TRUE   == crange_mgr_is_empty(crange_mgr))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: "
                                                "set header only\n");
        cngx_set_header_only(r);
    }

    if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_ms_send_header: "
                                                "send header failed\n");

        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: "
                                            "send header done\n");

    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) ++;
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: "
                                            "inc absent_seg_no to %ld\n",
                                            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_header: done\n");
    return (EC_TRUE);
}

/*shortcut in http orig procedure*/
EC_BOOL cvendor_content_ms_send_body(const UINT32 cvendor_md_id, const UINT32 seg_no, const UINT8 *data, const UINT32 len)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CRANGE_MGR                  *crange_mgr;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_send_body: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    ASSERT(0 < seg_no);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_TRUE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_body: "
                                                "header was not sent yet\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cngx_need_header_only(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_body: "
                                                "need header only => give up body sending\n");
        return (EC_TRUE);
    }

    if(seg_no != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_ms_send_body: "
                                                "seg_no %ld != absent_seg_no %ld => return\n",
                                                seg_no, CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
        return (EC_TRUE);
    }

    /*send body*/
    crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);
    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_body: "
                                                "[before] crange_mgr is\n");
        crange_mgr_print(LOGSTDOUT, crange_mgr);
    }

    /*send one seg only*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
    && EC_FALSE == crange_mgr_is_empty(crange_mgr))
    {
        CRANGE_NODE                *crange_node;
        CRANGE_SEG                 *crange_seg;

        crange_node = crange_mgr_first_node(crange_mgr);
        crange_seg  = crange_node_first_seg(crange_node);

        if(seg_no != CRANGE_SEG_NO(crange_seg))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "warn:cvendor_content_ms_send_body: "
                                                    "seg_no %ld != crange seg no %ld => return\n",
                                                    seg_no, CRANGE_SEG_NO(crange_seg));

            return (EC_TRUE);
        }

        ASSERT(seg_no == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, (uint32_t)len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_ms_send_body: "
                                                    "send body seg %ld failed\n",
                                                    CRANGE_SEG_NO(crange_seg));

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_body: "
                                                "send seg %ld [%ld, %ld], %ld bytes\n",
                                                CRANGE_SEG_NO(crange_seg),
                                                CRANGE_SEG_S_OFFSET(crange_seg),
                                                CRANGE_SEG_E_OFFSET(crange_seg),
                                                len);

        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) ++;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_body: "
                                                "send recved seg %ld done => sent body %ld bytes\n",
                                                CRANGE_SEG_NO(crange_seg),
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_body: "
                                                    "pop seg %ld\n",
                                                    CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }

        if(do_log(SEC_0175_CVENDOR, 9))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_body: "
                                                    "crange_node %p:\n",
                                                    crange_node);
            crange_node_print(LOGSTDOUT, crange_node);
        }

        /*pop empty crange_node and free it*/
        if(EC_FALSE == crange_node_has_segs(crange_node)
        && crange_node == crange_mgr_first_node(crange_mgr))
        {
            crange_mgr_first_node_pop(crange_mgr);
            crange_node_free(crange_node);
        }
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_body: "
                                                "[after] crange_mgr is\n");
        crange_mgr_print(LOGSTDOUT, crange_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ms_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CRANGE_MGR                  *crange_mgr;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chunk*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
    || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "orig => chunk procedure\n");

        return cvendor_content_chunk_send_response(cvendor_md_id);
    }

    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_response: "
                                                    "chttp rsp header range filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "chttp rsp header range filter done\n");
    }

    /*send header*/
    if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        if(EC_TRUE == cngx_need_send_header(r))
        {
            if(EC_FALSE == cvendor_content_ms_header_out_filter(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_response: "
                                                        "header_out filter failed\n");

                return (EC_FALSE);
            }

            if(EC_FALSE == cvendor_content_cache_save_header(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_response: "
                                                        "save header failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                    "save header done\n");

            cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

            cngx_disable_write_delayed(r);
        }
        else
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                    "header had already sent\n");
        }
    }
    else
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "absent_seg_no = %ld != 0 => ignore header_out filter and sending\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
    }

    crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);

    /*note: only after header_out filter with unchanged range segs, we can parse content lengt to segs*/
    /*parse Content-Length and segs from chttp rsp if cngx req has no 'Range'*/
    if(EC_TRUE == cngx_need_send_header(r)
    && EC_FALSE == cngx_need_header_only(r)
    && EC_TRUE == crange_mgr_is_empty(crange_mgr))
    {
        if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_response: "
                                                    "get range segs from chttp rsp failed\n");
            return (EC_FALSE);
        }
    }

    if(0 == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) && EC_TRUE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "crange_mgr size = %ld\n",
                                                crange_mgr_node_num(crange_mgr));

        if(EC_FALSE  == cngx_need_header_only(r)
        && BIT_FALSE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md) /*not chunk*/
        && EC_TRUE   == crange_mgr_is_empty(crange_mgr))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                    "set header only\n");
            cngx_set_header_only(r);
        }

        if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_ms_send_response: "
                                                    "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "send header done\n");

        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) ++;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "inc absent_seg_no to %ld\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
    }

    if(EC_TRUE == cngx_need_header_only(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "need header only => return\n");
        return (EC_TRUE);
    }
#if 0
    /*send body*/
    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "crange_mgr is\n");
        crange_mgr_print(LOGSTDOUT, crange_mgr);
    }


    /*send one seg only*/
    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
    && EC_FALSE == crange_mgr_is_empty(crange_mgr))
    {
        CRANGE_NODE                *crange_node;
        CRANGE_SEG                 *crange_seg;
        UINT32                      seg_no;

        crange_node = crange_mgr_first_node(crange_mgr);
        crange_seg  = crange_node_first_seg(crange_node);
        seg_no      = CRANGE_SEG_NO(crange_seg);

        if(seg_no != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_ms_send_response: "
                                                    "seg_no %ld != absent_seg_no %ld => return\n",
                                                    seg_no, CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

            return (EC_TRUE);
        }
        ASSERT(seg_no == CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        if(EC_FALSE == cvendor_content_ms_send_seg_n(cvendor_md_id, crange_seg))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_send_response: "
                                                    "get cache seg %ld failed\n",
                                                    seg_no);

            return (EC_FALSE);
        }

        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CVENDOR_ERR_SEG_NO;/*clear*/

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                "send cache seg %ld done => sent body %ld bytes\n",
                                                CRANGE_SEG_NO(crange_seg),
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                    "pop seg %ld\n",
                                                    CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }

        if(do_log(SEC_0175_CVENDOR, 9))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: "
                                                    "crange_node %p:\n",
                                                    crange_node);
            crange_node_print(LOGSTDOUT, crange_node);
        }
    }
#endif
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_send_response: done\n");
    return (EC_TRUE);
}

/*miss header procedure*/
EC_BOOL cvendor_content_ms_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     status; /*response status*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ms_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cvendor_content_ms_send_request(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_procedure: "
                                                "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                            "send request done\n");

    /*check and intercept error pages*/
    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md));
    if(EC_TRUE == cngx_need_intercept_errors(r, status))
    {
        cvendor_set_ngx_rc(cvendor_md_id, status, LOC_CVENDOR_0280);

        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "warn:cvendor_content_ms_procedure: "
                                                "intercept rsp status %u done\n",
                                                status);
        return (EC_FALSE); /*terminate and back to ngx procedure*/
    }

    /*301/302 redirect*/
    if(EC_TRUE == cvendor_is_redirect_rsp(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                                "301/302 => redirect procedure\n");
        /*return cvendor_content_redirect_procedure(cvendor_md_id);*//*TODO*/
        if(EC_FALSE == cvendor_content_redirect_procedure(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_procedure: "
                                                    "301/302 failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                                "301/302 done\n");
    }

    /*specific redirect*/
    if(EC_TRUE == cvendor_is_specific_redirect_rsp(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                                "specific redirect rsp => redirect procedure\n");
        /*return cvendor_content_redirect_procedure(cvendor_md_id);*//*TODO*/
        if(EC_FALSE == cvendor_content_redirect_procedure(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_procedure: "
                                                    "specific redirect rsp failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                                "specific redirect rsp done\n");
    }

    if(EC_FALSE == cngx_script_dir2_filter(r))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_procedure: "
                                                "script dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                            "script dir2 filter done\n");

    if(EC_FALSE == cngx_headers_dir2_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_procedure: "
                                                "headers dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                            "headers dir2 filter done\n");

    if(EC_FALSE == cvendor_content_ms_header_out_cache_control_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_procedure: "
                                                "filter rsp cache-control failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                            "filter rsp cache-control done\n");
#if 0
    if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                                "found orig_no_cache_flag is true => direct send response\n");

        return cvendor_content_direct_send_response(cvendor_md_id);
    }
#endif
    if(EC_FALSE == cvendor_content_ms_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ms_procedure: "
                                                "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ms_procedure: "
                                            "send response done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_preload_parse_header(const UINT32 cvendor_md_id, const CBYTES *header_cbytes)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_preload_parse_header: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(NULL_PTR != CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_parse_header: "
                                                "free old chttp_rsp %p\n",
                                                CVENDOR_MD_CHTTP_RSP(cvendor_md));

        chttp_rsp_free(CVENDOR_MD_CHTTP_RSP(cvendor_md));
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = NULL_PTR;
    }

    CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp_new();
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_parse_header: "
                                                "new chttp_rsp failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0281);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_parse_http_header(header_cbytes, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_parse_header: "
                                                "parse header failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0282);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_parse_header: "
                                                "header '\n%.*s\n' => \n",
                                                (uint32_t)CBYTES_LEN(header_cbytes),
                                                (char *)CBYTES_BUF(header_cbytes));

        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md));
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_preload_header_out_range_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_preload_header_out_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CHTTP_NO_CONTENT == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                                                "status 204 (no content) => done\n");

        return (EC_TRUE);
    }

    while(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        const char *k;
        char       *v;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        k = (const char *)"Content-Length";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR != v)
        {
            content_length = c_str_to_word(v);

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                                                    "parse Content-Length '%s' to %ld\n",
                                                    v,
                                                    content_length);
            break; /*fall through*/
        }

        k = (const char *)"Content-Range";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_header_out_range_filter: "
                                                    "no 'Content-Range'\n");
            /*maybe chunk*/
            return (EC_FALSE);
        }

        if(EC_FALSE == crange_parse_content_range(v, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_header_out_range_filter: "
                                                    "invalid Content-Range '%s'\n",
                                                    v);
            return (EC_FALSE);
        }

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                                                "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                v,
                                                range_start, range_end, content_length);
        break; /*fall through*/
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                                                "del rsp header '%s'\n",
                                                k);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(CVENDOR_MD_CONTENT_LENGTH(cvendor_md));

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k, v);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                                                "renew rsp header '%s':'%s'\n",
                                                k, v);

        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(EC_FALSE == cvendor_filter_header_out_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_header_out_range_filter: "
                                                "filter range failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                                            "filter range done\n");

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                           "CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG          = %s\n",
                           c_bit_bool_str(CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md)));

        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                           "CVENDOR_MD_CNGX_RANGE_EXIST_FLAG              = %s\n",
                           c_bit_bool_str(CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)));

        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                           "CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG = %s\n",
                           c_bit_bool_str(CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md)));
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_range_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_preload_header_out_rsp_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_preload_header_out_rsp_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0283);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_rsp_status_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }

        k = (const char *)"Location";
        if((CHTTP_MOVED_PERMANENTLY == response_status || CHTTP_MOVED_TEMPORARILY == response_status)
        && EC_TRUE == chttp_rsp_has_header_key(CVENDOR_MD_CHTTP_RSP(cvendor_md), k))/*has 'Location'*/
        {
            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_rsp_status_filter: "
                                                    "[cngx] found 301/302 and '%s' => response status = %u [after]\n",
                                                    k,
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }


    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_rsp_status_filter: "
                                                "[cngx] no range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    k = (const char *)"Content-Range";
    if(EC_TRUE == chttp_rsp_has_header_key(CVENDOR_MD_CHTTP_RSP(cvendor_md), k))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_rsp_status_filter: "
                                                "'Content-Range' exist => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(1 < crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_rsp_status_filter: "
                                                "[cngx] multi range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_rsp_status_filter: "
                                            "response status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_preload_header_out_filter(const UINT32 cvendor_md_id)
{
    //CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_preload_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"cache";
    cvendor_filter_header_out_common(cvendor_md_id, k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_filter: "
                                            "common filter done\n");

    /*Content-Length and Content-Range*/
    if(EC_FALSE == cvendor_content_preload_header_out_range_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_header_out_filter: "
                                                "range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_filter: "
                                            "range filter done\n");

    if(EC_FALSE == cvendor_content_preload_header_out_rsp_status_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_header_out_filter: "
                                                "status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_filter: "
                                            "status filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_preload_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_preload_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_send_response: "
                                            "absent_seg_no = %ld\n",
                                            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(EC_FALSE == cvendor_content_preload_header_out_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_send_response: "
                                                    "header_out filter failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0284);
            return (EC_FALSE);
        }

        cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);

        if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_preload_send_response: "
                                                    "send header failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_send_response: "
                                                "send header done\n");

        /*break through*/
    }

    if(EC_TRUE == cngx_need_header_only(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_send_response: "
                                                "need header only => return\n");
        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_send_response: done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_preload_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_preload_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_procedure: "
                                            "absent_seg_no = %ld\n",
                                            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

    /*fetch header from cache*/
    do
    {
        UINT32                       seg_no;
        CBYTES                       seg_cbytes;

        seg_no = 0;

        cbytes_init(&seg_cbytes);

        /*here seg_no is 0*/
        if(EC_FALSE == cvendor_get_cache_seg(cvendor_md_id, seg_no, &seg_cbytes))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_preload_procedure: "
                                                    "fetch seg %ld from cache failed\n",
                                                    seg_no);

            cbytes_clean(&seg_cbytes);

            return (EC_FALSE);
        }

        /*parse header*/
        if(EC_FALSE == cvendor_content_preload_parse_header(cvendor_md_id, &seg_cbytes))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_procedure: "
                                                    "parse seg %ld failed\n",
                                                    seg_no);
            cbytes_clean(&seg_cbytes);

            return (EC_FALSE);
        }
        cbytes_clean(&seg_cbytes);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_procedure: "
                                                "parse seg %ld done\n",
                                                seg_no);

        if(EC_FALSE == cngx_script_dir2_filter(r))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_procedure: "
                                                    "script dir2 filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_procedure: "
                                                "script dir2 filter done\n");

        if(EC_FALSE == cngx_headers_dir2_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_procedure: "
                                                    "headers dir2 filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_procedure: "
                                                "headers dir2 filter done\n");

        /*parse Content-Length and segs from chttp rsp if cngx req has no 'Range'*/
        if(EC_TRUE == crange_mgr_is_empty(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
        {
            if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_procedure: "
                                                        "get range segs from chttp rsp failed\n");

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_REQUEST, LOC_CVENDOR_0285);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_procedure: "
                                                    "get range segs from chttp rsp done\n");
        }

        if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_preload_procedure: "
                                                    "chttp rsp header_in range filter failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_REQUESTEDR_RANGE_NOT_SATISFIABLE, LOC_CVENDOR_0286);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_procedure: "
                                                "chttp rsp header_in range filter done\n");

        /*fall through*/
    }while(0);

    /*send header and body*/
    if(EC_FALSE == cvendor_content_preload_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_preload_procedure: "
                                                "send response failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_preload_procedure: "
                                            "send response done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_redirect_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;
    uint32_t                     redirect_times;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_redirect_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    dbg_log(SEC_0175_CVENDOR, 5)(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: redirect ctrl '%s'\n",
                        c_bit_bool_str(CHTTP_STORE_REDIRECT_CTRL(CVENDOR_MD_CHTTP_STORE(cvendor_md))));

    dbg_log(SEC_0175_CVENDOR, 5)(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: redirect max times '%ld'\n",
                        CHTTP_STORE_REDIRECT_MAX_TIMES(CVENDOR_MD_CHTTP_STORE(cvendor_md)));

    for(redirect_times = 0;
        BIT_TRUE == CHTTP_STORE_REDIRECT_CTRL(CVENDOR_MD_CHTTP_STORE(cvendor_md))
        && CHTTP_STORE_REDIRECT_MAX_TIMES(CVENDOR_MD_CHTTP_STORE(cvendor_md)) > redirect_times
        && EC_TRUE == cvendor_is_redirect_rsp(cvendor_md_id);
        redirect_times ++
    )
    {
        char      *loc;
        char      *host;
        char      *port;
        char      *uri;
        CHTTP_REQ  chttp_req_t;

        loc = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"Location");
        if(NULL_PTR == loc)
        {
            break;
        }
        dbg_log(SEC_0175_CVENDOR, 5)(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: [%u] redirect to '%s'\n", redirect_times, loc);

        host = NULL_PTR;
        port = NULL_PTR;
        uri  = NULL_PTR;

        if(EC_FALSE == c_parse_location(loc, &host, &port, &uri))
        {
            if(NULL_PTR != host)
            {
                safe_free(host, LOC_CVENDOR_0287);
            }
            if(NULL_PTR != port)
            {
                safe_free(port, LOC_CVENDOR_0288);
            }
            if(NULL_PTR != uri)
            {
                safe_free(uri, LOC_CVENDOR_0289);
            }
            break;
        }

        chttp_rsp_clean(CVENDOR_MD_CHTTP_RSP(cvendor_md));
        chttp_stat_clean(CVENDOR_MD_CHTTP_STAT(cvendor_md));
        CHTTP_STAT_REQ_S_MSEC(CVENDOR_MD_CHTTP_STAT(cvendor_md)) = c_get_cur_time_msec();

        chttp_req_init(&chttp_req_t);
        chttp_req_clone(&chttp_req_t, CVENDOR_MD_CHTTP_REQ(cvendor_md));

        if(NULL_PTR != host)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: location '%s' =>  host '%s'\n", loc, host);
            chttp_req_set_ipaddr(&chttp_req_t, host);
            chttp_req_renew_header(&chttp_req_t, (const char *)"Host", host);
            safe_free(host, LOC_CVENDOR_0290);

            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0291);
        }

        if(NULL_PTR != port)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: location '%s' =>  port '%s'\n", loc, port);
            chttp_req_set_port(&chttp_req_t, port);
            safe_free(port, LOC_CVENDOR_0292);
        }

        if(NULL_PTR == uri)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: location '%s' =>  uri is null\n", loc);

            chttp_req_clean(&chttp_req_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: location '%s' =>  uri '%s'\n", loc, uri);

        cstring_clean(CHTTP_REQ_URI(&chttp_req_t));
        chttp_req_set_uri(&chttp_req_t, uri);
        safe_free(uri, LOC_CVENDOR_0293);

        if(do_log(SEC_0175_CVENDOR, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: redirect request is\n");
            chttp_req_print(LOGSTDOUT, &chttp_req_t);

            sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: redirect store is\n");
            chttp_store_print(LOGSTDOUT, CVENDOR_MD_CHTTP_STORE(cvendor_md));
        }

        if(EC_FALSE == chttp_request(&chttp_req_t,
                                     CVENDOR_MD_CHTTP_STORE(cvendor_md),
                                     CVENDOR_MD_CHTTP_RSP(cvendor_md),
                                     CVENDOR_MD_CHTTP_STAT(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_redirect_procedure: redirect request failed\n");
            chttp_req_print(LOGSTDOUT, &chttp_req_t);

            chttp_req_clean(&chttp_req_t);
            return (EC_FALSE);
        }

        if(do_log(SEC_0175_CVENDOR, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_redirect_procedure: redirect response is\n");
            chttp_rsp_print(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md));
        }

        chttp_req_clean(&chttp_req_t);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_in_filter_upstream(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    CHTTP_REQ                   *chttp_req;

    UINT32                       upstream_peer_ipaddr;
    UINT32                       upstream_peer_port;

    uint8_t                     *upstream_name_str;
    uint32_t                     upstream_name_len;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_in_filter_upstream: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cngx_upstream_get_name(r, &upstream_name_str, &upstream_name_len))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_upstream: "
                                                "get upstream name failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_upstream_fetch(r, &upstream_peer_ipaddr, &upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_upstream: "
                                                "upstream '%.*s' fetch server failed\n",
                                                upstream_name_len, upstream_name_str);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_upstream: "
                                            "upstream '%.*s' fetch server %s:%ld\n",
                                            upstream_name_len, upstream_name_str,
                                            c_word_to_ipv4(upstream_peer_ipaddr), upstream_peer_port);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    if(EC_FALSE == chttp_req_set_ipaddr_word(chttp_req, upstream_peer_ipaddr))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_upstream: "
                                                "[conf] set ipaddr '%s' of upsteam '%.*s' to http req failed\n",
                                                c_word_to_ipv4(upstream_peer_ipaddr),
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0294);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_upstream: "
                                            "[conf] set ipaddr '%s' of upsteam '%.*s' to http req done\n",
                                            c_word_to_ipv4(upstream_peer_ipaddr),
                                            upstream_name_len, upstream_name_str);

    if(EC_FALSE == chttp_req_set_port_word(chttp_req, upstream_peer_port))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_upstream: "
                                                "[cngx] set port '%ld' of upsteam '%.*s' to http req failed\n",
                                                upstream_peer_port,
                                                upstream_name_len, upstream_name_str);
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0295);
        return (EC_FALSE);
    }

    chttp_req_set_conn_fail_callback(chttp_req,
                                     (CHTTP_REQ_CONN_FAIL_CALLBACK)cngx_upstream_set_down,
                                     (void *)r);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_upstream: "
                                            "[cngx] set port '%ld' of upsteam '%.*s' to http req done\n",
                                            upstream_peer_port,
                                            upstream_name_len, upstream_name_str);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_in_filter_server(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_in_filter_server: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_ims_header_in_filter_server: "
                                                    "get '%s' failed\n",
                                                    k);
            continue;
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_server: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            c_str_split(v, ":", segs, 2);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, segs[ 0 ]))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "warn:cvendor_content_ims_header_in_filter_server: "
                                                        "[cngx] set host of '%s' failed\n",
                                                        segs[ 0 ]);
                safe_free(v, LOC_CVENDOR_0296);

                continue;
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_server: "
                                                    "[cngx] set host '%s' to http req done\n",
                                                    segs[ 0 ]);
            safe_free(v, LOC_CVENDOR_0297);

            return (EC_TRUE);
        }
    }

    cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0298);
    return (EC_FALSE);
}

EC_BOOL cvendor_content_ims_header_in_filter_host(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_in_filter_host: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config ims host and port*/
    k = (const char *)CNGX_VAR_ORIG_HOST;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_host: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_host: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_host: "
                                                    "[conf] set ipaddr of host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0299);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0300);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_host: "
                                                "[conf] set ipaddr of host '%s' to http req done\n",
                                                v);

        if(EC_FALSE == chttp_req_renew_header(chttp_req, (const char *)"Host", v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_host: "
                                                    "[conf] set host '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0301);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0302);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_host: "
                                                "[conf] set host '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0303);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_in_filter_port(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

    static const char           *tags[ ] = {
        (const char *)"http_host",
        (const char *)"server_name",
        (const char *)"host",
    };

    UINT32                       tag_idx;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_in_filter_port: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_port: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_port: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0304);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_port: "
                                                "[conf] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0305);
        return (EC_TRUE);
    }

    if(EC_TRUE == chttp_req_is_local(chttp_req))
    {
        /*set default ims port*/
        if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[default] set default port '%d' to http req done\n",
                                                    CNGX_ORIG_HTTP_PORT_DEFAULT);
        }
        else
        {
            chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[default] set default port '%d' to https req done\n",
                                                    CNGX_ORIG_HTTPS_PORT_DEFAULT);
        }
        return (EC_TRUE);
    }

    /*when cngx NOT config orig port*/
    for(tag_idx = 0; tag_idx < sizeof(tags)/sizeof(tags[ 0 ]); tag_idx ++)
    {
        k = tags[ tag_idx ];

        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_port: "
                                                    "get '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            char   *segs[ 2 ];

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_port: "
                                                    "[cngx] get var '%s':'%s' done\n",
                                                    k, v);

            if(2 == c_str_split(v, ":", segs, 2))
            {
                /*set port*/
                if(EC_FALSE == chttp_req_set_port(chttp_req, segs[ 1 ]))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_port: "
                                                            "[cngx] set port '%s' to http req failed\n",
                                                            segs[ 1 ]);
                    safe_free(v, LOC_CVENDOR_0306);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_port: "
                                                        "[cngx] set port '%s' to http req done\n",
                                                        segs[ 1 ]);
                safe_free(v, LOC_CVENDOR_0307);

                return (EC_TRUE);
            }

            safe_free(v, LOC_CVENDOR_0308);

            /*continue*/
        }
    }

    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_port: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_port: "
                                                    "[cngx] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0309);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_port: "
                                                "[cngx] set port '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0310);

        return (EC_TRUE);
    }

    /*should never reach here*/

    /*set default ims port*/
    if(EC_FALSE == chttp_req_is_enabled_ssl(chttp_req))
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTP_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                "[default] set default port '%d' to http req done\n",
                                                CNGX_ORIG_HTTP_PORT_DEFAULT);
    }
    else
    {
        chttp_req_set_port_word(chttp_req, CNGX_ORIG_HTTPS_PORT_DEFAULT);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                "[default] set default port '%d' to https req done\n",
                                                CNGX_ORIG_HTTPS_PORT_DEFAULT);
    }
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_in_filter_ipaddr(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_in_filter_ipaddr: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);

    /*when cngx config orig ipaddr*/
    k = (const char *)CNGX_VAR_ORIG_IPADDR;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_ipaddr: "
                                                "get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_ipaddr: "
                                                "[conf] get var '%s':'%s' done\n",
                                                k, v);

        if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter_ipaddr: "
                                                    "[conf] set ipaddr '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0311);
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0312);
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter_ipaddr: "
                                                "[conf] set ipaddr  '%s' to http req done\n",
                                                v);

        safe_free(v, LOC_CVENDOR_0313);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_in_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_in_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*set ssl flag*/
    do
    {
        UINT32  ssl_flag;

        /*when cngx switch ssl on, then orig over https*/
        k = (const char *)CNGX_VAR_SSL_ORIG_SWITCH;
        cngx_get_var_switch(r, k, &ssl_flag, SWITCH_OFF);
        if(SWITCH_OFF == ssl_flag)
        {
            break;
        }

        /*ssl on*/
        chttp_req_enable_ssl(CVENDOR_MD_CHTTP_REQ(cvendor_md));

        /*[optional] cngx configure CA*/
        k = (const char *)CNGX_VAR_SSL_CA;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_ca_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "[conf] set ca '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0314);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0315);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] set ca '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0316);

            /*fall through*/
        }

        /*cngx configure certificate*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_certificate_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "[conf] set certificate '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0317);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0318);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] set certificate '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0319);

            /*fall through*/
        }

        /*cngx configure certificate key*/
        k = (const char *)CNGX_VAR_SSL_CERTIFICATE_KEY;
        if(EC_TRUE == cngx_get_var_str(r, k, &v, NULL_PTR)
        && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_client_private_key_file(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "[conf] set certificate key '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0320);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0321);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] set certificate key '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0322);

            /*fall through*/
        }
    }while(0);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config ims server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_server(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "[conf] set server '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0323);

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CVENDOR_0324);

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] set server '%s' to http req done\n",
                                                    v);

            safe_free(v, LOC_CVENDOR_0325);

            /*set or overwrite ipaddr*/
            if(EC_FALSE == cvendor_content_ims_header_in_filter_ipaddr(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "filter ipaddr failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] filter ipaddr '%s' done\n",
                                                    chttp_req_get_ipaddr_str(CVENDOR_MD_CHTTP_REQ(cvendor_md)));


            /*set or overwrite port*/
            if(EC_FALSE == cvendor_content_ims_header_in_filter_port(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "filter port failed\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] filter port %ld done\n",
                                                    chttp_req_get_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)));

            break; /*ok*/
        }

        /*set host*/
        if(EC_FALSE == cvendor_content_ims_header_in_filter_host(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "filter host failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite ipaddr*/
        if(EC_FALSE == cvendor_content_ims_header_in_filter_ipaddr(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "filter ipaddr failed\n");
            return (EC_FALSE);
        }

        /*set or overwrite port*/
        if(EC_FALSE == cvendor_content_ims_header_in_filter_port(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "filter port failed\n");
            return (EC_FALSE);
        }

        if(EC_TRUE == chttp_req_has_ipaddr(CVENDOR_MD_CHTTP_REQ(cvendor_md))
        && EC_TRUE == chttp_req_has_port(CVENDOR_MD_CHTTP_REQ(cvendor_md)))
        {
            break; /*ok*/
        }

        if(EC_TRUE == cngx_upstream_exist(r))
        {
            /*upstream*/
            if(EC_FALSE == cvendor_content_ims_header_in_filter_upstream(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "filter upstream failed\n");
                return (EC_FALSE);
            }
        }
        else
        {
            /*try best!*/
            if(EC_FALSE == cvendor_content_ims_header_in_filter_server(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "filter server failed\n");
                return (EC_FALSE);
            }
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                "set method '%s' failed\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0326);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CVENDOR_0327);

    /*set http request uri*/
    do
    {
        /*when cngx config orig uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "get var '%s' failed\n",
                                                    k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "get var '%s':'%s' done\n",
                                                    k, v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "[conf] set uri '%s' to http req failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0328);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[conf] set uri '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0329);

            break; /*ok*/
        }

        /*when cngx NOT config orig uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "[cngx] set uri '%s' failed\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0330);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                "[cngx] set uri '%s' to http req done\n",
                                                v);
        safe_free(v, LOC_CVENDOR_0331);

        if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[cngx] get args '%s'\n",
                                                    v);

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), (const char *)"?"))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "[cngx] set '?' failed\n");
                safe_free(v, LOC_CVENDOR_0332);
                return (EC_FALSE);
            }

            if(EC_FALSE == chttp_req_set_uri(CVENDOR_MD_CHTTP_REQ(cvendor_md), v))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                        "[cngx] set args '%s' failed\n",
                                                        v);
                safe_free(v, LOC_CVENDOR_0333);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                    "[cngx] set args '%s' to http req done\n",
                                                    v);
            safe_free(v, LOC_CVENDOR_0334);
        }
    }while(0);

    /*set range: 0-1*/
    if(1)
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        range_start = 0;
        range_end   = 1;
        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                "set header '%s':'%s' done\n",
                                                k, v);
    }

    /*set If-Modified-Since*/
    if(EC_FALSE == cstring_is_empty(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)))
    {
        k = (const char *)"If-Modified-Since";
        v = (char *      )cstring_get_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md));

        if(EC_FALSE == chttp_req_add_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                "set header '%s':'%s' done\n",
                                                k, v);
    }

    /*set If-None-Match*/
    if(EC_FALSE == cstring_is_empty(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)))
    {
        k = (const char *)"If-None-Match";
        v = (char *      )cstring_get_str(CVENDOR_MD_HEADER_ETAG(cvendor_md));

        if(EC_FALSE == chttp_req_add_header(CVENDOR_MD_CHTTP_REQ(cvendor_md), k, v))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_in_filter: "
                                                    "set header '%s':'%s' failed\n",
                                                    k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_in_filter: "
                                                "set header '%s':'%s' done\n",
                                                k, v);
    }
    return cvendor_filter_header_in_common(cvendor_md_id);
}

EC_BOOL cvendor_content_ims_header_out_304_last_modified_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_last_modified_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_last_modified_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    /*update rsp header*/
    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_last_modified_filter: "
                                                "[status %u] ims rsp has no header '%s'\n",
                                                status, k);

        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md_t));

        return (EC_FALSE);
    }

    /*renew Last-Modified in previous rsp*/
    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_last_modified_filter: "
                                            "[status %u] renew rsp header '%s':'%s' done\n",
                                            status, k, v);

    /*renew Last-Modified in cache (seg-0)*/
    if(EC_FALSE == cvendor_renew_header_cache(cvendor_md_id_t, k, v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_last_modified_filter: "
                                                "[status %u] renew cache header '%s':'%s' failed => ignore\n",
                                                status, k, v);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_last_modified_filter: "
                                            "[status %u] renew cache header '%s':'%s' done\n",
                                            status, k, v);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_304_expires_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    ngx_http_request_t          *r;

    const char                  *k;
    const char                  *v;
    uint32_t                     nsec;
    time_t                       t;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_expires_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_expires_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)CNGX_VAR_ORIG_EXPIRES_OVERRIDE_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &nsec, 0))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_expires_filter: "
                                                "[cngx] get var '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(0 == nsec) /*not override*/
    {
        do
        {
            const char      *expires_str_old;
            const char      *expires_str_new;

            k = (const char *)"Expires";

            expires_str_old = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            expires_str_new = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);

            if(NULL_PTR != expires_str_new) /*found new Expires*/
            {
                v = (const char *)expires_str_new;
                break;/*fall through*/
            }

            /*no Expires in new rsp*/
            if(NULL_PTR == expires_str_old)
            {
                return (EC_TRUE);/*terminate*/
            }

            /*remove Expires from old rsp*/
            v = NULL_PTR; /*fall through*/
        }while(0);while(0);

        if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
        {
            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"304-REF-Expires", v);
        }

        /*update old (previous)*/
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

        /*update cache*/
        cvendor_renew_header_cache(cvendor_md_id_t, k, v);

        return (EC_TRUE);
    }

    /*override*/
    if(NULL_PTR != (v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), (const char *)"Date")))
    {
        if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
        {
            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"304-REF-Date", v);
        }
        t = c_parse_http_time((uint8_t *)v, strlen(v));
    }
    else if(NULL_PTR != (v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), (const char *)"Last-Modified")))
    {
        if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
        {
            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"304-REF-Last-Modified", v);
        }
        t = c_parse_http_time((uint8_t *)v, strlen(v));
    }
    else
    {
        t = task_brd_default_get_time();
    }

    k = (const char *)"Expires";
    v = c_http_time(nsec + t);

    /*update old (previous)*/
    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

    /*update cache*/
    cvendor_renew_header_cache(cvendor_md_id_t, k, v);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_304_date_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_date_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_date_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    /*override*/
    k = (const char *)"Date";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);
    if(NULL_PTR != v)
    {
        /*update old (previous)*/
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

        /*update cache*/
        cvendor_renew_header_cache(cvendor_md_id_t, k, v);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_304_age_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_age_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_age_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    /*override*/
    k = (const char *)"Age";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);
    if(NULL_PTR != v)
    {
        /*update old (previous)*/
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

        /*update cache*/
        cvendor_renew_header_cache(cvendor_md_id_t, k, v);
    }
    else
    {
        v = (const char *)"0";
        /*update old (previous)*/
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

        /*update cache*/
        cvendor_renew_header_cache(cvendor_md_id_t, k, v);
    }

    return (EC_TRUE);
}


EC_BOOL cvendor_content_ims_header_out_304_content_range_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_content_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_content_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    /*renew Content-Range in previous rsp*/
    k = (const char *)"Content-Range";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_content_range_filter: "
                                                "[status %u] ims rsp has no header '%s' => done\n",
                                                status, k);
        return (EC_TRUE);
    }

    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_content_range_filter: "
                                            "[status %u] renew rsp header '%s':'%s' done\n",
                                            status, k, v);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_304_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_304_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    if(EC_FALSE == cvendor_content_ims_header_out_304_last_modified_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_filter: "
                                                "[status %u] last modified filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_filter: "
                                            "[status %u] last modified filter done\n",
                                            status);

    if(EC_FALSE == cvendor_content_ims_header_out_304_expires_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_filter: "
                                                "[status %u] expires filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_filter: "
                                            "[status %u] expires filter done\n",
                                            status);

    if(EC_FALSE == cvendor_content_ims_header_out_304_date_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_filter: "
                                                "[status %u] date filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_filter: "
                                            "[status %u] date filter done\n",
                                            status);

    if(EC_FALSE == cvendor_content_ims_header_out_304_age_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_filter: "
                                                "[status %u] age filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_filter: "
                                            "[status %u] age filter done\n",
                                            status);

    if(EC_FALSE == cvendor_content_ims_header_out_304_content_range_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_304_filter: "
                                                "[status %u] content range filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_filter: "
                                            "[status %u] content range filter done\n",
                                            status);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_304_filter: "
                                            "[status %u] filter done\n",
                                            status);
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_not_304_last_modified_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    const char                  *k;
    const char                  *v;

    time_t                       time_if_modified_since;
    time_t                       time_last_modified;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_last_modified_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_last_modified_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    /*update rsp header*/
    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_last_modified_filter: "
                                                "[status %u] ims rsp has no header '%s'\n",
                                                status, k);

        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md_t));

        return (EC_FALSE);
    }

    time_if_modified_since = c_parse_http_time(cstring_get_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)),
                                               (size_t)cstring_get_len(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)));

    time_last_modified = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    if(time_last_modified > time_if_modified_since)/*modified*/
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_last_modified_filter: "
                                                "[status %u] 'Last-Modified':'%s' > 'If-Modified-Since':'%s' "
                                                "=> return false\n",
                                                status,
                                                v,
                                                (char *)cstring_get_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)));

        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md_t));

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_last_modified_filter: "
                                            "[status %u] 'Last-Modified':'%s' <= 'If-Modified-Since':'%s' "
                                            "=> ims works\n",
                                            status,
                                            v,
                                            (char *)cstring_get_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)));

    /*renew Last-Modified in previous rsp*/
    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_last_modified_filter: "
                                            "[status %u] renew rsp header '%s':'%s' done\n",
                                            status, k, v);

    /*renew Last-Modified in cache (seg-0)*/
    if(EC_FALSE == cvendor_renew_header_cache(cvendor_md_id_t, k, v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_last_modified_filter: "
                                                "[status %u] renew cache header '%s':'%s' failed => ignore\n",
                                                status, k, v);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_last_modified_filter: "
                                            "[status %u] renew cache header '%s':'%s' done\n",
                                            status, k, v);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_not_304_etag_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_etag_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_etag_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    /*update rsp header*/
    k = (const char *)"ETag";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_etag_filter: "
                                                "[status %u] ims rsp has no header '%s'\n",
                                                status, k);

        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md_t));

        return (EC_FALSE);
    }

    /*renew Last-Modified in previous rsp*/
    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_etag_filter: "
                                            "[status %u] renew rsp header '%s':'%s' done\n",
                                            status, k, v);

    /*renew Last-Modified in cache (seg-0)*/
    if(EC_FALSE == cvendor_renew_header_cache(cvendor_md_id_t, k, v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_etag_filter: "
                                                "[status %u] renew cache header '%s':'%s' failed => ignore\n",
                                                status, k, v);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_etag_filter: "
                                            "[status %u] renew cache header '%s':'%s' done\n",
                                            status, k, v);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_not_304_expires_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    ngx_http_request_t          *r;

    const char                  *k;
    const char                  *v;
    uint32_t                     nsec;
    time_t                       t;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_expires_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_expires_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)CNGX_VAR_ORIG_EXPIRES_OVERRIDE_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &nsec, 0))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_expires_filter: "
                                             "[cngx] get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(0 == nsec) /*not override*/
    {
        do
        {
            const char      *expires_str_old;
            const char      *expires_str_new;

            k = (const char *)"Expires";

            expires_str_old = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            expires_str_new = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);

            if(NULL_PTR != expires_str_new) /*found new Expires*/
            {
                v = (const char *)expires_str_new;
                break;/*fall through*/
            }

            /*no Expires in new rsp*/
            if(NULL_PTR == expires_str_old)
            {
                return (EC_TRUE);/*terminate*/
            }

            /*remove Expires from old rsp*/
            v = NULL_PTR; /*fall through*/
        }while(0);

        if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
        {
            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"non-304-REF-Expires", v);
        }
        /*update old (previous)*/
        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

        /*update cache*/
        cvendor_renew_header_cache(cvendor_md_id_t, k, v);

        return (EC_TRUE);
    }

    /*override*/
    if(NULL_PTR != (v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), (const char *)"Date")))
    {
        if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
        {
            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"non-304-REF-Date", v);
        }
        t = c_parse_http_time((uint8_t *)v, strlen(v));
    }
    else if(NULL_PTR != (v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), (const char *)"Last-Modified")))
    {
        if(BIT_TRUE == CVENDOR_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cvendor_md))
        {
            chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), (const char *)"non-304-REF-Last-Modified", v);
        }
        t = c_parse_http_time((uint8_t *)v, strlen(v));
    }
    else
    {
        t = task_brd_default_get_time();
    }

    k = (const char *)"Expires";
    v = c_http_time(nsec + t);

    /*update old (previous)*/
    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);

    /*update cache*/
    cvendor_renew_header_cache(cvendor_md_id_t, k, v);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_not_304_content_range_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
    CVENDOR_MD                  *cvendor_md;
    CVENDOR_MD                  *cvendor_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_content_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_content_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md   = CVENDOR_MD_GET(cvendor_md_id);
    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);

    /*renew Content-Range in previous rsp*/
    k = (const char *)"Content-Range";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_content_range_filter: "
                                                "[status %u] ims rsp has no header '%s'\n",
                                                status, k);

        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md_t));

        return (EC_FALSE);
    }

    chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_content_range_filter: "
                                            "[status %u] renew rsp header '%s':'%s' done\n",
                                            status, k, v);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_header_out_not_304_filter(const UINT32 cvendor_md_id, const UINT32 cvendor_md_id_t, uint32_t status)
{
#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_header_out_not_304_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id_t);
        dbg_exit(MD_CVENDOR, cvendor_md_id_t);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    if(EC_FALSE == cvendor_content_ims_header_out_not_304_last_modified_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_filter: "
                                                "[status %u] last modified filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_filter: "
                                            "[status %u] last modified filter done\n",
                                            status);

    if(EC_FALSE == cvendor_content_ims_header_out_not_304_etag_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_filter: "
                                                "[status %u] etag filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_filter: "
                                            "[status %u] etag filter done\n",
                                            status);

    if(EC_FALSE == cvendor_content_ims_header_out_not_304_expires_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_filter: "
                                                "[status %u] expires filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_filter: "
                                            "[status %u] expires filter done\n",
                                            status);

    if(EC_FALSE == cvendor_content_ims_header_out_not_304_content_range_filter(cvendor_md_id, cvendor_md_id_t, status))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_header_out_not_304_filter: "
                                                "[status %u] content range filter done\n",
                                                status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_filter: "
                                            "[status %u] content range filter done\n",
                                            status);

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_header_out_not_304_filter: "
                                            "[status %u] filter done\n",
                                            status);
    return (EC_TRUE);
}

EC_BOOL cvendor_content_ims_send_request(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_send_request: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*chttp_req*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_REQ(cvendor_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_send_request: "
                                                    "new chttp_req failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0335);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_REQ(cvendor_md) = chttp_req;
    }
    else
    {
        chttp_req = CVENDOR_MD_CHTTP_REQ(cvendor_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_send_request: "
                                                    "new chttp_rsp failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0336);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CVENDOR_MD_CHTTP_RSP(cvendor_md);
        chttp_rsp_clean(chttp_rsp);
    }

    /*chttp_stat*/
    if(NULL_PTR == CVENDOR_MD_CHTTP_STAT(cvendor_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_send_request: "
                                                    "new chttp_stat failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0337);
            return (EC_FALSE);
        }
        CVENDOR_MD_CHTTP_STAT(cvendor_md)  = chttp_stat;
    }
    else
    {
        chttp_stat = CVENDOR_MD_CHTTP_STAT(cvendor_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_send_request: "
                                                "export headers_in to http req failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0338);
        return (EC_FALSE);
    }

    if(EC_FALSE == cvendor_content_ims_header_in_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_send_request: "
                                                "header_in filter failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0339);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_ims_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, NULL_PTR, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_send_request: "
                                                "http request failed\n");
        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CVENDOR_0340);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_ims_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_send_request: "
                                            "send request done\n");
    return (EC_TRUE);
}

/*If-Modified-Since procedure*/
EC_BOOL cvendor_content_ims_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    //ngx_int_t                    rc;

    UINT32                       cvendor_md_id_t;
    CVENDOR_MD                  *cvendor_md_t;

    uint32_t                     status;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_ims_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    ASSERT(EC_FALSE == cstring_is_empty(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)));
    ASSERT(EC_FALSE == cstring_is_empty(CVENDOR_MD_HEADER_ETAG(cvendor_md)));

    /*create new module*/
    cvendor_md_id_t = cvendor_start(r);
    if(CMPI_ERROR_MODI == cvendor_md_id_t)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_procedure: "
                                                "start cvendor module failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_procedure: "
                                            "start cvendor module %ld#\n",
                                            cvendor_md_id_t);

    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);
    CVENDOR_MD_DEPTH(cvendor_md_t) = CVENDOR_MD_DEPTH(cvendor_md) + 1;

    /*clone header Expires*/
    cstring_clone(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md_t));
    cstring_clone(CVENDOR_MD_HEADER_ETAG(cvendor_md), CVENDOR_MD_HEADER_ETAG(cvendor_md_t));
    cstring_clone(CVENDOR_MD_CACHE_PATH(cvendor_md), CVENDOR_MD_CACHE_PATH(cvendor_md_t));

    if(EC_FALSE == cvendor_content_ims_send_request(cvendor_md_id_t))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_procedure: "
                                                "send ims request failed\n");
        cvendor_end(cvendor_md_id_t);
        return (EC_FALSE);
    }

    status = CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md_t));
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_procedure: "
                                            "ims rsp status = %u\n",
                                            status);

    if(CHTTP_NOT_MODIFIED == status)
    {
        if(EC_FALSE == cvendor_content_ims_header_out_304_filter(cvendor_md_id, cvendor_md_id_t, status))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_procedure: "
                                                    "[status %u] filter failed\n",
                                                    status);
            cvendor_end(cvendor_md_id_t);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_procedure: "
                                                "[status %u] filter done\n",
                                                status);
        cvendor_end(cvendor_md_id_t);
        return (EC_TRUE);
    }

    /*compare If-Modified-Since and Last-Modified*/
    if(CHTTP_PARTIAL_CONTENT == status || CHTTP_OK == status)
    {
        if(EC_FALSE == cvendor_content_ims_header_out_not_304_filter(cvendor_md_id, cvendor_md_id_t, status))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_ims_procedure: "
                                                    "[status %u] filter failed\n",
                                                    status);
            cvendor_end(cvendor_md_id_t);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_procedure: "
                                                "[status %u] filter done\n",
                                                status);
        cvendor_end(cvendor_md_id_t);

        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "[DEBUG] cvendor_content_ims_procedure: "
                                            "ims rsp status = %u != %u => return false\n",
                                            status, CHTTP_NOT_MODIFIED);
    cvendor_end(cvendor_md_id_t);

    return (EC_FALSE);
}

EC_BOOL cvendor_content_expired_header_out_range_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_header_out_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CHTTP_NO_CONTENT == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                                "status 204 (no content) => done\n");

        return (EC_TRUE);
    }

    do /*renew content-length info*/
    {
        const char *k;
        char       *v;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        k = (const char *)"Content-Range";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                                    "no '%s'\n",
                                                    k);
            break;/*fall through*/
        }

        /*ignore Content-Length*/

        if(EC_FALSE == crange_parse_content_range(v, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_header_out_range_filter: "
                                                    "invalid '%s':'%s'\n",
                                                    k, v);
            return (EC_FALSE);
        }

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                                "parse '%s':'%s' to [%ld, %ld] / %ld\n",
                                                k, v,
                                                range_start, range_end, content_length);
        /*fall through*/
    }while(0);

    if(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        const char *k;
        char       *v;

        UINT32      content_length;

        k = (const char *)"Content-Length";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_header_out_range_filter: "
                                                    "no '%s' => failed\n",
                                                    k);
            return (EC_FALSE);
        }

        content_length = c_str_to_word(v);

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                                "parse '%s':'%s' to %ld\n",
                                                k, v,
                                                content_length);
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                                "del rsp header '%s'\n",
                                                k);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(CVENDOR_MD_CONTENT_LENGTH(cvendor_md));

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k, v);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                                "renew rsp header '%s'\n",
                                                k);

        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(EC_FALSE == cvendor_filter_header_out_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_header_out_range_filter: "
                                                "filter range failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                            "filter range done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_range_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_expired_header_out_filter(const UINT32 cvendor_md_id)
{
    //CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"expired";
    cvendor_filter_header_out_common(cvendor_md_id, k);

    /*Content-Length and Content-Range*/
    if(EC_FALSE == cvendor_content_expired_header_out_range_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_header_out_filter: "
                                                "range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_filter: "
                                            "range filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_expired_body_out_filter(const UINT32 cvendor_md_id)
{
    //CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_body_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_expired_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_send_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    cbytes_init(&seg_cbytes);

    /*force orig*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_seg_n: "
                                                "force orig, expired seg %ld\n",
                                                CRANGE_SEG_NO(crange_seg));

        /*force change to orig procedure*/
        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

        /*check seg num*/
        if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
        && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_send_seg_n: seg no %ld overflow!\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_seg_n: "
                                                "force orig, absent_seg_no %ld => orig\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        return cvendor_content_orig_procedure(cvendor_md_id);
    }

    /*no-expired*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_seg_n: "
                                                "no-expired => direct, expired seg %ld\n",
                                                CRANGE_SEG_NO(crange_seg));

        /*force change to direct procedure*/
        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

        /*check seg num*/
        if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
        && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_send_seg_n: seg no %ld overflow!\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_seg_n: "
                                                "no-expired => repair, absent_seg_no %ld\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        return cvendor_content_repair_procedure(cvendor_md_id);
    }

    if(EC_FALSE == cvendor_get_cache_seg_n(cvendor_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_seg_n: "
                                                "get cache seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);

        if(BIT_TRUE == CNGX_OPTION_ONLY_IF_CACHED(CVENDOR_MD_CNGX_OPTION(cvendor_md)))
        {
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_SERVICE_UNAVAILABLE, LOC_CVENDOR_0341);

            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_send_seg_n: "
                                                    "only-if-cached is true => %u\n",
                                                    NGX_HTTP_SERVICE_UNAVAILABLE);
            return (EC_FALSE);
        }

        /*change to orig procedure*/
        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

        /*check seg num*/
        if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
        && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_send_seg_n: seg no %ld overflow!\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_seg_n: "
                                                "absent_seg_no %ld => orig\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        return cvendor_content_orig_procedure(cvendor_md_id);
    }

    cvendor_content_expired_body_out_filter(cvendor_md_id);

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG;

    if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_seg_n: "
                                                "send body seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_seg_n: "
                                            "send body seg %ld: %ld bytes done\n",
                                            CRANGE_SEG_NO(crange_seg), CBYTES_LEN(&seg_cbytes));

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_expired_send_node(const UINT32 cvendor_md_id, CRANGE_NODE *crange_node)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

    CRANGE_SEG                  *crange_seg;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_send_node: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;
        uint32_t     flags;

        boundary = CRANGE_NODE_BOUNDARY(crange_node);

        cvendor_content_expired_body_out_filter(cvendor_md_id);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_node: "
                                                    "send body boundary failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_node: "
                                                "send body boundary: %ld bytes done\n",
                                                CSTRING_LEN(boundary));

        /*clean boundary which was sent out*/
        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    }

    while(NULL_PTR != (crange_seg = crange_node_first_seg(crange_node)))
    {
        UINT32      seg_no;

        seg_no = CRANGE_SEG_NO(crange_seg); /*range_seg may be free at other place, save it here*/

        if(EC_FALSE == cvendor_content_expired_send_seg_n(cvendor_md_id, crange_seg))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_node: "
                                                    "send expired seg %ld failed\n",
                                                    seg_no);

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_node: "
                                                "send expired seg %ld done => sent body %ld bytes\n",
                                                seg_no,
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_node: "
                                                    "pop seg %ld\n",
                                                    CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_expired_send_end(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_send_end: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_NO_MORE_FLAG
            /*
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            */
            ;

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_end: "
                                                "send body end failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_end: "
                                            "send body end done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_expired_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CRANGE_MGR                  *crange_mgr;
    CRANGE_NODE                 *crange_node;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            /*no-cache*/
            if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                        "expired => direct send response\n");
                return cvendor_content_direct_send_response(cvendor_md_id);
            }

            /*chunk*/
            if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
            || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                        "expired => chunk send response\n");

                return cvendor_content_chunk_send_response(cvendor_md_id);
            }

            if(EC_FALSE == cvendor_content_expired_header_out_filter(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_send_response: "
                                                        "header_out filter failed\n");
                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0342);
                return (EC_FALSE);
            }

            if(do_log(SEC_0175_CVENDOR, 9))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                        "rsp:\n");
                chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md));
            }

            cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

            cngx_disable_write_delayed(r);

            if(EC_TRUE == crange_mgr_is_empty(crange_mgr))
            {
                cngx_set_header_only(r);
            }

            if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_response: "
                                                        "send header failed\n");

                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                    "send header done\n");
        }
    }

    /*send body*/

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                            "before send body, chunk [%s]\n",
                                            BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md) ? "Y" : "N");

    /*send body: chunk*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                "found chunk flag => chunk procedure\n");
        return cvendor_content_chunk_send_response(cvendor_md_id);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                "before send body, crange_mgr:\n");
        crange_mgr_print(LOGSTDOUT, crange_mgr);
    }

    /*send body: ranges*/
    while(NULL_PTR != (crange_node = crange_mgr_first_node(crange_mgr)))
    {
        if(EC_FALSE == cvendor_content_expired_send_node(cvendor_md_id, crange_node))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_response: "
                                                    "send node (%ld:%s, %ld:%s) failed\n",
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                "send node (%ld:%s, %ld:%s) done => sent body %ld bytes\n",
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_mgr_first_node(crange_mgr) == crange_node)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_node: "
                                                    "pop node (%ld:%s, %ld:%s)\n",
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));
            crange_mgr_first_node_pop(crange_mgr);
            crange_node_free(crange_node);
        }
    }

    /*send body: last boundary (for multi-ranges)*/
    if(EC_FALSE == cstring_is_empty(CRANGE_MGR_BOUNDARY(crange_mgr)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;
        uint32_t     flags;

        boundary = CRANGE_MGR_BOUNDARY(crange_mgr);

        cvendor_content_expired_body_out_filter(cvendor_md_id);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_expired_send_response: "
                                                    "send body boundary failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                                "send body boundary: %ld bytes done\n",
                                                CSTRING_LEN(boundary));
    }

    /*send body end*/
    if(EC_FALSE == cvendor_content_expired_send_end(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_expired_send_response: "
                                                "send body end failed\n");

        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                            "send body end done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_send_response: "
                                            "send body done => complete %ld bytes\n",
                                            CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));
    return (EC_TRUE);
}

EC_BOOL cvendor_content_expired_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    ngx_int_t                    rc;

    UINT32                       cvendor_md_id_t;
    CVENDOR_MD                  *cvendor_md_t;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_expired_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    ASSERT(BIT_TRUE == CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md));

    /*check If-Modified-Since*/
    if(EC_FALSE == cstring_is_empty(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md))
    || EC_FALSE == cstring_is_empty(CVENDOR_MD_HEADER_ETAG(cvendor_md)))
    {
        const char      *cache_status;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "expired, found last-modified '%s' or etag '%s' => ims\n",
                                                (char *)cstring_get_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md)),
                                                (char *)cstring_get_str(CVENDOR_MD_HEADER_ETAG(cvendor_md)));

        if(0 && EC_TRUE == cvendor_content_ims_procedure(cvendor_md_id))
        {
            cache_status = (const char *)CNGX_CACHE_STATUS_REFRESH_HIT;
            CVENDOR_MD_CACHE_STATUS(cvendor_md) = cache_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                    "ims succ => cache_status = %s\n",
                                                    cache_status);
            return cvendor_content_expired_send_response(cvendor_md_id);
        }

        if(EC_TRUE == cvendor_content_orig_procedure(cvendor_md_id))
        {
            cache_status = (const char *)CNGX_CACHE_STATUS_REFRESH_HIT;
            CVENDOR_MD_CACHE_STATUS(cvendor_md) = cache_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                    "orig succ => cache_status = %s\n",
                                                    cache_status);
            return cvendor_content_expired_send_response(cvendor_md_id);
        }

        cache_status = (const char *)CNGX_CACHE_STATUS_REFRESH_MISS;
        CVENDOR_MD_CACHE_STATUS(cvendor_md) = cache_status;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "ims fail => cache_status = %s\n",
                                                cache_status);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "ims fail => cache ddir '%s'\n",
                                                (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)));
        ccache_dir_delete(CVENDOR_MD_CACHE_PATH(cvendor_md));
    }
    else
    {
        const char      *cache_status;

        cache_status = (const char *)CNGX_CACHE_STATUS_REFRESH_MISS;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "not found Expires => expired\n");

        CVENDOR_MD_CACHE_STATUS(cvendor_md) = cache_status;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "not found Expires => cache_status = %s\n",
                                                cache_status);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "not found Expires => cache ddir '%s'\n",
                                                (char *)cstring_get_str(CVENDOR_MD_CACHE_PATH(cvendor_md)));
        ccache_dir_delete(CVENDOR_MD_CACHE_PATH(cvendor_md));
    }

    /*create new module*/
    cvendor_md_id_t = cvendor_start(r);
    if(CMPI_ERROR_MODI == cvendor_md_id_t)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "start cvendor module failed\n");
        return (EC_FALSE);
    }

    cvendor_md_t = CVENDOR_MD_GET(cvendor_md_id_t);
    CVENDOR_MD_DEPTH(cvendor_md_t) = CVENDOR_MD_DEPTH(cvendor_md) + 1;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                            "start cvendor module %ld#\n",
                                            cvendor_md_id_t);

    dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                            "expired => orig procedure\n");

    if(EC_FALSE == cvendor_content_handler(cvendor_md_id_t))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                                "error:content handler failed, stop module %ld#\n",
                                                cvendor_md_id_t);

        cvendor_get_ngx_rc(cvendor_md_id_t, &rc, NULL_PTR);
        cvendor_set_ngx_rc(cvendor_md_id, rc, LOC_CVENDOR_0343);

        cvendor_end(cvendor_md_id_t);
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_expired_procedure: "
                                            "[DEBUG] content handler done, stop module %ld#\n",
                                            cvendor_md_id_t);

    cvendor_get_ngx_rc(cvendor_md_id_t, &rc, NULL_PTR);
    cvendor_set_ngx_rc(cvendor_md_id, rc, LOC_CVENDOR_0344);

    cvendor_end(cvendor_md_id_t);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_parse_header(const UINT32 cvendor_md_id, const CBYTES *header_cbytes)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_parse_header: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(NULL_PTR != CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_parse_header: "
                                                "free old chttp_rsp %p\n",
                                                CVENDOR_MD_CHTTP_RSP(cvendor_md));

        chttp_rsp_free(CVENDOR_MD_CHTTP_RSP(cvendor_md));
        CVENDOR_MD_CHTTP_RSP(cvendor_md) = NULL_PTR;
    }

    CVENDOR_MD_CHTTP_RSP(cvendor_md) = chttp_rsp_new();
    if(NULL_PTR == CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_parse_header: "
                                                "new chttp_rsp failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0345);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_parse_http_header(header_cbytes, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_parse_header: "
                                                "parse header failed\n");

        cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0346);
        return (EC_FALSE);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_parse_header: "
                                                "header '\n%.*s\n' => \n",
                                                (uint32_t)CBYTES_LEN(header_cbytes),
                                                (char *)CBYTES_BUF(header_cbytes));

        chttp_rsp_print_plain(LOGSTDOUT, CVENDOR_MD_CHTTP_RSP(cvendor_md));
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_save_header(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_save_header: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(NULL_PTR != CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        const char                  *k;
        char                        *v;

        k = (const char *)"ETag";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_save_header: "
                                                    "[rsp] no '%s'\n",
                                                    k);
        }
        else
        {
            cstring_clean(CVENDOR_MD_CACHED_ETAG(cvendor_md));
            cstring_init(CVENDOR_MD_CACHED_ETAG(cvendor_md), (const UINT8 *)v);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_save_header: "
                                                    "save '%s':'%s'\n",
                                                    k, v);
        }
    }

    if(NULL_PTR != CVENDOR_MD_CHTTP_RSP(cvendor_md))
    {
        const char                  *k;
        char                        *v;

        k = (const char *)"Last-Modified";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_save_header: "
                                                    "[rsp] no '%s'\n",
                                                    k);
        }
        else
        {
            cstring_clean(CVENDOR_MD_CACHED_LAST_MODIFED(cvendor_md));
            cstring_init(CVENDOR_MD_CACHED_LAST_MODIFED(cvendor_md), (const UINT8 *)v);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_save_header: "
                                                    "save '%s':'%s'\n",
                                                    k, v);
        }
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_save_header: "
                                            "done\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_if_modified_since_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    time_t                       ims_1st; /*if-modifed-since in cngx http req*/
    time_t                       ims_2nd; /*last-modified in response (seg-0 in storage)*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_if_modified_since_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"If-Modified-Since";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_if_modified_since_filter: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_modified_since_filter: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    ims_1st = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    safe_free(v, LOC_CVENDOR_0347);

    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_modified_since_filter: "
                                                "[rsp] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    ims_2nd = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    if(ims_1st < ims_2nd)
    {
        if(CHTTP_PARTIAL_CONTENT != CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
        {
            /*set rsp status to 200*/
            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_modified_since_filter: "
                                                    "set rsp status = %u\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        }

        return (EC_TRUE);
    }

    /*set rsp status to 304*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_NOT_MODIFIED;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_modified_since_filter: "
                                            "set rsp status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    crange_mgr_clean(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_modified_since_filter: "
                                            "clean cngx range mgr\n");

    chttp_rsp_only_headers(CVENDOR_MD_CHTTP_RSP(cvendor_md), g_cvendor_304_headers, g_cvendor_304_headers_num);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_modified_since_filter: "
                                            "reset rsp headers\n");

    cngx_set_header_only(r);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_modified_since_filter: "
                                            "set header only\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_if_none_match_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    char                        *etag_src; /*ETag on cache side*/
    char                        *etag_des; /*ETag on client side*/

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_if_none_match_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"If-None-Match";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_if_none_match_filter: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_none_match_filter: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    etag_des = v;

    k = (const char *)"ETag";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_none_match_filter: "
                                                "[rsp] no '%s'\n",
                                                k);
        safe_free(etag_des, LOC_CVENDOR_0348);
        return (EC_TRUE);
    }
    etag_src = v;

    if(0 != STRCASECMP(etag_src, etag_des)) /*not match*/
    {
        /*set rsp status to 200*/
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_none_match_filter: "
                                                "set rsp status = %u\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

        return (EC_TRUE);
    }

    /*set rsp status to 304*/
    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_NOT_MODIFIED;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_none_match_filter: "
                                            "set rsp status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    crange_mgr_clean(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md));

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_none_match_filter: "
                                            "clean cngx range mgr\n");

    chttp_rsp_only_headers(CVENDOR_MD_CHTTP_RSP(cvendor_md), g_cvendor_304_headers, g_cvendor_304_headers_num);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_none_match_filter: "
                                            "reset rsp headers\n");

    cngx_set_header_only(r);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_if_none_match_filter: "
                                            "set header only\n");
    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_range_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_range_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CHTTP_NO_CONTENT == CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                                                "status 204 (no content) => done\n");

        return (EC_TRUE);
    }

    while(BIT_FALSE == CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md))
    {
        const char *k;
        char       *v;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        k = (const char *)"Content-Length";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR != v)
        {
            content_length = c_str_to_word(v);

            CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
            CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                                                    "parse Content-Length '%s' to %ld\n",
                                                    v,
                                                    content_length);
            break; /*fall through*/
        }

        k = (const char *)"Content-Range";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_range_filter: "
                                                    "no 'Content-Range'\n");
            /*maybe chunk*/
            return (EC_FALSE);
        }

        if(EC_FALSE == crange_parse_content_range(v, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_range_filter: "
                                                    "invalid Content-Range '%s'\n",
                                                    v);
            return (EC_FALSE);
        }

        CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md) = BIT_TRUE;
        CVENDOR_MD_CONTENT_LENGTH(cvendor_md)            = content_length;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                                                "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                v,
                                                range_start, range_end, content_length);
        break; /*fall through*/
    }

    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        const char                  *k;
        const char                  *v;

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                                                "del rsp header '%s'\n",
                                                k);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(CVENDOR_MD_CONTENT_LENGTH(cvendor_md));

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md),k, v);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                                                "renew rsp header '%s':'%s'\n",
                                                k, v);

        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(EC_FALSE == cvendor_filter_header_out_range(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_range_filter: "
                                                "filter range failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                                            "filter range done\n");

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                           "CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG          = %s\n",
                           c_bit_bool_str(CVENDOR_MD_CONTENT_LENGTH_EXIST_FLAG(cvendor_md)));

        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                           "CVENDOR_MD_CNGX_RANGE_EXIST_FLAG              = %s\n",
                           c_bit_bool_str(CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md)));

        sys_log(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                           "CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG = %s\n",
                           c_bit_bool_str(CVENDOR_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cvendor_md)));
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_range_filter: "
                                            "done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_rsp_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_rsp_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_NOT_FOUND, LOC_CVENDOR_0349);

            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_rsp_status_filter: "
                                                    "[cngx] found 404 => response status = %u [after]\n",
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }

        k = (const char *)"Location";
        if((CHTTP_MOVED_PERMANENTLY == response_status || CHTTP_MOVED_TEMPORARILY == response_status)
        && EC_TRUE == chttp_rsp_has_header_key(CVENDOR_MD_CHTTP_RSP(cvendor_md), k))/*has 'Location'*/
        {
            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = response_status;
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_rsp_status_filter: "
                                                    "[cngx] found 301/302 and '%s' => response status = %u [after]\n",
                                                    k,
                                                    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
            return (EC_TRUE);
        }
    }


    if(BIT_FALSE == CVENDOR_MD_CNGX_RANGE_EXIST_FLAG(cvendor_md))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_rsp_status_filter: "
                                                "[cngx] no range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    k = (const char *)"Content-Range";
    if(EC_TRUE == chttp_rsp_has_header_key(CVENDOR_MD_CHTTP_RSP(cvendor_md), k))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_rsp_status_filter: "
                                                "'Content-Range' exist => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    if(1 < crange_mgr_node_num(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
    {
        CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_rsp_status_filter: "
                                                "[cngx] multi range => response status = %u [after]\n",
                                                CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)) = CHTTP_OK;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_rsp_status_filter: "
                                            "response status = %u\n",
                                            CHTTP_RSP_STATUS(CVENDOR_MD_CHTTP_RSP(cvendor_md)));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_expires_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;
    const char                  *v;

    time_t                       expires;
    time_t                       curtime;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_expires_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"Expires";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                "not found '%s' => done\n",
                                                k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                            "get '%s':'%s'\n",
                                            k, v);

    curtime = task_brd_default_get_time();

    if(EC_FALSE == c_str_is_digit(v))
    {
        expires = c_parse_http_time((uint8_t *)v, strlen(v));
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                "'%s' => %ld\n",
                                                v, expires);
        if(expires >= curtime)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                    "expires '%ld' >= curtime '%ld'\n",
                                                    expires, curtime);
            /*not expired yet*/
            return (EC_TRUE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                "expires '%ld' < curtime '%ld' => set cache_expired_flag to true\n",
                                                expires, curtime);

        /*REFRESH_HIT or REFRESH_MISS*/
        CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md) = BIT_TRUE;

        k = (const char *)"Last-Modified";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR != v)
        {
            cstring_append_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), (const UINT8 *)v);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                    "found '%s', set '%s' to expires\n",
                                                    k, v);
        }

        k = (const char *)"ETag";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR != v)
        {
            cstring_append_str(CVENDOR_MD_HEADER_ETAG(cvendor_md), (const UINT8 *)v);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                    "found '%s', set '%s' to expires\n",
                                                    k, v);
        }
        return (EC_TRUE);
    }

    expires = (time_t)c_str_to_word(v);
    if(0 == expires)
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                "expires = %ld => set cache_expired_flag to true\n",
                                                expires);

        /*REFRESH_HIT or REFRESH_MISS*/
        CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md) = BIT_TRUE;

        k = (const char *)"Last-Modified";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR != v)
        {
            cstring_append_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), (const UINT8 *)v);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                    "found '%s', set '%s' to expires\n",
                                                    k, v);
        }

        k = (const char *)"ETag";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR != v)
        {
            cstring_append_str(CVENDOR_MD_HEADER_ETAG(cvendor_md), (const UINT8 *)v);
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                    "found '%s', set '%s' to expires\n",
                                                    k, v);
        }

        return (EC_TRUE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                            "expires = %ld\n",
                                            expires);

    k = (const char *)"Date";
    v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
    if(NULL_PTR != v) /*found header 'Date'*/
    {
        time_t                       datetime;

        datetime = c_parse_http_time((uint8_t *)v, strlen(v));

        k = (const char *)"Expires";
        v = (const char *)c_http_time(datetime + expires);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                "'renew %s':'%s' from 'Date' and 'Expires'\n",
                                                k, v);

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    }
    else/*not found header 'Date'*/
    {
        k = (const char *)"Expires";
        v = c_http_time(curtime + expires);

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_expires_filter: "
                                                "'renew %s':'%s'\n",
                                                k, v);

        chttp_rsp_renew_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k, v);
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_age_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_age_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*check http rsp Cache-Control:max-age=xxx*/
    do
    {
        const char                  *k;
        char                        *v;

        uint32_t                     max_age;

        /*max-age*/
        k = (const char *)"Cache-Control";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[rsp] not found '%s' => done\n",
                                                    k);
            break;
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                "[rsp] get '%s':'%s'\n",
                                                k, v);

        /*convert to lowercase*/
        v = c_str_dup(v);
        str_to_lower((UINT8 *)v, strlen(v));

        if(EC_FALSE == c_str_fetch_uint32_t(v, (const char *)"max-age", (const char *)"=", &max_age))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[rsp] cannot fetch number from '%s':'%s'\n",
                                                    k, v);
            safe_free(v, LOC_CVENDOR_0350);
            break;
        }

        if(EC_TRUE == chttp_rsp_is_aged(CVENDOR_MD_CHTTP_RSP(cvendor_md), max_age))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[rsp] '%s':'%s' => aged\n",
                                                    k, v);

            safe_free(v, LOC_CVENDOR_0351);

            CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md) = BIT_TRUE;

            k = (const char *)"Last-Modified";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[rsp] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            k = (const char *)"ETag";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_ETAG(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[rsp] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            return (EC_TRUE);
        }

        safe_free(v, LOC_CVENDOR_0352);

        /*fall through*/
    }while(0);

    /*check http rsp max-age:xxx*/
    do
    {
        const char                  *k;
        const char                  *v;

        uint32_t                     max_age;

        /*max-age*/
        k = (const char *)"max-age";
        v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[rsp] not found '%s' => done\n",
                                                    k);
            break;
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                "[rsp] get '%s':'%s'\n",
                                                k, v);

        max_age = c_str_to_uint32_t(v);

        if(EC_TRUE == chttp_rsp_is_aged(CVENDOR_MD_CHTTP_RSP(cvendor_md), max_age))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[rsp] '%s':'%s' => aged\n",
                                                    k, v);

            CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md) = BIT_TRUE;

            k = (const char *)"Last-Modified";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[rsp] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            k = (const char *)"ETag";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_ETAG(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[rsp] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            return (EC_TRUE);
        }

        /*fall through*/
    }while(0);

    /*check http request Cache-Control:max-age=xxx*/
    do
    {
        const char                  *k;
        char                        *v;

        uint32_t                     max_age;

        k = (const char *)"Cache-Control";
        if(EC_FALSE == cngx_get_header_in(r, k, &v))
        {
             dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_age_filter: "
                                                     "[cngx] fetch header '%s' failed\n",
                                                     k);
             return (EC_FALSE);
        }

        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[cngx] not found '%s'\n",
                                                    k);
            break;
        }

        /*convert to lowercase*/
        str_to_lower((UINT8 *)v, strlen(v));

        if(EC_FALSE == c_str_fetch_uint32_t(v, (const char *)"max-age", (const char *)"=", &max_age))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[cngx] cannot fetch number from '%s':'%s'\n",
                                                    k, v);
            safe_free(v, LOC_CVENDOR_0353);
            break;
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                "[cngx] '%s':'%s' => max_age = %u\n",
                                                k, v, max_age);

        if(EC_TRUE == chttp_rsp_is_aged(CVENDOR_MD_CHTTP_RSP(cvendor_md), max_age))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[cngx] '%s':'%s' => aged, cache => force orig procedure\n",
                                                    k, v);

            safe_free(v, LOC_CVENDOR_0354);

            CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md) = BIT_TRUE;

            k = (const char *)"Last-Modified";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[cngx] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            k = (const char *)"ETag";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_ETAG(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[cngx] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            return (EC_TRUE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                "[cngx] '%s':'%s' => not aged\n",
                                                k, v);

        safe_free(v, LOC_CVENDOR_0355);
        /*fall through*/
    }while(0);

    /*check http request max-age:xxx*/
    do
    {
        const char                  *k;
        char                        *v;

        uint32_t                     max_age;

        k = (const char *)"max-age";
        if(EC_FALSE == cngx_get_header_in(r, k, &v))
        {
             dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_age_filter: "
                                                     "[cngx] fetch header '%s' failed\n",
                                                     k);
             return (EC_FALSE);
        }

        if(NULL_PTR == v)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[cngx] not found '%s'\n",
                                                    k);
            break;
        }

        max_age = c_str_to_uint32_t(v);

        if(EC_TRUE == chttp_rsp_is_aged(CVENDOR_MD_CHTTP_RSP(cvendor_md), max_age))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                    "[cngx] '%s':'%s' => aged, cache => force orig procedure\n",
                                                    k, v);

            safe_free(v, LOC_CVENDOR_0356);

            CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md) = BIT_TRUE;

            k = (const char *)"Last-Modified";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_LAST_MODIFIED(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[cngx] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            k = (const char *)"ETag";
            v = chttp_rsp_get_header(CVENDOR_MD_CHTTP_RSP(cvendor_md), k);
            if(NULL_PTR != v)
            {
                cstring_append_str(CVENDOR_MD_HEADER_ETAG(cvendor_md), (const UINT8 *)v);

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                        "[cngx] found '%s', set '%s' to expires\n",
                                                        k, v);
            }

            return (EC_TRUE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_age_filter: "
                                                "[cngx] '%s':'%s' => not aged\n",
                                                k, v);

        safe_free(v, LOC_CVENDOR_0357);
        /*fall through*/
    }while(0);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_cache_status_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    const char                  *v;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_cache_status_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
    {
        /*miss*/
        v = (const char *)CNGX_CACHE_STATUS_MISS;
        CVENDOR_MD_CACHE_STATUS(cvendor_md) = v;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_cache_status_filter: "
                                                "set cache status to '%s' done\n",
                                                v);
        return (EC_TRUE);
    }

    /*hit*/
    v = (const char *)CNGX_CACHE_STATUS_HIT;
    CVENDOR_MD_CACHE_STATUS(cvendor_md) = v;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_cache_status_filter: "
                                            "set cache status to '%s' done\n",
                                            v);
    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_header_out_filter(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_header_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    //r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    k = (const char *)"cache";
    cvendor_filter_header_out_common(cvendor_md_id, k);
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                            "common filter done\n");

    /*Content-Length and Content-Range*/
    if(EC_FALSE == cvendor_content_cache_header_out_range_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_filter: "
                                                "range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                            "range filter done\n");

    if(EC_FALSE == cvendor_content_cache_header_out_rsp_status_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_filter: "
                                                "status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                            "status filter done\n");

    if(EC_FALSE == cvendor_content_cache_header_out_if_modified_since_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_filter: "
                                                "if-modified-since filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                            "if-modified-since filter done\n");

    if(EC_FALSE == cvendor_content_cache_header_out_if_none_match_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_filter: "
                                                "if-none-match filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                            "if-none-match filter done\n");

    if(BIT_FALSE == CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md))
    {
        if(EC_FALSE == cvendor_content_cache_header_out_expires_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_filter: "
                                                    "expires filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                                "expires filter done\n");
    }

    if(BIT_FALSE == CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md))
    {
        if(EC_FALSE == cvendor_content_cache_header_out_age_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_filter: "
                                                    "age filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                                "age filter done\n");
    }

    if(EC_FALSE == cvendor_content_cache_header_out_cache_status_filter(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_header_out_filter: "
                                                "cache status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: "
                                            "cache status filter done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_body_out_filter(const UINT32 cvendor_md_id, const UINT32 seg_no, uint8_t **data, uint32_t *len)
{
    //CVENDOR_MD                  *cvendor_md;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_body_out_filter: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    //cvendor_md = CVENDOR_MD_GET(cvendor_md_id);
    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_send_seg_n(const UINT32 cvendor_md_id, const CRANGE_SEG *crange_seg)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_send_seg_n: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    cbytes_init(&seg_cbytes);

    /*force orig*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_seg_n: "
                                                "force orig, cache seg %ld\n",
                                                CRANGE_SEG_NO(crange_seg));

        /*force change to orig procedure*/
        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

        /*check seg num*/
        if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
        && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_send_seg_n: "
                                                    "seg no %ld overflow!\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_seg_n: "
                                                "force orig, absent_seg_no %ld => orig\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        return cvendor_content_orig_procedure(cvendor_md_id);
    }

    /*no-cache*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_seg_n: "
                                                "no-cache => direct, cache seg %ld\n",
                                                CRANGE_SEG_NO(crange_seg));

        /*force change to direct procedure*/
        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

        /*check seg num*/
        if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
        && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_send_seg_n: "
                                                    "seg no %ld overflow!\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_seg_n: "
                                                "no-cache => repair, absent_seg_no %ld\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        return cvendor_content_repair_procedure(cvendor_md_id);
    }

    if(EC_FALSE == cvendor_get_cache_seg_n(cvendor_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_seg_n: "
                                                "get cache seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);

        if(BIT_TRUE == CNGX_OPTION_ONLY_IF_CACHED(CVENDOR_MD_CNGX_OPTION(cvendor_md)))
        {
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_SERVICE_UNAVAILABLE, LOC_CVENDOR_0358);

            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_send_seg_n: "
                                                    "only-if-cached is true => %u\n",
                                                    NGX_HTTP_SERVICE_UNAVAILABLE);
            return (EC_FALSE);
        }

        /*change to orig procedure*/
        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = CRANGE_SEG_NO(crange_seg);

        /*check seg num*/
        if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
        && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_send_seg_n: seg no %ld overflow!\n",
                                                    CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_seg_n: "
                                                "absent_seg_no %ld => orig\n",
                                                CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));

        return cvendor_content_orig_procedure(cvendor_md_id);
    }

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG;

    cvendor_content_cache_body_out_filter(cvendor_md_id, CRANGE_SEG_NO(crange_seg), &data, &len);

    if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_seg_n: "
                                                "send body seg %ld failed\n",
                                                CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_seg_n: "
                                            "send body seg %ld: %ld bytes done\n",
                                            CRANGE_SEG_NO(crange_seg), CBYTES_LEN(&seg_cbytes));

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_send_node(const UINT32 cvendor_md_id, CRANGE_NODE *crange_node)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

    CRANGE_SEG                  *crange_seg;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_send_node: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    if(EC_FALSE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;
        uint32_t     flags;

        boundary = CRANGE_NODE_BOUNDARY(crange_node);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_node: "
                                                    "send body boundary failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_node: "
                                                "send body boundary: %ld bytes done\n",
                                                CSTRING_LEN(boundary));

        /*clean boundary which was sent out*/
        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    }

    while(NULL_PTR != (crange_seg = crange_node_first_seg(crange_node)))
    {
        UINT32      seg_no;

        seg_no = CRANGE_SEG_NO(crange_seg); /*range_seg may be free at other place, save it here*/

        if(EC_FALSE == cvendor_content_cache_send_seg_n(cvendor_md_id, crange_seg))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_node: "
                                                    "send cache seg %ld failed\n",
                                                    seg_no);

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_node: "
                                                "send cache seg %ld done => sent body %ld bytes\n",
                                                seg_no,
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_node: "
                                                    "pop seg %ld\n",
                                                    CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_send_end(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;
    uint32_t                     flags;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_send_end: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
            | CNGX_SEND_BODY_NO_MORE_FLAG
            /*
            | CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            */
            ;

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_end: "
                                                "send body end failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_end: "
                                            "send body end done\n");

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_send_response(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;

    ngx_http_request_t          *r;

    CRANGE_MGR                  *crange_mgr;
    CRANGE_NODE                 *crange_node;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_send_response: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    crange_mgr = CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        /*no-cache*/
        if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
        {
            if(BIT_TRUE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_send_response: "
                                                        "preload failed due to no cache\n");
                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                    "no cache => direct send response\n");

            return cvendor_content_direct_send_response(cvendor_md_id);
        }

        /*chunk*/
        if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
        || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                    "cache => chunk send response\n");

            return cvendor_content_chunk_send_response(cvendor_md_id);
        }

        if(EC_FALSE == cvendor_content_cache_header_out_filter(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_send_response: "
                                                    "header_out filter failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CVENDOR_0359);
            return (EC_FALSE);
        }

        if(BIT_TRUE == CVENDOR_MD_CACHE_EXPIRED_FLAG(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                    "cache => expired procedure\n");
            return cvendor_content_expired_procedure(cvendor_md_id);
        }

        if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
        {
            cngx_import_header_out(r, CVENDOR_MD_CHTTP_RSP(cvendor_md));

            cngx_disable_write_delayed(r);

            /*note: for HEAD request, send header only*/
            if(EC_TRUE == cngx_is_head_method(r))
            {
                cngx_set_header_only(r);

                if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
                {
                    dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_response: "
                                                            "[HEAD] send header failed\n");

                    return (EC_FALSE);
                }

                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                        "[HEAD] send header done\n");
                return (EC_TRUE);
            }

            if(EC_FALSE == cngx_need_header_only(r)
            && EC_TRUE == crange_mgr_is_empty(crange_mgr))
            {
                cngx_set_header_only(r);
            }

            if(EC_FALSE == cngx_send_header(r, &(CVENDOR_MD_NGX_RC(cvendor_md))))
            {
                dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_response: "
                                                        "send header failed\n");

                return (EC_FALSE);
            }

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                    "send header done\n");
        }
    }

    if(EC_TRUE == cngx_need_header_only(r))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                "need header only => return\n");
        return (EC_TRUE);
    }

    /*send body*/

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                            "before send body, chunk [%s]\n",
                                            BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md) ? "Y" : "N");

    /*send body: chunk*/
    if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                "found chunk flag => chunk procedure\n");
        return cvendor_content_chunk_send_response(cvendor_md_id);
    }

    if(do_log(SEC_0175_CVENDOR, 9))
    {
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                "before send body, crange_mgr:\n");
        crange_mgr_print(LOGSTDOUT, crange_mgr);
    }

    /*send body: ranges*/
    while(NULL_PTR != (crange_node = crange_mgr_first_node(crange_mgr)))
    {
        if(EC_FALSE == cvendor_content_cache_send_node(cvendor_md_id, crange_node))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_response: "
                                                    "send node (%ld:%s, %ld:%s) failed\n",
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                "send node (%ld:%s, %ld:%s) done => sent body %ld bytes\n",
                                                CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                                CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

        if(crange_mgr_first_node(crange_mgr) == crange_node)
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                    "pop node (%ld:%s, %ld:%s)\n",
                                                    CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                    CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));
            crange_mgr_first_node_pop(crange_mgr);
            crange_node_free(crange_node);
        }
    }

    /*send body: last boundary (for multi-ranges)*/
    if(EC_FALSE == cstring_is_empty(CRANGE_MGR_BOUNDARY(crange_mgr)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;
        uint32_t     flags;

        boundary = CRANGE_MGR_BOUNDARY(crange_mgr);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        flags = CVENDOR_MD_SEND_BODY_PRELOAD_FLAG(cvendor_md)
                | CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG;

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CVENDOR_MD_NGX_RC(cvendor_md))))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_send_response: "
                                                    "send body boundary failed\n");

            return (EC_FALSE);
        }

        CVENDOR_MD_SENT_BODY_SIZE(cvendor_md) += len;

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                                "send body boundary: %ld bytes done\n",
                                                CSTRING_LEN(boundary));
    }

    /*send body end*/
    if(EC_FALSE == cvendor_content_cache_send_end(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_send_response: "
                                                "send body end failed\n");

        return (EC_FALSE);
    }
    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                            "send body end done\n");

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_send_response: "
                                            "send body done => complete %ld bytes\n",
                                            CVENDOR_MD_SENT_BODY_SIZE(cvendor_md));

    return (EC_TRUE);
}

EC_BOOL cvendor_content_cache_procedure(const UINT32 cvendor_md_id)
{
    CVENDOR_MD                  *cvendor_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CVENDOR_DEBUG_SWITCH )
    if ( CVENDOR_MD_ID_CHECK_INVALID(cvendor_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cvendor_content_cache_procedure: cvendor module #0x%lx not started.\n",
                cvendor_md_id);
        dbg_exit(MD_CVENDOR, cvendor_md_id);
    }
#endif/*CVENDOR_DEBUG_SWITCH*/

    cvendor_md = CVENDOR_MD_GET(cvendor_md_id);

    r = CVENDOR_MD_NGX_HTTP_REQ(cvendor_md);

    /*fetch header from cache*/
    do
    {
        UINT32                       seg_no;
        CBYTES                       seg_cbytes;

        seg_no = 0;

        if(BIT_TRUE == CVENDOR_MD_ORIG_FORCE_FLAG(cvendor_md))
        {
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                    "force orig, seg %ld\n",
                                                    seg_no);

            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                    "force orig, absent_seg_no %ld => orig\n",
                                                    seg_no);

            /*change to orig procedure*/
            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = seg_no;

            /*check seg num*/
            if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
            && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: seg no %ld overflow!\n",
                                                        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
                return (EC_FALSE);
            }

            if(EC_FALSE == cvendor_content_orig_procedure(cvendor_md_id))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                        "force orig, orig send absent seg %ld failed\n",
                                                        seg_no);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                    "force orig, orig send absent seg %ld done\n",
                                                    seg_no);

            /*if chunk, send no more data*/
            if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
            || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "force orig, orig should sent out all chunk data\n");
                return (EC_TRUE);
            }

            break;/*fall through*/
        }

        cbytes_init(&seg_cbytes);

        /*here seg_no is 0*/
        if(EC_FALSE == cvendor_get_cache_seg(cvendor_md_id, seg_no, &seg_cbytes))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                    "fetch seg %ld from cache failed\n",
                                                    seg_no);

            cbytes_clean(&seg_cbytes);

            if(BIT_TRUE == CNGX_OPTION_ONLY_IF_CACHED(CVENDOR_MD_CNGX_OPTION(cvendor_md)))
            {
                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_SERVICE_UNAVAILABLE, LOC_CVENDOR_0360);

                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                        "only-if-cached is true => %u\n",
                                                        NGX_HTTP_SERVICE_UNAVAILABLE);
                return (EC_FALSE);
            }

            if(EC_TRUE == cngx_is_head_method(r))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "[HEAD] cache miss => head procedure\n");

                return cvendor_content_head_procedure(cvendor_md_id);
            }

            /*if IMS and switch on, direct procedure*/
            if(EC_TRUE == cngx_has_header_in_key(r, (const char *)"If-Modified-Since")
            && EC_TRUE == cngx_is_direct_ims_switch_on(r))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "[IMS] cache miss => direct procedure\n");

                CVENDOR_MD_CNGX_DIRECT_IMS_FLAG(cvendor_md) = BIT_TRUE;

                return cvendor_content_direct_procedure(cvendor_md_id);
            }

            if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "absent_seg_no %ld => ms\n",
                                                        seg_no);
            }
            else
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "[preload] absent_seg_no %ld => orig\n",
                                                        seg_no);
            }

            /*change to orig procedure*/
            CVENDOR_MD_ABSENT_SEG_NO(cvendor_md) = seg_no;

            /*check seg num*/
            if(CVENDOR_ERR_SEG_NO != CVENDOR_MD_ABSENT_SEG_NO(cvendor_md)
            && CVENDOR_MD_CACHE_SEG_MAX_NUM(cvendor_md) < CVENDOR_MD_ABSENT_SEG_NO(cvendor_md))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: seg no %ld overflow!\n",
                                                        CVENDOR_MD_ABSENT_SEG_NO(cvendor_md));
                return (EC_FALSE);
            }

#if 0
            if(BIT_FALSE == CVENDOR_MD_CNGX_PRELOAD_SWITCH_ON_FLAG(cvendor_md))
            {
                if(EC_FALSE == cvendor_content_ms_procedure(cvendor_md_id))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                            "ms send absent seg %ld failed\n",
                                                            seg_no);
                    return (EC_FALSE);
                }
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "ms send absent seg %ld done\n",
                                                        seg_no);
            }
            else
            {
                /*preload does not need send data to client. so choose orig procedure but not ms procedure*/
                if(EC_FALSE == cvendor_content_orig_procedure(cvendor_md_id))
                {
                    dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                            "[preload] orig send absent seg %ld failed\n",
                                                            seg_no);
                    return (EC_FALSE);
                }
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "[preload] orig send absent seg %ld done\n",
                                                        seg_no);
            }
#endif
            {
                /*preload does not need send data to client. so choose orig procedure but not ms procedure*/
                if(EC_FALSE == cvendor_content_orig_procedure(cvendor_md_id))
                {
                    dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                            "orig send absent seg %ld failed\n",
                                                            seg_no);
                    return (EC_FALSE);
                }
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "orig send absent seg %ld done\n",
                                                        seg_no);
            }

            /*if chunk, send no more data*/
            if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
            || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "orig should sent out all chunk data\n");
                return (EC_TRUE);
            }

            /*if no-cache, send no more data*/
            if(BIT_TRUE == CVENDOR_MD_ORIG_NO_CACHE_FLAG(cvendor_md))
            {
                dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                        "direct should sent out all no-cache data\n");
                return (EC_TRUE);
            }

            break;/*fall through*/
        }

        /*parse header*/
        if(EC_FALSE == cvendor_content_cache_parse_header(cvendor_md_id, &seg_cbytes))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                    "parse seg %ld failed\n",
                                                    seg_no);
            cbytes_clean(&seg_cbytes);

            return (EC_FALSE);
        }
        cbytes_clean(&seg_cbytes);
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                "parse seg %ld done\n",
                                                seg_no);

        if(EC_FALSE == cngx_script_dir2_filter(r))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                    "script dir2 filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                "script dir2 filter done\n");

        if(EC_FALSE == cngx_headers_dir2_filter(r, CVENDOR_MD_CHTTP_RSP(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                    "headers dir2 filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                "headers dir2 filter done\n");

        if(EC_FALSE == cvendor_content_cache_save_header(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                    "save header failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                "save header done\n");

        /*chunk*/
        if(BIT_TRUE == CVENDOR_MD_ORIG_CHUNK_FLAG(cvendor_md)
        || EC_TRUE  == chttp_rsp_is_chunked(CVENDOR_MD_CHTTP_RSP(cvendor_md)))
        {
            dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                    "cache => chunk procedure\n");

            return cvendor_content_chunk_send_response(cvendor_md_id);
        }

        /*parse Content-Length and segs from chttp rsp if cngx req has no 'Range'*/
        if(EC_TRUE == crange_mgr_is_empty(CVENDOR_MD_CNGX_RANGE_MGR(cvendor_md)))
        {
            if(EC_FALSE == cvendor_get_rsp_length_segs(cvendor_md_id, CVENDOR_MD_CACHE_SEG_SIZE(cvendor_md)))
            {
                dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                        "get range segs from chttp rsp failed\n");

                cvendor_set_ngx_rc(cvendor_md_id, NGX_HTTP_BAD_REQUEST, LOC_CVENDOR_0361);
                return (EC_FALSE);
            }
            dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                    "get range segs from chttp rsp done\n");
        }

        if(EC_FALSE == cvendor_filter_rsp_range(cvendor_md_id))
        {
            dbg_log(SEC_0175_CVENDOR, 0)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                    "chttp rsp header_in range filter failed\n");
            cvendor_set_ngx_rc(cvendor_md_id, CHTTP_REQUESTEDR_RANGE_NOT_SATISFIABLE, LOC_CVENDOR_0362);
            return (EC_FALSE);
        }
        dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                                "chttp rsp header_in range filter done\n");

        /*fall through*/
    }while(0);

    /*send header and body*/
    if(EC_FALSE == cvendor_content_cache_send_response(cvendor_md_id))
    {
        dbg_log(SEC_0175_CVENDOR, 1)(LOGSTDOUT, "error:cvendor_content_cache_procedure: "
                                                "send response failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0175_CVENDOR, 9)(LOGSTDOUT, "[DEBUG] cvendor_content_cache_procedure: "
                                            "send response done\n");
    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


