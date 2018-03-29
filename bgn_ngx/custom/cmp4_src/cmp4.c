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

#include "crfsmon.h"

#include "chttp.h"

#include "cngx.h"
#include "cngx_headers.h"

#include "cmp4.h"
#include "cngx_mp4.h"

#include "findex.inc"

#define CMP4_MD_CAPACITY()                  (cbc_md_capacity(MD_CMP4))

#define CMP4_MD_GET(cmp4_md_id)     ((CMP4_MD *)cbc_md_get(MD_CMP4, (cmp4_md_id)))

#define CMP4_MD_ID_CHECK_INVALID(cmp4_md_id)  \
    ((CMPI_ANY_MODI != (cmp4_md_id)) && ((NULL_PTR == CMP4_MD_GET(cmp4_md_id)) || (0 == (CMP4_MD_GET(cmp4_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CMP4 Module
*
**/
void cmp4_print_module_status(const UINT32 cmp4_md_id, LOG *log)
{
    CMP4_MD *cmp4_md;
    UINT32      this_cmp4_md_id;

    for( this_cmp4_md_id = 0; this_cmp4_md_id < CMP4_MD_CAPACITY(); this_cmp4_md_id ++ )
    {
        cmp4_md = CMP4_MD_GET(this_cmp4_md_id);

        if(NULL_PTR != cmp4_md && 0 < cmp4_md->usedcounter )
        {
            sys_log(log,"CMP4 Module # %u : %u refered\n",
                    this_cmp4_md_id,
                    cmp4_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CMP4 module
*
**/
EC_BOOL cmp4_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CMP4 , 32);
}

/**
*
* unregister CMP4 module
*
**/
EC_BOOL cmp4_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CMP4);
}

/**
*
* start CMP4 module
*
**/
UINT32 cmp4_start(ngx_http_request_t *r)
{
    CMP4_MD *cmp4_md;
    UINT32      cmp4_md_id;

    //TASK_BRD   *task_brd;

    uint32_t    cache_seg_size;

    //task_brd = task_brd_default_get();

    cmp4_md_id = cbc_md_new(MD_CMP4, sizeof(CMP4_MD));
    if(CMPI_ERROR_MODI == cmp4_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CMP4 module */
    cmp4_md = (CMP4_MD *)cbc_md_get(MD_CMP4, cmp4_md_id);
    cmp4_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */
    cngx_get_cache_seg_size(r, &cache_seg_size);
    CMP4_MD_CACHE_SEG_SIZE(cmp4_md) = cache_seg_size;
    cstring_init(CMP4_MD_CACHE_PATH(cmp4_md), NULL_PTR);
    CMP4_MD_CACHE_STATUS(cmp4_md) = CNGX_CACHE_STATUS_MISS;/*default*/

    CMP4_MD_NGX_HTTP_REQ(cmp4_md) = r;

    /*TODO: load all variables into module*/
    cngx_option_init(CMP4_MD_CNGX_OPTION(cmp4_md));

    CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md)          = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md)              = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_MULTIPLE_FLAG(cmp4_md)           = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_ADJUSTED_FLAG(cmp4_md)           = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_FILTERED_FLAG(cmp4_md)           = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cmp4_md) = BIT_FALSE;
    CMP4_MD_CACHE_EXPIRED_FLAG(cmp4_md)                 = BIT_FALSE;
    CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md)          = BIT_FALSE;
    CMP4_MD_ORIG_FORCE_FLAG(cmp4_md)                    = BIT_FALSE;
    CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md)                 = BIT_FALSE;

    crange_mgr_init(CMP4_MD_CNGX_RANGE_MGR(cmp4_md));

    CMP4_MD_CONTENT_LENGTH(cmp4_md)   = 0;

    cstring_init(CMP4_MD_HEADER_EXPIRES(cmp4_md), NULL_PTR);

    CMP4_MD_MP4(cmp4_md)              = NULL_PTR;
    CMP4_MD_MP4_START(cmp4_md)        = 0;
    CMP4_MD_MP4_LENGTH(cmp4_md)       = 0;

    CMP4_MD_DEPTH(cmp4_md)            = 0;

    CMP4_MD_CHTTP_REQ(cmp4_md)        = NULL_PTR;
    CMP4_MD_CHTTP_RSP(cmp4_md)        = NULL_PTR;
    CMP4_MD_CHTTP_STORE(cmp4_md)      = NULL_PTR;
    CMP4_MD_CHTTP_STAT(cmp4_md)       = NULL_PTR;

    CMP4_MD_ABSENT_SEG_NO(cmp4_md)    = CMP4_ERR_SEG_NO;
    CMP4_MD_SENT_BODY_SIZE(cmp4_md)   = 0;

    CMP4_MD_NGX_LOC(cmp4_md)          = LOC_NONE_END;
    CMP4_MD_NGX_RC(cmp4_md)           = NGX_OK;

    cmp4_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cmp4_end, cmp4_md_id);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_start: start CMP4 module #%u\n", cmp4_md_id);

    return ( cmp4_md_id );
}

/**
*
* end CMP4 module
*
**/
void cmp4_end(const UINT32 cmp4_md_id)
{
    CMP4_MD *cmp4_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cmp4_end, cmp4_md_id);

    cmp4_md = CMP4_MD_GET(cmp4_md_id);
    if(NULL_PTR == cmp4_md)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_end: cmp4_md_id = %u not exist.\n", cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cmp4_md->usedcounter )
    {
        cmp4_md->usedcounter --;
        return ;
    }

    if ( 0 == cmp4_md->usedcounter )
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_end: cmp4_md_id = %u is not started.\n", cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }

    CMP4_MD_CACHE_SEG_SIZE(cmp4_md) = 0;
    cstring_clean(CMP4_MD_CACHE_PATH(cmp4_md));
    CMP4_MD_CACHE_STATUS(cmp4_md) = NULL_PTR;

    CMP4_MD_NGX_HTTP_REQ(cmp4_md) = NULL_PTR;
    cngx_option_clean(CMP4_MD_CNGX_OPTION(cmp4_md));

    CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md)          = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md)              = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_MULTIPLE_FLAG(cmp4_md)           = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_ADJUSTED_FLAG(cmp4_md)           = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_FILTERED_FLAG(cmp4_md)           = BIT_FALSE;
    CMP4_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cmp4_md) = BIT_FALSE;
    CMP4_MD_CACHE_EXPIRED_FLAG(cmp4_md)                 = BIT_FALSE;
    CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md)          = BIT_FALSE;
    CMP4_MD_ORIG_FORCE_FLAG(cmp4_md)                    = BIT_FALSE;
    CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md)                 = BIT_FALSE;

    crange_mgr_clean(CMP4_MD_CNGX_RANGE_MGR(cmp4_md));

    CMP4_MD_CONTENT_LENGTH(cmp4_md)   = 0;

    cstring_clean(CMP4_MD_HEADER_EXPIRES(cmp4_md));

    CMP4_MD_MP4(cmp4_md)              = NULL_PTR;
    CMP4_MD_MP4_START(cmp4_md)        = 0;
    CMP4_MD_MP4_LENGTH(cmp4_md)       = 0;

    CMP4_MD_DEPTH(cmp4_md)            = 0;

    if(NULL_PTR != CMP4_MD_CHTTP_REQ(cmp4_md))
    {
        chttp_req_free(CMP4_MD_CHTTP_REQ(cmp4_md));
        CMP4_MD_CHTTP_REQ(cmp4_md) = NULL_PTR;
    }

    if(NULL_PTR != CMP4_MD_CHTTP_RSP(cmp4_md))
    {
        chttp_rsp_free(CMP4_MD_CHTTP_RSP(cmp4_md));
        CMP4_MD_CHTTP_RSP(cmp4_md) = NULL_PTR;
    }

    if(NULL_PTR != CMP4_MD_CHTTP_STORE(cmp4_md))
    {
        chttp_store_free(CMP4_MD_CHTTP_STORE(cmp4_md));
        CMP4_MD_CHTTP_STORE(cmp4_md) = NULL_PTR;
    }

    if(NULL_PTR != CMP4_MD_CHTTP_STAT(cmp4_md))
    {
        chttp_stat_free(CMP4_MD_CHTTP_STAT(cmp4_md));
        CMP4_MD_CHTTP_STAT(cmp4_md) = NULL_PTR;
    }

    CMP4_MD_ABSENT_SEG_NO(cmp4_md)    = CMP4_ERR_SEG_NO;
    CMP4_MD_SENT_BODY_SIZE(cmp4_md)   = 0;

    CMP4_MD_NGX_LOC(cmp4_md)          = LOC_NONE_END;
    CMP4_MD_NGX_RC(cmp4_md)           = NGX_OK;

    /* free module */
    cmp4_md->usedcounter = 0;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "cmp4_end: stop CMP4 module #%u\n", cmp4_md_id);
    cbc_md_free(MD_CMP4, cmp4_md_id);

    return ;
}

EC_BOOL cmp4_get_ngx_rc(const UINT32 cmp4_md_id, ngx_int_t *rc, UINT32 *location)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_ngx_rc: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CMP4_MD_NGX_RC(cmp4_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CMP4_MD_NGX_LOC(cmp4_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cmp4_set_ngx_rc(const UINT32 cmp4_md_id, const ngx_int_t rc, const UINT32 location)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_set_ngx_rc: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    /*do not override*/
    if(NGX_OK != CMP4_MD_NGX_RC(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_override_ngx_rc: "
                                             "ignore rc %d due to its %d now\n",
                                             rc, CMP4_MD_NGX_RC(cmp4_md));
        return (EC_TRUE);
    }

    CMP4_MD_NGX_RC(cmp4_md)  = rc;
    CMP4_MD_NGX_LOC(cmp4_md) = location;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_set_ngx_rc: "
                                         "set rc %d\n",
                                         rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cmp4_override_ngx_rc(const UINT32 cmp4_md_id, const ngx_int_t rc, const UINT32 location)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_override_ngx_rc: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(rc == CMP4_MD_NGX_RC(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_override_ngx_rc: "
                                             "ignore same rc %d\n",
                                             rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CMP4_MD_NGX_RC(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_override_ngx_rc: "
                                             "modify rc %d => %d\n",
                                             CMP4_MD_NGX_RC(cmp4_md), rc);
        CMP4_MD_NGX_RC(cmp4_md)  = rc;
        CMP4_MD_NGX_LOC(cmp4_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_override_ngx_rc: "
                                         "set rc %d\n",
                                         rc);

    CMP4_MD_NGX_RC(cmp4_md)  = rc;
    CMP4_MD_NGX_LOC(cmp4_md) = location;

    return (EC_TRUE);
}

EC_BOOL cmp4_set_store_cache_path(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_set_store_cache_path: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(EC_FALSE == cngx_set_store_cache_path(r, CMP4_MD_CACHE_PATH(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_set_store_cache_path: set store_path failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_set_store_cache_path: set store_path '%s'\n",
                    (char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md)));
    return (EC_TRUE);
}

EC_BOOL cmp4_get_cache_seg_uri(const UINT32 cmp4_md_id, const UINT32 seg_no, CSTRING *cache_uri)
{
    CMP4_MD                     *cmp4_md;;

    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_cache_seg_uri: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    //r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(EC_FALSE == cstring_format(cache_uri, "%s/%ld",
                                              (char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md)),
                                              seg_no))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg_uri: "
                                              "gen string '%s/%ld' failed\n",
                                             (char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md)),
                                              seg_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg_uri: cache_uri '%s'\n",
                    (char *)cstring_get_str(cache_uri));

    return (EC_TRUE);
}

/*get whole seg*/
EC_BOOL cmp4_get_cache_seg(const UINT32 cmp4_md_id, const UINT32 seg_no, CBYTES *seg_cbytes)
{
    //CMP4_MD                     *cmp4_md;

    CSTRING                      cache_uri_cstr;
    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;/*http port*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_cache_seg: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    //cmp4_md = CMP4_MD_GET(cmp4_md_id);

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cmp4_get_cache_seg_uri(cmp4_md_id, seg_no, &cache_uri_cstr))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if(EC_FALSE == crfsmon_crfs_store_http_srv_get(task_brd_default_get_crfsmon_id(),
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg: "
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
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg: "
                                             "read '%s' from cache failed\n",
                                             (char *)cstring_get_str(&cache_uri_cstr));

        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg: "
                                         "read '%s', %ld bytes from cache done\n",
                                         (char *)cstring_get_str(&cache_uri_cstr),
                                         cbytes_len(seg_cbytes));

    cstring_clean(&cache_uri_cstr);

    return (EC_TRUE);
}

EC_BOOL cmp4_get_cache_seg_n(const UINT32 cmp4_md_id, const CRANGE_SEG *crange_seg, CBYTES *seg_cbytes)
{
    CMP4_MD                     *cmp4_md;
    ngx_http_request_t          *r;

    CSTRING                      cache_uri_cstr;

    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_cache_seg_n: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cmp4_get_cache_seg_uri(cmp4_md_id, CRANGE_SEG_NO(crange_seg), &cache_uri_cstr))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg_n: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg_n: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if(EC_FALSE == crfsmon_crfs_store_http_srv_get(task_brd_default_get_crfsmon_id(),
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg_n: "
                                             "fetch cache server of '%s' failed\n",
                                             (char *)cstring_get_str(&cache_uri_cstr));
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_file_read(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                    &cache_uri_cstr,
                                    CRANGE_SEG_S_OFFSET(crange_seg),
                                    CRANGE_SEG_E_OFFSET(crange_seg),
                                    seg_cbytes))
    {
        UINT32 cmp4_md_id_t;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg_n: "
                                             "read '%s' from cache failed => try to repair seg %ld\n",
                                             (char *)cstring_get_str(&cache_uri_cstr),
                                             CRANGE_SEG_NO(crange_seg));

        cstring_clean(&cache_uri_cstr);
        cbytes_clean(seg_cbytes);

        cmp4_md_id_t = cmp4_start(r);
        if(CMPI_ERROR_MODI == cmp4_md_id_t)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg_n: "
                                                 "start cmp4 module failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg_n: "
                                             "start cmp4 module %ld#\n",
                                             cmp4_md_id_t);

        if(EC_FALSE == cmp4_content_repair_procedure(cmp4_md_id_t, crange_seg, seg_cbytes))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_seg_n: "
                                                 "repair crange_seg [%ld, %ld, %ld] failed\n",
                                                 CRANGE_SEG_NO(crange_seg),
                                                 CRANGE_SEG_S_OFFSET(crange_seg),
                                                 CRANGE_SEG_E_OFFSET(crange_seg));

            cmp4_end(cmp4_md_id_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg_n: "
                                             "repair crange_seg [%ld, %ld, %ld] done\n",
                                             CRANGE_SEG_NO(crange_seg),
                                             CRANGE_SEG_S_OFFSET(crange_seg),
                                             CRANGE_SEG_E_OFFSET(crange_seg));
        cmp4_end(cmp4_md_id_t);
        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_seg_n: "
                                         "read '%s', %ld bytes from cache done\n",
                                         (char *)cstring_get_str(&cache_uri_cstr),
                                         cbytes_len(seg_cbytes));

    cstring_clean(&cache_uri_cstr);

    return (EC_TRUE);
}

EC_BOOL cmp4_wait_cache_seg_n(const UINT32 cmp4_md_id, const CRANGE_SEG *range_seg, CBYTES *seg_cbytes)
{
    //CMP4_MD                  *cmp4_md;

    CSTRING                      cache_uri_cstr;

    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_wait_cache_seg_n: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    //cmp4_md = CMP4_MD_GET(cmp4_md_id);

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cmp4_get_cache_seg_uri(cmp4_md_id, CRANGE_SEG_NO(range_seg), &cache_uri_cstr))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_wait_cache_seg_n: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_wait_cache_seg_n: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if(EC_FALSE == crfsmon_crfs_store_http_srv_get(task_brd_default_get_crfsmon_id(),
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_wait_cache_seg_n: "
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
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_wait_cache_seg_n: "
                                             "read '%s' from cache failed\n",
                                             (char *)cstring_get_str(&cache_uri_cstr));

        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_wait_cache_seg_n: "
                                         "read '%s', %ld bytes from cache done\n",
                                         (char *)cstring_get_str(&cache_uri_cstr),
                                         cbytes_len(seg_cbytes));

    cstring_clean(&cache_uri_cstr);

    return (EC_TRUE);
}

EC_BOOL cmp4_get_cache_file_e(const UINT32 cmp4_md_id, size_t size, off_t offset, uint8_t *buf, ssize_t *rsize)
{
    CMP4_MD                     *cmp4_md;

    //ngx_http_request_t          *r;

    UINT32                       seg_size;

    UINT32                       seg_no_start;
    UINT32                       seg_no_end;

    UINT32                       seg_no;

    UINT32                       pos;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_cache_file_e: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    seg_size = CMP4_MD_CACHE_SEG_SIZE(cmp4_md);

    seg_no_start = (((UINT32)(offset           )) / seg_size) + 1;
    seg_no_end   = (((UINT32)(offset + size - 1)) / seg_size) + 1;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_file_e: "
                                         "offset %ld, size %d => seg start %ld, seg end %ld\n",
                                         (UINT32)offset, size,
                                         seg_no_start, seg_no_end);

    for(seg_no = seg_no_start, pos = 0; seg_no <= seg_no_end; seg_no ++)
    {
        UINT32                       seg_s_offset;
        UINT32                       seg_e_offset;

        CRANGE_SEG                   crange_seg;
        CBYTES                       seg_cbytes;

        seg_s_offset = ((seg_no == seg_no_start) ? (((UINT32)(offset           )) % seg_size): 0);
        seg_e_offset = ((seg_no == seg_no_end  ) ? (((UINT32)(offset + size - 1)) % seg_size): seg_size - 1);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_file_e: "
                                             "read seg [%ld, %ld, %ld]\n",
                                             seg_no, seg_s_offset, seg_e_offset);

        crange_seg_init(&crange_seg);

        CRANGE_SEG_SIZE(&crange_seg)     = seg_size;
        CRANGE_SEG_NO(&crange_seg)       = seg_no;
        CRANGE_SEG_S_OFFSET(&crange_seg) = seg_s_offset;
        CRANGE_SEG_E_OFFSET(&crange_seg) = seg_e_offset;

        cbytes_init(&seg_cbytes);

        if(EC_FALSE == cmp4_get_cache_seg_n(cmp4_md_id, &crange_seg, &seg_cbytes))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_file_e: "
                                                 "get cache seg %ld failed\n",
                                                 CRANGE_SEG_NO(&crange_seg));

            cbytes_clean(&seg_cbytes);
            //cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_NOT_FOUND, LOC_CMP4_0001);

            if(BIT_TRUE == CNGX_OPTION_ONLY_IF_CACHED(CMP4_MD_CNGX_OPTION(cmp4_md)))
            {
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_SERVICE_UNAVAILABLE, LOC_CMP4_0002);

                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_cache_file_e: "
                                                     "only-if-cached is true => %u\n",
                                                     NGX_HTTP_SERVICE_UNAVAILABLE);
                return (EC_FALSE);
            }
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_cache_file_e: "
                                             "read seg [%ld, %ld, %ld] from cache done: %ld bytes\n",
                                             CRANGE_SEG_NO(&crange_seg),
                                             CRANGE_SEG_S_OFFSET(&crange_seg),
                                             CRANGE_SEG_E_OFFSET(&crange_seg),
                                             CBYTES_LEN(&seg_cbytes));

        /*copy*/
        BCOPY(CBYTES_BUF(&seg_cbytes), buf + pos, CBYTES_LEN(&seg_cbytes));
        pos += CBYTES_LEN(&seg_cbytes);
        (*rsize) += (ssize_t)CBYTES_LEN(&seg_cbytes);

        cbytes_clean(&seg_cbytes);
    }

    return (EC_TRUE);
}

/*callback for cngx_mp4*/
STATIC_CAST static ngx_int_t __cmp4_get_cache_file_e(const UINT32 cmp4_md_id, size_t size, off_t offset, uint8_t *buf, ssize_t *rsize)
{
    if(EC_FALSE == cmp4_get_cache_file_e(cmp4_md_id, size, offset, buf, rsize))
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

void cmp4_print_ngx_buf(LOG *log, const UINT32 level, const ngx_buf_t *buf)
{
    if(NULL_PTR == buf)
    {
        sys_print(log, "cmp4_print_ngx_buf: (null)\n");
        return;
    }

    sys_print(log, "cmp4_print_ngx_buf: [%4d] %p:\n",
                   level, buf);

    sys_print(log, "cmp4_print_ngx_buf: pos %p, last %p\n", buf->pos, buf->last);
    sys_print(log, "cmp4_print_ngx_buf: file_pos %ld, file_last %ld\n", (UINT32)buf->file_pos, (UINT32)buf->file_last);
    sys_print(log, "cmp4_print_ngx_buf: start %p, end %p\n", buf->start, buf->end);
    sys_print(log, "cmp4_print_ngx_buf: tag %p\n", buf->tag);
    sys_print(log, "cmp4_print_ngx_buf: file %p, shadow %p\n", buf->file, buf->shadow);
    sys_print(log, "cmp4_print_ngx_buf: temporary    : %s\n", c_bit_bool_str(buf->temporary));
    sys_print(log, "cmp4_print_ngx_buf: memory       : %s\n", c_bit_bool_str(buf->memory));
    sys_print(log, "cmp4_print_ngx_buf: mmap         : %s\n", c_bit_bool_str(buf->mmap));
    sys_print(log, "cmp4_print_ngx_buf: recycled     : %s\n", c_bit_bool_str(buf->recycled));
    sys_print(log, "cmp4_print_ngx_buf: in_file      : %s\n", c_bit_bool_str(buf->in_file));
    sys_print(log, "cmp4_print_ngx_buf: flush        : %s\n", c_bit_bool_str(buf->flush));
    sys_print(log, "cmp4_print_ngx_buf: sync         : %s\n", c_bit_bool_str(buf->sync));
    sys_print(log, "cmp4_print_ngx_buf: last_buf     : %s\n", c_bit_bool_str(buf->last_buf));
    sys_print(log, "cmp4_print_ngx_buf: last_in_chain: %s\n", c_bit_bool_str(buf->last_in_chain));
    sys_print(log, "cmp4_print_ngx_buf: last_shadow  : %s\n", c_bit_bool_str(buf->last_shadow));
    sys_print(log, "cmp4_print_ngx_buf: temp_file    : %s\n", c_bit_bool_str(buf->temp_file));
    sys_print(log, "cmp4_print_ngx_buf: num: %d\n", buf->num);

    return;
}
void cmp4_print_ngx_chain(LOG *log, const UINT32 level, const ngx_chain_t *chain)
{
    if(NULL_PTR == chain)
    {
        sys_print(log, "cmp4_print_ngx_chain: ---- END ----\n");
        return;
    }
    sys_print(log, "cmp4_print_ngx_chain: [%4d] %p: buf %p, next %p\n",
                   level, chain,
                   chain->buf, chain->next);

    cmp4_print_ngx_buf(log, level, chain->buf);

    cmp4_print_ngx_chain(log, level + 1, chain->next);
    return;
}

void cmp4_stub_ngx_buf(const UINT32 level, ngx_buf_t *buf)
{
    if(NULL_PTR == buf)
    {
        return;
    }

    buf->num = level;

    return;
}
void cmp4_stub_ngx_chain(const UINT32 level, ngx_chain_t *chain)
{
    if(NULL_PTR == chain)
    {
        return;
    }

    cmp4_stub_ngx_buf(level, chain->buf);
    return cmp4_stub_ngx_chain(level + 1, chain->next);
}

EC_BOOL cmp4_get_meta(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;
    cngx_mp4_file_t             *mp4;

    const char                  *k;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_meta: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    ASSERT(NULL_PTR == CMP4_MD_MP4(cmp4_md));

    if(EC_FALSE == cngx_discard_req_body(r))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_meta: "
                                             "discard req body failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0002);
        return (EC_FALSE);
    }

    r->root_tested = !r->error_page;
    r->allow_ranges = 1;
    r->single_range = 1;

    mp4 = ngx_pcalloc(r->pool, sizeof(cngx_mp4_file_t));
    if (mp4 == NULL)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_meta: "
                                             "cngx alloc cngx_mp4_file_t failed\n");

        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0003);
        return (EC_FALSE);
    }

    mp4->handler         = (cngx_mp4_file_read_handler)__cmp4_get_cache_file_e;
    mp4->modi            = (ngx_uint_t)cmp4_md_id;
    mp4->start           = (ngx_uint_t)CMP4_MD_MP4_START(cmp4_md);
    mp4->length          = (ngx_uint_t)CMP4_MD_MP4_LENGTH(cmp4_md);
    mp4->end             = (off_t     )CMP4_MD_CONTENT_LENGTH(cmp4_md);
    mp4->request         = r;

    mp4->file.name.len   = (size_t  )cstring_get_len(CMP4_MD_CACHE_PATH(cmp4_md));
    mp4->file.name.data  = (u_char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md));
    mp4->file.log        = r->connection->log;

    k = (const char *)CNGX_VAR_MP4_BUFFER_SIZE;
    cngx_get_var_size(r, k, (ssize_t *)&(mp4->buffer_size)    , (ssize_t)CMP4_BUFFER_SIZE_DEFAULT);

    k = (const char *)CNGX_VAR_MP4_MAX_BUFFER_SIZE;
    cngx_get_var_size(r, k, (ssize_t *)&(mp4->max_buffer_size), (ssize_t)CMP4_MAX_BUFFER_SIZE_DEFAULT);

    switch (cngx_mp4_process(mp4)) {

    case NGX_DECLINED:
        if (mp4->buffer) {
            ngx_pfree(r->pool, mp4->buffer);
        }

        ngx_pfree(r->pool, mp4);
        mp4 = NULL;

        break;

    case NGX_OK:
        //r->headers_out.content_length_n = mp4->content_length;

        if(do_log(SEC_0147_CMP4, 9))
        {
            UINT32 level;

            level = 0;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_meta: "
                                                 "after process, stub mp4 out\n");
            cmp4_stub_ngx_chain(level, mp4->out);

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_meta: "
                                                 "after process, mp4 out is\n");
            cmp4_print_ngx_chain(LOGSTDOUT, level, mp4->out);
        }
        break;

    default: /* NGX_ERROR */
        if (mp4->buffer) {
            ngx_pfree(r->pool, mp4->buffer);
        }

        ngx_pfree(r->pool, mp4);

        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_meta: "
                                             "cngx process mp4 failed\n");

        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0004);
        return (EC_FALSE);
    }

    CMP4_MD_MP4(cmp4_md)    = mp4;

    return (EC_TRUE);
}

EC_BOOL cmp4_has_mp4_out(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    cngx_mp4_file_t             *mp4;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_has_mp4_out: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(NULL_PTR == CMP4_MD_MP4(cmp4_md))
    {
        return (EC_FALSE);
    }

    mp4 = CMP4_MD_MP4(cmp4_md);
    if(NULL_PTR == mp4->out)
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_get_req_range_segs(const UINT32 cmp4_md_id, const UINT32 seg_size)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_req_range_segs: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(NULL_PTR != r->headers_in.range)
    {
        char       *range_str;

        range_str = (char *)(r->headers_in.range->value.data);
        ASSERT('\0' == range_str[ r->headers_in.range->value.len ]);

        if(EC_FALSE == crange_parse_range(range_str, CMP4_MD_CNGX_RANGE_MGR(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_req_range_segs: "
                                                 "invalid Range '%s'\n",
                                                 range_str);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_req_range_segs: "
                                             "parse Range '%s' done\n",
                                             range_str);

        CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md)  = BIT_TRUE;

        if(1 < crange_mgr_node_num(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)))
        {
            CMP4_MD_CNGX_RANGE_MULTIPLE_FLAG(cmp4_md) = BIT_TRUE;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_req_range_segs: "
                                                 "set range_multiple_flag to %s\n",
                                                 c_bit_bool_str(CMP4_MD_CNGX_RANGE_MULTIPLE_FLAG(cmp4_md)));
        }

        if(EC_TRUE == crange_mgr_is_start_zero_endless(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)))
        {
            CMP4_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cmp4_md) = BIT_TRUE;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_req_range_segs: "
                                                 "set CMP4_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG flag to %s\n",
                                                 c_bit_bool_str(CMP4_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cmp4_md)));
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_req_range_segs: "
                                             "split Range '%s' into segs done\n",
                                             range_str);
        return (EC_TRUE);
    }

    CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md)  = BIT_FALSE;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_req_range_segs: no Range\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_get_rsp_length_segs(const UINT32 cmp4_md_id, const UINT32 seg_size)
{
    CMP4_MD                     *cmp4_md;;

    UINT32                       content_length;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_get_rsp_length_segs: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    ASSERT(EC_TRUE == crange_mgr_is_empty(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)));

    content_length = CMP4_MD_CONTENT_LENGTH(cmp4_md);

    if(0 == content_length)
    {
        char     *content_range_str;

        content_range_str = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"Content-Range");
        if(NULL_PTR != content_range_str)
        {
            UINT32      range_start;
            UINT32      range_end;

            if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_rsp_length_segs: "
                                                     "invalid Content-Range '%s'\n",
                                                     content_range_str);
                return (EC_FALSE);
            }

            CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
            CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_rsp_length_segs: "
                                                 "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                 content_range_str,
                                                 range_start, range_end, content_length);
        }
    }

    if(0 < content_length)
    {
        if(EC_FALSE == crange_mgr_add_range(CMP4_MD_CNGX_RANGE_MGR(cmp4_md),
                                            0,
                                            content_length - 1,
                                            seg_size))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_get_rsp_length_segs: "
                                                 "split content_length '%ld' into segs failed\n",
                                                 content_length);

            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_get_rsp_length_segs: "
                                             "split content_length '%ld' into segs done\n",
                                             content_length);
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_is_redirect_rsp(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;
    uint32_t                     status;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_is_redirect_rsp: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    status = CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md));
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_is_redirect_rsp: rsp status %u\n",
                        status);

    if(CHTTP_MOVED_PERMANENTLY == status
    || CHTTP_MOVED_TEMPORARILY == status)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmp4_is_specific_redirect_rsp(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    uint32_t                     status;
    uint32_t                     des_status;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_is_specific_redirect_rsp: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    status = CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md));
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_is_specific_redirect_rsp: "
                                         "rsp status %u\n",
                                         status);

    if(EC_FALSE == cngx_get_redirect_specific(r, status, &des_status, &v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_is_specific_redirect_rsp: "
                                             "got fialed\n");
        return (EC_FALSE);
    }

    if(CHTTP_STATUS_NONE == des_status || NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_is_specific_redirect_rsp: "
                                             "no spec => ignore\n");
        return (EC_FALSE);
    }

    if(CHTTP_MOVED_PERMANENTLY != des_status
    && CHTTP_MOVED_TEMPORARILY != des_status)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_is_specific_redirect_rsp: "
                                             "unsupported status %u\n",
                                             des_status);

        if(NULL_PTR != v)
        {
            safe_free(v, LOC_CMP4_0005);
        }
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_is_specific_redirect_rsp: "
                                             "status %u, but redirect url is null\n",
                                             des_status);
        return (EC_FALSE);
    }

    /*set to rsp header*/
    CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = des_status;
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_is_specific_redirect_rsp: "
                                         "modify rsp status: %u => %u\n",
                                         status, des_status);
    k = (const char *)"Location";
    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_is_specific_redirect_rsp: "
                                         "add rsp header '%s':'%s'\n",
                                         k, v);

    safe_free(v, LOC_CMP4_0006);
    return (EC_TRUE);
}

EC_BOOL cmp4_filter_rsp_range(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    UINT32                       content_length;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_rsp_range: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    content_length = CMP4_MD_CONTENT_LENGTH(cmp4_md);

    if(0 == content_length)
    {
        char                       *content_range_str;

        UINT32                      range_start;
        UINT32                      range_end;

        content_range_str = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"Content-Range");
        if(NULL_PTR == content_range_str)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_rsp_range: "
                                                 "no 'Content-Range' => failed\n");

            /*we always send rang request to orig. if no 'Content-Range', failed*/
            return (EC_FALSE);
        }

        if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_rsp_range: "
                                                 "invalid Content-Range '%s'\n",
                                                 content_range_str);
            return (EC_FALSE);
        }

        CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
        CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_rsp_range: "
                                             "Content-Range '%s' => content_length %ld\n",
                                             content_range_str,
                                             CMP4_MD_CONTENT_LENGTH(cmp4_md));
    }

    /*adjust range_start and range_end*/
    if(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md)
    && BIT_FALSE == CMP4_MD_CNGX_RANGE_ADJUSTED_FLAG(cmp4_md))
    {
        if(EC_FALSE == crange_mgr_adjust(CMP4_MD_CNGX_RANGE_MGR(cmp4_md),
                                         CMP4_MD_CONTENT_LENGTH(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_rsp_range: "
                                                 "crange_mgr_adjust with content_length %ld failed\n",
                                                 CMP4_MD_CONTENT_LENGTH(cmp4_md));
            return (EC_FALSE);
        }

        if(do_log(SEC_0147_CMP4, 9))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_rsp_range: "
                                                 "after crange_nodes adjust with content_length %ld =>\n",
                                                 CMP4_MD_CONTENT_LENGTH(cmp4_md));
            crange_mgr_print_no_seg(LOGSTDOUT, CMP4_MD_CNGX_RANGE_MGR(cmp4_md));
        }

        if(0 == crange_mgr_node_num(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_rsp_range: "
                                                 "crange_mgr_adjust with content_length %ld and no valid returned\n",
                                                 CMP4_MD_CONTENT_LENGTH(cmp4_md));

            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_RANGE_NOT_SATISFIABLE, LOC_CMP4_0007);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_rsp_range: "
                                             "crange_nodes adjust with content_length %ld done\n",
                                             CMP4_MD_CONTENT_LENGTH(cmp4_md));

        if(EC_FALSE == crange_mgr_split(CMP4_MD_CNGX_RANGE_MGR(cmp4_md), CMP4_MD_CACHE_SEG_SIZE(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_rsp_range: "
                                                 "crange_nodes split with seg size %ld failed\n",
                                                 CMP4_MD_CACHE_SEG_SIZE(cmp4_md));
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_rsp_range: "
                                             "crange_nodes split with seg size %ld done\n",
                                             CMP4_MD_CACHE_SEG_SIZE(cmp4_md));

        CMP4_MD_CNGX_RANGE_ADJUSTED_FLAG(cmp4_md) = BIT_TRUE;
    }

    if(BIT_FALSE == CMP4_MD_CNGX_RANGE_FILTERED_FLAG(cmp4_md))
    {
        /*filter req range_segs*/
        if(0 == CMP4_MD_MP4_START(cmp4_md) || NULL_PTR == CMP4_MD_MP4(cmp4_md))
        {
            crange_mgr_filter(CMP4_MD_CNGX_RANGE_MGR(cmp4_md), 0, content_length - 1, content_length);
            CMP4_MD_CNGX_RANGE_FILTERED_FLAG(cmp4_md) = BIT_TRUE;
        }
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_rsp_range: done\n");

    return (EC_TRUE);
}

/*for chttp_req to orig server*/
EC_BOOL cmp4_filter_header_in_common(const UINT32 cmp4_md_id, CHTTP_REQ *chttp_req)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_header_in_common: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*del debug headers*/
    chttp_req_del_header(chttp_req, (const char *)CNGX_BGN_MOD_DBG_SWITCH_HDR);
    chttp_req_del_header(chttp_req, (const char *)CNGX_BGN_MOD_DBG_NAME_HDR);
    chttp_req_del_header(chttp_req, (const char *)CNGX_BGN_MOD_DBG_ERROR_HDR);
    chttp_req_del_header(chttp_req, (const char *)CNGX_BGN_MOD_DBG_INFO_HDR);
    chttp_req_del_header(chttp_req, (const char *)CNGX_BGN_MOD_DBG_EXPIRE_HDR);

    if(EC_FALSE == cngx_headers_dir1_filter(r, CMP4_MD_CHTTP_REQ(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_in_common: "
                                             "dir1 filter failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*before sending response to client*/
EC_BOOL cmp4_filter_header_out_common(const UINT32 cmp4_md_id, const char *procedure)
{
    CMP4_MD                     *cmp4_md;;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_header_out_common: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    cmp4_filter_header_out_cache_control(cmp4_md_id);

    if(NULL_PTR != procedure && 0 == STRCASECMP(procedure, (const char *)"cache"))
    {
        const char                  *v;

        v = (const char *)CNGX_CACHE_STATUS_HIT;
        CMP4_MD_CACHE_STATUS(cmp4_md) = v;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_common: "
                                             "set cache status to '%s' done\n",
                                             v);
    }

    if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
    {
        const char                  *k;
        const char                  *v;

        k = (const char *)CNGX_BGN_MOD_DBG_X_PROCEDURE_TAG;
        v = (const char *)procedure;
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_common: "
                                                 "add header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }

        k = (const char *)CNGX_BGN_MOD_DBG_X_PROXY_TAG;
        v = (const char *)CNGX_BGN_MOD_DBG_X_PROXY_VAL;
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_common: "
                                                 "add header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }

        k = (const char *)CNGX_BGN_MOD_DBG_X_MODULE_TAG;
        v = (const char *)CMP4_MODULE_NAME;
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_common: "
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
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_common: "
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
        v = (const char *)chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
        if(NULL_PTR == v)
        {
            break; /*terminate*/
        }
        age = c_str_to_uint32_t(v);

        k = (const char *)"Date";
        v = (const char *)chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
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
        v = (const char *)c_http_time(age + (cur_time - date_time));
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_common: "
                                                 "renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
    }while(0);    

    cngx_set_cache_status(r, CMP4_MD_CACHE_STATUS(cmp4_md));

    /*merge header function. it should be optional function*/
    if(EC_TRUE == cngx_is_merge_header_switch_on(r))
    {
        chttp_rsp_merge_header(CMP4_MD_CHTTP_RSP(cmp4_md));
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_common: "
                                             "merge header done\n");
    }

    if(EC_FALSE == cngx_headers_dir3_filter(r, CMP4_MD_CHTTP_RSP(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_common: "
                                             "dir3 filter failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cmp4_filter_header_out_cache_control(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_header_out_cache_control: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(BIT_FALSE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
    {
        const char                  *k;

        k = (const char *)CHTTP_RSP_X_CACHE_CONTROL;

        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_filter_header_out_no_range(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    CRANGE_MGR                  *crange_mgr;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_header_out_no_range: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    crange_mgr = CMP4_MD_CNGX_RANGE_MGR(cmp4_md);

    ASSERT(BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md));

    /*if not need mp4 header*/
    if(0 == CMP4_MD_MP4_START(cmp4_md))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];
        UINT32                       content_length; /*rsp body length*/

        content_length = CMP4_MD_CONTENT_LENGTH(cmp4_md);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_no_range: "
                                                 "[start == 0] renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_no_range: "
                                             "[start == 0] renew header %s:%s done\n",
                                             k, v);

        snprintf(header_buf, sizeof(header_buf), "bytes %ld-%ld/%ld",
                                                 (UINT32)0,
                                                 content_length - 1,
                                                 content_length);
        k = (const char *)"Content-Range";
        v = (const char *)header_buf;
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_no_range: "
                                                 "[start == 0] renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_no_range: "
                                             "[start == 0] renew header %s:%s done\n",
                                             k, v);
    }
    else
    {
        const char                  *k;
        const char                  *v;

        cngx_mp4_file_t             *mp4;
        UINT32                       content_length; /*mp4 parsed content length*/

        mp4 = CMP4_MD_MP4(cmp4_md);
        if(NULL_PTR == mp4)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_no_range: "
                                                 "[start > 0] mp4 is null\n");
            return (EC_FALSE);
        }

        content_length = mp4->content_length;

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_no_range: "
                                                 "[start > 0] renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_no_range: "
                                             "[start > 0] renew header %s:%s done\n",
                                             k, v);

        k = (const char *)"Content-Range";
        if(EC_FALSE == chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_no_range: "
                                                 "[start > 0] del header %s failed\n",
                                                 k);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_no_range: "
                                             "[start > 0] del header %s done\n",
                                             k);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_no_range: "
                                         "done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_filter_header_out_single_range(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    CRANGE_MGR                  *crange_mgr;
    CRANGE_NODE                 *crange_node;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_header_out_single_range: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    crange_mgr = CMP4_MD_CNGX_RANGE_MGR(cmp4_md);

    ASSERT(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md));
    ASSERT(1 == crange_mgr_node_num(crange_mgr));

    /*only one crange_node*/
    crange_node = crange_mgr_first_node(crange_mgr);

    if(0 != CRANGE_NODE_RANGE_START(crange_node)
     || CRANGE_NODE_RANGE_END(crange_node) + 1 != CMP4_MD_CONTENT_LENGTH(cmp4_md))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];
        UINT32                       content_length; /*rsp body length*/

        content_length = (CRANGE_NODE_RANGE_END(crange_node) + 1 - CRANGE_NODE_RANGE_START(crange_node));

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_single_range: "
                                                 "renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "renew header %s:%s done\n",
                                             k, v);

        snprintf(header_buf, sizeof(header_buf), "bytes %ld-%ld/%ld",
                             CRANGE_NODE_RANGE_START(crange_node),
                             CRANGE_NODE_RANGE_END(crange_node),
                             CMP4_MD_CONTENT_LENGTH(cmp4_md));
        k = (const char *)"Content-Range";
        v = (const char *)header_buf;
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_single_range: "
                                                 "renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "renew header %s:%s done\n",
                                             k, v);
    }
    else if(BIT_TRUE == CMP4_MD_CNGX_RANGE_START_ZERO_ENDLESS_FLAG(cmp4_md))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];
        UINT32                       content_length; /*rsp body length*/

        content_length = CMP4_MD_CONTENT_LENGTH(cmp4_md);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_single_range: "
                                                 "[ZERO_ENDLESS] renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "[ZERO_ENDLESS] renew header %s:%s done\n",
                                             k, v);

        snprintf(header_buf, sizeof(header_buf), "bytes %ld-%ld/%ld",
                             (UINT32)0,
                             content_length - 1,
                             content_length);
        k = (const char *)"Content-Range";
        v = (const char *)header_buf;
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_single_range: "
                                                 "[ZERO_ENDLESS] renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "[ZERO_ENDLESS] renew header %s:%s done\n",
                                             k, v);
    }
    else if(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];
        UINT32                       content_length; /*whole content length*/

        content_length = CMP4_MD_CONTENT_LENGTH(cmp4_md);

        snprintf(header_buf, sizeof(header_buf), "bytes %ld-%ld/%ld",
                             (UINT32)0,
                             content_length - 1,
                             content_length);

        k = (const char *)"Content-Range";
        v = (const char *)header_buf;
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "error:cmp4_filter_header_out_single_range: "
                                                 "[cngx] range exist and covers whole content => renew header '%s':'%s' failed\n",
                                                 k, v);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "[cngx] range exist and covers whole content => renew header '%s':'%s' done\n",
                                             k, v);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "error:cmp4_filter_header_out_single_range: "
                                                 "[cngx] range exist and covers whole content => renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "[cngx] range exist and covers whole content => renew header %s:%s done\n",
                                             k, v);
    }
    else
    {
        const char                  *k;
        const char                  *v;

        UINT32                       content_length; /*whole content length*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "range covers whole content => delete header '%s' done\n",
                                             k);

        content_length = CMP4_MD_CONTENT_LENGTH(cmp4_md);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(content_length);
        if(EC_FALSE == chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_single_range: "
                                                 "renew header %s:%s failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                             "renew header %s:%s done\n",
                                             k, v);

    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_single_range: "
                                         "done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_filter_header_out_multi_range(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    CRANGE_MGR                  *crange_mgr;
    CLIST                       *crange_nodes;
    CLIST_DATA                  *clist_data;

    UINT32                       content_length;
    UINT32                       body_size;
    char                        *boundary;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_header_out_multi_range: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    ASSERT(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md));
    ASSERT(1 < crange_mgr_node_num(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)));

    content_length = CMP4_MD_CONTENT_LENGTH(cmp4_md);
    boundary       = c_get_day_time_str();

    crange_mgr     = CMP4_MD_CNGX_RANGE_MGR(cmp4_md);
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
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_multi_range:"
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
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_filter_header_out_multi_range:"
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
        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
    }

    if(1)
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];

        char                        *boundary_str;
        uint32_t                     boundary_len;

        crange_mgr_get_naked_boundary(CMP4_MD_CNGX_RANGE_MGR(cmp4_md), &boundary_str, &boundary_len);

        snprintf(header_buf, sizeof(header_buf), "multipart/byteranges; boundary=%.*s",
                                                 boundary_len, boundary_str);

        k = (const char *)"Content-Type";
        v = (const char *)header_buf;
        chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_multi_range: "
                                             "renew '%s' done\n",
                                             k, v);
    }

    if(1)
    {
        const char                  *k;
        const char                  *v;

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(body_size);

        chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_multi_range: "
                                             "renew header %s:%s done\n",
                                             k, v);
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_filter_header_out_range(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    UINT32                       crange_node_num;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_filter_header_out_range: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    crange_node_num = crange_mgr_node_num(CMP4_MD_CNGX_RANGE_MGR(cmp4_md));
    ASSERT(0 < crange_node_num);

    if(1 == crange_node_num)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_range: "
                                             "crange_node_num = %ld => single range\n",
                                             crange_node_num);
        return cmp4_filter_header_out_single_range(cmp4_md_id);
    }

    if(1 < crange_node_num)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_range: "
                                             "crange_node_num = %ld => multi range\n",
                                             crange_node_num);
        return cmp4_filter_header_out_multi_range(cmp4_md_id);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_filter_header_out_range: "
                                         "no range, done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_renew_header_cache(const UINT32 cmp4_md_id, const char *k, const char *v)
{
    CMP4_MD                     *cmp4_md;;

    //ngx_http_request_t          *r;

    UINT32                       seg_no;
    CSTRING                      cache_uri_cstr;

    UINT32                       cache_srv_tcid;
    UINT32                       cache_srv_ipaddr;
    UINT32                       cache_srv_port;

    CSTRKV_MGR                  *cstrkv_mgr;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_renew_header_cache: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    seg_no = 0;

    cstring_init(&cache_uri_cstr, NULL_PTR);
    if(EC_FALSE == cmp4_get_cache_seg_uri(cmp4_md_id, seg_no, &cache_uri_cstr))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_renew_header_cache: get cache_uri failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_renew_header_cache: gen cache_uri '%s' done\n",
                    (char *)cstring_get_str(&cache_uri_cstr));

    if(EC_FALSE == crfsmon_crfs_store_http_srv_get(task_brd_default_get_crfsmon_id(),
                                                &cache_uri_cstr,
                                                &cache_srv_tcid, &cache_srv_ipaddr, &cache_srv_port))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_renew_header_cache: "
                                             "fetch cache server of '%s' failed\n",
                                             (char *)cstring_get_str(&cache_uri_cstr));
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    cstrkv_mgr = cstrkv_mgr_new();
    if(NULL_PTR == cstrkv_mgr)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_renew_header_cache: "
                                             "new cstrkv_mgr failed\n");
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == cstrkv_mgr_add_kv_str(cstrkv_mgr, k, v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_renew_header_cache: "
                                             "add '%s':'%s' to cstrkv_mgr failed\n",
                                             k, v);
        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_renew_headers(cache_srv_tcid, cache_srv_ipaddr, cache_srv_port,
                                         &cache_uri_cstr, cstrkv_mgr, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_renew_header_cache: "
                                             "renew header '%s':'%s' in cache '%s' failed\n",
                                             k, v,
                                             (char *)cstring_get_str(&cache_uri_cstr));

        cstrkv_mgr_free(cstrkv_mgr);
        cstring_clean(&cache_uri_cstr);
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_renew_header_cache: "
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
EC_BOOL cmp4_content_handler(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_handler: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: enter\n");

    cngx_headers_dir0_filter(r);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: "
                                         "dir0 filter done\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md) = BIT_TRUE;
    }

    cngx_option_set_cacheable_method(r, CMP4_MD_CNGX_OPTION(cmp4_md));
    if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
    {
        if(BIT_TRUE == CNGX_OPTION_CACHEABLE_METHOD(CMP4_MD_CNGX_OPTION(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: method cachable\n");
            cngx_set_header_out_kv(r, (const char *)CNGX_BGN_MOD_DBG_X_METHOD_CACHABLE_TAG, (const char *)"yes");
        }
        else
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: method not cachable\n");
            cngx_set_header_out_kv(r, (const char *)CNGX_BGN_MOD_DBG_X_METHOD_CACHABLE_TAG, (const char *)"no");
        }
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        CHTTP_REQ       chttp_req_t;

        chttp_req_init(&chttp_req_t);

        cngx_export_header_in(r, &chttp_req_t);

        cngx_export_method(r, &chttp_req_t);
        cngx_export_uri(r, &chttp_req_t);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: cngx req is -------------------------\n");
        chttp_req_print_plain(LOGSTDOUT, &chttp_req_t);
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: -------------------------------------\n");

        chttp_req_clean(&chttp_req_t);
    }

    if(EC_TRUE == cngx_is_direct_orig_switch_on(r))
    {
        /*direct procedure to orig server*/
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: "
                                             "direct orig switch on => direct procedure\n");
        return cmp4_content_direct_procedure(cmp4_md_id);
    }

    cngx_option_set_only_if_cached(r, CMP4_MD_CNGX_OPTION(cmp4_md));
    if(BIT_FALSE == CNGX_OPTION_ONLY_IF_CACHED(CMP4_MD_CNGX_OPTION(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: "
                                             "only_if_cached is false\n");

        if(BIT_FALSE == CNGX_OPTION_CACHEABLE_METHOD(CMP4_MD_CNGX_OPTION(cmp4_md)))
        {
            /*direct procedure to orig server*/
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: "
                                                 "not cacheable method => direct procedure\n");
            return cmp4_content_direct_procedure(cmp4_md_id);
        }
    }
    /*else fall through*/

    /*parse 'Range' in cngx http req header*/
    if(EC_FALSE == cmp4_get_req_range_segs(cmp4_md_id, CMP4_MD_CACHE_SEG_SIZE(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_handler: "
                                             "get Range from cngx req failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_BAD_REQUEST, LOC_CMP4_0008);
        return (EC_FALSE);
    }

    /*ppriority: Range > start arg*/
    if(BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        if(EC_TRUE == cngx_get_mp4_start_length(r, &(CMP4_MD_MP4_START(cmp4_md)),
                                                    &(CMP4_MD_MP4_LENGTH(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: "
                                                 "[cngx] parsed mp4 start %ld, length %ld\n",
                                                 CMP4_MD_MP4_START(cmp4_md),
                                                 CMP4_MD_MP4_LENGTH(cmp4_md));
        }
    }

    if(EC_FALSE == cmp4_set_store_cache_path(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_handler: set store_path failed\n");

        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0009);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_handler: set store_path '%s'\n",
                    (char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md)));

    if(EC_TRUE == cngx_is_force_orig_switch_on(r))
    {
        CMP4_MD_ORIG_FORCE_FLAG(cmp4_md) = BIT_TRUE;
    }
    else
    {
        CMP4_MD_ORIG_FORCE_FLAG(cmp4_md) = BIT_FALSE;
    }

    return cmp4_content_cache_procedure(cmp4_md_id);
}

EC_BOOL cmp4_content_direct_header_in_filter_port(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_header_in_filter_port: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*when cngx config direct port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter_port: "
                                             "get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter_port: "
                                             "[conf] get var '%s':'%s' done\n",
                                             k, v);
        if(EC_FALSE == chttp_req_set_port(CMP4_MD_CHTTP_REQ(cmp4_md), v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter_port: "
                                                 "[conf] set port '%s' to http req failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0010);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter_port: "
                                             "[conf] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0011);
        return (EC_TRUE);
    }

    /*when cngx NOT config direct port*/
    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter_port: "
                                             "[cngx] get '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter_port: "
                                             "[cngx] get var '%s':'%s' done\n",
                                             k, v);

        if(EC_FALSE == chttp_req_set_port(CMP4_MD_CHTTP_REQ(cmp4_md), v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter_port: "
                                                 "[cngx] set port to http req failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0012);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter_port: "
                                             "[cngx] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0013);

        return (EC_TRUE);
    }

    /*set default direct port*/
    chttp_req_set_port_word(CMP4_MD_CHTTP_REQ(cmp4_md), CNGX_ORIG_PORT_DEFAULT);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                         "[default] set default port '%d' to http req done\n",
                                         CNGX_ORIG_PORT_DEFAULT);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_header_in_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_header_in_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config direct server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_server(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "[conf] set server '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0014);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            safe_free(v, LOC_CMP4_0015);

            break; /*ok*/
        }

        /*when cngx config direct host and port*/
        k = (const char *)CNGX_VAR_ORIG_HOST;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "[conf] set host '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0016);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[conf] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0017);

            /*set port*/
            if(EC_FALSE == cmp4_content_direct_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*now cngx NOT config direct server and NOT config direct (host, port)*/

        /*try http_host*/
        k = (const char *)"http_host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0018);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0019);

            /*set port*/
            if(EC_FALSE == cmp4_content_direct_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try server_name*/
        k = (const char *)"server_name";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0020);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0021);

            /*set port*/
            if(EC_FALSE == cmp4_content_direct_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try host*/
        k = (const char *)"host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "[cngx] set ipaddr of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0022);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0023);

            /*set port*/
            if(EC_FALSE == cmp4_content_direct_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                             "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(CMP4_MD_CHTTP_REQ(cmp4_md), v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                             "set method '%s' failed\n",
                                             v);
        safe_free(v, LOC_CMP4_0024);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CMP4_0025);

    /*set http request uri*/
    do
    {
        /*when cngx config direct uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_uri(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                     "[conf] set uri '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0026);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                                 "[conf] set uri '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0027);

            break; /*ok*/
        }

        /*when cngx NOT config direct uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(CMP4_MD_CHTTP_REQ(cmp4_md), v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "[cngx] set uri '%s' failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0028);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_in_filter: "
                                             "[cngx] set uri '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0029);
    }while(0);

    /*set range*/
    if(CMP4_ERR_SEG_NO != CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
        {
            range_start = 0;
            range_end   = range_start + CMP4_MD_CACHE_SEG_SIZE(cmp4_md) - 1;
        }
        else
        {
            range_start = (CMP4_MD_ABSENT_SEG_NO(cmp4_md) - 1) * CMP4_MD_CACHE_SEG_SIZE(cmp4_md);
            range_end   = range_start + CMP4_MD_CACHE_SEG_SIZE(cmp4_md) - 1;
        }

        if(0 < CMP4_MD_CONTENT_LENGTH(cmp4_md) && range_end >= CMP4_MD_CONTENT_LENGTH(cmp4_md))
        {
            range_end = CMP4_MD_CONTENT_LENGTH(cmp4_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(CMP4_MD_CHTTP_REQ(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_in_filter: "
                                                 "set header '%s':'%s' failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
    }

    return cmp4_filter_header_in_common(cmp4_md_id, CMP4_MD_CHTTP_REQ(cmp4_md));
}

EC_BOOL cmp4_content_direct_header_out_length_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_header_out_length_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(BIT_FALSE == CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md))
    {
        char       *content_length_str;
        UINT32      content_length;

        content_length_str = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"Content-Length");
        if(NULL_PTR == content_length_str)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_length_filter: "
                                                 "no 'Content-Length'\n");
            return (EC_FALSE);
        }

        content_length = c_str_to_word(content_length_str);

        CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
        CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_length_filter: "
                                             "parse Content-Length '%s' to %ld\n",
                                             content_length_str,
                                             content_length);
    }

    if(BIT_TRUE == CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md)
    && BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        if(EC_FALSE == cmp4_get_rsp_length_segs(cmp4_md_id, CMP4_MD_CACHE_SEG_SIZE(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_length_filter: "
                                                 "split content_length to segs failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_length_filter: "
                                             "split content_length to segs done\n");
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_length_filter: "
                                         "done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_header_out_range_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_header_out_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    while(BIT_FALSE == CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md))
    {
        char       *content_range_str;
        char       *content_length_str;

        content_range_str = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"Content-Range");
        if(NULL_PTR != content_range_str)
        {
            UINT32      range_start;
            UINT32      range_end;
            UINT32      content_length;

            if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_range_filter: "
                                                     "invalid Content-Range '%s'\n",
                                                     content_range_str);
                return (EC_FALSE);
            }

            CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
            CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_range_filter: "
                                                 "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                                 content_range_str,
                                                 range_start, range_end, content_length);
            /*fall throught*/
            break;
        }

        content_length_str = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"Content-Length");
        if(NULL_PTR != content_length_str)
        {
            UINT32      content_length;

            content_length = c_str_to_word(content_length_str);

            CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
            CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_range_filter: "
                                                 "parse Content-Length '%s' to %ld\n",
                                                 content_length_str,
                                                 content_length);
            /*fall throught*/
            break;
        }

        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_range_filter: "
                                             "no 'Content-Range' => failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cmp4_content_direct_header_out_length_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_range_filter: "
                                             "filter length failed\n");
        return(EC_FALSE);
    }

    if(BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        const char                  *k;
        const char                  *v;

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md),k);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_range_filter: "
                                             "del rsp header %s done\n",
                                             k);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(CMP4_MD_CONTENT_LENGTH(cmp4_md));
        chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md),k, v);
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_range_filter: "
                                             "renew rsp header %s:%s done\n",
                                             k, v);

        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        if(EC_FALSE == cmp4_filter_header_out_range(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_range_filter: "
                                                 "filter range failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_range_filter: "
                                             "filter range done\n");
    }
    if(1 < crange_mgr_node_num(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)))
    {
        const char                  *k;
        const char                  *v;

        char                         header_buf[ 64 ];

        char                        *boundary_str;
        uint32_t                     boundary_len;

        crange_mgr_get_naked_boundary(CMP4_MD_CNGX_RANGE_MGR(cmp4_md), &boundary_str, &boundary_len);

        snprintf(header_buf, sizeof(header_buf), "multipart/byteranges; boundary=%.*s",
                                                 boundary_len, boundary_str);

        k = (const char *)"Content-Type";
        v = (const char *)header_buf;
        chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md),k, v);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_range_filter: "
                                             "renew '%s' done\n",
                                             k);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_range_filter: "
                                         "done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_header_out_status_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    const char                  *k;
    char                        *v;
    uint32_t                     status;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_header_out_status_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);

        response_status = c_str_to_uint32_t(v);
        
        if(CHTTP_NOT_FOUND == response_status)
        {
            cmp4_set_ngx_rc(cmp4_md_id, CHTTP_NOT_FOUND, LOC_CMP4_0104);

            CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = response_status;
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_status_filter: "
                                                 "[cngx] found 404 => response status = %ld\n",
                                                 k,
                                                 CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
            return (EC_TRUE);            
        }    
    }

    status = CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md));
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_status_filter: "
                                         "response status = %u [before]\n",
                                         status);

    if(CHTTP_OK != status && CHTTP_PARTIAL_CONTENT != status)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_status_filter: "
                                            "unchangeable => response status = %u [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    if(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_PARTIAL_CONTENT;
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_status_filter: "
                                            "range exist => response status = %u [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_OK;
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_status_filter: "
                                         "response status = %u [after]\n",
                                         CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_header_out_connection_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    const char                  *k;
    uint32_t                     status;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_header_out_connection_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    status = CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md));

    if(CHTTP_NOT_FOUND == status)
    {
        k = (const char *)"Connection";
        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
        
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_connection_filter: "
                                             "404 => del %s\n",
                                             k);
        return (EC_TRUE);
    }
    
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_connection_filter: "
                                         "not 404\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_header_out_filter(const UINT32 cmp4_md_id)
{
    //CMP4_MD                  *cmp4_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_header_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    //cmp4_md = CMP4_MD_GET(cmp4_md_id);

    //r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    k = (const char *)"direct";
    cmp4_filter_header_out_common(cmp4_md_id, k);

    /*Content-Length and Content-Range*/
    if(EC_FALSE == cmp4_content_direct_header_out_range_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_filter: "
                                             "range filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_filter: "
                                         "range filter done\n");

    if(EC_FALSE == cmp4_content_direct_header_out_status_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_filter: "
                                             "status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_filter: "
                                         "status filter done\n");

    /*Connection*/
    if(EC_FALSE == cmp4_content_direct_header_out_connection_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_header_out_filter: "
                                             "connection filter failed\n");
        return (EC_FALSE);
    }
    
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_filter: "
                                         "connection filter done\n");
                                         
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_body_out_filter(const UINT32 cmp4_md_id)
{
    //CMP4_MD                  *cmp4_md;

    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_body_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    //cmp4_md = CMP4_MD_GET(cmp4_md_id);

    //r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_send_request(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_send_request: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*chttp_req*/
    if(NULL_PTR == CMP4_MD_CHTTP_REQ(cmp4_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_request: "
                                                 "new chttp_req failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0030);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_REQ(cmp4_md) = chttp_req;
    }
    else
    {
        chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CMP4_MD_CHTTP_RSP(cmp4_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_request: "
                                                 "new chttp_rsp failed\n");
            chttp_req_free(chttp_req);
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0031);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_RSP(cmp4_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CMP4_MD_CHTTP_RSP(cmp4_md);
        chttp_rsp_clean(chttp_rsp);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_request: "
                                             "export headers_in to http req failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0032);
        return (EC_FALSE);
    }
    if(EC_FALSE == cmp4_content_direct_header_in_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_request: "
                                             "header_in filter failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0033);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }
    if(EC_FALSE == chttp_request(chttp_req, NULL_PTR, chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_request: "
                                             "http request failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CMP4_0034);
        return (EC_FALSE);
    }
    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_send_seg_n(const UINT32 cmp4_md_id, const CRANGE_SEG *crange_seg)
{
    CMP4_MD                     *cmp4_md;;
    ngx_http_request_t          *r;
    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_send_seg_n: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);
    chttp_rsp = CMP4_MD_CHTTP_RSP(cmp4_md);

    ASSERT(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md));

    /*no-direct*/
    if(CMP4_MD_ABSENT_SEG_NO(cmp4_md) == CRANGE_SEG_NO(crange_seg))
    {
        uint8_t         *data;
        uint32_t         len;

        cmp4_content_direct_body_out_filter(cmp4_md_id);

        data = CBYTES_BUF(CHTTP_RSP_BODY(chttp_rsp)) + CRANGE_SEG_S_OFFSET(crange_seg);
        len  = (uint32_t)(CRANGE_SEG_E_OFFSET(crange_seg) + 1 - CRANGE_SEG_S_OFFSET(crange_seg));

        if(EC_FALSE == cngx_send_body(r, data, len,
                         /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                         &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_seg_n: "
                                                 "send body seg %ld failed\n",
                                                 CRANGE_SEG_NO(crange_seg));

            return (EC_FALSE);
        }

        CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_seg_n: "
                                             "send body seg %ld: %u bytes done\n",
                                             CRANGE_SEG_NO(crange_seg), len);

        chttp_rsp_clean(chttp_rsp);
        return (EC_TRUE);
    }

    /*else*/

    chttp_rsp_clean(chttp_rsp);

    CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_seg_n: "
                                         "set absent_seg_no = %ld\n",
                                         CMP4_MD_ABSENT_SEG_NO(cmp4_md));

    /*recursively*/
    return cmp4_content_direct_procedure(cmp4_md_id);
}

EC_BOOL cmp4_content_direct_send_node(const UINT32 cmp4_md_id, CRANGE_NODE *crange_node)
{
    CMP4_MD                     *cmp4_md;;
    ngx_http_request_t          *r;

    CRANGE_SEG                  *crange_seg;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_send_node: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*boundary*/
    if(EC_FALSE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;

        boundary = CRANGE_NODE_BOUNDARY(crange_node);

        cmp4_content_direct_body_out_filter(cmp4_md_id);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        if(EC_FALSE == cngx_send_body(r, data, len,
                         /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                         &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_node: "
                                                 "send body boundary failed\n");

            return (EC_FALSE);
        }

        CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_node: "
                                             "send body boundary: %ld bytes done\n",
                                             CSTRING_LEN(boundary));

        /*clean boundary which was sent out*/
        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    }

    while(NULL_PTR != (crange_seg = crange_node_first_seg(crange_node)))
    {        UINT32      seg_no;

        seg_no = CRANGE_SEG_NO(crange_seg); /*range_seg may be free at other place, save it here*/

        if(EC_FALSE == cmp4_content_direct_send_seg_n(cmp4_md_id, crange_seg))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_node: "
                                                 "send direct seg %ld failed\n",
                                                 seg_no);

            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_node: "
                                             "send direct seg %ld done => sent body %ld bytes\n",
                                             seg_no,
                                             CMP4_MD_SENT_BODY_SIZE(cmp4_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_node: "
                                                 "pop seg %ld\n",
                                                 CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_send_response(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_send_response: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);
    chttp_rsp = CMP4_MD_CHTTP_RSP(cmp4_md);

    if(EC_TRUE == cngx_need_send_header(r))
    {
        if(EC_FALSE == cmp4_content_direct_header_out_filter(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_response: "
                                                 "header_out filter failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0035);
            return (EC_FALSE);
        }

        cngx_import_header_out(r, chttp_rsp);

        cngx_disable_write_delayed(r);

        if(0 == CBYTES_LEN(CHTTP_RSP_BODY(chttp_rsp)))
        {
            cngx_set_header_only(r);

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                                 "set header only\n");
        }

        if(EC_FALSE == cngx_send_header(r, &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_response: "
                                                 "send header failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                             "send header done\n");


        if(0 == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
        {
            CMP4_MD_ABSENT_SEG_NO(cmp4_md) ++;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                                 "inc absent_seg_no to %ld\n",
                                                 CMP4_MD_ABSENT_SEG_NO(cmp4_md));
        }
    }

    /*direct is not triggered by seg loss, but by ngx cfg => send chttp rsp only*/
    if(BIT_FALSE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md)
    && CMP4_ERR_SEG_NO == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        uint8_t         *data;
        uint32_t         len;

        cmp4_content_direct_body_out_filter(cmp4_md_id);

        data = CBYTES_BUF(CHTTP_RSP_BODY(chttp_rsp));
        len  = (uint32_t)CBYTES_LEN(CHTTP_RSP_BODY(chttp_rsp));

        if(EC_FALSE == cngx_send_body(r, data, len,
                         /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                         &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_response: "
                                                 "send body failed\n");

            return (EC_FALSE);
        }

        CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                             "send body %u bytes done\n",
                                             len);

        chttp_rsp_clean(chttp_rsp);
        return (EC_TRUE);
    }

    if(EC_FALSE == cmp4_filter_rsp_range(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_response: "
                                             "chttp rsp header_in range filter failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_RANGE_NOT_SATISFIABLE, LOC_CMP4_0036);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                         "chttp rsp header_in range filter done\n");

    /*send body: direct*/
    if(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
    {
        CRANGE_MGR                  *crange_mgr;
        CRANGE_NODE                 *crange_node;

        crange_mgr = CMP4_MD_CNGX_RANGE_MGR(cmp4_md);
        if(do_log(SEC_0147_CMP4, 9))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                                 "before send body, crange_mgr:\n");
            crange_mgr_print(LOGSTDOUT, crange_mgr);
        }

        /*send body: ranges*/
        while(NULL_PTR != (crange_node = crange_mgr_first_node(crange_mgr)))
        {
            if(EC_FALSE == cmp4_content_direct_send_node(cmp4_md_id, crange_node))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_response: "
                                                     "send node (%ld:%s, %ld:%s) failed\n",
                                                     CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                     CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

                return (EC_FALSE);
            }

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                                 "send node (%ld:%s, %ld:%s) done => sent body %ld bytes\n",
                                                 CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                 CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                                 CMP4_MD_SENT_BODY_SIZE(cmp4_md));

            if(crange_mgr_first_node(crange_mgr) == crange_node)
            {
                dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
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

            boundary = CRANGE_MGR_BOUNDARY(crange_mgr);

            cmp4_content_direct_body_out_filter(cmp4_md_id);
            data = (uint8_t *)CSTRING_STR(boundary);
            len  = (uint32_t)CSTRING_LEN(boundary);

            if(EC_FALSE == cngx_send_body(r, data, len,
                             /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                             &(CMP4_MD_NGX_RC(cmp4_md))))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_send_response: "
                                                     "send body boundary failed\n");

                return (EC_FALSE);
            }

            CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                                 "send body boundary: %ld bytes done\n",
                                                 CSTRING_LEN(boundary));
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_send_response: "
                                             "send body done => complete %ld bytes\n",
                                             CMP4_MD_SENT_BODY_SIZE(cmp4_md));
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_content_direct_procedure(const UINT32 cmp4_md_id)
{
    CMP4_MD                  *cmp4_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_direct_procedure: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(EC_FALSE == cmp4_content_direct_send_request(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_procedure: "
                                             "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_procedure: "
                                         "send request done\n");

    if(EC_FALSE == cngx_headers_dir2_filter(r, CMP4_MD_CHTTP_RSP(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_procedure: "
                                             "dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_procedure: "
                                         "dir2 filter done\n");

    if(EC_FALSE == cmp4_content_direct_send_response(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_direct_procedure: "
                                             "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_direct_procedure: "
                                         "send response done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_header_in_filter_port(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_header_in_filter_port: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);

    /*when cngx config orig port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter_port: "
                                             "get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter_port: "
                                             "[conf] get var '%s':'%s' done\n",
                                             k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CMP4_0037);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter_port: "
                                             "[conf] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0038);
        return (EC_TRUE);
    }

    /*when cngx NOT config orig port*/
    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter_port: "
                                             "[cngx] get var '%s':'%s' done\n",
                                             k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter_port: "
                                                    "[cngx] set port to http req failed\n",
                                                    v);
            safe_free(v, LOC_CMP4_0039);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter_port: "
                                             "[cngx] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0040);

        return (EC_TRUE);
    }

    /*set default orig port*/
    chttp_req_set_port_word(chttp_req, CNGX_ORIG_PORT_DEFAULT);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                         "[default] set default port '%d' to http req done\n",
                                         CNGX_ORIG_PORT_DEFAULT);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_header_in_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_header_in_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config orig server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_server(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "[conf] set server '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0041);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            safe_free(v, LOC_CMP4_0042);

            break; /*ok*/
        }

        /*when cngx config orig host and port*/
        k = (const char *)CNGX_VAR_ORIG_HOST;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "[conf] set host '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0043);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[conf] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0044);

            /*set port*/
            if(EC_FALSE == cmp4_content_orig_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*now cngx NOT config orig server and NOT config orig (host, port)*/

        /*try http_host*/
        k = (const char *)"http_host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0045);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0046);

            /*set port*/
            if(EC_FALSE == cmp4_content_orig_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try server_name*/
        k = (const char *)"server_name";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0047);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0048);

            /*set port*/
            if(EC_FALSE == cmp4_content_orig_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try host*/
        k = (const char *)"host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "[cngx] set ipaddr of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0049);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0050);

            /*set port*/
            if(EC_FALSE == cmp4_content_orig_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                             "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(chttp_req, v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                             "set method '%s' failed\n",
                                             v);
        safe_free(v, LOC_CMP4_0051);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CMP4_0052);

    /*set http request uri*/
    do
    {
        /*when cngx config orig uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                     "[conf] set uri '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0053);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                                 "[conf] set uri '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0054);

            break; /*ok*/
        }

        /*when cngx NOT config orig uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "[cngx] set uri '%s' failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0055);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                             "[cngx] set uri '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0056);

        /*FLV: not carray on args to orig*/
    }while(0);

    /*set keep-alive*/
    k = (const char *)"Connection";
    v = (char       *)"keep-alive";
    chttp_req_renew_header(chttp_req, k, v);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                         "renew req header '%s':'%s' done\n",
                                         k, v);

    /*set range*/
    if(CMP4_ERR_SEG_NO != CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
        {
            range_start = 0;
            range_end   = range_start + CMP4_MD_CACHE_SEG_SIZE(cmp4_md) - 1;
        }
        else
        {
            range_start = (CMP4_MD_ABSENT_SEG_NO(cmp4_md) - 1) * CMP4_MD_CACHE_SEG_SIZE(cmp4_md);
            range_end   = range_start + CMP4_MD_CACHE_SEG_SIZE(cmp4_md) - 1;
        }

        if(0 < CMP4_MD_CONTENT_LENGTH(cmp4_md) && range_end >= CMP4_MD_CONTENT_LENGTH(cmp4_md))
        {
            range_end = CMP4_MD_CONTENT_LENGTH(cmp4_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(chttp_req, k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_in_filter: "
                                                 "set header '%s':'%s' failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_in_filter: "
                                             "set header '%s':'%s' done\n",
                                             k, v);
    }

    return cmp4_filter_header_in_common(cmp4_md_id, chttp_req);
}

EC_BOOL cmp4_content_orig_header_out_range_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_header_out_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    while(BIT_FALSE == CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md))
    {
        char       *content_range_str;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        content_range_str = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"Content-Range");
        if(NULL_PTR == content_range_str)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_range_filter: "
                                                 "no 'Content-Range' => failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == crange_parse_content_range(content_range_str, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_range_filter: "
                                                 "invalid Content-Range '%s'\n",
                                                 content_range_str);
            return (EC_FALSE);
        }

        CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
        CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_range_filter: "
                                             "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                             content_range_str,
                                             range_start, range_end, content_length);
        break;/*fall through*/
    }

    /*single range and multiple range*/
    if(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        if(EC_FALSE == cmp4_filter_header_out_range(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_range_filter: "
                                                 "filter range failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_range_filter: "
                                             "filter range done\n");
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_range_filter: "
                                         "done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_header_out_status_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_header_out_status_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);

        response_status = c_str_to_uint32_t(v);
        
        if(CHTTP_NOT_FOUND == response_status)
        {
            cmp4_set_ngx_rc(cmp4_md_id, CHTTP_NOT_FOUND, LOC_CMP4_0104);

            CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = response_status;
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                                 "[cngx] found 404 => response status = %ld\n",
                                                 k,
                                                 CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
            return (EC_TRUE);            
        }    
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                         "response status = %u [before]\n",
                                         CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));

    if(CHTTP_NOT_FOUND == CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                             "[cngx] 404 keep unchanged => response status = %u [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }
    
    if(CHTTP_MOVED_PERMANENTLY == CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md))
    || CHTTP_MOVED_TEMPORARILY == CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                             "[cngx] 301/302 keep unchanged => response status = %u [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    if(BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_OK;
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                             "[cngx] no range => response status = %u [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                         "CMP4_MD_CONTENT_LENGTH = %ld\n",
                                         CMP4_MD_CONTENT_LENGTH(cmp4_md));

    k = (const char *)"Content-Range";
    if(EC_TRUE == chttp_rsp_has_header_key(CMP4_MD_CHTTP_RSP(cmp4_md), k))
    {
        CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                             "'%s' exist => response status = %ld [after]\n",
                                             k, CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    if(1 < crange_mgr_node_num(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)))
    {
        CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                             "[cngx] multi range => response status = %ld [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_OK;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_status_filter: "
                                         "response status = %ld [after]\n",
                                         CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_header_out_cache_control_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_header_out_cache_control_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(BIT_FALSE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
    {
        const char      *k;
        const char      *v;

        k = (const char *)CHTTP_RSP_X_CACHE_CONTROL;
        v = (const char *)"no-cache";

        if(EC_TRUE == chttp_rsp_has_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_cache_control_filter: "
                                                 "found '%s':'%s' => set orig_no_cache_flag = true\n",
                                                 k, v);
            CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md) = BIT_TRUE;
            return (EC_TRUE);
        }

        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_cache_control_filter: "
                                         "found orig_no_cache_flag is true\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_header_out_mp4_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_header_out_mp4_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    /*parse mp4 meta*/
    if(BIT_FALSE == CMP4_MD_ORIG_FORCE_FLAG(cmp4_md)
    && BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md)
    && 0 < CMP4_MD_MP4_START(cmp4_md))
    {
        if(EC_FALSE == cmp4_get_meta(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_mp4_filter: "
                                                 "get meta failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_mp4_filter: "
                                             "get meta done\n");

        if(EC_FALSE == cmp4_filter_header_out_no_range(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_mp4_filter: "
                                                 "no range filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_mp4_filter: "
                                             "no range filter done\n");

        if(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id))
        {
            crange_mgr_clean(CMP4_MD_CNGX_RANGE_MGR(cmp4_md));
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_mp4_filter: "
                                                 "mp4 out chain exist => clean up crange mgr\n");
        }
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_mp4_filter: "
                                         "mp4 filter done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_header_out_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_header_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    k = (const char *)"orig";
    cmp4_filter_header_out_common(cmp4_md_id, k);

    v = (const char *)CNGX_CACHE_STATUS_MISS;
    CMP4_MD_CACHE_STATUS(cmp4_md) = v;

    /*mp4 range filter*/
    if(EC_FALSE == cmp4_content_orig_header_out_range_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_filter: "
                                             "range filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_filter: "
                                         "range filter done\n");

    /*mp4 filter*/
    if(EC_FALSE == cmp4_content_orig_header_out_mp4_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_filter: "
                                             "mp4 filter failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_filter: "
                                         "mp4 filter done\n");

    if(BIT_FALSE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
    {
        if(EC_FALSE == cmp4_content_orig_header_out_status_filter(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_header_out_filter: "
                                                 "status filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_filter: "
                                             "status filter done\n");
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_header_out_filter: done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_body_out_filter(const UINT32 cmp4_md_id, const UINT32 seg_no, uint8_t **data, uint32_t *len)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_body_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_set_store(const UINT32 cmp4_md_id, CHTTP_STORE *chttp_store)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_set_store: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*--- chttp_store settting --- BEG ---*/
    if(CMP4_ERR_SEG_NO == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        CHTTP_STORE_SEG_ID(chttp_store) = 0;
    }
    else
    {
        CHTTP_STORE_SEG_ID(chttp_store) = (uint32_t)CMP4_MD_ABSENT_SEG_NO(cmp4_md);
    }

    CHTTP_STORE_SEG_SIZE(chttp_store)     = CMP4_MD_CACHE_SEG_SIZE(cmp4_md);
    CHTTP_STORE_SEG_S_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;
    CHTTP_STORE_SEG_E_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;

    cstring_clone(CMP4_MD_CACHE_PATH(cmp4_md), CHTTP_STORE_BASEDIR(chttp_store));

    if(0 == CHTTP_STORE_SEG_ID(chttp_store))
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)   = EC_FALSE;
    }
    else
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)   = EC_TRUE;
    }

    if(EC_FALSE == cngx_set_store(r, chttp_store))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_set_store: "
                                             "fetch ngx cfg to chttp_store failed\n");
        return (EC_FALSE);
    }

    CHTTP_STORE_CACHE_CTRL(chttp_store) = CHTTP_STORE_CACHE_BOTH;

    /*--- chttp_store settting --- END ---*/

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_send_request(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STORE                 *chttp_store;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_send_request: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*chttp_req*/
    if(NULL_PTR == CMP4_MD_CHTTP_REQ(cmp4_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                                 "new chttp_req failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0057);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_REQ(cmp4_md) = chttp_req;
    }
    else
    {
        chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CMP4_MD_CHTTP_RSP(cmp4_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                                 "new chttp_rsp failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0058);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_RSP(cmp4_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CMP4_MD_CHTTP_RSP(cmp4_md);
        chttp_rsp_clean(chttp_rsp);
    }

    /*chttp_store*/
    if(NULL_PTR == CMP4_MD_CHTTP_STORE(cmp4_md))
    {
        chttp_store = chttp_store_new();
        if(NULL_PTR == chttp_store)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                                 "new chttp_store failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0059);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_STORE(cmp4_md) = chttp_store;
    }
    else
    {
        chttp_store = CMP4_MD_CHTTP_STORE(cmp4_md);
        chttp_store_clean(chttp_store);
    }

    if(EC_FALSE == cmp4_content_orig_set_store(cmp4_md_id, chttp_store))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                             "set chttp_store failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0060);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_request: "
                                             "chttp_store is\n");
        chttp_store_print(LOGSTDOUT, chttp_store);
    }

    /*chttp_stat*/
    if(NULL_PTR == CMP4_MD_CHTTP_STAT(cmp4_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                                 "new chttp_stat failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0061);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_STAT(cmp4_md)  = chttp_stat;
    }
    else
    {
        chttp_stat = CMP4_MD_CHTTP_STAT(cmp4_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                             "export headers_in to http req failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0062);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmp4_content_orig_header_in_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                             "header_in filter failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0063);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, chttp_store, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_request: "
                                             "http request failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CMP4_0064);
        return (EC_FALSE);
    }
    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_request: "
                                         "send request done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_send_mp4_meta(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;

    cngx_mp4_file_t             *mp4;
    ngx_chain_t                 *out;
    ngx_chain_t                **t;

    ngx_int_t                    rc;

    UINT32                       len;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_send_mp4_meta: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    ASSERT(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id));

    mp4 = CMP4_MD_MP4(cmp4_md);

    out = mp4->out;
    t   = &(out->next);
    len = 0;

    while(NULL_PTR != (*t)
    && NULL_PTR != (*t)->buf
    && 0 == (*t)->buf->in_file
#if 0
    && 0 == (*t)->buf->sync
    && 0 == (*t)->buf->flush
    && 0 == (*t)->buf->last_in_chain
#endif
    )
    {
        len += (*t)->buf->last - (*t)->buf->pos;

        t = &((*t)->next);
    }

    if(NULL_PTR != (*t))
    {
        mp4->out = (*t);
        (*t)    = NULL_PTR;
    }
    else
    {
        mp4->out = NULL_PTR;
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_mp4_meta: "
                                             "to send out chain: \n");
        cmp4_print_ngx_chain(LOGSTDOUT, 0, out);
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
    }

    ASSERT(0 == out->buf->in_file);

    rc = ngx_http_output_filter(r, out);
    if(rc == NGX_ERROR || rc > NGX_OK)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_mp4_meta: send body failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, rc, LOC_CMP4_0065);
        return (EC_FALSE);
    }

    if(rc == NGX_AGAIN/* || b->last > b->pos + NGX_LUA_OUTPUT_BLOCKING_LOWAT*/)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_mp4_meta: need send body again\n");

        return cngx_send_blocking(r);
    }

    CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_mp4_meta: "
                                         "done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_add_mp4_range(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;
    cngx_mp4_file_t             *mp4;
    ngx_chain_t                 *out;

    UINT32                       offset_start;
    UINT32                       offset_end;
    UINT32                       seg_size;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_add_mp4_range: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);
    mp4 = CMP4_MD_MP4(cmp4_md);
    out = mp4->out;

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_add_mp4_range: "
                                             "to send out chain: \n");
        cmp4_print_ngx_chain(LOGSTDOUT, 0, out);
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
    }

    /*now data in file, and chain length is one*/
    ASSERT(NULL_PTR == out->next);
    ASSERT(NULL_PTR != out->buf);

    ASSERT(1 == out->buf->in_file);
    ASSERT(out->buf->file_pos <= out->buf->file_last);

    mp4->out = NULL_PTR;

    offset_start = (UINT32)out->buf->file_pos;
    offset_end   = (UINT32)out->buf->file_last;
    seg_size     = CMP4_MD_CACHE_SEG_SIZE(cmp4_md);

#if 1
    if(EC_FALSE == crange_mgr_add_range(CMP4_MD_CNGX_RANGE_MGR(cmp4_md),
                                        offset_start,
                                        offset_end,
                                        seg_size))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_add_mp4_range: "
                                             "split [%ld, %ld] into segs failed\n",
                                             offset_start, offset_end);

        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_add_mp4_range: "
                                         "split [%ld, %ld] into segs done\n",
                                         offset_start, offset_end);
#endif
    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_send_ahead_body(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_send_ahead_body: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    ASSERT(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id));

    if(EC_FALSE == cmp4_content_orig_send_mp4_meta(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_ahead_body: "
                                             "send meta failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_ahead_body: "
                                         "send meta => OK\n");
    if(EC_FALSE == cmp4_content_orig_add_mp4_range(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_ahead_body: "
                                             "add range failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_ahead_body: "
                                         "add range => OK\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_send_seg_n(const UINT32 cmp4_md_id, const CRANGE_SEG *crange_seg)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_send_seg_n: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    cbytes_init(&seg_cbytes);

    if(EC_FALSE == cmp4_get_cache_seg_n(cmp4_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_seg_n: "
                                             "get cache seg %ld failed\n",
                                             CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_NOT_FOUND, LOC_CMP4_0066);
        return (EC_FALSE);
    }

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    cmp4_content_orig_body_out_filter(cmp4_md_id, CRANGE_SEG_NO(crange_seg), &data, &len);

    if(EC_FALSE == cngx_send_body(r, data, len,
                     /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                     &(CMP4_MD_NGX_RC(cmp4_md))))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_seg_n: "
                                             "send body seg %ld failed\n",
                                             CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;


    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_seg_n: "
                                         "send seg %ld [%ld, %ld], %ld bytes\n",
                                         CRANGE_SEG_NO(crange_seg),
                                         CRANGE_SEG_S_OFFSET(crange_seg),
                                         CRANGE_SEG_E_OFFSET(crange_seg),
                                         CBYTES_LEN(&seg_cbytes));

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_send_response(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    CRANGE_MGR                  *crange_mgr;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_send_response: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(EC_FALSE == cmp4_filter_rsp_range(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_response: "
                                             "chttp rsp header range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                         "chttp rsp header range filter done\n");

    /*send header*/
    if(0 == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        if(EC_FALSE == cmp4_content_orig_header_out_filter(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_response: "
                                                 "header_out filter failed\n");

            return (EC_FALSE);
        }

        cngx_import_header_out(r, CMP4_MD_CHTTP_RSP(cmp4_md));

        cngx_disable_write_delayed(r);
    }
    else
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "absent_seg_no = %ld != 0 => ignore header_out filter and sending\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));
    }

    crange_mgr = CMP4_MD_CNGX_RANGE_MGR(cmp4_md);

    /*note: only after header_out filter with unchanged range segs, we can parse content lengt to segs*/
    /*parse Content-Length and segs from chttp rsp if cngx req has no 'Range'*/

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: [1] "
                                         "crange_mgr size = %ld\n",
                                         crange_mgr_node_num(crange_mgr));

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: [1] "
                                         "cmp4_has_mp4_out: %s\n",
                                         c_bool_str(cmp4_has_mp4_out(cmp4_md_id)));

    if(EC_TRUE == crange_mgr_is_empty(crange_mgr)
    && EC_FALSE == cmp4_has_mp4_out(cmp4_md_id))
    {
        if(EC_FALSE == cmp4_get_rsp_length_segs(cmp4_md_id, CMP4_MD_CACHE_SEG_SIZE(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_response: "
                                                 "get rsp length segs from chttp rsp failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "get rsp length segs from chttp rsp done\n");
    }

    if(0 == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "crange_mgr size = %ld\n",
                                             crange_mgr_node_num(crange_mgr));
        if(EC_TRUE == crange_mgr_is_empty(crange_mgr)
        && EC_FALSE == cmp4_has_mp4_out(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                                 "set header only\n");
            cngx_set_header_only(r);
        }

        if(EC_FALSE == cngx_send_header(r, &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_response: "
                                                 "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "send header done\n");

        CMP4_MD_ABSENT_SEG_NO(cmp4_md) ++;
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "inc absent_seg_no to %ld\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));
    }

    /*send body*/
    /*send body: chain*/
    if(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "mp4 out chain exist => send ahead body\n");
        if(EC_FALSE == cmp4_content_orig_send_ahead_body(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_response: "
                                                 "send mp4 ahead body failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "send mp4 ahead body done\n");
    }

    /*send one seg only*/
    if(CMP4_ERR_SEG_NO != CMP4_MD_ABSENT_SEG_NO(cmp4_md)
    && EC_FALSE == crange_mgr_is_empty(crange_mgr))
    {
        CRANGE_NODE                *crange_node;
        CRANGE_SEG                 *crange_seg;
        UINT32                      seg_no;

        crange_node = crange_mgr_first_node(crange_mgr);
        crange_seg  = crange_node_first_seg(crange_node);
        seg_no      = CRANGE_SEG_NO(crange_seg);

        if(seg_no != CMP4_MD_ABSENT_SEG_NO(cmp4_md))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "warn:cmp4_content_orig_send_response: "
                                                 "seg_no %ld != absent_seg_no %ld => return\n",
                                                 seg_no, CMP4_MD_ABSENT_SEG_NO(cmp4_md));

            return (EC_TRUE);
        }
        ASSERT(seg_no == CMP4_MD_ABSENT_SEG_NO(cmp4_md));

        if(EC_FALSE == cmp4_content_orig_send_seg_n(cmp4_md_id, crange_seg))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_send_response: "
                                                 "get cache seg %ld failed\n",
                                                 seg_no);

            return (EC_FALSE);
        }

        CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CMP4_ERR_SEG_NO;/*clear*/

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                             "send cache seg %ld done => sent body %ld bytes\n",
                                             CRANGE_SEG_NO(crange_seg),
                                             CMP4_MD_SENT_BODY_SIZE(cmp4_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                                 "pop seg %ld\n",
                                                 CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }

        if(do_log(SEC_0147_CMP4, 9))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: "
                                                 "crange_node %p:\n",
                                                 crange_node);
            crange_node_print(LOGSTDOUT, crange_node);
        }
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_send_response: done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_orig_procedure(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_orig_procedure: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(EC_FALSE == cmp4_content_orig_send_request(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_procedure: "
                                             "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                         "send request done\n");

    if(EC_FALSE == cngx_headers_dir2_filter(r, CMP4_MD_CHTTP_RSP(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_procedure: "
                                             "dir2 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                         "dir2 filter done\n");

    /*301/302 redirect*/
    if(EC_TRUE == cmp4_is_redirect_rsp(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                             "301/302 => redirect procedure\n");
        /*return cmp4_content_redirect_procedure(cmp4_md_id);*//*TODO*/
        if(EC_FALSE == cmp4_content_redirect_procedure(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_procedure: "
                                                 "301/302 failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                             "301/302 done\n");
    }

    /*specific redirect*/
    if(EC_TRUE == cmp4_is_specific_redirect_rsp(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                             "specific redirect rsp => redirect procedure\n");
        /*return cmp4_content_redirect_procedure(cmp4_md_id);*//*TODO*/
        if(EC_FALSE == cmp4_content_redirect_procedure(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_procedure: "
                                                 "specific redirect rsp failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                             "specific redirect rsp done\n");
    }

    if(EC_FALSE == cmp4_content_orig_header_out_cache_control_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_procedure: "
                                             "filter rsp cache-control failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                         "filter rsp cache-control done\n");

    if(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                             "found orig_no_cache_flag is true => direct send response\n");

        return cmp4_content_direct_send_response(cmp4_md_id);
    }

    if(EC_FALSE == cmp4_content_orig_send_response(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_orig_procedure: "
                                             "send response failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_orig_procedure: "
                                         "send response done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_redirect_procedure(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;
    uint32_t                     redirect_times;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_redirect_procedure: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    dbg_log(SEC_0147_CMP4, 5)(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: redirect ctrl '%s'\n",
                        c_bool_str(CHTTP_STORE_REDIRECT_CTRL(CMP4_MD_CHTTP_STORE(cmp4_md))));

    dbg_log(SEC_0147_CMP4, 5)(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: redirect max times '%u'\n",
                        CHTTP_STORE_REDIRECT_MAX_TIMES(CMP4_MD_CHTTP_STORE(cmp4_md)));

    for(redirect_times = 0;
        EC_TRUE == CHTTP_STORE_REDIRECT_CTRL(CMP4_MD_CHTTP_STORE(cmp4_md))
        && CHTTP_STORE_REDIRECT_MAX_TIMES(CMP4_MD_CHTTP_STORE(cmp4_md)) > redirect_times
        && EC_TRUE == cmp4_is_redirect_rsp(cmp4_md_id);
        redirect_times ++
    )
    {
        char      *loc;
        char      *host;
        char      *port;
        char      *uri;
        CHTTP_REQ  chttp_req_t;

        loc = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"Location");
        if(NULL_PTR == loc)
        {
            break;
        }
        dbg_log(SEC_0147_CMP4, 5)(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: [%u] redirect to '%s'\n", redirect_times, loc);

        host = NULL_PTR;
        port = NULL_PTR;
        uri  = NULL_PTR;

        if(EC_FALSE == c_parse_location(loc, &host, &port, &uri))
        {
            if(NULL_PTR != host)
            {
                safe_free(host, LOC_CMP4_0067);
            }
            if(NULL_PTR != port)
            {
                safe_free(port, LOC_CMP4_0068);
            }
            if(NULL_PTR != uri)
            {
                safe_free(uri, LOC_CMP4_0069);
            }
            break;
        }

        chttp_rsp_clean(CMP4_MD_CHTTP_RSP(cmp4_md));
        chttp_stat_clean(CMP4_MD_CHTTP_STAT(cmp4_md));

        chttp_req_init(&chttp_req_t);
        chttp_req_clone(&chttp_req_t, CMP4_MD_CHTTP_REQ(cmp4_md));

        if(NULL_PTR != host)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: location '%s' =>  host '%s'\n", loc, host);
            chttp_req_set_ipaddr(&chttp_req_t, host);
            safe_free(host, LOC_CMP4_0070);
            
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
        }

        if(NULL_PTR != port)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: location '%s' =>  port '%s'\n", loc, port);
            chttp_req_set_port(&chttp_req_t, port);
            safe_free(port, LOC_CMP4_0071);
        }

        if(NULL_PTR == uri)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: location '%s' =>  uri is null\n", loc);

            chttp_req_clean(&chttp_req_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: location '%s' =>  uri '%s'\n", loc, uri);

        cstring_clean(CHTTP_REQ_URI(&chttp_req_t));
        chttp_req_set_uri(&chttp_req_t, uri);
        safe_free(uri, LOC_CMP4_0072);

        if(do_log(SEC_0147_CMP4, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: redirect request is\n");
            chttp_req_print(LOGSTDOUT, &chttp_req_t);

            sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: redirect store is\n");
            chttp_store_print(LOGSTDOUT, CMP4_MD_CHTTP_STORE(cmp4_md));
        }

        if(EC_FALSE == chttp_request(&chttp_req_t,
                                     CMP4_MD_CHTTP_STORE(cmp4_md),
                                     CMP4_MD_CHTTP_RSP(cmp4_md),
                                     CMP4_MD_CHTTP_STAT(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_redirect_procedure: redirect request failed\n");
            chttp_req_print(LOGSTDOUT, &chttp_req_t);

            chttp_req_clean(&chttp_req_t);
            return (EC_FALSE);
        }

        if(do_log(SEC_0147_CMP4, 9))
        {
            sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_redirect_procedure: redirect response is\n");
            chttp_rsp_print(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md));
        }

        chttp_req_clean(&chttp_req_t);
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_in_filter_port(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_in_filter_port: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*when cngx config ims port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter_port: "
                                             "get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter_port: "
                                             "[conf] get var '%s':'%s' done\n",
                                             k, v);
        if(EC_FALSE == chttp_req_set_port(CMP4_MD_CHTTP_REQ(cmp4_md), v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter_port: "
                                                 "[conf] set port '%s' to http req failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0073);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter_port: "
                                             "[conf] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0074);
        return (EC_TRUE);
    }

    /*when cngx NOT config ims port*/
    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter_port: "
                                             "[cngx] get '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter_port: "
                                             "[cngx] get var '%s':'%s' done\n",
                                             k, v);

        if(EC_FALSE == chttp_req_set_port(CMP4_MD_CHTTP_REQ(cmp4_md), v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter_port: "
                                                 "[cngx] set port to http req failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0075);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter_port: "
                                             "[cngx] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0076);

        return (EC_TRUE);
    }

    /*set default ims port*/
    chttp_req_set_port_word(CMP4_MD_CHTTP_REQ(cmp4_md), CNGX_ORIG_PORT_DEFAULT);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                        "[default] set default port '%d' to http req done\n",
                                        CNGX_ORIG_PORT_DEFAULT);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_in_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_in_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config ims server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_server(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[conf] set server '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0077);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            safe_free(v, LOC_CMP4_0078);

            break; /*ok*/
        }

        /*when cngx config ims host and port*/
        k = (const char *)CNGX_VAR_ORIG_HOST;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[conf] set host '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0079);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[conf] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0080);

            /*set port*/
            if(EC_FALSE == cmp4_content_ims_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*now cngx NOT config ims server and NOT config ims (host, port)*/

        /*try http_host*/
        k = (const char *)"http_host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0081);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0082);

            /*set port*/
            if(EC_FALSE == cmp4_content_ims_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try server_name*/
        k = (const char *)"server_name";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0083);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0084);

            /*set port*/
            if(EC_FALSE == cmp4_content_ims_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try host*/
        k = (const char *)"host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[cngx] set ipaddr of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0085);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0086);

            /*set port*/
            if(EC_FALSE == cmp4_content_ims_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                             "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(CMP4_MD_CHTTP_REQ(cmp4_md), v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                             "set method '%s' failed\n",
                                             v);
        safe_free(v, LOC_CMP4_0087);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CMP4_0088);

    /*set http request uri*/
    do
    {
        /*when cngx config orig uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_uri(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[conf] set uri '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0089);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[conf] set uri '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0090);

            break; /*ok*/
        }

        /*when cngx NOT config orig uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(CMP4_MD_CHTTP_REQ(cmp4_md), v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "[cngx] set uri '%s' failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0091);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                             "[cngx] set uri '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0092);

        if(EC_TRUE == cngx_get_req_arg(r, &v) && NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] get args '%s'\n",
                                                 v);

            if(EC_FALSE == chttp_req_set_uri(CMP4_MD_CHTTP_REQ(cmp4_md), (const char *)"?"))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[cngx] set '?' failed\n");
                safe_free(v, LOC_CMP4_0093);
                return (EC_FALSE);
            }

            if(EC_FALSE == chttp_req_set_uri(CMP4_MD_CHTTP_REQ(cmp4_md), v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                     "[cngx] set args '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0094);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                                 "[cngx] set args '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0095);
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
        if(EC_FALSE == chttp_req_renew_header(CMP4_MD_CHTTP_REQ(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                  "set header '%s':'%s' failed\n",
                                                  k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                             "set header '%s':'%s' done\n",
                                             k, v);
    }

    /*set If-Modified-Since*/
    if(EC_FALSE == cstring_is_empty(CMP4_MD_HEADER_EXPIRES(cmp4_md)))
    {
        k = (const char *)"If-Modified-Since";
        v = (char *      )cstring_get_str(CMP4_MD_HEADER_EXPIRES(cmp4_md));

        if(EC_FALSE == chttp_req_add_header(CMP4_MD_CHTTP_REQ(cmp4_md), k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_in_filter: "
                                                 "set header '%s':'%s' failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_in_filter: "
                                             "set header '%s':'%s' done\n",
                                             k, v);
    }

    return cmp4_filter_header_in_common(cmp4_md_id, CMP4_MD_CHTTP_REQ(cmp4_md));
}

EC_BOOL cmp4_content_ims_header_out_304_last_modified_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
    CMP4_MD                     *cmp4_md;
    CMP4_MD                     *cmp4_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_last_modified_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_last_modified_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md   = CMP4_MD_GET(cmp4_md_id);
    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);

    /*update rsp header*/
    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_304_last_modified_filter: "
                                             "[status %u] ims rsp has no header '%s' which is\n",
                                             status, k, v);

        chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md_t));

        return (EC_FALSE);
    }

    /*renew Last-Modified in previous rsp*/
    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_304_last_modified_filter: "
                                         "[status %u] renew rsp header '%s':'%s' done\n",
                                         status, k, v);

    /*renew Last-Modified in cache (seg-0)*/
    if(EC_FALSE == cmp4_renew_header_cache(cmp4_md_id_t, k, v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_304_last_modified_filter: "
                                             "[status %u] renew cache header '%s':'%s' failed => ignore\n",
                                             status, k, v);
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_304_last_modified_filter: "
                                         "[status %u] renew cache header '%s':'%s' done\n",
                                         status, k, v);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_out_304_expires_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
    CMP4_MD                     *cmp4_md;
    CMP4_MD                     *cmp4_md_t;

    ngx_http_request_t          *r;

    const char                  *k;
    const char                  *v;
    uint32_t                     nsec;
    time_t                       t;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_expires_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_expires_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md   = CMP4_MD_GET(cmp4_md_id);
    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    k = (const char *)CNGX_VAR_ORIG_EXPIRES_OVERRIDE_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &nsec, 0))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_304_expires_filter: "
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

            expires_str_old = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
            expires_str_new = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), k);

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

        if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
        {
            chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"304-REF-Expires", v);
        }

        /*update old (previous)*/
        chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);

        /*update cache*/
        cmp4_renew_header_cache(cmp4_md_id_t, k, v);

        return (EC_TRUE);
    }

    /*override*/
    if(NULL_PTR != (v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), (const char *)"Date")))
    {
        if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
        {
            chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"304-REF-Date", v);
        }
        t = c_parse_http_time((uint8_t *)v, strlen(v));
    }
    else if(NULL_PTR != (v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), (const char *)"Last-Modified")))
    {
        if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
        {
            chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"304-REF-Last-Modified", v);
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
    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);

    /*update cache*/
    cmp4_renew_header_cache(cmp4_md_id_t, k, v);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_out_304_content_range_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
    CMP4_MD                     *cmp4_md;
    CMP4_MD                     *cmp4_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_content_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_content_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md   = CMP4_MD_GET(cmp4_md_id);
    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);

    /*renew Content-Range in previous rsp*/
    k = (const char *)"Content-Range";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_304_content_range_filter: "
                                             "[status %u] ims rsp has no header '%s' which is\n",
                                             status, k, v);

        chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md_t));

        return (EC_FALSE);
    }
    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_304_content_range_filter: "
                                         "[status %u] renew rsp header '%s':'%s' done\n",
                                         status, k, v);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_out_304_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_304_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    if(EC_FALSE == cmp4_content_ims_header_out_304_last_modified_filter(cmp4_md_id, cmp4_md_id_t, status))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_304_filter: "
                                             "[status %u] last modified filter done\n",
                                             status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_304_filter: "
                                         "[status %u] last modified filter done\n",
                                         status);

    if(EC_FALSE == cmp4_content_ims_header_out_304_expires_filter(cmp4_md_id, cmp4_md_id_t, status))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_304_filter: "
                                             "[status %u] expires filter done\n",
                                             status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_304_filter: "
                                         "[status %u] expires filter done\n",
                                         status);

    if(EC_FALSE == cmp4_content_ims_header_out_304_content_range_filter(cmp4_md_id, cmp4_md_id_t, status))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_304_filter: "
                                             "[status %u] content range filter done\n",
                                             status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_304_filter: "
                                         "[status %u] content range filter done\n",
                                         status);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_304_filter: "
                                         "[status %u] filter done\n",
                                         status);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_out_not_304_last_modified_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
    CMP4_MD                     *cmp4_md;
    CMP4_MD                     *cmp4_md_t;

    const char                  *k;
    const char                  *v;

    time_t                       time_if_modified_since;
    time_t                       time_last_modified;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_last_modified_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_last_modified_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md   = CMP4_MD_GET(cmp4_md_id);
    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);

    /*update rsp header*/
    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_not_304_last_modified_filter: "
                                             "[status %u] ims rsp has no header '%s' which is\n",
                                             status, k, v);

        chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md_t));

        return (EC_FALSE);
    }

    time_if_modified_since = c_parse_http_time(cstring_get_str(CMP4_MD_HEADER_EXPIRES(cmp4_md)),
                                               (size_t)cstring_get_len(CMP4_MD_HEADER_EXPIRES(cmp4_md)));

    time_last_modified = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    if(time_last_modified > time_if_modified_since)/*modified*/
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_last_modified_filter: "
                                             "[status %u] 'Last-Modified':'%s' > 'If-Modified-Since':'%s' "
                                             "=> return false\n",
                                             status,
                                             v,
                                             (char *)cstring_get_str(CMP4_MD_HEADER_EXPIRES(cmp4_md)));

        chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md_t));

        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_last_modified_filter: "
                                         "[status %u] 'Last-Modified':'%s' <= 'If-Modified-Since':'%s' "
                                         "=> ims works\n",
                                         status,
                                         v,
                                         (char *)cstring_get_str(CMP4_MD_HEADER_EXPIRES(cmp4_md)));

    /*renew Last-Modified in previous rsp*/
    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_last_modified_filter: "
                                         "[status %u] renew rsp header '%s':'%s' done\n",
                                         status, k, v);

    /*renew Last-Modified in cache (seg-0)*/
    if(EC_FALSE == cmp4_renew_header_cache(cmp4_md_id_t, k, v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_not_304_last_modified_filter: "
                                             "[status %u] renew cache header '%s':'%s' failed => ignore\n",
                                             status, k, v);
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_last_modified_filter: "
                                         "[status %u] renew cache header '%s':'%s' done\n",
                                         status, k, v);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_out_not_304_expires_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
    CMP4_MD                     *cmp4_md;
    CMP4_MD                     *cmp4_md_t;

    ngx_http_request_t          *r;

    const char                  *k;
    const char                  *v;
    uint32_t                     nsec;
    time_t                       t;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_expires_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_expires_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md   = CMP4_MD_GET(cmp4_md_id);
    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    k = (const char *)CNGX_VAR_ORIG_EXPIRES_OVERRIDE_NSEC;
    if(EC_FALSE == cngx_get_var_uint32_t(r, k, &nsec, 0))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_not_304_expires_filter: "
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

            expires_str_old = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
            expires_str_new = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), k);

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

        if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
        {
            chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"non-304-REF-Expires", v);
        }
        /*update old (previous)*/
        chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);

        /*update cache*/
        cmp4_renew_header_cache(cmp4_md_id_t, k, v);

        return (EC_TRUE);
    }

    /*override*/
    if(NULL_PTR != (v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), (const char *)"Date")))
    {
        if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
        {
            chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"non-304-REF-Date", v);
        }
        t = c_parse_http_time((uint8_t *)v, strlen(v));
    }
    else if(NULL_PTR != (v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), (const char *)"Last-Modified")))
    {
        if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
        {
            chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), (const char *)"non-304-REF-Last-Modified", v);
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
    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);

    /*update cache*/
    cmp4_renew_header_cache(cmp4_md_id_t, k, v);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_out_not_304_content_range_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
    CMP4_MD                     *cmp4_md;
    CMP4_MD                     *cmp4_md_t;

    const char                  *k;
    const char                  *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_content_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_content_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md   = CMP4_MD_GET(cmp4_md_id);
    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);

    /*renew Content-Range in previous rsp*/
    k = (const char *)"Content-Range";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md_t), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_not_304_content_range_filter: "
                                             "[status %u] ims rsp has no header '%s' which is\n",
                                             status, k, v);

        chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md_t));

        return (EC_FALSE);
    }

    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_content_range_filter: "
                                         "[status %u] renew rsp header '%s':'%s' done\n",
                                         status, k, v);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_header_out_not_304_filter(const UINT32 cmp4_md_id, const UINT32 cmp4_md_id_t, uint32_t status)
{
#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id_t) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_header_out_not_304_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id_t);
        dbg_exit(MD_CMP4, cmp4_md_id_t);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    if(EC_FALSE == cmp4_content_ims_header_out_not_304_last_modified_filter(cmp4_md_id, cmp4_md_id_t, status))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_not_304_filter: "
                                             "[status %u] last modified filter done\n",
                                             status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_filter: "
                                         "[status %u] last modified filter done\n",
                                         status);

    if(EC_FALSE == cmp4_content_ims_header_out_not_304_expires_filter(cmp4_md_id, cmp4_md_id_t, status))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_not_304_filter: "
                                             "[status %u] expires filter done\n",
                                             status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_filter: "
                                         "[status %u] expires filter done\n",
                                         status);

    if(EC_FALSE == cmp4_content_ims_header_out_not_304_content_range_filter(cmp4_md_id, cmp4_md_id_t, status))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_header_out_not_304_filter: "
                                             "[status %u] content range filter done\n",
                                             status);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_filter: "
                                         "[status %u] content range filter done\n",
                                         status);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_header_out_not_304_filter: "
                                         "[status %u] filter done\n",
                                         status);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_ims_send_request(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_send_request: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*chttp_req*/
    if(NULL_PTR == CMP4_MD_CHTTP_REQ(cmp4_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_send_request: "
                                                 "new chttp_req failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0096);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_REQ(cmp4_md) = chttp_req;
    }
    else
    {
        chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CMP4_MD_CHTTP_RSP(cmp4_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_send_request: "
                                                 "new chttp_rsp failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0097);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_RSP(cmp4_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CMP4_MD_CHTTP_RSP(cmp4_md);
        chttp_rsp_clean(chttp_rsp);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_send_request: "
                                             "export headers_in to http req failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0098);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmp4_content_ims_header_in_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_send_request: "
                                             "header_in filter failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0099);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_ims_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, NULL_PTR, chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_send_request: "
                                             "http request failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CMP4_0100);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_ims_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_send_request: "
                                         "send request done\n");
    return (EC_TRUE);
}

/*If-Modified-Since procedure*/
EC_BOOL cmp4_content_ims_procedure(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    //ngx_int_t                    rc;

    UINT32                       cmp4_md_id_t;
    CMP4_MD                     *cmp4_md_t;

    uint32_t                     status;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_ims_procedure: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    ASSERT(EC_FALSE == cstring_is_empty(CMP4_MD_HEADER_EXPIRES(cmp4_md)));

    /*create new module*/
    cmp4_md_id_t = cmp4_start(r);
    if(CMPI_ERROR_MODI == cmp4_md_id_t)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_procedure: "
                                             "start cmp4 module failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_procedure: "
                                         "start cmp4 module %ld#\n",
                                         cmp4_md_id_t);

    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);
    CMP4_MD_DEPTH(cmp4_md_t) = CMP4_MD_DEPTH(cmp4_md) + 1;

    /*clone header Expires*/
    cstring_clone(CMP4_MD_HEADER_EXPIRES(cmp4_md), CMP4_MD_HEADER_EXPIRES(cmp4_md_t));
    cstring_clone(CMP4_MD_CACHE_PATH(cmp4_md), CMP4_MD_CACHE_PATH(cmp4_md_t));

    if(EC_FALSE == cmp4_content_ims_send_request(cmp4_md_id_t))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_procedure: "
                                             "send ims request failed\n");
        cmp4_end(cmp4_md_id_t);
        return (EC_FALSE);
    }

    status = CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md_t));
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_procedure: "
                                         "ims rsp status = %u\n",
                                         status);

    if(CHTTP_NOT_MODIFIED == status)
    {
        if(EC_FALSE == cmp4_content_ims_header_out_304_filter(cmp4_md_id, cmp4_md_id_t, status))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_procedure: "
                                                 "[status %u] filter failed\n",
                                                 status);
            cmp4_end(cmp4_md_id_t);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_procedure: "
                                             "[status %u] filter done\n",
                                             status);
        cmp4_end(cmp4_md_id_t);
        return (EC_TRUE);
    }

    /*compare If-Modified-Since and Last-Modified*/
    if(CHTTP_PARTIAL_CONTENT == status || CHTTP_OK == status)
    {
        if(EC_FALSE == cmp4_content_ims_header_out_not_304_filter(cmp4_md_id, cmp4_md_id_t, status))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_ims_procedure: "
                                                 "[status %u] filter failed\n",
                                                 status);
            cmp4_end(cmp4_md_id_t);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_procedure: "
                                             "[status %u] filter done\n",
                                             status);
        cmp4_end(cmp4_md_id_t);
        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "[DEBUG] cmp4_content_ims_procedure: "
                                         "ims rsp status = %u != %u => return false\n",
                                         status, CHTTP_NOT_MODIFIED);
    cmp4_end(cmp4_md_id_t);
    return (EC_FALSE);
}

EC_BOOL cmp4_content_repair_set_store(const UINT32 cmp4_md_id, CHTTP_STORE *chttp_store)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_repair_set_store: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*--- chttp_store settting --- BEG ---*/
    if(CMP4_ERR_SEG_NO == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        CHTTP_STORE_SEG_ID(chttp_store) = 0;
    }
    else
    {
        CHTTP_STORE_SEG_ID(chttp_store) = (uint32_t)CMP4_MD_ABSENT_SEG_NO(cmp4_md);
    }

    CHTTP_STORE_SEG_SIZE(chttp_store)     = CMP4_MD_CACHE_SEG_SIZE(cmp4_md);
    CHTTP_STORE_SEG_S_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;
    CHTTP_STORE_SEG_E_OFFSET(chttp_store) = CHTTP_SEG_ERR_OFFSET;

    cstring_clone(CMP4_MD_CACHE_PATH(cmp4_md), CHTTP_STORE_BASEDIR(chttp_store));

    if(0 == CHTTP_STORE_SEG_ID(chttp_store))
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)   = EC_FALSE;
    }
    else
    {
        CHTTP_STORE_MERGE_FLAG(chttp_store)   = EC_TRUE;
    }

    if(EC_FALSE == cngx_set_store(r, chttp_store))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_set_store: "
                                             "fetch ngx cfg to chttp_store failed\n");
        return (EC_FALSE);
    }

    CHTTP_STORE_CACHE_CTRL(chttp_store) = CHTTP_STORE_CACHE_BOTH;

    /*--- chttp_store settting --- END ---*/

    return (EC_TRUE);
}

EC_BOOL cmp4_content_repair_header_in_filter_port(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_repair_header_in_filter_port: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);

    /*when cngx config repair port*/
    k = (const char *)CNGX_VAR_ORIG_PORT;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter_port: "
                                             "get var '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter_port: "
                                             "[conf] get var '%s':'%s' done\n",
                                             k, v);
        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter_port: "
                                                    "[conf] set port '%s' to http req failed\n",
                                                    v);
            safe_free(v, LOC_CMP4_0101);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter_port: "
                                             "[conf] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0102);
        return (EC_TRUE);
    }

    /*when cngx NOT config repair port*/
    k = (const char *)"server_port";
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter_port: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }
    if(NULL_PTR != v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter_port: "
                                             "[cngx] get var '%s':'%s' done\n",
                                             k, v);

        if(EC_FALSE == chttp_req_set_port(chttp_req, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter_port: "
                                                    "[cngx] set port to http req failed\n",
                                                    v);
            safe_free(v, LOC_CMP4_0103);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter_port: "
                                             "[cngx] set port '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0104);

        return (EC_TRUE);
    }

    /*set default repair port*/
    chttp_req_set_port_word(chttp_req, CNGX_ORIG_PORT_DEFAULT);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                         "[default] set default port '%d' to http req done\n",
                                         CNGX_ORIG_PORT_DEFAULT);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_repair_header_in_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;
    CHTTP_REQ                   *chttp_req;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_repair_header_in_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);

    /*set http request server or ipaddr*/
    do
    {
        /*when cngx config repair server*/
        k = (const char *)CNGX_VAR_ORIG_SERVER;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_server(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "[conf] set server '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0105);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            safe_free(v, LOC_CMP4_0106);

            break; /*ok*/
        }

        /*when cngx config repair host and port*/
        k = (const char *)CNGX_VAR_ORIG_HOST;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[conf] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "[conf] set host '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0107);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[conf] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0108);

            /*set port*/
            if(EC_FALSE == cmp4_content_repair_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*now cngx NOT config repair server and NOT config repair (host, port)*/

        /*try http_host*/
        k = (const char *)"http_host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0109);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0110);

            /*set port*/
            if(EC_FALSE == cmp4_content_repair_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try server_name*/
        k = (const char *)"server_name";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "[cngx] set host of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0111);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0112);

            /*set port*/
            if(EC_FALSE == cmp4_content_repair_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }

        /*try host*/
        k = (const char *)"host";
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "get '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[cngx] get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_ipaddr(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "[cngx] set ipaddr of '%s' failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0113);
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_GATEWAY_TIME_OUT, LOC_CMP4_0016);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[cngx] set host '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0114);

            /*set port*/
            if(EC_FALSE == cmp4_content_repair_header_in_filter_port(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "filter port failed\n");
                return (EC_FALSE);
            }

            break; /*ok*/
        }
    }while(0);

    /*set http request method*/
    if(EC_FALSE == cngx_get_req_method_str(r, &v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                             "get method failed\n");
        return (EC_FALSE);
    }
    if(EC_FALSE == chttp_req_set_method(chttp_req, v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                             "set method '%s' failed\n",
                                             v);
        safe_free(v, LOC_CMP4_0115);
        return (EC_FALSE);
    }
    safe_free(v, LOC_CMP4_0116);

    /*set http request uri*/
    do
    {
        /*when cngx config repair uri*/
        k = (const char *)CNGX_VAR_ORIG_URI;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "get var '%s' failed\n",
                                                 k);
            return (EC_FALSE);
        }

        if(NULL_PTR != v)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "get var '%s':'%s' done\n",
                                                 k, v);

            if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                     "[conf] set uri '%s' to http req failed\n",
                                                     v);
                safe_free(v, LOC_CMP4_0117);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                                 "[conf] set uri '%s' to http req done\n",
                                                 v);
            safe_free(v, LOC_CMP4_0118);

            break; /*ok*/
        }

        /*when cngx NOT config repair uri*/
        if(EC_FALSE == cngx_get_req_uri(r, &v) || NULL_PTR == v)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "get uri failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == chttp_req_set_uri(chttp_req, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "[cngx] set uri '%s' failed\n",
                                                 v);
            safe_free(v, LOC_CMP4_0119);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                             "[cngx] set uri '%s' to http req done\n",
                                             v);
        safe_free(v, LOC_CMP4_0120);

        /*FLV: not carray on args to repair*/
    }while(0);

    /*set keep-alive*/
    k = (const char *)"Connection";
    v = (char       *)"keep-alive";
    chttp_req_renew_header(chttp_req, k, v);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                         "renew req header '%s':'%s' done\n",
                                         k, v);

    /*set range*/
    if(CMP4_ERR_SEG_NO != CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        UINT32      range_start;
        UINT32      range_end;
        char        range[ 32 ];

        if(0 == CMP4_MD_ABSENT_SEG_NO(cmp4_md))
        {
            range_start = 0;
            range_end   = range_start + CMP4_MD_CACHE_SEG_SIZE(cmp4_md) - 1;
        }
        else
        {
            range_start = (CMP4_MD_ABSENT_SEG_NO(cmp4_md) - 1) * CMP4_MD_CACHE_SEG_SIZE(cmp4_md);
            range_end   = range_start + CMP4_MD_CACHE_SEG_SIZE(cmp4_md) - 1;
        }

        if(0 < CMP4_MD_CONTENT_LENGTH(cmp4_md) && range_end >= CMP4_MD_CONTENT_LENGTH(cmp4_md))
        {
            range_end = CMP4_MD_CONTENT_LENGTH(cmp4_md) - 1;
        }

        snprintf(range, sizeof(range), "bytes=%ld-%ld", range_start, range_end);

        k = (const char *)"Range";
        v = (char       *)range;
        if(EC_FALSE == chttp_req_renew_header(chttp_req, k, v))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_header_in_filter: "
                                                 "set header '%s':'%s' failed\n",
                                                 k, v);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_header_in_filter: "
                                             "set header '%s':'%s' done\n",
                                             k, v);
    }

    return cmp4_filter_header_in_common(cmp4_md_id, chttp_req);
}

EC_BOOL cmp4_content_repair_send_request(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    CHTTP_REQ                   *chttp_req;
    CHTTP_RSP                   *chttp_rsp;
    CHTTP_STORE                 *chttp_store;
    CHTTP_STAT                  *chttp_stat;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_repair_send_request: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*chttp_req*/
    if(NULL_PTR == CMP4_MD_CHTTP_REQ(cmp4_md))
    {
        chttp_req = chttp_req_new();
        if(NULL_PTR == chttp_req)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                                 "new chttp_req failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0121);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_REQ(cmp4_md) = chttp_req;
    }
    else
    {
        chttp_req = CMP4_MD_CHTTP_REQ(cmp4_md);
        chttp_req_clean(chttp_req);
    }

    /*chttp_rsp*/
    if(NULL_PTR == CMP4_MD_CHTTP_RSP(cmp4_md))
    {
        chttp_rsp = chttp_rsp_new();
        if(NULL_PTR == chttp_rsp)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                                 "new chttp_rsp failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0122);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_RSP(cmp4_md) = chttp_rsp;
    }
    else
    {
        chttp_rsp = CMP4_MD_CHTTP_RSP(cmp4_md);
        chttp_rsp_clean(chttp_rsp);
    }

    /*chttp_store*/
    if(NULL_PTR == CMP4_MD_CHTTP_STORE(cmp4_md))
    {
        chttp_store = chttp_store_new();
        if(NULL_PTR == chttp_store)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                                 "new chttp_store failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0123);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_STORE(cmp4_md) = chttp_store;
    }
    else
    {
        chttp_store = CMP4_MD_CHTTP_STORE(cmp4_md);
        chttp_store_clean(chttp_store);
    }

    if(EC_FALSE == cmp4_content_repair_set_store(cmp4_md_id, chttp_store))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                             "set chttp_store failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0124);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_send_request: "
                                             "chttp_store is\n");
        chttp_store_print(LOGSTDOUT, chttp_store);
    }

    /*chttp_stat*/
    if(NULL_PTR == CMP4_MD_CHTTP_STAT(cmp4_md))
    {
        chttp_stat = chttp_stat_new();
        if(NULL_PTR == chttp_stat)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                                 "new chttp_stat failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0125);
            return (EC_FALSE);
        }
        CMP4_MD_CHTTP_STAT(cmp4_md)  = chttp_stat;
    }
    else
    {
        chttp_stat = CMP4_MD_CHTTP_STAT(cmp4_md);
        chttp_stat_clean(chttp_stat);
    }

    if(EC_FALSE == cngx_export_header_in(r, chttp_req))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                             "export headers_in to http req failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0126);
        return (EC_FALSE);
    }

    if(EC_FALSE == cmp4_content_repair_header_in_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                             "header_in filter failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0127);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_repair_send_request: http req:\n");
        chttp_req_print_plain(LOGSTDOUT, chttp_req);
    }

    if(EC_FALSE == chttp_request(chttp_req, chttp_store, chttp_rsp, chttp_stat))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_send_request: "
                                             "http request failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_BAD_GATEWAY, LOC_CMP4_0128);
        return (EC_FALSE);
    }
    if(do_log(SEC_0147_CMP4, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cmp4_content_repair_send_request: http rsp:\n");
        chttp_rsp_print_plain(LOGSTDOUT, chttp_rsp);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_send_request: "
                                         "send request done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_repair_fetch_response(const UINT32 cmp4_md_id, const CRANGE_SEG *crange_seg, CBYTES *seg_cbytes)
{
    CMP4_MD                     *cmp4_md;

    CHTTP_RSP                   *chttp_rsp;
    CBYTES                      *rsp_body;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_repair_fetch_response: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    chttp_rsp = CMP4_MD_CHTTP_RSP(cmp4_md);

    rsp_body  = CHTTP_RSP_BODY(chttp_rsp);

    if(0 == CRANGE_SEG_S_OFFSET(crange_seg) && CBYTES_LEN(rsp_body) == CRANGE_SEG_E_OFFSET(crange_seg) + 1)
    {
        cbytes_handover(rsp_body, seg_cbytes);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_fetch_response: "
                                             "handover rsp done\n");
        return (EC_TRUE);
    }

    if(CBYTES_LEN(rsp_body) <= CRANGE_SEG_S_OFFSET(crange_seg))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_fetch_response: "
                                             "body len %ld <= s_offset %ld\n",
                                             CBYTES_LEN(rsp_body),
                                             CRANGE_SEG_S_OFFSET(crange_seg));
        return (EC_FALSE);
    }

    if(CBYTES_LEN(rsp_body) <= CRANGE_SEG_E_OFFSET(crange_seg))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_fetch_response: "
                                             "body len %ld <= e_offset %ld\n",
                                             CBYTES_LEN(rsp_body),
                                             CRANGE_SEG_E_OFFSET(crange_seg));
        return (EC_FALSE);
    }

    ASSERT(CRANGE_SEG_S_OFFSET(crange_seg) <= CRANGE_SEG_E_OFFSET(crange_seg));
    cbytes_append(seg_cbytes, CBYTES_BUF(rsp_body) + CRANGE_SEG_S_OFFSET(crange_seg),
                              CRANGE_SEG_E_OFFSET(crange_seg) + 1 - CRANGE_SEG_S_OFFSET(crange_seg));


    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_fetch_response: "
                                         "copy rsp [%ld, %ld] / %ld done\n",
                                         CRANGE_SEG_S_OFFSET(crange_seg),
                                         CRANGE_SEG_E_OFFSET(crange_seg),
                                         CBYTES_LEN(rsp_body));
    return (EC_TRUE);
}

/*repair the absent seg*/
EC_BOOL cmp4_content_repair_procedure(const UINT32 cmp4_md_id, const CRANGE_SEG *crange_seg, CBYTES *seg_cbytes)
{
    CMP4_MD                     *cmp4_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_repair_procedure: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md) = BIT_TRUE;
    }

    cngx_option_set_cacheable_method(r, CMP4_MD_CNGX_OPTION(cmp4_md));
    if(BIT_TRUE == CMP4_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cmp4_md))
    {
        if(BIT_TRUE == CNGX_OPTION_CACHEABLE_METHOD(CMP4_MD_CNGX_OPTION(cmp4_md)))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: method cachable\n");
            cngx_set_header_out_kv(r, (const char *)CNGX_BGN_MOD_DBG_X_METHOD_CACHABLE_TAG, (const char *)"yes");
        }
        else
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: method not cachable\n");
            cngx_set_header_out_kv(r, (const char *)CNGX_BGN_MOD_DBG_X_METHOD_CACHABLE_TAG, (const char *)"no");
        }
    }

    if(EC_FALSE == cmp4_set_store_cache_path(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_procedure: set store_path failed\n");

        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0129);
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: set store_path '%s'\n",
                    (char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md)));

    if(EC_TRUE == cngx_is_force_orig_switch_on(r))
    {
        CMP4_MD_ORIG_FORCE_FLAG(cmp4_md) = BIT_TRUE;
    }
    else
    {
        CMP4_MD_ORIG_FORCE_FLAG(cmp4_md) = BIT_FALSE;
    }

    /*set absent seg no*/
    CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: "
                                         "set absent_seg_no = %ld\n",
                                         CMP4_MD_ABSENT_SEG_NO(cmp4_md));

    if(EC_FALSE == cmp4_content_repair_send_request(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_procedure: "
                                             "send request failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: "
                                         "send request done\n");

    /*301/302 redirect*/
    if(EC_TRUE == cmp4_is_redirect_rsp(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: "
                                             "301/302 => redirect procedure\n");
        /*return cmp4_content_redirect_procedure(cmp4_md_id);*//*TODO*/
        if(EC_FALSE == cmp4_content_redirect_procedure(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_procedure: "
                                                 "301/302 failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: "
                                             "301/302 done\n");
    }

    /*specific redirect*/
    if(EC_TRUE == cmp4_is_specific_redirect_rsp(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: "
                                             "specific redirect rsp => redirect procedure\n");
        /*return cmp4_content_redirect_procedure(cmp4_md_id);*//*TODO*/
        if(EC_FALSE == cmp4_content_redirect_procedure(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_procedure: "
                                                 "specific redirect rsp failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: "
                                             "specific redirect rsp done\n");
    }

    if(EC_FALSE == cmp4_content_repair_fetch_response(cmp4_md_id, crange_seg, seg_cbytes))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_repair_procedure: "
                                             "fetch response failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_repair_procedure: "
                                         "fetch response done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_expired_header_out_range_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_expired_header_out_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(1) /*renew content-length info*/
    {
        const char *k;
        char       *v;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        /*ignore Content-Length*/

        k = (const char *)"Content-Range";
        v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_header_out_range_filter: "
                                                 "no 'Content-Range' => failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == crange_parse_content_range(v, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_header_out_range_filter: "
                                                 "invalid Content-Range '%s'\n",
                                                 v);
            return (EC_FALSE);
        }

        CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
        CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_header_out_range_filter: "
                                             "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                             v,
                                             range_start, range_end, content_length);
        /*fall through*/
    }

    if(BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        const char                  *k;
        const char                  *v;

        /*no range in cngx http request, return whole content*/

        k = (const char *)"Content-Range";
        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md),k);
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_header_out_range_filter: "
                                             "del rsp header '%s'\n",
                                             k);

        k = (const char *)"Content-Length";
        v = (const char *)c_word_to_str(CMP4_MD_CONTENT_LENGTH(cmp4_md));

        chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md),k, v);
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_header_out_range_filter: "
                                             "renew rsp header '%s'\n",
                                             k);

        return (EC_TRUE);
    }

    /*single range and multiple range*/
    if(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        if(EC_FALSE == cmp4_filter_header_out_range(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_header_out_range_filter: "
                                                 "filter range failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_header_out_range_filter: "
                                             "filter range done\n");
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_header_out_range_filter: "
                                         "done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_expired_header_out_filter(const UINT32 cmp4_md_id)
{
    //CMP4_MD                  *cmp4_md;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_expired_header_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    //cmp4_md = CMP4_MD_GET(cmp4_md_id);

    //r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    k = (const char *)"expired";
    cmp4_filter_header_out_common(cmp4_md_id, k);

    /*Content-Length and Content-Range*/
    if(EC_FALSE == cmp4_content_expired_header_out_range_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_header_out_filter: "
                                             "range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_header_out_filter: "
                                         "range filter done\n");

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_expired_body_out_filter(const UINT32 cmp4_md_id)
{
    //CMP4_MD                  *cmp4_md;

    //ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_expired_body_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    //cmp4_md = CMP4_MD_GET(cmp4_md_id);

    //r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_expired_send_seg_n(const UINT32 cmp4_md_id, const CRANGE_SEG *crange_seg)
{
    CMP4_MD                     *cmp4_md;;
    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_expired_send_seg_n: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    cbytes_init(&seg_cbytes);

    /*force orig*/
    if(BIT_TRUE == CMP4_MD_ORIG_FORCE_FLAG(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_seg_n: "
                                             "force orig, expired seg %ld\n",
                                             CRANGE_SEG_NO(crange_seg));

        /*force change to orig procedure*/
        CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_seg_n: "
                                             "force orig, absent_seg_no %ld => orig\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));

        return cmp4_content_orig_procedure(cmp4_md_id);
    }

    /*no-expired*/
    if(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_seg_n: "
                                             "no-expired => direct, expired seg %ld\n",
                                             CRANGE_SEG_NO(crange_seg));

        /*force change to direct procedure*/
        CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_seg_n: "
                                             "no-expired => direct, absent_seg_no %ld\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));

        return cmp4_content_direct_procedure(cmp4_md_id);
    }

    if(EC_FALSE == cmp4_get_cache_seg_n(cmp4_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_seg_n: "
                                             "get cache seg %ld failed\n",
                                             CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);

        if(BIT_TRUE == CNGX_OPTION_ONLY_IF_CACHED(CMP4_MD_CNGX_OPTION(cmp4_md)))
        {
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_SERVICE_UNAVAILABLE, LOC_CMP4_0002);

            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_seg_n: "
                                                 "only-if-cached is true => %u\n",
                                                 NGX_HTTP_SERVICE_UNAVAILABLE);
            return (EC_FALSE);
        }

        /*change to orig procedure*/
        CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_seg_n: "
                                             "absent_seg_no %ld => orig\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));

        return cmp4_content_orig_procedure(cmp4_md_id);
    }

    cmp4_content_expired_body_out_filter(cmp4_md_id);

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    if(EC_FALSE == cngx_send_body(r, data, len,
                     /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                     &(CMP4_MD_NGX_RC(cmp4_md))))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_seg_n: "
                                             "send body seg %ld failed\n",
                                             CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_seg_n: "
                                         "send body seg %ld: %ld bytes done\n",
                                         CRANGE_SEG_NO(crange_seg), CBYTES_LEN(&seg_cbytes));

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_expired_send_node(const UINT32 cmp4_md_id, CRANGE_NODE *crange_node)
{
    CMP4_MD                     *cmp4_md;;
    ngx_http_request_t          *r;

    CRANGE_SEG                  *crange_seg;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_expired_send_node: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(EC_FALSE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;

        boundary = CRANGE_NODE_BOUNDARY(crange_node);

        cmp4_content_expired_body_out_filter(cmp4_md_id);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        if(EC_FALSE == cngx_send_body(r, data, len,
                         /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                         &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_node: "
                                                 "send body boundary failed\n");

            return (EC_FALSE);
        }

        CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_node: "
                                             "send body boundary: %ld bytes done\n",
                                             CSTRING_LEN(boundary));

        /*clean boundary which was sent out*/
        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    }

    while(NULL_PTR != (crange_seg = crange_node_first_seg(crange_node)))
    {        UINT32      seg_no;

        seg_no = CRANGE_SEG_NO(crange_seg); /*range_seg may be free at other place, save it here*/

        if(EC_FALSE == cmp4_content_expired_send_seg_n(cmp4_md_id, crange_seg))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_node: "
                                                 "send expired seg %ld failed\n",
                                                 seg_no);

            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_node: "
                                             "send expired seg %ld done => sent body %ld bytes\n",
                                             seg_no,
                                             CMP4_MD_SENT_BODY_SIZE(cmp4_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_node: "
                                                 "pop seg %ld\n",
                                                 CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_content_expired_send_response(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;

    CRANGE_MGR                  *crange_mgr;
    CRANGE_NODE                 *crange_node;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_expired_send_response: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    crange_mgr = CMP4_MD_CNGX_RANGE_MGR(cmp4_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        /*no-cache*/
        if(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
        {
            dbg_log(SEC_0147_CMP4, 1)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_response: "
                                                 "expired => direct send response\n");
            return cmp4_content_direct_send_response(cmp4_md_id);
        }

        if(EC_FALSE == cmp4_content_expired_header_out_filter(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_response: "
                                                 "header_out filter failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0130);
            return (EC_FALSE);
        }

        if(do_log(SEC_0147_CMP4, 9))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_response: "
                                                 "rsp:\n");
            chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md));
        }

        cngx_import_header_out(r, CMP4_MD_CHTTP_RSP(cmp4_md));

        cngx_disable_write_delayed(r);

        if(EC_TRUE == crange_mgr_is_empty(crange_mgr))
        {
            cngx_set_header_only(r);
        }

        if(EC_FALSE == cngx_send_header(r, &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_response: "
                                                 "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_response: "
                                             "send header done\n");
    }

    /*send body*/
    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_response: "
                                             "before send body, crange_mgr:\n");
        crange_mgr_print(LOGSTDOUT, crange_mgr);
    }

    /*send body: ranges*/
    while(NULL_PTR != (crange_node = crange_mgr_first_node(crange_mgr)))
    {
        if(EC_FALSE == cmp4_content_expired_send_node(cmp4_md_id, crange_node))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_response: "
                                                 "send node (%ld:%s, %ld:%s) failed\n",
                                                 CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                 CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_response: "
                                             "send node (%ld:%s, %ld:%s) done => sent body %ld bytes\n",
                                             CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                             CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                             CMP4_MD_SENT_BODY_SIZE(cmp4_md));

        if(crange_mgr_first_node(crange_mgr) == crange_node)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_node: "
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

        boundary = CRANGE_MGR_BOUNDARY(crange_mgr);

        cmp4_content_expired_body_out_filter(cmp4_md_id);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        if(EC_FALSE == cngx_send_body(r, data, len,
                         /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                         &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_expired_send_response: "
                                                 "send body boundary failed\n");

            return (EC_FALSE);
        }

        CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_response: "
                                             "send body boundary: %ld bytes done\n",
                                             CSTRING_LEN(boundary));
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_send_response: "
                                         "send body done => complete %ld bytes\n",
                                         CMP4_MD_SENT_BODY_SIZE(cmp4_md));
    return (EC_TRUE);
}

EC_BOOL cmp4_content_expired_procedure(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    ngx_int_t                    rc;

    UINT32                       cmp4_md_id_t;
    CMP4_MD                     *cmp4_md_t;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_expired_procedure: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    ASSERT(BIT_TRUE == CMP4_MD_CACHE_EXPIRED_FLAG(cmp4_md));

    /*check If-Modified-Since*/
    if(EC_FALSE == cstring_is_empty(CMP4_MD_HEADER_EXPIRES(cmp4_md)))
    {
        const char      *cache_status;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "found Expires '%s' => ims\n",
                                             (char *)cstring_get_str(CMP4_MD_HEADER_EXPIRES(cmp4_md)));

        if(EC_TRUE == cmp4_content_ims_procedure(cmp4_md_id))
        {
            cache_status = (const char *)CNGX_CACHE_STATUS_REFRESH_HIT;
            CMP4_MD_CACHE_STATUS(cmp4_md) = cache_status;
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                                 "ims succ => cache_status = %s\n",
                                                 cache_status);
            return cmp4_content_expired_send_response(cmp4_md_id);
        }

        cache_status = (const char *)CNGX_CACHE_STATUS_REFRESH_MISS;
        CMP4_MD_CACHE_STATUS(cmp4_md) = cache_status;
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "ims fail => cache_status = %s\n",
                                             cache_status);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "ims fail => cache ddir '%s'\n",
                                             (char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md)));
        ccache_dir_delete(CMP4_MD_CACHE_PATH(cmp4_md));
    }
    else
    {
        const char      *cache_status;

        cache_status = (const char *)CNGX_CACHE_STATUS_REFRESH_MISS;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "not found Expires => expired\n");

        CMP4_MD_CACHE_STATUS(cmp4_md) = cache_status;
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "not found Expires => cache_status = %s\n",
                                             cache_status);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "not found Expires => cache ddir '%s'\n",
                                             (char *)cstring_get_str(CMP4_MD_CACHE_PATH(cmp4_md)));
        ccache_dir_delete(CMP4_MD_CACHE_PATH(cmp4_md));
    }

    /*create new module*/
    cmp4_md_id_t = cmp4_start(r);
    if(CMPI_ERROR_MODI == cmp4_md_id_t)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "start cmp4 module failed\n");
        return (EC_FALSE);
    }

    cmp4_md_t = CMP4_MD_GET(cmp4_md_id_t);
    CMP4_MD_DEPTH(cmp4_md_t) = CMP4_MD_DEPTH(cmp4_md) + 1;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                         "start cmp4 module %ld#\n",
                                         cmp4_md_id_t);

    dbg_log(SEC_0147_CMP4, 1)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                         "expired => orig procedure\n");

    if(EC_FALSE == cmp4_content_handler(cmp4_md_id_t))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                             "error:content handler failed, stop module %ld#\n",
                                             cmp4_md_id_t);

        cmp4_get_ngx_rc(cmp4_md_id_t, &rc, NULL_PTR);
        cmp4_set_ngx_rc(cmp4_md_id, rc, LOC_CMP4_0131);

        cmp4_end(cmp4_md_id_t);
        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_expired_procedure: "
                                         "[DEBUG] content handler done, stop module %ld#\n",
                                         cmp4_md_id_t);

    cmp4_get_ngx_rc(cmp4_md_id_t, &rc, NULL_PTR);
    cmp4_set_ngx_rc(cmp4_md_id, rc, LOC_CMP4_0132);

    cmp4_end(cmp4_md_id_t);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_parse_header(const UINT32 cmp4_md_id, const CBYTES *header_cbytes)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_parse_header: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    if(NULL_PTR != CMP4_MD_CHTTP_RSP(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_parse_header: "
                                             "free old chttp_rsp %p\n",
                                             CMP4_MD_CHTTP_RSP(cmp4_md));

        chttp_rsp_free(CMP4_MD_CHTTP_RSP(cmp4_md));
        CMP4_MD_CHTTP_RSP(cmp4_md) = NULL_PTR;
    }

    CMP4_MD_CHTTP_RSP(cmp4_md) = chttp_rsp_new();
    if(NULL_PTR == CMP4_MD_CHTTP_RSP(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_parse_header: "
                                             "new chttp_rsp failed\n");

        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0133);
        return (EC_FALSE);
    }

    if(EC_FALSE == ccache_parse_header(header_cbytes, CMP4_MD_CHTTP_RSP(cmp4_md)))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_parse_header: "
                                             "parse header failed\n");

        cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0134);
        return (EC_FALSE);
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_parse_header: "
                                             "header '\n%.*s\n' => \n",
                                             CBYTES_LEN(header_cbytes),
                                             (char *)CBYTES_BUF(header_cbytes));

        chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md));
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_header_out_if_modified_since_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

    time_t                       ims_1st; /*if-modifed-since in cngx http req*/
    time_t                       ims_2nd; /*last-modified in response (seg-0 in storage)*/

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_header_out_if_modified_since_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    k = (const char *)"If-Modified-Since";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_if_modified_since_filter: "
                                             "[cngx] get '%s' failed\n",
                                             k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_if_modified_since_filter: "
                                             "[cngx] no '%s'\n",
                                             k);
        return (EC_TRUE);
    }

    ims_1st = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    safe_free(v, LOC_CMP4_0135);

    k = (const char *)"Last-Modified";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_if_modified_since_filter: "
                                             "[rsp] no '%s'\n",
                                             k);
        return (EC_TRUE);
    }

    ims_2nd = c_parse_http_time((uint8_t *)v, (size_t)strlen(v));

    if(ims_1st < ims_2nd)
    {
        if(CHTTP_PARTIAL_CONTENT != CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)))
        {
            /*set rsp status to 200*/
            CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_OK;

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_if_modified_since_filter: "
                                                 "set rsp status = %u\n",
                                                 CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        }

        return (EC_TRUE);
    }

    /*set rsp status to 304*/
    CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_NOT_MODIFIED;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_if_modified_since_filter: "
                                         "set rsp status = %u\n",
                                         CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));

    crange_mgr_clean(CMP4_MD_CNGX_RANGE_MGR(cmp4_md));

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_if_modified_since_filter: "
                                         "clean cngx range mgr\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_header_out_range_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_header_out_range_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    while(BIT_FALSE == CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md))
    {
        const char *k;
        char       *v;

        UINT32      range_start;
        UINT32      range_end;
        UINT32      content_length;

        k = (const char *)"Content-Range";
        v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_range_filter: "
                                                 "no 'Content-Range' => failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == crange_parse_content_range(v, &range_start, &range_end, &content_length))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_range_filter: "
                                                 "invalid Content-Range '%s'\n",
                                                 v);
            return (EC_FALSE);
        }

        CMP4_MD_CONTENT_LENGTH_EXIST_FLAG(cmp4_md) = BIT_TRUE;
        CMP4_MD_CONTENT_LENGTH(cmp4_md)            = content_length;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_range_filter: "
                                             "parse Content-Range '%s' to [%ld, %ld] / %ld\n",
                                             v,
                                             range_start, range_end, content_length);
        break; /*fall through*/
    }

    /*single range and multiple range*/
    if(BIT_TRUE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        if(EC_FALSE == cmp4_filter_header_out_range(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_range_filter: "
                                                 "filter range failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_range_filter: "
                                             "filter range done\n");
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_range_filter: "
                                         "done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_header_out_status_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_header_out_status_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    k = (const char *)"Response-Status";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
    if(NULL_PTR != v)
    {
        uint32_t        response_status;

        chttp_rsp_del_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);

        response_status = c_str_to_uint32_t(v);

        if(CHTTP_NOT_FOUND == response_status)
        {
            cmp4_set_ngx_rc(cmp4_md_id, CHTTP_NOT_FOUND, LOC_CMP4_0104);

            CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = response_status;
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_status_filter: "
                                                 "[cngx] found 404 => response status = %ld [after]\n",
                                                 k,
                                                 CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
            return (EC_TRUE);            
        }
        
        k = (const char *)"Location";
        if((CHTTP_MOVED_PERMANENTLY == response_status || CHTTP_MOVED_TEMPORARILY == response_status)
        && EC_TRUE == chttp_rsp_has_header_key(CMP4_MD_CHTTP_RSP(cmp4_md), k))/*has 'Location'*/
        {
            CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = response_status;
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_status_filter: "
                                                 "[cngx] found 301/302 and '%s' => response status = %ld [after]\n",
                                                 k,
                                                 CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
            return (EC_TRUE);
        }
    }

    if(BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md))
    {
        CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_OK;
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_status_filter: "
                                             "[cngx] no range => response status = %ld [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    k = (const char *)"Content-Range";
    if(EC_TRUE == chttp_rsp_has_header_key(CMP4_MD_CHTTP_RSP(cmp4_md), k))
    {
        CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_status_filter: "
                                             "'Content-Range' exist => response status = %ld [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    if(1 < crange_mgr_node_num(CMP4_MD_CNGX_RANGE_MGR(cmp4_md)))
    {
        CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_PARTIAL_CONTENT;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_status_filter: "
                                             "[cngx] multi range => response status = %ld [after]\n",
                                             CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));
        return (EC_TRUE);
    }

    CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)) = CHTTP_OK;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_status_filter: "
                                         "response status = %ld\n",
                                         CHTTP_RSP_STATUS(CMP4_MD_CHTTP_RSP(cmp4_md)));

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_header_out_expires_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    ngx_http_request_t          *r;
    const char                  *k;
    const char                  *v;

    time_t                       expires;
    time_t                       curtime;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_header_out_expires_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    k = (const char *)"Expires";
    v = chttp_rsp_get_header(CMP4_MD_CHTTP_RSP(cmp4_md), k);
    if(NULL_PTR == v)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                                "not found '%s' => done\n",
                                                k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                         "get '%s':'%s'\n",
                                         k, v);

    curtime = task_brd_default_get_time();

    if(EC_FALSE == c_str_is_digit(v))
    {
        expires = c_parse_http_time((uint8_t *)v, strlen(v));
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                             "'%s' => %d\n",
                                             v, expires);
        if(expires >= curtime)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                                 "expires '%d' >= curtime '%d'\n",
                                                 expires, curtime);
            /*not expired yet*/
            return (EC_TRUE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                             "expires '%d' < curtime '%d' => set cache_expired_flag to true\n",
                                             expires, curtime);

        /*REFRESH_HIT or REFRESH_MISS*/
        CMP4_MD_CACHE_EXPIRED_FLAG(cmp4_md) = BIT_TRUE;

        cstring_append_str(CMP4_MD_HEADER_EXPIRES(cmp4_md), (const UINT8 *)v);
        return (EC_TRUE);
    }

    expires = (time_t)c_str_to_word(v);
    if(0 == expires)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                             "expires = %d => set cache_expired_flag to true\n",
                                             expires);

        /*REFRESH_HIT or REFRESH_MISS*/
        CMP4_MD_CACHE_EXPIRED_FLAG(cmp4_md) = BIT_TRUE;

        v = c_http_time(curtime);
        cstring_append_str(CMP4_MD_HEADER_EXPIRES(cmp4_md), (const UINT8 *)v);
        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                         "expires = %d\n",
                                         expires);

    v = c_http_time(curtime + expires);

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                         "'renew %s':'%s'\n",
                                         k, v);

    chttp_rsp_renew_header(CMP4_MD_CHTTP_RSP(cmp4_md), k, v);

    if(CMP4_ERR_SEG_NO != CMP4_MD_ABSENT_SEG_NO(cmp4_md))
    {
        /*miss*/
        v = (const char *)CNGX_CACHE_STATUS_MISS;
        CMP4_MD_CACHE_STATUS(cmp4_md) = v;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                             "set cache status to '%s' done\n",
                                             v);
        return (EC_TRUE);
    }

    /*hit*/
    v = (const char *)CNGX_CACHE_STATUS_HIT;
    CMP4_MD_CACHE_STATUS(cmp4_md) = v;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_expires_filter: "
                                         "set cache status to '%s' done\n",
                                         v);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_header_out_mp4_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_header_out_mp4_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    /*parse mp4 meta*/
    if(BIT_FALSE == CMP4_MD_ORIG_FORCE_FLAG(cmp4_md)
    && BIT_FALSE == CMP4_MD_CNGX_RANGE_EXIST_FLAG(cmp4_md)
    && 0 < CMP4_MD_MP4_START(cmp4_md))
    {
        if(EC_FALSE == cmp4_get_meta(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_mp4_filter: "
                                                 "get meta failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_mp4_filter: "
                                             "get meta done\n");

        if(EC_FALSE == cmp4_filter_header_out_no_range(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_mp4_filter: "
                                                 "no range filter failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_mp4_filter: "
                                             "no range filter done\n");

        if(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id))
        {
            crange_mgr_clean(CMP4_MD_CNGX_RANGE_MGR(cmp4_md));
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_mp4_filter: "
                                                 "mp4 out chain exist => clean up crange mgr\n");
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_mp4_filter: "
                                             "mp4 filter done\n");
        return (EC_TRUE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_mp4_filter: "
                                         "mp4 filter done\n");
    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_header_out_filter(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

    //ngx_http_request_t          *r;
    const char                  *k;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_header_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    //r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    k = (const char *)"cache";
    cmp4_filter_header_out_common(cmp4_md_id, k);
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_filter: "
                                         "common filter done\n");

    /*mp4 filter Content-Range*/
    if(EC_FALSE == cmp4_content_cache_header_out_range_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_filter: "
                                             "range filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_filter: "
                                         "range filter done\n");

    /*mp4 filter*/
    if(EC_FALSE == cmp4_content_cache_header_out_mp4_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_filter: "
                                             "mp4 filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_filter: "
                                         "mp4 filter done\n");

    if(EC_FALSE == cmp4_content_cache_header_out_status_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_filter: "
                                             "status filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_filter: "
                                         "status filter done\n");

    if(EC_FALSE == cmp4_content_cache_header_out_if_modified_since_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_filter: "
                                             "if-modified-since filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_filter: "
                                         "if-modified-since filter done\n");

    if(EC_FALSE == cmp4_content_cache_header_out_expires_filter(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_header_out_filter: "
                                             "expires filter failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_filter: "
                                         "expires filter done\n");

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_header_out_filter: done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_body_out_filter(const UINT32 cmp4_md_id, const UINT32 seg_no, uint8_t **data, uint32_t *len)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_body_out_filter: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_send_seg_n(const UINT32 cmp4_md_id, const CRANGE_SEG *crange_seg)
{
    CMP4_MD                     *cmp4_md;;
    ngx_http_request_t          *r;
    CBYTES                       seg_cbytes;
    uint8_t                     *data;
    uint32_t                     len;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_send_seg_n: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    ASSERT(0 < CRANGE_SEG_NO(crange_seg));

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    cbytes_init(&seg_cbytes);

    /*force orig*/
    if(BIT_TRUE == CMP4_MD_ORIG_FORCE_FLAG(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_seg_n: "
                                             "force orig, cache seg %ld\n",
                                             CRANGE_SEG_NO(crange_seg));

        /*force change to orig procedure*/
        CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_seg_n: "
                                             "force orig, absent_seg_no %ld => orig\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));

        return cmp4_content_orig_procedure(cmp4_md_id);
    }

    /*no-cache*/
    if(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_seg_n: "
                                             "no-cache => direct, cache seg %ld\n",
                                             CRANGE_SEG_NO(crange_seg));

        /*force change to direct procedure*/
        CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_seg_n: "
                                             "no-cache => direct, absent_seg_no %ld\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));

        return cmp4_content_direct_procedure(cmp4_md_id);
    }

    if(EC_FALSE == cmp4_get_cache_seg_n(cmp4_md_id, crange_seg, &seg_cbytes))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_seg_n: "
                                             "get cache seg %ld failed\n",
                                             CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);

        if(BIT_TRUE == CNGX_OPTION_ONLY_IF_CACHED(CMP4_MD_CNGX_OPTION(cmp4_md)))
        {
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_SERVICE_UNAVAILABLE, LOC_CMP4_0002);

            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_seg_n: "
                                                "only-if-cached is true => %u\n",
                                                NGX_HTTP_SERVICE_UNAVAILABLE);
            return (EC_FALSE);
        }

        /*change to orig procedure*/
        CMP4_MD_ABSENT_SEG_NO(cmp4_md) = CRANGE_SEG_NO(crange_seg);

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_seg_n: "
                                             "absent_seg_no %ld => orig\n",
                                             CMP4_MD_ABSENT_SEG_NO(cmp4_md));

        return cmp4_content_orig_procedure(cmp4_md_id);
    }

    data = (uint8_t *)CBYTES_BUF(&seg_cbytes);
    len  = (uint32_t)CBYTES_LEN(&seg_cbytes);

    cmp4_content_cache_body_out_filter(cmp4_md_id, CRANGE_SEG_NO(crange_seg), &data, &len);

    if(EC_FALSE == cngx_send_body(r, data, len,
                     /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                     &(CMP4_MD_NGX_RC(cmp4_md))))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_seg_n: "
                                             "send body seg %ld failed\n",
                                             CRANGE_SEG_NO(crange_seg));

        cbytes_clean(&seg_cbytes);
        return (EC_FALSE);
    }

    CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_seg_n: "
                                         "send body seg %ld: %ld bytes done\n",
                                         CRANGE_SEG_NO(crange_seg), CBYTES_LEN(&seg_cbytes));

    cbytes_clean(&seg_cbytes);

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_send_node(const UINT32 cmp4_md_id, CRANGE_NODE *crange_node)
{
    CMP4_MD                     *cmp4_md;
    ngx_http_request_t          *r;

    CRANGE_SEG                  *crange_seg;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_send_node: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    if(EC_FALSE == cstring_is_empty(CRANGE_NODE_BOUNDARY(crange_node)))
    {
        CSTRING     *boundary;
        uint8_t     *data;
        uint32_t     len;

        boundary = CRANGE_NODE_BOUNDARY(crange_node);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        if(EC_FALSE == cngx_send_body(r, data, len,
                         /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                         &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_node: "
                                                 "send body boundary failed\n");

            return (EC_FALSE);
        }

        CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_node: "
                                             "send body boundary: %ld bytes done\n",
                                             CSTRING_LEN(boundary));

        /*clean boundary which was sent out*/
        cstring_clean(CRANGE_NODE_BOUNDARY(crange_node));
    }

    while(NULL_PTR != (crange_seg = crange_node_first_seg(crange_node)))
    {
        UINT32      seg_no;

        seg_no = CRANGE_SEG_NO(crange_seg); /*range_seg may be free at other place, save it here*/

        if(EC_FALSE == cmp4_content_cache_send_seg_n(cmp4_md_id, crange_seg))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_node: "
                                                 "send cache seg %ld failed\n",
                                                 seg_no);

            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_node: "
                                             "send cache seg %ld done => sent body %ld bytes\n",
                                             seg_no,
                                             CMP4_MD_SENT_BODY_SIZE(cmp4_md));

        if(crange_node_first_seg(crange_node) == crange_seg)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_node: "
                                                 "pop seg %ld\n",
                                                 CRANGE_SEG_NO(crange_seg));
            crange_node_first_seg_pop(crange_node);
            crange_seg_free(crange_seg);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_send_mp4_meta(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;

    cngx_mp4_file_t             *mp4;
    ngx_chain_t                 *out;
    ngx_chain_t                **t;

    ngx_int_t                    rc;

    UINT32                       len;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_send_mp4_meta: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    ASSERT(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id));

    mp4 = CMP4_MD_MP4(cmp4_md);

    out = mp4->out;
    t   = &(out->next);
    len = 0;

    while(NULL_PTR != (*t)
    && NULL_PTR != (*t)->buf
    && 0 == (*t)->buf->in_file
#if 0
    && 0 == (*t)->buf->sync
    && 0 == (*t)->buf->flush
    && 0 == (*t)->buf->last_in_chain
#endif
    )
    {
        len += (*t)->buf->last - (*t)->buf->pos;
        t = &((*t)->next);
    }

    if(NULL_PTR != (*t))
    {
        mp4->out = (*t);
        (*t)    = NULL_PTR;
    }
    else
    {
        mp4->out = NULL_PTR;
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_mp4_meta: "
                                             "to send out chain: \n");
        cmp4_print_ngx_chain(LOGSTDOUT, 0, out);
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
    }

    ASSERT(0 == out->buf->in_file);

    rc = ngx_http_output_filter(r, out);
    /*rc = ngx_http_write_filter(r, out);*//*no meaningful to takeover/skip ngx body filter*/
    if(rc == NGX_ERROR || rc > NGX_OK)
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_mp4_meta: send body failed\n");
        cmp4_set_ngx_rc(cmp4_md_id, rc, LOC_CMP4_0136);
        return (EC_FALSE);
    }

    if(rc == NGX_AGAIN/* || b->last > b->pos + NGX_LUA_OUTPUT_BLOCKING_LOWAT*/)
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_mp4_meta: need send body again\n");

        return cngx_send_blocking(r);
    }

    CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_mp4_meta: "
                                         "done => sent body %ld bytes\n",
                                         CMP4_MD_SENT_BODY_SIZE(cmp4_md));

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_add_mp4_range(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;
    cngx_mp4_file_t             *mp4;
    ngx_chain_t                 *out;

    UINT32                       offset_start;
    UINT32                       offset_end;
    UINT32                       seg_size;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_add_mp4_range: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);
    mp4 = CMP4_MD_MP4(cmp4_md);
    out = mp4->out;

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_add_mp4_range: "
                                             "to send out chain: \n");
        cmp4_print_ngx_chain(LOGSTDOUT, 0, out);
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG]---------------------------------------\n");
    }

    /*now data in file, and chain length is one*/
    ASSERT(NULL_PTR == out->next);
    ASSERT(NULL_PTR != out->buf);

    ASSERT(1 == out->buf->in_file);
    ASSERT(out->buf->file_pos <= out->buf->file_last);

    mp4->out = NULL_PTR;

    offset_start = (UINT32)out->buf->file_pos;
    offset_end   = (UINT32)out->buf->file_last;
    seg_size     = CMP4_MD_CACHE_SEG_SIZE(cmp4_md);

    if(EC_FALSE == crange_mgr_add_range(CMP4_MD_CNGX_RANGE_MGR(cmp4_md),
                                        offset_start,
                                        offset_end,
                                        seg_size))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_add_mp4_range: "
                                             "split [%ld, %ld] into segs failed\n",
                                             offset_start, offset_end);

        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_add_mp4_range: "
                                         "split [%ld, %ld] into segs done\n",
                                         offset_start, offset_end);
    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_send_mp4_meta_end(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_send_mp4_meta_end: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);
    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0,
                     CNGX_SEND_BODY_NO_MORE_FLAG/* | CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG*/,
                     &(CMP4_MD_NGX_RC(cmp4_md))))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_mp4_meta_end: "
                                             "send body chain-end failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_mp4_meta_end: "
                                         "send chain-end done\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_send_ahead_body(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_send_ahead_body: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    ASSERT(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id));

    if(EC_FALSE == cmp4_content_cache_send_mp4_meta(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_ahead_body: "
                                             "send meta failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_ahead_body: "
                                         "send meta => OK\n");
    if(EC_FALSE == cmp4_content_cache_add_mp4_range(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_ahead_body: "
                                             "add range failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_ahead_body: "
                                         "add range => OK\n");

    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_send_response(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;

    ngx_http_request_t          *r;

    CRANGE_MGR                  *crange_mgr;
    CRANGE_NODE                 *crange_node;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_send_response: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    r = CMP4_MD_NGX_HTTP_REQ(cmp4_md);

    crange_mgr = CMP4_MD_CNGX_RANGE_MGR(cmp4_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        /*no-cache*/
        if(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
        {
            dbg_log(SEC_0147_CMP4, 1)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                                 "cache => direct send response\n");
            return cmp4_content_direct_send_response(cmp4_md_id);
        }

        if(EC_FALSE == cmp4_content_cache_header_out_filter(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_response: "
                                                 "header_out filter failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CMP4_0137);
            return (EC_FALSE);
        }

        if(BIT_TRUE == CMP4_MD_CACHE_EXPIRED_FLAG(cmp4_md))
        {
            dbg_log(SEC_0147_CMP4, 1)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                                 "cache => expired procedure\n");
            return cmp4_content_expired_procedure(cmp4_md_id);
        }

        if(do_log(SEC_0147_CMP4, 9))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                                 "send header:\n");
            chttp_rsp_print_plain(LOGSTDOUT, CMP4_MD_CHTTP_RSP(cmp4_md));
        }

        cngx_import_header_out(r, CMP4_MD_CHTTP_RSP(cmp4_md));

        cngx_disable_write_delayed(r);

        if(EC_TRUE == crange_mgr_is_empty(crange_mgr)
        && EC_FALSE == cmp4_has_mp4_out(cmp4_md_id))
        {
            cngx_set_header_only(r);
        }

        if(EC_FALSE == cngx_send_header(r, &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_response: "
                                                 "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                             "send header done\n");
    }

    /*send body*/
    /*send body: chain*/
    if(EC_TRUE == cmp4_has_mp4_out(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                             "mp4 out chain exist => send ahead body\n");
        if(EC_FALSE == cmp4_content_cache_send_ahead_body(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_response: "
                                                 "send mp4 ahead body failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                             "send mp4 ahead body done\n");
    }

    if(do_log(SEC_0147_CMP4, 9))
    {
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                             "before send body, crange_mgr:\n");
        crange_mgr_print(LOGSTDOUT, crange_mgr);
    }

    /*send body: ranges*/
    while(NULL_PTR != (crange_node = crange_mgr_first_node(crange_mgr)))
    {
        if(EC_FALSE == cmp4_content_cache_send_node(cmp4_md_id, crange_node))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_response: "
                                                 "send node (%ld:%s, %ld:%s) failed\n",
                                                 CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                                 CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)));

            return (EC_FALSE);
        }

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                             "send node (%ld:%s, %ld:%s) done => sent body %ld bytes\n",
                                             CRANGE_NODE_RANGE_START(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_START(crange_node)),
                                             CRANGE_NODE_RANGE_END(crange_node), c_bool_str(CRANGE_NODE_SUFFIX_END(crange_node)),
                                             CMP4_MD_SENT_BODY_SIZE(cmp4_md));

        if(crange_mgr_first_node(crange_mgr) == crange_node)
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_node: "
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

        boundary = CRANGE_MGR_BOUNDARY(crange_mgr);

        data = (uint8_t *)CSTRING_STR(boundary);
        len  = (uint32_t)CSTRING_LEN(boundary);

        if(EC_FALSE == cngx_send_body(r, data, len,
                         /*CNGX_SEND_BODY_NO_MORE_FLAG | */CNGX_SEND_BODY_FLUSH_FLAG | CNGX_SEND_BODY_RECYCLED_FLAG,
                         &(CMP4_MD_NGX_RC(cmp4_md))))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_send_response: "
                                                 "send body boundary failed\n");

            return (EC_FALSE);
        }

        CMP4_MD_SENT_BODY_SIZE(cmp4_md) += len;

        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                             "send body boundary: %ld bytes done\n",
                                             CSTRING_LEN(boundary));
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_send_response: "
                                         "send body done => complete %ld bytes\n",
                                         CMP4_MD_SENT_BODY_SIZE(cmp4_md));
    return (EC_TRUE);
}

EC_BOOL cmp4_content_cache_procedure(const UINT32 cmp4_md_id)
{
    CMP4_MD                     *cmp4_md;;

#if ( SWITCH_ON == CMP4_DEBUG_SWITCH )
    if ( CMP4_MD_ID_CHECK_INVALID(cmp4_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cmp4_content_cache_procedure: cmp4 module #0x%lx not started.\n",
                cmp4_md_id);
        dbg_exit(MD_CMP4, cmp4_md_id);
    }
#endif/*CMP4_DEBUG_SWITCH*/

    cmp4_md = CMP4_MD_GET(cmp4_md_id);

    /*fetch header from cache*/
    do
    {
        UINT32                       seg_no;
        CBYTES                       seg_cbytes;

        seg_no = 0;

        if(BIT_TRUE == CMP4_MD_ORIG_FORCE_FLAG(cmp4_md))
        {
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                                 "force orig, seg %ld\n",
                                                 seg_no);

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                                 "force orig, absent_seg_no %ld => orig\n",
                                                 seg_no);

            /*change to orig procedure*/
            CMP4_MD_ABSENT_SEG_NO(cmp4_md) = seg_no;
            if(EC_FALSE == cmp4_content_orig_procedure(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                                     "force orig, orig send absent seg %ld failed\n",
                                                     seg_no);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                                 "force orig, orig send absent seg %ld done\n",
                                                 seg_no);

            break;/*fall through*/
        }

        cbytes_init(&seg_cbytes);

        if(EC_FALSE == cmp4_get_cache_seg(cmp4_md_id, seg_no, &seg_cbytes))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                                 "fetch seg %ld from cache failed\n",
                                                 seg_no);

            cbytes_clean(&seg_cbytes);

            if(BIT_TRUE == CNGX_OPTION_ONLY_IF_CACHED(CMP4_MD_CNGX_OPTION(cmp4_md)))
            {
                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_SERVICE_UNAVAILABLE, LOC_CMP4_0002);

                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                                     "only-if-cached is true => %u\n",
                                                     NGX_HTTP_SERVICE_UNAVAILABLE);
                return (EC_FALSE);
            }

            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                                 "absent_seg_no %ld => orig\n",
                                                 seg_no);

            /*change to orig procedure*/
            CMP4_MD_ABSENT_SEG_NO(cmp4_md) = seg_no;

            if(EC_FALSE == cmp4_content_orig_procedure(cmp4_md_id))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                                     "orig send absent seg %ld failed\n",
                                                     seg_no);
                return (EC_FALSE);
            }
            dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                                 "orig send absent seg %ld done\n",
                                                 seg_no);

            /*if no-cache, send no more data*/
            if(BIT_TRUE == CMP4_MD_ORIG_NO_CACHE_FLAG(cmp4_md))
            {
                dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                                     "direct should sent out all no-cache data\n");
                return (EC_TRUE);
            }

            break;/*fall through*/
        }

        /*parse header*/
        if(EC_FALSE == cmp4_content_cache_parse_header(cmp4_md_id, &seg_cbytes))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                                 "parse seg %ld failed\n",
                                                 seg_no);
            cbytes_clean(&seg_cbytes);

            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                             "parse seg %ld done\n",
                                             seg_no);

        cbytes_clean(&seg_cbytes);

        /*parse Content-Length and segs from chttp rsp if cngx req has no 'Range'*/
        if(EC_TRUE == crange_mgr_is_empty(CMP4_MD_CNGX_RANGE_MGR(cmp4_md))
        && EC_FALSE == cmp4_has_mp4_out(cmp4_md_id))
        {
            if(EC_FALSE == cmp4_get_rsp_length_segs(cmp4_md_id, CMP4_MD_CACHE_SEG_SIZE(cmp4_md)))
            {
                dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                                     "get range segs from chttp rsp failed\n");

                cmp4_set_ngx_rc(cmp4_md_id, NGX_HTTP_BAD_REQUEST, LOC_CMP4_0138);
                return (EC_FALSE);
            }
        }

        if(EC_FALSE == cmp4_filter_rsp_range(cmp4_md_id))
        {
            dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                                 "chttp rsp header_in range filter failed\n");
            cmp4_set_ngx_rc(cmp4_md_id, CHTTP_REQUESTEDR_RANGE_NOT_SATISFIABLE, LOC_CMP4_0139);
            return (EC_FALSE);
        }
        dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                             "chttp rsp header_in range filter done\n");

        /*fall through*/
    }while(0);

    /*send header and body*/
    if(EC_FALSE == cmp4_content_cache_send_response(cmp4_md_id))
    {
        dbg_log(SEC_0147_CMP4, 0)(LOGSTDOUT, "error:cmp4_content_cache_procedure: "
                                             "send response failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0147_CMP4, 9)(LOGSTDOUT, "[DEBUG] cmp4_content_cache_procedure: "
                                         "send response done\n");
    return (EC_TRUE);
}


#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


