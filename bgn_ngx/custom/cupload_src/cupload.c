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

#include "cbc.h"

#include "ccache.h"

#include "cupload.h"

#include "cngx.h"
#include "chttp.h"

#include "json.h"

#include "findex.inc"

#define CUPLOAD_MD_CAPACITY()                  (cbc_md_capacity(MD_CUPLOAD))

#define CUPLOAD_MD_GET(cupload_md_id)     ((CUPLOAD_MD *)cbc_md_get(MD_CUPLOAD, (cupload_md_id)))

#define CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id)  \
    ((CMPI_ANY_MODI != (cupload_md_id)) && ((NULL_PTR == CUPLOAD_MD_GET(cupload_md_id)) || (0 == (CUPLOAD_MD_GET(cupload_md_id)->usedcounter))))

/*-------------------------------------------------------------------*\
configuration example:
======================
server {
    listen  80;
    server_name *.upload.com;

    if ($uri = "/") {
        rewrite (.*) /index.html;
    }

    location ~ /(upload|check|override|delete|size|md5) {
        content_by_bgn cupload;
    }

    more_set_headers 'X-Upload: enabled';
}
\*-------------------------------------------------------------------*/

/**
*   for test only
*
*   to query the status of CUPLOAD Module
*
**/
void cupload_print_module_status(const UINT32 cupload_md_id, LOG *log)
{
    CUPLOAD_MD *cupload_md;
    UINT32      this_cupload_md_id;

    for( this_cupload_md_id = 0; this_cupload_md_id < CUPLOAD_MD_CAPACITY(); this_cupload_md_id ++ )
    {
        cupload_md = CUPLOAD_MD_GET(this_cupload_md_id);

        if(NULL_PTR != cupload_md && 0 < cupload_md->usedcounter )
        {
            sys_log(log,"CUPLOAD Module # %u : %u refered\n",
                    this_cupload_md_id,
                    cupload_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CUPLOAD module
*
**/
EC_BOOL cupload_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CUPLOAD , 1);
}

/**
*
* unregister CUPLOAD module
*
**/
EC_BOOL cupload_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CUPLOAD);
}

/**
*
* start CUPLOAD module
*
**/
UINT32 cupload_start(ngx_http_request_t *r)
{
    CUPLOAD_MD *cupload_md;
    UINT32      cupload_md_id;

    //TASK_BRD   *task_brd;

    uint32_t    cache_seg_size;

    //task_brd = task_brd_default_get();

    cupload_md_id = cbc_md_new(MD_CUPLOAD, sizeof(CUPLOAD_MD));
    if(CMPI_ERROR_MODI == cupload_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CUPLOAD module */
    cupload_md = (CUPLOAD_MD *)cbc_md_get(MD_CUPLOAD, cupload_md_id);
    cupload_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */
    cngx_get_cache_seg_size(r, &cache_seg_size);

    CUPLOAD_MD_FILE_OP(cupload_md)          = NULL_PTR;
    CUPLOAD_MD_FILE_PATH(cupload_md)        = NULL_PTR;
    CUPLOAD_MD_FILE_MD5(cupload_md)         = NULL_PTR;
    CUPLOAD_MD_FILE_BODY(cupload_md)        = NULL_PTR;
    CUPLOAD_MD_FILE_SIZE(cupload_md)        = 0;
    CUPLOAD_MD_FILE_S_OFFSET(cupload_md)    = 0;
    CUPLOAD_MD_FILE_E_OFFSET(cupload_md)    = 0;

    CUPLOAD_MD_NGX_HTTP_REQ(cupload_md)     = r;

    /*TODO: load all variables into module*/

    CUPLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cupload_md) = BIT_FALSE;

    CUPLOAD_MD_CONTENT_LENGTH(cupload_md)   = 0;

    CUPLOAD_MD_NGX_RSP_BODY(cupload_md)     = NULL_PTR;

    CUPLOAD_MD_NGX_LOC(cupload_md)          = LOC_NONE_END;
    CUPLOAD_MD_NGX_RC(cupload_md)           = NGX_OK;

    cupload_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cupload_end, cupload_md_id);

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_start: start CUPLOAD module #%ld\n", cupload_md_id);

    return ( cupload_md_id );
}

/**
*
* end CUPLOAD module
*
**/
void cupload_end(const UINT32 cupload_md_id)
{
    CUPLOAD_MD *cupload_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cupload_end, cupload_md_id);

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);
    if(NULL_PTR == cupload_md)
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_end: "
                                                "cupload_md_id = %ld not exist.\n",
                                                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cupload_md->usedcounter )
    {
        cupload_md->usedcounter --;
        return ;
    }

    if ( 0 == cupload_md->usedcounter )
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_end: "
                                                "cupload_md_id = %ld is not started.\n",
                                                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }

    if(NULL_PTR != CUPLOAD_MD_FILE_BODY(cupload_md))
    {
        cbytes_free(CUPLOAD_MD_FILE_BODY(cupload_md));
        CUPLOAD_MD_FILE_BODY(cupload_md) = NULL_PTR;
    }

    if(NULL_PTR != CUPLOAD_MD_FILE_PATH(cupload_md))
    {
        cstring_free(CUPLOAD_MD_FILE_PATH(cupload_md));
        CUPLOAD_MD_FILE_PATH(cupload_md) = NULL_PTR;
    }

    if(NULL_PTR != CUPLOAD_MD_FILE_OP(cupload_md))
    {
        cstring_free(CUPLOAD_MD_FILE_OP(cupload_md));
        CUPLOAD_MD_FILE_OP(cupload_md) = NULL_PTR;
    }

    if(NULL_PTR != CUPLOAD_MD_FILE_MD5(cupload_md))
    {
        cstring_free(CUPLOAD_MD_FILE_MD5(cupload_md));
        CUPLOAD_MD_FILE_MD5(cupload_md) = NULL_PTR;
    }

    if(NULL_PTR == CUPLOAD_MD_NGX_RSP_BODY(cupload_md))
    {
        cbytes_free(CUPLOAD_MD_NGX_RSP_BODY(cupload_md));
        CUPLOAD_MD_NGX_RSP_BODY(cupload_md) = NULL_PTR;
    }

    CUPLOAD_MD_FILE_SIZE(cupload_md)        = 0;
    CUPLOAD_MD_FILE_S_OFFSET(cupload_md)    = 0;
    CUPLOAD_MD_FILE_E_OFFSET(cupload_md)    = 0;

    CUPLOAD_MD_NGX_HTTP_REQ(cupload_md) = NULL_PTR;

    CUPLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cupload_md) = BIT_FALSE;

    CUPLOAD_MD_CONTENT_LENGTH(cupload_md) = 0;

    CUPLOAD_MD_NGX_LOC(cupload_md)        = LOC_NONE_END;
    CUPLOAD_MD_NGX_RC(cupload_md)         = NGX_OK;

    /* free module */
    cupload_md->usedcounter = 0;

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "cupload_end: stop CUPLOAD module #%ld\n", cupload_md_id);
    cbc_md_free(MD_CUPLOAD, cupload_md_id);

    return ;
}

EC_BOOL cupload_get_ngx_rc(const UINT32 cupload_md_id, ngx_int_t *rc, UINT32 *location)
{
    CUPLOAD_MD                  *cupload_md;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_get_ngx_rc: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CUPLOAD_MD_NGX_RC(cupload_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CUPLOAD_MD_NGX_LOC(cupload_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cupload_set_ngx_rc(const UINT32 cupload_md_id, const ngx_int_t rc, const UINT32 location)
{
    CUPLOAD_MD                  *cupload_md;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_set_ngx_rc: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    /*do not override*/
    if(NGX_OK != CUPLOAD_MD_NGX_RC(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_override_ngx_rc: "
                                                "ignore rc %ld due to its %ld now\n",
                                                rc, CUPLOAD_MD_NGX_RC(cupload_md));
        return (EC_TRUE);
    }

    CUPLOAD_MD_NGX_RC(cupload_md)  = rc;
    CUPLOAD_MD_NGX_LOC(cupload_md) = location;

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_set_ngx_rc: "
                                            "set rc %ld\n",
                                            rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cupload_override_ngx_rc(const UINT32 cupload_md_id, const ngx_int_t rc, const UINT32 location)
{
    CUPLOAD_MD                  *cupload_md;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_override_ngx_rc: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    if(rc == CUPLOAD_MD_NGX_RC(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_override_ngx_rc: "
                                                "ignore same rc %ld\n",
                                                rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CUPLOAD_MD_NGX_RC(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_override_ngx_rc: "
                                                "modify rc %ld => %ld\n",
                                                CUPLOAD_MD_NGX_RC(cupload_md), rc);
        CUPLOAD_MD_NGX_RC(cupload_md)  = rc;
        CUPLOAD_MD_NGX_LOC(cupload_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_override_ngx_rc: "
                                            "set rc %ld\n",
                                            rc);

    CUPLOAD_MD_NGX_RC(cupload_md)  = rc;
    CUPLOAD_MD_NGX_LOC(cupload_md) = location;

    return (EC_TRUE);
}

EC_BOOL cupload_parse_uri(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                   *cupload_md;

    ngx_http_request_t           *r;
    char                         *uri_str;
    char                         *uri_end;
    char                         *v;
    char                         *file_op_str;
    char                         *file_path_str;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_parse_uri: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    if(EC_FALSE == cngx_get_req_uri(r, &uri_str))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_uri: "
                                                "fetch req uri failed\n");
        return (EC_FALSE);
    }

    if(0 == STRCMP(uri_str, (const char *)"/"))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_uri: "
                                                "invalid file name '%s'\n",
                                                uri_str);
        safe_free(uri_str, LOC_CUPLOAD_0001);
        return (EC_FALSE);
    }

    uri_end             = uri_str + strlen(uri_str);
    file_op_str         = NULL_PTR;
    file_path_str       = NULL_PTR;

    for(v = uri_str; v < uri_end; v ++)
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
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "error:cupload_parse_uri: "
                                                "invalid uri %s\n",
                                                uri_str);

        safe_free(uri_str, LOC_CUPLOAD_0002);
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR == CUPLOAD_MD_FILE_OP(cupload_md));
    ASSERT(NULL_PTR == CUPLOAD_MD_FILE_PATH(cupload_md));

    CUPLOAD_MD_FILE_OP(cupload_md) = cstring_make("%.*s", file_path_str - file_op_str, file_op_str);
    if(NULL_PTR == CUPLOAD_MD_FILE_OP(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_uri: "
                                                "make file op '%.*s' failed\n",
                                                file_path_str - file_op_str, file_op_str);
        safe_free(uri_str, LOC_CUPLOAD_0003);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_uri: "
                                            "parsed file op '%s'\n",
                                            (char *)CUPLOAD_MD_FILE_OP_STR(cupload_md));

    CUPLOAD_MD_FILE_PATH(cupload_md) = cstring_new((UINT8 *)file_path_str, LOC_CUPLOAD_0004);
    if(NULL_PTR == CUPLOAD_MD_FILE_PATH(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_uri: "
                                                "make file path '%s' failed\n",
                                                file_path_str);
        safe_free(uri_str, LOC_CUPLOAD_0005);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_uri: "
                                            "parsed file path '%s'\n",
                                            (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

    safe_free(uri_str, LOC_CUPLOAD_0006);

    return (EC_TRUE);
}

EC_BOOL cupload_parse_file_range(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_parse_file_range: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    /*[example] Content-Range: bytes 7-14/20*/
    k = (const char *)"Content-Range";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_range: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_range: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    if(NULL_PTR != v)
    {
        char   *segs[ 4 ];

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_range: "
                                                "[cngx] get var '%s':'%s' done\n",
                                                k, v);

        if(4 != c_str_split(v, (const char *)":-/ \t", (char **)segs, 4))
        {
            dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_range: "
                                                    "[cngx] invalid %s\n",
                                                    k);
            safe_free(v, LOC_CUPLOAD_0007);
            return (EC_FALSE);
        }

        if(0 != STRCASECMP("bytes", segs[0])
        || EC_FALSE == c_str_is_digit(segs[1])
        || EC_FALSE == c_str_is_digit(segs[2])
        || EC_FALSE == c_str_is_digit(segs[3]))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_range: "
                                                    "[cngx] invald '%s': %s %s-%s/%s\n",
                                                    k, segs[0], segs[1], segs[2], segs[3]);
            safe_free(v, LOC_CUPLOAD_0008);
            return (EC_FALSE);
        }

        CUPLOAD_MD_FILE_S_OFFSET(cupload_md) = c_str_to_word(segs[1]);
        CUPLOAD_MD_FILE_E_OFFSET(cupload_md) = c_str_to_word(segs[2]);
        CUPLOAD_MD_FILE_SIZE(cupload_md)     = c_str_to_word(segs[3]);

        if(CUPLOAD_MD_FILE_S_OFFSET(cupload_md) > CUPLOAD_MD_FILE_E_OFFSET(cupload_md)
        || CUPLOAD_MD_FILE_SIZE(cupload_md)     < CUPLOAD_MD_FILE_E_OFFSET(cupload_md))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_range: "
                                                    "[cngx] invald '%s': %s %s-%s/%s\n",
                                                    k, segs[0], segs[1], segs[2], segs[3]);
            safe_free(v, LOC_CUPLOAD_0009);
            return (EC_FALSE);
        }

        safe_free(v, LOC_CUPLOAD_0010);

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_range: "
                                                "[cngx] parsed range: [%ld, %ld]/%ld\n",
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_SIZE(cupload_md));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cupload_parse_file_md5(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_parse_file_md5: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    /*Content-MD5: 0123456789abcdef*/
    k = (const char *)"Content-MD5";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_md5: "
                                                "[cngx] get '%s' failed\n",
                                                k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_md5: "
                                                "[cngx] no '%s'\n",
                                                k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_md5: "
                                            "[cngx] parsed '%s':'%s'\n",
                                            k, v);

    CUPLOAD_MD_FILE_MD5(cupload_md) = cstring_new((UINT8 *)v, LOC_CUPLOAD_0011);
    if(NULL_PTR == CUPLOAD_MD_FILE_MD5(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_md5: "
                                                "new cstring '%s' failed\n",
                                                v);
        safe_free(v, LOC_CUPLOAD_0012);
        return (EC_FALSE);
    }

    safe_free(v, LOC_CUPLOAD_0013);
    return (EC_TRUE);
}

EC_BOOL cupload_parse_file_body(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_parse_file_body: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    if(EC_FALSE == cngx_read_req_body(r))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_body: "
                                                "read req body failed\n");
        return (EC_FALSE);
    }

    if(CUPLOAD_MD_FILE_S_OFFSET(cupload_md) > CUPLOAD_MD_FILE_E_OFFSET(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_body: "
                                                "invalid range [%ld, %ld]\n",
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md));
        return (EC_FALSE);
    }

    if(CUPLOAD_MD_FILE_S_OFFSET(cupload_md) < CUPLOAD_MD_FILE_E_OFFSET(cupload_md))
    {
        CUPLOAD_MD_FILE_BODY(cupload_md) = cbytes_new(0);
        if(NULL_PTR == CUPLOAD_MD_FILE_BODY(cupload_md))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_body: "
                                                    "new cbytes failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == cngx_get_req_body(r, CUPLOAD_MD_FILE_BODY(cupload_md)))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_body: "
                                                    "get req body failed\n");
            cbytes_free(CUPLOAD_MD_FILE_BODY(cupload_md));
            CUPLOAD_MD_FILE_BODY(cupload_md) = NULL_PTR;
            return (EC_FALSE);
        }
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_body: "
                                                "req body len %ld\n",
                                                CBYTES_LEN(CUPLOAD_MD_FILE_BODY(cupload_md)));
    }

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_parse_file_body: done\n");

    return (EC_TRUE);
}

EC_BOOL cupload_write_file_handler(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_write_file_handler: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_write_file_handler: enter\n");

    /*check validity*/
    if(NULL_PTR == CUPLOAD_MD_FILE_PATH(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                "no file name\n");
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0014);
        return (EC_FALSE);
    }

    if(CUPLOAD_MD_FILE_S_OFFSET(cupload_md) > CUPLOAD_MD_FILE_E_OFFSET(cupload_md)
    || CUPLOAD_MD_FILE_E_OFFSET(cupload_md) > CUPLOAD_MD_FILE_SIZE(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                "file name '%s', invalid range [%ld, %ld]/%ld\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_SIZE(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0014);
        return (EC_FALSE);
    }

    /*create/write file*/
    if(EC_FALSE == c_file_exist((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md)))
    {
        UINT32      offset;
        UINT32      wsize;
        int         fd;

        fd = c_file_open((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), O_RDWR | O_CREAT, 0666);
        if(ERR_FD == fd)
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                    "create file %s failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0014);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_truncate(fd, CUPLOAD_MD_FILE_SIZE(cupload_md)))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                    "truncate file %s to %ld failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_SIZE(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0015);

            return (EC_FALSE);
        }

        offset = CUPLOAD_MD_FILE_S_OFFSET(cupload_md);
        wsize  = CUPLOAD_MD_FILE_E_OFFSET(cupload_md) + 1 - CUPLOAD_MD_FILE_S_OFFSET(cupload_md);

        if(0 == wsize)
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "warn:cupload_write_file_handler: "
                                                    "nothing write to file %s [%ld, %ld]\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0020);

            return (EC_TRUE);
        }

        if(EC_FALSE == c_file_write(fd, &offset, wsize, CBYTES_BUF(CUPLOAD_MD_FILE_BODY(cupload_md))))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                    "write file %s [%ld, %ld] failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0016);

            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_write_file_handler: "
                                                "write file %s [%ld, %ld] done\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0020);

        return (EC_TRUE);
    }
    else
    {
        UINT32      offset;
        UINT32      fsize;
        UINT32      wsize;
        int         fd;

        fd = c_file_open((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), O_RDWR, 0666);
        if(ERR_FD == fd)
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                    "open file %s failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0017);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_size(fd, &fsize))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                    "size of file %s failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0018);

            return (EC_FALSE);
        }

        if(fsize != CUPLOAD_MD_FILE_SIZE(cupload_md))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                    "file %s size %ld != %ld\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    fsize, CUPLOAD_MD_FILE_SIZE(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0019);

            return (EC_FALSE);
        }

        offset = CUPLOAD_MD_FILE_S_OFFSET(cupload_md);
        wsize  = CUPLOAD_MD_FILE_E_OFFSET(cupload_md) + 1 - CUPLOAD_MD_FILE_S_OFFSET(cupload_md);

        if(0 == wsize)
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "warn:cupload_write_file_handler: "
                                                    "nothing write to file %s:[%ld, %ld]\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0019);

            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_write(fd, &offset, wsize, CBYTES_BUF(CUPLOAD_MD_FILE_BODY(cupload_md))))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                                    "write file %s:[%ld, %ld] failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0020);

            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_write_file_handler: "
                                                "write file %s:[%ld, %ld] done\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0020);

        return (EC_TRUE);
    }

    /*never reach here*/
    dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_write_file_handler: "
                                            "file '%s', should never reach here\n",
                                            (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
    cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0020);
    return (EC_FALSE);
}

EC_BOOL cupload_override_file_handler(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_override_file_handler: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_override_file_handler: enter\n");

    /*check validity*/
    if(NULL_PTR == CUPLOAD_MD_FILE_PATH(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_override_file_handler: "
                                                "no file name\n");
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0014);
        return (EC_FALSE);
    }

    if(CUPLOAD_MD_FILE_S_OFFSET(cupload_md) > CUPLOAD_MD_FILE_E_OFFSET(cupload_md)
    || CUPLOAD_MD_FILE_E_OFFSET(cupload_md) > CUPLOAD_MD_FILE_SIZE(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_override_file_handler: "
                                                "file name '%s', invalid range [%ld, %ld]/%ld\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_SIZE(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0014);
        return (EC_FALSE);
    }

    /*delete file if exist*/

    if(EC_FALSE == c_file_exist((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md)))
    {
        if(EC_FALSE == c_file_unlink((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md)))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_override_file_handler: "
                                                    "unlink file '%s' failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_NOT_FOUND, LOC_CUPLOAD_0023);
            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_override_file_handler: "
                                                "unlink file '%s' done\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
    }

    /*creat file*/
    if(1)
    {
        UINT32                       offset;
        UINT32                       wsize;
        int                          fd;

        fd = c_file_open((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), O_RDWR | O_CREAT, 0666);
        if(ERR_FD == fd)
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_override_file_handler: "
                                                    "create file %s failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0014);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_truncate(fd, CUPLOAD_MD_FILE_SIZE(cupload_md)))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_override_file_handler: "
                                                    "truncate file %s to %ld failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_SIZE(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0015);

            return (EC_FALSE);
        }

        offset = CUPLOAD_MD_FILE_S_OFFSET(cupload_md);
        wsize  = CUPLOAD_MD_FILE_E_OFFSET(cupload_md) + 1 - CUPLOAD_MD_FILE_S_OFFSET(cupload_md);

        if(0 == wsize)
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "warn:cupload_override_file_handler: "
                                                    "nothing write to file %s [%ld, %ld]\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0020);

            return (EC_TRUE);
        }

        if(EC_FALSE == c_file_write(fd, &offset, wsize, CBYTES_BUF(CUPLOAD_MD_FILE_BODY(cupload_md))))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_override_file_handler: "
                                                    "write file %s [%ld, %ld] failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0016);

            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_override_file_handler: "
                                                "write file %s [%ld, %ld] done\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0020);

        return (EC_TRUE);
    }

    /*never reach here*/
    dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_override_file_handler: "
                                            "file '%s', should never reach here\n",
                                            (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
    cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0020);
    return (EC_FALSE);
}

EC_BOOL cupload_check_file_handler(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

    CMD5_DIGEST                  seg_md5sum;
    UINT32                       fsize;
    int                          fd;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_check_file_handler: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    if(NULL_PTR == CUPLOAD_MD_FILE_MD5(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_check_file_handler: "
                                                "no md5\n");

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0021);
        return (EC_FALSE);
    }

    if(CUPLOAD_MD_FILE_S_OFFSET(cupload_md) >= CUPLOAD_MD_FILE_E_OFFSET(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_check_file_handler: "
                                                "invalid content-range: [%ld, %ld]/%ld\n",
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_SIZE(cupload_md));

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0022);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), F_OK))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_check_file_handler: "
                                                "file '%s' not exist\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_NOT_FOUND, LOC_CUPLOAD_0023);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_check_file_handler: "
                                                "open file '%s' failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_FORBIDDEN, LOC_CUPLOAD_0024);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_check_file_handler: "
                                                "size file '%s' failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_FORBIDDEN, LOC_CUPLOAD_0025);

        return (EC_FALSE);
    }

    if(fsize != CUPLOAD_MD_FILE_SIZE(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_check_file_handler: "
                                                "file '%s' size %ld != %ld\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                fsize,
                                                CUPLOAD_MD_FILE_SIZE(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_UNAUTHORIZED, LOC_CUPLOAD_0026);

        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_check_file_handler: "
                                            "file '%s' size %ld matched\n",
                                            (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                            CUPLOAD_MD_FILE_SIZE(cupload_md));

    if(NULL_PTR != CUPLOAD_MD_FILE_MD5(cupload_md))
    {
        UINT32      data_size;

        data_size = CUPLOAD_MD_FILE_E_OFFSET(cupload_md) + 1 - CUPLOAD_MD_FILE_S_OFFSET(cupload_md);
        if(EC_FALSE == c_file_seg_md5(fd, CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                            data_size, CMD5_DIGEST_SUM(&seg_md5sum)))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_check_file_handler: "
                                                    "md5sum file '%s' range [%ld, %ld] failed\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

            c_file_close(fd);
            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0027);

            return (EC_FALSE);
        }

        c_file_close(fd);

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_check_file_handler: "
                                                "file '%s' range [%ld, %ld] => md5 %s\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                cmd5_digest_hex_str(&seg_md5sum));

        if(0 != STRCASECMP(cmd5_digest_hex_str(&seg_md5sum), (char *)CUPLOAD_MD_FILE_MD5_STR(cupload_md)))
        {
            dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_check_file_handler: "
                                                    "file '%s' range [%ld, %ld] md5 %s != %s\n",
                                                    (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                    CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                    CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                    cmd5_digest_hex_str(&seg_md5sum),
                                                    CUPLOAD_MD_FILE_MD5_STR(cupload_md));

            cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_UNAUTHORIZED, LOC_CUPLOAD_0028);
            return (EC_TRUE);
        }

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_check_file_handler: "
                                                "file '%s' range [%ld, %ld] md5 %s matched\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_MD5_STR(cupload_md));

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0029);
        return (EC_TRUE);
    }

    c_file_close(fd);

    cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0029);
    return (EC_TRUE);
}

EC_BOOL cupload_delete_file_handler(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_delete_file_handler: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    if(EC_FALSE == c_file_access((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), F_OK))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_delete_file_handler: "
                                                "file '%s' not exist\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_NOT_FOUND, LOC_CUPLOAD_0023);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_unlink((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md)))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_delete_file_handler: "
                                                "unlink file '%s' failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_NOT_FOUND, LOC_CUPLOAD_0023);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_delete_file_handler: "
                                            "unlink file '%s' done\n",
                                            (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

    cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0029);
    return (EC_TRUE);
}

EC_BOOL cupload_size_file_handler(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

    ngx_http_request_t          *r;

    UINT32                       fsize;
    int                          fd;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_size_file_handler: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    if(EC_FALSE == c_file_access((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), F_OK))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_size_file_handler: "
                                                "file '%s' not exist\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_NOT_FOUND, LOC_CUPLOAD_0023);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_size_file_handler: "
                                                "open file '%s' failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_FORBIDDEN, LOC_CUPLOAD_0024);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_size_file_handler: "
                                                "size file '%s' failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_FORBIDDEN, LOC_CUPLOAD_0025);

        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_size_file_handler: "
                                            "file '%s' size %ld\n",
                                            (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                            fsize);

    cngx_set_header_out_kv(r, (const char *)"X-File-Size", c_word_to_str(fsize));
    cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0029);
    return (EC_TRUE);
}

EC_BOOL cupload_md5_file_handler(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

    ngx_http_request_t          *r;

    CMD5_DIGEST                  seg_md5sum;
    UINT32                       fsize;
    UINT32                       data_size;
    int                          fd;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_md5_file_handler: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    if(CUPLOAD_MD_FILE_S_OFFSET(cupload_md) > CUPLOAD_MD_FILE_E_OFFSET(cupload_md))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_md5_file_handler: "
                                                "invalid content-range: [%ld, %ld]/%ld\n",
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_SIZE(cupload_md));

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0022);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), F_OK))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_md5_file_handler: "
                                                "file '%s' not exist\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_NOT_FOUND, LOC_CUPLOAD_0023);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_md5_file_handler: "
                                                "open file '%s' failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_FORBIDDEN, LOC_CUPLOAD_0024);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_md5_file_handler: "
                                                "size file '%s' failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_FORBIDDEN, LOC_CUPLOAD_0025);

        return (EC_FALSE);
    }

    if(0 == CUPLOAD_MD_FILE_S_OFFSET(cupload_md)
    && 0 == CUPLOAD_MD_FILE_E_OFFSET(cupload_md)
    && 0 == CUPLOAD_MD_FILE_SIZE(cupload_md))
    {
        CUPLOAD_MD_FILE_S_OFFSET(cupload_md) = 0;
        CUPLOAD_MD_FILE_E_OFFSET(cupload_md) = fsize - 1;
        CUPLOAD_MD_FILE_SIZE(cupload_md)     = fsize;
    }

    data_size = CUPLOAD_MD_FILE_E_OFFSET(cupload_md) + 1 - CUPLOAD_MD_FILE_S_OFFSET(cupload_md);
    if(EC_FALSE == c_file_seg_md5(fd, CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                        data_size, CMD5_DIGEST_SUM(&seg_md5sum)))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_md5_file_handler: "
                                                "md5sum file '%s' range [%ld, %ld] failed\n",
                                                (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                                CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                                CUPLOAD_MD_FILE_E_OFFSET(cupload_md));

        c_file_close(fd);
        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUPLOAD_0027);

        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_md5_file_handler: "
                                            "file '%s' range [%ld, %ld]/%ld => md5 %s\n",
                                            (char *)CUPLOAD_MD_FILE_PATH_STR(cupload_md),
                                            CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                                            CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                                            CUPLOAD_MD_FILE_SIZE(cupload_md),
                                            cmd5_digest_hex_str(&seg_md5sum));

    cngx_set_header_out_kv(r, (const char *)"X-Content-Range",
                               c_format_str("%ld-%ld/%ld",
                               CUPLOAD_MD_FILE_S_OFFSET(cupload_md),
                               CUPLOAD_MD_FILE_E_OFFSET(cupload_md),
                               CUPLOAD_MD_FILE_SIZE(cupload_md)));

    cngx_set_header_out_kv(r, (const char *)"X-MD5", cmd5_digest_hex_str(&seg_md5sum));

    cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_OK, LOC_CUPLOAD_0029);
    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL cupload_content_handler(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                  *cupload_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_content_handler: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CUPLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cupload_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CUPLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cupload_md) = BIT_TRUE;
    }

    if(EC_FALSE == cupload_parse_uri(cupload_md_id))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                "parse uri failed\n");

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0030);
        cupload_content_send_response(cupload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_content_handler: "
                                            "parse uri done\n");

    if(EC_FALSE == cupload_parse_file_range(cupload_md_id))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_range: "
                                                "parse file range failed\n");

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0031);
        cupload_content_send_response(cupload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_content_handler: "
                                            "parse file range done\n");

    if(EC_FALSE == cupload_parse_file_md5(cupload_md_id))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_parse_file_range: "
                                                "parse file md5 failed\n");

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0032);
        cupload_content_send_response(cupload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_content_handler: "
                                            "parse file md5 done\n");

    if(EC_FALSE == cupload_parse_file_body(cupload_md_id))
    {
        dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                "parse file body failed\n");

        cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0033);
        cupload_content_send_response(cupload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_content_handler: "
                                            "parse file body done\n");

    /*upload file*/
    if(NULL_PTR != CUPLOAD_MD_FILE_OP(cupload_md)
    && EC_TRUE == cstring_is_str(CUPLOAD_MD_FILE_OP(cupload_md), (UINT8 *)CUPLOAD_FILE_UPLOAD_OP))
    {
        if(EC_FALSE == cupload_write_file_handler(cupload_md_id))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                    "write file failed\n");

            cupload_content_send_response(cupload_md_id);
            return (EC_FALSE);
        }

        cupload_content_send_response(cupload_md_id);
        return (EC_TRUE);
    }

    /*override file*/
    if(NULL_PTR != CUPLOAD_MD_FILE_OP(cupload_md)
    && EC_TRUE == cstring_is_str(CUPLOAD_MD_FILE_OP(cupload_md), (UINT8 *)CUPLOAD_FILE_OVERRIDE_OP))
    {
        if(EC_FALSE == cupload_override_file_handler(cupload_md_id))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                    "override file failed\n");

            cupload_content_send_response(cupload_md_id);
            return (EC_FALSE);
        }

        cupload_content_send_response(cupload_md_id);
        return (EC_TRUE);
    }

    /*check file*/
    if(NULL_PTR != CUPLOAD_MD_FILE_OP(cupload_md)
    && EC_TRUE == cstring_is_str(CUPLOAD_MD_FILE_OP(cupload_md), (UINT8 *)CUPLOAD_FILE_CHECK_OP))
    {
        if(EC_FALSE == cupload_check_file_handler(cupload_md_id))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                    "check file failed\n");

            cupload_content_send_response(cupload_md_id);
            return (EC_FALSE);
        }

        cupload_content_send_response(cupload_md_id);
        return (EC_TRUE);
    }

    /*delete file*/
    if(NULL_PTR != CUPLOAD_MD_FILE_OP(cupload_md)
    && EC_TRUE == cstring_is_str(CUPLOAD_MD_FILE_OP(cupload_md), (UINT8 *)CUPLOAD_FILE_DELETE_OP))
    {
        if(EC_FALSE == cupload_delete_file_handler(cupload_md_id))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                    "delete file failed\n");

            cupload_content_send_response(cupload_md_id);
            return (EC_FALSE);
        }

        cupload_content_send_response(cupload_md_id);
        return (EC_TRUE);
    }

    /*size file*/
    if(NULL_PTR != CUPLOAD_MD_FILE_OP(cupload_md)
    && EC_TRUE == cstring_is_str(CUPLOAD_MD_FILE_OP(cupload_md), (UINT8 *)CUPLOAD_FILE_SIZE_OP))
    {
        if(EC_FALSE == cupload_size_file_handler(cupload_md_id))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                    "size file failed\n");

            cupload_content_send_response(cupload_md_id);
            return (EC_FALSE);
        }

        cupload_content_send_response(cupload_md_id);
        return (EC_TRUE);
    }

    /*md5 file*/
    if(NULL_PTR != CUPLOAD_MD_FILE_OP(cupload_md)
    && EC_TRUE == cstring_is_str(CUPLOAD_MD_FILE_OP(cupload_md), (UINT8 *)CUPLOAD_FILE_MD5_OP))
    {
        if(EC_FALSE == cupload_md5_file_handler(cupload_md_id))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_handler: "
                                                    "md5 file failed\n");

            cupload_content_send_response(cupload_md_id);
            return (EC_FALSE);
        }

        cupload_content_send_response(cupload_md_id);
        return (EC_TRUE);
    }

    cupload_set_ngx_rc(cupload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CUPLOAD_0034);
    cupload_content_send_response(cupload_md_id);
    return (EC_FALSE);
}

EC_BOOL cupload_content_send_response(const UINT32 cupload_md_id)
{
    CUPLOAD_MD                 *cupload_md;

    ngx_http_request_t         *r;
    uint32_t                    len;
    uint32_t                    flags;

#if ( SWITCH_ON == CUPLOAD_DEBUG_SWITCH )
    if ( CUPLOAD_MD_ID_CHECK_INVALID(cupload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cupload_content_send_response: cupload module #0x%lx not started.\n",
                cupload_md_id);
        dbg_exit(MD_CUPLOAD, cupload_md_id);
    }
#endif/*CUPLOAD_DEBUG_SWITCH*/

    cupload_md = CUPLOAD_MD_GET(cupload_md_id);

    r = CUPLOAD_MD_NGX_HTTP_REQ(cupload_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);/*xxx*/

        cngx_set_header_out_status(r, CUPLOAD_MD_NGX_RC(cupload_md));
        cngx_set_header_out_content_length(r, 0);/*no body*/

        if(EC_FALSE == cngx_send_header(r, &(CUPLOAD_MD_NGX_RC(cupload_md))))
        {
            dbg_log(SEC_0173_CUPLOAD, 0)(LOGSTDOUT, "error:cupload_content_send_response: "
                                                    "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_content_send_response: "
                                                "send header done\n");
    }

    /*send body*/
    if(NULL_PTR != CUPLOAD_MD_NGX_RSP_BODY(cupload_md))
    {
        uint8_t     *data;

        data = (uint8_t *)CBYTES_BUF(CUPLOAD_MD_NGX_RSP_BODY(cupload_md));
        len  = (uint32_t )CBYTES_LEN(CUPLOAD_MD_NGX_RSP_BODY(cupload_md));

        flags =   CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG
                | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CUPLOAD_MD_NGX_RC(cupload_md))))
        {
            dbg_log(SEC_0173_CUPLOAD, 1)(LOGSTDOUT, "error:cupload_content_send_response: "
                                                    "send body failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CUPLOAD, 9)(LOGSTDOUT, "[DEBUG] cupload_content_send_response: "
                                                "send body done => complete %ld bytes\n",
                                                CUPLOAD_MD_SENT_BODY_SIZE(cupload_md));
        return (EC_TRUE);
    }

    flags =   CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CUPLOAD_MD_NGX_RC(cupload_md))))
    {
        dbg_log(SEC_0173_CUPLOAD, 1)(LOGSTDOUT, "error:cupload_content_send_response: "
                                                "send body failed\n");

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


