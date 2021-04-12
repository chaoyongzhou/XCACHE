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

#include "cstore.h"

#include "findex.inc"

#define CSTORE_MD_CAPACITY()                  (cbc_md_capacity(MD_CSTORE))

#define CSTORE_MD_GET(cstore_md_id)     ((CSTORE_MD *)cbc_md_get(MD_CSTORE, (cstore_md_id)))

#define CSTORE_MD_ID_CHECK_INVALID(cstore_md_id)  \
    ((CMPI_ANY_MODI != (cstore_md_id)) && ((NULL_PTR == CSTORE_MD_GET(cstore_md_id)) || (0 == (CSTORE_MD_GET(cstore_md_id)->usedcounter))))

/*-------------------------------------------------------------------*\
nginx server configuration example:
===================================
server {
    listen  80;
    server_name *.store.com;

    client_body_in_file_only off;
    client_max_body_size 4m;

    set $c_acl_token   1234567890abcdef;
    access_by_bgn cacltime;

    location ~ /bucket {
        root /tmp/upload;
        set $c_store_backup_dir /tmp/backup;
        content_by_bgn cstore;
    }
}
\*-------------------------------------------------------------------*/

/**
*   for test only
*
*   to query the status of CSTORE Module
*
**/
void cstore_print_module_status(const UINT32 cstore_md_id, LOG *log)
{
    CSTORE_MD  *cstore_md;
    UINT32      this_cstore_md_id;

    for( this_cstore_md_id = 0; this_cstore_md_id < CSTORE_MD_CAPACITY(); this_cstore_md_id ++ )
    {
        cstore_md = CSTORE_MD_GET(this_cstore_md_id);

        if(NULL_PTR != cstore_md && 0 < cstore_md->usedcounter )
        {
            sys_log(log,"CSTORE Module # %u : %u refered\n",
                    this_cstore_md_id,
                    cstore_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CSTORE module
*
**/
EC_BOOL cstore_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CSTORE , 1);
}

/**
*
* unregister CSTORE module
*
**/
EC_BOOL cstore_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CSTORE);
}

/**
*
* start CSTORE module
*
**/
UINT32 cstore_start(ngx_http_request_t *r)
{
    CSTORE_MD  *cstore_md;
    UINT32      cstore_md_id;

    cstore_md_id = cbc_md_new(MD_CSTORE, sizeof(CSTORE_MD));
    if(CMPI_ERROR_MODI == cstore_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CSTORE module */
    cstore_md = (CSTORE_MD *)cbc_md_get(MD_CSTORE, cstore_md_id);
    cstore_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */

    CSTORE_MD_METHOD(cstore_md)           = NULL_PTR;
    CSTORE_MD_ROOT_PATH(cstore_md)        = NULL_PTR;
    CSTORE_MD_BUCKET_PATH(cstore_md)      = NULL_PTR;

    CSTORE_MD_FILE_OP(cstore_md)          = NULL_PTR;
    CSTORE_MD_FILE_PATH(cstore_md)        = NULL_PTR;
    CSTORE_MD_FILE_MD5(cstore_md)         = NULL_PTR;
    CSTORE_MD_FILE_BODY(cstore_md)        = NULL_PTR;
    CSTORE_MD_FILE_SIZE(cstore_md)        = 0;
    CSTORE_MD_FILE_S_OFFSET(cstore_md)    = 0;
    CSTORE_MD_FILE_E_OFFSET(cstore_md)    = 0;

    CSTORE_MD_NGX_HTTP_REQ(cstore_md)     = r;

    /*TODO: load all variables into module*/

    CSTORE_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstore_md) = BIT_FALSE;

    CSTORE_MD_CONTENT_LENGTH(cstore_md)   = 0;

    CSTORE_MD_NGX_RSP_BODY(cstore_md)     = NULL_PTR;

    CSTORE_MD_NGX_LOC(cstore_md)          = LOC_NONE_END;
    CSTORE_MD_NGX_RC(cstore_md)           = NGX_OK;

    cstore_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cstore_end, cstore_md_id);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_start: start CSTORE module #%ld\n", cstore_md_id);

    return ( cstore_md_id );
}

/**
*
* end CSTORE module
*
**/
void cstore_end(const UINT32 cstore_md_id)
{
    CSTORE_MD  *cstore_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cstore_end, cstore_md_id);

    cstore_md = CSTORE_MD_GET(cstore_md_id);
    if(NULL_PTR == cstore_md)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_end: "
                                               "cstore_md_id = %ld not exist.\n",
                                               cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cstore_md->usedcounter )
    {
        cstore_md->usedcounter --;
        return ;
    }

    if ( 0 == cstore_md->usedcounter )
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_end: "
                                               "cstore_md_id = %ld is not started.\n",
                                               cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }

    if(NULL_PTR != CSTORE_MD_FILE_BODY(cstore_md))
    {
        cbytes_free(CSTORE_MD_FILE_BODY(cstore_md));
        CSTORE_MD_FILE_BODY(cstore_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORE_MD_FILE_PATH(cstore_md))
    {
        cstring_free(CSTORE_MD_FILE_PATH(cstore_md));
        CSTORE_MD_FILE_PATH(cstore_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md))
    {
        cstring_free(CSTORE_MD_FILE_OP(cstore_md));
        CSTORE_MD_FILE_OP(cstore_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORE_MD_FILE_MD5(cstore_md))
    {
        cstring_free(CSTORE_MD_FILE_MD5(cstore_md));
        CSTORE_MD_FILE_MD5(cstore_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORE_MD_NGX_RSP_BODY(cstore_md))
    {
        cbytes_free(CSTORE_MD_NGX_RSP_BODY(cstore_md));
        CSTORE_MD_NGX_RSP_BODY(cstore_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORE_MD_ROOT_PATH(cstore_md))
    {
        cstring_free(CSTORE_MD_ROOT_PATH(cstore_md));
        CSTORE_MD_ROOT_PATH(cstore_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORE_MD_BUCKET_PATH(cstore_md))
    {
        cstring_free(CSTORE_MD_BUCKET_PATH(cstore_md));
        CSTORE_MD_BUCKET_PATH(cstore_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORE_MD_METHOD(cstore_md))
    {
        cstring_free(CSTORE_MD_METHOD(cstore_md));
        CSTORE_MD_METHOD(cstore_md) = NULL_PTR;
    }

    CSTORE_MD_FILE_SIZE(cstore_md)        = 0;
    CSTORE_MD_FILE_S_OFFSET(cstore_md)    = 0;
    CSTORE_MD_FILE_E_OFFSET(cstore_md)    = 0;

    CSTORE_MD_NGX_HTTP_REQ(cstore_md) = NULL_PTR;

    CSTORE_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstore_md) = BIT_FALSE;

    CSTORE_MD_CONTENT_LENGTH(cstore_md) = 0;

    CSTORE_MD_NGX_LOC(cstore_md)        = LOC_NONE_END;
    CSTORE_MD_NGX_RC(cstore_md)         = NGX_OK;

    /* free module */
    cstore_md->usedcounter = 0;

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "cstore_end: stop CSTORE module #%ld\n", cstore_md_id);
    cbc_md_free(MD_CSTORE, cstore_md_id);

    return ;
}

EC_BOOL cstore_get_ngx_rc(const UINT32 cstore_md_id, ngx_int_t *rc, UINT32 *location)
{
    CSTORE_MD                   *cstore_md;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_get_ngx_rc: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CSTORE_MD_NGX_RC(cstore_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CSTORE_MD_NGX_LOC(cstore_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cstore_set_ngx_rc(const UINT32 cstore_md_id, const ngx_int_t rc, const UINT32 location)
{
    CSTORE_MD                   *cstore_md;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_set_ngx_rc: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    /*do not override*/
    if(NGX_OK != CSTORE_MD_NGX_RC(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_override_ngx_rc: "
                                               "ignore rc %ld due to its %ld now\n",
                                               rc, CSTORE_MD_NGX_RC(cstore_md));
        return (EC_TRUE);
    }

    CSTORE_MD_NGX_RC(cstore_md)  = rc;
    CSTORE_MD_NGX_LOC(cstore_md) = location;

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_set_ngx_rc: "
                                           "set rc %ld\n",
                                           rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cstore_override_ngx_rc(const UINT32 cstore_md_id, const ngx_int_t rc, const UINT32 location)
{
    CSTORE_MD                   *cstore_md;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_override_ngx_rc: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    if(rc == CSTORE_MD_NGX_RC(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_override_ngx_rc: "
                                               "ignore same rc %ld\n",
                                               rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CSTORE_MD_NGX_RC(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_override_ngx_rc: "
                                               "modify rc %ld => %ld\n",
                                               CSTORE_MD_NGX_RC(cstore_md), rc);
        CSTORE_MD_NGX_RC(cstore_md)  = rc;
        CSTORE_MD_NGX_LOC(cstore_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_override_ngx_rc: "
                                           "set rc %ld\n",
                                           rc);

    CSTORE_MD_NGX_RC(cstore_md)  = rc;
    CSTORE_MD_NGX_LOC(cstore_md) = location;

    return (EC_TRUE);
}

EC_BOOL cstore_parse_method(const UINT32 cstore_md_id)
{
    CSTORE_MD                    *cstore_md;

    ngx_http_request_t           *r;
    char                         *method_str;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_parse_method: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    if(EC_FALSE == cngx_get_req_method_str(r, &method_str))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_method: "
                                               "fetch method failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == method_str)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_method: "
                                               "method is null\n");
        return (EC_FALSE);
    }

    CSTORE_MD_METHOD(cstore_md) = cstring_new((UINT8 *)method_str, LOC_CSTORE_0001);
    if(NULL_PTR == CSTORE_MD_METHOD(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_method: "
                                               "new method '%s' failed\n",
                                               method_str);

        safe_free(method_str, LOC_CSTORE_0002);

        return (EC_FALSE);
    }

    safe_free(method_str, LOC_CSTORE_0003);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_method: "
                                           "parsed method '%s'\n",
                                           (char *)CSTORE_MD_METHOD_STR(cstore_md));

    return (EC_TRUE);
}

EC_BOOL cstore_parse_file_path(const UINT32 cstore_md_id)
{
    CSTORE_MD                    *cstore_md;

    ngx_http_request_t           *r;
    char                         *uri_str;
    char                         *bucket_path_str;
    char                         *root_path_str;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_parse_file_path: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    if(EC_FALSE == cngx_get_req_uri(r, &uri_str))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_path: "
                                               "fetch req uri failed\n");
        return (EC_FALSE);
    }

    if(0 == STRCMP(uri_str, (const char *)"/"))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_path: "
                                               "invalid file name '%s'\n",
                                               uri_str);
        safe_free(uri_str, LOC_CSTORE_0004);
        return (EC_FALSE);
    }

    bucket_path_str       = uri_str;

    ASSERT(NULL_PTR == CSTORE_MD_BUCKET_PATH(cstore_md));
    CSTORE_MD_BUCKET_PATH(cstore_md) = cstring_new((UINT8 *)bucket_path_str, LOC_CSTORE_0005);
    if(NULL_PTR == CSTORE_MD_BUCKET_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_path: "
                                               "make bucket path '%s' failed\n",
                                               bucket_path_str);

        safe_free(uri_str, LOC_CSTORE_0006);
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md));

    if(EC_TRUE == cngx_get_root(r, &root_path_str) && NULL_PTR != root_path_str)
    {
        CSTORE_MD_ROOT_PATH(cstore_md) = cstring_new((UINT8 *)root_path_str, LOC_CSTORE_0007);
        if(NULL_PTR == CSTORE_MD_ROOT_PATH(cstore_md))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_path: "
                                                   "make root path '%s' failed\n",
                                                   root_path_str);

            safe_free(root_path_str, LOC_CSTORE_0008);
            safe_free(uri_str, LOC_CSTORE_0009);
            return (EC_FALSE);
        }

        CSTORE_MD_FILE_PATH(cstore_md) = cstring_make("%s%s", root_path_str, bucket_path_str);
        if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_path: "
                                                   "make file path '%s%s' failed\n",
                                                   root_path_str, bucket_path_str);

            safe_free(root_path_str, LOC_CSTORE_0010);
            safe_free(uri_str, LOC_CSTORE_0011);
            return (EC_FALSE);
        }
        safe_free(root_path_str, LOC_CSTORE_0012);
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_path: "
                                               "parsed and composed file path '%s'\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
    }
    else
    {
        CSTORE_MD_FILE_PATH(cstore_md) = cstring_new((UINT8 *)bucket_path_str, LOC_CSTORE_0013);
        if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_path: "
                                                   "make file path '%s' failed\n",
                                                   bucket_path_str);
            safe_free(uri_str, LOC_CSTORE_0014);
            return (EC_FALSE);
        }
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_path: "
                                               "parsed file path '%s'\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
    }

    safe_free(uri_str, LOC_CSTORE_0015);

    return (EC_TRUE);
}

EC_BOOL cstore_parse_file_op(const UINT32 cstore_md_id)
{
    CSTORE_MD                    *cstore_md;

    ngx_http_request_t           *r;
    char                         *file_op_str;

    const char                   *k;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_parse_file_op: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    k = (const char *)"op=";
    if(EC_FALSE == cngx_get_req_argv(r, k, &file_op_str))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_op: "
                                               "get arg '%s' failed\n",
                                               k);
        return (EC_FALSE);
    }

    if(NULL_PTR == file_op_str)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_op: "
                                               "no arg '%s'\n",
                                               k);
        return (EC_FALSE);
    }

    CSTORE_MD_FILE_OP(cstore_md) = cstring_new((UINT8 *)file_op_str, LOC_CSTORE_0016);
    if(NULL_PTR == CSTORE_MD_FILE_OP(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_op: "
                                               "make op '%s' failed\n",
                                               file_op_str);

        safe_free(file_op_str, LOC_CSTORE_0017);
        return (EC_FALSE);
    }
    safe_free(file_op_str, LOC_CSTORE_0018);

    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "[DEBUG] cstore_parse_file_op: "
                                           "parsed op '%s'\n",
                                           (char *)CSTORE_MD_FILE_OP_STR(cstore_md));

    return (EC_TRUE);
}

EC_BOOL cstore_parse_file_range(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_parse_file_range: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*[example] Content-Range: bytes 7-14/20*/
    k = (const char *)"Content-Range";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_range: "
                                               "[cngx] get '%s' failed\n",
                                               k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_range: "
                                               "[cngx] no '%s'\n",
                                               k);
        return (EC_TRUE);
    }

    if(NULL_PTR != v)
    {
        char   *segs[ 4 ];

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_range: "
                                               "[cngx] get var '%s':'%s' done\n",
                                               k, v);

        if(4 != c_str_split(v, (const char *)":-/ \t", (char **)segs, 4))
        {
            dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_range: "
                                                   "[cngx] invalid %s\n",
                                                   k);
            safe_free(v, LOC_CSTORE_0019);
            return (EC_FALSE);
        }

        if(0 != STRCASECMP("bytes", segs[0])
        || EC_FALSE == c_str_is_digit(segs[1])
        || EC_FALSE == c_str_is_digit(segs[2])
        || EC_FALSE == c_str_is_digit(segs[3]))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_range: "
                                                   "[cngx] invald '%s': %s %s-%s/%s\n",
                                                   k, segs[0], segs[1], segs[2], segs[3]);
            safe_free(v, LOC_CSTORE_0020);
            return (EC_FALSE);
        }

        CSTORE_MD_FILE_S_OFFSET(cstore_md) = c_str_to_word(segs[1]);
        CSTORE_MD_FILE_E_OFFSET(cstore_md) = c_str_to_word(segs[2]);
        CSTORE_MD_FILE_SIZE(cstore_md)     = c_str_to_word(segs[3]);

        if(CSTORE_MD_FILE_S_OFFSET(cstore_md) > CSTORE_MD_FILE_E_OFFSET(cstore_md)
        || CSTORE_MD_FILE_SIZE(cstore_md)     < CSTORE_MD_FILE_E_OFFSET(cstore_md))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_range: "
                                                   "[cngx] invald '%s': %s %s-%s/%s\n",
                                                   k, segs[0], segs[1], segs[2], segs[3]);
            safe_free(v, LOC_CSTORE_0021);
            return (EC_FALSE);
        }

        safe_free(v, LOC_CSTORE_0022);

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_range: "
                                               "[cngx] parsed range: [%ld, %ld]/%ld\n",
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cstore_parse_file_md5(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_parse_file_md5: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*Content-MD5: 0123456789abcdef*/
    k = (const char *)"Content-MD5";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_md5: "
                                               "[cngx] get '%s' failed\n",
                                               k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_md5: "
                                               "[cngx] no '%s'\n",
                                               k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_md5: "
                                           "[cngx] parsed '%s':'%s'\n",
                                           k, v);

    CSTORE_MD_FILE_MD5(cstore_md) = cstring_new((UINT8 *)v, LOC_CSTORE_0023);
    if(NULL_PTR == CSTORE_MD_FILE_MD5(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_md5: "
                                               "new cstring '%s' failed\n",
                                               v);
        safe_free(v, LOC_CSTORE_0024);
        return (EC_FALSE);
    }

    safe_free(v, LOC_CSTORE_0025);
    return (EC_TRUE);
}

EC_BOOL cstore_parse_file_body(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_parse_file_body: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    if(CSTORE_MD_FILE_S_OFFSET(cstore_md) > CSTORE_MD_FILE_E_OFFSET(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_body: "
                                               "invalid range [%ld, %ld]\n",
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md));
        return (EC_FALSE);
    }

    if(NULL_PTR == CSTORE_MD_FILE_BODY(cstore_md))
    {
        CSTORE_MD_FILE_BODY(cstore_md) = cbytes_new(0);
        if(NULL_PTR == CSTORE_MD_FILE_BODY(cstore_md))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_body: "
                                                   "new cbytes failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == cngx_read_req_body(r, CSTORE_MD_FILE_BODY(cstore_md), &CSTORE_MD_NGX_RC(cstore_md)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_body: "
                                               "read req body failed\n");

        cbytes_free(CSTORE_MD_FILE_BODY(cstore_md));
        CSTORE_MD_FILE_BODY(cstore_md) = NULL_PTR;
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_body: "
                                           "req body len %ld\n",
                                           CBYTES_LEN(CSTORE_MD_FILE_BODY(cstore_md)));

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_parse_file_body: done\n");

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstore_check_file_path_validity(const CSTRING *file_name)
{
    char        *file_name_str;
    char        *saveptr;
    char        *file_name_seg;
    UINT32       file_name_depth;

    if(NULL_PTR == file_name)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_check_file_path_validity: "
                                               "no file name\n");

        return (EC_FALSE);
    }

    file_name_str = c_str_dup((char *)cstring_get_str(file_name));
    if(NULL_PTR == file_name_str)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_check_file_path_validity: "
                                               "dup '%s' failed\n",
                                               (char *)cstring_get_str(file_name));

        return (EC_FALSE);
    }

    file_name_depth = 0;
    saveptr = file_name_str;
    while((file_name_seg = strtok_r(NULL_PTR, (char *)"/", &saveptr)) != NULL_PTR)
    {
        file_name_depth ++;

        if(CSTORE_FILE_NAME_MAX_DEPTH <= file_name_depth)
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_check_file_path_validity: "
                                                   "file name '%s' depth overflow\n",
                                                   (char *)cstring_get_str(file_name));

            c_str_free(file_name_str);

            return (EC_FALSE);
        }

        if(CSTORE_FILE_NAME_SEG_MAX_SIZE < strlen(file_name_seg))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_check_file_path_validity: "
                                                   "file name '%s' seg size overflow\n",
                                                   (char *)cstring_get_str(file_name));

            c_str_free(file_name_str);

            return (EC_FALSE);
        }

        if(EC_TRUE == c_str_is_in(file_name_seg, (const char *)"|", (const char *)".."))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_check_file_path_validity: "
                                                   "file name '%s' is invalid\n",
                                                   (char *)cstring_get_str(file_name));

            c_str_free(file_name_str);

            return (EC_FALSE);
        }
    }

    c_str_free(file_name_str);

    return (EC_TRUE);
}

STATIC_CAST CSTRING *__cstore_make_part_file_path(CSTRING *file_name, const UINT32 s_offset, const UINT32 e_offset, const UINT32 fsize)
{
    CSTRING     *part_file_path;

    part_file_path = cstring_make("%s.part_%ld_%ld_%ld",
                                 (char *)cstring_get_str(file_name),
                                 s_offset, e_offset, fsize);
    return (part_file_path);
}

EC_BOOL cstore_upload_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;
    CSTRING                     *path_cstr;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_upload_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_upload_file_handler: enter\n");

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_upload_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0026);
        return (EC_FALSE);
    }

    if(CSTORE_MD_FILE_S_OFFSET(cstore_md) > CSTORE_MD_FILE_E_OFFSET(cstore_md)
    || CSTORE_MD_FILE_E_OFFSET(cstore_md) > CSTORE_MD_FILE_SIZE(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_upload_file_handler: "
                                               "file name '%s', invalid range [%ld, %ld]/%ld\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0027);
        return (EC_FALSE);
    }

    path_cstr = __cstore_make_part_file_path(CSTORE_MD_FILE_PATH(cstore_md),
                                            CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                            CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                            CSTORE_MD_FILE_SIZE(cstore_md));
    if(NULL_PTR == path_cstr)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_upload_file_handler: "
                                               "make file name '%s_%ld_%ld_%ld' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0028);
        return (EC_FALSE);
    }
    else
    {
        UINT32      offset;
        UINT32      wsize;
        int         fd;

        fd = c_file_open((char *)cstring_get_str(path_cstr), O_RDWR | O_CREAT, 0666);
        if(ERR_FD == fd)
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_upload_file_handler: "
                                                   "open or create file '%s' failed\n",
                                                   (char *)cstring_get_str(path_cstr));

            cstring_free(path_cstr);

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0029);
            return (EC_FALSE);
        }

        offset = 0;
        wsize  = CSTORE_MD_FILE_E_OFFSET(cstore_md) + 1 - CSTORE_MD_FILE_S_OFFSET(cstore_md);

        if(0 == wsize)
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "warn:cstore_upload_file_handler: "
                                                   "nothing write to file '%s' [%ld, %ld]\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md));

            c_file_close(fd);
            cstring_free(path_cstr);

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0030);
            return (EC_TRUE);
        }

        if(NULL_PTR == CSTORE_MD_FILE_BODY(cstore_md))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "warn:cstore_upload_file_handler: "
                                                   "body of file '%s' [%ld, %ld] is null\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md));

            c_file_close(fd);
            cstring_free(path_cstr);

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0031);

            return (EC_TRUE);
        }

        if(EC_FALSE == c_file_write(fd, &offset, wsize, CBYTES_BUF(CSTORE_MD_FILE_BODY(cstore_md))))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_upload_file_handler: "
                                                   "write file '%s' [%ld, %ld] failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md));

            c_file_close(fd);
            cstring_free(path_cstr);

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0032);

            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_upload_file_handler: "
                                               "write file '%s' [%ld, %ld] done\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md));

        c_file_close(fd);
        cstring_free(path_cstr);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0033);

        return (EC_TRUE);
    }

    /*never reach here*/
    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_upload_file_handler: "
                                           "file '%s', should never reach here\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0034);
    return (EC_FALSE);
}

EC_BOOL cstore_merge_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;
    CSTRING                     *src_file_path;
    CSTRING                     *des_file_path;

    int                          src_fd;
    int                          des_fd;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_merge_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_merge_file_handler: enter\n");

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_merge_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0035);
        return (EC_FALSE);
    }

    des_file_path = CSTORE_MD_FILE_PATH(cstore_md);

    if(CSTORE_MD_FILE_S_OFFSET(cstore_md) > CSTORE_MD_FILE_E_OFFSET(cstore_md)
    || CSTORE_MD_FILE_E_OFFSET(cstore_md) > CSTORE_MD_FILE_SIZE(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_merge_file_handler: "
                                               "file name '%s', invalid range [%ld, %ld]/%ld\n",
                                               (char *)cstring_get_str(des_file_path),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0036);
        return (EC_FALSE);
    }

    src_file_path = __cstore_make_part_file_path(des_file_path,
                                                CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                                CSTORE_MD_FILE_SIZE(cstore_md));
    if(NULL_PTR == src_file_path)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_merge_file_handler: "
                                               "make file name '%s_%ld_%ld_%ld' failed\n",
                                               (char *)cstring_get_str(des_file_path),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0037);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_exist((char *)cstring_get_str(src_file_path)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "[DEBUG] cstore_merge_file_handler: "
                                               "no file '%s' => merge succ\n",
                                               (char *)cstring_get_str(src_file_path));

        cstring_free(src_file_path);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0038);
        return (EC_TRUE);
    }

    /*src file read only*/
    src_fd = c_file_open((char *)cstring_get_str(src_file_path), O_RDONLY, 0666);
    if(ERR_FD == src_fd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_merge_file_handler: "
                                               "open file '%s' failed\n",
                                               (char *)cstring_get_str(src_file_path));

        cstring_free(src_file_path);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0039);
        return (EC_FALSE);
    }

    des_fd = c_file_open((char *)cstring_get_str(des_file_path), O_RDWR | O_CREAT, 0666);
    if(ERR_FD == des_fd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_merge_file_handler: "
                                               "open file '%s' failed\n",
                                               (char *)cstring_get_str(src_file_path));

        c_file_close(src_fd);
        cstring_free(src_file_path);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0040);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_merge(src_fd, des_fd, (UINT32)CSTORE_FILE_MERGE_SEG_SIZE))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_merge_file_handler: "
                                               "merge '%s' to '%s' failed\n",
                                               (char *)cstring_get_str(src_file_path),
                                               (char *)cstring_get_str(des_file_path));

        c_file_close(src_fd);
        c_file_close(des_fd);
        cstring_free(src_file_path);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0041);
        return (EC_FALSE);
    }

    c_file_close(src_fd);
    c_file_close(des_fd);

    /*unlink src file*/
    if(EC_FALSE == c_file_unlink((char *)cstring_get_str(src_file_path)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_merge_file_handler: "
                                               "unlink '%s' failed\n",
                                               (char *)cstring_get_str(src_file_path));

        cstring_free(src_file_path);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0042);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_merge_file_handler: "
                                           "unlink '%s' done\n",
                                           (char *)cstring_get_str(src_file_path));

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_merge_file_handler: "
                                           "merge '%s' to '%s' done\n",
                                           (char *)cstring_get_str(src_file_path),
                                           (char *)cstring_get_str(des_file_path));

    cstring_free(src_file_path);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0043);

    return (EC_TRUE);
}

EC_BOOL cstore_override_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_override_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_override_file_handler: enter\n");

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0044);
        return (EC_FALSE);
    }

    if(CSTORE_MD_FILE_S_OFFSET(cstore_md) > CSTORE_MD_FILE_E_OFFSET(cstore_md)
    || CSTORE_MD_FILE_E_OFFSET(cstore_md) > CSTORE_MD_FILE_SIZE(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                               "file '%s', invalid range [%ld, %ld]/%ld\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0045);
        return (EC_FALSE);
    }

    /*make sure file exist*/
    if(EC_FALSE == c_file_exist((char *)CSTORE_MD_FILE_PATH_STR(cstore_md)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                               "file '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0046);
        return (EC_FALSE);
    }

    /*write file*/
    if(1)
    {
        UINT32                       offset;
        UINT32                       wsize;
        UINT32                       fsize;
        int                          fd;

        fd = c_file_open((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), O_RDWR, 0666);
        if(ERR_FD == fd)
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                                   "open file '%s' failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0047);
            return (EC_FALSE);
        }

        if(EC_FALSE == c_file_size(fd, &fsize))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                                   "size file '%s' failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

            c_file_close(fd);
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0048);

            return (EC_FALSE);
        }

        if(CSTORE_MD_FILE_E_OFFSET(cstore_md) >= fsize)
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                                   "file '%s', file size %ld, "
                                                   "range [%ld, %ld)/%ld overflow \n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   fsize,
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_SIZE(cstore_md));

            c_file_close(fd);
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0049);

            return (EC_FALSE);
        }

        offset = CSTORE_MD_FILE_S_OFFSET(cstore_md);
        wsize  = CSTORE_MD_FILE_E_OFFSET(cstore_md) + 1 - CSTORE_MD_FILE_S_OFFSET(cstore_md);

        if(0 == wsize)
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "warn:cstore_override_file_handler: "
                                                   "write nothing to file '%s' [%ld, %ld]\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md));

            c_file_close(fd);
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0050);

            return (EC_TRUE);
        }

        if(EC_FALSE == c_file_write(fd, &offset, wsize, CBYTES_BUF(CSTORE_MD_FILE_BODY(cstore_md))))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                                   "write file '%s' [%ld, %ld] failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md));

            c_file_close(fd);
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0051);

            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_override_file_handler: "
                                               "write file '%s' [%ld, %ld] done\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0052);

        return (EC_TRUE);
    }

    /*never reach here*/
    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_override_file_handler: "
                                           "file '%s', should never reach here\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0053);
    return (EC_FALSE);
}

EC_BOOL cstore_empty_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;
    int                          fd;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_empty_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_empty_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0054);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), O_RDWR | O_CREAT, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_empty_file_handler: "
                                               "open or create file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0055);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_truncate(fd, 0))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_empty_file_handler: "
                                               "truncate file '%s' to empty failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        c_file_close(fd);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0056);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_empty_file_handler: "
                                           "empty file '%s' done\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

    c_file_close(fd);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0057);

    return (EC_TRUE);

}

EC_BOOL cstore_check_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    CMD5_DIGEST                  seg_md5sum;
    UINT32                       fsize;
    int                          fd;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_check_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0058);
        return (EC_FALSE);
    }

    if(NULL_PTR == CSTORE_MD_FILE_MD5(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                               "no md5\n");

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0059);
        return (EC_FALSE);
    }

    if(CSTORE_MD_FILE_S_OFFSET(cstore_md) >= CSTORE_MD_FILE_E_OFFSET(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                               "invalid content-range: [%ld, %ld]/%ld\n",
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0060);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), F_OK))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                               "file '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0061);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                               "open file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0062);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                               "size file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0063);

        return (EC_FALSE);
    }

    if(fsize != CSTORE_MD_FILE_SIZE(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                               "file '%s' size %ld != %ld\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               fsize,
                                               CSTORE_MD_FILE_SIZE(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_UNAUTHORIZED, LOC_CSTORE_0064);

        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_check_file_handler: "
                                           "file '%s' size %ld matched\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                           CSTORE_MD_FILE_SIZE(cstore_md));

    if(NULL_PTR != CSTORE_MD_FILE_MD5(cstore_md))
    {
        UINT32      data_size;

        data_size = CSTORE_MD_FILE_E_OFFSET(cstore_md) + 1 - CSTORE_MD_FILE_S_OFFSET(cstore_md);
        if(EC_FALSE == c_file_seg_md5(fd, CSTORE_MD_FILE_S_OFFSET(cstore_md),
                            data_size, CMD5_DIGEST_SUM(&seg_md5sum)))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_check_file_handler: "
                                                   "md5sum file '%s' range [%ld, %ld] failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md));

            c_file_close(fd);
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0065);

            return (EC_FALSE);
        }

        c_file_close(fd);

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_check_file_handler: "
                                               "file '%s' range [%ld, %ld] => md5 %s\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               cmd5_digest_hex_str(&seg_md5sum));

        if(0 != STRCASECMP(cmd5_digest_hex_str(&seg_md5sum), (char *)CSTORE_MD_FILE_MD5_STR(cstore_md)))
        {
            dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_check_file_handler: "
                                                   "file '%s' range [%ld, %ld] md5 %s != %s\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                                   CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                                   CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                                   cmd5_digest_hex_str(&seg_md5sum),
                                                   CSTORE_MD_FILE_MD5_STR(cstore_md));

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_UNAUTHORIZED, LOC_CSTORE_0066);
            return (EC_TRUE);
        }

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_check_file_handler: "
                                               "file '%s' range [%ld, %ld] md5 %s matched\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_MD5_STR(cstore_md));

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0067);
        return (EC_TRUE);
    }

    c_file_close(fd);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0068);
    return (EC_TRUE);
}

EC_BOOL cstore_delete_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_delete_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_delete_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0069);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), F_OK))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_delete_file_handler: "
                                               "file '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0070);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_unlink((char *)CSTORE_MD_FILE_PATH_STR(cstore_md)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_delete_file_handler: "
                                               "unlink file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0071);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_delete_file_handler: "
                                           "unlink file '%s' done\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0072);
    return (EC_TRUE);
}

EC_BOOL cstore_size_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    UINT32                       fsize;
    int                          fd;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_size_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_size_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0073);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), F_OK))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_size_file_handler: "
                                               "file '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        if(EC_FALSE == cngx_has_var(r, (const char *)CSTORE_CNGX_VAR_PULL_BACKEND_CMD))
        {
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0074);
            return (EC_FALSE);
        }

        if(EC_FALSE == cstore_pull_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_size_file_handler: "
                                                   "pull file '%s' failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0075);
            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "[DEBUG] cstore_size_file_handler: "
                                               "pull file '%s' done\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
    }

    fd = c_file_open((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_size_file_handler: "
                                               "open file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0076);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_size_file_handler: "
                                               "size file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0077);

        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_size_file_handler: "
                                           "file '%s' size %ld\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                           fsize);

    cngx_set_header_out_kv(r, (const char *)"X-File-Size", c_word_to_str(fsize));
    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0078);
    return (EC_TRUE);
}

EC_BOOL cstore_md5_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    CMD5_DIGEST                  seg_md5sum;
    UINT32                       fsize;
    UINT32                       data_size;
    int                          fd;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_md5_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_md5_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0079);
        return (EC_FALSE);
    }

    if(CSTORE_MD_FILE_S_OFFSET(cstore_md) > CSTORE_MD_FILE_E_OFFSET(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_md5_file_handler: "
                                               "invalid content-range: [%ld, %ld]/%ld\n",
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0080);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), F_OK))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_md5_file_handler: "
                                               "file '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        if(EC_FALSE == cngx_has_var(r, (const char *)CSTORE_CNGX_VAR_PULL_BACKEND_CMD))
        {
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0081);
            return (EC_FALSE);
        }

        if(EC_FALSE == cstore_pull_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_md5_file_handler: "
                                                   "pull file '%s' failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0082);
            return (EC_FALSE);
        }
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_md5_file_handler: "
                                               "pull file '%s' done\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
    }

    fd = c_file_open((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_md5_file_handler: "
                                               "open file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0083);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_md5_file_handler: "
                                               "size file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0084);

        return (EC_FALSE);
    }

    if(0 == CSTORE_MD_FILE_S_OFFSET(cstore_md)
    && 0 == CSTORE_MD_FILE_E_OFFSET(cstore_md)
    && 0 == CSTORE_MD_FILE_SIZE(cstore_md))
    {
        CSTORE_MD_FILE_S_OFFSET(cstore_md) = 0;
        CSTORE_MD_FILE_E_OFFSET(cstore_md) = fsize - 1;
        CSTORE_MD_FILE_SIZE(cstore_md)     = fsize;
    }

    data_size = CSTORE_MD_FILE_E_OFFSET(cstore_md) + 1 - CSTORE_MD_FILE_S_OFFSET(cstore_md);
    if(EC_FALSE == c_file_seg_md5(fd, CSTORE_MD_FILE_S_OFFSET(cstore_md),
                        data_size, CMD5_DIGEST_SUM(&seg_md5sum)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_md5_file_handler: "
                                               "md5sum file '%s' range [%ld, %ld] failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0085);

        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_md5_file_handler: "
                                           "file '%s' range [%ld, %ld]/%ld => md5 %s\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                           CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                           CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                           CSTORE_MD_FILE_SIZE(cstore_md),
                                           cmd5_digest_hex_str(&seg_md5sum));

    cngx_set_header_out_kv(r, (const char *)"X-Content-Range",
                               c_format_str("%ld-%ld/%ld",
                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                               CSTORE_MD_FILE_SIZE(cstore_md)));

    cngx_set_header_out_kv(r, (const char *)"X-MD5", cmd5_digest_hex_str(&seg_md5sum));

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0086);
    return (EC_TRUE);
}

EC_BOOL cstore_download_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    UINT32                       fsize;
    UINT32                       rsize;
    CBYTES                      *rsp_body;
    UINT32                       offset;
    uint32_t                     client_body_max_size;
    int                          fd;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_download_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0087);
        return (EC_FALSE);
    }

    if(CSTORE_MD_FILE_S_OFFSET(cstore_md) > CSTORE_MD_FILE_E_OFFSET(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "invalid content-range: [%ld, %ld]/%ld\n",
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_SIZE(cstore_md));

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0088);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), F_OK))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "file '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        if(EC_FALSE == cngx_has_var(r, (const char *)CSTORE_CNGX_VAR_PULL_BACKEND_CMD))
        {
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0089);
            return (EC_FALSE);
        }

        if(EC_FALSE == cstore_pull_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                                   "pull file '%s' failed\n",
                                                   (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0090);
            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "[DEBUG] cstore_download_file_handler: "
                                               "pull file '%s' done\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
    }

    fd = c_file_open((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "open file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0091);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "size file '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0092);

        return (EC_FALSE);
    }

    if(CSTORE_MD_FILE_E_OFFSET(cstore_md) >= fsize)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "file '%s', size %ld, range [%ld, %ld] is invalid\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               fsize,
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md));

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0093);

        return (EC_FALSE);
    }

    if(0 == CSTORE_MD_FILE_S_OFFSET(cstore_md)
    && 0 == CSTORE_MD_FILE_E_OFFSET(cstore_md)
    && 0 == CSTORE_MD_FILE_SIZE(cstore_md))
    {
        CSTORE_MD_FILE_S_OFFSET(cstore_md) = 0;
        CSTORE_MD_FILE_E_OFFSET(cstore_md) = fsize - 1;
        CSTORE_MD_FILE_SIZE(cstore_md)     = fsize;
    }

    rsize  = CSTORE_MD_FILE_E_OFFSET(cstore_md) + 1 - CSTORE_MD_FILE_S_OFFSET(cstore_md);
    offset = CSTORE_MD_FILE_S_OFFSET(cstore_md);

    cngx_get_client_body_max_size(r, &client_body_max_size);

    if(rsize > client_body_max_size)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "file '%s' range [%ld, %ld], "
                                               "rsize %ld > client_body_max_size %u\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               rsize, client_body_max_size);

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0094);

        return (EC_FALSE);
    }

    rsp_body = cbytes_new(rsize);
    if(NULL_PTR == rsp_body)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "file '%s' range [%ld, %ld], "
                                               "new cbytes with size %ld failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                               rsize);

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0095);

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_load(fd, &offset, rsize, CBYTES_BUF(rsp_body)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_download_file_handler: "
                                               "read file '%s' range [%ld, %ld] failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                               CSTORE_MD_FILE_E_OFFSET(cstore_md));

        cbytes_free(rsp_body);

        c_file_close(fd);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0096);

        return (EC_FALSE);
    }

    CSTORE_MD_NGX_RSP_BODY(cstore_md) = rsp_body;

    c_file_close(fd);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_download_file_handler: "
                                           "read file '%s' range [%ld, %ld]/%ld => done\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                           CSTORE_MD_FILE_S_OFFSET(cstore_md),
                                           CSTORE_MD_FILE_E_OFFSET(cstore_md),
                                           CSTORE_MD_FILE_SIZE(cstore_md));

    cngx_set_header_out_kv(r, (const char *)"X-Content-Range",
                               c_format_str("%ld-%ld/%ld",
                               CSTORE_MD_FILE_S_OFFSET(cstore_md),
                               CSTORE_MD_FILE_E_OFFSET(cstore_md),
                               CSTORE_MD_FILE_SIZE(cstore_md)));

    cngx_set_header_out_kv(r, (const char *)"Content-Length", c_word_to_str(rsize));

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0097);
    return (EC_TRUE);
}

/**
*
* complete trigger push file to backend storage
*
**/
EC_BOOL cstore_complete_file_handler(const UINT32 cstore_md_id)
{
#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_complete_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    if(EC_FALSE == cstore_push_file_handler(cstore_md_id))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_complete_file_handler: "
                                               "push file to backend failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_complete_file_handler: "
                                           "push file to backend done\n");

    return (EC_TRUE);
}

/**
*
* make dir in backend storage
*
**/
EC_BOOL cstore_make_dir_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;
    char                        *bucket_dir_path;
    char                        *backend_cmd_format;
    char                        *backend_cmd;

    char                        *cmd_output;
    UINT32                       cmd_output_max_size;
    UINT32                       cmd_output_size;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_make_dir_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_make_dir_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0098);
        return (EC_FALSE);
    }

    k = (const char *)CSTORE_CNGX_VAR_MKDIR_BACKEND_CMD;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_make_dir_handler: "
                                               "get var '%s' failed\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0099);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_make_dir_handler: "
                                               "not configure '%s'\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_ALLOWED, LOC_CSTORE_0100);
        return (EC_FALSE);
    }

    backend_cmd_format = v;

    bucket_dir_path = (char *)CSTORE_MD_BUCKET_PATH_STR(cstore_md);

    k = (const char *)"{bucket_path}";
    backend_cmd = c_str_replace(backend_cmd_format, k, bucket_dir_path);
    if(NULL_PTR == backend_cmd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_make_dir_handler: "
                                               "replace '%s' with '%s' in '%s' failed\n",
                                               k, bucket_dir_path, backend_cmd_format);

        safe_free(backend_cmd_format, LOC_CSTORE_0101);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0102);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_make_dir_handler: "
                                           "replace '%s' with '%s' in '%s' => '%s'\n",
                                           k, bucket_dir_path, backend_cmd_format, backend_cmd);
    safe_free(backend_cmd_format, LOC_CSTORE_0103);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_make_dir_handler: "
                                           "parsed cmd '%s'\n",
                                           backend_cmd);

    /*excute command*/
    cmd_output_max_size = CSTORE_CACHE_MAX_SIZE;
    cmd_output_size     = 0;

    cmd_output = (char *)safe_malloc(cmd_output_max_size, LOC_CSTORE_0104);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_make_dir_handler: "
                                               "alloc cmd ouptut with size %ld failed\n",
                                               cmd_output_max_size);

        safe_free(backend_cmd, LOC_CSTORE_0105);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0106);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_exec_shell(backend_cmd, cmd_output, cmd_output_max_size, &cmd_output_size))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_make_dir_handler: "
                                               "execute cmd '%s' failed\n",
                                               backend_cmd);

        safe_free(cmd_output, LOC_CSTORE_0107);
        safe_free(backend_cmd, LOC_CSTORE_0108);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0109);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_make_dir_handler: "
                                           "cmd: '%s'\n"
                                           "result: '\n%.*s\n'\n",
                                           backend_cmd,
                                           (uint32_t)cmd_output_size, cmd_output);

    safe_free(cmd_output, LOC_CSTORE_0110);
    safe_free(backend_cmd, LOC_CSTORE_0111);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0112);
    return (EC_TRUE);
}

/**
*
* push file to backend storage
*
**/
EC_BOOL cstore_push_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;
    char                        *src_file_path;
    char                        *bucket_file_path;
    char                        *backend_cmd_format;
    char                        *backend_cmd;

    char                        *cmd_output;
    UINT32                       cmd_output_max_size;
    UINT32                       cmd_output_size;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_push_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0113);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), F_OK))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                               "file '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0114);
        return (EC_FALSE);
    }

    k = (const char *)CSTORE_CNGX_VAR_PUSH_BACKEND_CMD;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                               "get var '%s' failed\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0115);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CSTORE, 1)(LOGSTDOUT, "[DEBUG] cstore_push_file_handler: "
                                               "not configure '%s'\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0116);
        return (EC_TRUE);
    }

    backend_cmd_format = v;

    src_file_path      = (char *)CSTORE_MD_FILE_PATH_STR(cstore_md);
    bucket_file_path   = (char *)CSTORE_MD_BUCKET_PATH_STR(cstore_md);

    k = (const char *)CSTORE_CNGX_VAR_MKDIR_BACKEND_CMD;
    if(EC_TRUE == cngx_has_var(r, k))
    {
        char                        *bucket_dir_path;

        bucket_dir_path = c_dirname(bucket_file_path);
        if(NULL_PTR == bucket_dir_path)
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                                   "dirname of '%s' failed\n",
                                                   bucket_file_path);

            safe_free(backend_cmd_format, LOC_CSTORE_0117);
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0118);
            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_push_file_handler: "
                                               "dirname '%s' => '%s'\n",
                                               bucket_file_path, bucket_dir_path);

        /*trick: exchange temporarily*/
        cstring_set_str(CSTORE_MD_BUCKET_PATH(cstore_md), (UINT8 *)bucket_dir_path);

        if(EC_FALSE == cstore_make_dir_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                                   "mkdir '%s' failed\n",
                                                   bucket_dir_path);

            /*trick: exchange back*/
            cstring_set_str(CSTORE_MD_BUCKET_PATH(cstore_md), (UINT8 *)bucket_file_path);

            safe_free(bucket_dir_path, LOC_CSTORE_0119);
            safe_free(backend_cmd_format, LOC_CSTORE_0120);
            cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_ALLOWED, LOC_CSTORE_0121);
            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_push_file_handler: "
                                               "mkdir '%s' done\n",
                                               bucket_dir_path);

        /*trick: exchange back*/
        cstring_set_str(CSTORE_MD_BUCKET_PATH(cstore_md), (UINT8 *)bucket_file_path);;

        safe_free(bucket_dir_path, LOC_CSTORE_0122);
    }

    k = (const char *)"{file_path}";
    backend_cmd = c_str_replace(backend_cmd_format, (const char *)"{file_path}", src_file_path);
    if(NULL_PTR == backend_cmd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                               "replace '%s' with '%s' in '%s' failed\n",
                                               k, src_file_path, backend_cmd_format);

        safe_free(backend_cmd_format, LOC_CSTORE_0123);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0124);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_push_file_handler: "
                                           "replace '%s' with '%s' in '%s' => '%s'\n",
                                           k, src_file_path, backend_cmd_format, backend_cmd);
    safe_free(backend_cmd_format, LOC_CSTORE_0125);
    backend_cmd_format = backend_cmd;

    k = (const char *)"{bucket_path}";
    backend_cmd = c_str_replace(backend_cmd_format, k, bucket_file_path);
    if(NULL_PTR == backend_cmd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                               "replace '%s' with '%s' in '%s' failed\n",
                                               k, bucket_file_path, backend_cmd_format);

        safe_free(backend_cmd_format, LOC_CSTORE_0126);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0127);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_push_file_handler: "
                                           "replace '%s' with '%s' in '%s' => '%s'\n",
                                           k, bucket_file_path, backend_cmd_format, backend_cmd);
    safe_free(backend_cmd_format, LOC_CSTORE_0128);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_push_file_handler: "
                                           "parsed cmd '%s'\n",
                                           backend_cmd);

    /*excute command*/
    cmd_output_max_size = CSTORE_CACHE_MAX_SIZE;
    cmd_output_size     = 0;

    cmd_output = (char *)safe_malloc(cmd_output_max_size, LOC_CSTORE_0129);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                               "alloc cmd ouptut with size %ld failed\n",
                                               cmd_output_max_size);

        safe_free(backend_cmd, LOC_CSTORE_0130);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0131);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_exec_shell(backend_cmd, cmd_output, cmd_output_max_size, &cmd_output_size))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_push_file_handler: "
                                               "execute cmd '%s' failed\n",
                                               backend_cmd);

        safe_free(cmd_output, LOC_CSTORE_0132);
        safe_free(backend_cmd, LOC_CSTORE_0133);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0134);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_push_file_handler: "
                                           "cmd: '%s'\n"
                                           "result: '\n%.*s\n'\n",
                                           backend_cmd,
                                           (uint32_t)cmd_output_size, cmd_output);

    safe_free(cmd_output, LOC_CSTORE_0135);
    safe_free(backend_cmd, LOC_CSTORE_0136);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0137);
    return (EC_TRUE);
}

/**
*
* pull file from backend storage
*
**/
EC_BOOL cstore_pull_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;
    char                        *src_file_path;
    char                        *bucket_file_path;
    char                        *backend_cmd_format;
    char                        *backend_cmd;

    char                        *cmd_output;
    UINT32                       cmd_output_max_size;
    UINT32                       cmd_output_size;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_pull_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0138);
        return (EC_FALSE);
    }

    if(EC_TRUE == c_file_access((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), F_OK))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "file '%s' already exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_ALLOWED, LOC_CSTORE_0139);
        return (EC_FALSE);
    }

    k = (const char *)CSTORE_CNGX_VAR_PULL_BACKEND_CMD;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "get var '%s' failed\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0140);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "not configure '%s'\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_ALLOWED, LOC_CSTORE_0141);
        return (EC_FALSE);
    }

    backend_cmd_format = v;

    src_file_path      = (char *)CSTORE_MD_FILE_PATH_STR(cstore_md);
    bucket_file_path   = (char *)CSTORE_MD_BUCKET_PATH_STR(cstore_md);

    k = (const char *)"{file_path}";
    backend_cmd = c_str_replace(backend_cmd_format, (const char *)"{file_path}", src_file_path);
    if(NULL_PTR == backend_cmd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "replace '%s' with '%s' in '%s' failed\n",
                                               k, src_file_path, backend_cmd_format);

        safe_free(backend_cmd_format, LOC_CSTORE_0142);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0143);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_pull_file_handler: "
                                           "replace '%s' with '%s' in '%s' => '%s'\n",
                                           k, src_file_path, backend_cmd_format, backend_cmd);
    safe_free(backend_cmd_format, LOC_CSTORE_0144);
    backend_cmd_format = backend_cmd;

    k = (const char *)"{bucket_path}";
    backend_cmd = c_str_replace(backend_cmd_format, k, bucket_file_path);
    if(NULL_PTR == backend_cmd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "replace '%s' with '%s' in '%s' failed\n",
                                               k, bucket_file_path, backend_cmd_format);

        safe_free(backend_cmd_format, LOC_CSTORE_0145);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0146);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_pull_file_handler: "
                                           "replace '%s' with '%s' in '%s' => '%s'\n",
                                           k, bucket_file_path, backend_cmd_format, backend_cmd);
    safe_free(backend_cmd_format, LOC_CSTORE_0147);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_pull_file_handler: "
                                           "parsed cmd '%s'\n",
                                           backend_cmd);

    /*excute command*/
    cmd_output_max_size = CSTORE_CACHE_MAX_SIZE;
    cmd_output_size     = 0;

    cmd_output = (char *)safe_malloc(cmd_output_max_size, LOC_CSTORE_0148);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "alloc cmd ouptut with size %ld failed\n",
                                               cmd_output_max_size);

        safe_free(backend_cmd, LOC_CSTORE_0149);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0150);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_exec_shell(backend_cmd, cmd_output, cmd_output_max_size, &cmd_output_size))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_pull_file_handler: "
                                               "execute cmd '%s' failed\n",
                                               backend_cmd);

        safe_free(cmd_output, LOC_CSTORE_0151);
        safe_free(backend_cmd, LOC_CSTORE_0152);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0153);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_pull_file_handler: "
                                           "cmd: '%s'\n"
                                           "result: '\n%.*s\n'\n",
                                           backend_cmd,
                                           (uint32_t)cmd_output_size, cmd_output);

    safe_free(cmd_output, LOC_CSTORE_0154);
    safe_free(backend_cmd, LOC_CSTORE_0155);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0156);
    return (EC_TRUE);
}

/**
*
* purge file or directory from backend storage
*
**/
EC_BOOL cstore_purge_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

    char                        *bucket_file_path;
    char                        *backend_cmd_format;
    char                        *backend_cmd;

    char                        *cmd_output;
    UINT32                       cmd_output_max_size;
    UINT32                       cmd_output_size;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_purge_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_purge_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0157);
        return (EC_FALSE);
    }

    k = (const char *)CSTORE_CNGX_VAR_PURGE_BACKEND_CMD;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_purge_file_handler: "
                                               "get var '%s' failed\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0158);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_purge_file_handler: "
                                               "not configure '%s'\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_ALLOWED, LOC_CSTORE_0159);
        return (EC_FALSE);
    }

    backend_cmd_format = v;

    bucket_file_path   = (char *)CSTORE_MD_BUCKET_PATH_STR(cstore_md);

    k = (const char *)"{bucket_path}";
    backend_cmd = c_str_replace(backend_cmd_format, k, bucket_file_path);
    if(NULL_PTR == backend_cmd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_purge_file_handler: "
                                               "replace '%s' with '%s' in '%s' failed\n",
                                               k, bucket_file_path, backend_cmd_format);

        safe_free(backend_cmd_format, LOC_CSTORE_0160);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0161);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_purge_file_handler: "
                                           "replace '%s' with '%s' in '%s' => '%s'\n",
                                           k, bucket_file_path, backend_cmd_format, backend_cmd);
    safe_free(backend_cmd_format, LOC_CSTORE_0162);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_purge_file_handler: "
                                           "parsed cmd '%s'\n",
                                           backend_cmd);

    /*excute command*/
    cmd_output_max_size = CSTORE_CACHE_MAX_SIZE;
    cmd_output_size     = 0;

    cmd_output = (char *)safe_malloc(cmd_output_max_size, LOC_CSTORE_0163);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_purge_file_handler: "
                                               "alloc cmd ouptut with size %ld failed\n",
                                               cmd_output_max_size);

        safe_free(backend_cmd, LOC_CSTORE_0164);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0165);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_exec_shell(backend_cmd, cmd_output, cmd_output_max_size, &cmd_output_size))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_purge_file_handler: "
                                               "execute cmd '%s' failed\n",
                                               backend_cmd);

        safe_free(cmd_output, LOC_CSTORE_0166);
        safe_free(backend_cmd, LOC_CSTORE_0167);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0168);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_purge_file_handler: "
                                           "cmd: '%s'\n"
                                           "result: '\n%.*s\n'\n",
                                           backend_cmd,
                                           (uint32_t)cmd_output_size, cmd_output);

    safe_free(cmd_output, LOC_CSTORE_0169);
    safe_free(backend_cmd, LOC_CSTORE_0170);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0171);
    return (EC_TRUE);
}

/**
*
* list files of backend storage
*
**/
EC_BOOL cstore_list_file_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

    char                        *bucket_file_path;
    char                        *backend_cmd_format;
    char                        *backend_cmd;

    char                        *cmd_output;
    UINT32                       cmd_output_max_size;
    UINT32                       cmd_output_size;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_list_file_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_file_handler: "
                                               "no file name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0172);
        return (EC_FALSE);
    }

    k = (const char *)CSTORE_CNGX_VAR_LIST_BACKEND_CMD;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_file_handler: "
                                               "get var '%s' failed\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0173);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_file_handler: "
                                               "not configure '%s'\n",
                                               k);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_ALLOWED, LOC_CSTORE_0174);
        return (EC_FALSE);
    }

    backend_cmd_format = v;

    bucket_file_path   = (char *)CSTORE_MD_BUCKET_PATH_STR(cstore_md);

    k = (const char *)"{bucket_path}";
    backend_cmd = c_str_replace(backend_cmd_format, k, bucket_file_path);
    if(NULL_PTR == backend_cmd)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_file_handler: "
                                               "replace '%s' with '%s' in '%s' failed\n",
                                               k, bucket_file_path, backend_cmd_format);

        safe_free(backend_cmd_format, LOC_CSTORE_0175);
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0176);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_list_file_handler: "
                                           "replace '%s' with '%s' in '%s' => '%s'\n",
                                           k, bucket_file_path, backend_cmd_format, backend_cmd);
    safe_free(backend_cmd_format, LOC_CSTORE_0177);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_list_file_handler: "
                                           "parsed cmd '%s'\n",
                                           backend_cmd);

    /*excute command*/
    cmd_output_max_size = CSTORE_CACHE_MAX_SIZE;
    cmd_output_size     = 0;

    cmd_output = (char *)safe_malloc(cmd_output_max_size, LOC_CSTORE_0178);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_file_handler: "
                                               "alloc cmd ouptut with size %ld failed\n",
                                               cmd_output_max_size);

        safe_free(backend_cmd, LOC_CSTORE_0179);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0180);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_exec_shell(backend_cmd, cmd_output, cmd_output_max_size, &cmd_output_size))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_file_handler: "
                                               "execute cmd '%s' failed\n",
                                               backend_cmd);

        safe_free(cmd_output, LOC_CSTORE_0181);
        safe_free(backend_cmd, LOC_CSTORE_0182);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0183);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_list_file_handler: "
                                           "cmd: '%s'\n"
                                           "result: '\n%.*s\n'\n",
                                           backend_cmd,
                                           (uint32_t)cmd_output_size, cmd_output);

    /*make response*/
    CSTORE_MD_NGX_RSP_BODY(cstore_md) = cbytes_new(0);
    if(NULL_PTR == CSTORE_MD_NGX_RSP_BODY(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_file_handler: "
                                               "cmd: '%s'\n"
                                               "result: '\n%.*s\n'"
                                               "=> new rsp body failed\n",
                                               backend_cmd,
                                               (uint32_t)cmd_output_size, cmd_output);

        safe_free(cmd_output, LOC_CSTORE_0184);
        safe_free(backend_cmd, LOC_CSTORE_0185);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0186);
        return (EC_FALSE);
    }

    cbytes_mount(CSTORE_MD_NGX_RSP_BODY(cstore_md),
                    cmd_output_size, (UINT8 *)cmd_output, BIT_FALSE);

    cngx_set_header_out_kv(r, (const char *)"Content-Length", c_word_to_str(cmd_output_size));

    safe_free(backend_cmd, LOC_CSTORE_0187);

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0188);
    return (EC_TRUE);
}

EC_BOOL cstore_delete_dir_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                *cstore_md;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_delete_dir_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_delete_dir_handler: "
                                               "no dir name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0189);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_dir_exist((char *)CSTORE_MD_FILE_PATH_STR(cstore_md)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_delete_dir_handler: "
                                               "dir '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0190);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_dir_remove((char *)CSTORE_MD_FILE_PATH_STR(cstore_md)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_delete_dir_handler: "
                                               "remove dir '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0191);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_delete_dir_handler: "
                                           "remove dir '%s' done\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0192);
    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstore_list_dir(char *dir_path, UINT32 *file_num,
                char *cmd_output, const UINT32 cmd_output_max_size, UINT32 *cmd_output_size)
{
    DIR                         *dp;
    struct dirent               *entry;
    UINT32                       dir_path_len;

    dp = opendir(dir_path);
    if(NULL_PTR == dp)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                               "open dir '%s' failed\n",
                                               dir_path);
        return (EC_FALSE);
    }

    if(0 != chdir(dir_path))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                               "cd dir '%s' failed\n",
                                               dir_path);
        closedir(dp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] __cstore_list_dir: "
                                           "cd dir '%s'\n",
                                           dir_path);

    dir_path_len = strlen(dir_path);

    while(NULL_PTR != (entry = readdir(dp)))
    {
        struct stat      statbuf;

        if(0 != lstat(entry->d_name, &statbuf))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                                   "lstat '%s/%s' failed\n",
                                                   dir_path, entry->d_name);

            closedir(dp);
            return (EC_FALSE);
        }

        if(0 == STRCASECMP(entry->d_name, ".")
        || 0 == STRCASECMP(entry->d_name, ".."))
        {
            continue;
        }

        if(S_IFDIR  & statbuf.st_mode)
        {
            char    *child_dir_path;

            if('/' == dir_path[ dir_path_len - 1 ])
            {
                child_dir_path = c_str_make("%s%s", dir_path, entry->d_name);
                if(NULL_PTR == child_dir_path)
                {
                    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                                           "make dir str '%s%s' failed\n",
                                                           dir_path, entry->d_name);

                    closedir(dp);
                    return (EC_FALSE);
                }
                dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] __cstore_list_dir: "
                                                       "make dir str '%s%s' => %s\n",
                                                       dir_path, entry->d_name, child_dir_path);
            }
            else
            {
                child_dir_path = c_str_make("%s/%s", dir_path, entry->d_name);
                if(NULL_PTR == child_dir_path)
                {
                    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                                           "make dir str '%s/%s' failed\n",
                                                           dir_path, entry->d_name);

                    closedir(dp);
                    return (EC_FALSE);
                }
                dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] __cstore_list_dir: "
                                                       "make dir str '%s/%s' => %s\n",
                                                       dir_path, entry->d_name, child_dir_path);
            }

            if(EC_FALSE == __cstore_list_dir(child_dir_path, file_num,
                                    cmd_output, cmd_output_max_size, cmd_output_size))
            {
                dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                                       "finger dir '%s' failed\n",
                                                       child_dir_path);

                c_str_free(child_dir_path);
                closedir(dp);
                return (EC_FALSE);
            }

            c_str_free(child_dir_path);

            if(0 != chdir(dir_path))
            {
                dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                                       "cd dir '%s' again but failed\n",
                                                       dir_path);
                closedir(dp);
                return (EC_FALSE);
            }

            dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] __cstore_list_dir: "
                                                   "cd dir '%s' again\n",
                                                   dir_path);
            continue;
        }

        if(S_IFREG & statbuf.st_mode)/*cover S_IFLNK*/
        {
            if('/' == dir_path[ dir_path_len - 1 ])
            {
                char        *file_path;
                uint32_t     child_file_len;
                uint32_t     cmd_output_left_size;

                child_file_len       = dir_path_len + strlen(entry->d_name) + 1;
                cmd_output_left_size = (uint32_t)(cmd_output_max_size - (*cmd_output_size));

                if(child_file_len >= cmd_output_left_size)
                {
                    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                                           "make file str '%s%s' failed\n",
                                                           dir_path, entry->d_name);

                    closedir(dp);
                    return (EC_FALSE);
                }

                file_path = cmd_output + (*cmd_output_size);

                (*cmd_output_size) += snprintf(file_path, cmd_output_left_size, "%s%s\n",
                                               dir_path, entry->d_name);

                (*file_num) ++;

                dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] __cstore_list_dir: "
                                                       "make file str '%s%s' => [%ld] %.*s\n",
                                                       dir_path, entry->d_name,
                                                       (*file_num),
                                                       child_file_len, file_path);
            }
            else
            {
                char        *file_path;
                uint32_t     child_file_len;
                uint32_t     cmd_output_left_size;

                child_file_len       = dir_path_len + 1 + strlen(entry->d_name) + 1;
                cmd_output_left_size = (uint32_t)(cmd_output_max_size - (*cmd_output_size));

                if(child_file_len >= cmd_output_left_size)
                {
                    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:__cstore_list_dir: "
                                                           "make file str '%s/%s' failed\n",
                                                           dir_path, entry->d_name);

                    closedir(dp);
                    return (EC_FALSE);
                }

                file_path = cmd_output + (*cmd_output_size);

                (*cmd_output_size) += snprintf(file_path, cmd_output_left_size, "%s/%s\n",
                                               dir_path, entry->d_name);

                (*file_num) ++;

                dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] __cstore_list_dir: "
                                                       "make file str '%s/%s' => [%ld] %.*s\n",
                                                       dir_path, entry->d_name,
                                                       (*file_num),
                                                       child_file_len, file_path);
            }

            continue;
        }
    }

    closedir(dp);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] __cstore_list_dir: "
                                           "close dir '%s'\n",
                                           dir_path);
    return (EC_TRUE);
}

/**
*
* finger regular file from dir
*
**/
EC_BOOL cstore_list_dir_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

    char                        *cmd_output;
    UINT32                       cmd_output_max_size;
    UINT32                       cmd_output_size;
    UINT32                       file_num;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_list_dir_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*check validity*/
    if(NULL_PTR == CSTORE_MD_FILE_PATH(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_dir_handler: "
                                               "no dir name\n");
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0193);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_dir_exist((char *)CSTORE_MD_FILE_PATH_STR(cstore_md)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_dir_handler: "
                                               "dir '%s' not exist\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));
        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_NOT_FOUND, LOC_CSTORE_0194);
        return (EC_FALSE);
    }

    cmd_output_max_size = CSTORE_CACHE_MAX_SIZE;
    cmd_output_size     = 0;

    cmd_output = (char *)safe_malloc(cmd_output_max_size, LOC_CSTORE_0195);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_dir_handler: "
                                               "alloc cmd ouptut with size %ld failed\n",
                                               cmd_output_max_size);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0196);
        return (EC_TRUE);
    }

    file_num = 0;
    if(EC_FALSE == __cstore_list_dir((char *)CSTORE_MD_FILE_PATH_STR(cstore_md), &file_num,
                                    cmd_output, cmd_output_max_size, &cmd_output_size))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_dir_handler: "
                                               "finger dir '%s' failed\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));


        safe_free(cmd_output, LOC_CSTORE_0197);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORE_0198);
        return (EC_FALSE);
    }

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_list_dir_handler: "
                                           "finger dir '%s'\n"
                                           "result: '\n%.*s\n'\n",
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md),
                                           (uint32_t)cmd_output_size, cmd_output);

    /*make response*/
    CSTORE_MD_NGX_RSP_BODY(cstore_md) = cbytes_new(0);
    if(NULL_PTR == CSTORE_MD_NGX_RSP_BODY(cstore_md))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_list_dir_handler: "
                                               "result: '\n%.*s\n'"
                                               "=> new rsp body failed\n",
                                               (uint32_t)cmd_output_size, cmd_output);

        safe_free(cmd_output, LOC_CSTORE_0199);

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_FORBIDDEN, LOC_CSTORE_0200);
        return (EC_FALSE);
    }

    cbytes_mount(CSTORE_MD_NGX_RSP_BODY(cstore_md),
                    cmd_output_size, (UINT8 *)cmd_output, BIT_FALSE);

    cngx_set_header_out_kv(r, (const char *)"Content-Length", c_word_to_str(cmd_output_size));

    cngx_set_header_out_kv(r, (const char *)"X-File-Num", c_word_to_str(file_num));

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_OK, LOC_CSTORE_0201);

    return (EC_TRUE);
}


/**
*
* content handler
*
**/
EC_BOOL cstore_content_handler(const UINT32 cstore_md_id)
{
    CSTORE_MD                   *cstore_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_content_handler: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CSTORE_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstore_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CSTORE_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstore_md) = BIT_TRUE;
    }

    if(EC_FALSE == cstore_parse_method(cstore_md_id))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                               "parse method failed\n");

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0202);
        cstore_content_send_response(cstore_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_handler: "
                                           "parse method done\n");

    if(EC_FALSE == cstore_parse_file_path(cstore_md_id))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                               "parse file path failed\n");

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0203);
        cstore_content_send_response(cstore_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_handler: "
                                           "parse file path done\n");

    if(EC_FALSE == cstore_parse_file_op(cstore_md_id))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                               "parse file op failed\n");

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0204);
        cstore_content_send_response(cstore_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_handler: "
                                           "parse file op done\n");

    if(EC_FALSE == cstore_parse_file_range(cstore_md_id))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_range: "
                                               "parse file range failed\n");

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0205);
        cstore_content_send_response(cstore_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_handler: "
                                           "parse file range done\n");

    if(EC_FALSE == cstore_parse_file_md5(cstore_md_id))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_parse_file_range: "
                                               "parse file md5 failed\n");

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0206);
        cstore_content_send_response(cstore_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_handler: "
                                           "parse file md5 done\n");

    if(EC_FALSE == cstore_parse_file_body(cstore_md_id))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                               "parse file body failed\n");

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0207);
        cstore_content_send_response(cstore_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_handler: "
                                           "parse file body done\n");

    /*make sure path validity*/
    if(EC_FALSE == __cstore_check_file_path_validity(CSTORE_MD_FILE_PATH(cstore_md)))
    {
        dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                               "invalid file path '%s'\n",
                                               (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

        cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0208);
        cstore_content_send_response(cstore_md_id);
        return (EC_FALSE);
    }

    /*upload file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_UPLOAD_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"POST"))
    {
        if(EC_FALSE == cstore_upload_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "upload file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*merge part to file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_MERGE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"PUT"))
    {
        if(EC_FALSE == cstore_merge_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "merge file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*override file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_OVERRIDE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"PUT"))
    {
        if(EC_FALSE == cstore_override_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "override file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*check file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_CHECK_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_check_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "check file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*delete file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_DELETE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"DELETE"))
    {
        if(EC_FALSE == cstore_delete_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "delete file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*size file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_SIZE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_size_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "size file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*md5 file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_MD5_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_md5_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "md5 file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*empty file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_EMPTY_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"PUT"))
    {
        if(EC_FALSE == cstore_empty_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "empty file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*download file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_DOWNLOAD_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_download_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "download file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*complete file*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_COMPLETE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_complete_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "complete file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*make dir in backend*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_DIR_MAKE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"PUT"))
    {
        if(EC_FALSE == cstore_make_dir_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "make dir failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*push file to backend*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_PUSH_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"PUT"))
    {
        if(EC_FALSE == cstore_push_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "push file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*pull file from backend*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_PULL_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_pull_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "pull file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*list files of backend*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_LIST_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_list_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "list files failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*purge file or directory from backend*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_FILE_PURGE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"DELETE"))
    {
        if(EC_FALSE == cstore_purge_file_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "purge file failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*delete dir*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_DIR_DELETE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"DELETE"))
    {
        if(EC_FALSE == cstore_delete_dir_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "delete dir failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    /*finger dir*/
    if(NULL_PTR != CSTORE_MD_FILE_OP(cstore_md)
    && EC_TRUE == cstring_is_str(CSTORE_MD_FILE_OP(cstore_md), (UINT8 *)CSTORE_DIR_LIST_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORE_MD_METHOD(cstore_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstore_list_dir_handler(cstore_md_id))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                                   "list dir failed\n");

            cstore_content_send_response(cstore_md_id);
            return (EC_FALSE);
        }

        cstore_content_send_response(cstore_md_id);
        return (EC_TRUE);
    }

    dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_handler: "
                                           "unknown method '%s', op '%s', path '%s'\n",
                                           (char *)CSTORE_MD_METHOD_STR(cstore_md),
                                           (char *)CSTORE_MD_FILE_OP_STR(cstore_md),
                                           (char *)CSTORE_MD_FILE_PATH_STR(cstore_md));

    cstore_set_ngx_rc(cstore_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORE_0209);
    cstore_content_send_response(cstore_md_id);
    return (EC_FALSE);
}

EC_BOOL cstore_content_send_response(const UINT32 cstore_md_id)
{
    CSTORE_MD                  *cstore_md;

    ngx_http_request_t         *r;
    uint32_t                    len;
    uint32_t                    flags;

#if ( SWITCH_ON == CSTORE_DEBUG_SWITCH )
    if ( CSTORE_MD_ID_CHECK_INVALID(cstore_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstore_content_send_response: cstore module #0x%lx not started.\n",
                cstore_md_id);
        dbg_exit(MD_CSTORE, cstore_md_id);
    }
#endif/*CSTORE_DEBUG_SWITCH*/

    cstore_md = CSTORE_MD_GET(cstore_md_id);

    r = CSTORE_MD_NGX_HTTP_REQ(cstore_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);/*xxx*/

        cngx_set_header_out_status(r, CSTORE_MD_NGX_RC(cstore_md));
        cngx_set_header_out_content_length(r, 0);/*no body*/

        if(EC_FALSE == cngx_send_header(r, &(CSTORE_MD_NGX_RC(cstore_md))))
        {
            dbg_log(SEC_0173_CSTORE, 0)(LOGSTDOUT, "error:cstore_content_send_response: "
                                                   "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_send_response: "
                                               "send header done\n");
    }

    /*send body*/
    if(NULL_PTR != CSTORE_MD_NGX_RSP_BODY(cstore_md))
    {
        uint8_t     *data;

        data = (uint8_t *)CBYTES_BUF(CSTORE_MD_NGX_RSP_BODY(cstore_md));
        len  = (uint32_t )CBYTES_LEN(CSTORE_MD_NGX_RSP_BODY(cstore_md));

        flags =   CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG
                | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CSTORE_MD_NGX_RC(cstore_md))))
        {
            dbg_log(SEC_0173_CSTORE, 1)(LOGSTDOUT, "error:cstore_content_send_response: "
                                                   "send body failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0173_CSTORE, 9)(LOGSTDOUT, "[DEBUG] cstore_content_send_response: "
                                               "send body done => complete %ld bytes\n",
                                               CSTORE_MD_SENT_BODY_SIZE(cstore_md));
        return (EC_TRUE);
    }

    flags =   CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CSTORE_MD_NGX_RC(cstore_md))))
    {
        dbg_log(SEC_0173_CSTORE, 1)(LOGSTDOUT, "error:cstore_content_send_response: "
                                               "send body failed\n");

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


