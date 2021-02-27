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

#include "cngx.h"
#include "chttp.h"

#include "cdownload.h"

#include "findex.inc"

#define CDOWNLOAD_MD_CAPACITY()                  (cbc_md_capacity(MD_CDOWNLOAD))

#define CDOWNLOAD_MD_GET(cdownload_md_id)     ((CDOWNLOAD_MD *)cbc_md_get(MD_CDOWNLOAD, (cdownload_md_id)))

#define CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id)  \
    ((CMPI_ANY_MODI != (cdownload_md_id)) && ((NULL_PTR == CDOWNLOAD_MD_GET(cdownload_md_id)) || (0 == (CDOWNLOAD_MD_GET(cdownload_md_id)->usedcounter))))

/*-------------------------------------------------------------------*\
nginx server configuration example:
===================================
server {
    listen  80;
    server_name *.download.com;

    if ($uri = "/") {
        rewrite (.*) /index.html;
    }

    location ~ /(download|delete|size|md5) {
        content_by_bgn cdownload;
    }

    more_set_headers 'X-Upload: enabled';
}
\*-------------------------------------------------------------------*/

/**
*   for test only
*
*   to query the status of CDOWNLOAD Module
*
**/
void cdownload_print_module_status(const UINT32 cdownload_md_id, LOG *log)
{
    CDOWNLOAD_MD *cdownload_md;
    UINT32      this_cdownload_md_id;

    for( this_cdownload_md_id = 0; this_cdownload_md_id < CDOWNLOAD_MD_CAPACITY(); this_cdownload_md_id ++ )
    {
        cdownload_md = CDOWNLOAD_MD_GET(this_cdownload_md_id);

        if(NULL_PTR != cdownload_md && 0 < cdownload_md->usedcounter )
        {
            sys_log(log,"CDOWNLOAD Module # %u : %u refered\n",
                    this_cdownload_md_id,
                    cdownload_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CDOWNLOAD module
*
**/
EC_BOOL cdownload_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CDOWNLOAD , 1);
}

/**
*
* unregister CDOWNLOAD module
*
**/
EC_BOOL cdownload_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CDOWNLOAD);
}

/**
*
* start CDOWNLOAD module
*
**/
UINT32 cdownload_start(ngx_http_request_t *r)
{
    CDOWNLOAD_MD *cdownload_md;
    UINT32      cdownload_md_id;

    //TASK_BRD   *task_brd;

    uint32_t    cache_seg_size;

    //task_brd = task_brd_default_get();

    cdownload_md_id = cbc_md_new(MD_CDOWNLOAD, sizeof(CDOWNLOAD_MD));
    if(CMPI_ERROR_MODI == cdownload_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CDOWNLOAD module */
    cdownload_md = (CDOWNLOAD_MD *)cbc_md_get(MD_CDOWNLOAD, cdownload_md_id);
    cdownload_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */
    cngx_get_cache_seg_size(r, &cache_seg_size);

    CDOWNLOAD_MD_FILE_OP(cdownload_md)          = NULL_PTR;
    CDOWNLOAD_MD_FILE_PATH(cdownload_md)        = NULL_PTR;
    CDOWNLOAD_MD_FILE_MD5(cdownload_md)         = NULL_PTR;
    CDOWNLOAD_MD_FILE_BODY(cdownload_md)        = NULL_PTR;
    CDOWNLOAD_MD_FILE_SIZE(cdownload_md)        = 0;
    CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md)    = 0;
    CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md)    = 0;

    CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md)     = r;

    /*TODO: load all variables into module*/

    CDOWNLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cdownload_md) = BIT_FALSE;

    CDOWNLOAD_MD_CONTENT_LENGTH(cdownload_md)   = 0;

    CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md)     = NULL_PTR;

    CDOWNLOAD_MD_NGX_LOC(cdownload_md)          = LOC_NONE_END;
    CDOWNLOAD_MD_NGX_RC(cdownload_md)           = NGX_OK;

    cdownload_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cdownload_end, cdownload_md_id);

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_start: start CDOWNLOAD module #%ld\n", cdownload_md_id);

    return ( cdownload_md_id );
}

/**
*
* end CDOWNLOAD module
*
**/
void cdownload_end(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD *cdownload_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cdownload_end, cdownload_md_id);

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);
    if(NULL_PTR == cdownload_md)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_end: "
                                                  "cdownload_md_id = %ld not exist.\n",
                                                  cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cdownload_md->usedcounter )
    {
        cdownload_md->usedcounter --;
        return ;
    }

    if ( 0 == cdownload_md->usedcounter )
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_end: "
                                                  "cdownload_md_id = %ld is not started.\n",
                                                  cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }

    if(NULL_PTR != CDOWNLOAD_MD_FILE_BODY(cdownload_md))
    {
        cbytes_free(CDOWNLOAD_MD_FILE_BODY(cdownload_md));
        CDOWNLOAD_MD_FILE_BODY(cdownload_md) = NULL_PTR;
    }

    if(NULL_PTR != CDOWNLOAD_MD_FILE_PATH(cdownload_md))
    {
        cstring_free(CDOWNLOAD_MD_FILE_PATH(cdownload_md));
        CDOWNLOAD_MD_FILE_PATH(cdownload_md) = NULL_PTR;
    }

    if(NULL_PTR != CDOWNLOAD_MD_FILE_OP(cdownload_md))
    {
        cstring_free(CDOWNLOAD_MD_FILE_OP(cdownload_md));
        CDOWNLOAD_MD_FILE_OP(cdownload_md) = NULL_PTR;
    }

    if(NULL_PTR != CDOWNLOAD_MD_FILE_MD5(cdownload_md))
    {
        cstring_free(CDOWNLOAD_MD_FILE_MD5(cdownload_md));
        CDOWNLOAD_MD_FILE_MD5(cdownload_md) = NULL_PTR;
    }

    if(NULL_PTR == CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md))
    {
        cbytes_free(CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md));
        CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md) = NULL_PTR;
    }

    CDOWNLOAD_MD_FILE_SIZE(cdownload_md)        = 0;
    CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md)    = 0;
    CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md)    = 0;

    CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md) = NULL_PTR;

    CDOWNLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cdownload_md) = BIT_FALSE;

    CDOWNLOAD_MD_CONTENT_LENGTH(cdownload_md) = 0;

    CDOWNLOAD_MD_NGX_LOC(cdownload_md)        = LOC_NONE_END;
    CDOWNLOAD_MD_NGX_RC(cdownload_md)         = NGX_OK;

    /* free module */
    cdownload_md->usedcounter = 0;

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "cdownload_end: stop CDOWNLOAD module #%ld\n", cdownload_md_id);
    cbc_md_free(MD_CDOWNLOAD, cdownload_md_id);

    return ;
}

EC_BOOL cdownload_get_ngx_rc(const UINT32 cdownload_md_id, ngx_int_t *rc, UINT32 *location)
{
    CDOWNLOAD_MD                *cdownload_md;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_get_ngx_rc: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CDOWNLOAD_MD_NGX_RC(cdownload_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CDOWNLOAD_MD_NGX_LOC(cdownload_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cdownload_set_ngx_rc(const UINT32 cdownload_md_id, const ngx_int_t rc, const UINT32 location)
{
    CDOWNLOAD_MD                *cdownload_md;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_set_ngx_rc: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    /*do not override*/
    if(NGX_OK != CDOWNLOAD_MD_NGX_RC(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_override_ngx_rc: "
                                                  "ignore rc %ld due to its %ld now\n",
                                                  rc, CDOWNLOAD_MD_NGX_RC(cdownload_md));
        return (EC_TRUE);
    }

    CDOWNLOAD_MD_NGX_RC(cdownload_md)  = rc;
    CDOWNLOAD_MD_NGX_LOC(cdownload_md) = location;

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_set_ngx_rc: "
                                              "set rc %ld\n",
                                              rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cdownload_override_ngx_rc(const UINT32 cdownload_md_id, const ngx_int_t rc, const UINT32 location)
{
    CDOWNLOAD_MD                *cdownload_md;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_override_ngx_rc: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    if(rc == CDOWNLOAD_MD_NGX_RC(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_override_ngx_rc: "
                                                  "ignore same rc %ld\n",
                                                  rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CDOWNLOAD_MD_NGX_RC(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_override_ngx_rc: "
                                                  "modify rc %ld => %ld\n",
                                                  CDOWNLOAD_MD_NGX_RC(cdownload_md), rc);
        CDOWNLOAD_MD_NGX_RC(cdownload_md)  = rc;
        CDOWNLOAD_MD_NGX_LOC(cdownload_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_override_ngx_rc: "
                                              "set rc %ld\n",
                                              rc);

    CDOWNLOAD_MD_NGX_RC(cdownload_md)  = rc;
    CDOWNLOAD_MD_NGX_LOC(cdownload_md) = location;

    return (EC_TRUE);
}

EC_BOOL cdownload_parse_uri(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                   *cdownload_md;

    ngx_http_request_t           *r;
    char                         *uri_str;
    char                         *uri_end;
    char                         *v;
    char                         *file_op_str;
    char                         *file_path_str;
    char                         *root_path_str;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_parse_uri: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    if(EC_FALSE == cngx_get_req_uri(r, &uri_str))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_uri: "
                                                  "fetch req uri failed\n");
        return (EC_FALSE);
    }

    if(0 == STRCMP(uri_str, (const char *)"/"))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_uri: "
                                                  "invalid file name '%s'\n",
                                                  uri_str);
        safe_free(uri_str, LOC_CDOWNLOAD_0001);
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
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "error:cdownload_parse_uri: "
                                                  "invalid uri %s\n",
                                                  uri_str);

        safe_free(uri_str, LOC_CDOWNLOAD_0002);
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR == CDOWNLOAD_MD_FILE_OP(cdownload_md));
    ASSERT(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md));

    CDOWNLOAD_MD_FILE_OP(cdownload_md) = cstring_make("%.*s", file_path_str - file_op_str, file_op_str);
    if(NULL_PTR == CDOWNLOAD_MD_FILE_OP(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_uri: "
                                                  "make file op '%.*s' failed\n",
                                                  file_path_str - file_op_str, file_op_str);
        safe_free(uri_str, LOC_CDOWNLOAD_0003);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_uri: "
                                              "parsed file op '%s'\n",
                                              (char *)CDOWNLOAD_MD_FILE_OP_STR(cdownload_md));

    if(EC_TRUE == cngx_get_root(r, &root_path_str) && NULL_PTR != root_path_str)
    {
        CDOWNLOAD_MD_FILE_PATH(cdownload_md) = cstring_make("%s%s", root_path_str, file_path_str);
        if(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_uri: "
                                                      "make file path '%s%s' failed\n",
                                                      root_path_str, file_path_str);

            safe_free(root_path_str, LOC_CDOWNLOAD_0004);
            safe_free(uri_str, LOC_CDOWNLOAD_0005);
            return (EC_FALSE);
        }
        safe_free(root_path_str, LOC_CDOWNLOAD_0006);
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_uri: "
                                                  "parsed and composed file path '%s'\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
    }
    else
    {
        CDOWNLOAD_MD_FILE_PATH(cdownload_md) = cstring_new((UINT8 *)file_path_str, LOC_CDOWNLOAD_0007);
        if(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_uri: "
                                                      "make file path '%s' failed\n",
                                                      file_path_str);
            safe_free(uri_str, LOC_CDOWNLOAD_0008);
            return (EC_FALSE);
        }
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_uri: "
                                                  "parsed file path '%s'\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
    }

    safe_free(uri_str, LOC_CDOWNLOAD_0009);

    return (EC_TRUE);
}

EC_BOOL cdownload_parse_file_range(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_parse_file_range: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    /*[example] Content-Range: bytes 7-14/20*/
    k = (const char *)"Content-Range";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_range: "
                                                  "[cngx] get '%s' failed\n",
                                                  k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_range: "
                                                  "[cngx] no '%s'\n",
                                                  k);
        return (EC_TRUE);
    }

    if(NULL_PTR != v)
    {
        char   *segs[ 4 ];

        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_range: "
                                                  "[cngx] get var '%s':'%s' done\n",
                                                  k, v);

        if(4 != c_str_split(v, (const char *)":-/ \t", (char **)segs, 4))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_range: "
                                                      "[cngx] invalid %s\n",
                                                      k);
            safe_free(v, LOC_CDOWNLOAD_0010);
            return (EC_FALSE);
        }

        if(0 != STRCASECMP("bytes", segs[0])
        || EC_FALSE == c_str_is_digit(segs[1])
        || EC_FALSE == c_str_is_digit(segs[2])
        || EC_FALSE == c_str_is_digit(segs[3]))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_range: "
                                                      "[cngx] invald '%s': %s %s-%s/%s\n",
                                                      k, segs[0], segs[1], segs[2], segs[3]);
            safe_free(v, LOC_CDOWNLOAD_0011);
            return (EC_FALSE);
        }

        CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) = c_str_to_word(segs[1]);
        CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md) = c_str_to_word(segs[2]);
        CDOWNLOAD_MD_FILE_SIZE(cdownload_md)     = c_str_to_word(segs[3]);

        if(CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) > CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md)
        || CDOWNLOAD_MD_FILE_SIZE(cdownload_md)     < CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_range: "
                                                      "[cngx] invald '%s': %s %s-%s/%s\n",
                                                      k, segs[0], segs[1], segs[2], segs[3]);
            safe_free(v, LOC_CDOWNLOAD_0012);
            return (EC_FALSE);
        }

        safe_free(v, LOC_CDOWNLOAD_0013);

        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_range: "
                                                  "[cngx] parsed range: [%ld, %ld]/%ld\n",
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_SIZE(cdownload_md));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cdownload_parse_file_md5(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    ngx_http_request_t          *r;

    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_parse_file_md5: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    /*Content-MD5: 0123456789abcdef*/
    k = (const char *)"Content-MD5";
    if(EC_FALSE == cngx_get_header_in(r, k, &v))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_md5: "
                                                  "[cngx] get '%s' failed\n",
                                                  k);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_md5: "
                                                  "[cngx] no '%s'\n",
                                                  k);
        return (EC_TRUE);
    }

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_md5: "
                                              "[cngx] parsed '%s':'%s'\n",
                                              k, v);

    CDOWNLOAD_MD_FILE_MD5(cdownload_md) = cstring_new((UINT8 *)v, LOC_CDOWNLOAD_0014);
    if(NULL_PTR == CDOWNLOAD_MD_FILE_MD5(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_md5: "
                                                  "new cstring '%s' failed\n",
                                                  v);
        safe_free(v, LOC_CDOWNLOAD_0015);
        return (EC_FALSE);
    }

    safe_free(v, LOC_CDOWNLOAD_0016);
    return (EC_TRUE);
}

EC_BOOL cdownload_parse_file_body(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_parse_file_body: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    if(CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) > CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_body: "
                                                  "invalid range [%ld, %ld]\n",
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDOWNLOAD_MD_FILE_BODY(cdownload_md))
    {
        CDOWNLOAD_MD_FILE_BODY(cdownload_md) = cbytes_new(0);
        if(NULL_PTR == CDOWNLOAD_MD_FILE_BODY(cdownload_md))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_body: "
                                                      "new cbytes failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == cngx_read_req_body(r, CDOWNLOAD_MD_FILE_BODY(cdownload_md), &CDOWNLOAD_MD_NGX_RC(cdownload_md)))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_body: "
                                                  "read req body failed\n");

        cbytes_free(CDOWNLOAD_MD_FILE_BODY(cdownload_md));
        CDOWNLOAD_MD_FILE_BODY(cdownload_md) = NULL_PTR;
        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_body: "
                                              "req body len %ld\n",
                                              CBYTES_LEN(CDOWNLOAD_MD_FILE_BODY(cdownload_md)));

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_parse_file_body: done\n");

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cdownload_check_file_path_validity(const CSTRING *file_name)
{
    char        *file_name_str;
    char        *saveptr;
    char        *file_name_seg;
    UINT32       file_name_depth;

    if(NULL_PTR == file_name)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:__cdownload_check_file_path_validity: "
                                                  "no file name\n");

        return (EC_FALSE);
    }

    file_name_str = c_str_dup((char *)cstring_get_str(file_name));
    if(NULL_PTR == file_name_str)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:__cdownload_check_file_path_validity: "
                                                  "dup '%s' failed\n",
                                                  (char *)cstring_get_str(file_name));

        return (EC_FALSE);
    }

    file_name_depth = 0;
    saveptr = file_name_str;
    while((file_name_seg = strtok_r(NULL_PTR, (char *)"/", &saveptr)) != NULL_PTR)
    {
        file_name_depth ++;

        if(CDOWNLOAD_FILE_NAME_MAX_DEPTH <= file_name_depth)
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:__cdownload_check_file_path_validity: "
                                                      "file name '%s' depth overflow\n",
                                                      (char *)cstring_get_str(file_name));

            c_str_free(file_name_str);

            return (EC_FALSE);
        }

        if(CDOWNLOAD_FILE_NAME_SEG_MAX_SIZE < strlen(file_name_seg))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:__cdownload_check_file_path_validity: "
                                                      "file name '%s' seg size overflow\n",
                                                      (char *)cstring_get_str(file_name));

            c_str_free(file_name_str);

            return (EC_FALSE);
        }

        if(EC_TRUE == c_str_is_in(file_name_seg, (const char *)"|", (const char *)".."))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:__cdownload_check_file_path_validity: "
                                                      "file name '%s' is invalid\n",
                                                      (char *)cstring_get_str(file_name));

            c_str_free(file_name_str);

            return (EC_FALSE);
        }
    }

    c_str_free(file_name_str);

    return (EC_TRUE);
}

EC_BOOL cdownload_check_file_handler(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    CMD5_DIGEST                  seg_md5sum;
    UINT32                       fsize;
    int                          fd;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_check_file_handler: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    /*check validity*/
    if(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                  "no file name\n");
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0017);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDOWNLOAD_MD_FILE_MD5(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                  "no md5\n");

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0018);
        return (EC_FALSE);
    }

    if(CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) >= CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                  "invalid content-range: [%ld, %ld]/%ld\n",
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_SIZE(cdownload_md));

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0019);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), F_OK))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                  "file '%s' not exist\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_NOT_FOUND, LOC_CDOWNLOAD_0020);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                  "open file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0021);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                  "size file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0022);

        return (EC_FALSE);
    }

    if(fsize != CDOWNLOAD_MD_FILE_SIZE(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                  "file '%s' size %ld != %ld\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  fsize,
                                                  CDOWNLOAD_MD_FILE_SIZE(cdownload_md));

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_UNAUTHORIZED, LOC_CDOWNLOAD_0023);

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_check_file_handler: "
                                              "file '%s' size %ld matched\n",
                                              (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                              CDOWNLOAD_MD_FILE_SIZE(cdownload_md));

    if(NULL_PTR != CDOWNLOAD_MD_FILE_MD5(cdownload_md))
    {
        UINT32      data_size;

        data_size = CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md) + 1 - CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md);
        if(EC_FALSE == c_file_seg_md5(fd, CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                            data_size, CMD5_DIGEST_SUM(&seg_md5sum)))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_check_file_handler: "
                                                      "md5sum file '%s' range [%ld, %ld] failed\n",
                                                      (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                      CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                      CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md));

            c_file_close(fd);
            cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CDOWNLOAD_0024);

            return (EC_FALSE);
        }

        c_file_close(fd);

        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_check_file_handler: "
                                                  "file '%s' range [%ld, %ld] => md5 %s\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  cmd5_digest_hex_str(&seg_md5sum));

        if(0 != STRCASECMP(cmd5_digest_hex_str(&seg_md5sum), (char *)CDOWNLOAD_MD_FILE_MD5_STR(cdownload_md)))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_check_file_handler: "
                                                      "file '%s' range [%ld, %ld] md5 %s != %s\n",
                                                      (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                      CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                      CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                      cmd5_digest_hex_str(&seg_md5sum),
                                                      CDOWNLOAD_MD_FILE_MD5_STR(cdownload_md));

            cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_UNAUTHORIZED, LOC_CDOWNLOAD_0025);
            return (EC_TRUE);
        }

        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_check_file_handler: "
                                                  "file '%s' range [%ld, %ld] md5 %s matched\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_MD5_STR(cdownload_md));

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_OK, LOC_CDOWNLOAD_0026);
        return (EC_TRUE);
    }

    c_file_close(fd);

    cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_OK, LOC_CDOWNLOAD_0027);
    return (EC_TRUE);
}

EC_BOOL cdownload_delete_file_handler(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_delete_file_handler: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    /*check validity*/
    if(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_delete_file_handler: "
                                                  "no file name\n");
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0028);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), F_OK))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_delete_file_handler: "
                                                  "file '%s' not exist\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_NOT_FOUND, LOC_CDOWNLOAD_0029);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_unlink((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md)))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_delete_file_handler: "
                                                  "unlink file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_NOT_FOUND, LOC_CDOWNLOAD_0030);
        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_delete_file_handler: "
                                              "unlink file '%s' done\n",
                                              (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));

    cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_OK, LOC_CDOWNLOAD_0031);
    return (EC_TRUE);
}

EC_BOOL cdownload_size_file_handler(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    ngx_http_request_t          *r;

    UINT32                       fsize;
    int                          fd;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_size_file_handler: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    /*check validity*/
    if(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_size_file_handler: "
                                                  "no file name\n");
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0032);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), F_OK))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_size_file_handler: "
                                                  "file '%s' not exist\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_NOT_FOUND, LOC_CDOWNLOAD_0033);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_size_file_handler: "
                                                  "open file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0034);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_size_file_handler: "
                                                  "size file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0035);

        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_size_file_handler: "
                                              "file '%s' size %ld\n",
                                              (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                              fsize);

    cngx_set_header_out_kv(r, (const char *)"X-File-Size", c_word_to_str(fsize));
    cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_OK, LOC_CDOWNLOAD_0036);
    return (EC_TRUE);
}

EC_BOOL cdownload_md5_file_handler(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    ngx_http_request_t          *r;

    CMD5_DIGEST                  seg_md5sum;
    UINT32                       fsize;
    UINT32                       data_size;
    int                          fd;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_md5_file_handler: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    /*check validity*/
    if(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_md5_file_handler: "
                                                  "no file name\n");
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0037);
        return (EC_FALSE);
    }

    if(CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) > CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_md5_file_handler: "
                                                  "invalid content-range: [%ld, %ld]/%ld\n",
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_SIZE(cdownload_md));

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0038);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), F_OK))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_md5_file_handler: "
                                                  "file '%s' not exist\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_NOT_FOUND, LOC_CDOWNLOAD_0039);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_md5_file_handler: "
                                                  "open file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0040);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_md5_file_handler: "
                                                  "size file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0041);

        return (EC_FALSE);
    }

    if(0 == CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md)
    && 0 == CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md)
    && 0 == CDOWNLOAD_MD_FILE_SIZE(cdownload_md))
    {
        CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) = 0;
        CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md) = fsize - 1;
        CDOWNLOAD_MD_FILE_SIZE(cdownload_md)     = fsize;
    }

    data_size = CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md) + 1 - CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md);
    if(EC_FALSE == c_file_seg_md5(fd, CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                        data_size, CMD5_DIGEST_SUM(&seg_md5sum)))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_md5_file_handler: "
                                                  "md5sum file '%s' range [%ld, %ld] failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md));

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CDOWNLOAD_0042);

        return (EC_FALSE);
    }

    c_file_close(fd);

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_md5_file_handler: "
                                              "file '%s' range [%ld, %ld]/%ld => md5 %s\n",
                                              (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                              CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                              CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                              CDOWNLOAD_MD_FILE_SIZE(cdownload_md),
                                              cmd5_digest_hex_str(&seg_md5sum));

    cngx_set_header_out_kv(r, (const char *)"X-Content-Range",
                               c_format_str("%ld-%ld/%ld",
                               CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                               CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                               CDOWNLOAD_MD_FILE_SIZE(cdownload_md)));

    cngx_set_header_out_kv(r, (const char *)"X-MD5", cmd5_digest_hex_str(&seg_md5sum));

    cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_OK, LOC_CDOWNLOAD_0043);
    return (EC_TRUE);
}

EC_BOOL cdownload_read_file_handler(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    ngx_http_request_t          *r;

    UINT32                       fsize;
    UINT32                       rsize;
    CBYTES                      *rsp_body;
    UINT32                       offset;
    uint32_t                     client_body_max_size;
    int                          fd;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_read_file_handler: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    /*check validity*/
    if(NULL_PTR == CDOWNLOAD_MD_FILE_PATH(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "no file name\n");
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0037);
        return (EC_FALSE);
    }

    if(CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) > CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "invalid content-range: [%ld, %ld]/%ld\n",
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_SIZE(cdownload_md));

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0038);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), F_OK))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "file '%s' not exist\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_NOT_FOUND, LOC_CDOWNLOAD_0039);
        return (EC_FALSE);
    }

    fd = c_file_open((char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "open file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0040);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "size file '%s' failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0041);

        return (EC_FALSE);
    }

    if(CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md) >= fsize)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "file '%s', size %ld, range [%ld, %ld] is invalid\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  fsize,
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md));

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0041);

        return (EC_FALSE);
    }

    if(0 == CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md)
    && 0 == CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md)
    && 0 == CDOWNLOAD_MD_FILE_SIZE(cdownload_md))
    {
        CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md) = 0;
        CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md) = fsize - 1;
        CDOWNLOAD_MD_FILE_SIZE(cdownload_md)     = fsize;
    }

    rsize  = CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md) + 1 - CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md);
    offset = CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md);

    cngx_get_client_body_max_size(r, &client_body_max_size);

    if(rsize > client_body_max_size)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "file '%s' range [%ld, %ld], "
                                                  "rsize %ld > client_body_max_size %u\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  rsize, client_body_max_size);

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_FORBIDDEN, LOC_CDOWNLOAD_0042);

        return (EC_FALSE);
    }

    rsp_body = cbytes_new(rsize);
    if(NULL_PTR == rsp_body)
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "file '%s' range [%ld, %ld], "
                                                  "new cbytes with size %ld failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                                  rsize);

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CDOWNLOAD_0042);

        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_load(fd, &offset, rsize, CBYTES_BUF(rsp_body)))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_read_file_handler: "
                                                  "read file '%s' range [%ld, %ld] failed\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                                  CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md));

        cbytes_free(rsp_body);

        c_file_close(fd);
        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CDOWNLOAD_0042);

        return (EC_FALSE);
    }

    CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md) = rsp_body;

    c_file_close(fd);

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_read_file_handler: "
                                              "read file '%s' range [%ld, %ld]/%ld => done\n",
                                              (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md),
                                              CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                                              CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                                              CDOWNLOAD_MD_FILE_SIZE(cdownload_md));

    cngx_set_header_out_kv(r, (const char *)"X-Content-Range",
                               c_format_str("%ld-%ld/%ld",
                               CDOWNLOAD_MD_FILE_S_OFFSET(cdownload_md),
                               CDOWNLOAD_MD_FILE_E_OFFSET(cdownload_md),
                               CDOWNLOAD_MD_FILE_SIZE(cdownload_md)));

    cngx_set_header_out_kv(r, (const char *)"Content-Length", c_word_to_str(rsize));

    cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_OK, LOC_CDOWNLOAD_0043);
    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL cdownload_content_handler(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                *cdownload_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_content_handler: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CDOWNLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cdownload_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CDOWNLOAD_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cdownload_md) = BIT_TRUE;
    }

    if(EC_FALSE == cdownload_parse_uri(cdownload_md_id))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                  "parse uri failed\n");

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0044);
        cdownload_content_send_response(cdownload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_content_handler: "
                                              "parse uri done\n");

    if(EC_FALSE == cdownload_parse_file_range(cdownload_md_id))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_range: "
                                                  "parse file range failed\n");

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0045);
        cdownload_content_send_response(cdownload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_content_handler: "
                                              "parse file range done\n");

    if(EC_FALSE == cdownload_parse_file_md5(cdownload_md_id))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_parse_file_range: "
                                                  "parse file md5 failed\n");

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0046);
        cdownload_content_send_response(cdownload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_content_handler: "
                                              "parse file md5 done\n");

    if(EC_FALSE == cdownload_parse_file_body(cdownload_md_id))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                  "parse file body failed\n");

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0047);
        cdownload_content_send_response(cdownload_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_content_handler: "
                                              "parse file body done\n");

    /*make sure path validity*/
    if(EC_FALSE == __cdownload_check_file_path_validity(CDOWNLOAD_MD_FILE_PATH(cdownload_md)))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                  "invalid file path '%s'\n",
                                                  (char *)CDOWNLOAD_MD_FILE_PATH_STR(cdownload_md));

        cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0048);
        cdownload_content_send_response(cdownload_md_id);
        return (EC_FALSE);
    }

    /*download file*/
    if(NULL_PTR != CDOWNLOAD_MD_FILE_OP(cdownload_md)
    && EC_TRUE == cstring_is_str(CDOWNLOAD_MD_FILE_OP(cdownload_md), (UINT8 *)CDOWNLOAD_FILE_DOWNLOAD_OP))
    {
        if(EC_FALSE == cdownload_read_file_handler(cdownload_md_id))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                      "download file failed\n");

            cdownload_content_send_response(cdownload_md_id);
            return (EC_FALSE);
        }

        cdownload_content_send_response(cdownload_md_id);
        return (EC_TRUE);
    }

    /*check file*/
    if(NULL_PTR != CDOWNLOAD_MD_FILE_OP(cdownload_md)
    && EC_TRUE == cstring_is_str(CDOWNLOAD_MD_FILE_OP(cdownload_md), (UINT8 *)CDOWNLOAD_FILE_CHECK_OP))
    {
        if(EC_FALSE == cdownload_check_file_handler(cdownload_md_id))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                    "check file failed\n");

            cdownload_content_send_response(cdownload_md_id);
            return (EC_FALSE);
        }

        cdownload_content_send_response(cdownload_md_id);
        return (EC_TRUE);
    }

    /*delete file*/
    if(NULL_PTR != CDOWNLOAD_MD_FILE_OP(cdownload_md)
    && EC_TRUE == cstring_is_str(CDOWNLOAD_MD_FILE_OP(cdownload_md), (UINT8 *)CDOWNLOAD_FILE_DELETE_OP))
    {
        if(EC_FALSE == cdownload_delete_file_handler(cdownload_md_id))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                      "delete file failed\n");

            cdownload_content_send_response(cdownload_md_id);
            return (EC_FALSE);
        }

        cdownload_content_send_response(cdownload_md_id);
        return (EC_TRUE);
    }

    /*size file*/
    if(NULL_PTR != CDOWNLOAD_MD_FILE_OP(cdownload_md)
    && EC_TRUE == cstring_is_str(CDOWNLOAD_MD_FILE_OP(cdownload_md), (UINT8 *)CDOWNLOAD_FILE_SIZE_OP))
    {
        if(EC_FALSE == cdownload_size_file_handler(cdownload_md_id))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                      "size file failed\n");

            cdownload_content_send_response(cdownload_md_id);
            return (EC_FALSE);
        }

        cdownload_content_send_response(cdownload_md_id);
        return (EC_TRUE);
    }

    /*md5 file*/
    if(NULL_PTR != CDOWNLOAD_MD_FILE_OP(cdownload_md)
    && EC_TRUE == cstring_is_str(CDOWNLOAD_MD_FILE_OP(cdownload_md), (UINT8 *)CDOWNLOAD_FILE_MD5_OP))
    {
        if(EC_FALSE == cdownload_md5_file_handler(cdownload_md_id))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_handler: "
                                                      "md5 file failed\n");

            cdownload_content_send_response(cdownload_md_id);
            return (EC_FALSE);
        }

        cdownload_content_send_response(cdownload_md_id);
        return (EC_TRUE);
    }

    cdownload_set_ngx_rc(cdownload_md_id, NGX_HTTP_BAD_REQUEST, LOC_CDOWNLOAD_0049);
    cdownload_content_send_response(cdownload_md_id);
    return (EC_FALSE);
}

EC_BOOL cdownload_content_send_response(const UINT32 cdownload_md_id)
{
    CDOWNLOAD_MD                 *cdownload_md;

    ngx_http_request_t         *r;
    uint32_t                    len;
    uint32_t                    flags;

#if ( SWITCH_ON == CDOWNLOAD_DEBUG_SWITCH )
    if ( CDOWNLOAD_MD_ID_CHECK_INVALID(cdownload_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdownload_content_send_response: cdownload module #0x%lx not started.\n",
                cdownload_md_id);
        dbg_exit(MD_CDOWNLOAD, cdownload_md_id);
    }
#endif/*CDOWNLOAD_DEBUG_SWITCH*/

    cdownload_md = CDOWNLOAD_MD_GET(cdownload_md_id);

    r = CDOWNLOAD_MD_NGX_HTTP_REQ(cdownload_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);/*xxx*/

        cngx_set_header_out_status(r, CDOWNLOAD_MD_NGX_RC(cdownload_md));
        cngx_set_header_out_content_length(r, 0);/*no body*/

        if(EC_FALSE == cngx_send_header(r, &(CDOWNLOAD_MD_NGX_RC(cdownload_md))))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 0)(LOGSTDOUT, "error:cdownload_content_send_response: "
                                                      "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_content_send_response: "
                                                  "send header done\n");
    }

    /*send body*/
    if(NULL_PTR != CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md))
    {
        uint8_t     *data;

        data = (uint8_t *)CBYTES_BUF(CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md));
        len  = (uint32_t )CBYTES_LEN(CDOWNLOAD_MD_NGX_RSP_BODY(cdownload_md));

        flags =   CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG
                | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CDOWNLOAD_MD_NGX_RC(cdownload_md))))
        {
            dbg_log(SEC_0172_CDOWNLOAD, 1)(LOGSTDOUT, "error:cdownload_content_send_response: "
                                                      "send body failed\n");

            return (EC_FALSE);
        }

        CDOWNLOAD_MD_SENT_BODY_SIZE(cdownload_md) += len;

        dbg_log(SEC_0172_CDOWNLOAD, 9)(LOGSTDOUT, "[DEBUG] cdownload_content_send_response: "
                                                  "send body done => complete %ld bytes\n",
                                                  CDOWNLOAD_MD_SENT_BODY_SIZE(cdownload_md));
        return (EC_TRUE);
    }

    flags =   CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CDOWNLOAD_MD_NGX_RC(cdownload_md))))
    {
        dbg_log(SEC_0172_CDOWNLOAD, 1)(LOGSTDOUT, "error:cdownload_content_send_response: "
                                                  "send body failed\n");

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


