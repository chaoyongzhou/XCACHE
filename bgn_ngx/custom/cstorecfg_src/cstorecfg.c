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

#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

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

#include "json.h"
#include "cstorecfg.h"

#include "findex.inc"

#define CSTORECFG_MD_CAPACITY()                  (cbc_md_capacity(MD_CSTORECFG))

#define CSTORECFG_MD_GET(cstorecfg_md_id)     ((CSTORECFG_MD *)cbc_md_get(MD_CSTORECFG, (cstorecfg_md_id)))

#define CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id)  \
    ((CMPI_ANY_MODI != (cstorecfg_md_id)) && ((NULL_PTR == CSTORECFG_MD_GET(cstorecfg_md_id)) || (0 == (CSTORECFG_MD_GET(cstorecfg_md_id)->usedcounter))))

/*-------------------------------------------------------------------*\
nginx server configuration example:
===================================
server {
    listen  80;
    server_name *.storecfg.com;

    location ~ /storecfg {
        content_by_bgn cstorecfg;
    }

    more_set_headers 'X-StoreCfg: enabled';
}
\*-------------------------------------------------------------------*/

/**
*   for test only
*
*   to query the status of CSTORECFG Module
*
**/
void cstorecfg_print_module_status(const UINT32 cstorecfg_md_id, LOG *log)
{
    CSTORECFG_MD *cstorecfg_md;
    UINT32      this_cstorecfg_md_id;

    for( this_cstorecfg_md_id = 0; this_cstorecfg_md_id < CSTORECFG_MD_CAPACITY(); this_cstorecfg_md_id ++ )
    {
        cstorecfg_md = CSTORECFG_MD_GET(this_cstorecfg_md_id);

        if(NULL_PTR != cstorecfg_md && 0 < cstorecfg_md->usedcounter )
        {
            sys_log(log,"CSTORECFG Module # %u : %u refered\n",
                    this_cstorecfg_md_id,
                    cstorecfg_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CSTORECFG module
*
**/
EC_BOOL cstorecfg_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CSTORECFG , 1);
}

/**
*
* unregister CSTORECFG module
*
**/
EC_BOOL cstorecfg_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CSTORECFG);
}

/**
*
* start CSTORECFG module
*
**/
UINT32 cstorecfg_start(ngx_http_request_t *r)
{
    CSTORECFG_MD *cstorecfg_md;
    UINT32        cstorecfg_md_id;

    cstorecfg_md_id = cbc_md_new(MD_CSTORECFG, sizeof(CSTORECFG_MD));
    if(CMPI_ERROR_MODI == cstorecfg_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CSTORECFG module */
    cstorecfg_md = (CSTORECFG_MD *)cbc_md_get(MD_CSTORECFG, cstorecfg_md_id);
    cstorecfg_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */

    CSTORECFG_MD_METHOD(cstorecfg_md)           = NULL_PTR;
    CSTORECFG_MD_HOST(cstorecfg_md)             = NULL_PTR;
    CSTORECFG_MD_BUCKET_NAME(cstorecfg_md)      = NULL_PTR;
    CSTORECFG_MD_BUCKET_OP(cstorecfg_md)        = NULL_PTR;
    CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md)    = NULL_PTR;
    CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md)    = NULL_PTR;
    CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md)  = NULL_PTR;
    CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md)  = NULL_PTR;
    CSTORECFG_MD_BUF_CACHE(cstorecfg_md)        = NULL_PTR;
    CSTORECFG_MD_CFG_CACHE(cstorecfg_md)        = NULL_PTR;
    CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md)     = NULL_PTR;

    CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md)     = r;

    /*TODO: load all variables into module*/

    CSTORECFG_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstorecfg_md) = BIT_FALSE;

    CSTORECFG_MD_CONTENT_LENGTH(cstorecfg_md)   = 0;

    CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md)     = NULL_PTR;

    CSTORECFG_MD_NGX_LOC(cstorecfg_md)          = LOC_NONE_END;
    CSTORECFG_MD_NGX_RC(cstorecfg_md)           = NGX_OK;

    cstorecfg_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cstorecfg_end, cstorecfg_md_id);

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_start: start CSTORECFG module #%ld\n", cstorecfg_md_id);

    return ( cstorecfg_md_id );
}

/**
*
* end CSTORECFG module
*
**/
void cstorecfg_end(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD *cstorecfg_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cstorecfg_end, cstorecfg_md_id);

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);
    if(NULL_PTR == cstorecfg_md)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_end: "
                                                  "cstorecfg_md_id = %ld not exist.\n",
                                                  cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cstorecfg_md->usedcounter )
    {
        cstorecfg_md->usedcounter --;
        return ;
    }

    if ( 0 == cstorecfg_md->usedcounter )
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_end: "
                                                  "cstorecfg_md_id = %ld is not started.\n",
                                                  cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }

    if(NULL_PTR != CSTORECFG_MD_BUF_CACHE(cstorecfg_md))
    {
        safe_free(CSTORECFG_MD_BUF_CACHE(cstorecfg_md), LOC_CSTORECFG_0001);
        CSTORECFG_MD_BUF_CACHE(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_CFG_CACHE(cstorecfg_md))
    {
        safe_free(CSTORECFG_MD_CFG_CACHE(cstorecfg_md), LOC_CSTORECFG_0002);
        CSTORECFG_MD_CFG_CACHE(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md))
    {
        cbytes_free(CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md));
        CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md))
    {
        cbytes_free(CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md));
        CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_METHOD(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_METHOD(cstorecfg_md));
        CSTORECFG_MD_METHOD(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_HOST(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_HOST(cstorecfg_md));
        CSTORECFG_MD_HOST(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md));
        CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md));
        CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md));
        CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md));
        CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_BUCKET_NAME(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_BUCKET_NAME(cstorecfg_md));
        CSTORECFG_MD_BUCKET_NAME(cstorecfg_md) = NULL_PTR;
    }

    if(NULL_PTR != CSTORECFG_MD_BUCKET_OP(cstorecfg_md))
    {
        cstring_free(CSTORECFG_MD_BUCKET_OP(cstorecfg_md));
        CSTORECFG_MD_BUCKET_OP(cstorecfg_md) = NULL_PTR;
    }

    CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md) = NULL_PTR;

    CSTORECFG_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstorecfg_md) = BIT_FALSE;

    CSTORECFG_MD_CONTENT_LENGTH(cstorecfg_md) = 0;

    CSTORECFG_MD_NGX_LOC(cstorecfg_md)        = LOC_NONE_END;
    CSTORECFG_MD_NGX_RC(cstorecfg_md)         = NGX_OK;

    /* free module */
    cstorecfg_md->usedcounter = 0;

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "cstorecfg_end: stop CSTORECFG module #%ld\n", cstorecfg_md_id);
    cbc_md_free(MD_CSTORECFG, cstorecfg_md_id);

    return ;
}

EC_BOOL cstorecfg_get_ngx_rc(const UINT32 cstorecfg_md_id, ngx_int_t *rc, UINT32 *location)
{
    CSTORECFG_MD                  *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_get_ngx_rc: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CSTORECFG_MD_NGX_RC(cstorecfg_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CSTORECFG_MD_NGX_LOC(cstorecfg_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cstorecfg_set_ngx_rc(const UINT32 cstorecfg_md_id, const ngx_int_t rc, const UINT32 location)
{
    CSTORECFG_MD                  *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_set_ngx_rc: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    /*do not override*/
    if(NGX_OK != CSTORECFG_MD_NGX_RC(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_override_ngx_rc: "
                                                  "ignore rc %ld due to its %ld now\n",
                                                  rc, CSTORECFG_MD_NGX_RC(cstorecfg_md));
        return (EC_TRUE);
    }

    CSTORECFG_MD_NGX_RC(cstorecfg_md)  = rc;
    CSTORECFG_MD_NGX_LOC(cstorecfg_md) = location;

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_set_ngx_rc: "
                                              "set rc %ld\n",
                                              rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cstorecfg_override_ngx_rc(const UINT32 cstorecfg_md_id, const ngx_int_t rc, const UINT32 location)
{
    CSTORECFG_MD                  *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_override_ngx_rc: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    if(rc == CSTORECFG_MD_NGX_RC(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_override_ngx_rc: "
                                                  "ignore same rc %ld\n",
                                                  rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CSTORECFG_MD_NGX_RC(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_override_ngx_rc: "
                                                  "modify rc %ld => %ld\n",
                                                  CSTORECFG_MD_NGX_RC(cstorecfg_md), rc);
        CSTORECFG_MD_NGX_RC(cstorecfg_md)  = rc;
        CSTORECFG_MD_NGX_LOC(cstorecfg_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_override_ngx_rc: "
                                              "set rc %ld\n",
                                              rc);

    CSTORECFG_MD_NGX_RC(cstorecfg_md)  = rc;
    CSTORECFG_MD_NGX_LOC(cstorecfg_md) = location;

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_method(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                 *cstorecfg_md;

    ngx_http_request_t           *r;
    char                         *method_str;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_method: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    if(EC_FALSE == cngx_get_req_method_str(r, &method_str))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_method: "
                                                  "fetch method failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == method_str)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_method: "
                                                  "method is null\n");
        return (EC_FALSE);
    }

    CSTORECFG_MD_METHOD(cstorecfg_md) = cstring_new((UINT8 *)method_str, LOC_CSTORECFG_0003);
    if(NULL_PTR == CSTORECFG_MD_METHOD(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_method: "
                                                  "new method '%s' failed\n",
                                                  method_str);

        safe_free(method_str, LOC_CSTORECFG_0004);

        return (EC_FALSE);
    }

    safe_free(method_str, LOC_CSTORECFG_0005);

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_method: "
                                              "parsed method '%s'\n",
                                              (char *)CSTORECFG_MD_METHOD_STR(cstorecfg_md));

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_host(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                 *cstorecfg_md;

    ngx_http_request_t           *r;
    char                         *host_str;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_host: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    if(EC_FALSE == cngx_get_req_host(r, &host_str))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_host: "
                                                  "fetch host failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == host_str)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_host: "
                                                  "host is null\n");
        return (EC_FALSE);
    }

    CSTORECFG_MD_HOST(cstorecfg_md) = cstring_new((UINT8 *)host_str, LOC_CSTORECFG_0006);
    if(NULL_PTR == CSTORECFG_MD_HOST(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_host: "
                                                  "new host '%s' failed\n",
                                                  host_str);

        safe_free(host_str, LOC_CSTORECFG_0007);

        return (EC_FALSE);
    }

    safe_free(host_str, LOC_CSTORECFG_0008);

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_host: "
                                              "parsed host '%s'\n",
                                              (char *)CSTORECFG_MD_HOST_STR(cstorecfg_md));

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_file_name(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                 *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_file_name: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    /*conf file name*/
    CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md) = cstring_make("%s/%s.conf",
                                                  (char *)CSTORECFG_CONF_PATH,
                                                  (char *)CSTORECFG_MD_HOST_STR(cstorecfg_md));
    if(NULL_PTR == CSTORECFG_MD_CFG_FILE_NAME(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_file_name: "
                                                  "make conf file '%s/%s.conf' failed\n",
                                                  (char *)CSTORECFG_CONF_PATH,
                                                  (char *)CSTORECFG_MD_HOST_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_file_name: "
                                              "make conf file name '%s'\n",
                                              (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md));

    /*tmp file name*/
    CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md) = cstring_make("%s/.%s.conf",
                                                  (char *)CSTORECFG_CONF_PATH,
                                                  (char *)CSTORECFG_MD_HOST_STR(cstorecfg_md));
    if(NULL_PTR == CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_file_name: "
                                                  "make conf file '%s/%s.conf' failed\n",
                                                  (char *)CSTORECFG_CONF_PATH,
                                                  (char *)CSTORECFG_MD_HOST_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_file_name: "
                                              "make temp file name '%s'\n",
                                              (char *)CSTORECFG_MD_TMP_FILE_NAME(cstorecfg_md));

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_cmd_line(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                 *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_cmd_line: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    if(EC_FALSE == c_file_access((const char *)CSTORECFG_CROSSPLANE, X_OK))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_cmd_line: "
                                                  "no file '%s' or not executable\n",
                                                  (char *)CSTORECFG_CROSSPLANE);

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_cmd_line: "
                                              "check OK: '%s'\n",
                                              (char *)CSTORECFG_CROSSPLANE);

    /*minify cmd line*/

    CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md) = cstring_make("%s minify %s -o %s",
                                (char *)CSTORECFG_CROSSPLANE,
                                (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md),
                                (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
    if(NULL_PTR == CSTORECFG_MD_MINIFY_CMD_LINE(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_cmd_line: "
                                                  "make cmd line '%s minify %s -o %s' failed\n",
                                                  (char *)CSTORECFG_CROSSPLANE,
                                                  (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md),
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_cmd_line: "
                                              "make cmd line '%s'\n",
                                              (char *)CSTORECFG_MD_MINIFY_CMD_LINE_STR(cstorecfg_md));

    /*format cmd line*/

    CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md) = cstring_make("%s format %s -o %s",
                                (char *)CSTORECFG_CROSSPLANE,
                                (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md),
                                (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md));
    if(NULL_PTR == CSTORECFG_MD_FORMAT_CMD_LINE(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_cmd_line: "
                                                  "make cmd line '%s format %s -o %s' failed\n",
                                                  (char *)CSTORECFG_CROSSPLANE,
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md),
                                                  (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_cmd_line: "
                                              "make cmd line '%s'\n",
                                              (char *)CSTORECFG_MD_FORMAT_CMD_LINE_STR(cstorecfg_md));

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_cache(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                 *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_cache: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    /*buf cache*/

    CSTORECFG_MD_BUF_CACHE(cstorecfg_md) = safe_malloc(CSTORECFG_CACHE_MAX_SIZE, LOC_CSTORECFG_0009);
    if(NULL_PTR == CSTORECFG_MD_BUF_CACHE(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_cache: "
                                                  "malloc buf cache with size %ld failed\n",
                                                  (UINT32)CSTORECFG_CACHE_MAX_SIZE);

        return (EC_FALSE);
    }

    /*cfg cache*/

    CSTORECFG_MD_CFG_CACHE(cstorecfg_md) = safe_malloc(CSTORECFG_CACHE_MAX_SIZE, LOC_CSTORECFG_0010);
    if(NULL_PTR == CSTORECFG_MD_CFG_CACHE(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_cache: "
                                                  "malloc cfg cache with size %ld failed\n",
                                                  (UINT32)CSTORECFG_CACHE_MAX_SIZE);

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_bucket_name(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                 *cstorecfg_md;

    ngx_http_request_t           *r;
    char                         *bucket_name_str;

    const char                   *k;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_bucket_name: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    k = (const char *)"bucket=";
    if(EC_FALSE == cngx_get_req_argv(r, k, &bucket_name_str))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_bucket_name: "
                                                  "get arg '%s' failed\n",
                                                  k);
        return (EC_FALSE);
    }

    if(NULL_PTR == bucket_name_str)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_bucket_name: "
                                                  "no arg '%s'\n",
                                                  k);
        return (EC_FALSE);
    }

    CSTORECFG_MD_BUCKET_NAME(cstorecfg_md) = cstring_new((UINT8 *)bucket_name_str, LOC_CSTORECFG_0011);
    if(NULL_PTR == CSTORECFG_MD_BUCKET_NAME(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_bucket_name: "
                                                  "make name '%s' failed\n",
                                                  bucket_name_str);

        safe_free(bucket_name_str, LOC_CSTORECFG_0012);
        return (EC_FALSE);
    }
    safe_free(bucket_name_str, LOC_CSTORECFG_0013);

    dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_bucket_name: "
                                              "parsed name '%s'\n",
                                              (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_bucket_op(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                 *cstorecfg_md;

    ngx_http_request_t           *r;
    char                         *bucket_op_str;

    const char                   *k;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_bucket_op: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    k = (const char *)"op=";
    if(EC_FALSE == cngx_get_req_argv(r, k, &bucket_op_str))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_bucket_op: "
                                                  "get arg '%s' failed\n",
                                                  k);
        return (EC_FALSE);
    }

    if(NULL_PTR == bucket_op_str)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_bucket_op: "
                                                  "no arg '%s'\n",
                                                  k);
        return (EC_FALSE);
    }

    CSTORECFG_MD_BUCKET_OP(cstorecfg_md) = cstring_new((UINT8 *)bucket_op_str, LOC_CSTORECFG_0014);
    if(NULL_PTR == CSTORECFG_MD_BUCKET_OP(cstorecfg_md))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_bucket_op: "
                                                  "make op '%s' failed\n",
                                                  bucket_op_str);

        safe_free(bucket_op_str, LOC_CSTORECFG_0015);
        return (EC_FALSE);
    }
    safe_free(bucket_op_str, LOC_CSTORECFG_0016);

    dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_bucket_op: "
                                              "parsed op '%s'\n",
                                              (char *)CSTORECFG_MD_BUCKET_OP_STR(cstorecfg_md));

    return (EC_TRUE);
}

EC_BOOL cstorecfg_parse_req_body(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                *cstorecfg_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_parse_req_body: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    if(NULL_PTR == CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md))
    {
        CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md) = cbytes_new(0);
        if(NULL_PTR == CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_req_body: "
                                                      "new cbytes failed\n");
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == cngx_read_req_body(r, CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md), &CSTORECFG_MD_NGX_RC(cstorecfg_md)))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_parse_req_body: "
                                                  "read req body failed\n");

        cbytes_free(CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md));
        CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md) = NULL_PTR;
        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_req_body: "
                                              "req body len %ld\n",
                                              CBYTES_LEN(CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md)));

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_parse_req_body: done\n");

    return (EC_TRUE);
}

EC_BOOL cstorecfg_node_init(CSTORECFG_NODE *cstorecfg_node)
{
    if(NULL_PTR != cstorecfg_node)
    {
        cstring_init(CSTORECFG_NODE_ROOT_PATH(cstorecfg_node), NULL_PTR);
        cstring_init(CSTORECFG_NODE_BACKUP_PATH(cstorecfg_node), NULL_PTR);
    }

    return (EC_TRUE);
}

EC_BOOL cstorecfg_node_clean(CSTORECFG_NODE *cstorecfg_node)
{
    if(NULL_PTR != cstorecfg_node)
    {
        cstring_clean(CSTORECFG_NODE_ROOT_PATH(cstorecfg_node));
        cstring_clean(CSTORECFG_NODE_BACKUP_PATH(cstorecfg_node));
    }

    return (EC_TRUE);
}

void cstorecfg_node_print(LOG *log, const CSTORECFG_NODE *cstorecfg_node)
{
    if(NULL_PTR != cstorecfg_node)
    {
        sys_log(log, "cstorecfg_node_print: "
                     "cstorecfg_node %p, "
                     "root %s, backup %s\n",
                     (char *)CSTORECFG_NODE_ROOT_PATH_STR(cstorecfg_node),
                     (char *)CSTORECFG_NODE_BACKUP_PATH_STR(cstorecfg_node));
    }
    return;
}

STATIC_CAST EC_BOOL __cstorecfg_parse_req_cfg(const UINT32 cstorecfg_md_id, CSTORECFG_NODE *cstorecfg_node)
{
    CSTORECFG_MD                *cstorecfg_md;

    //ngx_http_request_t          *r;

    json_object                 *store_cfg_obj;
    json_object                 *obj;
    char                        *store_cfg_str;
    UINT32                       store_cfg_len;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_parse_req_cfg: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    //r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    if(EC_TRUE == cbytes_is_empty(CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md)))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_parse_req_cfg: "
                                                  "req has no body\n");
        return (EC_FALSE);
    }

    store_cfg_str = (char *)CBYTES_BUF(CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md));
    store_cfg_len = CBYTES_LEN(CSTORECFG_MD_NGX_REQ_BODY(cstorecfg_md));

    store_cfg_obj = json_tokener_parse(store_cfg_str);
    if(NULL_PTR == store_cfg_obj)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_parse_req_cfg: "
                                                  "parse '%.*s' failed\n",
                                                  (uint32_t)store_cfg_len, store_cfg_str);
        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_parse_req_cfg: "
                                              "parse '%.*s' done\n",
                                              (uint32_t)store_cfg_len, store_cfg_str);

    obj = json_object_object_get(store_cfg_obj, "root");
    cstring_init(CSTORECFG_NODE_ROOT_PATH(cstorecfg_node), (UINT8 *)json_object_to_json_string(obj));
    dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "[DEBUG] __cstorecfg_parse_req_cfg: "
                                              "root path: %s\n",
                                              (char *)CSTORECFG_NODE_ROOT_PATH_STR(cstorecfg_node));

    obj = json_object_object_get(store_cfg_obj, "backup");
    cstring_init(CSTORECFG_NODE_BACKUP_PATH(cstorecfg_node), (UINT8 *)json_object_to_json_string(obj));
    dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "[DEBUG] __cstorecfg_parse_req_cfg: "
                                              "backup path: %s\n",
                                              (char *)CSTORECFG_NODE_BACKUP_PATH_STR(cstorecfg_node));

    json_object_put(store_cfg_obj);

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_minify_cfg_file(const UINT32 cstorecfg_md_id,
                                                    char *cmd_output,
                                                    const UINT32 cmd_output_max_size,
                                                    UINT32 *cmd_output_size)
{
    CSTORECFG_MD                *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_minify_cfg_file: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    if(EC_FALSE == c_file_access((char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md), F_OK))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_minify_cfg_file: "
                                                  "no file '%s'\n",
                                                  (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md));
        return (EC_FALSE);
    }

    if(EC_TRUE == c_file_access((char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md), F_OK))
    {
        if(EC_FALSE == c_file_unlink((char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md)))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_minify_cfg_file: "
                                                      "unlink existing file '%s' failed\n",
                                                      (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));

            return (EC_FALSE);
        }
        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_minify_cfg_file: "
                                                  "unlink existing file '%s' done\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));

    }

    if(EC_FALSE == c_exec_shell((char *)CSTORECFG_MD_MINIFY_CMD_LINE_STR(cstorecfg_md),
                                cmd_output, cmd_output_max_size, cmd_output_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_minify_cfg_file: "
                                                  "execute '%s' failed\n",
                                                  (char *)CSTORECFG_MD_MINIFY_CMD_LINE_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_minify_cfg_file: "
                                              "execute '%s' result:\n%.*s\n",
                                              (char *)CSTORECFG_MD_MINIFY_CMD_LINE_STR(cstorecfg_md),
                                              (*cmd_output_size), cmd_output);

    if(EC_FALSE == c_file_access((char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md), F_OK))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_minify_cfg_file: "
                                                  "generate file '%s' failed\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_format_cfg_file(const UINT32 cstorecfg_md_id,
                                                    char *cmd_output,
                                                    const UINT32 cmd_output_max_size,
                                                    UINT32 *cmd_output_size)
{
    CSTORECFG_MD                *cstorecfg_md;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_format_cfg_file: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    if(EC_FALSE == c_file_access((char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md), F_OK))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_format_cfg_file: "
                                                  "no file '%s'\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
        return (EC_FALSE);
    }

    if(EC_TRUE == c_file_access((char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md), F_OK))
    {
        if(EC_FALSE == c_file_unlink((char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md)))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_format_cfg_file: "
                                                      "unlink existing file '%s' failed\n",
                                                      (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md));

            return (EC_FALSE);
        }

        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_format_cfg_file: "
                                                  "unlink existing file '%s' done\n",
                                                  (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md));

    }

    if(EC_FALSE == c_exec_shell((char *)CSTORECFG_MD_FORMAT_CMD_LINE_STR(cstorecfg_md),
                                cmd_output, cmd_output_max_size, cmd_output_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_format_cfg_file: "
                                                  "execute '%s' failed\n",
                                                  (char *)CSTORECFG_MD_FORMAT_CMD_LINE_STR(cstorecfg_md));
        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_format_cfg_file: "
                                              "execute '%s' result:\n%.*s\n",
                                              (char *)CSTORECFG_MD_FORMAT_CMD_LINE_STR(cstorecfg_md),
                                              (*cmd_output_size), cmd_output);

    if(EC_FALSE == c_file_access((char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md), F_OK))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_format_cfg_file: "
                                                  "generate file '%s' failed\n",
                                                  (char *)CSTORECFG_MD_CFG_FILE_NAME_STR(cstorecfg_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_unlink((char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md)))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_format_cfg_file: "
                                                  "unlink tmp file '%s' failed\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_format_cfg_file: "
                                              "unlink tmp file '%s' done\n",
                                              (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_load_tmp_file(const UINT32 cstorecfg_md_id,
                                                    char *content,
                                                    const UINT32 content_max_size,
                                                    UINT32 *content_size)
{
    CSTORECFG_MD                *cstorecfg_md;
    UINT32                       offset;
    int                          fd;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_load_tmp_file: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    fd = c_file_open((char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_load_tmp_file: "
                                                  "open '%s' failed\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_read(fd, &offset, content_max_size, (UINT8 *)content))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_load_tmp_file: "
                                                  "read '%s' failed\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
        c_file_close(fd);

        return (EC_FALSE);
    }

    c_file_close(fd);

    if(offset < content_max_size)
    {
        *(content + offset) = '\0';
    }

    (*content_size) = offset;

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_flush_tmp_file(const UINT32 cstorecfg_md_id,
                                                    const char *content,
                                                    const UINT32 content_max_size,
                                                    UINT32 *content_size)
{
    CSTORECFG_MD                *cstorecfg_md;
    UINT32                       offset;
    int                          fd;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_flush_tmp_file: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    fd = c_file_open((char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md), O_WRONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_flush_tmp_file: "
                                                  "open '%s' failed\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_truncate(fd, 0))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_flush_tmp_file: "
                                                  "truncate '%s' failed\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
        c_file_close(fd);

        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_write(fd, &offset, content_max_size, (UINT8 *)content))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_flush_tmp_file: "
                                                  "write '%s' failed\n",
                                                  (char *)CSTORECFG_MD_TMP_FILE_NAME_STR(cstorecfg_md));
        c_file_close(fd);

        return (EC_FALSE);
    }

    c_file_close(fd);

    (*content_size) = offset;

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_bucket_add(const UINT32 cstorecfg_md_id, const CSTORECFG_NODE *cstorecfg_node)
{
    CSTORECFG_MD                *cstorecfg_md;

    char                        *buf;
    UINT32                       buf_max_size;
    UINT32                       buf_size;

    char                        *cfg;
    UINT32                       cfg_max_size;
    UINT32                       cfg_size;

    char                        *s;
    char                        *t;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_bucket_add: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    buf_max_size = CSTORECFG_CACHE_MAX_SIZE;
    buf = CSTORECFG_MD_BUF_CACHE(cstorecfg_md);

    cfg_max_size = CSTORECFG_CACHE_MAX_SIZE;
    cfg = CSTORECFG_MD_CFG_CACHE(cstorecfg_md);

    if(EC_FALSE == __cstorecfg_minify_cfg_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_add: "
                                                  "minfiy conf file failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == __cstorecfg_load_tmp_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_add: "
                                                  "load tmp file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_add: "
                                              "load tmp file: '%.*s'\n",
                                              (uint32_t)buf_size, buf);

    t = c_str_make("location ~ /%s{", (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));
    if(NULL_PTR == t)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_add: "
                                                  "make str 'location ~ /%s{' failed\n",
                                                  (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    /*check existence*/
    s = strstr(buf, t);
    if(NULL_PTR != s)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_add: "
                                                  "found duplicate location '%s'\n",
                                                  (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0017);

        safe_free(t, LOC_CSTORECFG_0018);
        return (EC_FALSE);
    }
    safe_free(t, LOC_CSTORECFG_0019);

    cfg_size = 0;

    BCOPY(buf, cfg, buf_size - 1);
    cfg_size += buf_size - 1;

    for(; 0 < cfg_size && '}' != cfg[ cfg_size - 1 ]; cfg_size --)
    {
        /*do nothing*/
    }
    cfg_size --;

    cfg_size += snprintf(cfg + cfg_size, cfg_max_size - cfg_size,
                         "location ~ /%s"
                         "{"
                         "root %s;"
                         "set $c_store_backup_dir %s;"
                         "content_by_bgn cstore;"
                         "}"
                         "}", /*server conf block terminator*/
                         (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md),
                         (char *)CSTORECFG_NODE_ROOT_PATH_STR(cstorecfg_node),
                         (char *)CSTORECFG_NODE_BACKUP_PATH_STR(cstorecfg_node));

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_add: "
                                              "result tmp file: '%.*s'\n",
                                              (uint32_t)cfg_size, cfg);

    cfg_max_size = cfg_size;
    if(EC_FALSE == __cstorecfg_flush_tmp_file(cstorecfg_md_id, cfg, cfg_max_size, &cfg_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_add: "
                                                  "flush tmp file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_add: "
                                              "flush tmp file: '%.*s'\n",
                                              (uint32_t)cfg_size, cfg);

    if(EC_FALSE == __cstorecfg_format_cfg_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_add: "
                                                  "format conf file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_add: "
                                              "format conf file done\n");

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_bucket_delete(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                *cstorecfg_md;

    char                        *buf;
    UINT32                       buf_max_size;
    UINT32                       buf_size;

    char                        *cfg;
    UINT32                       cfg_max_size;
    UINT32                       cfg_size;

    char                        *s;
    char                        *e;
    char                        *t;
    UINT32                       depth;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_bucket_delete: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    buf_max_size = CSTORECFG_CACHE_MAX_SIZE;
    buf = CSTORECFG_MD_BUF_CACHE(cstorecfg_md);

    cfg_max_size = CSTORECFG_CACHE_MAX_SIZE;
    cfg = CSTORECFG_MD_CFG_CACHE(cstorecfg_md);

    if(EC_FALSE == __cstorecfg_minify_cfg_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_delete: "
                                                  "minfiy conf file failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == __cstorecfg_load_tmp_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_delete: "
                                                  "load tmp file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_delete: "
                                              "load tmp file: '%.*s'\n",
                                              (uint32_t)buf_size, buf);

    t = c_str_make("location ~ /%s{", (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));
    if(NULL_PTR == t)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_delete: "
                                                  "make str 'location ~ /%s{' failed\n",
                                                  (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    s = strstr(buf, t);
    if(NULL_PTR == s)
    {
        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_delete: "
                                                  "not found '%s'\n",
                                                  t);

        safe_free(t, LOC_CSTORECFG_0020);
        return (EC_TRUE);
    }
    safe_free(t, LOC_CSTORECFG_0021);

    for(e = s + strlen(t), depth = 1; e < buf + buf_size && 0 < depth; e ++)
    {
        if('{' == (*e))
        {
            depth ++;
            continue;
        }

        if('}' == (*e))
        {
            depth --;
            continue;
        }
    }

    if(e >= buf + buf_size || 0 < depth)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_delete: "
                                                  "something wrong: "
                                                  "bucket: '%s', tmp file '%.*s'\n",
                                                  (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md),
                                                  (uint32_t)buf_size, buf);

        return (EC_FALSE);
    }

    cfg_size = 0;

    BCOPY(buf, cfg, s - buf);
    cfg_size += s - buf;

    BCOPY(e, cfg + cfg_size, buf + buf_size - e);
    cfg_size += buf + buf_size - e;

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_delete: "
                                              "result tmp file: '%.*s'\n",
                                              (uint32_t)cfg_size, cfg);

    cfg_max_size = cfg_size;
    if(EC_FALSE == __cstorecfg_flush_tmp_file(cstorecfg_md_id, cfg, cfg_max_size, &cfg_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_delete: "
                                                  "flush tmp file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_delete: "
                                              "flush tmp file: '%.*s'\n",
                                              (uint32_t)cfg_size, cfg);

    if(EC_FALSE == __cstorecfg_format_cfg_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_delete: "
                                                  "format conf file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_delete: "
                                              "format conf file done\n");

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_bucket_modify(const UINT32 cstorecfg_md_id, const CSTORECFG_NODE *cstorecfg_node)
{
    CSTORECFG_MD                *cstorecfg_md;

    char                        *buf;
    UINT32                       buf_max_size;
    UINT32                       buf_size;

    char                        *cfg;
    UINT32                       cfg_max_size;
    UINT32                       cfg_size;

    char                        *s;
    char                        *e;
    char                        *t;
    UINT32                       depth;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cstorecfg_bucket_modify: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    buf_max_size = CSTORECFG_CACHE_MAX_SIZE;
    buf = CSTORECFG_MD_BUF_CACHE(cstorecfg_md);

    cfg_max_size = CSTORECFG_CACHE_MAX_SIZE;
    cfg = CSTORECFG_MD_CFG_CACHE(cstorecfg_md);

    if(EC_FALSE == __cstorecfg_minify_cfg_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_modify: "
                                                  "minfiy conf file failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == __cstorecfg_load_tmp_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_modify: "
                                                  "load tmp file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_modify: "
                                              "load tmp file: '%.*s'\n",
                                              (uint32_t)buf_size, buf);

    t = c_str_make("location ~ /%s{", (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));
    if(NULL_PTR == t)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_modify: "
                                                  "make str 'location ~ /%s{' failed\n",
                                                  (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));

        return (EC_FALSE);
    }

    s = strstr(buf, t);
    if(NULL_PTR == s)
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_modify: "
                                                  "not found '%s'\n",
                                                  t);

        safe_free(t, LOC_CSTORECFG_0022);
        return (EC_FALSE);
    }
    safe_free(t, LOC_CSTORECFG_0023);

    for(e = s + strlen(t), depth = 1; e < buf + buf_size && 0 < depth; e ++)
    {
        if('{' == (*e))
        {
            depth ++;
            continue;
        }

        if('}' == (*e))
        {
            depth --;
            continue;
        }
    }

    if(e >= buf + buf_size || 0 < depth)
    {
        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_modify: "
                                                  "something wrong: "
                                                  "bucket: '%s', tmp file '%.*s'\n",
                                                  (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md),
                                                  (uint32_t)buf_size, buf);

        return (EC_TRUE);
    }

    cfg_size = 0;

    BCOPY(buf, cfg, s - buf);
    cfg_size += s - buf;

    BCOPY(e, cfg + cfg_size, buf + buf_size - e);
    cfg_size += buf + buf_size - e;

    for(; 0 < cfg_size && '}' != cfg[ cfg_size - 1 ]; cfg_size --)
    {
        /*do nothing*/
    }
    cfg_size --;

    cfg_size += snprintf(cfg + cfg_size, cfg_max_size - cfg_size,
                         "location ~ /%s"
                         "{"
                         "root %s;"
                         "set $c_store_backup_dir %s;"
                         "content_by_bgn cstore;"
                         "}"
                         "}", /*server conf block terminator*/
                         (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md),
                         (char *)CSTORECFG_NODE_ROOT_PATH_STR(cstorecfg_node),
                         (char *)CSTORECFG_NODE_BACKUP_PATH_STR(cstorecfg_node));

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_modify: "
                                              "result tmp file: '%.*s'\n",
                                              (uint32_t)cfg_size, cfg);

    cfg_max_size = cfg_size;
    if(EC_FALSE == __cstorecfg_flush_tmp_file(cstorecfg_md_id, cfg, cfg_max_size, &cfg_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_modify: "
                                                  "flush tmp file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_modify: "
                                              "flush tmp file: '%.*s'\n",
                                              (uint32_t)cfg_size, cfg);

    if(EC_FALSE == __cstorecfg_format_cfg_file(cstorecfg_md_id, buf, buf_max_size, &buf_size))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_modify: "
                                                  "format conf file failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_modify: "
                                              "format conf file done\n");

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cstorecfg_bucket_activate()
{
    pid_t                        ppid;

    if(EC_FALSE == c_get_ppid(&ppid))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_activate: "
                                                  "get parent pid failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == c_send_signal(ppid, SIGHUP))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:__cstorecfg_bucket_activate: "
                                                  "send reload signal to parent %d failed\n",
                                                  ppid);

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] __cstorecfg_bucket_activate: "
                                              "send reload signal to parent %d done\n",
                                              ppid);

    return (EC_TRUE);
}

/**
*
* bucket add handler
*
**/
EC_BOOL cstorecfg_bucket_add_handler(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_NODE               cstorecfg_node;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_bucket_add_handler: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_node_init(&cstorecfg_node);

    if(EC_FALSE == __cstorecfg_parse_req_cfg(cstorecfg_md_id, &cstorecfg_node))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_add_handler: "
                                                  "parse cfg failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0024);

        cstorecfg_node_clean(&cstorecfg_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cstorecfg_bucket_add(cstorecfg_md_id, &cstorecfg_node))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_add_handler: "
                                                  "add bucket failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0025);

        cstorecfg_node_clean(&cstorecfg_node);
        return (EC_FALSE);
    }

    cstorecfg_node_clean(&cstorecfg_node);

    if(0)
    {
        if(EC_FALSE == __cstorecfg_bucket_activate())
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_add_handler: "
                                                      "activate bucket failed\n");

            cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0026);

            return (EC_FALSE);
        }

        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_bucket_add_handler: "
                                                  "activate bucket done\n");
    }

    cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_OK, LOC_CSTORECFG_0027);

    return (EC_TRUE);
}

/**
*
* bucket delete handler
*
**/
EC_BOOL cstorecfg_bucket_delete_handler(const UINT32 cstorecfg_md_id)
{
#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_bucket_delete_handler: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    if(EC_FALSE == __cstorecfg_bucket_delete(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_delete_handler: "
                                                  "add bucket failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0028);

        return (EC_FALSE);
    }

    if(0)
    {
        if(EC_FALSE == __cstorecfg_bucket_activate())
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_delete_handler: "
                                                      "activate conf failed\n");

            cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0029);

            return (EC_FALSE);
        }

        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_bucket_add_handler: "
                                                  "activate conf done\n");
    }

    cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_OK, LOC_CSTORECFG_0030);

    return (EC_TRUE);
}

/**
*
* bucket modify handler
*
**/
EC_BOOL cstorecfg_bucket_modify_handler(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_NODE               cstorecfg_node;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_bucket_modify_handler: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_node_init(&cstorecfg_node);

    if(EC_FALSE == __cstorecfg_parse_req_cfg(cstorecfg_md_id, &cstorecfg_node))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_modify_handler: "
                                                  "parse cfg failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0031);

        cstorecfg_node_clean(&cstorecfg_node);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cstorecfg_bucket_modify(cstorecfg_md_id, &cstorecfg_node))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_modify_handler: "
                                                  "add bucket failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0032);

        cstorecfg_node_clean(&cstorecfg_node);
        return (EC_FALSE);
    }

    cstorecfg_node_clean(&cstorecfg_node);

    if(0)
    {
        if(EC_FALSE == __cstorecfg_bucket_activate())
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_modify_handler: "
                                                      "activate conf failed\n");

            cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0033);

            return (EC_FALSE);
        }

        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_bucket_modify_handler: "
                                                  "activate conf done\n");
    }
    cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_OK, LOC_CSTORECFG_0034);

    return (EC_TRUE);
}

/**
*
* bucket activate handler
*
**/
EC_BOOL cstorecfg_bucket_activate_handler(const UINT32 cstorecfg_md_id)
{
#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_bucket_activate_handler: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    if(EC_FALSE == __cstorecfg_bucket_activate())
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_bucket_activate_handler: "
                                                  "activate conf failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0035);

        return (EC_FALSE);
    }

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_bucket_activate_handler: "
                                              "activate conf done\n");

    cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_OK, LOC_CSTORECFG_0036);

    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL cstorecfg_content_handler(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD                *cstorecfg_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_content_handler: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CSTORECFG_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstorecfg_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CSTORECFG_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cstorecfg_md) = BIT_TRUE;
    }

    if(EC_FALSE == cstorecfg_parse_method(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse method failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0037);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse method done\n");

    if(EC_FALSE == cstorecfg_parse_host(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse host failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0038);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse host done\n");

    if(EC_FALSE == cstorecfg_parse_file_name(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse conf file name failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0039);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse conf file name done\n");

    if(EC_FALSE == cstorecfg_parse_cmd_line(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse cmd line failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0040);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse cmd line done\n");

    if(EC_FALSE == cstorecfg_parse_cache(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse cache failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSTORECFG_0041);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse cache done\n");

    if(EC_FALSE == cstorecfg_parse_bucket_name(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse name failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0042);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse name done\n");

    if(EC_FALSE == cstorecfg_parse_bucket_op(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse op failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0043);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse op done\n");

    if(EC_FALSE == cstorecfg_parse_req_body(cstorecfg_md_id))
    {
        dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                  "parse body failed\n");

        cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0044);
        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_handler: "
                                              "parse body done\n");

    /*add bucket*/
    if(NULL_PTR != CSTORECFG_MD_BUCKET_OP(cstorecfg_md)
    && EC_TRUE == cstring_is_str(CSTORECFG_MD_BUCKET_OP(cstorecfg_md), (UINT8 *)CSTORECFG_BUCKET_ADD_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORECFG_MD_METHOD(cstorecfg_md), (UINT8 *)"POST"))
    {
        if(EC_FALSE == cstorecfg_bucket_add_handler(cstorecfg_md_id))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                      "add bucket failed\n");

            cstorecfg_content_send_response(cstorecfg_md_id);
            return (EC_FALSE);
        }

        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_TRUE);
    }

    /*delete bucket*/
    if(NULL_PTR != CSTORECFG_MD_BUCKET_OP(cstorecfg_md)
    && EC_TRUE == cstring_is_str(CSTORECFG_MD_BUCKET_OP(cstorecfg_md), (UINT8 *)CSTORECFG_BUCKET_DELETE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORECFG_MD_METHOD(cstorecfg_md), (UINT8 *)"DELETE"))
    {
        if(EC_FALSE == cstorecfg_bucket_delete_handler(cstorecfg_md_id))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                      "delete bucket failed\n");

            cstorecfg_content_send_response(cstorecfg_md_id);
            return (EC_FALSE);
        }

        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_TRUE);
    }

    /*modify bucket*/
    if(NULL_PTR != CSTORECFG_MD_BUCKET_OP(cstorecfg_md)
    && EC_TRUE == cstring_is_str(CSTORECFG_MD_BUCKET_OP(cstorecfg_md), (UINT8 *)CSTORECFG_BUCKET_MODIFY_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORECFG_MD_METHOD(cstorecfg_md), (UINT8 *)"PUT"))
    {
        if(EC_FALSE == cstorecfg_bucket_modify_handler(cstorecfg_md_id))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                      "modify bucket failed\n");

            cstorecfg_content_send_response(cstorecfg_md_id);
            return (EC_FALSE);
        }

        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_TRUE);
    }

    /*activate bucket*/
    if(NULL_PTR != CSTORECFG_MD_BUCKET_OP(cstorecfg_md)
    && EC_TRUE == cstring_is_str(CSTORECFG_MD_BUCKET_OP(cstorecfg_md), (UINT8 *)CSTORECFG_BUCKET_ACTIVATE_OP)
    && EC_TRUE == cstring_is_str_ignore_case(CSTORECFG_MD_METHOD(cstorecfg_md), (UINT8 *)"GET"))
    {
        if(EC_FALSE == cstorecfg_bucket_activate_handler(cstorecfg_md_id))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                                      "activate bucket failed\n");

            cstorecfg_content_send_response(cstorecfg_md_id);
            return (EC_FALSE);
        }

        cstorecfg_content_send_response(cstorecfg_md_id);
        return (EC_TRUE);
    }

    dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_handler: "
                                              "unknown method '%s', op '%s', bucket '%s'\n",
                                              (char *)CSTORECFG_MD_METHOD_STR(cstorecfg_md),
                                              (char *)CSTORECFG_MD_BUCKET_OP_STR(cstorecfg_md),
                                              (char *)CSTORECFG_MD_BUCKET_NAME_STR(cstorecfg_md));

    cstorecfg_set_ngx_rc(cstorecfg_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSTORECFG_0045);
    cstorecfg_content_send_response(cstorecfg_md_id);
    return (EC_FALSE);
}

EC_BOOL cstorecfg_content_send_response(const UINT32 cstorecfg_md_id)
{
    CSTORECFG_MD               *cstorecfg_md;

    ngx_http_request_t         *r;
    uint32_t                    len;
    uint32_t                    flags;

#if ( SWITCH_ON == CSTORECFG_DEBUG_SWITCH )
    if ( CSTORECFG_MD_ID_CHECK_INVALID(cstorecfg_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cstorecfg_content_send_response: cstorecfg module #0x%lx not started.\n",
                cstorecfg_md_id);
        dbg_exit(MD_CSTORECFG, cstorecfg_md_id);
    }
#endif/*CSTORECFG_DEBUG_SWITCH*/

    cstorecfg_md = CSTORECFG_MD_GET(cstorecfg_md_id);

    r = CSTORECFG_MD_NGX_HTTP_REQ(cstorecfg_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);/*xxx*/

        cngx_set_header_out_status(r, CSTORECFG_MD_NGX_RC(cstorecfg_md));
        cngx_set_header_out_content_length(r, 0);/*no body*/

        if(EC_FALSE == cngx_send_header(r, &(CSTORECFG_MD_NGX_RC(cstorecfg_md))))
        {
            dbg_log(SEC_0172_CSTORECFG, 0)(LOGSTDOUT, "error:cstorecfg_content_send_response: "
                                                      "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_send_response: "
                                                  "send header done\n");
    }

    /*send body*/
    if(NULL_PTR != CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md))
    {
        uint8_t     *data;

        data = (uint8_t *)CBYTES_BUF(CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md));
        len  = (uint32_t )CBYTES_LEN(CSTORECFG_MD_NGX_RSP_BODY(cstorecfg_md));

        flags =   CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG
                | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CSTORECFG_MD_NGX_RC(cstorecfg_md))))
        {
            dbg_log(SEC_0172_CSTORECFG, 1)(LOGSTDOUT, "error:cstorecfg_content_send_response: "
                                                      "send body failed\n");

            return (EC_FALSE);
        }

        dbg_log(SEC_0172_CSTORECFG, 9)(LOGSTDOUT, "[DEBUG] cstorecfg_content_send_response: "
                                                  "send body done => complete %ld bytes\n",
                                                  CSTORECFG_MD_SENT_BODY_SIZE(cstorecfg_md));
        return (EC_TRUE);
    }

    flags =   CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CSTORECFG_MD_NGX_RC(cstorecfg_md))))
    {
        dbg_log(SEC_0172_CSTORECFG, 1)(LOGSTDOUT, "error:cstorecfg_content_send_response: "
                                                  "send body failed\n");

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/



