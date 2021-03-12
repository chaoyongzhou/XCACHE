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

#include "cshell.h"

#include "findex.inc"

#define CSHELL_MD_CAPACITY()                  (cbc_md_capacity(MD_CSHELL))

#define CSHELL_MD_GET(cshell_md_id)     ((CSHELL_MD *)cbc_md_get(MD_CSHELL, (cshell_md_id)))

#define CSHELL_MD_ID_CHECK_INVALID(cshell_md_id)  \
    ((CMPI_ANY_MODI != (cshell_md_id)) && ((NULL_PTR == CSHELL_MD_GET(cshell_md_id)) || (0 == (CSHELL_MD_GET(cshell_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CSHELL Module
*
**/
void cshell_print_module_status(const UINT32 cshell_md_id, LOG *log)
{
    CSHELL_MD *cshell_md;
    UINT32      this_cshell_md_id;

    for( this_cshell_md_id = 0; this_cshell_md_id < CSHELL_MD_CAPACITY(); this_cshell_md_id ++ )
    {
        cshell_md = CSHELL_MD_GET(this_cshell_md_id);

        if(NULL_PTR != cshell_md && 0 < cshell_md->usedcounter )
        {
            sys_log(log,"CSHELL Module # %u : %u refered\n",
                    this_cshell_md_id,
                    cshell_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CSHELL module
*
**/
EC_BOOL cshell_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CSHELL , 1);
}

/**
*
* unregister CSHELL module
*
**/
EC_BOOL cshell_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CSHELL);
}

/**
*
* start CSHELL module
*
**/
UINT32 cshell_start(ngx_http_request_t *r)
{
    CSHELL_MD *cshell_md;
    UINT32       cshell_md_id;

    cshell_md_id = cbc_md_new(MD_CSHELL, sizeof(CSHELL_MD));
    if(CMPI_ERROR_MODI == cshell_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CSHELL module */
    cshell_md = (CSHELL_MD *)cbc_md_get(MD_CSHELL, cshell_md_id);
    cshell_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    /* init */
    CSHELL_MD_NGX_HTTP_REQ(cshell_md)     = r;

    /*TODO: load all variables into module*/

    CSHELL_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cshell_md) = BIT_FALSE;

    CSHELL_MD_CMD_LINE(cshell_md)                  = NULL_PTR;
    CSHELL_MD_CMD_OUTPUT_MAX_SIZE(cshell_md)       = 0;

    CSHELL_MD_CONTENT_LENGTH(cshell_md)            = 0;

    CSHELL_MD_NGX_RSP_BODY(cshell_md)              = NULL_PTR;
    CSHELL_MD_SENT_BODY_SIZE(cshell_md)            = 0;

    CSHELL_MD_NGX_LOC(cshell_md)                   = LOC_NONE_END;
    CSHELL_MD_NGX_RC(cshell_md)                    = NGX_OK;

    cshell_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cshell_end, cshell_md_id);

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_start: start CSHELL module #%ld\n", cshell_md_id);

    return ( cshell_md_id );
}

/**
*
* end CSHELL module
*
**/
void cshell_end(const UINT32 cshell_md_id)
{
    CSHELL_MD *cshell_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cshell_end, cshell_md_id);

    cshell_md = CSHELL_MD_GET(cshell_md_id);
    if(NULL_PTR == cshell_md)
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_end: "
                                               "cshell_md_id = %ld not exist.\n",
                                               cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cshell_md->usedcounter )
    {
        cshell_md->usedcounter --;
        return ;
    }

    if ( 0 == cshell_md->usedcounter )
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_end: "
                                               "cshell_md_id = %ld is not started.\n",
                                               cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }

    if(NULL_PTR != CSHELL_MD_NGX_RSP_BODY(cshell_md))
    {
        cbytes_free(CSHELL_MD_NGX_RSP_BODY(cshell_md));
        CSHELL_MD_NGX_RSP_BODY(cshell_md) = NULL_PTR;
    }

    if(NULL_PTR != CSHELL_MD_CMD_LINE(cshell_md))
    {
        cstring_free(CSHELL_MD_CMD_LINE(cshell_md));
        CSHELL_MD_CMD_LINE(cshell_md) = NULL_PTR;
    }

    CSHELL_MD_NGX_HTTP_REQ(cshell_md) = NULL_PTR;

    CSHELL_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cshell_md) = BIT_FALSE;

    CSHELL_MD_CONTENT_LENGTH(cshell_md)            = 0;
    CSHELL_MD_SENT_BODY_SIZE(cshell_md)            = 0;
    CSHELL_MD_CMD_OUTPUT_MAX_SIZE(cshell_md)       = 0;

    CSHELL_MD_NGX_LOC(cshell_md)                   = LOC_NONE_END;
    CSHELL_MD_NGX_RC(cshell_md)                    = NGX_OK;

    /* free module */
    cshell_md->usedcounter = 0;

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "cshell_end: stop CSHELL module #%ld\n", cshell_md_id);
    cbc_md_free(MD_CSHELL, cshell_md_id);

    return ;
}

EC_BOOL cshell_get_ngx_rc(const UINT32 cshell_md_id, ngx_int_t *rc, UINT32 *location)
{
    CSHELL_MD                  *cshell_md;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_get_ngx_rc: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CSHELL_MD_NGX_RC(cshell_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CSHELL_MD_NGX_LOC(cshell_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cshell_set_ngx_rc(const UINT32 cshell_md_id, const ngx_int_t rc, const UINT32 location)
{
    CSHELL_MD                  *cshell_md;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_set_ngx_rc: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    /*do not override*/
    if(NGX_OK != CSHELL_MD_NGX_RC(cshell_md))
    {
        dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_override_ngx_rc: "
                                               "ignore rc %ld due to its %ld now\n",
                                               rc, CSHELL_MD_NGX_RC(cshell_md));
        return (EC_TRUE);
    }

    CSHELL_MD_NGX_RC(cshell_md)  = rc;
    CSHELL_MD_NGX_LOC(cshell_md) = location;

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_set_ngx_rc: "
                                           "set rc %ld\n",
                                           rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cshell_override_ngx_rc(const UINT32 cshell_md_id, const ngx_int_t rc, const UINT32 location)
{
    CSHELL_MD                  *cshell_md;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_override_ngx_rc: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    if(rc == CSHELL_MD_NGX_RC(cshell_md))
    {
        dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_override_ngx_rc: "
                                               "ignore same rc %ld\n",
                                               rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CSHELL_MD_NGX_RC(cshell_md))
    {
        dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_override_ngx_rc: "
                                               "modify rc %ld => %ld\n",
                                               CSHELL_MD_NGX_RC(cshell_md), rc);
        CSHELL_MD_NGX_RC(cshell_md)  = rc;
        CSHELL_MD_NGX_LOC(cshell_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_override_ngx_rc: "
                                           "set rc %ld\n",
                                           rc);

    CSHELL_MD_NGX_RC(cshell_md)  = rc;
    CSHELL_MD_NGX_LOC(cshell_md) = location;

    return (EC_TRUE);
}

EC_BOOL cshell_parse_cmd_output_size(const UINT32 cshell_md_id)
{
    CSHELL_MD                   *cshell_md;

    ngx_http_request_t          *r;
    const char                  *k;
    ssize_t                      cmd_output_conf_size;

    uint32_t                     client_body_max_size;
    uint32_t                     cmd_output_max_size;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_cmd_handler: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    r = CSHELL_MD_NGX_HTTP_REQ(cshell_md);

    /*output size limited by client body max size*/
    k = (const char *)CSHELL_CNGX_VAR_OUTPUT_SIZE;
    cngx_get_var_size(r, k, &cmd_output_conf_size, (ssize_t)CSHELL_CNGX_OUTPUT_SIZE_DEFAULT);
    cngx_get_client_body_max_size(r, &client_body_max_size);

    if(cmd_output_conf_size >= client_body_max_size)
    {
        cmd_output_max_size = client_body_max_size;
    }
    else
    {
        cmd_output_max_size = cmd_output_conf_size;
    }

    CSHELL_MD_CMD_OUTPUT_MAX_SIZE(cshell_md) = cmd_output_max_size;

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_parse_cmd_output_size: "
                                           "output size %d, client body max %d => output size %u\n",
                                           cmd_output_conf_size, client_body_max_size, cmd_output_max_size);

    return (EC_TRUE);
}

EC_BOOL cshell_parse_cmd(const UINT32 cshell_md_id)
{
    CSHELL_MD                   *cshell_md;

    ngx_http_request_t          *r;

    CBYTES                       req_body;
    char                        *cmd_line;
    UINT32                       cmd_len;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_cmd_handler: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    r = CSHELL_MD_NGX_HTTP_REQ(cshell_md);

    cbytes_init(&req_body);

    if(EC_FALSE == cngx_read_req_body(r, &req_body, &CSHELL_MD_NGX_RC(cshell_md)))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "read body failed\n");

        cbytes_clean(&req_body);
        return (EC_FALSE);
    }

    if(EC_TRUE == cbytes_is_empty(&req_body))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "req has no body\n");

        cbytes_clean(&req_body);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSHELL_0001);
        return (EC_FALSE);
    }

    cmd_line = (char *)CBYTES_BUF(&req_body);
    cmd_len  = (uint32_t)CBYTES_LEN(&req_body);

    CSHELL_MD_CMD_LINE(cshell_md) = cstring_make("%.*s", cmd_len, cmd_line);
    if(NULL_PTR == CSHELL_MD_CMD_LINE(cshell_md))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "make cmdline '%.*s' failed\n",
                                               cmd_len, cmd_line);

        cbytes_clean(&req_body);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSHELL_0001);
        return (EC_FALSE);
    }

    cbytes_clean(&req_body);

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_cmd_handler: "
                                           "make cmdline '%s' done\n",
                                           (char *)CSHELL_MD_CMD_LINE_STR(cshell_md));

    return (EC_TRUE);
}

EC_BOOL cshell_parse_cmd_default(const UINT32 cshell_md_id)
{
    CSHELL_MD                   *cshell_md;

    ngx_http_request_t          *r;
    const char                  *k;
    char                        *v;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_parse_cmd_default: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    r = CSHELL_MD_NGX_HTTP_REQ(cshell_md);

    /*command*/
    k = (const char *)CSHELL_CNGX_VAR_CMD;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_parse_cmd_default: "
                                               "get var '%s' failed\n",
                                               k);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSHELL_0001);
        return (EC_FALSE);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_parse_cmd_default: "
                                               "not configure '%s'\n",
                                               k);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSHELL_0002);
        return (EC_FALSE);
    }

    CSHELL_MD_CMD_LINE(cshell_md) = cstring_new((UINT8 *)v, LOC_CSHELL_0002);
    if(NULL_PTR == CSHELL_MD_CMD_LINE(cshell_md))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_parse_cmd_default: "
                                               "make cmdline '%s' failed\n",
                                               v);

        safe_free(v, LOC_CSHELL_0002);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSHELL_0001);
        return (EC_FALSE);
    }

    safe_free(v, LOC_CSHELL_0002);

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_parse_cmd_default: "
                                           "make cmdline '%s' done\n",
                                           (char *)CSHELL_MD_CMD_LINE_STR(cshell_md));

    return (EC_TRUE);
}

EC_BOOL cshell_cmd_handler(const UINT32 cshell_md_id)
{
    CSHELL_MD                   *cshell_md;

    ngx_http_request_t          *r;

    char                        *cmd_output_buff;
    UINT32                       cmd_output_max_size;

    UINT32                       cmd_output_size;
    CBYTES                      *rsp_body;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_cmd_handler: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    r = CSHELL_MD_NGX_HTTP_REQ(cshell_md);

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_cmd_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CSHELL_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cshell_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CSHELL_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cshell_md) = BIT_TRUE;
    }

    if(EC_FALSE == cshell_parse_cmd_output_size(cshell_md_id))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "parse cmd output size failed\n");

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSHELL_0001);
        return (EC_FALSE);
    }

    if(EC_FALSE == cshell_parse_cmd(cshell_md_id))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "parse cmd failed\n");

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_BAD_REQUEST, LOC_CSHELL_0001);
        return (EC_FALSE);
    }

    cmd_output_max_size = CSHELL_MD_CMD_OUTPUT_MAX_SIZE(cshell_md);

    cmd_output_buff = (char *)safe_malloc(cmd_output_max_size, LOC_CSHELL_0003);
    if(NULL_PTR == cmd_output_buff)
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "alloc cmd_output_buff %ld bytes failed\n",
                                               cmd_output_max_size);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSHELL_0005);
        return (EC_FALSE);
    }

    /*execute*/
    if(EC_FALSE == exec_shell((char *)CSHELL_MD_CMD_LINE_STR(cshell_md),
                                cmd_output_buff, cmd_output_max_size,
                                &cmd_output_size))
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "exec '%s' failed\n",
                                               (char *)CSHELL_MD_CMD_LINE_STR(cshell_md));

        safe_free(cmd_output_buff, LOC_CSHELL_0006);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSHELL_0008);
        return (EC_FALSE);
    }

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_cmd_handler: "
                                           "exec '%s' done\n",
                                           (char *)CSHELL_MD_CMD_LINE_STR(cshell_md));

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_cmd_handler: "
                                           "exec '%s' =>\n"
                                           "%.*s\n",
                                           (char *)CSHELL_MD_CMD_LINE_STR(cshell_md),
                                           (uint32_t)cmd_output_size, cmd_output_buff);

    rsp_body = cbytes_new(0);
    if(NULL_PTR == rsp_body)
    {
        dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_cmd_handler: "
                                               "cmd '%s', new rsp body failed\n",
                                               (char *)CSHELL_MD_CMD_LINE_STR(cshell_md));

        safe_free(cmd_output_buff, LOC_CSHELL_0009);

        cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CSHELL_0011);
        return (EC_FALSE);
    }

    cbytes_mount(rsp_body, cmd_output_size, (UINT8 *)cmd_output_buff, BIT_FALSE);
    CSHELL_MD_NGX_RSP_BODY(cshell_md) = rsp_body;

    cmd_output_buff = NULL_PTR;/*clear*/

    cngx_set_header_out_kv(r, (const char *)"Content-Length", c_word_to_str(cmd_output_size));

    cshell_set_ngx_rc(cshell_md_id, NGX_HTTP_OK, LOC_CSHELL_0013);

    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL cshell_content_handler(const UINT32 cshell_md_id)
{
    CSHELL_MD                   *cshell_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_content_handler: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    r = CSHELL_MD_NGX_HTTP_REQ(cshell_md);

    dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CSHELL_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cshell_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CSHELL_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cshell_md) = BIT_TRUE;
    }

    if(EC_FALSE == cshell_cmd_handler(cshell_md_id))
    {
        cshell_content_send_response(cshell_md_id);
        return (EC_FALSE);
    }

    cshell_content_send_response(cshell_md_id);
    return (EC_TRUE);
}

EC_BOOL cshell_content_send_response(const UINT32 cshell_md_id)
{
    CSHELL_MD                 *cshell_md;

    ngx_http_request_t         *r;
    uint32_t                    len;
    uint32_t                    flags;

#if ( SWITCH_ON == CSHELL_DEBUG_SWITCH )
    if ( CSHELL_MD_ID_CHECK_INVALID(cshell_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cshell_content_send_response: cshell module #0x%lx not started.\n",
                cshell_md_id);
        dbg_exit(MD_CSHELL, cshell_md_id);
    }
#endif/*CSHELL_DEBUG_SWITCH*/

    cshell_md = CSHELL_MD_GET(cshell_md_id);

    r = CSHELL_MD_NGX_HTTP_REQ(cshell_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);/*xxx*/

        cngx_set_header_out_status(r, CSHELL_MD_NGX_RC(cshell_md));
        cngx_set_header_out_content_length(r, 0);/*no body*/

        if(EC_FALSE == cngx_send_header(r, &(CSHELL_MD_NGX_RC(cshell_md))))
        {
            dbg_log(SEC_0170_CSHELL, 0)(LOGSTDOUT, "error:cshell_content_send_response: "
                                                   "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_content_send_response: "
                                               "send header done\n");
    }

    /*send body*/
    if(NULL_PTR != CSHELL_MD_NGX_RSP_BODY(cshell_md))
    {
        uint8_t     *data;

        data = (uint8_t *)CBYTES_BUF(CSHELL_MD_NGX_RSP_BODY(cshell_md));
        len  = (uint32_t )CBYTES_LEN(CSHELL_MD_NGX_RSP_BODY(cshell_md));

        flags =   CNGX_SEND_BODY_FLUSH_FLAG
                | CNGX_SEND_BODY_RECYCLED_FLAG
                | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

        if(EC_FALSE == cngx_send_body(r, data, len, flags, &(CSHELL_MD_NGX_RC(cshell_md))))
        {
            dbg_log(SEC_0170_CSHELL, 1)(LOGSTDOUT, "error:cshell_content_send_response: "
                                                   "send body failed\n");

            return (EC_FALSE);
        }

        CSHELL_MD_SENT_BODY_SIZE(cshell_md) += len;

        dbg_log(SEC_0170_CSHELL, 9)(LOGSTDOUT, "[DEBUG] cshell_content_send_response: "
                                               "send body done => complete %ld bytes\n",
                                               CSHELL_MD_SENT_BODY_SIZE(cshell_md));
        return (EC_TRUE);
    }

    flags =   CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CSHELL_MD_NGX_RC(cshell_md))))
    {
        dbg_log(SEC_0170_CSHELL, 1)(LOGSTDOUT, "error:cshell_content_send_response: "
                                               "send body failed\n");

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


