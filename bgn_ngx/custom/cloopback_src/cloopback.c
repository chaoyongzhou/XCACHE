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

#include "cngx.h"
#include "cngx_headers.h"

#include "cmd5.h"

#include "cloopback.h"

#define CLOOPBACK_MD_CAPACITY()                  (cbc_md_capacity(MD_CLOOPBACK))

#define CLOOPBACK_MD_GET(cloopback_md_id)     ((CLOOPBACK_MD *)cbc_md_get(MD_CLOOPBACK, (cloopback_md_id)))

#define CLOOPBACK_MD_ID_CHECK_INVALID(cloopback_md_id)  \
    ((CMPI_ANY_MODI != (cloopback_md_id)) && ((NULL_PTR == CLOOPBACK_MD_GET(cloopback_md_id)) || (0 == (CLOOPBACK_MD_GET(cloopback_md_id)->usedcounter))))


/**
*   for test only
*
*   to query the status of CLOOPBACK Module
*
**/
void cloopback_print_module_status(const UINT32 cloopback_md_id, LOG *log)
{
    CLOOPBACK_MD *cloopback_md;
    UINT32        this_cloopback_md_id;

    for( this_cloopback_md_id = 0; this_cloopback_md_id < CLOOPBACK_MD_CAPACITY(); this_cloopback_md_id ++ )
    {
        cloopback_md = CLOOPBACK_MD_GET(this_cloopback_md_id);

        if(NULL_PTR != cloopback_md && 0 < cloopback_md->usedcounter )
        {
            sys_log(log,"CLOOPBACK Module # %u : %u refered\n",
                    this_cloopback_md_id,
                    cloopback_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CLOOPBACK module
*
**/
EC_BOOL cloopback_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CLOOPBACK , 128);
}

/**
*
* unregister CLOOPBACK module
*
**/
EC_BOOL cloopback_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CLOOPBACK);
}

/**
*
* start CLOOPBACK module
*
**/
UINT32 cloopback_start(ngx_http_request_t *r)
{
    CLOOPBACK_MD *cloopback_md;
    UINT32       cloopback_md_id;

    cloopback_md_id = cbc_md_new(MD_CLOOPBACK, sizeof(CLOOPBACK_MD));
    if(CMPI_ERROR_MODI == cloopback_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CLOOPBACK module */
    cloopback_md = (CLOOPBACK_MD *)cbc_md_get(MD_CLOOPBACK, cloopback_md_id);
    cloopback_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CLOOPBACK_MD_NGX_HTTP_REQ(cloopback_md)     = r;

    CLOOPBACK_MD_NGX_LOC(cloopback_md)          = LOC_NONE_END;
    CLOOPBACK_MD_NGX_RC(cloopback_md)           = NGX_OK;

    cloopback_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cloopback_end, cloopback_md_id);

    dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_start: start CLOOPBACK module #%u\n", cloopback_md_id);

    return ( cloopback_md_id );
}

/**
*
* end CLOOPBACK module
*
**/
void cloopback_end(const UINT32 cloopback_md_id)
{
    CLOOPBACK_MD *cloopback_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cloopback_end, cloopback_md_id);

    cloopback_md = CLOOPBACK_MD_GET(cloopback_md_id);
    if(NULL_PTR == cloopback_md)
    {
        dbg_log(SEC_0127_CLOOPBACK, 0)(LOGSTDOUT, "error:cloopback_end: cloopback_md_id = %u not exist.\n", cloopback_md_id);
        dbg_exit(MD_CLOOPBACK, cloopback_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cloopback_md->usedcounter )
    {
        cloopback_md->usedcounter --;
        return ;
    }

    if ( 0 == cloopback_md->usedcounter )
    {
        dbg_log(SEC_0127_CLOOPBACK, 0)(LOGSTDOUT, "error:cloopback_end: cloopback_md_id = %u is not started.\n", cloopback_md_id);
        dbg_exit(MD_CLOOPBACK, cloopback_md_id);
    }

    CLOOPBACK_MD_NGX_HTTP_REQ(cloopback_md)     = NULL_PTR;

    CLOOPBACK_MD_NGX_LOC(cloopback_md)          = LOC_NONE_END;
    CLOOPBACK_MD_NGX_RC(cloopback_md)           = NGX_OK;

    /* free module */
    cloopback_md->usedcounter = 0;

    dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "cloopback_end: stop CLOOPBACK module #%u\n", cloopback_md_id);
    cbc_md_free(MD_CLOOPBACK, cloopback_md_id);

    return ;
}

EC_BOOL cloopback_get_ngx_rc(const UINT32 cloopback_md_id, ngx_int_t *rc, UINT32 *location)
{
    CLOOPBACK_MD                  *cloopback_md;

#if ( SWITCH_ON == CLOOPBACK_DEBUG_SWITCH )
    if ( CLOOPBACK_MD_ID_CHECK_INVALID(cloopback_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cloopback_get_ngx_rc: cloopback module #0x%lx not started.\n",
                cloopback_md_id);
        dbg_exit(MD_CLOOPBACK, cloopback_md_id);
    }
#endif/*CLOOPBACK_DEBUG_SWITCH*/

    cloopback_md = CLOOPBACK_MD_GET(cloopback_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CLOOPBACK_MD_NGX_RC(cloopback_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CLOOPBACK_MD_NGX_LOC(cloopback_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cloopback_set_ngx_rc(const UINT32 cloopback_md_id, const ngx_int_t rc, const UINT32 location)
{
    CLOOPBACK_MD                  *cloopback_md;
    ngx_http_request_t           *r;

#if ( SWITCH_ON == CLOOPBACK_DEBUG_SWITCH )
    if ( CLOOPBACK_MD_ID_CHECK_INVALID(cloopback_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cloopback_set_ngx_rc: cloopback module #0x%lx not started.\n",
                cloopback_md_id);
        dbg_exit(MD_CLOOPBACK, cloopback_md_id);
    }
#endif/*CLOOPBACK_DEBUG_SWITCH*/

    cloopback_md = CLOOPBACK_MD_GET(cloopback_md_id);

    /*do not override*/
    if(NGX_OK != CLOOPBACK_MD_NGX_RC(cloopback_md))
    {
        dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_set_ngx_rc: "
                                                 "ignore rc %d due to its %d now\n",
                                                 rc, CLOOPBACK_MD_NGX_RC(cloopback_md));
        return (EC_TRUE);
    }

    r = CLOOPBACK_MD_NGX_HTTP_REQ(cloopback_md);
    if(EC_FALSE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_set_ngx_rc: "
                                                 "ignore rc %d due to header had sent out\n",
                                                 rc);
        cngx_disable_keepalive(r);
        return (EC_TRUE);
    }

    CLOOPBACK_MD_NGX_RC(cloopback_md)  = rc;
    CLOOPBACK_MD_NGX_LOC(cloopback_md) = location;

    dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_set_ngx_rc: "
                                             "set rc %d\n",
                                             rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cloopback_override_ngx_rc(const UINT32 cloopback_md_id, const ngx_int_t rc, const UINT32 location)
{
    CLOOPBACK_MD                *cloopback_md;
    ngx_http_request_t          *r;

#if ( SWITCH_ON == CLOOPBACK_DEBUG_SWITCH )
    if ( CLOOPBACK_MD_ID_CHECK_INVALID(cloopback_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cloopback_override_ngx_rc: cloopback module #0x%lx not started.\n",
                cloopback_md_id);
        dbg_exit(MD_CLOOPBACK, cloopback_md_id);
    }
#endif/*CLOOPBACK_DEBUG_SWITCH*/

    cloopback_md = CLOOPBACK_MD_GET(cloopback_md_id);

    if(rc == CLOOPBACK_MD_NGX_RC(cloopback_md))
    {
        dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_override_ngx_rc: "
                                                 "ignore same rc %d\n",
                                                 rc);
        return (EC_TRUE);
    }

    r = CLOOPBACK_MD_NGX_HTTP_REQ(cloopback_md);
    if(EC_FALSE == cngx_need_send_header(r))
    {
        dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_override_ngx_rc: "
                                                 "ignore rc %d due to header had sent out\n",
                                                 rc);
        cngx_disable_keepalive(r);
        return (EC_TRUE);
    }

    if(NGX_OK != CLOOPBACK_MD_NGX_RC(cloopback_md))
    {
        dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_override_ngx_rc: "
                                                 "modify rc %d => %d\n",
                                                 CLOOPBACK_MD_NGX_RC(cloopback_md), rc);
        CLOOPBACK_MD_NGX_RC(cloopback_md)  = rc;
        CLOOPBACK_MD_NGX_LOC(cloopback_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_override_ngx_rc: "
                                             "set rc %d\n",
                                             rc);

    CLOOPBACK_MD_NGX_RC(cloopback_md)  = rc;
    CLOOPBACK_MD_NGX_LOC(cloopback_md) = location;

    return (EC_TRUE);
}

/**
*
* access filter
*
**/
EC_BOOL cloopback_access_filter(const UINT32 cloopback_md_id)
{
    CLOOPBACK_MD                *cloopback_md;

    ngx_http_request_t          *r;

    char                        *var_hostname;
    char                        *header_x_via;

#if ( SWITCH_ON == CLOOPBACK_DEBUG_SWITCH )
    if ( CLOOPBACK_MD_ID_CHECK_INVALID(cloopback_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cloopback_access_filter: cloopback module #0x%lx not started.\n",
                cloopback_md_id);
        dbg_exit(MD_CLOOPBACK, cloopback_md_id);
    }
#endif/*CLOOPBACK_DEBUG_SWITCH*/

    cloopback_md = CLOOPBACK_MD_GET(cloopback_md_id);

    r = CLOOPBACK_MD_NGX_HTTP_REQ(cloopback_md);

    dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_access_filter: enter\n");

    if(do_log(SEC_0127_CLOOPBACK, 9))
    {
        CHTTP_REQ       chttp_req_t;

        chttp_req_init(&chttp_req_t);

        cngx_export_header_in(r, &chttp_req_t);

        cngx_export_method(r, &chttp_req_t);
        cngx_export_uri(r, &chttp_req_t);

        dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_access_filter: cngx req is -------------------------\n");
        chttp_req_print_plain(LOGSTDOUT, &chttp_req_t);
        dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_access_filter: -------------------------------------\n");

        chttp_req_clean(&chttp_req_t);
    }

    /*
     * if no x-loopback-enabled, then check passed
     * if x-loopback-enabled = yes, then check passed
     * if x-loopback-enabled = no, then
     *      if current visiable hostname is undefined, then check failed
     *      if header x-via is not found, then check passed
     *      if header x-via contains current visiable hostname, then check failed
     *      else check passed
     *
     */

    /*check header x-loopback-enabled*/
    do
    {
        const char                  *k;
        char                        *v;

        k = (const char *)CLOOPBACK_ENABLED_HEADER;
        if(EC_FALSE == cngx_get_header_in(r, k, &v))
        {
            dbg_log(SEC_0127_CLOOPBACK, 0)(LOGSTDOUT, "error:cloopback_access_filter: "
                                                      "get '%s' failed\n",
                                                      k);
            return (EC_FALSE);
        }

        /*if no x-loopback-enabled, then check passed*/
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_access_filter: "
                                                      "no header '%s' => check passed\n",
                                                      k);
            return (EC_TRUE);
        }

        /*if x-loopback-enabled = yes, then check passed*/
        if(EC_TRUE == c_str_is_in(v, (const char *)":", (const char *)"yes:y"))
        {
            dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_access_filter: "
                                                      "header '%s' = '%s' => check passed\n",
                                                      k, v);
            safe_free(v, LOC_CLOOPBACK_0001);
            return (EC_TRUE);
        }

        safe_free(v, LOC_CLOOPBACK_0002);
    }while(0);

    /*get variable c_visible_hostname*/
    do
    {
        const char                  *k;
        char                        *v;

        k = (const char *)CLOOPBACK_VAR_HOSTNAME;
        if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
        {
            dbg_log(SEC_0127_CLOOPBACK, 0)(LOGSTDOUT, "error:cloopback_access_filter: "
                                                      "get var '%s' failed\n",
                                                      k);

            cloopback_set_ngx_rc(cloopback_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CLOOPBACK_0003);
            cngx_set_deny_reason(r, DENY_REASON_CLOOPBACK_0001);
            return (EC_FALSE);
        }

        /*if current visiable hostname is undefined, then check failed*/
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0127_CLOOPBACK, 0)(LOGSTDOUT, "error:cloopback_access_filter: "
                                                      "var '%s' undefined => check failed\n",
                                                      k);
            cloopback_set_ngx_rc(cloopback_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CLOOPBACK_0004);
            cngx_set_deny_reason(r, DENY_REASON_CLOOPBACK_0002);
            return (EC_FALSE);
        }

        var_hostname = v;
    }while(0);

    /*get header x-via*/
    do
    {
        const char                  *k;
        char                        *v;

        k = (const char *)CLOOPBACK_VIA_HEADER;
        if(EC_FALSE == cngx_get_header_in(r, k, &v))
        {
            dbg_log(SEC_0127_CLOOPBACK, 0)(LOGSTDOUT, "error:cloopback_access_filter: "
                                                      "get '%s' failed\n",
                                                      k);
            safe_free(var_hostname, LOC_CLOOPBACK_0005);

            cloopback_set_ngx_rc(cloopback_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CLOOPBACK_0006);
            cngx_set_deny_reason(r, DENY_REASON_CLOOPBACK_0003);
            return (EC_FALSE);
        }

        /*if header x-via is not found, then check passed*/
        if(NULL_PTR == v)
        {
            dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_access_filter: "
                                                      "no header '%s' => check passed\n",
                                                      k);
            safe_free(var_hostname, LOC_CLOOPBACK_0007);
            return (EC_TRUE);
        }

        header_x_via = v;
    }while(0);

    /*if header x-via contains current visiable hostname, then check failed*/
    if(NULL_PTR != strcasestr(header_x_via, var_hostname))
    {
        dbg_log(SEC_0127_CLOOPBACK, 0)(LOGSTDOUT, "error:cloopback_access_filter: "
                                                  "header '%s':'%s' contains visable host '%s' => check failed\n",
                                                  (const char *)CLOOPBACK_VIA_HEADER, header_x_via,
                                                  var_hostname);

        cloopback_set_ngx_rc(cloopback_md_id, NGX_HTTP_FORBIDDEN, LOC_CLOOPBACK_0008);
        cngx_set_deny_reason(r, DENY_REASON_CLOOPBACK_0004);

        safe_free(var_hostname, LOC_CLOOPBACK_0009);
        safe_free(header_x_via, LOC_CLOOPBACK_0010);

        return (EC_FALSE);
    }

    dbg_log(SEC_0127_CLOOPBACK, 9)(LOGSTDOUT, "[DEBUG] cloopback_access_filter: "
                                              "check passed\n");

    safe_free(var_hostname, LOC_CLOOPBACK_0011);
    safe_free(header_x_via, LOC_CLOOPBACK_0012);

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


