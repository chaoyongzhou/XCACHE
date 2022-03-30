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

/*----------------------------------------------------------------------------*\
 *                             LOG RELAY                                      *
 *              based on unix domain socket with unix packet                  *
\*----------------------------------------------------------------------------*/

/*-------------------------------------------------------------------*\
nginx server configuration example:
===================================
server {
    listen  80;
    server_name logrelay.test.com;

    client_body_in_file_only off;
    client_max_body_size 8m;

    more_set_headers 'X-LogRelay: enabled';

    location ~ /logs {
        set $c_acl_token 1234567890abcdefghijklmnopqrstuv;
        set $c_unixpacket_domain_socket_path "/opt/tmp/logrelay/unixpacket.sock";
        set $c_unixpacket_domain_socket_timeout_nsec 1200; # default is 60
        set $c_unixpacket_domain_socket_expired_nsec 600;  # default is 60
        set $c_unixpacket_domain_socket_connect_nsec 10;   # default is 60
        set $c_unixpacket_domain_socket_max_packets  10240;# default is 1024
        access_by_bgn cacltime;
        content_by_bgn cunixpacket;
    }
}
\*-------------------------------------------------------------------*/

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

#include "csocket.h"
#include "cepoll.h"

#include "cngx.h"
#include "chttp.h"

#include "cunixpacket.h"

#include "findex.inc"

#define CUNIXPACKET_ASSERT(condition)   ASSERT(condition)

#define CUNIXPACKET_MD_CAPACITY()                  (cbc_md_capacity(MD_CUNIXPACKET))

#define CUNIXPACKET_MD_GET(cunixpacket_md_id)     ((CUNIXPACKET_MD *)cbc_md_get(MD_CUNIXPACKET, (cunixpacket_md_id)))

#define CUNIXPACKET_MD_ID_CHECK_INVALID(cunixpacket_md_id)  \
    ((CMPI_ANY_MODI != (cunixpacket_md_id)) && ((NULL_PTR == CUNIXPACKET_MD_GET(cunixpacket_md_id)) || (0 == (CUNIXPACKET_MD_GET(cunixpacket_md_id)->usedcounter))))

/*-------------------------------------------------------------------*\
nginx server configuration example:
===================================
server {
    listen  80;
    server_name *.logagent.com;

    client_body_in_file_only off;
    client_max_body_size 8m;
    more_set_headers 'X-LogRelay: enabled';

    location ~ /logs {
        set $c_acl_token 1234567890abcdefghijklmnopqrstuv;
        set $c_unixpacket_domain_socket_path "/opt/tmp/verender_logagent/unixpacket_v4.sock";
        set $c_unixpacket_domain_socket_timeout_nsec 1200;
        set $c_unixpacket_domain_socket_connect_nsec 10;
        set $c_unixpacket_domain_socket_expired_nsec 600;
        set $c_unixpacket_domain_socket_max_packets  10240;
        content_by_bgn cunixpacket;
    }
}
\*-------------------------------------------------------------------*/

/*global uds list for all module instances*/
static CLIST    *g_cunixpacket_uds_list = NULL_PTR;
static EC_BOOL   g_cunixpacket_uds_list_destroy_register_flag = EC_FALSE;

/**
*   for test only
*
*   to query the status of CUNIXPACKET Module
*
**/
void cunixpacket_print_module_status(const UINT32 cunixpacket_md_id, LOG *log)
{
    CUNIXPACKET_MD  *cunixpacket_md;
    UINT32                 this_cunixpacket_md_id;

    for( this_cunixpacket_md_id = 0; this_cunixpacket_md_id < CUNIXPACKET_MD_CAPACITY(); this_cunixpacket_md_id ++ )
    {
        cunixpacket_md = CUNIXPACKET_MD_GET(this_cunixpacket_md_id);

        if(NULL_PTR != cunixpacket_md && 0 < cunixpacket_md->usedcounter )
        {
            sys_log(log,"CUNIXPACKET Module # %u : %u refered\n",
                    this_cunixpacket_md_id,
                    cunixpacket_md->usedcounter);
        }
    }

    return ;
}

/**
*
* register CUNIXPACKET module
*
**/
EC_BOOL cunixpacket_reg()
{
    /*register mm*/
    /*do nothing*/

    /*register module*/
    return cbc_md_reg(MD_CUNIXPACKET , 1);
}

/**
*
* unregister CUNIXPACKET module
*
**/
EC_BOOL cunixpacket_unreg()
{
    /*unregister mm*/
    /*do nothing*/

    /*unregister module*/
    return cbc_md_unreg(MD_CUNIXPACKET);
}

/**
*
* start CUNIXPACKET module
*
**/
UINT32 cunixpacket_start(ngx_http_request_t *r)
{
    CUNIXPACKET_MD       *cunixpacket_md;
    UINT32                      cunixpacket_md_id;

    const char                 *k;
    char                       *v;
    CSTRING                    *uds_path;

    init_static_mem();

    if(NULL_PTR == g_cunixpacket_uds_list)
    {
        if(EC_FALSE == cunixpacket_uds_list_init())
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_start: "
                                                        "init uds list failed\n");
            return (CMPI_ERROR_MODI);
        }
    }

    cunixpacket_md_id = cbc_md_new(MD_CUNIXPACKET, sizeof(CUNIXPACKET_MD));
    if(CMPI_ERROR_MODI == cunixpacket_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    k = (const char *)CUNIXPACKET_CNGX_VAR_UDS_PATH;
    if(EC_FALSE == cngx_get_var_str(r, k, &v, NULL_PTR))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_start: "
                                                    "get var '%s' failed\n",
                                                    k);
        cbc_md_free(MD_CUNIXPACKET, cunixpacket_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(NULL_PTR == v)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 1)(LOGSTDOUT, "[DEBUG] cunixpacket_start: "
                                                    "not configure '%s'\n",
                                                    k);

        cbc_md_free(MD_CUNIXPACKET, cunixpacket_md_id);
        return (CMPI_ERROR_MODI);
    }

    uds_path = cstring_new((UINT8 *)v, LOC_CUNIXPACKET_0006);
    if(NULL_PTR == uds_path)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_start: "
                                                    "make unix socket path '%s' failed\n",
                                                    k);

        c_str_free(v);
        cbc_md_free(MD_CUNIXPACKET, cunixpacket_md_id);
        return (CMPI_ERROR_MODI);
    }
    c_str_free(v);

    /* initialize new one CUNIXPACKET module */
    cunixpacket_md = (CUNIXPACKET_MD *)cbc_md_get(MD_CUNIXPACKET, cunixpacket_md_id);
    cunixpacket_md->usedcounter   = 0;

    /* create a new module node */

    /* init */

    CUNIXPACKET_MD_UDS_PATH(cunixpacket_md)         = uds_path;

    CUNIXPACKET_MD_NGX_HTTP_REQ(cunixpacket_md)     = r;

    /*TODO: load all variables into module*/

    CUNIXPACKET_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cunixpacket_md) = BIT_FALSE;

    CUNIXPACKET_MD_CONTENT_LENGTH(cunixpacket_md)            = 0;

    CUNIXPACKET_MD_NGX_LOC(cunixpacket_md)                   = LOC_NONE_END;
    CUNIXPACKET_MD_NGX_RC(cunixpacket_md)                    = NGX_OK;

    cunixpacket_md->usedcounter = 1;

    if(EC_FALSE == g_cunixpacket_uds_list_destroy_register_flag)
    {
        csig_atexit_register((CSIG_ATEXIT_HANDLER)cunixpacket_uds_list_destroy, (UINT32)NULL_PTR);
        g_cunixpacket_uds_list_destroy_register_flag = EC_TRUE;
    }

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cunixpacket_end, cunixpacket_md_id);

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_start: start CUNIXPACKET module #%ld\n", cunixpacket_md_id);

    return ( cunixpacket_md_id );
}

/**
*
* end CUNIXPACKET module
*
**/
void cunixpacket_end(const UINT32 cunixpacket_md_id)
{
    CUNIXPACKET_MD  *cunixpacket_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cunixpacket_end, cunixpacket_md_id);

    cunixpacket_md = CUNIXPACKET_MD_GET(cunixpacket_md_id);
    if(NULL_PTR == cunixpacket_md)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_end: "
                                                    "cunixpacket_md_id = %ld not exist.\n",
                                                    cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cunixpacket_md->usedcounter )
    {
        cunixpacket_md->usedcounter --;
        return ;
    }

    if ( 0 == cunixpacket_md->usedcounter )
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_end: "
                                                    "cunixpacket_md_id = %ld is not started.\n",
                                                    cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }

    if(NULL_PTR != CUNIXPACKET_MD_UDS_PATH(cunixpacket_md))
    {
        cstring_free(CUNIXPACKET_MD_UDS_PATH(cunixpacket_md));
        CUNIXPACKET_MD_UDS_PATH(cunixpacket_md) = NULL_PTR;
    }

    CUNIXPACKET_MD_NGX_HTTP_REQ(cunixpacket_md) = NULL_PTR;

    CUNIXPACKET_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cunixpacket_md) = BIT_FALSE;

    CUNIXPACKET_MD_CONTENT_LENGTH(cunixpacket_md) = 0;

    CUNIXPACKET_MD_NGX_LOC(cunixpacket_md)        = LOC_NONE_END;
    CUNIXPACKET_MD_NGX_RC(cunixpacket_md)         = NGX_OK;

    /* free module */
    cunixpacket_md->usedcounter = 0;

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "cunixpacket_end: stop CUNIXPACKET module #%ld\n", cunixpacket_md_id);
    cbc_md_free(MD_CUNIXPACKET, cunixpacket_md_id);

    return ;
}

EC_BOOL cunixpacket_get_ngx_rc(const UINT32 cunixpacket_md_id, ngx_int_t *rc, UINT32 *location)
{
    CUNIXPACKET_MD                   *cunixpacket_md;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_MD_ID_CHECK_INVALID(cunixpacket_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_get_ngx_rc: cunixpacket module #0x%lx not started.\n",
                cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_md = CUNIXPACKET_MD_GET(cunixpacket_md_id);

    if(NULL_PTR != rc)
    {
        (*rc) = CUNIXPACKET_MD_NGX_RC(cunixpacket_md);
    }

    if(NULL_PTR != location)
    {
        (*location) = CUNIXPACKET_MD_NGX_LOC(cunixpacket_md);
    }
    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cunixpacket_set_ngx_rc(const UINT32 cunixpacket_md_id, const ngx_int_t rc, const UINT32 location)
{
    CUNIXPACKET_MD                   *cunixpacket_md;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_MD_ID_CHECK_INVALID(cunixpacket_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_set_ngx_rc: cunixpacket module #0x%lx not started.\n",
                cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_md = CUNIXPACKET_MD_GET(cunixpacket_md_id);

    /*do not override*/
    if(NGX_OK != CUNIXPACKET_MD_NGX_RC(cunixpacket_md)
    && NGX_HTTP_OK != CUNIXPACKET_MD_NGX_RC(cunixpacket_md))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_set_ngx_rc: "
                                                    "ignore rc %ld due to its %ld now\n",
                                                    rc, CUNIXPACKET_MD_NGX_RC(cunixpacket_md));
        return (EC_TRUE);
    }

    CUNIXPACKET_MD_NGX_RC(cunixpacket_md)  = rc;
    CUNIXPACKET_MD_NGX_LOC(cunixpacket_md) = location;

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_set_ngx_rc: "
                                                "set rc %ld\n",
                                                rc);

    return (EC_TRUE);
}

/*only for failure!*/
EC_BOOL cunixpacket_override_ngx_rc(const UINT32 cunixpacket_md_id, const ngx_int_t rc, const UINT32 location)
{
    CUNIXPACKET_MD                   *cunixpacket_md;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_MD_ID_CHECK_INVALID(cunixpacket_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_override_ngx_rc: cunixpacket module #0x%lx not started.\n",
                cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_md = CUNIXPACKET_MD_GET(cunixpacket_md_id);

    if(rc == CUNIXPACKET_MD_NGX_RC(cunixpacket_md))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_override_ngx_rc: "
                                                    "ignore same rc %ld\n",
                                                    rc);
        return (EC_TRUE);
    }

    if(NGX_OK != CUNIXPACKET_MD_NGX_RC(cunixpacket_md))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_override_ngx_rc: "
                                                    "modify rc %ld => %ld\n",
                                                    CUNIXPACKET_MD_NGX_RC(cunixpacket_md), rc);
        CUNIXPACKET_MD_NGX_RC(cunixpacket_md)  = rc;
        CUNIXPACKET_MD_NGX_LOC(cunixpacket_md) = location;

        return (EC_TRUE);
    }

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_override_ngx_rc: "
                                                "set rc %ld\n",
                                                rc);

    CUNIXPACKET_MD_NGX_RC(cunixpacket_md)  = rc;
    CUNIXPACKET_MD_NGX_LOC(cunixpacket_md) = location;

    return (EC_TRUE);
}

EC_BOOL cunixpacket_process(const UINT32 UNUSED(none))
{
    UINT32      cunixpacket_uds_node_num;
    UINT32      cunixpacket_uds_node_idx;
    uint64_t    cur_time_nsec;

    CUNIXPACKET_ASSERT(NULL_PTR != g_cunixpacket_uds_list);

    cur_time_nsec = c_get_cur_time_nsec();

    cunixpacket_uds_node_num = clist_size(g_cunixpacket_uds_list);
    for(cunixpacket_uds_node_idx = 0;
        cunixpacket_uds_node_idx < cunixpacket_uds_node_num;
        cunixpacket_uds_node_idx ++)
    {
        CUNIXPACKET_UDS_NODE *cunixpacket_uds_node;

        cunixpacket_uds_node = clist_pop_front(g_cunixpacket_uds_list);
        if(NULL_PTR == cunixpacket_uds_node)
        {
            continue;
        }

        if(cur_time_nsec > CUNIXPACKET_UDS_NODE_EXPIRED_TS(cunixpacket_uds_node))
        {
            /*expired*/
            dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_process: "
                                                        "expired uds node (%s, %d), discard packets %ld\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                        clist_size(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node)));
            cunixpacket_uds_node_free(cunixpacket_uds_node);
            continue;
        }

        while(CUNIXPACKET_UDS_NODE_MAX_PACKETS(cunixpacket_uds_node) < clist_size(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node)))
        {
            CBYTES      *uds_packet_data;

            uds_packet_data = clist_pop_front(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node));

            /*discard packet data*/
            dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_process: "
                                                        "uds node (%s, %d) discard data len %ld\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                        CBYTES_LEN(uds_packet_data));

            cbytes_free(uds_packet_data);
        }

        clist_push_back(g_cunixpacket_uds_list, (void *)cunixpacket_uds_node);

        if(0 == clist_size(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node)))
        {
            if(cur_time_nsec >= CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node))
            {
                CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node) = cur_time_nsec
                                                                      + CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node);

            }
            continue;
        }

        /*connect uds if need*/
        if(ERR_FD == CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node)
        && cur_time_nsec >= CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 1)(LOGSTDOUT, "[DEBUG] cunixpacket_process: "
                                                        "uds path '%s' has no socket\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node));

            if(EC_FALSE == csocket_unixpacket_connect((const char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                      CSOCKET_IS_NONBLOCK_MODE,
                                                      &CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node)))
            {
                CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node) = cur_time_nsec
                                                                      + CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node);

                dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_process: "
                                                            "connect unix socket path '%s' failed "
                                                            "=> retry in %u seconds\n",
                                                            (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                            CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node));

                continue;
            }

            CUNIXPACKET_UDS_NODE_IS_CONNECTED(cunixpacket_uds_node) = BIT_TRUE;

            dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_process: "
                                                        "connect unix socket path '%s' done, socket %d\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
        }

        if(BIT_FALSE == CUNIXPACKET_UDS_NODE_IS_POLLING(cunixpacket_uds_node)
        && BIT_TRUE == CUNIXPACKET_UDS_NODE_IS_CONNECTED(cunixpacket_uds_node))
        {
            cepoll_set_event(task_brd_default_get_cepoll(),
                            CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                            CEPOLL_WR_EVENT,
                            (const char *)"cunixpacket_send_packet",
                            (CEPOLL_EVENT_HANDLER)cunixpacket_send_packet,
                            (void *)cunixpacket_uds_node);

            cepoll_set_shutdown(task_brd_default_get_cepoll(),
                            CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                            (const char *)"cunixpacket_uds_node_shutdown",
                            (CEPOLL_EVENT_HANDLER)cunixpacket_uds_node_shutdown,
                            (void *)cunixpacket_uds_node);

            cepoll_set_timeout(task_brd_default_get_cepoll(),
                            CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                            (uint32_t)CUNIXPACKET_UDS_NODE_TIMEOUT_NSEC(cunixpacket_uds_node),
                            (const char *)"cunixpacket_uds_node_timeout",
                            (CEPOLL_EVENT_HANDLER)cunixpacket_uds_node_timeout,
                            (void *)cunixpacket_uds_node);

            CUNIXPACKET_UDS_NODE_IS_POLLING(cunixpacket_uds_node) = BIT_TRUE;

            dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_process: "
                                                        "uds path %s, socket %d "
                                                        "=> set WR event done\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
        }
    }

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cunixpacket_process,
                        (void *)NULL_PTR);

    return (EC_TRUE);
}

CUNIXPACKET_UDS_NODE *cunixpacket_uds_node_new()
{
    CUNIXPACKET_UDS_NODE *cunixpacket_uds_node;

    alloc_static_mem(MM_CUNIXPACKET_UDS_NODE, &cunixpacket_uds_node, LOC_CUNIXPACKET_0007);
    if(NULL_PTR == cunixpacket_uds_node)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_uds_node_new: "
                                                    "new cunixpacket_uds_node failed\n");
        return (NULL_PTR);
    }

    cunixpacket_uds_node_init(cunixpacket_uds_node);

    return (cunixpacket_uds_node);
}

/* one page block = 64MB */
EC_BOOL cunixpacket_uds_node_init(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node)
{
    if(NULL_PTR != cunixpacket_uds_node)
    {
        CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node)             = NULL_PTR;
        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node)           = ERR_FD;
        CUNIXPACKET_UDS_NODE_IS_POLLING(cunixpacket_uds_node)       = BIT_FALSE;
        CUNIXPACKET_UDS_NODE_IS_CONNECTED(cunixpacket_uds_node)     = BIT_FALSE;

        CUNIXPACKET_UDS_NODE_MAX_PACKETS(cunixpacket_uds_node)      = 0;

        CUNIXPACKET_UDS_NODE_TIMEOUT_NSEC(cunixpacket_uds_node)     = 0;
        CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node)     = 0;
        CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node)     = 0;

        CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node)       = 0;
        CUNIXPACKET_UDS_NODE_EXPIRED_TS(cunixpacket_uds_node)       = 0;

        clist_init(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node), MM_CBYTES, LOC_CUNIXPACKET_0008);
    }

    return (EC_TRUE);
}

EC_BOOL cunixpacket_uds_node_clean(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node)
{
    if(NULL_PTR != cunixpacket_uds_node)
    {
        if(NULL_PTR != CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node))
        {
            cstring_free(CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node));
            CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node)     = NULL_PTR;
        }

        if(ERR_FD != CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node))
        {
            cepoll_del_all(task_brd_default_get_cepoll(), CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
            csocket_close(CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
            CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node) = ERR_FD;
        }

        CUNIXPACKET_UDS_NODE_IS_POLLING(cunixpacket_uds_node)      = BIT_FALSE;
        CUNIXPACKET_UDS_NODE_IS_CONNECTED(cunixpacket_uds_node)    = BIT_FALSE;

        CUNIXPACKET_UDS_NODE_MAX_PACKETS(cunixpacket_uds_node)      = 0;

        CUNIXPACKET_UDS_NODE_TIMEOUT_NSEC(cunixpacket_uds_node)     = 0;
        CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node)     = 0;
        CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node)     = 0;

        CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node)       = 0;
        CUNIXPACKET_UDS_NODE_EXPIRED_TS(cunixpacket_uds_node)       = 0;

        clist_clean(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node), (CLIST_DATA_DATA_CLEANER)cbytes_free);
    }

    return (EC_TRUE);
}

EC_BOOL cunixpacket_uds_node_free(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node)
{
    if(NULL_PTR != cunixpacket_uds_node)
    {
        cunixpacket_uds_node_clean(cunixpacket_uds_node);
        free_static_mem(MM_CUNIXPACKET_UDS_NODE, cunixpacket_uds_node, LOC_CUNIXPACKET_0009);
    }

    return (EC_TRUE);
}

STATIC_CAST EC_BOOL __cunixpacket_uds_node_cmp_path(const CUNIXPACKET_UDS_NODE *cunixpacket_uds_node, const CSTRING *cunixpacket_uds_path)
{
    return cstring_is_equal(CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node), cunixpacket_uds_path);
}

CUNIXPACKET_UDS_NODE *cunixpacket_uds_list_search(const CSTRING *cunixpacket_uds_path)
{
    CUNIXPACKET_ASSERT(NULL_PTR != g_cunixpacket_uds_list);

    return clist_search_data_front(g_cunixpacket_uds_list, (void *)cunixpacket_uds_path,
                                   (CLIST_DATA_DATA_CMP)__cunixpacket_uds_node_cmp_path);
}

CUNIXPACKET_UDS_NODE *cunixpacket_uds_list_add(const CSTRING *cunixpacket_uds_path, int cunixpacket_uds_socket)
{
    CUNIXPACKET_UDS_NODE *cunixpacket_uds_node;

    CUNIXPACKET_ASSERT(NULL_PTR != g_cunixpacket_uds_list);

    cunixpacket_uds_node = cunixpacket_uds_list_search(cunixpacket_uds_path);
    if(NULL_PTR != cunixpacket_uds_node)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 1)(LOGSTDOUT, "warn:cunixpacket_uds_list_add: "
                                                    "found duplicate uds path '%s' with socket %d\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
        return (cunixpacket_uds_node);
    }

    cunixpacket_uds_node = cunixpacket_uds_node_new();
    if(NULL_PTR == cunixpacket_uds_node)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_uds_list_add: "
                                                    "new uds node of path '%s' failed\n",
                                                    (char *)cstring_get_str(cunixpacket_uds_path));
        return (NULL_PTR);
    }

    CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node) = cstring_dup(cunixpacket_uds_path);
    if(NULL_PTR == CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_uds_list_add: "
                                                    "dup uds path '%s' failed\n",
                                                    (char *)cstring_get_str(cunixpacket_uds_path));
        cunixpacket_uds_node_free(cunixpacket_uds_node);
        return (NULL_PTR);
    }

    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node) = cunixpacket_uds_socket;

    clist_push_back(g_cunixpacket_uds_list, (void *)cunixpacket_uds_node);

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_uds_list_add: "
                                                "push uds node ('%s', %d) done\n",
                                                CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
    return (cunixpacket_uds_node);
}

EC_BOOL cunixpacket_uds_node_shutdown(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node)
{
    CUNIXPACKET_ASSERT(NULL_PTR != g_cunixpacket_uds_list);

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_uds_node_shutdown: "
                                                "shutdown uds node ('%s', %d)\n",
                                                CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));

    clist_del(g_cunixpacket_uds_list, (void *)cunixpacket_uds_node, NULL_PTR);

    cunixpacket_uds_node_free(cunixpacket_uds_node);

    return (EC_TRUE);
}

EC_BOOL cunixpacket_uds_node_timeout(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node)
{
    CUNIXPACKET_ASSERT(NULL_PTR != g_cunixpacket_uds_list);

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_uds_node_timeout: "
                                                "timeout uds node ('%s', %d)\n",
                                                CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));

    clist_del(g_cunixpacket_uds_list, (void *)cunixpacket_uds_node, NULL_PTR);

    cunixpacket_uds_node_free(cunixpacket_uds_node);

    return (EC_TRUE);
}

EC_BOOL cunixpacket_uds_list_cleanup()
{
    CUNIXPACKET_UDS_NODE *cunixpacket_uds_node;

    CUNIXPACKET_ASSERT(NULL_PTR != g_cunixpacket_uds_list);

    while(NULL_PTR != (cunixpacket_uds_node = clist_pop_front(g_cunixpacket_uds_list)))
    {
        cunixpacket_uds_node_free(cunixpacket_uds_node);
    }

    return (EC_TRUE);
}

EC_BOOL cunixpacket_uds_list_init()
{
    if(NULL_PTR == g_cunixpacket_uds_list)
    {
        g_cunixpacket_uds_list = clist_new(MM_CUNIXPACKET_UDS_NODE, LOC_CUNIXPACKET_0010);

        if(NULL_PTR == g_cunixpacket_uds_list)
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_uds_list_init: "
                                                        "init unix packet uds list failed\n");

            return (EC_FALSE);
        }

        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cunixpacket_process,
                            (void *)NULL_PTR);

        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_uds_list_init: "
                                                    "init unix packet uds list done\n");

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cunixpacket_uds_list_destroy(const UINT32 UNUSED(none))
{
    if(NULL_PTR != g_cunixpacket_uds_list)
    {
        cunixpacket_uds_list_cleanup();

        clist_free(g_cunixpacket_uds_list, LOC_CUNIXPACKET_0011);
        g_cunixpacket_uds_list = NULL_PTR;


        csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cunixpacket_uds_list_destroy, (UINT32)NULL_PTR);
        g_cunixpacket_uds_list_destroy_register_flag = EC_FALSE;

        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_uds_list_destory: "
                                                    "destroy unix packet uds list done\n");
    }
    return (EC_TRUE);
}

/**
*
* send data to unix domain socket with unixpacket
*
**/
EC_BOOL cunixpacket_send_packet(CUNIXPACKET_UDS_NODE *cunixpacket_uds_node)
{
    CBYTES                      *uds_packet_data;
    UINT32                       uds_packet_sent_len;
    CUNIXPACKET_UDS_NODE  *cunixpacket_uds_node_t;

    /*check validity*/
    if(NULL_PTR == CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_packet: "
                                                    "no uds path\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node), F_OK))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_packet: "
                                                    "uds path '%s' access failed\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node));
        return (EC_FALSE);
    }

    cunixpacket_uds_node_t = cunixpacket_uds_list_search(CUNIXPACKET_UDS_NODE_PATH(cunixpacket_uds_node));
    if(NULL_PTR == cunixpacket_uds_node_t)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_packet: "
                                                    "uds path '%s' not registered\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node));

        cunixpacket_uds_node_free(cunixpacket_uds_node);
        return (EC_FALSE);
    }

    if(cunixpacket_uds_node_t != cunixpacket_uds_node)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_packet: "
                                                    "search uds node %p != %p\n",
                                                    cunixpacket_uds_node_t,
                                                    cunixpacket_uds_node);

        cunixpacket_uds_node_free(cunixpacket_uds_node);
        return (EC_FALSE);
    }

    if(ERR_FD == CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_packet: "
                                                    "uds path '%s' has no socket\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node));
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_send_packet: "
                                                "found uds node (%s, %d)\n",
                                                (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));

    uds_packet_sent_len = 0;
    while(NULL_PTR != (uds_packet_data = clist_pop_front(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node))))
    {
        /*no limit rate, no socket busy handling yet ...*/

        if(EC_FALSE == csocket_unixpacket_send(CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                               CBYTES_BUF(uds_packet_data),
                                               CBYTES_LEN(uds_packet_data),
                                               NULL_PTR))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_packet: "
                                                        "send unix domain socket packet %p:%ld failed\n",
                                                        CBYTES_BUF(uds_packet_data),
                                                        CBYTES_LEN(uds_packet_data));

            clist_push_front(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node), (void *)uds_packet_data);


            dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_packet: "
                                                        "send alread %ld bytes\n",
                                                        uds_packet_sent_len);

            /*return false would trigger shutdown handler and delete event and close socket*/
            return (EC_FALSE);
        }

        uds_packet_sent_len += CBYTES_LEN(uds_packet_data);
        cbytes_free(uds_packet_data);
    }

    if(0 < CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node))
    {
        CUNIXPACKET_UDS_NODE_EXPIRED_TS(cunixpacket_uds_node) = c_get_cur_time_nsec()
                                                              + CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node);

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_packet: "
                                                    "uds node (%s, %d) => update expired in %u seconds\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node));
    }

    if(EC_TRUE == clist_is_empty(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node)))
    {
        cepoll_del_event(task_brd_default_get_cepoll(),
                         CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                         CEPOLL_WR_EVENT);

        CUNIXPACKET_UDS_NODE_IS_POLLING(cunixpacket_uds_node) = BIT_FALSE;

        dbg_log(SEC_0009_CUNIXPACKET, 5)(LOGSTDOUT, "[DEBUG] cunixpacket_send_packet: "
                                                    "uds path %s, socket %d nothing to send "
                                                    "=> del WR event done\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                     CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
    }

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_packet: "
                                                "send %ld bytes succ\n",
                                                uds_packet_sent_len);

    return (EC_TRUE);
}

/**
*
* cache data which would be sent to unix domain socket with unixpacket
*
**/
EC_BOOL cunixpacket_send_handler(const UINT32 cunixpacket_md_id)
{
    CUNIXPACKET_MD        *cunixpacket_md;

    ngx_http_request_t          *r;
    CBYTES                      *ngx_req_body;

    CUNIXPACKET_UDS_NODE  *cunixpacket_uds_node;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_MD_ID_CHECK_INVALID(cunixpacket_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_send_handler: cunixpacket module #0x%lx not started.\n",
                cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_md = CUNIXPACKET_MD_GET(cunixpacket_md_id);

    r = CUNIXPACKET_MD_NGX_HTTP_REQ(cunixpacket_md);

    /*check validity*/
    if(NULL_PTR == CUNIXPACKET_MD_UDS_PATH(cunixpacket_md))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                    "no uds path\n");
        cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_NOT_FOUND, LOC_CUNIXPACKET_0012);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_access((char *)CUNIXPACKET_MD_UDS_PATH_STR(cunixpacket_md), F_OK))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                    "uds path '%s' access failed\n",
                                                    (char *)CUNIXPACKET_MD_UDS_PATH_STR(cunixpacket_md));
        cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_NOT_FOUND, LOC_CUNIXPACKET_0013);
        return (EC_FALSE);
    }

    /*add or search uds node*/
    cunixpacket_uds_node = cunixpacket_uds_list_add(CUNIXPACKET_MD_UDS_PATH(cunixpacket_md), ERR_FD);
    if(NULL_PTR == cunixpacket_uds_node)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                    "push uds node (%s, %d) failed\n",
                                                    (char *)CUNIXPACKET_MD_UDS_PATH_STR(cunixpacket_md),
                                                    ERR_FD);
        cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUNIXPACKET_0014);
        return (EC_FALSE);
    }

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                "add or found uds node ('%s', %d) done\n",
                                                (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));

    if(0 == CUNIXPACKET_UDS_NODE_TIMEOUT_NSEC(cunixpacket_uds_node))
    {
        const char                 *k;

        k = (const char *)CUNIXPACKET_CNGX_VAR_UDS_TIMEOUT_NSEC;
        if(EC_FALSE == cngx_get_var_uint32_t(r, k,
                                &CUNIXPACKET_UDS_NODE_TIMEOUT_NSEC(cunixpacket_uds_node),
                                CUNIXPACKET_UDS_TIMEOUT_NSEC_DEFAULT))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                        "uds node (%s, %d) get var '%s' failed\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                        k);
            cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUNIXPACKET_0015);
            return (EC_FALSE);
        }

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                    "uds node (%s, %d) => var '%s' = %d\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                    k,
                                                    CUNIXPACKET_UDS_NODE_TIMEOUT_NSEC(cunixpacket_uds_node));
    }

    if(0 == CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node))
    {
        const char                 *k;

        k = (const char *)CUNIXPACKET_CNGX_VAR_UDS_EXPIRED_NSEC;
        if(EC_FALSE == cngx_get_var_uint32_t(r, k,
                                &CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node),
                                CUNIXPACKET_UDS_EXPIRED_NSEC_DEFAULT))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                        "uds node (%s, %d) get var '%s' failed\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                        k);
            cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUNIXPACKET_0016);
            return (EC_FALSE);
        }

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                    "uds node (%s, %d) => var '%s' = %d\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                    k,
                                                    CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node));
    }

    if(0 == CUNIXPACKET_UDS_NODE_EXPIRED_TS(cunixpacket_uds_node))
    {
        CUNIXPACKET_UDS_NODE_EXPIRED_TS(cunixpacket_uds_node) = c_get_cur_time_nsec()
                                                              + CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node);

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                    "uds node (%s, %d) => set expired in %u seconds\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_EXPIRED_NSEC(cunixpacket_uds_node));
    }

    if(0 == CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node))
    {
        const char                 *k;

        k = (const char *)CUNIXPACKET_CNGX_VAR_UDS_CONNECT_NSEC;
        if(EC_FALSE == cngx_get_var_uint32_t(r, k,
                                &CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node),
                                CUNIXPACKET_UDS_CONNECT_NSEC_DEFAULT))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                        "uds node (%s, %d) get var '%s' failed\n",
                                                        (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                        CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                        k);
            cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUNIXPACKET_0017);
            return (EC_FALSE);
        }

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                    "uds node (%s, %d) => var '%s' = %d\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node),
                                                    k,
                                                    CUNIXPACKET_UDS_NODE_CONNECT_NSEC(cunixpacket_uds_node));
    }

    if(0 == CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node))
    {
        /*connect immediately*/
        CUNIXPACKET_UDS_NODE_CONNECT_TS(cunixpacket_uds_node) = c_get_cur_time_nsec();

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                    "uds node (%s, %d) => set to connect\n",
                                                    (char *)CUNIXPACKET_UDS_NODE_PATH_STR(cunixpacket_uds_node),
                                                    CUNIXPACKET_UDS_NODE_SOCKET(cunixpacket_uds_node));
    }

    if(0 == CUNIXPACKET_UDS_NODE_MAX_PACKETS(cunixpacket_uds_node))
    {
        const char                 *k;

        k = (const char *)CUNIXPACKET_CNGX_VAR_UDS_MAX_PACKETS;
        if(EC_FALSE == cngx_get_var_uint32_t(r, k,
                                &CUNIXPACKET_UDS_NODE_MAX_PACKETS(cunixpacket_uds_node),
                                CUNIXPACKET_UDS_MAX_PACKETS_DEFAULT))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                        "get var '%s' failed\n",
                                                        k);
            cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUNIXPACKET_0018);
            return (EC_FALSE);
        }

        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                    "var '%s' = %d\n",
                                                    k,
                                                    CUNIXPACKET_UDS_NODE_MAX_PACKETS(cunixpacket_uds_node));
    }

    /*cache data*/

    ngx_req_body = cbytes_new(0);
    if(NULL_PTR == ngx_req_body)
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                    "new ngx req body failed\n");

        cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUNIXPACKET_0019);
        return (EC_FALSE);
    }

    if(EC_FALSE == cngx_read_req_body(r, ngx_req_body, &CUNIXPACKET_MD_NGX_RC(cunixpacket_md)))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_send_handler: "
                                                    "read req body failed\n");

        cbytes_free(ngx_req_body);
        cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_INTERNAL_SERVER_ERROR, LOC_CUNIXPACKET_0020);
        return (EC_FALSE);
    }

    if(EC_TRUE == cbytes_is_empty(ngx_req_body))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "warn:cunixpacket_send_handler: "
                                                    "ngx req body is empty => give up\n");

        cbytes_free(ngx_req_body);
        cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_OK, LOC_CUNIXPACKET_0021);
        return (EC_TRUE);
    }

    clist_push_back(CUNIXPACKET_UDS_NODE_PACKET_LIST(cunixpacket_uds_node), (void *)ngx_req_body);

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_send_handler: "
                                                "cache data %ld bytes\n",
                                                CBYTES_LEN(ngx_req_body));

    cunixpacket_set_ngx_rc(cunixpacket_md_id, NGX_HTTP_OK, LOC_CUNIXPACKET_0022);

    return (EC_TRUE);
}

/**
*
* content handler
*
**/
EC_BOOL cunixpacket_content_handler(const UINT32 cunixpacket_md_id)
{
    CUNIXPACKET_MD        *cunixpacket_md;

    ngx_http_request_t          *r;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_MD_ID_CHECK_INVALID(cunixpacket_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_content_handler: cunixpacket module #0x%lx not started.\n",
                cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_md = CUNIXPACKET_MD_GET(cunixpacket_md_id);

    r = CUNIXPACKET_MD_NGX_HTTP_REQ(cunixpacket_md);

    dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_content_handler: enter\n");

    /*priority: if set debug on when module starting, ignore switch in cngx http req header*/
    if(BIT_FALSE == CUNIXPACKET_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cunixpacket_md)
    && EC_TRUE == cngx_is_debug_switch_on(r))
    {
        CUNIXPACKET_MD_CNGX_DEBUG_SWITCH_ON_FLAG(cunixpacket_md) = BIT_TRUE;
    }

    /*cache data*/
    if(EC_FALSE == cunixpacket_send_handler(cunixpacket_md_id))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_content_handler: "
                                                    "cache data failed\n");

        cunixpacket_content_send_response(cunixpacket_md_id);
        return (EC_FALSE);
    }

    cunixpacket_content_send_response(cunixpacket_md_id);
    return (EC_TRUE);
}

EC_BOOL cunixpacket_content_send_response(const UINT32 cunixpacket_md_id)
{
    CUNIXPACKET_MD       *cunixpacket_md;

    ngx_http_request_t         *r;
    uint32_t                    flags;

#if ( SWITCH_ON == CUNIXPACKET_DEBUG_SWITCH )
    if ( CUNIXPACKET_MD_ID_CHECK_INVALID(cunixpacket_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cunixpacket_content_send_response: cunixpacket module #0x%lx not started.\n",
                cunixpacket_md_id);
        dbg_exit(MD_CUNIXPACKET, cunixpacket_md_id);
    }
#endif/*CUNIXPACKET_DEBUG_SWITCH*/

    cunixpacket_md = CUNIXPACKET_MD_GET(cunixpacket_md_id);

    r = CUNIXPACKET_MD_NGX_HTTP_REQ(cunixpacket_md);

    /*send header*/
    if(EC_TRUE == cngx_need_send_header(r))
    {
        cngx_disable_write_delayed(r);

        cngx_set_header_only(r);/*xxx*/

        cngx_set_header_out_status(r, CUNIXPACKET_MD_NGX_RC(cunixpacket_md));
        cngx_set_header_out_content_length(r, 0);/*no body*/

        if(EC_FALSE == cngx_send_header(r, &(CUNIXPACKET_MD_NGX_RC(cunixpacket_md))))
        {
            dbg_log(SEC_0009_CUNIXPACKET, 0)(LOGSTDOUT, "error:cunixpacket_content_send_response: "
                                                        "send header failed\n");

            return (EC_FALSE);
        }
        dbg_log(SEC_0009_CUNIXPACKET, 9)(LOGSTDOUT, "[DEBUG] cunixpacket_content_send_response: "
                                                    "send header done\n");
    }

    flags =   CNGX_SEND_BODY_FLUSH_FLAG
            | CNGX_SEND_BODY_RECYCLED_FLAG
            | CNGX_SEND_BODY_NO_MORE_FLAG;/*xxx*/

    if(EC_FALSE == cngx_send_body(r, NULL_PTR, (uint32_t)0, flags, &(CUNIXPACKET_MD_NGX_RC(cunixpacket_md))))
    {
        dbg_log(SEC_0009_CUNIXPACKET, 1)(LOGSTDOUT, "error:cunixpacket_content_send_response: "
                                                    "send body failed\n");

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


