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

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cvector.h"
#include "chashalgo.h"
#include "cbc.h"

#include "cmisc.h"

#include "task.h"

#include "cmpie.h"

#include "crb.h"
#include "chttp.h"
#include "chttps.h"
#include "cdetectn.h"
#include "cdetect.h"
#include "cdetecthttp.h"

#include "findex.inc"

#define CDETECT_MD_CAPACITY()                  (cbc_md_capacity(MD_CDETECT))

#define CDETECT_MD_GET(cdetect_md_id)     ((CDETECT_MD *)cbc_md_get(MD_CDETECT, (cdetect_md_id)))

#define CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id)  \
    ((CMPI_ANY_MODI != (cdetect_md_id)) && ((NULL_PTR == CDETECT_MD_GET(cdetect_md_id)) || (0 == (CDETECT_MD_GET(cdetect_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CDETECT Module
*
**/
void cdetect_print_module_status(const UINT32 cdetect_md_id, LOG *log)
{
    CDETECT_MD *cdetect_md;
    UINT32 this_cdetect_md_id;

    for( this_cdetect_md_id = 0; this_cdetect_md_id < CDETECT_MD_CAPACITY(); this_cdetect_md_id ++ )
    {
        cdetect_md = CDETECT_MD_GET(this_cdetect_md_id);

        if ( NULL_PTR != cdetect_md && 0 < cdetect_md->usedcounter )
        {
            sys_log(log,"CDETECT Module # %ld : %ld refered\n",
                    this_cdetect_md_id,
                    cdetect_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CDETECT module
*
*
**/
UINT32 cdetect_free_module_static_mem(const UINT32 cdetect_md_id)
{
    //CDETECT_MD  *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_free_module_static_mem: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    //cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    free_module_static_mem(MD_CDETECT, cdetect_md_id);

    return 0;
}

/**
*
* start CDETECT module
*
**/
UINT32 cdetect_start(const CSTRING *cdetect_conf_file)
{
    CDETECT_MD *cdetect_md;
    UINT32      cdetect_md_id;
    UINT32      cdetectn_modi_active;
    UINT32      cdetectn_modi_standby;

    cbc_md_reg(MD_CDETECT , 1);

    cdetect_md_id = cbc_md_new(MD_CDETECT, sizeof(CDETECT_MD));
    if(CMPI_ERROR_MODI == cdetect_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CDETECT module */
    cdetect_md = (CDETECT_MD *)cbc_md_get(MD_CDETECT, cdetect_md_id);
    cdetect_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md)  = 0;
    CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md)  = CMPI_ERROR_MODI;
    CDETECT_MD_CDETECTN_MODI_STANDBY(cdetect_md) = CMPI_ERROR_MODI;

    /*start active cdetectn*/
    cdetectn_modi_active = cdetectn_start();
    if(CMPI_ERROR_MODI == cdetectn_modi_active)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start: "
                                                "start active CDETECTN failed\n");

        cbc_md_free(MD_CDETECT, cdetect_md_id);
        return (CMPI_ERROR_MODI);
    }
    if(EC_FALSE == cdetectn_load_conf(cdetectn_modi_active, cdetect_conf_file))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start: "
                                                "cdetctn load '%s' failed\n",
                                                (char *)cstring_get_str(cdetect_conf_file));

        cdetectn_end(cdetectn_modi_active);
        cbc_md_free(MD_CDETECT, cdetect_md_id);
        return (CMPI_ERROR_MODI);
    }
    CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md) = cdetectn_modi_active;

    /*start standby cdetectn*/
    cdetectn_modi_standby = cdetectn_start();
    if(CMPI_ERROR_MODI == cdetectn_modi_standby)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start: "
                                                "start standby CDETECTN failed\n");

        cdetectn_end(cdetectn_modi_active);
        cbc_md_free(MD_CDETECT, cdetect_md_id);
        return (CMPI_ERROR_MODI);
    }
    CDETECT_MD_CDETECTN_MODI_STANDBY(cdetect_md) = cdetectn_modi_standby;

    CDETECT_MD_REALOD_STATUS(cdetect_md) = CDETECT_RELOAD_STATUS_OK;

    cstring_init(CDETECT_MD_CONF_FILE(cdetect_md), cstring_get_str(cdetect_conf_file));

    cdetect_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cdetect_end, cdetect_md_id);

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "[DEBUG] cdetect_start: "
                                            "start CDETECT module #%ld\n",
                                            cdetect_md_id);

    if(SWITCH_ON == CDETECTHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CDETECT module is allowed to launch tdns http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == cdetect_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start: init cdetecthttp defer request queue failed\n");
                cdetect_end(cdetect_md_id);
                return (CMPI_ERROR_MODI);
            }

            cdetecthttp_log_start();
            task_brd_default_bind_http_srv_modi(cdetect_md_id);
            chttp_rest_list_push((const char *)CDETECTHTTP_REST_API_NAME, cdetecthttp_commit_request);

            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "[DEBUG] cdetect_start: "
                                                    "start detect http server\n");
        }
        else
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "[DEBUG] cdetect_start: "
                                                    "NOT start detect http server\n");
        }
    }

    return ( cdetect_md_id );
}

/**
*
* end CDETECT module
*
**/
void cdetect_end(const UINT32 cdetect_md_id)
{
    CDETECT_MD *cdetect_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cdetect_end, cdetect_md_id);

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);
    if(NULL_PTR == cdetect_md)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_end: "
                                                "cdetect_md_id = %ld not exist.\n",
                                                cdetect_md_id);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cdetect_md->usedcounter )
    {
        cdetect_md->usedcounter --;
        return ;
    }

    if ( 0 == cdetect_md->usedcounter )
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_end: "
                                                "cdetect_md_id = %ld is not started.\n",
                                                cdetect_md_id);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }

    if(CMPI_ERROR_MODI != CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md))
    {
        cdetectn_end(CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md));
        CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md) = CMPI_ERROR_MODI;
    }

    if(CMPI_ERROR_MODI != CDETECT_MD_CDETECTN_MODI_STANDBY(cdetect_md))
    {
        cdetectn_end(CDETECT_MD_CDETECTN_MODI_STANDBY(cdetect_md));
        CDETECT_MD_CDETECTN_MODI_STANDBY(cdetect_md) = CMPI_ERROR_MODI;
    }

    cstring_clean(CDETECT_MD_CONF_FILE(cdetect_md));

    CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md) = 0;

    /* free module : */
    //cdetect_free_module_static_mem(cdetect_md_id);

    cdetect_md->usedcounter = 0;

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "cdetect_end: stop CDETECT module #%ld\n", cdetect_md_id);
    cbc_md_free(MD_CDETECT, cdetect_md_id);

    return ;
}

/**
*
*  print orig nodes
*
*
**/
EC_BOOL cdetect_show_orig_nodes(const UINT32 cdetect_md_id, LOG *log)
{
    CDETECT_MD *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_show_orig_nodes: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    return cdetectn_show_orig_nodes(CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md), log);
}

/**
*
*  print single orig node
*
*
**/
EC_BOOL cdetect_show_orig_node(const UINT32 cdetect_md_id, const CSTRING *domain, LOG *log)
{
    CDETECT_MD *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_show_orig_node: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    return cdetectn_show_orig_node(CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md), domain, log);
}

/**
*
*  dns resolve
*
**/
EC_BOOL cdetect_dns_resolve(const UINT32 cdetect_md_id, const CSTRING *domain, UINT32 *ipaddr)
{
    CDETECT_MD          *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_dns_resolve: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    if(EC_FALSE == cdetectn_dns_resolve(CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md), domain, ipaddr))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_dns_resolve: "
                                                "resolve domain '%s' failed\n",
                                                (char *)cstring_get_str(domain));
        return (EC_FALSE);
    }

    dbg_log(SEC_0043_CDETECT, 5)(LOGSTDOUT, "[DEBUG] cdetect_dns_resolve: "
                                            "domain '%s' => ip '%s'\n",
                                            (char *)cstring_get_str(domain),
                                            c_word_to_ipv4(*ipaddr));
    return (EC_TRUE);
}

/**
*
*  switch active and standby cdetectn
*
**/
EC_BOOL cdetect_switch(const UINT32 cdetect_md_id)
{
    CDETECT_MD          *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_switch: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md) ^= 1;

    dbg_log(SEC_0043_CDETECT, 5)(LOGSTDOUT, "[DEBUG] cdetect_switch: "
                                            "switch to %ld\n",
                                            CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md));

    return (EC_TRUE);
}

/**
*
*  reload status string
*
**/
const char *cdetect_reload_status_str(const UINT32 cdetect_md_id)
{
    CDETECT_MD          *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_reload_status_str: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    switch(CDETECT_MD_REALOD_STATUS(cdetect_md))
    {
        case CDETECT_RELOAD_STATUS_OK:
            return (const char *)"OK";

        case CDETECT_RELOAD_STATUS_ONGOING:
            return (const char *)"ONGOING";

        case CDETECT_RELOAD_STATUS_COMPLETED:
            return (const char *)"COMPLETED";

        default:
            break;
    }

    return (const char *)"UNKNOWN";
}

/**
*
*  reload detect conf and switch detect
*
**/
EC_BOOL cdetect_reload(const UINT32 cdetect_md_id)
{
    CDETECT_MD          *cdetect_md;

    UINT32               cdetectn_modi_standby;

    TASK_BRD            *task_brd;
    MOD_NODE             recv_mod_node;
    EC_BOOL              ret;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_reload: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    if(CDETECT_RELOAD_STATUS_OK != CDETECT_MD_REALOD_STATUS(cdetect_md))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_reload: "
                                                "invalid reload status %s\n",
                                                cdetect_reload_status_str(cdetect_md_id));
        return (EC_FALSE);
    }

    /*initialize reload status*/
    CDETECT_MD_REALOD_STATUS(cdetect_md) = CDETECT_RELOAD_STATUS_ONGOING;
    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_reload: "
                                            "set reload status from OK to ONGOING\n");

    cdetectn_modi_standby = CDETECT_MD_CDETECTN_MODI_STANDBY(cdetect_md);

    task_brd = task_brd_default_get();

    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&recv_mod_node) = cdetectn_modi_standby;

    ret = EC_FALSE;
    task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
             &recv_mod_node,
             &ret,
             FI_cdetectn_load_conf, CMPI_ERROR_MODI, CDETECT_MD_CONF_FILE(cdetect_md));

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_reload: "
                                                "cdetectn %ld load conf '%s' failed\n",
                                                cdetectn_modi_standby,
                                                (char *)cstring_get_str(CDETECT_MD_CONF_FILE(cdetect_md)));
        CDETECT_MD_REALOD_STATUS(cdetect_md) = CDETECT_RELOAD_STATUS_OK;
        return (EC_FALSE);
    }
#if 0
    if(EC_FALSE == cdetectn_load_conf(cdetectn_modi_standby, CDETECT_MD_CONF_FILE(cdetect_md)))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_reload: "
                                                "load conf '%s' failed\n",
                                                (char *)cstring_get_str(CDETECT_MD_CONF_FILE(cdetect_md)));
        CDETECT_MD_REALOD_STATUS(cdetect_md) = CDETECT_RELOAD_STATUS_OK;
        return (EC_FALSE);
    }
#endif
    if(EC_FALSE == cdetect_switch(cdetect_md_id))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_reload: "
                                                "switch cdetectn failed\n");
        CDETECT_MD_REALOD_STATUS(cdetect_md) = CDETECT_RELOAD_STATUS_OK;
        return (EC_FALSE);
    }

    /*update reload status*/
    CDETECT_MD_REALOD_STATUS(cdetect_md) = CDETECT_RELOAD_STATUS_COMPLETED;

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_reload: "
                                            "set reload status from ONGOING to COMPLETED\n");

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_reload: "
                                            "reload conf '%s' done\n",
                                            (char *)cstring_get_str(CDETECT_MD_CONF_FILE(cdetect_md)));

    return (EC_TRUE);
}

/**
*
*  cdetectn choice
*
**/
EC_BOOL cdetect_choice(const UINT32 cdetect_md_id, UINT32 *choice)
{
    CDETECT_MD          *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_choice: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    if(NULL_PTR != choice)
    {
        (*choice) = (CDETECT_MD_CDETECTN_MODI_CHOICE(cdetect_md) & 1);
    }

    return (EC_TRUE);
}

/**
*
*  start to detect domain
*
**/
EC_BOOL cdetect_start_domain(const UINT32 cdetect_md_id, const CSTRING *domain)
{
    CDETECT_MD          *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_start_domain: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    if(EC_FALSE == cdetectn_start_domain(CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md), domain))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start_domain: "
                                                "start domain '%s' failed\n",
                                                (char *)cstring_get_str(domain));
        return (EC_FALSE);
    }

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_start_domain: "
                                            "start domain '%s' done\n",
                                            (char *)cstring_get_str(domain));
    return (EC_TRUE);
}

/**
*
*  stop to detect domain
*
**/
EC_BOOL cdetect_stop_domain(const UINT32 cdetect_md_id, const CSTRING *domain)
{
    CDETECT_MD          *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_stop_domain: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    if(EC_FALSE == cdetectn_stop_domain(CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md), domain))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_stop_domain: "
                                                "stop domain '%s' failed\n",
                                                (char *)cstring_get_str(domain));
        return (EC_FALSE);
    }

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_stop_domain: "
                                            "stop domain '%s' done\n",
                                            (char *)cstring_get_str(domain));

    return (EC_TRUE);
}

/**
*
*  process entry
*
**/
EC_BOOL cdetect_process(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num)
{
    CDETECT_MD          *cdetect_md;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_process: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    if(EC_FALSE == cdetectn_process(CDETECT_MD_CDETECTN_MODI_ACTIVE(cdetect_md), detect_task_max_num))
    {
        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "error:cdetect_process: "
                                                "failed\n");
        return (EC_FALSE);
    }

    rlog(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_process: "
                                         "done\n");

    return (EC_TRUE);
}

/**
*
*  process loop
*
**/
EC_BOOL cdetect_process_loop(const UINT32 cdetect_md_id, const UINT32 detect_task_max_num)
{
    CDETECT_MD          *cdetect_md;

    TASK_BRD            *task_brd;
    MOD_NODE             recv_mod_node;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_process_loop: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    if(CDETECT_RELOAD_STATUS_COMPLETED == CDETECT_MD_REALOD_STATUS(cdetect_md))
    {
        /*update reload status*/

        CDETECT_MD_REALOD_STATUS(cdetect_md) = CDETECT_RELOAD_STATUS_OK;

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_process_loop: "
                                                "update reload status to OK\n");
    }

    cdetect_process(cdetect_md_id, detect_task_max_num);

    task_brd = task_brd_default_get();

    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&recv_mod_node) = cdetect_md_id;

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_cdetect_process_loop, CMPI_ERROR_MODI, detect_task_max_num);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


