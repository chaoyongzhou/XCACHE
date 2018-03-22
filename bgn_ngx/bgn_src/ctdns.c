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

#include "carray.h"
#include "cvector.h"

#include "cbc.h"
#include "ctimer.h"
#include "cbtimer.h"
#include "cmisc.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "cload.h"
#include "coroutine.h"
#include "cmd5.h"
#include "cbase64code.h"

#include "crb.h"
#include "chttp.h"
#include "chttps.h"
#include "ctdns.h"
#include "ctdnshttp.h"
//#include "ctdnshttps.h"
#include "cp2phttp.h"

#include "cping.h"

#include "findex.inc"

#define CTDNS_MD_CAPACITY()                  (cbc_md_capacity(MD_CTDNS))

#define CTDNS_MD_GET(ctdns_md_id)     ((CTDNS_MD *)cbc_md_get(MD_CTDNS, (ctdns_md_id)))

#define CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id)  \
    ((CMPI_ANY_MODI != (ctdns_md_id)) && ((NULL_PTR == CTDNS_MD_GET(ctdns_md_id)) || (0 == (CTDNS_MD_GET(ctdns_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CTDNS Module
*
**/
void ctdns_print_module_status(const UINT32 ctdns_md_id, LOG *log)
{
    CTDNS_MD *ctdns_md;
    UINT32 this_ctdns_md_id;

    for( this_ctdns_md_id = 0; this_ctdns_md_id < CTDNS_MD_CAPACITY(); this_ctdns_md_id ++ )
    {
        ctdns_md = CTDNS_MD_GET(this_ctdns_md_id);

        if ( NULL_PTR != ctdns_md && 0 < ctdns_md->usedcounter )
        {
            sys_log(log,"CTDNS Module # %ld : %ld refered\n",
                    this_ctdns_md_id,
                    ctdns_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CTDNS module
*
*
**/
UINT32 ctdns_free_module_static_mem(const UINT32 ctdns_md_id)
{
    CTDNS_MD  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_free_module_static_mem: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    free_module_static_mem(MD_CTDNS, ctdns_md_id);

    return 0;
}

/**
*
* start CTDNS module
*
**/
UINT32 ctdns_start(const CSTRING *ctdns_root_dir)
{
    CTDNS_MD *ctdns_md;
    UINT32    ctdns_md_id;

    //TASK_BRD *task_brd;
    EC_BOOL   ret;

    CSTRING *ctdns_dir;
    CSTRING *ctdnsnp_root_dir;
    
    //task_brd = task_brd_default_get();
 
    ctdns_md_id = cbc_md_new(MD_CTDNS, sizeof(CTDNS_MD));
    if(CMPI_ERROR_MODI == ctdns_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    ctdns_dir = cstring_make("%s/tdns%02ld", (char *)cstring_get_str(ctdns_root_dir), ctdns_md_id);
    if(NULL_PTR == ctdns_dir)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: new ctdns_dir failed\n");

        cbc_md_free(MD_CTDNS, ctdns_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == c_dir_exist((char *)cstring_get_str(ctdns_dir)))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: TDNS %ld dir %s not exist\n",
                           ctdns_md_id, (char *)cstring_get_str(ctdns_dir));

        cbc_md_free(MD_CTDNS, ctdns_md_id);
        cstring_free(ctdns_dir);
        return (CMPI_ERROR_MODI);
    }
    cstring_free(ctdns_dir);

    ctdnsnp_root_dir = cstring_make("%s/tdns%02ld", (char *)cstring_get_str(ctdns_root_dir), ctdns_md_id);
    if(NULL_PTR == ctdnsnp_root_dir)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: new ctdnsnp_root_dir failed\n");

        cbc_md_free(MD_CTDNS, ctdns_md_id);
        return (CMPI_ERROR_MODI);
    }
  
    /* initialize new one CTDNS module */
    ctdns_md = (CTDNS_MD *)cbc_md_get(MD_CTDNS, ctdns_md_id);
    ctdns_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem(); 

    CTDNS_MD_NPP(ctdns_md) = NULL_PTR;

    ret = EC_TRUE;
    if(EC_TRUE  == ret && NULL_PTR != ctdnsnp_root_dir
    && EC_FALSE == cstring_is_empty(ctdnsnp_root_dir)
    && EC_TRUE  == ctdnsnp_mgr_exist(ctdnsnp_root_dir))
    {
        CTDNS_MD_NPP(ctdns_md) = ctdnsnp_mgr_open(ctdnsnp_root_dir);
        if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: open npp from root dir %s failed\n",
                               (char *)cstring_get_str(ctdnsnp_root_dir));
            ret = EC_FALSE;
        }
    }

    /*fix: to reduce the np loading time elapsed*/
    if(EC_TRUE == ret && NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        if(EC_FALSE == ctdnsnp_mgr_open_np_all(CTDNS_MD_NPP(ctdns_md)))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: open all np from root dir %s failed\n",
                               (char *)cstring_get_str(ctdnsnp_root_dir));

            ctdnsnp_mgr_close_np_all(CTDNS_MD_NPP(ctdns_md));/*roll back*/
         
            ret = EC_FALSE;
        }  
    }

    cstring_free(ctdnsnp_root_dir); 

    if(EC_TRUE == ret && NULL_PTR != ctdns_root_dir)
    {
        CTDNS_MD_SVP(ctdns_md) = ctdnssv_mgr_open(ctdns_root_dir);
        if(NULL_PTR == CTDNS_MD_SVP(ctdns_md))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: open svp from root dir %s failed\n",
                               (char *)cstring_get_str(ctdns_root_dir));
            ret = EC_FALSE;
        }    
    }
 
    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
        {
            ctdnsnp_mgr_close(CTDNS_MD_NPP(ctdns_md));
            CTDNS_MD_NPP(ctdns_md) = NULL_PTR;
        }

        if(NULL_PTR != CTDNS_MD_SVP(ctdns_md))
        {
            ctdnssv_mgr_close(CTDNS_MD_SVP(ctdns_md));
            CTDNS_MD_SVP(ctdns_md) = NULL_PTR;
        }
        
        cbc_md_free(MD_CTDNS, ctdns_md_id);

        return (CMPI_ERROR_MODI);
    }

    ctdns_susv_init(CTDNS_MD_SUSV(ctdns_md));

    ctdns_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)ctdns_end, ctdns_md_id);

    dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "[DEBUG] ctdns_start: start CTDNS module #%ld\n", ctdns_md_id);

    if(SWITCH_ON == CTDNSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CTDNS module is allowed to launch tdns http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == ctdns_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: init ctdnshttp defer request queue failed\n");
                ctdns_end(ctdns_md_id);
                return (CMPI_ERROR_MODI);
            }

            ctdnshttp_log_start();
            task_brd_default_bind_http_srv_modi(ctdns_md_id);
            chttp_rest_list_push((const char *)CTDNSHTTP_REST_API_NAME, ctdnshttp_commit_request);
        }

        /*https server*/
#if 0
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled() && 0 == ctdns_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: init ctdnshttp defer request queue failed\n");
                ctdns_end(ctdns_md_id);
                return (CMPI_ERROR_MODI);
            }
            ctdnshttps_log_start();
            task_brd_default_bind_https_srv_modi(ctdns_md_id);
            chttps_rest_list_push((const char *)CTDNSHTTPS_REST_API_NAME, ctdnshttps_commit_request);
        }
#endif     

    } 

#if 1
    if(SWITCH_ON == CP2PHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: trick! start p2p http server with same port as that of tdns http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == ctdns_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_start: init cp2phttp defer request queue failed\n");
                ctdns_end(ctdns_md_id);
                return (CMPI_ERROR_MODI);
            }

            //cp2phttp_log_start();
            /*task_brd_default_bind_http_srv_modi(CMPI_ERROR_MODI);*//*never bind due to override previouse ctdns_md_id*/
            chttp_rest_list_push((const char *)CP2PHTTP_REST_API_NAME, cp2phttp_commit_request);

            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "[DEBUG] ctdns_start: "
                                                  "start p2p http server\n");
        }
        else
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "[DEBUG] ctdns_start: "
                                                  "NOT start p2p http server\n");        
        }
    } 
#endif

    /*launch detection*/
    //ctdns_detect_loop(ctdns_md_id);
    if(1)
    {
        CBTIMER_NODE *cbtimer_node;
     
        cbtimer_node = cbtimer_add(TASK_BRD_CBTIMER_LIST(task_brd_default_get()),
                                   (UINT8 *)"CTDNS_DETECT_TASK",
                                   CBTIMER_NEVER_EXPIRE,
                                   CTDNS_NODE_DETECT_NSEC,
                                   FI_ctdns_detect_task, ctdns_md_id);    
    }
    
    return ( ctdns_md_id );
}

/**
*
* end CTDNS module
*
**/
void ctdns_end(const UINT32 ctdns_md_id)
{
    CTDNS_MD *ctdns_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)ctdns_end, ctdns_md_id);

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);
    if(NULL_PTR == ctdns_md)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_end: ctdns_md_id = %ld not exist.\n", ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
 
    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < ctdns_md->usedcounter )
    {
        ctdns_md->usedcounter --;
        return ;
    }

    if ( 0 == ctdns_md->usedcounter )
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_end: ctdns_md_id = %ld is not started.\n", ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
    
#if 0
    /*stop server*/
    if(SWITCH_ON == CTDNSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CTDNS module is allowed to launch tdns http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled() && 0 == ctdns_md_id)
        {
            task_brd_default_stop_http_srv();
            chttp_defer_request_queue_clean();
        }
    }
#endif

    /* if nobody else occupied the module,then free its resource */
    if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        ctdnsnp_mgr_close(CTDNS_MD_NPP(ctdns_md));
        CTDNS_MD_NPP(ctdns_md) = NULL_PTR;
    }

    if(NULL_PTR != CTDNS_MD_SVP(ctdns_md))
    {
        ctdnssv_mgr_close(CTDNS_MD_SVP(ctdns_md));
        CTDNS_MD_SVP(ctdns_md) = NULL_PTR;
    }    

    ctdns_susv_clean(CTDNS_MD_SUSV(ctdns_md));

    /* free module : */
    //ctdns_free_module_static_mem(ctdns_md_id);

    ctdns_md->usedcounter = 0;

    dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "ctdns_end: stop CTDNS module #%ld\n", ctdns_md_id);
    cbc_md_free(MD_CTDNS, ctdns_md_id);

    return ;
}

CSTRING *ctdns_gen_upper_service_name(const CSTRING *service_name)
{
    CSTRING *upper_service_name;

    upper_service_name = cstring_new(cstring_get_str(service_name), LOC_CTDNS_0001);
    if(NULL_PTR == upper_service_name)
    {
        return (NULL_PTR);
    }

    if(EC_FALSE == cstring_append_str(upper_service_name, (const UINT8 *)".upper"))
    {
        cstring_free(upper_service_name);
        return (NULL_PTR);
    }

    return (upper_service_name);
}

CSTRING *ctdns_gen_edge_service_name(const CSTRING *service_name)
{
    CSTRING *edge_service_name;

    edge_service_name = cstring_new(cstring_get_str(service_name), LOC_CTDNS_0002);
    if(NULL_PTR == edge_service_name)
    {
        return (NULL_PTR);
    }

    if(EC_FALSE == cstring_append_str(edge_service_name, (const UINT8 *)".edges"))
    {
        cstring_free(edge_service_name);
        return (NULL_PTR);
    }

    return (edge_service_name);
}

CTDNS_SUSV_NODE *ctdns_susv_node_new()
{
    CTDNS_SUSV_NODE *ctdns_susv_node;

    alloc_static_mem(MM_CTDNS_SUSV_NODE, &ctdns_susv_node, LOC_CTDNS_0003);
    if(NULL_PTR != ctdns_susv_node)
    {
        ctdns_susv_node_init(ctdns_susv_node);
    }
    return (ctdns_susv_node);
}

EC_BOOL ctdns_susv_node_init(CTDNS_SUSV_NODE *ctdns_susv_node)
{
    cstring_init(CTDNS_SUSV_NODE_SERVICE(ctdns_susv_node), NULL_PTR);
    
    CTDNS_SUSV_NODE_TCID(ctdns_susv_node)             = CMPI_ERROR_TCID;
    CTDNS_SUSV_NODE_FAILS(ctdns_susv_node)            = 0;

    return (EC_TRUE);
}

EC_BOOL ctdns_susv_node_clean(CTDNS_SUSV_NODE *ctdns_susv_node)
{
    cstring_clean(CTDNS_SUSV_NODE_SERVICE(ctdns_susv_node));
    
    CTDNS_SUSV_NODE_TCID(ctdns_susv_node)             = CMPI_ERROR_TCID;
    CTDNS_SUSV_NODE_FAILS(ctdns_susv_node)            = 0;
    
    return (EC_TRUE);
}

EC_BOOL ctdns_susv_node_free(CTDNS_SUSV_NODE *ctdns_susv_node)
{
    if(NULL_PTR != ctdns_susv_node)
    {
        ctdns_susv_node_clean(ctdns_susv_node);
        free_static_mem(MM_CTDNS_SUSV_NODE, ctdns_susv_node, LOC_CTDNS_0004);
    }
    return (EC_TRUE);
}

void ctdns_susv_node_print(LOG *log, const CTDNS_SUSV_NODE *ctdns_susv_node)
{
    sys_print(log, "ctdns_susv_node %p: service %s, tcid %s, fails %ld\n",
                    ctdns_susv_node,
                    (char *)cstring_get_str(CTDNS_SUSV_NODE_SERVICE(ctdns_susv_node)),
                    c_word_to_ipv4(CTDNS_SUSV_NODE_TCID(ctdns_susv_node)),
                    CTDNS_SUSV_NODE_FAILS(ctdns_susv_node)
                    );
   
    return;
}

EC_BOOL ctdns_susv_node_cmp(const CTDNS_SUSV_NODE *ctdns_susv_node_1st, const CTDNS_SUSV_NODE *ctdns_susv_node_2nd)
{
    if(CTDNS_SUSV_NODE_TCID(ctdns_susv_node_1st) != CTDNS_SUSV_NODE_TCID(ctdns_susv_node_2nd))
    {
        return (EC_FALSE);
    }

    return cstring_is_equal(CTDNS_SUSV_NODE_SERVICE(ctdns_susv_node_1st), CTDNS_SUSV_NODE_SERVICE(ctdns_susv_node_2nd));
}

EC_BOOL ctdns_susv_init(CTDNS_SUSV *ctdns_susv)
{
    clist_init(CTDNS_SUSV_MGR(ctdns_susv), MM_CTDNS_SUSV_NODE, LOC_CTDNS_0005);
    return (EC_TRUE);
}

EC_BOOL ctdns_susv_clean(CTDNS_SUSV *ctdns_susv)
{
    clist_clean(CTDNS_SUSV_MGR(ctdns_susv), (CLIST_DATA_DATA_CLEANER)ctdns_susv_node_free);
    
    return (EC_TRUE);
}

void ctdns_susv_print(LOG *log, const CTDNS_SUSV *ctdns_susv)
{
    clist_print(log, CTDNS_SUSV_MGR(ctdns_susv), (CLIST_DATA_DATA_PRINT)ctdns_susv_node_print);
   
    return;
}

CTDNS_SUSV_NODE *ctdns_susv_search(CTDNS_SUSV *ctdns_susv, const CSTRING *service, const UINT32 tcid)
{
    CTDNS_SUSV_NODE     ctdns_susv_node_t;

    /*mount only*/
    cstring_set_str(CTDNS_SUSV_NODE_SERVICE(&ctdns_susv_node_t), cstring_get_str(service));
    CTDNS_SUSV_NODE_TCID(&ctdns_susv_node_t) = tcid;
    
    return clist_search_data_front(CTDNS_SUSV_MGR(ctdns_susv), (void *)&ctdns_susv_node_t, 
                                   (CLIST_DATA_DATA_CMP)ctdns_susv_node_cmp);
}

CTDNS_SUSV_NODE *ctdns_susv_delete(CTDNS_SUSV *ctdns_susv, const CSTRING *service, const UINT32 tcid)
{
    CTDNS_SUSV_NODE     ctdns_susv_node_t;

    /*mount only*/
    cstring_set_str(CTDNS_SUSV_NODE_SERVICE(&ctdns_susv_node_t), cstring_get_str(service));
    CTDNS_SUSV_NODE_TCID(&ctdns_susv_node_t) = tcid;

    return  clist_del(CTDNS_SUSV_MGR(ctdns_susv), (void *)&ctdns_susv_node_t, 
                       (CLIST_DATA_DATA_CMP)ctdns_susv_node_cmp);
}

EC_BOOL ctdns_susv_add(CTDNS_SUSV *ctdns_susv, const CSTRING *service, const UINT32 tcid, const UINT32 fails)
{
    CTDNS_SUSV_NODE *ctdns_susv_node;

    ctdns_susv_node = ctdns_susv_node_new();
    if(NULL_PTR == ctdns_susv_node)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_susv_add: new ctdns_susv_node failed\n");
        return (EC_FALSE); 
    }

    cstring_clone(service, CTDNS_SUSV_NODE_SERVICE(ctdns_susv_node));
    CTDNS_SUSV_NODE_TCID(ctdns_susv_node)  = tcid;
    CTDNS_SUSV_NODE_FAILS(ctdns_susv_node) = fails;

    if(NULL_PTR == clist_push_back(CTDNS_SUSV_MGR(ctdns_susv), (void *)ctdns_susv_node))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_susv_add: add ('%s', '%s', %ld) failed\n",
                                              (char *)cstring_get_str(service),
                                              c_word_to_ipv4(tcid), 
                                              fails);
        ctdns_susv_node_free(ctdns_susv_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  set suspicious server to monitor
*
**/
EC_BOOL ctdns_set_susv(const UINT32 ctdns_md_id, const CSTRING *service, const UINT32 tcid, const UINT32 max_fails)
{
    CTDNS_MD        *ctdns_md;
    CTDNS_SUSV      *ctdns_susv;
    CTDNS_SUSV_NODE *ctdns_susv_node;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_set_susv: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md   = CTDNS_MD_GET(ctdns_md_id);
    ctdns_susv = CTDNS_MD_SUSV(ctdns_md);

    ctdns_susv_node = ctdns_susv_search(ctdns_susv, service, tcid);
    if(NULL_PTR == ctdns_susv_node)
    {
        return ctdns_susv_add(ctdns_susv, service, tcid, 1); /*new one*/
    }

    CTDNS_SUSV_NODE_FAILS(ctdns_susv_node) ++;

    if(max_fails < CTDNS_SUSV_NODE_FAILS(ctdns_susv_node))
    {
        ctdns_susv_delete(ctdns_susv, service, tcid);
        ctdns_susv_node_free(ctdns_susv_node);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  unset suspicious server from monitor
*
**/
EC_BOOL ctdns_unset_susv(const UINT32 ctdns_md_id, const CSTRING *service, const UINT32 tcid)
{
    CTDNS_MD        *ctdns_md;
    CTDNS_SUSV      *ctdns_susv;
    CTDNS_SUSV_NODE *ctdns_susv_node;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_unset_susv: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md   = CTDNS_MD_GET(ctdns_md_id);
    ctdns_susv = CTDNS_MD_SUSV(ctdns_md);

    ctdns_susv_node = ctdns_susv_delete(ctdns_susv, service, tcid);
    if(NULL_PTR != ctdns_susv_node)
    {
        ctdns_susv_node_free(ctdns_susv_node);
    }

    return (EC_TRUE);
}

/**
*
*  flush npp and svp to disk
*
**/
EC_BOOL ctdns_flush(const UINT32 ctdns_md_id)
{
    //CTDNS_MD  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_flush: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(EC_FALSE == ctdns_flush_npp(ctdns_md_id))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_flush: flush npp failed!\n");
        return (EC_FALSE); 
    }

    if(EC_FALSE == ctdns_flush_svp(ctdns_md_id))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_flush: flush svp failed!\n");
        return (EC_FALSE); 
    }    
    
    dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "[DEBUG] ctdns_flush: flush done\n");
    return (EC_TRUE);
}

/**
*
*  get name node pool of the module
*
**/
CTDNSNP_MGR *ctdns_get_npp(const UINT32 ctdns_md_id)
{
    CTDNS_MD   *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_get_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);
    return CTDNS_MD_NPP(ctdns_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL ctdns_open_npp(const UINT32 ctdns_md_id, const CSTRING *ctdnsnp_db_root_dir)
{
    CTDNS_MD   *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_open_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_open_npp: npp was open\n");
        return (EC_FALSE);
    }

    CTDNS_MD_NPP(ctdns_md) = ctdnsnp_mgr_open(ctdnsnp_db_root_dir);
    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_open_npp: open npp from root dir %s failed\n", (char *)cstring_get_str(ctdnsnp_db_root_dir));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  close name node pool
*
**/
EC_BOOL ctdns_close_npp(const UINT32 ctdns_md_id)
{
    CTDNS_MD   *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_close_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_close_npp: npp was not open\n");
        return (EC_FALSE);
    }

    ctdnsnp_mgr_close(CTDNS_MD_NPP(ctdns_md));
    CTDNS_MD_NPP(ctdns_md) = NULL_PTR;
    return (EC_TRUE);
}

/**
*
*  create name node pool
*
**/
EC_BOOL ctdns_create_npp(const UINT32 ctdns_md_id,
                             const UINT32 ctdnsnp_model,
                             const UINT32 ctdnsnp_max_num,
                             const CSTRING *ctdnsnp_db_root_dir)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_create_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR != CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: npp already exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(ctdnsnp_model))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: ctdnsnp_model %u is invalid\n", ctdnsnp_model);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(ctdnsnp_max_num))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: ctdnsnp_disk_max_num %u is invalid\n", ctdnsnp_max_num);
        return (EC_FALSE);
    }

    CTDNS_MD_NPP(ctdns_md) = ctdnsnp_mgr_create((uint8_t ) ctdnsnp_model,
                                             (uint32_t) ctdnsnp_max_num,
                                             ctdnsnp_db_root_dir);
    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_create_npp: create npp failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check existing of a tcid
*
**/
EC_BOOL ctdns_exists_tcid(const UINT32 ctdns_md_id, const UINT32 tcid)
{ 
    CTDNS_MD      *ctdns_md;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_exists_tcid: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_exists_tcid: npp was not open\n");
        return (EC_FALSE);
    }
    
    return ctdnsnp_mgr_find(CTDNS_MD_NPP(ctdns_md), tcid);
}

EC_BOOL ctdns_exists_service(const UINT32 ctdns_md_id, const CSTRING *service_name)
{
    CTDNS_MD      *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_exists_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    return ctdnssv_mgr_exists(CTDNS_MD_SVP(ctdns_md), service_name);
}

EC_BOOL ctdns_set_service(const UINT32 ctdns_md_id, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port, const CSTRING *service_name)
{
    CTDNS_MD                  *ctdns_md;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_set_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    return ctdnssv_mgr_set(CTDNS_MD_SVP(ctdns_md), tcid, ipaddr, port, service_name);
}

EC_BOOL ctdns_unset_service(const UINT32 ctdns_md_id, const UINT32 tcid, const CSTRING *service_name)
{    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_unset_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    return ctdns_delete_tcid_from_service(ctdns_md_id, service_name, tcid);
}


EC_BOOL ctdns_finger_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    CTDNS_MD                  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_finger_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    return ctdnssv_mgr_get(CTDNS_MD_SVP(ctdns_md), service_name, max_num, ctdnssv_node_mgr);
}

EC_BOOL ctdns_finger_edge_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    //CTDNS_MD                  *ctdns_md;
    CSTRING                   *edge_service_name;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_finger_edge_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    edge_service_name = ctdns_gen_edge_service_name(service_name);
    if(NULL_PTR == edge_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_finger_edge_service: "
                                              "gen edge service name failed\n");    
        return (EC_FALSE);
    }    

    if(EC_FALSE == ctdns_finger_service(ctdns_md_id, edge_service_name, max_num, ctdnssv_node_mgr))
    {
        cstring_free(edge_service_name);
        return (EC_FALSE);
    }
    
    cstring_free(edge_service_name);
    return (EC_TRUE);
}

EC_BOOL ctdns_finger_upper_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    //CTDNS_MD                  *ctdns_md;
    CSTRING                   *upper_service_name;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_finger_upper_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    upper_service_name = ctdns_gen_upper_service_name(service_name);
    if(NULL_PTR == upper_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_finger_upper_service: "
                                              "gen upper service name failed\n");    
        return (EC_FALSE);
    }    

    if(EC_FALSE == ctdns_finger_service(ctdns_md_id, upper_service_name, max_num, ctdnssv_node_mgr))
    {
        cstring_free(upper_service_name);
        return (EC_FALSE);
    }
    
    cstring_free(upper_service_name);
    return (EC_TRUE);
}

EC_BOOL ctdns_reserve_tcid_from_service(const UINT32 ctdns_md_id, const CSTRING *service_name, UINT32 *tcid, UINT32 *port)
{
    CTDNS_MD                  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_reserve_tcid_from_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    return ctdnssv_mgr_pop(CTDNS_MD_SVP(ctdns_md), service_name, tcid, NULL_PTR, port);
}

EC_BOOL ctdns_release_tcid_to_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid, const UINT32 port)
{
    //CTDNS_MD                  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_release_tcid_to_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    /*delete tcid from npp and svp*/
    ctdns_delete(ctdns_md_id, tcid);

    return ctdns_config_tcid(ctdns_md_id, service_name, tcid, port);
}

EC_BOOL ctdns_delete_tcid_from_service(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid)
{
    CTDNS_MD                  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_delete_tcid_from_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    return ctdnssv_mgr_delete_one(CTDNS_MD_SVP(ctdns_md), service_name, tcid); /*delete tcid from service*/
}

EC_BOOL ctdns_delete_tcid_from_all_service(const UINT32 ctdns_md_id, const UINT32 tcid)
{
    CTDNS_MD                  *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_delete_tcid_from_all_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    return ctdnssv_mgr_delete(CTDNS_MD_SVP(ctdns_md), tcid);
}


/**
*
*  set a tcid
*
**/
EC_BOOL ctdns_set_no_service(const UINT32 ctdns_md_id, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port)
{
    CTDNS_MD      *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_set_no_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set_no_service: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdnsnp_mgr_set(CTDNS_MD_NPP(ctdns_md), tcid, ipaddr, port))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set_no_service: set (tcid %s, ip %s, port %ld) failed\n",
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_set_no_service: set (tcid %s, ip %s, port %ld) done\n",
                     c_word_to_ipv4(tcid),
                     c_word_to_ipv4(ipaddr),
                     port);
                     
    return (EC_TRUE);
}

EC_BOOL ctdns_set(const UINT32 ctdns_md_id, const UINT32 network_level, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port, const CSTRING *service_name)
{
    CTDNS_MD      *ctdns_md;

    TASK_BRD      *task_brd;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_set: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ASSERT(NULL_PTR != service_name);
    ASSERT(EC_FALSE == cstring_is_empty(service_name));

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    task_brd = task_brd_default_get();

    if(CMPI_TOP_NETWORK == TASK_BRD_NETWORK_LEVEL(task_brd))
    {
        if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: npp was not open\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == ctdnsnp_mgr_set(CTDNS_MD_NPP(ctdns_md), tcid, ipaddr, port))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: set npp (tcid %s, ip %s, port %ld) failed\n",
                             c_word_to_ipv4(tcid),
                             c_word_to_ipv4(ipaddr),
                             port);
            return (EC_FALSE);
        }
        dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_set: set npp (tcid %s, ip %s, port %ld) done\n",
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port);      
    }

    if(network_level < TASK_BRD_NETWORK_LEVEL(task_brd))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: unreachable network: expect %ld < own %ld\n",
                        network_level, TASK_BRD_NETWORK_LEVEL(task_brd));
        return (EC_FALSE);
    }

    if(network_level > TASK_BRD_NETWORK_LEVEL(task_brd))
    {
        CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
        UINT32            max_num;

        TASK_MGR         *task_mgr;
        CLIST_DATA       *clist_data;

        max_num = (UINT32)(~(UINT32)0);/*all*/

        ctdnssv_node_mgr = ctdnssv_node_mgr_new();
        if(NULL_PTR == ctdnssv_node_mgr)
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: "
                                                  "new ctdnssv_node_mgr failed\n");    
            return (EC_FALSE);
        }     
        
        /*finger all*/
        if(EC_FALSE == ctdns_finger_service(ctdns_md_id, service_name, max_num, ctdnssv_node_mgr))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: "
                                                  "finger service '%s' failed\n",
                                                  (char *)cstring_get_str(service_name));    
            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_FALSE);
        }

        if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
        {
            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: "
                                                  "service '%s' has no node\n",
                                                  (char *)cstring_get_str(service_name));    
            ctdnssv_node_mgr_free(ctdnssv_node_mgr);
            return (EC_TRUE);
        }

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
        CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
        {
            CTDNSSV_NODE        *ctdnssv_node;
            MOD_NODE             recv_mod_node;

            ctdnssv_node = CLIST_DATA_DATA(clist_data);

            MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
            MOD_NODE_MODI(&recv_mod_node) = 0; /*only one tdns module*/
            
            task_p2p_inc(task_mgr, ctdns_md_id, 
                         &recv_mod_node, 
                         NULL_PTR, 
                         FI_ctdns_set, CMPI_ERROR_MODI, network_level, tcid, ipaddr, port, service_name);
        }
        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_TRUE);
    }
    
    if(NULL_PTR == CTDNS_MD_SVP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: svp was not open\n");
        return (EC_FALSE);
    }    

    if(EC_FALSE == ctdnssv_mgr_set(CTDNS_MD_SVP(ctdns_md), tcid, ipaddr, port, service_name))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_set: set svp (service '%s', tcid %s, ip %s, port %ld) failed\n",
                         (char *)cstring_get_str(service_name),
                         c_word_to_ipv4(tcid),
                         c_word_to_ipv4(ipaddr),
                         port);
        return (EC_FALSE);
    }

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_set: set svp (service '%s', tcid %s, ip %s, port %ld) done\n",
                     (char *)cstring_get_str(service_name),
                     c_word_to_ipv4(tcid),
                     c_word_to_ipv4(ipaddr),
                     port);   
                     
    return (EC_TRUE);
}

/**
*
*  get a tcid
*
**/
EC_BOOL ctdns_get(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, UINT32 *port)
{
    CTDNS_MD      *ctdns_md;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_get: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_get: npp was not open\n");
        return (EC_FALSE);
    }

    return ctdnsnp_mgr_get(CTDNS_MD_NPP(ctdns_md), tcid, ipaddr, port);
}


/**
*
*  delete a tcid
*
**/
EC_BOOL ctdns_delete(const UINT32 ctdns_md_id, const UINT32 tcid)
{
    CTDNS_MD      *ctdns_md;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_delete: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);
    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_delete: no npp\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CTDNS_MD_SVP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_delete: no svp\n");
        return (EC_FALSE);
    }    

    ctdnssv_mgr_delete(CTDNS_MD_SVP(ctdns_md), tcid);
    
    return ctdnsnp_mgr_delete(CTDNS_MD_NPP(ctdns_md), tcid);
}

/**
*
*  flush name node pool
*
**/
EC_BOOL ctdns_flush_npp(const UINT32 ctdns_md_id)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_flush_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_flush_npp: npp was not open\n");
        return (EC_TRUE);
    }
 
    if(EC_FALSE == ctdnsnp_mgr_flush(CTDNS_MD_NPP(ctdns_md)))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_flush_npp: flush failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "[DEBUG] ctdns_flush_npp: flush done\n");
    return (EC_TRUE);
}

/**
*
*  flush service pool
*
**/
EC_BOOL ctdns_flush_svp(const UINT32 ctdns_md_id)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_flush_svp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_SVP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_flush_svp: svp was not open\n");
        return (EC_TRUE);
    }
 
    if(EC_FALSE == ctdnssv_mgr_flush(CTDNS_MD_SVP(ctdns_md)))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_flush_svp: flush failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "[DEBUG] ctdns_flush_svp: flush done\n");
    return (EC_TRUE);
}

/**
*
*  count tcid num
*
**/
EC_BOOL ctdns_tcid_num(const UINT32 ctdns_md_id, UINT32 *tcid_num)
{
    CTDNS_MD      *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_tcid_num: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_tcid_num: npp was not open\n");
        return (EC_FALSE);
    }

    return ctdnsnp_mgr_tcid_num(CTDNS_MD_NPP(ctdns_md), tcid_num);
}

/**
*
*  count node num fo specific service
*
**/
EC_BOOL ctdns_node_num(const UINT32 ctdns_md_id, const CSTRING *service_name, UINT32 *tcid_num)
{
    CTDNS_MD      *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_node_num: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_SVP(ctdns_md))
    {
        dbg_log(SEC_0026_CTDNS, 1)(LOGSTDOUT, "warn:ctdns_node_num: svp was not open\n");
        return (EC_FALSE);
    }

    return ctdnssv_mgr_node_num_of_sp(CTDNS_MD_SVP(ctdns_md), service_name, tcid_num);
}

/**
*
*  config a free tcid which is not used by anyone
*
**/
EC_BOOL ctdns_config_tcid(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid, const UINT32 port)
{
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_config_tcid: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    if(EC_TRUE == ctdns_exists_tcid(ctdns_md_id, tcid))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_config_tcid: tcid '%s' already exists\n",
                                              c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    if(EC_FALSE == ctdns_set_service(ctdns_md_id, tcid, CMPI_ERROR_IPADDR, port, service_name))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_config_tcid: config tcid '%s' port %ld to service '%s' failed\n",
                                              c_word_to_ipv4(tcid), port,
                                              (char *)cstring_get_str(service_name));    
        return (EC_FALSE);
    }

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_config_tcid: config tcid '%s' port %ld to service '%s' done\n",
                                          c_word_to_ipv4(tcid), port,
                                          (char *)cstring_get_str(service_name));    

    return (EC_TRUE);
}

/**
*
*  reserve a tcid to use from specific service
*
**/
EC_BOOL ctdns_reserve_tcid(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 ipaddr, UINT32 *tcid, UINT32 *port)
{
    UINT32      reserved_tcid;
    UINT32      reserved_port;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_reserve_tcid: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    if(EC_FALSE == ctdns_reserve_tcid_from_service(ctdns_md_id, service_name, &reserved_tcid, &reserved_port))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_reserve_tcid: reserve tcid from service '%s' failed\n",
                                              (char *)cstring_get_str(service_name));
        return (EC_FALSE);
    }
#if 0
    if(EC_FALSE == ctdns_set(ctdns_md_id, reserved_tcid, ipaddr, reserved_port, service_name))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_reserve_tcid: set (tcid %s, ip %s, port %ld) to service '%s' failed\n",
                                              c_word_to_ipv4(reserved_tcid),
                                              c_word_to_ipv4(ipaddr),
                                              reserved_port,
                                              (char *)cstring_get_str(service_name));

        ctdns_release_tcid_to_service(ctdns_md_id, service_name, reserved_tcid, reserved_port);
        return (EC_FALSE);
    }
#endif
    (*tcid) = reserved_tcid;
    (*port) = reserved_port;

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_reserve_tcid: reserve tcid '%s' port %ld from service '%s' done\n",
                                          c_word_to_ipv4(*tcid), (*port),
                                          (char *)cstring_get_str(service_name));    

    return (EC_TRUE);
}

/**
*
*  release a used tcid to unused from specific service
*
**/
EC_BOOL ctdns_release_tcid(const UINT32 ctdns_md_id, const CSTRING *service_name, const UINT32 tcid, const UINT32 port)
{   
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_release_tcid: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    if(EC_FALSE == ctdns_release_tcid_to_service(ctdns_md_id, service_name, tcid, port))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_release_tcid: release tcid '%s' port %ld to service '%s' failed\n",
                                              c_word_to_ipv4(tcid), port, 
                                              (char *)cstring_get_str(service_name));
        return (EC_FALSE);
    }

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_release_tcid: release tcid '%s' port %ld to service '%s' done\n",
                                          c_word_to_ipv4(tcid), port,
                                          (char *)cstring_get_str(service_name));    

    return (EC_TRUE);
}

/**
*
*  show name node pool info
*
*
**/
EC_BOOL ctdns_show_npp(const UINT32 ctdns_md_id, LOG *log)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_show_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    ctdnsnp_mgr_print(log, CTDNS_MD_NPP(ctdns_md));
 
    return (EC_TRUE);
}

/**
*
*  show service pool info
*
*
**/
EC_BOOL ctdns_show_svp(const UINT32 ctdns_md_id, LOG *log)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_show_svp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_SVP(ctdns_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    ctdnssv_mgr_print(log, CTDNS_MD_SVP(ctdns_md));
 
    return (EC_TRUE);
}

/**
*
*  check this TDNS has namenode
*
*
**/
EC_BOOL ctdns_has_npp(const UINT32 ctdns_md_id)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_has_npp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_NPP(ctdns_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this TDNS has service pool
*
*
**/
EC_BOOL ctdns_has_svp(const UINT32 ctdns_md_id)
{
    CTDNS_MD *ctdns_md;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_has_svp: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR == CTDNS_MD_SVP(ctdns_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL ctdns_online_notify(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name)
{
    //CTDNS_MD         *ctdns_md;

    TASK_MGR         *task_mgr;

    CSTRING          *edge_service_name;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_online_notify: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online_notify: "
                                              "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }

    edge_service_name = ctdns_gen_edge_service_name(service_name);
    if(NULL_PTR == edge_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online_notify: "
                                              "gen edge service name failed\n");    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }
  
    
    if(EC_FALSE == ctdns_finger_service(ctdns_md_id, 
                                        edge_service_name, 
                                        (UINT32)(~(UINT32)0), 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online_notify: "
                                              "finger service '%s' failed\n",
                                              (char *)cstring_get_str(edge_service_name));    
        cstring_free(edge_service_name);
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online_notify: "
                                              "no edge node for service '%s'\n",
                                              (char *)cstring_get_str(edge_service_name));    
        cstring_free(edge_service_name);
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }
    cstring_free(edge_service_name);

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one tdns module*/

        if(do_log(SEC_0026_CTDNS, 9))
        {
            dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_online_notify: "
                                                  "notify edge node '%s' that "
                                                  "network %ld, tcid '%s' online\n",
                                                  c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                  network,
                                                  c_word_to_ipv4(tcid)); 
        }
        
        task_p2p_inc(task_mgr, 
                    ctdns_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_ctdns_online, CMPI_ERROR_MODI, network, tcid, service_name);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

EC_BOOL ctdns_offline_notify(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name)
{
    //CTDNS_MD         *ctdns_md;

    TASK_MGR         *task_mgr;

    CSTRING          *edge_service_name;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_offline_notify: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline_notify: "
                                              "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }

    edge_service_name = ctdns_gen_edge_service_name(service_name);
    if(NULL_PTR == edge_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline_notify: "
                                              "gen edge service name failed\n");    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }
  
    
    if(EC_FALSE == ctdns_finger_service(ctdns_md_id, 
                                        edge_service_name, 
                                        (UINT32)(~(UINT32)0), 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline_notify: "
                                              "finger service '%s' failed\n",
                                              (char *)cstring_get_str(edge_service_name));    
        cstring_free(edge_service_name);
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline_notify: "
                                              "no edge node for service '%s'\n",
                                              (char *)cstring_get_str(edge_service_name));    
        cstring_free(edge_service_name);
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }
    cstring_free(edge_service_name);

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one tdns module*/

        if(do_log(SEC_0026_CTDNS, 9))
        {
            dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_offline_notify: "
                                                  "notify edge node '%s' that "
                                                  "network %ld, tcid '%s' offline\n",
                                                  c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                  network,
                                                  c_word_to_ipv4(tcid)); 
        }
        
        task_p2p_inc(task_mgr, 
                    ctdns_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_ctdns_offline, CMPI_ERROR_MODI, network, tcid, service_name);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

EC_BOOL ctdns_refresh_cache_notify(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name, const CSTRING *path)
{
    //CTDNS_MD         *ctdns_md;

    TASK_MGR         *task_mgr;

    CSTRING          *edge_service_name;
    
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    CLIST_DATA       *clist_data;
        
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_refresh_cache_notify: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache_notify: "
                                              "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }

    edge_service_name = ctdns_gen_edge_service_name(service_name);
    if(NULL_PTR == edge_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache_notify: "
                                              "gen edge service name failed\n");    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }
  
    
    if(EC_FALSE == ctdns_finger_service(ctdns_md_id, 
                                        edge_service_name, 
                                        (UINT32)(~(UINT32)0), 
                                        ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache_notify: "
                                              "finger service '%s' failed\n",
                                              (char *)cstring_get_str(edge_service_name));    
        cstring_free(edge_service_name);
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache_notify: "
                                              "no edge node for service '%s'\n",
                                              (char *)cstring_get_str(edge_service_name));    
        cstring_free(edge_service_name);
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }
    cstring_free(edge_service_name);

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = CTDNSSV_NODE_TCID(ctdnssv_node);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one tdns module*/

        if(do_log(SEC_0026_CTDNS, 9))
        {
            dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_refresh_cache_notify: "
                                                  "notify edge node '%s' that "
                                                  "network %ld, tcid '%s' refresh path '%s'\n",
                                                  c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                  network,
                                                  c_word_to_ipv4(tcid),
                                                  (char *)cstring_get_str(path)); 
        }
        
        task_p2p_inc(task_mgr, 
                    ctdns_md_id, 
                    &recv_mod_node,
                    NULL_PTR, FI_ctdns_refresh_cache, CMPI_ERROR_MODI, network, tcid, service_name, path);
    }
    ctdnssv_node_mgr_free(ctdnssv_node_mgr);  
    
    task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
                     
    return (EC_TRUE);
}

/**
*
*  ping tcid and record the elapsed msec
*
*
**/
EC_BOOL ctdns_ping_over_http(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, UINT32 *port, UINT32 *elapsed_msec)
{
    //CTDNS_MD         *ctdns_md;
    
    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;

    UINT32            tdns_ipaddr;
    UINT32            tdns_port; 

    uint32_t          s_nsec;
    uint32_t          s_msec;

    uint32_t          e_nsec;
    uint32_t          e_msec;       

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_ping_over_http: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);   

    if(EC_FALSE == c_tdns_resolve(tcid, &tdns_ipaddr, &tdns_port))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_ping_over_http: tdns resolve '%s' failed\n",
                        c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }
    
    chttp_req_set_ipaddr_word(&chttp_req, tdns_ipaddr);
    chttp_req_set_port_word(&chttp_req, tdns_port);    

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)"/tdns/ping");

    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)c_word_to_ipv4(tdns_ipaddr));
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (const char *)"0");

    s_nsec = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());
    s_msec = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_ping_over_http: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_ping_over_http: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    e_nsec = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());
    e_msec = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());    

    (*elapsed_msec) = ((e_nsec - s_nsec) * 1000 + e_msec - s_msec);
    (*ipaddr)       = tdns_ipaddr;
    (*port)         = tdns_port;

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_ping_over_http: ping tcid '%s' (ip '%s', port %ld) in %ld msec done\n",
                                          c_word_to_ipv4(tcid),
                                          c_word_to_ipv4(tdns_ipaddr),
                                          tdns_port,
                                          (*elapsed_msec));        
    return (EC_TRUE);
}

EC_BOOL ctdns_ping(const UINT32 ctdns_md_id, const UINT32 tcid, UINT32 *ipaddr, UINT32 *port, UINT32 *elapsed_msec)
{
    //CTDNS_MD         *ctdns_md;
    
    UINT32            tdns_ipaddr;
    UINT32            tdns_port;     
    UINT32            ping_elapsed_msec;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_ping: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);   

    if(EC_FALSE == c_tdns_resolve(tcid, &tdns_ipaddr, &tdns_port))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_ping: tdns resolve '%s' failed\n",
                        c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }
    
    if(EC_FALSE == cping_check(tdns_ipaddr, tdns_port, &ping_elapsed_msec))
    {
        dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_ping: ping tcid '%s' (ip '%s', port %ld) failed\n",
                                              c_word_to_ipv4(tcid),
                                              c_word_to_ipv4(tdns_ipaddr),
                                              tdns_port); 
        return (EC_FALSE);
    }

    (*elapsed_msec) = ping_elapsed_msec;
    (*ipaddr)       = tdns_ipaddr;
    (*port)         = tdns_port;

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_ping: ping tcid '%s' (ip '%s', port %ld) in %ld msec done\n",
                                          c_word_to_ipv4(tcid),
                                          c_word_to_ipv4(tdns_ipaddr),
                                          tdns_port,
                                          (*elapsed_msec));        
    return (EC_TRUE);
}

/**
*
*  online reporting
*
*
**/
EC_BOOL ctdns_online(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name)
{
    //CTDNS_MD        *ctdns_md;
    
    TASK_BRD        *task_brd;

    CSTRING         *upper_service_name;
    CSTRING         *edge_service_name;
    
    UINT32           remote_ipaddr;
    UINT32           remote_port;
    UINT32           elapsed_msec;
        
    UINT32           local_ipaddr;
    UINT32           local_port;

    MOD_NODE         recv_mod_node;
    EC_BOOL          ret;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_online: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    task_brd = task_brd_default_get();

    if(TASK_BRD_NETWORK_LEVEL(task_brd) >= network)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online: "
                                              "cur network level %ld >= reporter network %ld\n",
                                              TASK_BRD_NETWORK_LEVEL(task_brd),
                                              network);    
        return (EC_FALSE);
    }

    if(TASK_BRD_NETWORK_LEVEL(task_brd) + 1 < network)
    {
        return ctdns_online_notify(ctdns_md_id, network, tcid, service_name);
    }    

    /*now TASK_BRD_NETWORK_LEVEL(task_brd) + 1 == network*/
    if(EC_FALSE == ctdns_ping(ctdns_md_id, tcid, &remote_ipaddr, &remote_port, &elapsed_msec))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online: "
                                              "ping tcid '%s' failed\n",
                                              c_word_to_ipv4(tcid));      
        return (EC_FALSE);
    }

    if(elapsed_msec > CTDNS_EDGE_PING_MAX_MSEC)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online: "
                                              "ping tcid '%s' elapsed %ld msec overflow\n",
                                              c_word_to_ipv4(tcid),
                                              elapsed_msec);      
        return (EC_FALSE);
    }

    if(EC_FALSE == c_tdns_resolve(CMPI_LOCAL_TCID, &local_ipaddr, &local_port))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online: "
                                              "tdns resolve '%s' failed\n",
                                              c_word_to_ipv4(CMPI_LOCAL_TCID));
        return (EC_FALSE);
    }    

    /*set remote as upper*/

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one tdns module*/

    upper_service_name = ctdns_gen_upper_service_name(service_name);
    if(NULL_PTR == upper_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online: "
                                              "gen upper service name failed\n");
        return (EC_FALSE);
    }
    
    ret = EC_FALSE;
    task_p2p(ctdns_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, 
             &recv_mod_node, 
             &ret, FI_ctdns_set_service, CMPI_ERROR_MODI, CMPI_LOCAL_TCID, local_ipaddr, local_port, upper_service_name);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online: "
                                              "set (service '%s', tcid '%s', ip '%s', port %ld) on tcid '%s' failed\n",
                                              (char *)cstring_get_str(upper_service_name),
                                              c_word_to_ipv4(CMPI_LOCAL_TCID),
                                              c_word_to_ipv4(local_ipaddr),
                                              local_port,
                                              c_word_to_ipv4(tcid));
        cstring_free(upper_service_name);
        return (EC_FALSE);
    }

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_online: "
                                          "set (service '%s', tcid '%s', ip '%s', port %ld) on tcid '%s' done\n",
                                          (char *)cstring_get_str(upper_service_name),
                                          c_word_to_ipv4(CMPI_LOCAL_TCID),
                                          c_word_to_ipv4(local_ipaddr),
                                          local_port,
                                          c_word_to_ipv4(tcid));    

    cstring_free(upper_service_name);
    
    /*set local as edge*/
    edge_service_name = ctdns_gen_edge_service_name(service_name);
    if(NULL_PTR == edge_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_online: "
                                              "gen edge service name failed\n");
        return (EC_FALSE);
    }
    ctdns_set_service(ctdns_md_id, tcid, remote_ipaddr, remote_port, edge_service_name);

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_online: "
                                          "set (service '%s', tcid '%s', ip '%s', port %ld) done\n",
                                          (char *)cstring_get_str(edge_service_name),
                                          c_word_to_ipv4(tcid),
                                          c_word_to_ipv4(remote_ipaddr),
                                          remote_port);    
    cstring_free(edge_service_name);
    return (EC_TRUE);
}

/**
*
*  offline reporting
*
*
**/
EC_BOOL ctdns_offline(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name)
{
    //CTDNS_MD        *ctdns_md;
    
    TASK_BRD        *task_brd;

    CSTRING         *upper_service_name;
    CSTRING         *edge_service_name;
   
    MOD_NODE         recv_mod_node;
    EC_BOOL          ret;

#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_offline: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    task_brd = task_brd_default_get();

    if(TASK_BRD_NETWORK_LEVEL(task_brd) >= network)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline: "
                                              "cur network level %ld >= reporter network %ld\n",
                                              TASK_BRD_NETWORK_LEVEL(task_brd),
                                              network);    
        return (EC_FALSE);
    }

    if(TASK_BRD_NETWORK_LEVEL(task_brd) + 1 < network)
    {
        return ctdns_offline_notify(ctdns_md_id, network, tcid, service_name);
    }    

    /*now TASK_BRD_NETWORK_LEVEL(task_brd) + 1 == network*/  

    /*unset remote as upper*/

    MOD_NODE_TCID(&recv_mod_node) = tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one tdns module*/

    upper_service_name = ctdns_gen_upper_service_name(service_name);
    if(NULL_PTR == upper_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline: "
                                              "gen upper service name failed\n");
        return (EC_FALSE);
    }
    
    ret = EC_FALSE;
    task_p2p(ctdns_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP, 
             &recv_mod_node, 
             &ret, FI_ctdns_unset_service, CMPI_ERROR_MODI, CMPI_LOCAL_TCID, upper_service_name);

    if(EC_FALSE == ret)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline: "
                                              "set (service '%s', tcid '%s') on tcid '%s' failed\n",
                                              (char *)cstring_get_str(upper_service_name),
                                              c_word_to_ipv4(CMPI_LOCAL_TCID),
                                              c_word_to_ipv4(tcid));
        cstring_free(upper_service_name);
        return (EC_FALSE);
    }

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_offline: "
                                          "set (service '%s', tcid '%s') on tcid '%s' done\n",
                                          (char *)cstring_get_str(upper_service_name),
                                          c_word_to_ipv4(CMPI_LOCAL_TCID),
                                          c_word_to_ipv4(tcid));    

    cstring_free(upper_service_name);
    
    /*unset local as edge*/
    edge_service_name = ctdns_gen_edge_service_name(service_name);
    if(NULL_PTR == edge_service_name)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_offline: "
                                              "gen edge service name failed\n");
        return (EC_FALSE);
    }
    ctdns_unset_service(ctdns_md_id, tcid, edge_service_name);

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_offline: "
                                          "set (service '%s', tcid '%s') done\n",
                                          (char *)cstring_get_str(edge_service_name),
                                          c_word_to_ipv4(tcid));    
    cstring_free(edge_service_name);
    return (EC_TRUE);
}

/**
*
*  refresh local cache
*
**/
EC_BOOL ctdns_refresh_local_cache(const UINT32 ctdns_md_id, const CSTRING *path)
{
    CTDNS_MD          *ctdns_md;

    CHTTP_REQ         chttp_req;
    CHTTP_RSP         chttp_rsp;
    CSTRING           body_cstr;
    UINT32            body_len;
   
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_refresh_local_cache: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        ctdns_print_module_status(ctdns_md_id, LOGSTDOUT);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);
    
    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);
    
    chttp_req_set_ipaddr(&chttp_req, (const char *)"127.0.0.1");
    chttp_req_set_port(&chttp_req, (const char *)"80");    

    chttp_req_set_method(&chttp_req, (const char *)"GET");
    chttp_req_set_uri(&chttp_req, (const char *)"/");

    cstring_init(&body_cstr, NULL_PTR);
    cstring_format(&body_cstr, "[\"%s\"]", cstring_get_str(path));
    body_len = cstring_get_len(&body_cstr);
    chttp_req_set_body(&chttp_req, (const uint8_t *)cstring_get_str(&body_cstr), (uint32_t)body_len);
    cstring_clean(&body_cstr);
    
    chttp_req_add_header(&chttp_req, (const char *)"Host", (const char *)"www.refresh.com");
    chttp_req_add_header(&chttp_req, (const char *)"Accept"    , (const char *)"*/*");
    chttp_req_add_header(&chttp_req, (const char *)"Connection", (const char *)"keep-alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", c_word_to_str(body_len));

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_local_cache: http request failed\n");

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(CHTTP_OK != CHTTP_RSP_STATUS(&chttp_rsp))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_local_cache: invalid rsp status %u\n",
                        CHTTP_RSP_STATUS(&chttp_rsp));

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_refresh_local_cache: refresh '%s' done\n",
                    (const char *)cstring_get_str(path));    
    
    return (EC_TRUE);
}

/**
*
*  refresh cache path
*
*
**/
EC_BOOL ctdns_refresh_cache(const UINT32 ctdns_md_id, const UINT32 network, const UINT32 tcid, const CSTRING *service_name, const CSTRING *path)
{
    //CTDNS_MD        *ctdns_md;
    
    TASK_BRD        *task_brd;
   
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_refresh_cache: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    task_brd = task_brd_default_get();

    if(CMPI_TOP_NETWORK == network)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache: "
                                              "network level should never be top\n");    
        return (EC_FALSE);
    }
    
    if(TASK_BRD_NETWORK_LEVEL(task_brd) > network)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache: "
                                              "cur network level %ld >= reporter network %ld\n",
                                              TASK_BRD_NETWORK_LEVEL(task_brd),
                                              network);    
        return (EC_FALSE);
    }

    if(TASK_BRD_NETWORK_LEVEL(task_brd) < network)
    {
        return ctdns_refresh_cache_notify(ctdns_md_id, network, tcid, service_name, path);
    }    

    /*now TASK_BRD_NETWORK_LEVEL(task_brd) == network*/  
    if(CMPI_ANY_TCID != tcid && CMPI_LOCAL_TCID != tcid)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache: "
                                              "local tcid '%s' != des tcid '%s'\n",
                                              c_word_to_ipv4(CMPI_LOCAL_TCID),
                                              c_word_to_ipv4(tcid));    
        return (EC_FALSE);
    }
    
    /*refresh local cache*/

    if(EC_FALSE == ctdns_refresh_local_cache(ctdns_md_id, path))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_refresh_cache: "
                                              "refresh '%s' failed\n",
                                              (char *)cstring_get_str(path));
        return (EC_FALSE);
    }       

    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_refresh_cache: "
                                          "refresh '%s' done\n",
                                          (char *)cstring_get_str(path));        

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __ctdns_detect_service(const UINT32 ctdns_md_id, const CSTRING *service_name, CTDNSSV_NODE_MGR *ctdnssv_node_mgr)
{
    UINT32            max_num;

    TASK_BRD         *task_brd;
    TASK_MGR         *task_mgr;
    CLIST_DATA       *clist_data;

    UINT32            ipaddr;
    UINT32            port;
    UINT32            elapsed_msec;
    
    CVECTOR          *ret_vec;
    UINT32            ret_pos;
    
    max_num  = (UINT32)(~(UINT32)0);

    ret_vec = cvector_new(0, MM_UINT32, LOC_CTDNS_0006);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:__ctdns_detect_service: "
                                              "new ret_vec failed\n");    
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;
        UINT32              *ret;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] __ctdns_detect_service: "
                                              "detect service '%s' node '%s'\n",
                                              (char *)cstring_get_str(service_name),
                                              c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node))); 

        alloc_static_mem(MM_UINT32, &ret, LOC_CTDNS_0007);
        cvector_push_no_lock(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;
        
        task_p2p_inc(task_mgr, 
                    ctdns_md_id, 
                    &recv_mod_node,
                    ret, 
                    FI_ctdns_ping, CMPI_ERROR_MODI, CTDNSSV_NODE_TCID(ctdnssv_node), 
                    &ipaddr, &port, &elapsed_msec);
    }
    
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    ret_pos = 0;
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {   
        UINT32              *ret;    
   
        ret = (UINT32 *)cvector_get(ret_vec, ret_pos);

        if(EC_FALSE == (*ret))
        {
            CTDNSSV_NODE        *ctdnssv_node;
            
            ctdnssv_node = CLIST_DATA_DATA(clist_data);

            dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "[DEBUG] __ctdns_detect_service: "
                                                  "delete node '%s' from service '%s'\n",
                                                  c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                  (char *)cstring_get_str(service_name)); 

            ctdns_delete_tcid_from_service(ctdns_md_id, service_name, CTDNSSV_NODE_TCID(ctdnssv_node));
        }

        cvector_set(ret_vec, ret_pos, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_CTDNS_0008);   
        
        ret_pos ++;
    }

    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    cvector_free(ret_vec, LOC_CTDNS_0009);
    
    return (EC_TRUE);
}
/**
*
*  detect nodes alive of service
*
*
**/
EC_BOOL ctdns_detect_service(const UINT32 ctdns_md_id, const CSTRING *service_name)
{
    //CTDNS_MD         *ctdns_md;
    CTDNSSV_NODE_MGR *ctdnssv_node_mgr;
    UINT32            max_num;

    TASK_BRD         *task_brd;
    TASK_MGR         *task_mgr;
    CLIST_DATA       *clist_data;

    UINT32            ipaddr;
    UINT32            port;
    UINT32            elapsed_msec;
    
    CVECTOR          *ret_vec;
    UINT32            ret_pos;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_detect_service: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    //ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    max_num  = (UINT32)(~(UINT32)0);

    ctdnssv_node_mgr = ctdnssv_node_mgr_new();
    if(NULL_PTR == ctdnssv_node_mgr)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_detect_service: "
                                              "new ctdnssv_node_mgr failed\n");    
        return (EC_FALSE);
    }
    
    if(EC_FALSE == ctdns_finger_service(ctdns_md_id, 
                                         service_name, 
                                         max_num, 
                                         ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_detect_service: "
                                              "finger service '%s' failed\n",
                                              (char *)cstring_get_str(service_name));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    if(EC_TRUE == ctdnssv_node_mgr_is_empty(ctdnssv_node_mgr))
    {
        dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_detect_service: "
                                              "no node for service '%s'\n",
                                              (char *)cstring_get_str(service_name));    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_TRUE);
    }

    ret_vec = cvector_new(0, MM_UINT32, LOC_CTDNS_0010);
    if(NULL_PTR == ret_vec)
    {
        dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "error:ctdns_detect_service: "
                                              "new ret_vec failed\n");    
        ctdnssv_node_mgr_free(ctdnssv_node_mgr);
        return (EC_FALSE);
    }

    task_brd = task_brd_default_get();

    /*try one by one*/
    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {
        CTDNSSV_NODE        *ctdnssv_node;
        MOD_NODE             recv_mod_node;
        UINT32              *ret;

        ctdnssv_node = CLIST_DATA_DATA(clist_data);

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one p2p module*/

        dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_detect_service: "
                                              "detect service '%s' node '%s'\n",
                                              (char *)cstring_get_str(service_name),
                                              c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node))); 

        alloc_static_mem(MM_UINT32, &ret, LOC_CTDNS_0011);
        cvector_push_no_lock(ret_vec, (void *)ret);
        (*ret) = EC_FALSE;
        
        task_p2p_inc(task_mgr, 
                    ctdns_md_id, 
                    &recv_mod_node,
                    ret, 
                    FI_ctdns_ping, CMPI_ERROR_MODI, CTDNSSV_NODE_TCID(ctdnssv_node), 
                    &ipaddr, &port, &elapsed_msec);
    }
    
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    ret_pos = 0;
    CLIST_LOOP_NEXT(CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr), clist_data)
    {   
        CTDNSSV_NODE        *ctdnssv_node;
        UINT32              *ret;    

        ctdnssv_node = CLIST_DATA_DATA(clist_data);
   
        ret = (UINT32 *)cvector_get(ret_vec, ret_pos);

        if(EC_FALSE == (*ret))
        {
            dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_detect_service: "
                                                  "suspect node '%s' from service '%s'\n",
                                                  c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                  (char *)cstring_get_str(service_name));   
                                                  
            if(EC_FALSE == ctdns_set_susv(ctdns_md_id, service_name, CTDNSSV_NODE_TCID(ctdnssv_node), 
                                           CTDNS_NODE_DETECT_MAX_FAILS))
            {
                dbg_log(SEC_0026_CTDNS, 0)(LOGSTDOUT, "[DEBUG] ctdns_detect_service: "
                                                      "delete node '%s' from service '%s'\n",
                                                      c_word_to_ipv4(CTDNSSV_NODE_TCID(ctdnssv_node)),
                                                      (char *)cstring_get_str(service_name)); 

                ctdns_delete_tcid_from_service(ctdns_md_id, service_name, CTDNSSV_NODE_TCID(ctdnssv_node));            
            }
        }
        else
        {
            ctdns_unset_susv(ctdns_md_id, service_name, CTDNSSV_NODE_TCID(ctdnssv_node));
        }

        cvector_set(ret_vec, ret_pos, NULL_PTR);
        free_static_mem(MM_UINT32, ret, LOC_CTDNS_0012);   
        
        ret_pos ++;
    }

    ctdnssv_node_mgr_free(ctdnssv_node_mgr);
    cvector_free(ret_vec, LOC_CTDNS_0013);
    
    return (EC_TRUE);
}

EC_BOOL ctdns_detect(const UINT32 ctdns_md_id)
{
    CTDNS_MD         *ctdns_md;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_detect: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_md = CTDNS_MD_GET(ctdns_md_id);

    if(NULL_PTR != CTDNS_MD_SVP(ctdns_md))
    {
        CTDNSSV_MGR   *ctdnssv_mgr;
        CLIST_DATA    *clist_data;

        ctdnssv_mgr = CTDNS_MD_SVP(ctdns_md);
        
        CLIST_LOOP_NEXT(CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr), clist_data)
        {
            CTDNSSV     *ctdnssv;
            CSTRING      service_name;

            ctdnssv = CLIST_DATA_DATA(clist_data);

            if(sizeof(CTDNSHTTP_NODES_SERVICE_NAME) - 1 == CTDNSSV_SNAME_LEN(ctdnssv)
            && 0 == STRNCMP((char *)CTDNSHTTP_NODES_SERVICE_NAME, (char *)CTDNSSV_SNAME(ctdnssv), CTDNSSV_SNAME_LEN(ctdnssv)))
            {
                continue;
            }

            cstring_init(&service_name, NULL_PTR);
            cstring_set_chars(&service_name, CTDNSSV_SNAME(ctdnssv), CTDNSSV_SNAME_LEN(ctdnssv));

            dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_detect: "
                                                  "service: %s\n",
                                                  (char *)cstring_get_str(&service_name));
            ctdns_detect_service(ctdns_md_id, &service_name);

            cstring_clean(&service_name);
        }    
    }
  
    return (EC_TRUE);
}

/**
*
*  detect task
*
*
**/
EC_BOOL ctdns_detect_task(const UINT32 ctdns_md_id)
{
    TASK_BRD       *task_brd;
    MOD_NODE        recv_mod_node;    
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_detect_task: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    task_brd = task_brd_default_get();

    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&recv_mod_node) = ctdns_md_id;
    
    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_ctdns_detect, CMPI_ERROR_MODI);    

    return (EC_TRUE);
}

/**
*
*  detect loop
*
*
**/
EC_BOOL ctdns_detect_loop(const UINT32 ctdns_md_id)
{
    TASK_BRD       *task_brd;
    MOD_NODE        recv_mod_node;    
    UINT32          msec;
    
#if ( SWITCH_ON == CTDNS_DEBUG_SWITCH )
    if ( CTDNS_MD_ID_CHECK_INVALID(ctdns_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:ctdns_detect_loop: ctdns module #0x%lx not started.\n",
                ctdns_md_id);
        dbg_exit(MD_CTDNS, ctdns_md_id);
    }
#endif/*CTDNS_DEBUG_SWITCH*/

    ctdns_detect(ctdns_md_id);

    task_brd = task_brd_default_get();

    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&recv_mod_node) = ctdns_md_id;

    msec = CTDNS_NODE_DETECT_NSEC * 1000;
    dbg_log(SEC_0026_CTDNS, 9)(LOGSTDOUT, "[DEBUG] ctdns_detect_loop: "
                                          "sleep %ld msec\n",
                                          msec);
    coroutine_usleep(msec, LOC_CTDNS_0014);
    
    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_ctdns_detect_loop, CMPI_ERROR_MODI);    

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

