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
    CDETECT_MD  *cdetect_md;

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

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

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

    TASK_BRD   *task_brd;
    
    task_brd = task_brd_default_get();
 
    cdetect_md_id = cbc_md_new(MD_CDETECT, sizeof(CDETECT_MD));
    if(CMPI_ERROR_MODI == cdetect_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == c_file_access((char *)cstring_get_str(cdetect_conf_file), F_OK))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start: "
                                                "cdetect conf file '%s' not exist\n",
                                                cdetect_md_id, 
                                                (char *)cstring_get_str(cdetect_conf_file));

        cbc_md_free(MD_CDETECT, cdetect_md_id);
        return (CMPI_ERROR_MODI);
    }
  
    /* initialize new one CDETECT module */
    cdetect_md = (CDETECT_MD *)cbc_md_get(MD_CDETECT, cdetect_md_id);
    cdetect_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem(); 

    crb_tree_init(CDETECT_MD_ORIG_NODE_TREE(cdetect_md), 
                  (CRB_DATA_CMP)cdetect_orig_node_cmp, 
                  (CRB_DATA_FREE)cdetect_orig_node_free, 
                  (CRB_DATA_PRINT)cdetect_orig_node_print);

    clist_init(CDETECT_MD_DETECT_NODE_LIST(cdetect_md), MM_UINT32, LOC_CDETECT_0001);

    CDETECT_MD_DETECT_TASK_NUM(cdetect_md) = 0;
    
    cdetect_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cdetect_end, cdetect_md_id);

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "[DEBUG] cdetect_start: "
                                            "start CDETECT module #%ld\n", 
                                            cdetect_md_id);

    if(EC_FALSE == cdetect_load_conf(cdetect_md_id, cdetect_conf_file))
    {
        cdetect_end(cdetect_md_id);
        return (CMPI_ERROR_MODI);
    }

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

    crb_tree_clean(CDETECT_MD_ORIG_NODE_TREE(cdetect_md));
    clist_clean(CDETECT_MD_DETECT_NODE_LIST(cdetect_md), NULL_PTR);

    CDETECT_MD_DETECT_TASK_NUM(cdetect_md) = 0;
    
    /* free module : */
    //cdetect_free_module_static_mem(cdetect_md_id);

    cdetect_md->usedcounter = 0;

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "cdetect_end: stop CDETECT module #%ld\n", cdetect_md_id);
    cbc_md_free(MD_CDETECT, cdetect_md_id);

    return ;
}

/*------------------------------------------------ interface for cdetect orig node ------------------------------------------------*/
CDETECT_ORIG_NODE *cdetect_orig_node_new()
{
    CDETECT_ORIG_NODE *cdetect_orig_node;
    
    alloc_static_mem(MM_CDETECT_ORIG_NODE, &cdetect_orig_node, LOC_CDETECT_0002);
    if(NULL_PTR != cdetect_orig_node)
    {
        cdetect_orig_node_init(cdetect_orig_node);
    }
    return (cdetect_orig_node);
}

EC_BOOL cdetect_orig_node_init(CDETECT_ORIG_NODE *cdetect_orig_node)
{
    cstring_init(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node), NULL_PTR);
    cstring_init(CDETECT_ORIG_NODE_URL(cdetect_orig_node), NULL_PTR);
    clist_init(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), MM_CDETECT_IP_NODE, LOC_CDETECT_0003);

    CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node)    = 0;
    CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node)    = 0;

    CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node)        = CHTTP_OK;        /*default*/
    CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node)        = CHTTP_FORBIDDEN; /*default*/
    CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)         = CDETECT_ORIG_NODE_CHOICE_LATEST;/*default*/
    CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node)             = 0;
    
    CDETECT_ORIG_NODE_LAST_DETECT_TIME(cdetect_orig_node)        = 0;
    CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node)        = 0;
    CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node)  = NULL_PTR;

    CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node)        = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdetect_orig_node_clean(CDETECT_ORIG_NODE *cdetect_orig_node)
{
    cstring_clean(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node));
    cstring_clean(CDETECT_ORIG_NODE_URL(cdetect_orig_node));
    clist_clean(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), (CLIST_DATA_DATA_CLEANER)cdetect_ip_node_free);

    CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node)    = 0;
    CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node)    = 0;

    CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node)        = CHTTP_OK;        /*default*/
    CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node)        = CHTTP_FORBIDDEN; /*default*/
    CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)         = CDETECT_ORIG_NODE_CHOICE_LATEST;/*default*/
    CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node)             = 0;
    
    CDETECT_ORIG_NODE_LAST_DETECT_TIME(cdetect_orig_node)        = 0;
    CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node)        = 0;
    CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node)  = NULL_PTR;

    CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node)        = NULL_PTR;    
    return (EC_TRUE);
}

EC_BOOL cdetect_orig_node_clear(CDETECT_ORIG_NODE *cdetect_orig_node)
{
    //cstring_clean(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node));
    //cstring_clean(CDETECT_ORIG_NODE_URL(cdetect_orig_node));
    //clist_clean(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), (CLIST_DATA_DATA_CLEANER)cdetect_ip_node_free);

    //CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node)    = 0;
    //CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node)    = 0;

    CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node)        = CHTTP_OK;        /*default*/
    CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node)        = CHTTP_FORBIDDEN; /*default*/
    CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)         = CDETECT_ORIG_NODE_CHOICE_LATEST;/*default*/
    //CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node)             = 0;
    
    CDETECT_ORIG_NODE_LAST_DETECT_TIME(cdetect_orig_node)        = 0;
    CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node)        = 0;
    CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node)  = NULL_PTR;

    CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node)        = NULL_PTR;    
    return (EC_TRUE);
}

EC_BOOL cdetect_orig_node_free(CDETECT_ORIG_NODE *cdetect_orig_node)
{
    if(NULL_PTR != cdetect_orig_node)
    {
        cdetect_orig_node_clean(cdetect_orig_node);
        free_static_mem(MM_CDETECT_ORIG_NODE, cdetect_orig_node, LOC_CDETECT_0004);
    }
    return (EC_TRUE);
}

int cdetect_orig_node_cmp(const CDETECT_ORIG_NODE *cdetect_orig_node_1st, const CDETECT_ORIG_NODE *cdetect_orig_node_2nd)
{
    if(CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node_1st) > CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node_2nd))
    {
        return (1);
    }

    if(CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node_1st) < CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node_2nd))
    {
        return (-1);
    }    
    
    return cstring_cmp(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node_1st), CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node_2nd));
}

void cdetect_orig_node_print(LOG *log, const CDETECT_ORIG_NODE *cdetect_orig_node)
{
    if(NULL_PTR != cdetect_orig_node)
    {
        sys_log(log, "cdetect_orig_node_print %p: domain %s (hash %u), url: %s, "
                     "interval %u sec, stopping %u sec, ip list: \n",
                     cdetect_orig_node,
                     (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                     CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node),
                     (char *)CDETECT_ORIG_NODE_URL_STR(cdetect_orig_node),
                     CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node),
                     CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node));
                        
        clist_print(log, CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node),(CLIST_DATA_DATA_PRINT)cdetect_ip_node_print_plain);
    }

    return;
}

/*stop detecting or not*/
EC_BOOL cdetect_orig_node_need_stop_detecting(const CDETECT_ORIG_NODE *cdetect_orig_node)
{
    if(0 < CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node))
    {
        ctime_t     cur_time;
        ctime_t     stop_time;

        cur_time    = task_brd_default_get_time();
        stop_time   = CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node) 
                    + CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node);

        if(stop_time < cur_time)
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);   
}

/*skip detecting this time or not*/
EC_BOOL cdetect_orig_node_need_skip_detecting(const CDETECT_ORIG_NODE *cdetect_orig_node)
{
    if(0 < CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node))
    {
        ctime_t     cur_time;
        ctime_t     next_time; /*next detecing time*/

        cur_time    = task_brd_default_get_time();
        next_time   = CDETECT_ORIG_NODE_LAST_DETECT_TIME(cdetect_orig_node) 
                    + CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node);

        if(next_time > cur_time)
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);   
}

/*------------------------------------------------ interface for cdetect ip node ------------------------------------------------*/
CDETECT_IP_NODE *cdetect_ip_node_new()
{
    CDETECT_IP_NODE *cdetect_ip_node;
    
    alloc_static_mem(MM_CDETECT_IP_NODE, &cdetect_ip_node, LOC_CDETECT_0005);
    if(NULL_PTR != cdetect_ip_node)
    {
        cdetect_ip_node_init(cdetect_ip_node);
    }
    return (cdetect_ip_node);
}

EC_BOOL cdetect_ip_node_init(CDETECT_IP_NODE *cdetect_ip_node)
{
    CDETECT_IP_NODE_IPADDR(cdetect_ip_node)                = CMPI_ERROR_IPADDR;
    CDETECT_IP_NODE_PORT(cdetect_ip_node)                  = CMPI_ERROR_SRVPORT;
    CDETECT_IP_NODE_STATUS(cdetect_ip_node)                = CDETECT_IP_NODE_STATUS_ERR;

    CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node)      = CDETECT_IP_NODE_COST_MSEC_ERR;

    return (EC_TRUE);
}

EC_BOOL cdetect_ip_node_clean(CDETECT_IP_NODE *cdetect_ip_node)
{
    CDETECT_IP_NODE_IPADDR(cdetect_ip_node)                = CMPI_ERROR_IPADDR;
    CDETECT_IP_NODE_PORT(cdetect_ip_node)                  = CMPI_ERROR_SRVPORT;
    CDETECT_IP_NODE_STATUS(cdetect_ip_node)                = CDETECT_IP_NODE_STATUS_ERR;

    CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node)      = CDETECT_IP_NODE_COST_MSEC_ERR;

    return (EC_TRUE);
}

EC_BOOL cdetect_ip_node_clear(CDETECT_IP_NODE *cdetect_ip_node)
{
    //CDETECT_IP_NODE_IPADDR(cdetect_ip_node)                = CMPI_ERROR_IPADDR;
    //CDETECT_IP_NODE_PORT(cdetect_ip_node)                  = CMPI_ERROR_SRVPORT;

    CDETECT_IP_NODE_STATUS(cdetect_ip_node)                = CDETECT_IP_NODE_STATUS_ERR;
    CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node)      = CDETECT_IP_NODE_COST_MSEC_ERR;

    return (EC_TRUE);
}

EC_BOOL cdetect_ip_node_free(CDETECT_IP_NODE *cdetect_ip_node)
{
    if(NULL_PTR != cdetect_ip_node)
    {
        cdetect_ip_node_clean(cdetect_ip_node);
        free_static_mem(MM_CDETECT_IP_NODE, cdetect_ip_node, LOC_CDETECT_0006);
    }
    return (EC_TRUE);
}

STATIC_CAST static const char *__cdetect_ip_node_status_str(const CDETECT_IP_NODE *cdetect_ip_node)
{
    if(CDETECT_IP_NODE_STATUS_REACHABLE == CDETECT_IP_NODE_STATUS(cdetect_ip_node))
    {
        return (const char *)"REACHABLE";
    }

    if(CDETECT_IP_NODE_STATUS_FORBIDDEN == CDETECT_IP_NODE_STATUS(cdetect_ip_node))
    {
        return (const char *)"FORBIDDEN";
    }
    return (const char *)"ERR";
}

void cdetect_ip_node_print(LOG *log, const CDETECT_IP_NODE *cdetect_ip_node)
{
    sys_log(log, "cdetect_ip_node_print %p: ip %s, status: %s, detect cost: %u ms\n",
                 cdetect_ip_node,
                 c_word_to_ipv4(CDETECT_IP_NODE_IPADDR(cdetect_ip_node)),
                 __cdetect_ip_node_status_str(cdetect_ip_node),
                 CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node)
                 );

    return;
}

void cdetect_ip_node_print_plain(LOG *log, const CDETECT_IP_NODE *cdetect_ip_node)
{
    if(CDETECT_IP_NODE_COST_MSEC_ERR == CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node))
    {
        sys_print(log, " cdetect_ip_node %p: ip %s, port %ld, status: %s, detect cost: --\n",
                       cdetect_ip_node,
                       c_word_to_ipv4(CDETECT_IP_NODE_IPADDR(cdetect_ip_node)),
                       CDETECT_IP_NODE_PORT(cdetect_ip_node),
                       __cdetect_ip_node_status_str(cdetect_ip_node));
    }
    else
    {
        sys_print(log, " cdetect_ip_node %p: ip %s, port %ld, status: %s, detect cost: %u ms\n",
                       cdetect_ip_node, 
                       c_word_to_ipv4(CDETECT_IP_NODE_IPADDR(cdetect_ip_node)),
                       CDETECT_IP_NODE_PORT(cdetect_ip_node),
                       __cdetect_ip_node_status_str(cdetect_ip_node),
                       CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node));
    }
    return;
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

    crb_tree_print(log, CDETECT_MD_ORIG_NODE_TREE(cdetect_md));
 
    return (EC_TRUE);
}

CDETECT_ORIG_NODE *__cdetect_search_orig_node(const UINT32 cdetect_md_id, const CSTRING *domain)
{
    CDETECT_MD                  *cdetect_md;

    CRB_NODE                    *crb_node;

    CDETECT_ORIG_NODE            cdetect_orig_node_t;
    UINT32                       domain_hash;

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    domain_hash = CDETECT_ORIG_NODE_DOMAIN_HASH_ALGO(CSTRING_LEN(domain), CSTRING_STR(domain));
    
    /*mount only*/
    cstring_set_str(CDETECT_ORIG_NODE_DOMAIN(&cdetect_orig_node_t), cstring_get_str(domain));
    CDETECT_ORIG_NODE_DOMAIN_HASH(&cdetect_orig_node_t) = (uint32_t)domain_hash;

    crb_node = crb_tree_search_data(CDETECT_MD_ORIG_NODE_TREE(cdetect_md), (void *)&cdetect_orig_node_t);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);             
    }

    return (CDETECT_ORIG_NODE *)CRB_NODE_DATA(crb_node);
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

    CDETECT_ORIG_NODE *cdetect_orig_node;

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

    cdetect_orig_node = __cdetect_search_orig_node(cdetect_md_id, domain);
    if(NULL_PTR == cdetect_orig_node)
    {
        sys_log(log, "[DEBUG] cdetect_show_orig_node: "
                     "no orig node for domain '%s'\n",
                     (char *)cstring_get_str(domain));

        return (EC_TRUE);             
    }
    
    cdetect_orig_node_print(log, cdetect_orig_node);
    
    return (EC_TRUE);
}


STATIC_CAST static uint32_t __cdetect_choice_strategy(const char *choice_stragety)
{
    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"RRB:ROUND-ROBBIN"))
    {
        return (CDETECT_ORIG_NODE_CHOICE_RRB);
    }

    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"FAST"))
    {
        return (CDETECT_ORIG_NODE_CHOICE_FAST);
    }   

    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"LATEST"))
    {
        return (CDETECT_ORIG_NODE_CHOICE_LATEST);
    } 

    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"MS"))
    {
        return (CDETECT_ORIG_NODE_CHOICE_MS);
    }     

    return (CDETECT_ORIG_NODE_CHOICE_ERR);
}

STATIC_CAST static const char * __cdetect_choice_strategy_to_str(const uint32_t choice_stragety)
{
    if(CDETECT_ORIG_NODE_CHOICE_RRB == choice_stragety)
    {
        return (const char *)"RRB";
    }

    if(CDETECT_ORIG_NODE_CHOICE_FAST == choice_stragety)
    {
        return (const char *)"FAST";
    }   

    if(CDETECT_ORIG_NODE_CHOICE_LATEST == choice_stragety)
    {
        return (const char *)"LATEST";
    }  

    if(CDETECT_ORIG_NODE_CHOICE_MS == choice_stragety)
    {
        return (const char *)"MS";
    }    

    return (const char *)"ERR";
}

STATIC_CAST static EC_BOOL __cdetect_parse_ip_node(CLIST *cdetect_ip_nodes, char *ip)
{
    char                *segs[ 2 ];
    uint32_t             segs_num;

    segs_num = c_str_split(ip, (const char *)":", segs, sizeof(segs)/sizeof(segs[ 0 ]));
    if(1 != segs_num && 2 != segs_num)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_ip_node: "
                                                "invalid segs num: %u\n", 
                                                segs_num);
        return (EC_FALSE);    
    }
    
    if(1 == segs_num)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;

        c_str_trim_space(segs[ 0 ]);
        if(EC_FALSE == c_ipv4_is_ok(segs[ 0 ]))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_ip_node: "
                                                    "invalid ip '%s'\n",
                                                    segs[ 0 ]);
            return (EC_FALSE);
        }
        
        cdetect_ip_node = cdetect_ip_node_new();
        if(NULL_PTR == cdetect_ip_node)
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_ip_node: "
                                                    "new cdetect_ip_node failed\n");
            return (EC_FALSE);
        }

        CDETECT_IP_NODE_IPADDR(cdetect_ip_node) = c_ipv4_to_word(segs[ 0 ]);
        CDETECT_IP_NODE_PORT(cdetect_ip_node)   = CDETECT_IP_NODE_PORT_DEFAULT;
        CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_REACHABLE; /*default*/

        clist_push_back(cdetect_ip_nodes, (void *)cdetect_ip_node);
        
        return (EC_TRUE);
    }
    
    if(2 == segs_num)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;

        c_str_trim_space(segs[ 0 ]);
        c_str_trim_space(segs[ 1 ]);
        
        if(EC_FALSE == c_ipv4_is_ok(segs[ 0 ]))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_ip_node: "
                                                    "invalid ip '%s'\n",
                                                    segs[ 0 ]);
            return (EC_FALSE);
        }
        
        cdetect_ip_node = cdetect_ip_node_new();
        if(NULL_PTR == cdetect_ip_node)
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_ip_node: "
                                                    "new cdetect_ip_node failed\n");
            return (EC_FALSE);
        }

        CDETECT_IP_NODE_IPADDR(cdetect_ip_node) = c_ipv4_to_word(segs[ 0 ]);
        CDETECT_IP_NODE_PORT(cdetect_ip_node)   = c_port_to_word(segs[ 1 ]);
        CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_REACHABLE; /*default*/

        clist_push_back(cdetect_ip_nodes, (void *)cdetect_ip_node);
        
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetect_parse_ip_nodes(CLIST *cdetect_ip_nodes, char *ips)
{
    char                *segs[ CDETECT_ORIG_NODE_MAX_IP_NODES ];
    uint32_t             segs_num;
    uint32_t             idx;

    segs_num = c_str_split(ips, (const char *)",", segs, sizeof(segs)/sizeof(segs[ 0 ]));
   
    for(idx = 0; idx < segs_num; idx ++)
    {
        c_str_trim_space(segs[ idx ]);
        if(EC_FALSE == __cdetect_parse_ip_node(cdetect_ip_nodes, segs[ idx ]))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_ip_nodes: "
                                                    "parse ip node failed\n");
            return (EC_FALSE);
        }
    }
    
    return (EC_TRUE);
}

/*format: domain | ip[:port][,...] | url | interval nsec | stopping nsec | reachable status | forbidden status | strategy */
STATIC_CAST static EC_BOOL __cdetect_parse_conf_line(const UINT32 cdetect_md_id, char *cdetect_conf_start, char *cdetect_conf_end)
{
    CDETECT_MD          *cdetect_md;
    CDETECT_ORIG_NODE   *cdetect_orig_node;
    CRB_NODE            *crb_node;
    
    char                *segs[ 8 ];
    char                *p;
    uint32_t             segs_num;
    uint32_t             idx;
    UINT32               domain_hash;
    
    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    /*locate the first char which is not space*/
    
    for(p = cdetect_conf_start;isspace(*p); p ++) 
    {
        /*do nothing*/
    }                               
    
    if('\0' == (*p))
    {
        dbg_log(SEC_0043_CDETECT, 6)(LOGSTDOUT, "[DEBUG] __cdetect_parse_conf_line: "
                                                "skip empty line '%.*s'\n",
                                                (cdetect_conf_end - cdetect_conf_start), 
                                                cdetect_conf_start);      
        /*skip empty line*/
        return (EC_TRUE);
    }
    
    if('#' == (*p))
    {
        /*skip commented line*/
        dbg_log(SEC_0043_CDETECT, 6)(LOGSTDOUT, "[DEBUG] __cdetect_parse_conf_line: "
                                                "skip commented line '%.*s'\n",
                                                (cdetect_conf_end - cdetect_conf_start), 
                                                cdetect_conf_start);          
        return (EC_TRUE);
    }

    dbg_log(SEC_0043_CDETECT, 6)(LOGSTDOUT, "[DEBUG] __cdetect_parse_conf_line: "
                                            "handle line '%.*s'\n",
                                            (cdetect_conf_end - cdetect_conf_start), 
                                            cdetect_conf_start);      
    
    segs_num = sizeof(segs)/sizeof(segs[ 0 ]);
    if(segs_num != c_str_split(cdetect_conf_start, (const char *)"|", segs, segs_num))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_conf_line: "
                                                "unable to split '%.*s' into %u segs\n",
                                                (cdetect_conf_end - cdetect_conf_start), 
                                                cdetect_conf_start,
                                                segs_num);    
        return (EC_FALSE);
    }

    for(idx = 0; idx < segs_num; idx ++)
    {
        c_str_trim_space(segs[ idx ]);
    }

    cdetect_orig_node = cdetect_orig_node_new();
    if(NULL_PTR == cdetect_orig_node)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_conf_line: "
                                                "new cdetect_orig_node failed\n");
        return (EC_FALSE);
    }

    domain_hash = CDETECT_ORIG_NODE_DOMAIN_HASH_ALGO(strlen(segs[ 0 ]), (const uint8_t *)segs[ 0 ]);
    
    cstring_init(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node), (const uint8_t *)segs[ 0 ]);
    if(EC_FALSE == __cdetect_parse_ip_nodes(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), segs[ 1 ]))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_conf_line: "
                                                "parse ips '%s' failed\n",
                                                segs[ 1 ]);
                        
        cdetect_orig_node_free(cdetect_orig_node);                
        return (EC_FALSE);
    }

    if(0 != STRCMP(segs[ 2 ], "-"))/*url is not configured*/
    {
        cstring_init(CDETECT_ORIG_NODE_URL(cdetect_orig_node), (const uint8_t *)segs[ 2 ]);
    }
    
    CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node) = c_str_to_uint32_t(segs[ 3 ]);
    CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node) = c_str_to_uint32_t(segs[ 4 ]);
    
    CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node) = c_str_to_uint32_t(segs[ 5 ]);
    CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node) = c_str_to_uint32_t(segs[ 6 ]);

    if(0 != STRCMP(segs[ 7 ], "-")) /*strategy is not configured*/
    {
        CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)  = __cdetect_choice_strategy(segs[ 7 ]);
    }
    CDETECT_ORIG_NODE_DOMAIN_HASH(cdetect_orig_node)      = (uint32_t)domain_hash;
    
    crb_node = crb_tree_insert_data(CDETECT_MD_ORIG_NODE_TREE(cdetect_md), (void *)cdetect_orig_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_conf_line: "
                                                "insert '%s' failed\n",
                                                segs[ 0 ]);
                        
        cdetect_orig_node_free(cdetect_orig_node);                
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cdetect_orig_node)/*found duplicate*/
    {
        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_parse_conf_line: "
                                                "ignore duplicate '%s'\n",
                                                segs[ 0 ]);
                        
        cdetect_orig_node_free(cdetect_orig_node);                
        return (EC_TRUE);
    }

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_parse_conf_line: "
                                            "insert '%s' done\n",
                                            segs[ 0 ]);    
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetect_parse_conf_file(const UINT32 cdetect_md_id, char *cdetect_conf_start, char *cdetect_conf_end)
{
    char        *cdetect_conf_line_start;
    uint32_t     cdetect_conf_line_no;

    cdetect_conf_line_start = cdetect_conf_start;
    cdetect_conf_line_no    = 1;
    
    while(cdetect_conf_line_start < cdetect_conf_end)
    {
        char  *cdetect_conf_line_end;

        cdetect_conf_line_end = cdetect_conf_line_start;
        
        while(cdetect_conf_line_end < cdetect_conf_end)
        {
            if('\n' == (*cdetect_conf_line_end ++)) /*also works for line-terminator '\r\n'*/
            {
                break;
            }
        }

        if(cdetect_conf_line_end > cdetect_conf_end)
        {
            break;
        }

        *(cdetect_conf_line_end - 1) = '\0'; /*insert string terminator*/

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "error:__cdetect_parse_conf_file: "
                                                "to parse line %u# '%.*s' failed\n",
                                                cdetect_conf_line_no, 
                                                (cdetect_conf_line_end - cdetect_conf_line_start), 
                                                cdetect_conf_line_start);
                                                
        if(EC_FALSE == __cdetect_parse_conf_line(cdetect_md_id, cdetect_conf_line_start, cdetect_conf_line_end))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_parse_conf_file: "
                                                    "parse line %u# '%.*s' failed\n",
                                                    cdetect_conf_line_no, 
                                                    (cdetect_conf_line_end - cdetect_conf_line_start), 
                                                    cdetect_conf_line_start);
            return (EC_FALSE);          
        }

        cdetect_conf_line_no ++;

        cdetect_conf_line_start = cdetect_conf_line_end;
    }
    
    return (EC_TRUE);
}

/**
*
*  load detect conf
*
*
**/
EC_BOOL cdetect_load_conf(const UINT32 cdetect_md_id, const CSTRING *cdetect_conf_file)
{
    CDETECT_MD  *cdetect_md;

    UINT32       fsize;
    UINT32       offset;
    UINT8       *fcontent;
    int          fd;

#if ( SWITCH_ON == CDETECT_DEBUG_SWITCH )
    if ( CDETECT_MD_ID_CHECK_INVALID(cdetect_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetect_load_conf: cdetect module #0x%lx not started.\n",
                cdetect_md_id);
        cdetect_print_module_status(cdetect_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECT, cdetect_md_id);
    }
#endif/*CDETECT_DEBUG_SWITCH*/

    cdetect_md = CDETECT_MD_GET(cdetect_md_id);

    fd = c_file_open((char *)cstring_get_str(cdetect_conf_file), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_load_conf: "
                                                "open file '%s' failed\n",
                                                (char *)cstring_get_str(cdetect_conf_file));
        return (EC_FALSE);                     
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_load_conf: "
                                                "get size of '%s' failed\n",
                                                (char *)cstring_get_str(cdetect_conf_file));    
        c_file_close(fd);
        return (EC_FALSE);
    }

    if(0 == fsize)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_load_conf: "
                                                "file '%s' size is 0\n",
                                                (char *)cstring_get_str(cdetect_conf_file));    
        c_file_close(fd);
        return (EC_FALSE);
    }

    fcontent = safe_malloc(fsize, LOC_CDETECT_0007);
    if(NULL_PTR == fcontent)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_load_conf: "
                                                "malloc %ld bytes failed\n",
                                                fsize);    
        c_file_close(fd);
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, fcontent))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_load_conf: "
                                                "load file '%s' failed\n",
                                                (char *)cstring_get_str(cdetect_conf_file));    
        c_file_close(fd);
        safe_free(fcontent, LOC_CDETECT_0008);
        return (EC_FALSE);
    }
    c_file_close(fd);

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_load_conf: "
                                            "load file '%s' from disk done\n",
                                            (char *)cstring_get_str(cdetect_conf_file));  

    /*parse*/
    if(EC_FALSE == __cdetect_parse_conf_file(cdetect_md_id, (char *)fcontent, (char *)(fcontent + fsize)))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_load_conf: "
                                                "parse conf file '%s' failed\n",
                                                (char *)cstring_get_str(cdetect_conf_file));    
        safe_free(fcontent, LOC_CDETECT_0009);
        return (EC_FALSE);
    }
    safe_free(fcontent, LOC_CDETECT_0010);

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_load_conf: "
                                            "parse conf file '%s' done\n",
                                            (char *)cstring_get_str(cdetect_conf_file));     
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetect_dns_resolve_orig_node_choice_ms(CDETECT_ORIG_NODE *cdetect_orig_node, UINT32 *ipaddr)
{
    CLIST_DATA          *clist_data;
    
    /*always search from head to tail. the master orig is at the first one*/
    CLIST_LOOP_NEXT(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), clist_data)
    {   
        CDETECT_IP_NODE     *cdetect_ip_node;
        
        cdetect_ip_node = (CDETECT_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECT_IP_NODE_STATUS_REACHABLE == CDETECT_IP_NODE_STATUS(cdetect_ip_node))
        {
            /*the first reachable ip*/
            (*ipaddr) = CDETECT_IP_NODE_IPADDR(cdetect_ip_node);

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_dns_resolve_orig_node_choice_ms: "
                                                    "[MS] domain '%s' => ip '%s'\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node));              
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetect_dns_resolve_orig_node_choice_rrb(CDETECT_ORIG_NODE *cdetect_orig_node, UINT32 *ipaddr)
{
    CLIST_DATA          *clist_data;

    /*always search from head to tail. generally the reachable orig should be at the first one*/
    CLIST_LOOP_NEXT(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), clist_data)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;
        
        cdetect_ip_node = (CDETECT_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECT_IP_NODE_STATUS_REACHABLE == CDETECT_IP_NODE_STATUS(cdetect_ip_node))
        {
            /*the first reachable ip.*/
            (*ipaddr) = CDETECT_IP_NODE_IPADDR(cdetect_ip_node);

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_dns_resolve_orig_node_choice_rrb: "
                                                    "[RRB] domain '%s' => ip '%s'\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node));              
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetect_dns_resolve_orig_node_choice_fast(CDETECT_ORIG_NODE *cdetect_orig_node, UINT32 *ipaddr)
{
    CLIST_DATA          *clist_data;
    CDETECT_IP_NODE     *cdetect_ip_node_fast;

    cdetect_ip_node_fast = NULL_PTR;

    CLIST_LOOP_NEXT(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), clist_data)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;
        
        cdetect_ip_node = (CDETECT_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECT_IP_NODE_STATUS_REACHABLE != CDETECT_IP_NODE_STATUS(cdetect_ip_node))
        {
            continue;
        }

        if(NULL_PTR == cdetect_ip_node_fast)
        {
            cdetect_ip_node_fast = cdetect_ip_node;
            continue;
        }

        /*compare time-cost*/
        if(CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node_fast) > CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node))
        {
            cdetect_ip_node_fast = cdetect_ip_node;
        }
    }

    if(NULL_PTR != cdetect_ip_node_fast)
    {
        /*the fast ip.*/
        (*ipaddr) = CDETECT_IP_NODE_IPADDR(cdetect_ip_node_fast);

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_dns_resolve_orig_node_choice_fast: "
                                                "[FALST] domain '%s' => ip '%s'\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node_fast)
                            );      
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetect_dns_resolve_orig_node_choice_latest(CDETECT_ORIG_NODE *cdetect_orig_node, UINT32 *ipaddr)
{   
    CLIST_DATA          *clist_data;
    CLIST_DATA          *clist_data_latest;

    clist_data_latest = CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node);
    if(NULL_PTR != clist_data_latest)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;

        clist_data_latest = CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node);
        cdetect_ip_node   = (CDETECT_IP_NODE *)CLIST_DATA_DATA(clist_data_latest);  

        if(CDETECT_IP_NODE_STATUS_REACHABLE == CDETECT_IP_NODE_STATUS(cdetect_ip_node))
        {
            /*the latest ip.*/
            (*ipaddr) = CDETECT_IP_NODE_IPADDR(cdetect_ip_node);

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_dns_resolve_orig_node_choice_latest: "
                                                    "[LATEST] domain '%s' => ip '%s'\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node)
                                );      
            return (EC_TRUE);
        }        
    }

    CLIST_LOOP_NEXT(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), clist_data)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;

        if(clist_data == clist_data_latest)
        {
            continue;
        }
        
        cdetect_ip_node = (CDETECT_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECT_IP_NODE_STATUS_REACHABLE == CDETECT_IP_NODE_STATUS(cdetect_ip_node))
        {
            /*the reachable ip.*/
            (*ipaddr) = CDETECT_IP_NODE_IPADDR(cdetect_ip_node);

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_dns_resolve_orig_node_choice_latest: "
                                                    "[LATEST] domain '%s' => reachable ip '%s'\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node)
                                );        
            return (EC_TRUE);
        }
    }
    
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetect_dns_resolve_orig_node_choice_default(CDETECT_ORIG_NODE *cdetect_orig_node, UINT32 *ipaddr)
{   
    CDETECT_IP_NODE     *cdetect_ip_node;

    cdetect_ip_node = clist_first_data(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node));
    if(NULL_PTR != cdetect_ip_node)
    {
        /*the reachable ip.*/
        (*ipaddr) = CDETECT_IP_NODE_IPADDR(cdetect_ip_node);

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_dns_resolve_orig_node_choice_default: "
                                                "[default] domain '%s' => first ip '%s'\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node)
                            );       
        return (EC_TRUE);
    }

    return (EC_FALSE);
}
STATIC_CAST static EC_BOOL __cdetect_dns_resolve_orig_node(CDETECT_ORIG_NODE *cdetect_orig_node, UINT32 *ipaddr)
{
    if(CDETECT_ORIG_NODE_CHOICE_MS == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)
    && EC_TRUE == __cdetect_dns_resolve_orig_node_choice_ms(cdetect_orig_node, ipaddr))
    {
        return (EC_TRUE);
    } 

    if(CDETECT_ORIG_NODE_CHOICE_RRB == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)
    && EC_TRUE == __cdetect_dns_resolve_orig_node_choice_rrb(cdetect_orig_node, ipaddr))
    {
        return (EC_TRUE);
    }

    if(CDETECT_ORIG_NODE_CHOICE_FAST == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)
    && EC_TRUE == __cdetect_dns_resolve_orig_node_choice_fast(cdetect_orig_node, ipaddr))
    {
        return (EC_TRUE);
    } 

    if(CDETECT_ORIG_NODE_CHOICE_LATEST == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node)
    && EC_TRUE == __cdetect_dns_resolve_orig_node_choice_latest(cdetect_orig_node, ipaddr))
    {
        return (EC_TRUE);
    } 

    return __cdetect_dns_resolve_orig_node_choice_default(cdetect_orig_node, ipaddr);
}


/**
*
*  dns resolve
*
**/
EC_BOOL cdetect_dns_resolve(const UINT32 cdetect_md_id, const CSTRING *domain, UINT32 *ipaddr)
{
    CDETECT_MD          *cdetect_md;

    CDETECT_ORIG_NODE   *cdetect_orig_node;
    
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

    cdetect_orig_node = __cdetect_search_orig_node(cdetect_md_id, domain);
    if(NULL_PTR == cdetect_orig_node)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_dns_resolve: "
                                                "domain '%s' not configured\n",
                                                (char *)cstring_get_str(domain));      
        return (EC_FALSE);
    }

    /*update access time*/
    CDETECT_ORIG_NODE_LAST_ACCESS_TIME(cdetect_orig_node) = task_brd_default_get_time();

    if(EC_TRUE == clist_is_empty(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node)))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_dns_resolve: "
                                                "domain '%s' has no ip configured\n",
                                                (char *)cstring_get_str(domain));      
        return (EC_FALSE);
    }

    /*add to detect due to the domain is accessed*/
    if(NULL_PTR == CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node)
    && EC_FALSE == cstring_is_empty(CDETECT_ORIG_NODE_URL(cdetect_orig_node)))
    {
        CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node) = 
                    clist_push_back(CDETECT_MD_DETECT_NODE_LIST(cdetect_md), (void *)cdetect_orig_node);
    }    

    if(EC_FALSE == __cdetect_dns_resolve_orig_node(cdetect_orig_node, ipaddr))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0043_CDETECT, 5)(LOGSTDOUT, "[DEBUG] cdetect_dns_resolve: "
                                            "domain '%s' => ip '%s'\n",
                                            (char *)cstring_get_str(domain),
                                            c_word_to_ipv4(*ipaddr)); 
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetect_request(const CSTRING *domain, const CSTRING *uri, const UINT32 ipaddr, const UINT32 port, 
                                     UINT32 *detect_task_num, uint32_t *status)
{
    CHTTP_REQ            chttp_req;
    CHTTP_RSP            chttp_rsp;
    CHTTP_STAT           chttp_stat; /*statistics. e.g. for billing*/

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);
    chttp_stat_init(&chttp_stat);

    chttp_req_set_ipaddr_word(&chttp_req, ipaddr);
    chttp_req_set_port_word(&chttp_req, port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    cstring_clone(uri, CHTTP_REQ_URI(&chttp_req));

    chttp_req_add_header(&chttp_req, (const char *)"Host" , (const char *)cstring_get_str(domain));
    chttp_req_add_header(&chttp_req, (const char *)"Connection"    , (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    (*detect_task_num) ++;
    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, &chttp_stat))
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_request: "
                                                "request domain '%s', uri '%s', ip '%s' port '%ld' failed\n",
                                                (const char *)cstring_get_str(domain),
                                                (const char *)cstring_get_str(uri),
                                                c_word_to_ipv4(ipaddr), 
                                                port);    


        (*detect_task_num) --;
        
        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        chttp_stat_clean(&chttp_stat);
        return (EC_FALSE);
    }
    (*detect_task_num) --;

    (*status) = CHTTP_RSP_STATUS(&chttp_rsp);

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);
    chttp_stat_clean(&chttp_stat);
    return (EC_TRUE);
}


STATIC_CAST static EC_BOOL __cdetect_start_orig_node_choice_ms(CDETECT_ORIG_NODE   *cdetect_orig_node, UINT32 *detect_task_num)
{
    CLIST_DATA          *clist_data;

    /*the first one is master orig. always start from the master orig*/
    CLIST_LOOP_NEXT(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), clist_data)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;

        uint32_t             status;
        
        /*the first one is master orig*/
        cdetect_ip_node = CLIST_DATA_DATA(clist_data);    

        if(EC_FALSE == __cdetect_request(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node), 
                                         CDETECT_ORIG_NODE_URL(cdetect_orig_node),
                                         CDETECT_IP_NODE_IPADDR(cdetect_ip_node),
                                         CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                         detect_task_num,
                                         &status))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "warn:__cdetect_start_orig_node_choice_ms: "
                                                    "[MS] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));      
            continue;
        }

        if(status == CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_ms: "
                                                    "[MS] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 
            return (EC_TRUE);
        }

        if(status == CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_FORBIDDEN;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_ms: "
                                                    "[MS] (domain '%s', ip '%s', port '%ld') forbidden\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 
            continue;
        }    

        CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_ms: "
                                                "[MS] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                                status);

        /*loop next one*/
    }

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_start_orig_node_choice_ms: "
                                            "[MS] detect domain '%s' failed\n",
                                            (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node));  
    /*none succ*/
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetect_start_orig_node_choice_rrb(CDETECT_ORIG_NODE   *cdetect_orig_node, UINT32 *detect_task_num)
{
    UINT32               node_num;
    UINT32               node_idx;

    node_num = clist_size(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node));
    for(node_idx = 0; node_idx < node_num; node_idx ++)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;
        uint32_t             status;
        
        cdetect_ip_node = clist_first_data(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node));

        if(EC_FALSE == __cdetect_request(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node), 
                                         CDETECT_ORIG_NODE_URL(cdetect_orig_node),
                                         CDETECT_IP_NODE_IPADDR(cdetect_ip_node),
                                         CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                         detect_task_num,
                                         &status))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_start_orig_node_choice_rrb: "
                                                    "[RRB] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));      

            /*move to tail*/
            clist_pop_front(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node));
            clist_push_back(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), (void *)cdetect_ip_node);
            continue;
        }        

        if(status == CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_rrb: "
                                                    "[RRB] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 
            return (EC_TRUE);
        }

        if(status == CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_FORBIDDEN;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_rrb: "
                                                    "[RRB] (domain '%s', ip '%s', port '%ld') forbidden\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 

            /*move to tail*/
            clist_pop_front(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node));
            clist_push_back(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), (void *)cdetect_ip_node);
            continue;
        }    

        CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_ERR;  
        
        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_rrb: "
                                                "[RRB] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                                status);
         
        /*move to tail*/
        clist_pop_front(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node));
        clist_push_back(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), (void *)cdetect_ip_node);
    }

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_start_orig_node_choice_rrb: "
                                            "[RRB] detect domain '%s' failed\n",
                                            (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node));      

    /*none succ*/
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetect_start_orig_node_choice_fast(CDETECT_ORIG_NODE   *cdetect_orig_node, UINT32 *detect_task_num)
{
    CLIST_DATA          *clist_data;
    EC_BOOL              flag; /*true: indicate someone node is reachable, false: none is reachable*/

    flag = EC_FALSE;
    
    /*the first one is master orig. always start from the master orig*/
    CLIST_LOOP_NEXT(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), clist_data)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;

        uint32_t             status;
        
        uint32_t             start_nsec;
        uint32_t             start_msec;
        
        cdetect_ip_node = CLIST_DATA_DATA(clist_data);    

        /*record start time*/
        start_nsec = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());
        start_msec = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());
        
        if(EC_FALSE == __cdetect_request(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node), 
                                         CDETECT_ORIG_NODE_URL(cdetect_orig_node),
                                         CDETECT_IP_NODE_IPADDR(cdetect_ip_node),
                                         CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                         detect_task_num,
                                         &status))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "warn:__cdetect_start_orig_node_choice_fast: "
                                                    "[FAST] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));      
            continue;
        }

        if(status == CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node))
        {
            uint32_t             end_nsec;
            uint32_t             end_msec;
        
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_REACHABLE;
            flag = EC_TRUE;

            end_nsec = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());
            end_msec = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());

            CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node) = (end_nsec - start_nsec) * 1000 + (end_msec - start_msec);

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_fast: "
                                                    "[FAST] (domain '%s', ip '%s', port '%ld') reachable, cost %u ms\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                                    CDETECT_IP_NODE_DETECT_COST_MSEC(cdetect_ip_node));                 
            continue;
        }

        if(status == CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_FORBIDDEN;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_fast: "
                                                    "[FAST] (domain '%s', ip '%s', port '%ld') forbidden\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 
            continue;
        }    

        CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_fast: "
                                                "[FAST] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                                status);

        /*loop next one*/
    }

    if(EC_FALSE == flag)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_start_orig_node_choice_fast: "
                                                "[FAST] detect domain '%s' failed\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node));  
        /*none succ*/
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetect_start_orig_node_choice_latest(CDETECT_ORIG_NODE   *cdetect_orig_node, UINT32 *detect_task_num)
{
    CLIST_DATA      *clist_data;

    clist_data = CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node);
    while(NULL_PTR != clist_data)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;
        uint32_t             status;
        
        cdetect_ip_node = CLIST_DATA_DATA(clist_data); 

        if(EC_FALSE == __cdetect_request(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node), 
                                         CDETECT_ORIG_NODE_URL(cdetect_orig_node),
                                         CDETECT_IP_NODE_IPADDR(cdetect_ip_node),
                                         CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                         detect_task_num,
                                         &status))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "warn:__cdetect_start_orig_node_choice_latest: "
                                                    "[LATEST] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));      
            
            break; /*fall through*/
        }        

        if(status == CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_latest: "
                                                    "[LATEST] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 
            return (EC_TRUE);
        }

        if(status == CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_FORBIDDEN;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_latest: "
                                                    "[LATEST] (domain '%s', ip '%s', port '%ld') forbidden\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 
            break;/*fall through*/
        }    

        CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_latest: "
                                                "[LATEST] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                                status);
        break;/*fall through*/
    }

    CLIST_LOOP_NEXT(CDETECT_ORIG_NODE_IP_NODES(cdetect_orig_node), clist_data)
    {
        CDETECT_IP_NODE     *cdetect_ip_node;
        uint32_t             status;
        
        if(clist_data == CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node))
        {   
            /*already detected, skip it*/
            continue;
        }

        cdetect_ip_node = CLIST_DATA_DATA(clist_data); 

        if(EC_FALSE == __cdetect_request(CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node), 
                                         CDETECT_ORIG_NODE_URL(cdetect_orig_node),
                                         CDETECT_IP_NODE_IPADDR(cdetect_ip_node),
                                         CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                         detect_task_num,
                                         &status))
        {
            dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "warn:__cdetect_start_orig_node_choice_latest: "
                                                    "[LATEST] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));      
            
            continue;
        }        

        if(status == CDETECT_ORIG_NODE_STATUS_REACHABLE(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_latest: "
                                                    "[LATEST] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 

            CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node) = clist_data; /*update*/
            return (EC_TRUE);
        }

        if(status == CDETECT_ORIG_NODE_STATUS_FORBIDDEN(cdetect_orig_node))
        {
            CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_FORBIDDEN;

            dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_latest: "
                                                    "[LATEST] (domain '%s', ip '%s', port '%ld') forbidden\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                    CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                    CDETECT_IP_NODE_PORT(cdetect_ip_node));                 
            continue;
        }    

        CDETECT_IP_NODE_STATUS(cdetect_ip_node) = CDETECT_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] __cdetect_start_orig_node_choice_latest: "
                                                "[LATEST] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node),
                                                CDETECT_IP_NODE_IPADDR_STR(cdetect_ip_node),
                                                CDETECT_IP_NODE_PORT(cdetect_ip_node),
                                                status);        
    }

    CDETECT_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetect_orig_node) = NULL_PTR; /*clean*/

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:__cdetect_start_orig_node_choice_latest: "
                                            "[LATEST] detect domain '%s' failed\n",
                                            (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node)); 
    /*none succ*/
    return (EC_FALSE);
}

/**
*
*  start to detect domain
*
**/
EC_BOOL cdetect_start_domain(const UINT32 cdetect_md_id, const CSTRING *domain)
{
    CDETECT_MD          *cdetect_md;

    CDETECT_ORIG_NODE   *cdetect_orig_node;
    
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

    cdetect_orig_node = __cdetect_search_orig_node(cdetect_md_id, domain);
    if(NULL_PTR == cdetect_orig_node)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start_domain: "
                                                "domain '%s' not configured\n",
                                                (char *)cstring_get_str(domain));      
        return (EC_FALSE);
    }

    CDETECT_ORIG_NODE_LAST_DETECT_TIME(cdetect_orig_node) = task_brd_default_get_time();

    dbg_log(SEC_0043_CDETECT, 5)(LOGSTDOUT, "[DEBUG] cdetect_start_domain: "
                                            "domain '%s'\n",
                                            (char *)cstring_get_str(domain));  

    if(CDETECT_ORIG_NODE_CHOICE_MS == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node))
    {
        return __cdetect_start_orig_node_choice_ms(cdetect_orig_node, &(CDETECT_MD_DETECT_TASK_NUM(cdetect_md)));
    }

    if(CDETECT_ORIG_NODE_CHOICE_RRB == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node))
    {
        return __cdetect_start_orig_node_choice_rrb(cdetect_orig_node, &(CDETECT_MD_DETECT_TASK_NUM(cdetect_md)));
    }

    if(CDETECT_ORIG_NODE_CHOICE_FAST == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node))
    {
        return __cdetect_start_orig_node_choice_fast(cdetect_orig_node, &(CDETECT_MD_DETECT_TASK_NUM(cdetect_md)));
    }    

    if(CDETECT_ORIG_NODE_CHOICE_LATEST == CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node))
    {
        return __cdetect_start_orig_node_choice_latest(cdetect_orig_node, &(CDETECT_MD_DETECT_TASK_NUM(cdetect_md)));
    }    

    dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_start_domain: "
                                            "domain '%s' configured invalid strategy '%u'\n",
                                            (char *)cstring_get_str(domain),
                                            CDETECT_ORIG_NODE_CHOICE_STRATEGY(cdetect_orig_node));      
    return (EC_FALSE);
}

/**
*
*  stop to detect domain
*
**/
EC_BOOL cdetect_stop_domain(const UINT32 cdetect_md_id, const CSTRING *domain)
{
    CDETECT_MD          *cdetect_md;

    CDETECT_ORIG_NODE   *cdetect_orig_node;
   
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

    cdetect_orig_node = __cdetect_search_orig_node(cdetect_md_id, domain);
    if(NULL_PTR == cdetect_orig_node)
    {
        dbg_log(SEC_0043_CDETECT, 0)(LOGSTDOUT, "error:cdetect_stop_domain: "
                                                "domain '%s' not configured\n",
                                                (char *)cstring_get_str(domain));      
        return (EC_FALSE);
    }

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_stop_domain: "
                                            "stop to detect domain '%s'\n",
                                            (char *)cstring_get_str(domain)); 

    if(NULL_PTR != CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node))
    {
        clist_erase(CDETECT_MD_DETECT_NODE_LIST(cdetect_md), CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node));
        CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node) = NULL_PTR;
    }

    cdetect_orig_node_clear(cdetect_orig_node);    
    
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

    UINT32               detect_node_num;
    UINT32               detect_node_idx;

    TASK_BRD            *task_brd;
    
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

    detect_node_num = clist_size(CDETECT_MD_DETECT_NODE_LIST(cdetect_md));

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_process: "
                                            "detect_task_max_num = %ld, detect_node_num = %ld\n",
                                            detect_task_max_num,
                                            detect_node_num);

    task_brd = task_brd_default_get();
    for(detect_node_idx = 0; detect_node_idx < detect_node_num; detect_node_idx ++)
    {
        CDETECT_ORIG_NODE   *cdetect_orig_node;
        MOD_NODE             recv_mod_node;
        CLIST_DATA          *clist_data;

        rlog(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_process: "
                                             "[%ld] "
                                             "detect detect_task_max_num = %ld, "
                                             "detect_task_max_num = %ld, "
                                             "detect_node_num = %ld\n",
                                             detect_node_idx,
                                             CDETECT_MD_DETECT_TASK_NUM(cdetect_md),
                                             detect_task_max_num,
                                             detect_node_num);
                                            
        if(CDETECT_MD_DETECT_TASK_NUM(cdetect_md) >= detect_task_max_num)
        {
            break;/*terminate*/
        }

        /*move from head to tail with free and malloc. */
        /*do not change the mounted point (CDETECT_ORIG_NODE_DETECT_ORIG_NODE).*/
        clist_data = CLIST_FIRST_NODE(CDETECT_MD_DETECT_NODE_LIST(cdetect_md));
        clist_move_back(CDETECT_MD_DETECT_NODE_LIST(cdetect_md), clist_data);

        cdetect_orig_node = CLIST_DATA_DATA(clist_data);
        ASSERT(CDETECT_ORIG_NODE_DETECT_ORIG_NODE(cdetect_orig_node) == clist_data);

        /*if none access in stopping interval, then stop detecting*/
        if(EC_TRUE == cdetect_orig_node_need_stop_detecting(cdetect_orig_node))
        {
            rlog(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_process: "
                                                    "stop to detect domain '%s' due to stopping interval (%u sec)\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node), 
                                                    CDETECT_ORIG_NODE_DETECT_STOPPING_NSEC(cdetect_orig_node)); 

            cdetect_stop_domain(cdetect_md_id, CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node));
            continue;
        }

        /*if next detecting time not reached, then give up detecting this time*/
        if(EC_TRUE == cdetect_orig_node_need_skip_detecting(cdetect_orig_node))
        {
            rlog(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_process: "
                                                    "give up detecting domain '%s' due to detect interval (%u sec)\n",
                                                    (char *)CDETECT_ORIG_NODE_DOMAIN_STR(cdetect_orig_node), 
                                                    CDETECT_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetect_orig_node));     

            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = cdetect_md_id;
        
        task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                 &recv_mod_node,
                 NULL_PTR,
                 FI_cdetect_start_domain, CMPI_ERROR_MODI, CDETECT_ORIG_NODE_DOMAIN(cdetect_orig_node));
    }

    dbg_log(SEC_0043_CDETECT, 9)(LOGSTDOUT, "[DEBUG] cdetect_process: "
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
    TASK_BRD       *task_brd;
    MOD_NODE        recv_mod_node;

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


