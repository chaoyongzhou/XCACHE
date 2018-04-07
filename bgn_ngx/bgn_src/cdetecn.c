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

#include "findex.inc"


#define CDETECTN_MD_CAPACITY()                  (cbc_md_capacity(MD_CDETECTN))

#define CDETECTN_MD_GET(cdetectn_md_id)     ((CDETECTN_MD *)cbc_md_get(MD_CDETECTN, (cdetectn_md_id)))

#define CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id)  \
    ((CMPI_ANY_MODI != (cdetectn_md_id)) && ((NULL_PTR == CDETECTN_MD_GET(cdetectn_md_id)) || (0 == (CDETECTN_MD_GET(cdetectn_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CDETECTN Module
*
**/
void cdetectn_print_module_status(const UINT32 cdetectn_md_id, LOG *log)
{
    CDETECTN_MD *cdetectn_md;
    UINT32 this_cdetectn_md_id;

    for( this_cdetectn_md_id = 0; this_cdetectn_md_id < CDETECTN_MD_CAPACITY(); this_cdetectn_md_id ++ )
    {
        cdetectn_md = CDETECTN_MD_GET(this_cdetectn_md_id);

        if ( NULL_PTR != cdetectn_md && 0 < cdetectn_md->usedcounter )
        {
            sys_log(log,"CDETECTN Module # %ld : %ld refered\n",
                    this_cdetectn_md_id,
                    cdetectn_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CDETECTN module
*
*
**/
UINT32 cdetectn_free_module_static_mem(const UINT32 cdetectn_md_id)
{
    CDETECTN_MD  *cdetectn_md;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_free_module_static_mem: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    free_module_static_mem(MD_CDETECTN, cdetectn_md_id);

    return 0;
}

/**
*
* start CDETECTN module
*
**/
UINT32 cdetectn_start()
{
    CDETECTN_MD *cdetectn_md;
    UINT32      cdetectn_md_id;

    cbc_md_reg(MD_CDETECTN , 2);

    cdetectn_md_id = cbc_md_new(MD_CDETECTN, sizeof(CDETECTN_MD));
    if(CMPI_ERROR_MODI == cdetectn_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CDETECTN module */
    cdetectn_md = (CDETECTN_MD *)cbc_md_get(MD_CDETECTN, cdetectn_md_id);
    cdetectn_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    crb_tree_init(CDETECTN_MD_ORIG_NODE_TREE(cdetectn_md),
                  (CRB_DATA_CMP)cdetectn_orig_node_cmp,
                  (CRB_DATA_FREE)cdetectn_orig_node_free,
                  (CRB_DATA_PRINT)cdetectn_orig_node_print);

    clist_init(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md), MM_UINT32, LOC_CDETECN_0001);

    CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md) = 0;

    cdetectn_md->usedcounter = 1;

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cdetectn_end, cdetectn_md_id);

    dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "[DEBUG] cdetectn_start: "
                                             "start CDETECTN module #%ld\n",
                                             cdetectn_md_id);

    return ( cdetectn_md_id );
}

/**
*
* end CDETECTN module
*
**/
void cdetectn_end(const UINT32 cdetectn_md_id)
{
    CDETECTN_MD *cdetectn_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cdetectn_end, cdetectn_md_id);

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);
    if(NULL_PTR == cdetectn_md)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_end: "
                                                 "cdetectn_md_id = %ld not exist.\n",
                                                 cdetectn_md_id);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cdetectn_md->usedcounter )
    {
        cdetectn_md->usedcounter --;
        return ;
    }

    if ( 0 == cdetectn_md->usedcounter )
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_end: "
                                                 "cdetectn_md_id = %ld is not started.\n",
                                                 cdetectn_md_id);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }

    crb_tree_clean(CDETECTN_MD_ORIG_NODE_TREE(cdetectn_md));
    clist_clean(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md), NULL_PTR);

    CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md) = 0;

    /* free module : */
    //cdetectn_free_module_static_mem(cdetectn_md_id);

    cdetectn_md->usedcounter = 0;

    dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "cdetectn_end: stop CDETECTN module #%ld\n", cdetectn_md_id);
    cbc_md_free(MD_CDETECTN, cdetectn_md_id);

    return ;
}

/*------------------------------------------------ interface for cdetectn orig node ------------------------------------------------*/
CDETECTN_ORIG_NODE *cdetectn_orig_node_new()
{
    CDETECTN_ORIG_NODE *cdetectn_orig_node;

    alloc_static_mem(MM_CDETECTN_ORIG_NODE, &cdetectn_orig_node, LOC_CDETECN_0002);
    if(NULL_PTR != cdetectn_orig_node)
    {
        cdetectn_orig_node_init(cdetectn_orig_node);
    }
    return (cdetectn_orig_node);
}

EC_BOOL cdetectn_orig_node_init(CDETECTN_ORIG_NODE *cdetectn_orig_node)
{
    cstring_init(CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node), NULL_PTR);
    cstring_init(CDETECTN_ORIG_NODE_URL(cdetectn_orig_node), NULL_PTR);
    clist_init(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), MM_CDETECTN_IP_NODE, LOC_CDETECN_0003);

    CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node)    = 0;
    CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node)    = 0;

    CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)    = CHTTP_OK;        /*default*/
    CDETECTN_ORIG_NODE_REACHABLE_STATUS_END(cdetectn_orig_node)    = CHTTP_OK;        /*default*/
    CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)         = CDETECTN_ORIG_NODE_CHOICE_LATEST;/*default*/
    CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node)             = 0;

    CDETECTN_ORIG_NODE_LAST_DETECT_TIME(cdetectn_orig_node)        = 0;
    CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node)        = 0;
    CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node)  = NULL_PTR;

    CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node)        = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdetectn_orig_node_clean(CDETECTN_ORIG_NODE *cdetectn_orig_node)
{
    cstring_clean(CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node));
    cstring_clean(CDETECTN_ORIG_NODE_URL(cdetectn_orig_node));
    clist_clean(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), (CLIST_DATA_DATA_CLEANER)cdetectn_ip_node_free);

    CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node)    = 0;
    CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node)    = 0;

    CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)    = CHTTP_OK;        /*default*/
    CDETECTN_ORIG_NODE_REACHABLE_STATUS_END(cdetectn_orig_node)    = CHTTP_OK;        /*default*/

    CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)         = CDETECTN_ORIG_NODE_CHOICE_LATEST;/*default*/
    CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node)             = 0;

    CDETECTN_ORIG_NODE_LAST_DETECT_TIME(cdetectn_orig_node)        = 0;
    CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node)        = 0;
    CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node)  = NULL_PTR;

    CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node)        = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL cdetectn_orig_node_clear(CDETECTN_ORIG_NODE *cdetectn_orig_node)
{
    //cstring_clean(CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node));
    //cstring_clean(CDETECTN_ORIG_NODE_URL(cdetectn_orig_node));
    //clist_clean(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), (CLIST_DATA_DATA_CLEANER)cdetectn_ip_node_free);

    //CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node)    = 0;
    //CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node)    = 0;

    CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)    = CHTTP_OK;        /*default*/
    CDETECTN_ORIG_NODE_REACHABLE_STATUS_END(cdetectn_orig_node)    = CHTTP_OK;        /*default*/
    
    CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)         = CDETECTN_ORIG_NODE_CHOICE_LATEST;/*default*/
    //CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node)             = 0;

    CDETECTN_ORIG_NODE_LAST_DETECT_TIME(cdetectn_orig_node)        = 0;
    CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node)        = 0;
    CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node)  = NULL_PTR;

    CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node)        = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL cdetectn_orig_node_free(CDETECTN_ORIG_NODE *cdetectn_orig_node)
{
    if(NULL_PTR != cdetectn_orig_node)
    {
        cdetectn_orig_node_clean(cdetectn_orig_node);
        free_static_mem(MM_CDETECTN_ORIG_NODE, cdetectn_orig_node, LOC_CDETECN_0004);
    }
    return (EC_TRUE);
}

int cdetectn_orig_node_cmp(const CDETECTN_ORIG_NODE *cdetectn_orig_node_1st, const CDETECTN_ORIG_NODE *cdetectn_orig_node_2nd)
{
    if(CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node_1st) > CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node_2nd))
    {
        return (1);
    }

    if(CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node_1st) < CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node_2nd))
    {
        return (-1);
    }

    return cstring_cmp(CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node_1st), CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node_2nd));
}

void cdetectn_orig_node_print(LOG *log, const CDETECTN_ORIG_NODE *cdetectn_orig_node)
{
    if(NULL_PTR != cdetectn_orig_node)
    {
        sys_log(log, "cdetectn_orig_node_print %p: domain %s (hash %u), url: %s, "
                     "interval %u sec, stopping %u sec, ip list: \n",
                     cdetectn_orig_node,
                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                     CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node),
                     (char *)CDETECTN_ORIG_NODE_URL_STR(cdetectn_orig_node),
                     CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node),
                     CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node));

        clist_print(log, CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node),(CLIST_DATA_DATA_PRINT)cdetectn_ip_node_print_plain);
    }

    return;
}

/*stop detecting or not*/
EC_BOOL cdetectn_orig_node_need_stop_detecting(const CDETECTN_ORIG_NODE *cdetectn_orig_node)
{
    if(0 < CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node))
    {
        ctime_t     cur_time;
        ctime_t     stop_time;

        cur_time    = task_brd_default_get_time();
        stop_time   = CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node)
                    + CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node);

        if(stop_time < cur_time)
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

/*skip detecting this time or not*/
EC_BOOL cdetectn_orig_node_need_skip_detecting(const CDETECTN_ORIG_NODE *cdetectn_orig_node)
{
    if(0 < CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node))
    {
        ctime_t     cur_time;
        ctime_t     next_time; /*next detecing time*/

        cur_time    = task_brd_default_get_time();
        next_time   = CDETECTN_ORIG_NODE_LAST_DETECT_TIME(cdetectn_orig_node)
                    + CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node);

        if(next_time > cur_time)
        {
            return (EC_TRUE);
        }
    }
    return (EC_FALSE);
}

/*------------------------------------------------ interface for cdetectn ip node ------------------------------------------------*/
CDETECTN_IP_NODE *cdetectn_ip_node_new()
{
    CDETECTN_IP_NODE *cdetectn_ip_node;

    alloc_static_mem(MM_CDETECTN_IP_NODE, &cdetectn_ip_node, LOC_CDETECN_0005);
    if(NULL_PTR != cdetectn_ip_node)
    {
        cdetectn_ip_node_init(cdetectn_ip_node);
    }
    return (cdetectn_ip_node);
}

EC_BOOL cdetectn_ip_node_init(CDETECTN_IP_NODE *cdetectn_ip_node)
{
    cstring_init(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node), NULL_PTR);
    
    CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)                = CMPI_ERROR_IPADDR;
    CDETECTN_IP_NODE_PORT(cdetectn_ip_node)                  = CMPI_ERROR_SRVPORT;
    CDETECTN_IP_NODE_STATUS(cdetectn_ip_node)                = CDETECTN_IP_NODE_STATUS_ERR;

    CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node)      = CDETECTN_IP_NODE_COST_MSEC_ERR;

    return (EC_TRUE);
}

EC_BOOL cdetectn_ip_node_clean(CDETECTN_IP_NODE *cdetectn_ip_node)
{
    cstring_clean(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node));
    
    CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)                = CMPI_ERROR_IPADDR;
    CDETECTN_IP_NODE_PORT(cdetectn_ip_node)                  = CMPI_ERROR_SRVPORT;
    CDETECTN_IP_NODE_STATUS(cdetectn_ip_node)                = CDETECTN_IP_NODE_STATUS_ERR;

    CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node)      = CDETECTN_IP_NODE_COST_MSEC_ERR;

    return (EC_TRUE);
}

EC_BOOL cdetectn_ip_node_clear(CDETECTN_IP_NODE *cdetectn_ip_node)
{
    //CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)                = CMPI_ERROR_IPADDR;
    //CDETECTN_IP_NODE_PORT(cdetectn_ip_node)                  = CMPI_ERROR_SRVPORT;

    CDETECTN_IP_NODE_STATUS(cdetectn_ip_node)                = CDETECTN_IP_NODE_STATUS_ERR;
    CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node)      = CDETECTN_IP_NODE_COST_MSEC_ERR;

    return (EC_TRUE);
}

EC_BOOL cdetectn_ip_node_free(CDETECTN_IP_NODE *cdetectn_ip_node)
{
    if(NULL_PTR != cdetectn_ip_node)
    {
        cdetectn_ip_node_clean(cdetectn_ip_node);
        free_static_mem(MM_CDETECTN_IP_NODE, cdetectn_ip_node, LOC_CDETECN_0006);
    }
    return (EC_TRUE);
}

STATIC_CAST static const char *__cdetectn_ip_node_status_str(const CDETECTN_IP_NODE *cdetectn_ip_node)
{
    if(CDETECTN_IP_NODE_STATUS_REACHABLE == CDETECTN_IP_NODE_STATUS(cdetectn_ip_node))
    {
        return (const char *)"REACHABLE";
    }

    return (const char *)"ERR";
}

void cdetectn_ip_node_print(LOG *log, const CDETECTN_IP_NODE *cdetectn_ip_node)
{
    sys_log(log, "cdetectn_ip_node_print %p: domain %s, ip %s, status: %s, detect cost: %u ms\n",
                 cdetectn_ip_node,
                 (char *)cstring_get_str(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)),
                 c_word_to_ipv4(CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)),
                 __cdetectn_ip_node_status_str(cdetectn_ip_node),
                 CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node)
                 );

    return;
}

void cdetectn_ip_node_print_plain(LOG *log, const CDETECTN_IP_NODE *cdetectn_ip_node)
{
    if(CDETECTN_IP_NODE_COST_MSEC_ERR == CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node))
    {
        sys_print(log, " cdetectn_ip_node %p: domain %s, ip %s, port %ld, status: %s, detect cost: --\n",
                       cdetectn_ip_node,
                       (char *)cstring_get_str(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)),
                       c_word_to_ipv4(CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)),
                       CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                       __cdetectn_ip_node_status_str(cdetectn_ip_node));
    }
    else
    {
        sys_print(log, " cdetectn_ip_node %p: domain %s, ip %s, port %ld, status: %s, detect cost: %u ms\n",
                       cdetectn_ip_node,
                       (char *)cstring_get_str(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)),
                       c_word_to_ipv4(CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node)),
                       CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                       __cdetectn_ip_node_status_str(cdetectn_ip_node),
                       CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node));
    }
    return;
}

/**
*
*  print orig nodes
*
*
**/
EC_BOOL cdetectn_show_orig_nodes(const UINT32 cdetectn_md_id, LOG *log)
{
    CDETECTN_MD *cdetectn_md;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_show_orig_nodes: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    crb_tree_print(log, CDETECTN_MD_ORIG_NODE_TREE(cdetectn_md));

    return (EC_TRUE);
}

STATIC_CAST CDETECTN_ORIG_NODE *__cdetectn_search_orig_node(const UINT32 cdetectn_md_id, const CSTRING *domain)
{
    CDETECTN_MD                  *cdetectn_md;

    CRB_NODE                    *crb_node;

    CDETECTN_ORIG_NODE            cdetectn_orig_node_t;
    UINT32                       domain_hash;

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    domain_hash = CDETECTN_ORIG_NODE_DOMAIN_HASH_ALGO(CSTRING_LEN(domain), CSTRING_STR(domain));

    /*mount only*/
    cstring_set_str(CDETECTN_ORIG_NODE_DOMAIN(&cdetectn_orig_node_t), cstring_get_str(domain));
    CDETECTN_ORIG_NODE_DOMAIN_HASH(&cdetectn_orig_node_t) = (uint32_t)domain_hash;

    crb_node = crb_tree_search_data(CDETECTN_MD_ORIG_NODE_TREE(cdetectn_md), (void *)&cdetectn_orig_node_t);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    return (CDETECTN_ORIG_NODE *)CRB_NODE_DATA(crb_node);
}

/**
*
*  print single orig node
*
*
**/
EC_BOOL cdetectn_show_orig_node(const UINT32 cdetectn_md_id, const CSTRING *domain, LOG *log)
{
    CDETECTN_MD *cdetectn_md;

    CDETECTN_ORIG_NODE *cdetectn_orig_node;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_show_orig_node: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    cdetectn_orig_node = __cdetectn_search_orig_node(cdetectn_md_id, domain);
    if(NULL_PTR == cdetectn_orig_node)
    {
        sys_log(log, "[DEBUG] cdetectn_show_orig_node: "
                     "no orig node for domain '%s'\n",
                     (char *)cstring_get_str(domain));

        return (EC_TRUE);
    }

    cdetectn_orig_node_print(log, cdetectn_orig_node);

    return (EC_TRUE);
}


STATIC_CAST static uint32_t __cdetectn_choice_strategy(const char *choice_stragety)
{
    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"RRB:ROUND-ROBBIN"))
    {
        return (CDETECTN_ORIG_NODE_CHOICE_RRB);
    }

    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"FAST"))
    {
        return (CDETECTN_ORIG_NODE_CHOICE_FAST);
    }

    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"LATEST"))
    {
        return (CDETECTN_ORIG_NODE_CHOICE_LATEST);
    }

    if(EC_TRUE == c_str_is_in(choice_stragety, (const char *)":", (const char *)"MS"))
    {
        return (CDETECTN_ORIG_NODE_CHOICE_MS);
    }

    return (CDETECTN_ORIG_NODE_CHOICE_ERR);
}

STATIC_CAST static const char * __cdetectn_choice_strategy_to_str(const uint32_t choice_stragety)
{
    if(CDETECTN_ORIG_NODE_CHOICE_RRB == choice_stragety)
    {
        return (const char *)"RRB";
    }

    if(CDETECTN_ORIG_NODE_CHOICE_FAST == choice_stragety)
    {
        return (const char *)"FAST";
    }

    if(CDETECTN_ORIG_NODE_CHOICE_LATEST == choice_stragety)
    {
        return (const char *)"LATEST";
    }

    if(CDETECTN_ORIG_NODE_CHOICE_MS == choice_stragety)
    {
        return (const char *)"MS";
    }

    return (const char *)"ERR";
}

STATIC_CAST static EC_BOOL __cdetectn_parse_ip_node(CLIST *cdetectn_ip_nodes, char *ip)
{
    char                *segs[ 2 ];
    uint32_t             segs_num;

    segs_num = c_str_split(ip, (const char *)":", segs, sizeof(segs)/sizeof(segs[ 0 ]));
    if(1 != segs_num && 2 != segs_num)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_ip_node: "
                                                 "invalid segs num: %u\n",
                                                 segs_num);
        return (EC_FALSE);
    }

    if(1 == segs_num)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        c_str_trim_space(segs[ 0 ]);

        cdetectn_ip_node = cdetectn_ip_node_new();
        if(NULL_PTR == cdetectn_ip_node)
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_ip_node: "
                                                     "new cdetectn_ip_node failed\n");
            return (EC_FALSE);
        }

        if(EC_TRUE == c_ipv4_is_ok(segs[ 0 ]))
        {
            CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node) = c_ipv4_to_word(segs[ 0 ]);       
        }
        else
        {
            UINT32                ipv4;
            
            if(EC_FALSE == c_dns_resolve(segs[ 0 ], &ipv4))
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_ip_node: "
                                                         "dns resolve '%s' failed\n",
                                                         segs[ 0 ]);
                cdetectn_ip_node_free(cdetectn_ip_node);
                return (EC_FALSE);            
            }
            
            cstring_init(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node), (UINT8 *)segs[ 0 ]);
            CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node) = ipv4;
            
        }

        CDETECTN_IP_NODE_PORT(cdetectn_ip_node)   = CDETECTN_IP_NODE_PORT_DEFAULT;
        CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_REACHABLE; /*default*/        
        
        clist_push_back(cdetectn_ip_nodes, (void *)cdetectn_ip_node);

        return (EC_TRUE);
    }

    if(2 == segs_num)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        c_str_trim_space(segs[ 0 ]);
        c_str_trim_space(segs[ 1 ]);

        cdetectn_ip_node = cdetectn_ip_node_new();
        if(NULL_PTR == cdetectn_ip_node)
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_ip_node: "
                                                     "new cdetectn_ip_node failed\n");
            return (EC_FALSE);
        }
        
        if(EC_TRUE == c_ipv4_is_ok(segs[ 0 ]))
        {
            CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node) = c_ipv4_to_word(segs[ 0 ]);       
        }
        else
        {
            UINT32                ipv4;
            
            if(EC_FALSE == c_dns_resolve(segs[ 0 ], &ipv4))
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_ip_node: "
                                                         "dns resolve '%s' failed\n",
                                                         segs[ 0 ]);
                cdetectn_ip_node_free(cdetectn_ip_node);
                return (EC_FALSE);            
            }

            CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node) = ipv4;
            cstring_init(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node), (UINT8 *)segs[ 0 ]);
        }

        CDETECTN_IP_NODE_PORT(cdetectn_ip_node)   = c_port_to_word(segs[ 1 ]); 
        CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_REACHABLE; /*default*/

        clist_push_back(cdetectn_ip_nodes, (void *)cdetectn_ip_node);

        return (EC_TRUE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetectn_parse_ip_nodes(CLIST *cdetectn_ip_nodes, char *ips)
{
    char                *segs[ CDETECTN_ORIG_NODE_MAX_IP_NODES ];
    uint32_t             segs_num;
    uint32_t             idx;

    segs_num = c_str_split(ips, (const char *)",", segs, sizeof(segs)/sizeof(segs[ 0 ]));

    for(idx = 0; idx < segs_num; idx ++)
    {
        c_str_trim_space(segs[ idx ]);
        if(EC_FALSE == __cdetectn_parse_ip_node(cdetectn_ip_nodes, segs[ idx ]))
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_ip_nodes: "
                                                     "parse ip node failed\n");
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/*format: domain | ip[:port][,...] | url | interval nsec | stopping nsec | reachable status | forbidden status | strategy */
STATIC_CAST static EC_BOOL __cdetectn_parse_conf_line(const UINT32 cdetectn_md_id, char *cdetectn_conf_start, char *cdetectn_conf_end)
{
    CDETECTN_MD         *cdetectn_md;
    CDETECTN_ORIG_NODE  *cdetectn_orig_node;
    CRB_NODE            *crb_node;

    char                *segs[ 7 ];
    char                *p;
    uint32_t             segs_num;
    uint32_t             idx;
    UINT32               domain_hash;

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    /*locate the first char which is not space*/

    for(p = cdetectn_conf_start;isspace(*p); p ++)
    {
        /*do nothing*/
    }

    if('\0' == (*p))
    {
        dbg_log(SEC_0070_CDETECTN, 6)(LOGSTDOUT, "[DEBUG] __cdetectn_parse_conf_line: "
                                                 "skip empty line '%.*s'\n",
                                                 (cdetectn_conf_end - cdetectn_conf_start),
                                                 cdetectn_conf_start);
        /*skip empty line*/
        return (EC_TRUE);
    }

    if('#' == (*p))
    {
        /*skip commented line*/
        dbg_log(SEC_0070_CDETECTN, 6)(LOGSTDOUT, "[DEBUG] __cdetectn_parse_conf_line: "
                                                 "skip commented line '%.*s'\n",
                                                 (cdetectn_conf_end - cdetectn_conf_start),
                                                 cdetectn_conf_start);
        return (EC_TRUE);
    }

    dbg_log(SEC_0070_CDETECTN, 6)(LOGSTDOUT, "[DEBUG] __cdetectn_parse_conf_line: "
                                             "handle line '%.*s'\n",
                                             (cdetectn_conf_end - cdetectn_conf_start),
                                             cdetectn_conf_start);

    segs_num = sizeof(segs)/sizeof(segs[ 0 ]);
    if(segs_num != c_str_split(cdetectn_conf_start, (const char *)"|", segs, segs_num))
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_conf_line: "
                                                 "unable to split '%.*s' into %u segs\n",
                                                 (cdetectn_conf_end - cdetectn_conf_start),
                                                 cdetectn_conf_start,
                                                 segs_num);
        return (EC_FALSE);
    }

    for(idx = 0; idx < segs_num; idx ++)
    {
        c_str_trim_space(segs[ idx ]);
    }

    cdetectn_orig_node = cdetectn_orig_node_new();
    if(NULL_PTR == cdetectn_orig_node)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_conf_line: "
                                                 "new cdetectn_orig_node failed\n");
        return (EC_FALSE);
    }

    domain_hash = CDETECTN_ORIG_NODE_DOMAIN_HASH_ALGO(strlen(segs[ 0 ]), (const uint8_t *)segs[ 0 ]);

    cstring_init(CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node), (const uint8_t *)segs[ 0 ]);
    if(EC_FALSE == __cdetectn_parse_ip_nodes(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), segs[ 1 ]))
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_conf_line: "
                                                 "parse ips '%s' failed\n",
                                                 segs[ 1 ]);

        cdetectn_orig_node_free(cdetectn_orig_node);
        return (EC_FALSE);
    }

    if(0 != STRCMP(segs[ 2 ], "-"))/*url is not configured*/
    {
        cstring_init(CDETECTN_ORIG_NODE_URL(cdetectn_orig_node), (const uint8_t *)segs[ 2 ]);
    }

    CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node) = c_str_to_uint32_t(segs[ 3 ]);
    CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node) = c_str_to_uint32_t(segs[ 4 ]);

    CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node) = c_str_to_uint32_t_ireplace(segs[ 5 ], 'X', 0);
    CDETECTN_ORIG_NODE_REACHABLE_STATUS_END(cdetectn_orig_node) = c_str_to_uint32_t_ireplace(segs[ 5 ], 'X', 9);

    if(0 != STRCMP(segs[ 6 ], "-")) /*strategy is not configured*/
    {
        CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)  = __cdetectn_choice_strategy(segs[ 6 ]);
    }
    CDETECTN_ORIG_NODE_DOMAIN_HASH(cdetectn_orig_node)      = (uint32_t)domain_hash;

    crb_node = crb_tree_insert_data(CDETECTN_MD_ORIG_NODE_TREE(cdetectn_md), (void *)cdetectn_orig_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_conf_line: "
                                                 "insert '%s' failed\n",
                                                 segs[ 0 ]);

        cdetectn_orig_node_free(cdetectn_orig_node);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cdetectn_orig_node)/*found duplicate*/
    {
        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_parse_conf_line: "
                                                 "ignore duplicate '%s'\n",
                                                 segs[ 0 ]);

        cdetectn_orig_node_free(cdetectn_orig_node);
        return (EC_TRUE);
    }

    dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_parse_conf_line: "
                                             "insert '%s' done\n",
                                             segs[ 0 ]);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetectn_parse_conf_file(const UINT32 cdetectn_md_id, char *cdetectn_conf_start, char *cdetectn_conf_end)
{
    char        *cdetectn_conf_line_start;
    uint32_t     cdetectn_conf_line_no;

    cdetectn_conf_line_start = cdetectn_conf_start;
    cdetectn_conf_line_no    = 1;

    while(cdetectn_conf_line_start < cdetectn_conf_end)
    {
        char  *cdetectn_conf_line_end;

        cdetectn_conf_line_end = cdetectn_conf_line_start;

        while(cdetectn_conf_line_end < cdetectn_conf_end)
        {
            if('\n' == (*cdetectn_conf_line_end ++)) /*also works for line-terminator '\r\n'*/
            {
                break;
            }
        }

        if(cdetectn_conf_line_end > cdetectn_conf_end)
        {
            break;
        }

        *(cdetectn_conf_line_end - 1) = '\0'; /*insert string terminator*/

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "error:__cdetectn_parse_conf_file: "
                                                 "to parse line %u# '%.*s' failed\n",
                                                 cdetectn_conf_line_no,
                                                 (cdetectn_conf_line_end - cdetectn_conf_line_start),
                                                 cdetectn_conf_line_start);

#if 0
        if(EC_FALSE == __cdetectn_parse_conf_line(cdetectn_md_id, cdetectn_conf_line_start, cdetectn_conf_line_end))
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_conf_file: "
                                                     "parse line %u# '%.*s' failed\n",
                                                     cdetectn_conf_line_no,
                                                     (cdetectn_conf_line_end - cdetectn_conf_line_start),
                                                     cdetectn_conf_line_start);
            return (EC_FALSE);
        }
#endif
#if 1
        /*note: here is the alternative way to reduce reloading impact on service*/
        {
            TASK_BRD    *task_brd;
            MOD_NODE     recv_mod_node;
            EC_BOOL      ret;
            
            task_brd = task_brd_default_get();

            MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
            MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
            MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
            MOD_NODE_MODI(&recv_mod_node) = cdetectn_md_id;

            ret = EC_FALSE;
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &recv_mod_node,
                     &ret,
                     FI_cdetectn_parse_conf_line, CMPI_ERROR_MODI, 
                     (UINT32)cdetectn_conf_line_start, (UINT32)cdetectn_conf_line_end);

            if(EC_FALSE == ret)
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_parse_conf_file: "
                                                         "parse line %u# '%.*s' failed\n",
                                                         cdetectn_conf_line_no,
                                                         (cdetectn_conf_line_end - cdetectn_conf_line_start),
                                                         cdetectn_conf_line_start);
                return (EC_FALSE);
            }            
        }
#endif
        cdetectn_conf_line_no ++;

        cdetectn_conf_line_start = cdetectn_conf_line_end;
    }

    return (EC_TRUE);
}

/*trick!*/
EC_BOOL cdetectn_parse_conf_line(const UINT32 cdetectn_md_id, const UINT32 cdetectn_conf_start, const UINT32 cdetectn_conf_end)
{
#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_parse_conf_line: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        cdetectn_print_module_status(cdetectn_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    return __cdetectn_parse_conf_line(cdetectn_md_id, (char *)cdetectn_conf_start, (char *)cdetectn_conf_end);
}

/**
*
*  load detect conf
*
*
**/
EC_BOOL cdetectn_load_conf(const UINT32 cdetectn_md_id, const CSTRING *cdetectn_conf_file)
{
    CDETECTN_MD  *cdetectn_md;

    UINT32       fsize;
    UINT32       offset;
    UINT8       *fcontent;
    int          fd;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_load_conf: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        cdetectn_print_module_status(cdetectn_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    if(EC_FALSE == c_file_access((char *)cstring_get_str(cdetectn_conf_file), F_OK))
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_load_conf: "
                                                 "conf file '%s' not exist\n",
                                                 (char *)cstring_get_str(cdetectn_conf_file));

        return (EC_FALSE);
    }    

    fd = c_file_open((char *)cstring_get_str(cdetectn_conf_file), O_RDONLY, 0666);
    if(ERR_FD == fd)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_load_conf: "
                                                 "open file '%s' failed\n",
                                                 (char *)cstring_get_str(cdetectn_conf_file));
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(fd, &fsize))
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_load_conf: "
                                                 "get size of '%s' failed\n",
                                                 (char *)cstring_get_str(cdetectn_conf_file));
        c_file_close(fd);
        return (EC_FALSE);
    }

    if(0 == fsize)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_load_conf: "
                                                 "file '%s' size is 0\n",
                                                 (char *)cstring_get_str(cdetectn_conf_file));
        c_file_close(fd);
        return (EC_FALSE);
    }

    fcontent = safe_malloc(fsize, LOC_CDETECN_0007);
    if(NULL_PTR == fcontent)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_load_conf: "
                                                 "malloc %ld bytes failed\n",
                                                 fsize);
        c_file_close(fd);
        return (EC_FALSE);
    }

    offset = 0;
    if(EC_FALSE == c_file_load(fd, &offset, fsize, fcontent))
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_load_conf: "
                                                 "load file '%s' failed\n",
                                                 (char *)cstring_get_str(cdetectn_conf_file));
        c_file_close(fd);
        safe_free(fcontent, LOC_CDETECN_0008);
        return (EC_FALSE);
    }
    c_file_close(fd);

    dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_load_conf: "
                                             "load file '%s' from disk done\n",
                                             (char *)cstring_get_str(cdetectn_conf_file));

    /*clear*/
    crb_tree_clean(CDETECTN_MD_ORIG_NODE_TREE(cdetectn_md));
    clist_clean(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md), NULL_PTR);

    CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md) = 0;

    dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_load_conf: "
                                             "clear old data done\n");    

    /*parse*/
    if(EC_FALSE == __cdetectn_parse_conf_file(cdetectn_md_id, (char *)fcontent, (char *)(fcontent + fsize)))
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_load_conf: "
                                                 "parse conf file '%s' failed\n",
                                                 (char *)cstring_get_str(cdetectn_conf_file));
        safe_free(fcontent, LOC_CDETECN_0009);
        return (EC_FALSE);
    }
    safe_free(fcontent, LOC_CDETECN_0010);

    dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_load_conf: "
                                             "parse conf file '%s' done\n",
                                             (char *)cstring_get_str(cdetectn_conf_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetectn_dns_resolve_orig_node_choice_ms(CDETECTN_ORIG_NODE *cdetectn_orig_node, UINT32 *ipaddr)
{
    CLIST_DATA          *clist_data;

    /*always search from head to tail. the master orig is at the first one*/
    CLIST_LOOP_NEXT(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        cdetectn_ip_node = (CDETECTN_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECTN_IP_NODE_STATUS_REACHABLE == CDETECTN_IP_NODE_STATUS(cdetectn_ip_node))
        {
            /*the first reachable ip*/
            (*ipaddr) = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_dns_resolve_orig_node_choice_ms: "
                                                     "[MS] domain '%s' => ip '%s'\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node));
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetectn_dns_resolve_orig_node_choice_rrb(CDETECTN_ORIG_NODE *cdetectn_orig_node, UINT32 *ipaddr)
{
    CLIST_DATA          *clist_data;

    /*always search from head to tail. generally the reachable orig should be at the first one*/
    CLIST_LOOP_NEXT(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        cdetectn_ip_node = (CDETECTN_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECTN_IP_NODE_STATUS_REACHABLE == CDETECTN_IP_NODE_STATUS(cdetectn_ip_node))
        {
            /*the first reachable ip.*/
            (*ipaddr) = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_dns_resolve_orig_node_choice_rrb: "
                                                     "[RRB] domain '%s' => ip '%s'\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node));
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetectn_dns_resolve_orig_node_choice_fast(CDETECTN_ORIG_NODE *cdetectn_orig_node, UINT32 *ipaddr)
{
    CLIST_DATA          *clist_data;
    CDETECTN_IP_NODE     *cdetectn_ip_node_fast;

    cdetectn_ip_node_fast = NULL_PTR;

    CLIST_LOOP_NEXT(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        cdetectn_ip_node = (CDETECTN_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECTN_IP_NODE_STATUS_REACHABLE != CDETECTN_IP_NODE_STATUS(cdetectn_ip_node))
        {
            continue;
        }

        if(NULL_PTR == cdetectn_ip_node_fast)
        {
            cdetectn_ip_node_fast = cdetectn_ip_node;
            continue;
        }

        /*compare time-cost*/
        if(CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node_fast) > CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node))
        {
            cdetectn_ip_node_fast = cdetectn_ip_node;
        }
    }

    if(NULL_PTR != cdetectn_ip_node_fast)
    {
        /*the fast ip.*/
        (*ipaddr) = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node_fast);

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_dns_resolve_orig_node_choice_fast: "
                                                 "[FALST] domain '%s' => ip '%s'\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                 CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node_fast)
                            );
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetectn_dns_resolve_orig_node_choice_latest(CDETECTN_ORIG_NODE *cdetectn_orig_node, UINT32 *ipaddr)
{
    CLIST_DATA          *clist_data;
    CLIST_DATA          *clist_data_latest;

    clist_data_latest = CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node);
    if(NULL_PTR != clist_data_latest)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        clist_data_latest = CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node);
        cdetectn_ip_node   = (CDETECTN_IP_NODE *)CLIST_DATA_DATA(clist_data_latest);

        if(CDETECTN_IP_NODE_STATUS_REACHABLE == CDETECTN_IP_NODE_STATUS(cdetectn_ip_node))
        {
            /*the latest ip.*/
            (*ipaddr) = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_dns_resolve_orig_node_choice_latest: "
                                                     "[LATEST] domain '%s' => ip '%s'\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node)
                                );
            return (EC_TRUE);
        }
    }

    CLIST_LOOP_NEXT(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        if(clist_data == clist_data_latest)
        {
            continue;
        }

        cdetectn_ip_node = (CDETECTN_IP_NODE *)CLIST_DATA_DATA(clist_data);
        if(CDETECTN_IP_NODE_STATUS_REACHABLE == CDETECTN_IP_NODE_STATUS(cdetectn_ip_node))
        {
            /*the reachable ip.*/
            (*ipaddr) = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_dns_resolve_orig_node_choice_latest: "
                                                     "[LATEST] domain '%s' => reachable ip '%s'\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node)
                                );
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetectn_dns_resolve_orig_node_choice_default(CDETECTN_ORIG_NODE *cdetectn_orig_node, UINT32 *ipaddr)
{
    CDETECTN_IP_NODE     *cdetectn_ip_node;

    cdetectn_ip_node = clist_first_data(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node));
    if(NULL_PTR != cdetectn_ip_node)
    {
        /*the reachable ip.*/
        (*ipaddr) = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_dns_resolve_orig_node_choice_default: "
                                                 "[default] domain '%s' => first ip '%s'\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                 CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node)
                            );
        return (EC_TRUE);
    }

    return (EC_FALSE);
}
STATIC_CAST static EC_BOOL __cdetectn_dns_resolve_orig_node(CDETECTN_ORIG_NODE *cdetectn_orig_node, UINT32 *ipaddr)
{
    if(CDETECTN_ORIG_NODE_CHOICE_MS == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)
    && EC_TRUE == __cdetectn_dns_resolve_orig_node_choice_ms(cdetectn_orig_node, ipaddr))
    {
        return (EC_TRUE);
    }

    if(CDETECTN_ORIG_NODE_CHOICE_RRB == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)
    && EC_TRUE == __cdetectn_dns_resolve_orig_node_choice_rrb(cdetectn_orig_node, ipaddr))
    {
        return (EC_TRUE);
    }

    if(CDETECTN_ORIG_NODE_CHOICE_FAST == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)
    && EC_TRUE == __cdetectn_dns_resolve_orig_node_choice_fast(cdetectn_orig_node, ipaddr))
    {
        return (EC_TRUE);
    }

    if(CDETECTN_ORIG_NODE_CHOICE_LATEST == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node)
    && EC_TRUE == __cdetectn_dns_resolve_orig_node_choice_latest(cdetectn_orig_node, ipaddr))
    {
        return (EC_TRUE);
    }

    return __cdetectn_dns_resolve_orig_node_choice_default(cdetectn_orig_node, ipaddr);
}


/**
*
*  dns resolve
*
**/
EC_BOOL cdetectn_dns_resolve(const UINT32 cdetectn_md_id, const CSTRING *domain, UINT32 *ipaddr)
{
    CDETECTN_MD          *cdetectn_md;

    CDETECTN_ORIG_NODE   *cdetectn_orig_node;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_dns_resolve: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        cdetectn_print_module_status(cdetectn_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    cdetectn_orig_node = __cdetectn_search_orig_node(cdetectn_md_id, domain);
    if(NULL_PTR == cdetectn_orig_node)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_dns_resolve: "
                                                 "domain '%s' not configured\n",
                                                 (char *)cstring_get_str(domain));
        return (EC_FALSE);
    }

    /*update access time*/
    CDETECTN_ORIG_NODE_LAST_ACCESS_TIME(cdetectn_orig_node) = task_brd_default_get_time();

    if(EC_TRUE == clist_is_empty(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node)))
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_dns_resolve: "
                                                 "domain '%s' has no ip configured\n",
                                                 (char *)cstring_get_str(domain));
        return (EC_FALSE);
    }

    /*add to detect due to the domain is accessed*/
    if(NULL_PTR == CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node)
    && EC_FALSE == cstring_is_empty(CDETECTN_ORIG_NODE_URL(cdetectn_orig_node)))
    {
        CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node) =
                    clist_push_back(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md), (void *)cdetectn_orig_node);
    }

    if(EC_FALSE == __cdetectn_dns_resolve_orig_node(cdetectn_orig_node, ipaddr))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0070_CDETECTN, 5)(LOGSTDOUT, "[DEBUG] cdetectn_dns_resolve: "
                                             "domain '%s' => ip '%s'\n",
                                             (char *)cstring_get_str(domain),
                                             c_word_to_ipv4(*ipaddr));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetectn_request(const CSTRING *domain, const CSTRING *uri, const UINT32 ipaddr, const UINT32 port,
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
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_request: "
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


STATIC_CAST static EC_BOOL __cdetectn_start_orig_node_choice_ms(CDETECTN_ORIG_NODE   *cdetectn_orig_node, UINT32 *detect_task_num)
{
    CLIST_DATA          *clist_data;

    /*the first one is master orig. always start from the master orig*/
    CLIST_LOOP_NEXT(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        CSTRING              *url;
        CSTRING              *domain;
        UINT32                ipaddr;
        UINT32                port;

        uint32_t              status;

        /*the first one is master orig*/
        cdetectn_ip_node = CLIST_DATA_DATA(clist_data);

        if(EC_TRUE == cstring_is_empty(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)))
        {
            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node);
            ipaddr = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);
        }
        else
        {
            if(EC_FALSE == c_dns_resolve((char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node), &ipaddr))
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_ms: "
                                                         "[MS] resolve domain '%s' failed\n",
                                                         (char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node));
                continue;
            }

            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);            
        }

        if(EC_FALSE == __cdetectn_request(domain, url, ipaddr, port, detect_task_num, &status))
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_ms: "
                                                     "[MS] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                     (char *)cstring_get_str(domain),
                                                     ipaddr, port);
            continue;
        }

        if(status >= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)
        && status <= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node))
        {
            CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_ms: "
                                                     "[MS] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                     CDETECTN_IP_NODE_PORT(cdetectn_ip_node));
            return (EC_TRUE);
        }

        CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_ms: "
                                                 "[MS] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                 CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                 CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                                                 status);

        /*loop next one*/
    }

    dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_start_orig_node_choice_ms: "
                                             "[MS] detect domain '%s' failed\n",
                                             (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node));
    /*none succ*/
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetectn_start_orig_node_choice_rrb(CDETECTN_ORIG_NODE   *cdetectn_orig_node, UINT32 *detect_task_num)
{
    UINT32               node_num;
    UINT32               node_idx;

    node_num = clist_size(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node));
    for(node_idx = 0; node_idx < node_num; node_idx ++)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        CSTRING              *url;
        CSTRING              *domain;
        UINT32                ipaddr;
        UINT32                port;
        
        uint32_t              status;

        cdetectn_ip_node = clist_first_data(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node));

        if(EC_TRUE == cstring_is_empty(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)))
        {
            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node);
            ipaddr = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);
        }
        else
        {
            if(EC_FALSE == c_dns_resolve((char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node), &ipaddr))
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_rrb: "
                                                         "[MS] resolve domain '%s' failed\n",
                                                         (char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node));
                continue;
            }

            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);            
        }

        if(EC_FALSE == __cdetectn_request(domain, url, ipaddr, port, detect_task_num, &status))
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_start_orig_node_choice_rrb: "
                                                     "[RRB] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                     (char *)cstring_get_str(domain),
                                                     ipaddr, port);

            /*move to tail*/
            clist_pop_front(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node));
            clist_push_back(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), (void *)cdetectn_ip_node);
            continue;
        }

        if(status >= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)
        && status <= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node))
        {
            CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_rrb: "
                                                     "[RRB] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                     CDETECTN_IP_NODE_PORT(cdetectn_ip_node));
            return (EC_TRUE);
        }

        CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_rrb: "
                                                 "[RRB] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                 CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                 CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                                                 status);

        /*move to tail*/
        clist_pop_front(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node));
        clist_push_back(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), (void *)cdetectn_ip_node);
    }

    dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_start_orig_node_choice_rrb: "
                                             "[RRB] detect domain '%s' failed\n",
                                             (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node));

    /*none succ*/
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cdetectn_start_orig_node_choice_fast(CDETECTN_ORIG_NODE   *cdetectn_orig_node, UINT32 *detect_task_num)
{
    CLIST_DATA          *clist_data;
    EC_BOOL              flag; /*true: indicate someone node is reachable, false: none is reachable*/

    flag = EC_FALSE;

    /*the first one is master orig. always start from the master orig*/
    CLIST_LOOP_NEXT(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        CSTRING              *url;
        CSTRING              *domain;
        UINT32                ipaddr;
        UINT32                port;
        
        uint32_t              status;

        uint32_t              start_nsec;
        uint32_t              start_msec;

        cdetectn_ip_node = CLIST_DATA_DATA(clist_data);

        if(EC_TRUE == cstring_is_empty(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)))
        {
            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node);
            ipaddr = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);
        }
        else
        {
            if(EC_FALSE == c_dns_resolve((char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node), &ipaddr))
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_fast: "
                                                         "[MS] resolve domain '%s' failed\n",
                                                         (char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node));
                continue;
            }

            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);            
        }        

        /*record start time*/
        start_nsec = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());
        start_msec = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());

        if(EC_FALSE == __cdetectn_request(domain, url, ipaddr, port, detect_task_num, &status))
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_fast: "
                                                     "[FAST] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                     (char *)cstring_get_str(domain),
                                                     ipaddr, port);
            continue;
        }

        if(status >= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)
        && status <= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node))
        {
            uint32_t             end_nsec;
            uint32_t             end_msec;

            CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_REACHABLE;
            flag = EC_TRUE;

            end_nsec = (uint32_t)CTMV_NSEC(task_brd_default_get_daytime());
            end_msec = (uint32_t)CTMV_MSEC(task_brd_default_get_daytime());

            CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node) = (end_nsec - start_nsec) * 1000 + (end_msec - start_msec);

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_fast: "
                                                     "[FAST] (domain '%s', ip '%s', port '%ld') reachable, cost %u ms\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                     CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                                                     CDETECTN_IP_NODE_DETECT_COST_MSEC(cdetectn_ip_node));
            continue;
        }

        CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_fast: "
                                                 "[FAST] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                 CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                 CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                                                 status);

        /*loop next one*/
    }

    if(EC_FALSE == flag)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_start_orig_node_choice_fast: "
                                                 "[FAST] detect domain '%s' failed\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node));
        /*none succ*/
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdetectn_start_orig_node_choice_latest(CDETECTN_ORIG_NODE   *cdetectn_orig_node, UINT32 *detect_task_num)
{
    CLIST_DATA      *clist_data;

    clist_data = CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node);
    while(NULL_PTR != clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        CSTRING              *url;
        CSTRING              *domain;
        UINT32                ipaddr;
        UINT32                port;
        
        uint32_t              status;

        cdetectn_ip_node = CLIST_DATA_DATA(clist_data);

        if(EC_TRUE == cstring_is_empty(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)))
        {
            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node);
            ipaddr = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);
        }
        else
        {
            if(EC_FALSE == c_dns_resolve((char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node), &ipaddr))
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_latest: "
                                                         "[MS] resolve domain '%s' failed\n",
                                                         (char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node));
                break; /*fall through*/
            }

            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);            
        }
        
        if(EC_FALSE == __cdetectn_request(domain, url, ipaddr, port, detect_task_num, &status))
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_latest: "
                                                     "[LATEST] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                     (char *)cstring_get_str(domain),
                                                     ipaddr, port);

            break; /*fall through*/
        }

        if(status >= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)
        && status <= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node))
        {
            CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_latest: "
                                                     "[LATEST] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                     CDETECTN_IP_NODE_PORT(cdetectn_ip_node));
            return (EC_TRUE);
        }

        CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_latest: "
                                                 "[LATEST] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                 CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                 CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                                                 status);
        break;/*fall through*/
    }

    CLIST_LOOP_NEXT(CDETECTN_ORIG_NODE_IP_NODES(cdetectn_orig_node), clist_data)
    {
        CDETECTN_IP_NODE     *cdetectn_ip_node;

        CSTRING              *url;
        CSTRING              *domain;
        UINT32                ipaddr;
        UINT32                port;
        
        uint32_t              status;

        if(clist_data == CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node))
        {
            /*already detected, skip it*/
            continue;
        }

        cdetectn_ip_node = CLIST_DATA_DATA(clist_data);

        if(EC_TRUE == cstring_is_empty(CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node)))
        {
            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node);
            ipaddr = CDETECTN_IP_NODE_IPADDR(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);
        }
        else
        {
            if(EC_FALSE == c_dns_resolve((char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node), &ipaddr))
            {
                dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_latest: "
                                                         "[MS] resolve domain '%s' failed\n",
                                                         (char *)CDETECTN_IP_NODE_DOMAIN_STR(cdetectn_ip_node));
                continue;
            }

            url    = CDETECTN_ORIG_NODE_URL(cdetectn_orig_node);
            domain = CDETECTN_IP_NODE_DOMAIN(cdetectn_ip_node);
            port   = CDETECTN_IP_NODE_PORT(cdetectn_ip_node);            
        }
        
        if(EC_FALSE == __cdetectn_request(domain, url, ipaddr, port, detect_task_num, &status))
        {
            dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "warn:__cdetectn_start_orig_node_choice_latest: "
                                                     "[LATEST] detect (domain '%s', ip '%s', port '%ld') failed\n",
                                                     (char *)cstring_get_str(domain),
                                                     ipaddr, port);

            continue;
        }

        if(status >= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node)
        && status <= CDETECTN_ORIG_NODE_REACHABLE_STATUS_BEG(cdetectn_orig_node))
        {
            CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_REACHABLE;

            dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_latest: "
                                                     "[LATEST] (domain '%s', ip '%s', port '%ld') reachable\n",
                                                     (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                     CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                     CDETECTN_IP_NODE_PORT(cdetectn_ip_node));

            CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node) = clist_data; /*update*/
            return (EC_TRUE);
        }

        CDETECTN_IP_NODE_STATUS(cdetectn_ip_node) = CDETECTN_IP_NODE_STATUS_ERR;

        dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] __cdetectn_start_orig_node_choice_latest: "
                                                 "[LATEST] (domain '%s', ip '%s', port '%ld') unknown %u\n",
                                                 (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                 CDETECTN_IP_NODE_IPADDR_STR(cdetectn_ip_node),
                                                 CDETECTN_IP_NODE_PORT(cdetectn_ip_node),
                                                 status);
    }

    CDETECTN_ORIG_NODE_LAST_REACHABLE_IP_NODE(cdetectn_orig_node) = NULL_PTR; /*clean*/

    dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:__cdetectn_start_orig_node_choice_latest: "
                                             "[LATEST] detect domain '%s' failed\n",
                                             (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node));
    /*none succ*/
    return (EC_FALSE);
}

/**
*
*  start to detect domain
*
**/
EC_BOOL cdetectn_start_domain(const UINT32 cdetectn_md_id, const CSTRING *domain)
{
    CDETECTN_MD          *cdetectn_md;

    CDETECTN_ORIG_NODE   *cdetectn_orig_node;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_start_domain: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        cdetectn_print_module_status(cdetectn_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    cdetectn_orig_node = __cdetectn_search_orig_node(cdetectn_md_id, domain);
    if(NULL_PTR == cdetectn_orig_node)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_start_domain: "
                                                 "domain '%s' not configured\n",
                                                 (char *)cstring_get_str(domain));
        return (EC_FALSE);
    }

    CDETECTN_ORIG_NODE_LAST_DETECT_TIME(cdetectn_orig_node) = task_brd_default_get_time();

    dbg_log(SEC_0070_CDETECTN, 5)(LOGSTDOUT, "[DEBUG] cdetectn_start_domain: "
                                             "domain '%s'\n",
                                             (char *)cstring_get_str(domain));

    if(CDETECTN_ORIG_NODE_CHOICE_MS == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node))
    {
        return __cdetectn_start_orig_node_choice_ms(cdetectn_orig_node, &(CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md)));
    }

    if(CDETECTN_ORIG_NODE_CHOICE_RRB == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node))
    {
        return __cdetectn_start_orig_node_choice_rrb(cdetectn_orig_node, &(CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md)));
    }

    if(CDETECTN_ORIG_NODE_CHOICE_FAST == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node))
    {
        return __cdetectn_start_orig_node_choice_fast(cdetectn_orig_node, &(CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md)));
    }

    if(CDETECTN_ORIG_NODE_CHOICE_LATEST == CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node))
    {
        return __cdetectn_start_orig_node_choice_latest(cdetectn_orig_node, &(CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md)));
    }

    dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_start_domain: "
                                             "domain '%s' configured invalid strategy '%u'\n",
                                             (char *)cstring_get_str(domain),
                                             CDETECTN_ORIG_NODE_CHOICE_STRATEGY(cdetectn_orig_node));
    return (EC_FALSE);
}

/**
*
*  stop to detect domain
*
**/
EC_BOOL cdetectn_stop_domain(const UINT32 cdetectn_md_id, const CSTRING *domain)
{
    CDETECTN_MD          *cdetectn_md;

    CDETECTN_ORIG_NODE   *cdetectn_orig_node;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_stop_domain: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        cdetectn_print_module_status(cdetectn_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    cdetectn_orig_node = __cdetectn_search_orig_node(cdetectn_md_id, domain);
    if(NULL_PTR == cdetectn_orig_node)
    {
        dbg_log(SEC_0070_CDETECTN, 0)(LOGSTDOUT, "error:cdetectn_stop_domain: "
                                                 "domain '%s' not configured\n",
                                                 (char *)cstring_get_str(domain));
        return (EC_FALSE);
    }

    dbg_log(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_stop_domain: "
                                             "stop to detect domain '%s'\n",
                                             (char *)cstring_get_str(domain));

    if(NULL_PTR != CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node))
    {
        clist_erase(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md), CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node));
        CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node) = NULL_PTR;
    }

    cdetectn_orig_node_clear(cdetectn_orig_node);

    return (EC_TRUE);
}

/**
*
*  process entry
*
**/
EC_BOOL cdetectn_process(const UINT32 cdetectn_md_id, const UINT32 detect_task_max_num)
{
    CDETECTN_MD          *cdetectn_md;

    UINT32               detect_node_num;
    UINT32               detect_node_idx;

    TASK_BRD            *task_brd;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_process: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        cdetectn_print_module_status(cdetectn_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_md = CDETECTN_MD_GET(cdetectn_md_id);

    detect_node_num = clist_size(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md));

    rlog(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_process: "
                                          "detect_task_max_num = %ld, detect_node_num = %ld\n",
                                          detect_task_max_num,
                                          detect_node_num);

    task_brd = task_brd_default_get();
    for(detect_node_idx = 0; detect_node_idx < detect_node_num; detect_node_idx ++)
    {
        CDETECTN_ORIG_NODE   *cdetectn_orig_node;
        MOD_NODE             recv_mod_node;
        CLIST_DATA          *clist_data;

        rlog(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_process: "
                                              "[%ld] "
                                              "detect detect_task_max_num = %ld, "
                                              "detect_task_max_num = %ld, "
                                              "detect_node_num = %ld\n",
                                              detect_node_idx,
                                              CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md),
                                              detect_task_max_num,
                                              detect_node_num);

        if(CDETECTN_MD_DETECT_TASK_NUM(cdetectn_md) >= detect_task_max_num)
        {
            break;/*terminate*/
        }

        /*move from head to tail with free and malloc. */
        /*do not change the mounted point (CDETECTN_ORIG_NODE_DETECT_ORIG_NODE).*/
        clist_data = CLIST_FIRST_NODE(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md));
        clist_move_back(CDETECTN_MD_DETECT_NODE_LIST(cdetectn_md), clist_data);

        cdetectn_orig_node = CLIST_DATA_DATA(clist_data);
        ASSERT(CDETECTN_ORIG_NODE_DETECT_ORIG_NODE(cdetectn_orig_node) == clist_data);

        /*if none access in stopping interval, then stop detecting*/
        if(EC_TRUE == cdetectn_orig_node_need_stop_detecting(cdetectn_orig_node))
        {
            rlog(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_process: "
                                                  "stop to detect domain '%s' due to stopping interval (%u sec)\n",
                                                  (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                  CDETECTN_ORIG_NODE_DETECT_STOPPING_NSEC(cdetectn_orig_node));

            cdetectn_stop_domain(cdetectn_md_id, CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node));
            continue;
        }

        /*if next detecting time not reached, then give up detecting this time*/
        if(EC_TRUE == cdetectn_orig_node_need_skip_detecting(cdetectn_orig_node))
        {
            rlog(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_process: "
                                                  "give up detecting domain '%s' due to detect interval (%u sec)\n",
                                                  (char *)CDETECTN_ORIG_NODE_DOMAIN_STR(cdetectn_orig_node),
                                                  CDETECTN_ORIG_NODE_DETECT_INTERVAL_NSEC(cdetectn_orig_node));

            continue;
        }

        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = cdetectn_md_id;

        task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                 &recv_mod_node,
                 NULL_PTR,
                 FI_cdetectn_start_domain, CMPI_ERROR_MODI, CDETECTN_ORIG_NODE_DOMAIN(cdetectn_orig_node));
    }

    rlog(SEC_0070_CDETECTN, 9)(LOGSTDOUT, "[DEBUG] cdetectn_process: "
                                          "done\n");

    return (EC_TRUE);
}

/**
*
*  process loop
*
**/
EC_BOOL cdetectn_process_loop(const UINT32 cdetectn_md_id, const UINT32 detect_task_max_num)
{
    TASK_BRD       *task_brd;
    MOD_NODE        recv_mod_node;

#if ( SWITCH_ON == CDETECTN_DEBUG_SWITCH )
    if ( CDETECTN_MD_ID_CHECK_INVALID(cdetectn_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cdetectn_process_loop: cdetectn module #0x%lx not started.\n",
                cdetectn_md_id);
        cdetectn_print_module_status(cdetectn_md_id, LOGSTDOUT);
        dbg_exit(MD_CDETECTN, cdetectn_md_id);
    }
#endif/*CDETECTN_DEBUG_SWITCH*/

    cdetectn_process(cdetectn_md_id, detect_task_max_num);

    task_brd = task_brd_default_get();

    MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
    MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
    MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
    MOD_NODE_MODI(&recv_mod_node) = cdetectn_md_id;

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_cdetectn_process_loop, CMPI_ERROR_MODI, detect_task_max_num);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


