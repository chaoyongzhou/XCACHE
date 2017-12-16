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

#include "ccallback.h"

CCALLBACK_NODE *ccallback_node_new()
{
    CCALLBACK_NODE *ccallback_node;

    alloc_static_mem(MM_CCALLBACK_NODE, &ccallback_node, LOC_CCALLBACK_0001);
    if(NULL_PTR == ccallback_node)
    {
        dbg_log(SEC_0178_CCALLBACK, 0)(LOGSTDOUT, "error:ccallback_node_new: failed to alloc tasks node\n");
        return (NULL_PTR);
    }

    ccallback_node_init(ccallback_node);
    return (ccallback_node);
}

EC_BOOL ccallback_node_init(CCALLBACK_NODE *ccallback_node)
{
    CCALLBACK_NODE_NAME(ccallback_node) = NULL_PTR;
    CCALLBACK_NODE_FUNC(ccallback_node) = NULL_PTR;
    CCALLBACK_NODE_DATA(ccallback_node) = NULL_PTR;
    
    return (EC_TRUE);
}

EC_BOOL ccallback_node_clean(CCALLBACK_NODE *ccallback_node)
{
    CCALLBACK_NODE_NAME(ccallback_node) = NULL_PTR;

    CCALLBACK_NODE_FUNC(ccallback_node) = NULL_PTR;
    CCALLBACK_NODE_DATA(ccallback_node) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL ccallback_node_free(CCALLBACK_NODE *ccallback_node)
{
    if(NULL_PTR != ccallback_node)
    {
        ccallback_node_clean(ccallback_node);
        free_static_mem(MM_CCALLBACK_NODE, ccallback_node, LOC_CCALLBACK_0002);
    }
    return (EC_TRUE);
}

void ccallback_node_print(LOG *log, const CCALLBACK_NODE *ccallback_node)
{
    sys_log(log, "ccallback_node_print: ccallback_node %p: '%s':%lx:%lx\n", 
                  ccallback_node,
                  CCALLBACK_NODE_NAME(ccallback_node),
                  CCALLBACK_NODE_DATA(ccallback_node),
                  CCALLBACK_NODE_FUNC(ccallback_node));
    return;                   
}

EC_BOOL ccallback_node_filter_default(const CCALLBACK_NODE *ccallback_node, const char *name, const UINT32 data, const UINT32 func)
{
    if(func == CCALLBACK_NODE_FUNC(ccallback_node)
    && data == CCALLBACK_NODE_DATA(ccallback_node)
    && 0 == STRCASECMP(CCALLBACK_NODE_NAME(ccallback_node), name))
    {
        return (EC_TRUE);    
    }
    return (EC_FALSE);
}

EC_BOOL ccallback_node_runner_default(UINT32 unused, CCALLBACK_NODE *ccallback_node)
{
    ccallback_node_print(LOGSTDOUT, ccallback_node);
    return (EC_TRUE);
}

EC_BOOL ccallback_list_init(CCALLBACK_LIST *ccallback_list)
{
    CCALLBACK_LIST_NAME(ccallback_list)   = NULL_PTR;
    
    clist_init(CCALLBACK_LIST_NODES(ccallback_list), MM_CCALLBACK_NODE, LOC_CCALLBACK_0003);

    CCALLBACK_LIST_RUNNER(ccallback_list) = NULL_PTR;
    CCALLBACK_LIST_FILTER(ccallback_list) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL ccallback_list_clean(CCALLBACK_LIST *ccallback_list)
{
    CCALLBACK_LIST_NAME(ccallback_list)   = NULL_PTR;
    
    clist_clean(CCALLBACK_LIST_NODES(ccallback_list), (CLIST_DATA_DATA_CLEANER)ccallback_node_free);

    CCALLBACK_LIST_RUNNER(ccallback_list) = NULL_PTR;
    CCALLBACK_LIST_FILTER(ccallback_list) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL ccallback_list_set_name(CCALLBACK_LIST *ccallback_list, const char *name)
{
    CCALLBACK_LIST_NAME(ccallback_list) = name;
    return (EC_TRUE);
}

EC_BOOL ccallback_list_set_runner(CCALLBACK_LIST *ccallback_list, CCALLBACK_RUNNER runner)
{
    CCALLBACK_LIST_RUNNER(ccallback_list) = runner;
    return (EC_TRUE);
}

EC_BOOL ccallback_list_set_filter(CCALLBACK_LIST *ccallback_list, CCALLBACK_FILTER filter)
{
    CCALLBACK_LIST_FILTER(ccallback_list) = filter;
    return (EC_TRUE);
}

void ccallback_list_print(LOG *log, const CCALLBACK_LIST *ccallback_list)
{
    sys_log(log, "ccallback_list_print: ccallback_list %p, name '%s', runner %p, filter %p, nodes:\n", 
                  ccallback_list, 
                  CCALLBACK_LIST_NAME(ccallback_list),
                  CCALLBACK_LIST_RUNNER(ccallback_list),
                  CCALLBACK_LIST_FILTER(ccallback_list));
                  
    clist_print(log, CCALLBACK_LIST_NODES(ccallback_list), (CLIST_DATA_DATA_PRINT)ccallback_node_print);
    return;
}

CCALLBACK_NODE *ccallback_list_search(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func)
{
    CLIST_DATA          *clist_data;

    CCALLBACK_FILTER     callback_filter;

    if(NULL_PTR != CCALLBACK_LIST_FILTER(ccallback_list))
    {
        callback_filter = CCALLBACK_LIST_FILTER(ccallback_list);
    }
    else
    {
        callback_filter = ccallback_node_filter_default;
    }

    CLIST_LOOP_NEXT(CCALLBACK_LIST_NODES(ccallback_list), clist_data)
    {
        CCALLBACK_NODE              *ccallback_node;

        ccallback_node = (CCALLBACK_NODE *)CLIST_DATA_DATA(clist_data);
        if(EC_TRUE == callback_filter(ccallback_node, name, data, func))
        {
            return (ccallback_node);    
        }
    }

    return (NULL_PTR);
}

CCALLBACK_NODE *ccallback_list_push(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func)
{
    CCALLBACK_NODE  *ccallback_node;

    ccallback_node = ccallback_list_search(ccallback_list, name, data, func);
    if(NULL_PTR != ccallback_node)
    {
        dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "warn:ccallback_list_push: "
                                                  "ccallback_list %p [%s], "
                                                  "ccallback_node '%s':%lx:%lx exist already\n",
                                                  ccallback_list,
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  CCALLBACK_NODE_NAME(ccallback_node),
                                                  CCALLBACK_NODE_DATA(ccallback_node),
                                                  CCALLBACK_NODE_FUNC(ccallback_node));
        return (ccallback_node);
    }

    ccallback_node = ccallback_node_new();
    if(NULL_PTR == ccallback_node)
    {
        dbg_log(SEC_0178_CCALLBACK, 0)(LOGSTDOUT, "error:ccallback_list_push: "
                                                  "ccallback_list %p [%s], "
                                                  "new ccallback_node failed\n",
                                                  ccallback_list,
                                                  CCALLBACK_LIST_NAME(ccallback_list));
        return (NULL_PTR);
    }

    CCALLBACK_NODE_NAME(ccallback_node) = name;
    CCALLBACK_NODE_FUNC(ccallback_node) = func;
    CCALLBACK_NODE_DATA(ccallback_node) = data;

    clist_push_back(CCALLBACK_LIST_NODES(ccallback_list), (void *)ccallback_node);
    dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_list_push: "
                                              "ccallback_list %p [%s], "
                                              "push ccallback_node '%s':%lx:%lx done\n",
                                              ccallback_list,
                                              CCALLBACK_LIST_NAME(ccallback_list),
                                              CCALLBACK_NODE_NAME(ccallback_node),
                                              CCALLBACK_NODE_DATA(ccallback_node),
                                              CCALLBACK_NODE_FUNC(ccallback_node));
    
    return (ccallback_node);
}

EC_BOOL ccallback_list_erase(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func)
{
    CCALLBACK_NODE  *ccallback_node;

    ccallback_node = ccallback_list_search(ccallback_list, name, data, func);
    if(NULL_PTR != ccallback_node)
    {
        clist_del(CCALLBACK_LIST_NODES(ccallback_list), (void *)ccallback_node, NULL_PTR);
        
        dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_list_erase: "
                                                  "ccallback_list %p [%s], " 
                                                  "pop '%s'\n",
                                                  ccallback_list,
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  CCALLBACK_NODE_NAME(ccallback_node));
        ccallback_node_free(ccallback_node);
    }

    return (EC_TRUE);
}

EC_BOOL ccallback_list_pop(CCALLBACK_LIST *ccallback_list)
{
    CCALLBACK_NODE  *ccallback_node;

    ccallback_node = clist_pop_back(CCALLBACK_LIST_NODES(ccallback_list));
    if(NULL_PTR != ccallback_node)
    {
        dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_list_pop: "
                                                  "ccallback_list %p [%s], " 
                                                  "pop '%s'\n",
                                                  ccallback_list,
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  CCALLBACK_NODE_NAME(ccallback_node));
        ccallback_node_free(ccallback_node);
    }

    return (EC_TRUE);
}

/*note: reset nodes but not runner or filter*/
EC_BOOL ccallback_list_reset(CCALLBACK_LIST *ccallback_list)
{
    CCALLBACK_NODE  *ccallback_node;

    while(NULL_PTR != (ccallback_node = clist_pop_back(CCALLBACK_LIST_NODES(ccallback_list))))
    {
        dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_list_reset: "
                                                  "ccallback_list %p [%s], " 
                                                  "pop '%s'\n",
                                                  ccallback_list,
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  CCALLBACK_NODE_NAME(ccallback_node));
        ccallback_node_free(ccallback_node);
    }
    
    return (EC_TRUE);
}

EC_BOOL ccallback_list_run_not_check(CCALLBACK_LIST *ccallback_list, UINT32 arg)
{
    CLIST_DATA        *clist_data;
    CCALLBACK_RUNNER   callback_runner;
   
    if(NULL_PTR == CCALLBACK_LIST_RUNNER(ccallback_list))
    {   
        callback_runner = ccallback_node_runner_default;
    }
    else
    {
        callback_runner = CCALLBACK_LIST_RUNNER(ccallback_list);
    }

    /*stack, FILO*/
    CLIST_LOOP_PREV(CCALLBACK_LIST_NODES(ccallback_list), clist_data)
    {
        CCALLBACK_NODE    *ccallback_node;
        const char        *ccallback_node_name;

        ccallback_node = (CCALLBACK_NODE *)CLIST_DATA_DATA(clist_data);
        ccallback_node_name = CCALLBACK_NODE_NAME(ccallback_node);

        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_not_check: [%s] run '%s'\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  ccallback_node_name);
                                                  
        callback_runner(arg, ccallback_node);
        
        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_not_check: [%s] run '%s' ... done\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  ccallback_node_name);           
    }


    dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_not_check: [%s] done\n",
                                              CCALLBACK_LIST_NAME(ccallback_list)); 
    return (EC_TRUE);
}

EC_BOOL ccallback_list_run_and_check(CCALLBACK_LIST *ccallback_list, UINT32 arg)
{
    CLIST_DATA        *clist_data;
    CCALLBACK_RUNNER   callback_runner;

    if(NULL_PTR == CCALLBACK_LIST_RUNNER(ccallback_list))
    {   
        callback_runner = ccallback_node_runner_default;
    }
    else
    {
        callback_runner = CCALLBACK_LIST_RUNNER(ccallback_list);
    }

    /*stack, FILO*/
    CLIST_LOOP_PREV(CCALLBACK_LIST_NODES(ccallback_list), clist_data)
    {
        CCALLBACK_NODE    *ccallback_node;
        const char        *ccallback_node_name;
        EC_BOOL            ret;

        ccallback_node = (CCALLBACK_NODE *)CLIST_DATA_DATA(clist_data);   
        ccallback_node_name = CCALLBACK_NODE_NAME(ccallback_node);
        
        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: [%s] run '%s'\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  ccallback_node_name);

        ret = callback_runner(arg, ccallback_node);
        if(EC_TRUE != ret/* && EC_AGAIN != ret && EC_DONE != ret*/)
        {
            dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: [%s] run '%s' ... terminate [%ld]\n",
                                                      CCALLBACK_LIST_NAME(ccallback_list),
                                                      ccallback_node_name, ret);
            return (ret);
        }

        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: run [%s] '%s' ... done\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  ccallback_node_name);
    }

    dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: run [%s] done\n",
                                              CCALLBACK_LIST_NAME(ccallback_list));    

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

