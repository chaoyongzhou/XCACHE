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
    CCALLBACK_NODE_NAME(ccallback_node)      = NULL_PTR;
    CCALLBACK_NODE_FUNC(ccallback_node)      = NULL_PTR;
    CCALLBACK_NODE_DATA(ccallback_node)      = NULL_PTR;

    CCALLBACK_NODE_USED_FLAG(ccallback_node) = BIT_FALSE;

    return (EC_TRUE);
}

EC_BOOL ccallback_node_clean(CCALLBACK_NODE *ccallback_node)
{
    CCALLBACK_NODE_NAME(ccallback_node)      = NULL_PTR;
    CCALLBACK_NODE_FUNC(ccallback_node)      = NULL_PTR;
    CCALLBACK_NODE_DATA(ccallback_node)      = NULL_PTR;

    CCALLBACK_NODE_USED_FLAG(ccallback_node) = BIT_FALSE;
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
    sys_log(log, "ccallback_node_print: ccallback_node %p: '%s':%lx:%p, used: %s\n",
                  ccallback_node,
                  CCALLBACK_NODE_NAME(ccallback_node),
                  CCALLBACK_NODE_DATA(ccallback_node),
                  CCALLBACK_NODE_FUNC(ccallback_node),
                  c_bit_bool_str(CCALLBACK_NODE_USED_FLAG(ccallback_node)));
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

    cvector_init(CCALLBACK_LIST_NODES(ccallback_list), 2, MM_CCALLBACK_NODE, CVECTOR_LOCK_DISABLE, LOC_CCALLBACK_0003);

    CCALLBACK_LIST_RUNNER(ccallback_list) = NULL_PTR;
    CCALLBACK_LIST_FILTER(ccallback_list) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL ccallback_list_clean(CCALLBACK_LIST *ccallback_list)
{
    CCALLBACK_LIST_NAME(ccallback_list)   = NULL_PTR;

    cvector_clean(CCALLBACK_LIST_NODES(ccallback_list), (CVECTOR_DATA_CLEANER)ccallback_node_free, LOC_CCALLBACK_0004);

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

    cvector_print(log, CCALLBACK_LIST_NODES(ccallback_list), (CVECTOR_DATA_PRINT)ccallback_node_print);
    return;
}

CCALLBACK_NODE *ccallback_list_search(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func)
{
    CCALLBACK_FILTER     callback_filter;
    UINT32               num;
    UINT32               pos;

    if(NULL_PTR != CCALLBACK_LIST_FILTER(ccallback_list))
    {
        callback_filter = CCALLBACK_LIST_FILTER(ccallback_list);
    }
    else
    {
        callback_filter = ccallback_node_filter_default;
    }

    num = cvector_size(CCALLBACK_LIST_NODES(ccallback_list));
    for(pos = 0; pos < num; pos ++)
    {
        CCALLBACK_NODE *ccallback_node;

        ccallback_node = (CCALLBACK_NODE *)cvector_get(CCALLBACK_LIST_NODES(ccallback_list), pos);

        /*skip not used node*/
        if(NULL_PTR == ccallback_node || BIT_FALSE == CCALLBACK_NODE_USED_FLAG(ccallback_node))
        {
            continue;
        }

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
                                                  "ccallback_node '%s':%lx:%p exist already\n",
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

    CCALLBACK_NODE_NAME(ccallback_node)      = name;
    CCALLBACK_NODE_FUNC(ccallback_node)      = func;
    CCALLBACK_NODE_DATA(ccallback_node)      = data;
    CCALLBACK_NODE_USED_FLAG(ccallback_node) = BIT_TRUE;

    cvector_push(CCALLBACK_LIST_NODES(ccallback_list), (void *)ccallback_node);

    dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_list_push: "
                                              "ccallback_list %p [%s], "
                                              "push ccallback_node '%s':%lx:%p done => size %ld\n",
                                              ccallback_list,
                                              CCALLBACK_LIST_NAME(ccallback_list),
                                              CCALLBACK_NODE_NAME(ccallback_node),
                                              CCALLBACK_NODE_DATA(ccallback_node),
                                              CCALLBACK_NODE_FUNC(ccallback_node),
                                              cvector_size(CCALLBACK_LIST_NODES(ccallback_list)));

    return (ccallback_node);
}

EC_BOOL ccallback_list_erase(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func)
{
    CCALLBACK_NODE  *ccallback_node;

    ccallback_node = ccallback_list_search(ccallback_list, name, data, func);
    if(NULL_PTR != ccallback_node)
    {
        /*set node to be not used*/
        CCALLBACK_NODE_USED_FLAG(ccallback_node) = BIT_FALSE;

        dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_list_erase: "
                                                  "ccallback_list %p [%s], "
                                                  "erase '%s'\n",
                                                  ccallback_list,
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  CCALLBACK_NODE_NAME(ccallback_node));
    }

    return (EC_TRUE);
}

/*clear dead nodes. be careful if must use this interface!*/
EC_BOOL ccallback_list_clear(CCALLBACK_LIST *ccallback_list)
{
    UINT32           num;
    UINT32           pos;

    num = cvector_size(CCALLBACK_LIST_NODES(ccallback_list));

    for(pos = 0; pos < num; pos ++)
    {
        CCALLBACK_NODE *ccallback_node;

        ccallback_node = (CCALLBACK_NODE *)cvector_get(CCALLBACK_LIST_NODES(ccallback_list), pos);

        /*skip used node*/
        if(NULL_PTR == ccallback_node || BIT_TRUE == CCALLBACK_NODE_USED_FLAG(ccallback_node))
        {
            continue;
        }

        cvector_set(CCALLBACK_LIST_NODES(ccallback_list), pos, NULL_PTR);

        ccallback_node_free(ccallback_node);
    }

    return (EC_TRUE);
}

/*note: reset nodes but not runner or filter*/
EC_BOOL ccallback_list_reset(CCALLBACK_LIST *ccallback_list)
{
    UINT32           num;
    UINT32           pos;

    /*set all nodes to be not used*/

    num = cvector_size(CCALLBACK_LIST_NODES(ccallback_list));

    for(pos = 0; pos < num; pos ++)
    {
        CCALLBACK_NODE *ccallback_node;

        ccallback_node = (CCALLBACK_NODE *)cvector_get(CCALLBACK_LIST_NODES(ccallback_list), pos);

        if(NULL_PTR == ccallback_node || BIT_FALSE == CCALLBACK_NODE_USED_FLAG(ccallback_node))
        {
            continue;
        }

        /*set node to be not used*/
        CCALLBACK_NODE_USED_FLAG(ccallback_node) = BIT_FALSE;

        dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_list_reset: "
                                                  "ccallback_list %p [%s], "
                                                  "reset [%ld/%ld] '%s'\n",
                                                  ccallback_list,
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  pos, num,
                                                  CCALLBACK_NODE_NAME(ccallback_node));
    }

    return (EC_TRUE);
}

EC_BOOL ccallback_list_run_not_check(CCALLBACK_LIST *ccallback_list, UINT32 arg)
{
    CCALLBACK_RUNNER   callback_runner;

    UINT32             num;
    UINT32             pos;

    if(NULL_PTR == CCALLBACK_LIST_RUNNER(ccallback_list))
    {
        callback_runner = ccallback_node_runner_default;
    }
    else
    {
        callback_runner = CCALLBACK_LIST_RUNNER(ccallback_list);
    }

    num = cvector_size(CCALLBACK_LIST_NODES(ccallback_list));

    /*stack, FILO*/
    /*note: if new node is pushed into cvector during old node running, new node should not run at this loop*/
    for(pos = num; pos -- > 0; )
    {
        CCALLBACK_NODE    *ccallback_node;
        const char        *ccallback_node_name;

        ccallback_node = (CCALLBACK_NODE *)cvector_get(CCALLBACK_LIST_NODES(ccallback_list), pos);

        /*skip not used node*/
        if(NULL_PTR == ccallback_node || BIT_FALSE == CCALLBACK_NODE_USED_FLAG(ccallback_node))
        {
            continue;
        }

        ccallback_node_name = CCALLBACK_NODE_NAME(ccallback_node);

        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_not_check: [%s] run [%ld/%ld] '%s'\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  pos, num,
                                                  ccallback_node_name);

        callback_runner(arg, ccallback_node);

        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_not_check: [%s] run [%ld/%ld] '%s' ... done\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  pos, num,
                                                  ccallback_node_name);
    }

    dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_not_check: [%s] done\n",
                                              CCALLBACK_LIST_NAME(ccallback_list));

    return (EC_TRUE);
}

EC_BOOL ccallback_list_run_and_check(CCALLBACK_LIST *ccallback_list, UINT32 arg)
{
    CCALLBACK_RUNNER   callback_runner;

    UINT32             num;
    UINT32             pos;

    if(NULL_PTR == CCALLBACK_LIST_RUNNER(ccallback_list))
    {
        callback_runner = ccallback_node_runner_default;
    }
    else
    {
        callback_runner = CCALLBACK_LIST_RUNNER(ccallback_list);
    }

    num = cvector_size(CCALLBACK_LIST_NODES(ccallback_list));

    /*stack, FILO*/
    /*note: if new node is pushed into cvector during old node running, new node should not run at this loop*/
    for(pos = num; pos -- > 0; )
    {
        CCALLBACK_NODE    *ccallback_node;
        const char        *ccallback_node_name;
        EC_BOOL            ret;

        ccallback_node = (CCALLBACK_NODE *)cvector_get(CCALLBACK_LIST_NODES(ccallback_list), pos);

        /*skip not used node*/
        if(NULL_PTR == ccallback_node || BIT_FALSE == CCALLBACK_NODE_USED_FLAG(ccallback_node))
        {
            continue;
        }

        ccallback_node_name = CCALLBACK_NODE_NAME(ccallback_node);

        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: [%s] run [%ld/%ld] '%s' [old size %ld, cur size %ld] [%p]\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  pos, num,
                                                  ccallback_node_name,
                                                  num, cvector_size(CCALLBACK_LIST_NODES(ccallback_list)),
                                                  ccallback_node);

        ret = callback_runner(arg, ccallback_node);
        if(EC_TRUE != ret/* && EC_AGAIN != ret && EC_DONE != ret*/)
        {
            dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: [%s] run [%ld/%ld] '%s' ... terminate [%ld]\n",
                                                      CCALLBACK_LIST_NAME(ccallback_list),
                                                      pos, num,
                                                      ccallback_node_name, ret);

            return (ret);
        }

        dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: [%s] run [%ld/%ld] '%s' ... ok\n",
                                                  CCALLBACK_LIST_NAME(ccallback_list),
                                                  pos, num,
                                                  ccallback_node_name);
    }

    dbg_log(SEC_0178_CCALLBACK, 5)(LOGSTDOUT, "[DEBUG] ccallback_list_run_and_check: run [%s] done\n",
                                              CCALLBACK_LIST_NAME(ccallback_list));

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

