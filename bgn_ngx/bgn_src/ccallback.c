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
        dbg_log(SEC_0178_CCALLBACK, 0)(LOGSTDOUT, "error:ccallback_node_new: "
                                                  "failed to alloc tasks node\n");
        return (NULL_PTR);
    }

    ccallback_node_init(ccallback_node);
    return (ccallback_node);
}

EC_BOOL ccallback_node_init(CCALLBACK_NODE *ccallback_node)
{
    if(NULL_PTR != ccallback_node)
    {
        CCALLBACK_NODE_NAME(ccallback_node)         = NULL_PTR;
        CCALLBACK_NODE_FUNC(ccallback_node)         = NULL_PTR;
        CCALLBACK_NODE_DATA(ccallback_node)         = NULL_PTR;

        CCALLBACK_NODE_USED_FLAG(ccallback_node)    = BIT_FALSE;
        CCALLBACK_NODE_TIMER_FLAG(ccallback_node)   = BIT_FALSE;
    }

    return (EC_TRUE);
}

EC_BOOL ccallback_node_clean(CCALLBACK_NODE *ccallback_node)
{
    if(NULL_PTR != ccallback_node)
    {
        ASSERT(BIT_FALSE == CCALLBACK_NODE_TIMER_FLAG(ccallback_node));

        CCALLBACK_NODE_NAME(ccallback_node)         = NULL_PTR;
        CCALLBACK_NODE_FUNC(ccallback_node)         = NULL_PTR;
        CCALLBACK_NODE_DATA(ccallback_node)         = NULL_PTR;

        CCALLBACK_NODE_USED_FLAG(ccallback_node)    = BIT_FALSE;
        CCALLBACK_NODE_TIMER_FLAG(ccallback_node)   = BIT_FALSE;
    }
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

EC_BOOL ccallback_node_set(CCALLBACK_NODE *ccallback_node, const char *name, void *data, void *func)
{
    if(NULL_PTR != ccallback_node)
    {
        /*override*/

        CCALLBACK_NODE_NAME(ccallback_node)      = name;
        CCALLBACK_NODE_FUNC(ccallback_node)      = func;
        CCALLBACK_NODE_DATA(ccallback_node)      = data;
        CCALLBACK_NODE_USED_FLAG(ccallback_node) = BIT_TRUE;

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ccallback_node_is_used(const CCALLBACK_NODE *ccallback_node)
{
    if(NULL_PTR != ccallback_node
    && BIT_TRUE == CCALLBACK_NODE_USED_FLAG(ccallback_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void ccallback_node_print(LOG *log, const CCALLBACK_NODE *ccallback_node)
{
    if(NULL_PTR != ccallback_node)
    {
        sys_log(log, "ccallback_node_print: "
                     "ccallback_node %p: '%s':%lx:%p, used: %s\n",
                      ccallback_node,
                      CCALLBACK_NODE_NAME(ccallback_node),
                      CCALLBACK_NODE_DATA(ccallback_node),
                      CCALLBACK_NODE_FUNC(ccallback_node),
                      c_bit_bool_str(CCALLBACK_NODE_USED_FLAG(ccallback_node)));
    }
    return;
}

EC_BOOL ccallback_node_run(CCALLBACK_NODE *ccallback_node)
{
    if(NULL_PTR != ccallback_node)
    {
        if(BIT_TRUE == CCALLBACK_NODE_USED_FLAG(ccallback_node))
        {
            if(NULL_PTR != CCALLBACK_NODE_FUNC(ccallback_node))
            {
                CCALLBACK_RUNNER         callback_runner;

                dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_node_run: "
                                                          "%p, name %s, func %p, data %p\n",
                                                          ccallback_node,
                                                          CCALLBACK_NODE_NAME(ccallback_node),
                                                          CCALLBACK_NODE_FUNC(ccallback_node),
                                                          CCALLBACK_NODE_DATA(ccallback_node));

                callback_runner = (CCALLBACK_RUNNER)CCALLBACK_NODE_FUNC(ccallback_node);
                return callback_runner(CCALLBACK_NODE_DATA(ccallback_node));
            }

            dbg_log(SEC_0178_CCALLBACK, 0)(LOGSTDOUT, "error:ccallback_node_run: "
                                                      "%p, func is null\n",
                                                      ccallback_node);
            return (EC_FALSE);
        }

        dbg_log(SEC_0178_CCALLBACK, 9)(LOGSTDOUT, "[DEBUG] ccallback_node_run: "
                                                  "%p, not used\n",
                                                  ccallback_node);

        return (EC_TRUE);
    }

    return (EC_FALSE);
}


EC_BOOL ccallback_node_filter_default(const CCALLBACK_NODE *ccallback_node, const char *name, void *data, void *func)
{
    if(func == CCALLBACK_NODE_FUNC(ccallback_node)
    && data == CCALLBACK_NODE_DATA(ccallback_node)
    && 0 == STRCASECMP(CCALLBACK_NODE_NAME(ccallback_node), name))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL ccallback_node_runner_default(CCALLBACK_NODE *ccallback_node)
{
    ccallback_node_print(LOGSTDOUT, ccallback_node);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

