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

#include "cmisc.h"
#include "ctimeout.h"
#include "crb.h"

#include "ctimeout.h"

CTIMEOUT_NODE *ctimeout_node_new()
{
    CTIMEOUT_NODE *ctimeout_node;

    alloc_static_mem(MM_CTIMEOUT_NODE, &ctimeout_node, LOC_CTIMEOUT_0001);
    if(NULL_PTR == ctimeout_node)
    {
        dbg_log(SEC_0097_CTIMEOUT, 0)(LOGSTDOUT, "error:ctimeout_node_new: "
                                                 "failed to alloc tasks node\n");
        return (NULL_PTR);
    }

    ctimeout_node_init(ctimeout_node);
    return (ctimeout_node);
}

EC_BOOL ctimeout_node_init(CTIMEOUT_NODE *ctimeout_node)
{
    if(NULL_PTR != ctimeout_node)
    {
        CTIMEOUT_NODE_O_MSEC(ctimeout_node)    = 0;
        CTIMEOUT_NODE_S_MSEC(ctimeout_node)    = 0;
        CTIMEOUT_NODE_E_MSEC(ctimeout_node)    = 0;

        ccallback_node_init(CTIMEOUT_NODE_CB(ctimeout_node));
    }

    return (EC_TRUE);
}

EC_BOOL ctimeout_node_clean(CTIMEOUT_NODE *ctimeout_node)
{
    if(NULL_PTR != ctimeout_node)
    {
        CTIMEOUT_NODE_O_MSEC(ctimeout_node)    = 0;
        CTIMEOUT_NODE_S_MSEC(ctimeout_node)    = 0;
        CTIMEOUT_NODE_E_MSEC(ctimeout_node)    = 0;

        ccallback_node_clean(CTIMEOUT_NODE_CB(ctimeout_node));
    }
    return (EC_TRUE);
}

EC_BOOL ctimeout_node_free(CTIMEOUT_NODE *ctimeout_node)
{
    if(NULL_PTR != ctimeout_node)
    {
        ctimeout_node_clean(ctimeout_node);
        free_static_mem(MM_CTIMEOUT_NODE, ctimeout_node, LOC_CTIMEOUT_0002);
    }
    return (EC_TRUE);
}

EC_BOOL ctimeout_node_is_used(const CTIMEOUT_NODE *ctimeout_node)
{
    return ccallback_node_is_used(CTIMEOUT_NODE_CB(ctimeout_node));
}

EC_BOOL ctimeout_node_set_timeout(CTIMEOUT_NODE *ctimeout_node, const uint64_t timeout_msec)
{
    if(NULL_PTR != ctimeout_node)
    {
        CTIMEOUT_NODE_O_MSEC(ctimeout_node) = timeout_msec;

        if(0 < timeout_msec)
        {
            uint64_t    time_msec_cur;

            time_msec_cur = c_get_cur_time_msec();
            CTIMEOUT_NODE_S_MSEC(ctimeout_node) = time_msec_cur + 0;
            CTIMEOUT_NODE_E_MSEC(ctimeout_node) = time_msec_cur + timeout_msec;
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}


EC_BOOL ctimeout_node_set_callback(CTIMEOUT_NODE *ctimeout_node, const char *name, void *data, void *func, const uint64_t timeout_msec)
{
    if(NULL_PTR != ctimeout_node)
    {
        /*override*/

        ccallback_node_set(CTIMEOUT_NODE_CB(ctimeout_node), name, data, func);
        ctimeout_node_set_timeout(ctimeout_node, timeout_msec);

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL ctimeout_node_run_callback(CTIMEOUT_NODE *ctimeout_node)
{
    if(NULL_PTR != ctimeout_node)
    {
        return ccallback_node_run(CTIMEOUT_NODE_CB(ctimeout_node));
    }

    return (EC_FALSE);
}

void ctimeout_node_print(LOG *log, const CTIMEOUT_NODE *ctimeout_node)
{
    if(NULL_PTR != ctimeout_node)
    {
        sys_log(log, "ctimeout_node_print: "
                     "ctimeout_node %p: timeout %ld, start %ld, end %ld, "
                     "callback ('%s':%lx:%p, used: %s)\n",
                      ctimeout_node,
                      CTIMEOUT_NODE_O_MSEC(ctimeout_node),
                      CTIMEOUT_NODE_S_MSEC(ctimeout_node),
                      CTIMEOUT_NODE_E_MSEC(ctimeout_node),
                      CCALLBACK_NODE_NAME(CTIMEOUT_NODE_CB(ctimeout_node)),
                      CCALLBACK_NODE_DATA(CTIMEOUT_NODE_CB(ctimeout_node)),
                      CCALLBACK_NODE_FUNC(CTIMEOUT_NODE_CB(ctimeout_node)),
                      c_bit_bool_str(CCALLBACK_NODE_USED_FLAG(CTIMEOUT_NODE_CB(ctimeout_node))));
    }
    return;
}

int ctimeout_node_cmp(const CTIMEOUT_NODE *ctimeout_node_1st, const CTIMEOUT_NODE *ctimeout_node_2nd)
{
    if(ctimeout_node_1st == ctimeout_node_2nd)
    {
        return (0);
    }

    if(CTIMEOUT_NODE_E_MSEC(ctimeout_node_1st) > CTIMEOUT_NODE_E_MSEC(ctimeout_node_2nd))
    {
        return (1);
    }

    if(CTIMEOUT_NODE_E_MSEC(ctimeout_node_1st) < CTIMEOUT_NODE_E_MSEC(ctimeout_node_2nd))
    {
        return (-1);
    }

    if(ctimeout_node_1st > ctimeout_node_2nd)
    {
        return (1);
    }

    /*ctimeout_node_1st < ctimeout_node_2nd*/
    return (-1);
}

EC_BOOL ctimeout_tree_add_timer(CRB_TREE *crb_tree, CTIMEOUT_NODE *ctimeout_node)
{
    CRB_NODE    *crb_node;

    crb_node = crb_tree_insert_data(crb_tree, (void *)ctimeout_node);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0097_CTIMEOUT, 0)(LOGSTDOUT, "error:ctimeout_tree_add_timer: "
                                                 "add timer %p failed\n",
                                                 ctimeout_node);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != (void *)ctimeout_node)
    {
        dbg_log(SEC_0097_CTIMEOUT, 0)(LOGSTDOUT, "error:ctimeout_tree_add_timer: "
                                                 "found duplicate timer %p vs %p failed\n",
                                                 CRB_NODE_DATA(crb_node),
                                                 ctimeout_node);
        return (EC_FALSE);
    }

    CCALLBACK_NODE_TIMER_FLAG(CTIMEOUT_NODE_CB(ctimeout_node)) = BIT_TRUE;

    dbg_log(SEC_0097_CTIMEOUT, 5)(LOGSTDOUT, "[DEBUG] ctimeout_tree_add_timer: "
                                             "add timer %p (name:%s,o:%ld,s:%ld,e:%ld) done\n",
                                             ctimeout_node,
                                             CCALLBACK_NODE_NAME(CTIMEOUT_NODE_CB(ctimeout_node)),
                                             CTIMEOUT_NODE_O_MSEC(ctimeout_node),
                                             CTIMEOUT_NODE_S_MSEC(ctimeout_node),
                                             CTIMEOUT_NODE_E_MSEC(ctimeout_node));
    return (EC_TRUE);
}

EC_BOOL ctimeout_tree_del_timer(CRB_TREE *crb_tree, CTIMEOUT_NODE *ctimeout_node)
{
    if(0 < CTIMEOUT_NODE_O_MSEC(ctimeout_node))
    {
        if(EC_FALSE == crb_tree_delete_data(crb_tree, (void *)ctimeout_node))
        {
            dbg_log(SEC_0097_CTIMEOUT, 0)(LOGSTDOUT, "error:ctimeout_tree_del_timer: "
                                                     "del timer %p (name:%s,o:%ld,s:%ld,e:%ld) failed\n",
                                                     ctimeout_node,
                                                     CCALLBACK_NODE_NAME(CTIMEOUT_NODE_CB(ctimeout_node)),
                                                     CTIMEOUT_NODE_O_MSEC(ctimeout_node),
                                                     CTIMEOUT_NODE_S_MSEC(ctimeout_node),
                                                     CTIMEOUT_NODE_E_MSEC(ctimeout_node));

            return (EC_FALSE);
        }

        CCALLBACK_NODE_TIMER_FLAG(CTIMEOUT_NODE_CB(ctimeout_node)) = BIT_FALSE;

        dbg_log(SEC_0097_CTIMEOUT, 5)(LOGSTDOUT, "[DEBUG] ctimeout_tree_del_timer: "
                                                 "del timer %p (name:%s,o:%ld,s:%ld,e:%ld) done\n",
                                                 ctimeout_node,
                                                 CCALLBACK_NODE_NAME(CTIMEOUT_NODE_CB(ctimeout_node)),
                                                 CTIMEOUT_NODE_O_MSEC(ctimeout_node),
                                                 CTIMEOUT_NODE_S_MSEC(ctimeout_node),
                                                 CTIMEOUT_NODE_E_MSEC(ctimeout_node));
        return (EC_TRUE);
    }

    dbg_log(SEC_0097_CTIMEOUT, 0)(LOGSTDOUT, "warn:ctimeout_tree_del_timer: "
                                             "del timer %p (name:%s,o:%ld,s:%ld,e:%ld) => giveup\n",
                                             ctimeout_node,
                                             CCALLBACK_NODE_NAME(CTIMEOUT_NODE_CB(ctimeout_node)),
                                             CTIMEOUT_NODE_O_MSEC(ctimeout_node),
                                             CTIMEOUT_NODE_S_MSEC(ctimeout_node),
                                             CTIMEOUT_NODE_E_MSEC(ctimeout_node));
    return (EC_TRUE);
}

uint64_t ctimeout_tree_find_timer(CRB_TREE *crb_tree)
{
    CTIMEOUT_NODE  *ctimeout_node;
    uint64_t        cur_msec;

    ctimeout_node = crb_tree_first_data(crb_tree);
    if(NULL_PTR == ctimeout_node)
    {
        return ((uint64_t)-1);
    }

    cur_msec = c_get_cur_time_msec();
    if(cur_msec >= CTIMEOUT_NODE_E_MSEC(ctimeout_node))
    {
        return ((uint64_t)0);
    }

    /*left msec*/
    return (CTIMEOUT_NODE_E_MSEC(ctimeout_node) - cur_msec);
}

EC_BOOL ctimeout_tree_process_timer(CRB_TREE *crb_tree)
{
    uint64_t        cur_msec;

    cur_msec = c_get_cur_time_msec();

    for(;;)
    {
        CTIMEOUT_NODE  *ctimeout_node;

        ctimeout_node = crb_tree_first_data(crb_tree);
        if(NULL_PTR == ctimeout_node)
        {
            return (EC_TRUE);
        }

        /*not timeout*/
        if(cur_msec < CTIMEOUT_NODE_E_MSEC(ctimeout_node))
        {
            break;
        }

        /*process timeout*/
        ASSERT(0 < CTIMEOUT_NODE_O_MSEC(ctimeout_node));

        ctimeout_tree_del_timer(crb_tree, ctimeout_node);

        /*handle timeout*/
        ctimeout_node_run_callback(ctimeout_node);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

