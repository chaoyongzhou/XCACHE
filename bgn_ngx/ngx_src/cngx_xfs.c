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
#include "cmisc.h"

#include "cmpic.inc"
#include "findex.inc"

#include "task.h"

#include "cmon.h"
#include "csdisc.h"
#include "cngx_xfs.h"


/*
*
* actually ask xfs to register ngx in order to obtain real comm of xfs
*
*/
EC_BOOL cngx_reg_xfs_0(const UINT32 xfs_tcid)
{
    MOD_NODE   recv_mod_node;

    MOD_NODE_TCID(&recv_mod_node) = xfs_tcid;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one xfs*/

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_cxfs_reg_ngx, CMPI_ERROR_MODI);
    return (EC_TRUE);
}

EC_BOOL cngx_reg_xfs_1(const UINT32 xfs_tcid)
{
    CMON_NODE cmon_node;

    /*add XFS to NGX BGN*/
    cmon_node_init(&cmon_node);
    CMON_NODE_TCID(&cmon_node)  = xfs_tcid;
    CMON_NODE_MODI(&cmon_node)  = 0;
    CMON_NODE_STATE(&cmon_node) = CMON_NODE_IS_UP;
    cmon_add_node(task_brd_default_get_cmon_id(), &cmon_node);

    cmon_node_clean(&cmon_node);

    return (EC_TRUE);
}

EC_BOOL cngx_reg_xfs_2(const UINT32 xfs_tcid)
{
    TASK_BRD                *task_brd;
    TASKS_CFG               *tasks_cfg;

    CMON_NODE                cmon_node;
    MOD_NODE                 recv_mod_node;

    task_brd = task_brd_default_get();

    tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), xfs_tcid, CMPI_ANY_MASK, CMPI_ANY_MASK);
    if(NULL_PTR == tasks_cfg)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:cngx_reg_xfs: no xfs '%s' configured\n",
                                             c_word_to_ipv4(xfs_tcid));
        return (EC_FALSE);
    }

    /*init*/
    cmon_node_init(&cmon_node);
    CMON_NODE_TCID(&cmon_node)   = TASKS_CFG_TCID(tasks_cfg);
    CMON_NODE_IPADDR(&cmon_node) = TASKS_CFG_SRVIPADDR(tasks_cfg);
    CMON_NODE_PORT(&cmon_node)   = TASKS_CFG_SRVPORT(tasks_cfg);
    CMON_NODE_MODI(&cmon_node)   = 0;/*only one xfs*/
    CMON_NODE_STATE(&cmon_node)  = CMON_NODE_IS_UP; /*ngx connect xfs, and regard xfs is up*/

    if(EC_FALSE == cmon_add_node(task_brd_default_get_cmon_id(), &cmon_node))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cngx_reg_xfs: "
                        "add cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) failed\n",
                        c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(&cmon_node)), CMON_NODE_PORT(&cmon_node),
                        CMON_NODE_MODI(&cmon_node),
                        cmon_node_state(&cmon_node)
                        );
    }
    else
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cngx_reg_xfs: "
                        "add cmon_node (tcid %s, srv %s:%ld, modi %ld, state %s) succ\n",
                        c_word_to_ipv4(CMON_NODE_TCID(&cmon_node)),
                        c_word_to_ipv4(CMON_NODE_IPADDR(&cmon_node)), CMON_NODE_PORT(&cmon_node),
                        CMON_NODE_MODI(&cmon_node),
                        cmon_node_state(&cmon_node)
                        );
    }

    MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_FWD_RANK;
    MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

    task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &recv_mod_node,
             NULL_PTR,
             FI_super_connect, CMPI_ERROR_MODI, xfs_tcid, CMPI_ANY_COMM, (UINT32)CSOCKET_CNODE_NUM);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cngx_reg_xfs: reg xfs '%s'\n",
                                         c_word_to_ipv4(xfs_tcid));

    return (EC_TRUE);
}


EC_BOOL cngx_reg_xfs(const UINT32 xfs_tcid)
{
    return cngx_reg_xfs_2(xfs_tcid);
}

#endif/*(SWITCH_ON == NGX_BGN_SWITCH)*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
