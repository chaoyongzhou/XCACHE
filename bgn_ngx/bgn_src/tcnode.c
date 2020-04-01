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

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "clist.h"
#include "cstring.h"
#include "tcnode.h"
#include "cmpic.inc"
#include "log.h"

#include "cmisc.h"

#include "mm.h"
#include "bgnctrl.h"


/*-------------------------------------------- interface of TASKC_NODE --------------------------------------------*/

EC_BOOL taskc_node_cmp_tcid(const TASKC_NODE *taskc_node_1, TASKC_NODE *taskc_node_2)
{
    if(TASKC_NODE_TCID(taskc_node_1) == TASKC_NODE_TCID(taskc_node_2))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL taskc_node_cmp_tcid_comm(const TASKC_NODE *taskc_node_1, TASKC_NODE *taskc_node_2)
{
    if(TASKC_NODE_TCID(taskc_node_1) != TASKC_NODE_TCID(taskc_node_2)
    || TASKC_NODE_COMM(taskc_node_1) != TASKC_NODE_COMM(taskc_node_2))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void taskc_node_print(LOG *log, const TASKC_NODE *taskc_node)
{
    sys_log(log, "tcid %s, comm %ld, size %ld\n",
                  TASKC_NODE_TCID_STR(taskc_node),
                  TASKC_NODE_COMM(taskc_node),
                  TASKC_NODE_SIZE(taskc_node));
    return;
}

void taskc_node_print_plain(LOG *log, const TASKC_NODE *taskc_node)
{
    sys_print(log, "tcid %s, comm %ld, size %ld\n",
                  TASKC_NODE_TCID_STR(taskc_node),
                  TASKC_NODE_COMM(taskc_node),
                  TASKC_NODE_SIZE(taskc_node));
    return;
}

void taskc_node_sprint(CSTRING *cstring, const TASKC_NODE *taskc_node)
{
    cstring_format(cstring, "tcid %s, comm %ld, size %ld\n",
                  TASKC_NODE_TCID_STR(taskc_node),
                  TASKC_NODE_COMM(taskc_node),
                  TASKC_NODE_SIZE(taskc_node));
    return;
}


TASKC_NODE *taskc_node_new()
{
    TASKC_NODE *taskc_node;

    alloc_static_mem(MM_TASKC_NODE, &taskc_node, LOC_TCNODE_0001);
    if(NULL_PTR == taskc_node)
    {
        dbg_log(SEC_0088_TCNODE, 0)(LOGSTDOUT, "error:taskc_node_new: failed to alloc TASKC_NODE\n");
        return (NULL_PTR);
    }
    taskc_node_init(taskc_node);

    return (taskc_node);
}

EC_BOOL taskc_node_free(TASKC_NODE *taskc_node)
{
    if(NULL_PTR != taskc_node)
    {
        taskc_node_clean(taskc_node);
        free_static_mem(MM_TASKC_NODE, taskc_node, LOC_TCNODE_0002);
    }
    return (EC_TRUE);
}

EC_BOOL taskc_node_init(TASKC_NODE *taskc_node)
{
    TASKC_NODE_TCID(taskc_node) = CMPI_ERROR_TCID;
    TASKC_NODE_COMM(taskc_node) = CMPI_ERROR_COMM;
    TASKC_NODE_SIZE(taskc_node) = 0;
    return (EC_TRUE);
}

EC_BOOL taskc_node_clean(TASKC_NODE *taskc_node)
{
    TASKC_NODE_TCID(taskc_node) = CMPI_ERROR_TCID;
    TASKC_NODE_COMM(taskc_node) = CMPI_ERROR_COMM;
    TASKC_NODE_SIZE(taskc_node) = 0;
    return (EC_TRUE);
}

void taskc_node_clone(const TASKC_NODE *src_taskc_node, TASKC_NODE *des_taskc_node)
{
    TASKC_NODE_TCID(des_taskc_node) = TASKC_NODE_TCID(src_taskc_node);
    TASKC_NODE_COMM(des_taskc_node) = TASKC_NODE_COMM(src_taskc_node);
    TASKC_NODE_SIZE(des_taskc_node) = TASKC_NODE_SIZE(src_taskc_node);
    return;
}

/*-------------------------------------------- interface of TASKC_MGR --------------------------------------------*/
TASKC_MGR * taskc_mgr_new()
{
    TASKC_MGR *taskc_mgr;

    alloc_static_mem(MM_TASKC_MGR, &(taskc_mgr), LOC_TCNODE_0003);
    if(NULL_PTR == taskc_mgr)
    {
        dbg_log(SEC_0088_TCNODE, 0)(LOGSTDOUT, "error:taskc_mgr_new: failed to alloc TASKC_MGR\n");
        return (NULL_PTR);
    }

    taskc_mgr_init(taskc_mgr);
    return (taskc_mgr);
}

void taskc_mgr_free(TASKC_MGR *taskc_mgr)
{
    taskc_mgr_clean(taskc_mgr);
    free_static_mem(MM_TASKC_MGR, (void *)(taskc_mgr), LOC_TCNODE_0004);
    return;
}

void taskc_mgr_init(TASKC_MGR *taskc_mgr)
{
    CLIST *taskc_node_list;

    taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(taskc_mgr);
    clist_init(taskc_node_list, MM_IGNORE, LOC_TCNODE_0005);
    return;
}

void taskc_mgr_clone(const TASKC_MGR *src_taskc_mgr, TASKC_MGR *des_taskc_mgr)
{
    CLIST *src_taskc_node_list;
    CLIST *des_taskc_node_list;

    src_taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(src_taskc_mgr);
    des_taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(des_taskc_mgr);

    clist_clone(src_taskc_node_list, des_taskc_node_list, (CLIST_DATA_DATA_MALLOC)taskc_node_new, (CLIST_DATA_DATA_CLONE)taskc_node_clone);
    return;
}

void taskc_mgr_clean(TASKC_MGR *taskc_mgr)
{
    CLIST *taskc_node_list;

    taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(taskc_mgr);
    clist_clean(taskc_node_list, (CLIST_DATA_DATA_CLEANER)taskc_node_free);
    return;
}

void taskc_mgr_print(LOG *log, const TASKC_MGR *taskc_mgr)
{
    CLIST *taskc_node_list;

    taskc_node_list = (CLIST *)TASKC_MGR_NODE_LIST(taskc_mgr);

    clist_print(log, taskc_node_list, (CLIST_DATA_DATA_PRINT)taskc_node_print_plain);
    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/
