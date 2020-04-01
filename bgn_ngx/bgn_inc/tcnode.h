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

#ifndef _TCNODE_H
#define _TCNODE_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "clist.h"
#include "cstring.h"

typedef struct
{
    UINT32 taskc_id;
    UINT32 taskc_comm;
    UINT32 taskc_size;
}TASKC_NODE;

typedef struct
{
    CLIST taskc_node_list;
}TASKC_MGR;

#define TASKC_NODE_TCID(taskc_node)         ((taskc_node)->taskc_id)
#define TASKC_NODE_TCID_STR(taskc_node)     (c_word_to_ipv4(TASKC_NODE_TCID(taskc_node)))
#define TASKC_NODE_COMM(taskc_node)         ((taskc_node)->taskc_comm)
#define TASKC_NODE_SIZE(taskc_node)         ((taskc_node)->taskc_size)

#define TASKC_MGR_NODE_LIST(taskc_mgr)  (&((taskc_mgr)->taskc_node_list))

/*-------------------------------------------- interface of TASKC_NODE --------------------------------------------*/
EC_BOOL taskc_node_cmp_tcid(const TASKC_NODE *taskc_node_1, TASKC_NODE *taskc_node_2);

EC_BOOL taskc_node_cmp_tcid_comm(const TASKC_NODE *taskc_node_1, TASKC_NODE *taskc_node_2);

void    taskc_node_print(LOG *log, const TASKC_NODE *taskc_node);

void    taskc_node_print_plain(LOG *log, const TASKC_NODE *taskc_node);

void    taskc_node_sprint(CSTRING *cstring, const TASKC_NODE *taskc_node);

TASKC_NODE *taskc_node_new();

EC_BOOL taskc_node_free(TASKC_NODE *taskc_node);

EC_BOOL taskc_node_init(TASKC_NODE *taskc_node);

EC_BOOL taskc_node_clean(TASKC_NODE *taskc_node);

void taskc_node_clone(const TASKC_NODE *src_taskc_node, TASKC_NODE *des_taskc_node);

/*-------------------------------------------- interface of TASKC_MGR --------------------------------------------*/

TASKC_MGR * taskc_mgr_new();

void taskc_mgr_free(TASKC_MGR *taskc_mgr);

void taskc_mgr_init(TASKC_MGR *taskc_mgr);

void taskc_mgr_clone(const TASKC_MGR *src_taskc_mgr, TASKC_MGR *des_taskc_mgr);

void taskc_mgr_clean(TASKC_MGR *taskc_mgr);

void taskc_mgr_print(LOG *log, const TASKC_MGR *taskc_mgr);

#endif /*_TCNODE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

