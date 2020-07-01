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

#ifndef _CTIMEOUT_H
#define _CTIMEOUT_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "ccallback.h"
#include "crb.h"

typedef struct
{
    uint64_t                    o_msec;       /*timeout in msec (must > 0)*/
    uint64_t                    s_msec;       /*start time in msec*/
    uint64_t                    e_msec;       /*end time in msec*/

    CCALLBACK_NODE              timeout_cb;
}CTIMEOUT_NODE;

#define CTIMEOUT_NODE_O_MSEC(ctimeout_node)             ((ctimeout_node)->o_msec)
#define CTIMEOUT_NODE_S_MSEC(ctimeout_node)             ((ctimeout_node)->s_msec)
#define CTIMEOUT_NODE_E_MSEC(ctimeout_node)             ((ctimeout_node)->e_msec)
#define CTIMEOUT_NODE_CB(ctimeout_node)                 (&((ctimeout_node)->timeout_cb))


CTIMEOUT_NODE *ctimeout_node_new();

EC_BOOL ctimeout_node_init(CTIMEOUT_NODE *ctimeout_node);

EC_BOOL ctimeout_node_clean(CTIMEOUT_NODE *ctimeout_node);

EC_BOOL ctimeout_node_free(CTIMEOUT_NODE *ctimeout_node);

EC_BOOL ctimeout_node_is_used(const CTIMEOUT_NODE *ctimeout_node);

EC_BOOL ctimeout_node_set_timeout(CTIMEOUT_NODE *ctimeout_node, const uint64_t timeout_msec);

EC_BOOL ctimeout_node_set_callback(CTIMEOUT_NODE *ctimeout_node, const char *name, void *data, void *func, const uint64_t timeout_msec);

EC_BOOL ctimeout_node_run_callback(CTIMEOUT_NODE *ctimeout_node);

void    ctimeout_node_print(LOG *log, const CTIMEOUT_NODE *ctimeout_node);

int ctimeout_node_cmp(const CTIMEOUT_NODE *ctimeout_node_1st, const CTIMEOUT_NODE *ctimeout_node_2nd);

EC_BOOL ctimeout_tree_add_timer(CRB_TREE *crb_tree, CTIMEOUT_NODE *ctimeout_node);

EC_BOOL ctimeout_tree_del_timer(CRB_TREE *crb_tree, CTIMEOUT_NODE *ctimeout_node);

uint64_t ctimeout_tree_find_timer(CRB_TREE *crb_tree);

EC_BOOL ctimeout_tree_process_timer(CRB_TREE *crb_tree);


#endif/*_CTIMEOUT_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

