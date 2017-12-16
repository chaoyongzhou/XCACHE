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

#ifndef _CROUTER_H
#define _CROUTER_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "cvector.h"
#include "crouter.inc"
#include "taskcfg.inc"

CROUTER_NODE *crouter_node_new(const UINT32 des_tcid);

CROUTER_NODE *crouter_node_create(const UINT32 des_tcid, const TASKS_NODE *next_hop_tasks_node);

EC_BOOL crouter_node_init(CROUTER_NODE *crouter_node, const UINT32 des_tcid);

EC_BOOL crouter_node_clean(CROUTER_NODE *crouter_node);

EC_BOOL crouter_node_free(CROUTER_NODE *crouter_node);

EC_BOOL crouter_node_is_empty(const CROUTER_NODE *crouter_node);

void    crouter_node_print(LOG *log, const CROUTER_NODE *crouter_node);

void    crouter_node_sprint_in_plain(CSTRING *cstring, const CROUTER_NODE *crouter_node, UINT32 *index);

void    crouter_node_print_in_plain(LOG *log, const CROUTER_NODE *crouter_node, UINT32 *index);

UINT32 crouter_node_add_next_hop(CROUTER_NODE *crouter_node, const TASKS_NODE *tasks_node);

TASKS_NODE * crouter_node_rmv_next_hop(CROUTER_NODE *crouter_node, const TASKS_NODE *tasks_node);

TASKS_NODE * crouter_node_rmv_next_hop_by_tcid(CROUTER_NODE *crouter_node, const UINT32 next_hop_tcid);

TASKS_NODE * crouter_node_rmv_next_hop_by_pos(CROUTER_NODE *crouter_node, const UINT32 next_hop_pos);

UINT32 crouter_node_count_next_hop(const CROUTER_NODE *crouter_node);

UINT32 crouter_node_search_next_hop_by_tcid(CROUTER_NODE *crouter_node, const UINT32 next_hop_tcid);

TASKS_NODE *crouter_node_find_next_hop_by_tcid(CROUTER_NODE *crouter_node, const UINT32 next_hop_tcid);

TASKS_NODE * crouter_node_min_load_next_hop(const CROUTER_NODE *crouter_node);

CROUTER_NODE_VEC *crouter_node_vec_new();

EC_BOOL crouter_node_vec_init(CROUTER_NODE_VEC *crouter_node_vec);

EC_BOOL crouter_node_vec_clean(CROUTER_NODE_VEC *crouter_node_vec);

EC_BOOL crouter_node_vec_free(CROUTER_NODE_VEC *crouter_node_vec);

CROUTER_NODE *crouter_node_vec_get(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos);

CROUTER_NODE *crouter_node_vec_get_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos);

CROUTER_NODE *crouter_node_vec_add(CROUTER_NODE_VEC *crouter_node_vec, const TASKS_WORKER *tasks_worker, const UINT32 des_tcid, const UINT32 next_hop_tcid);

CROUTER_NODE *crouter_node_vec_add_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const TASKS_WORKER *tasks_worker, const UINT32 des_tcid, const UINT32 next_hop_tcid);

CROUTER_NODE *crouter_node_vec_erase(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos);

CROUTER_NODE *crouter_node_vec_erase_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 pos);

EC_BOOL crouter_node_vec_rmv(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid, const UINT32 next_hop_tcid);

EC_BOOL crouter_node_vec_rmv_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid, const UINT32 next_hop_tcid);

UINT32 crouter_node_vec_search(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid);

UINT32 crouter_node_vec_search_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid);

CROUTER_NODE *crouter_node_vec_find(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid);

CROUTER_NODE *crouter_node_vec_find_no_lock(CROUTER_NODE_VEC *crouter_node_vec, const UINT32 des_tcid);

CROUTER_CFG *crouter_cfg_new(const UINT32 src_tcid, const UINT32 des_tcid, const UINT32 next_hop, const UINT32 max_hops);

CROUTER_CFG *crouter_cfg_new_0();

EC_BOOL crouter_cfg_init(CROUTER_CFG *crouter_cfg, const UINT32 src_tcid, const UINT32 des_tcid, const UINT32 next_hop, const UINT32 max_hops);

EC_BOOL crouter_cfg_clean(CROUTER_CFG *crouter_cfg);

EC_BOOL crouter_cfg_free(CROUTER_CFG *crouter_cfg);

EC_BOOL crouter_cfg_clone(const CROUTER_CFG *src_crouter_cfg, CROUTER_CFG *des_crouter_cfg);

void    crouter_cfg_print(LOG *log, CROUTER_CFG *crouter_cfg);
void    crouter_cfg_print_xml(LOG *log, const CROUTER_CFG *crouter_cfg, const UINT32 level);

#endif /*_CROUTER_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

