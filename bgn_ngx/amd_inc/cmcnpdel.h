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

#ifndef    _CMCNPDEL_H
#define    _CMCNPDEL_H

#include "type.h"
#include "log.h"

#include "cmcnprb.h"
#include "cmcnp.inc"
#include "cmcnpdel.inc"


void cmcnpdel_node_init(CMCNPDEL_NODE *node, const uint32_t node_pos);

void cmcnpdel_node_clean(CMCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdel_node_clone(const CMCNPDEL_NODE *node_src, CMCNPDEL_NODE *node_des);

void cmcnpdel_node_print(LOG *log, const CMCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdel_node_is_empty(const CMCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdel_is_empty(const CMCNPDEL_NODE *head);

/*--------------------------------------------- DEL list operations ---------------------------------------------*/
void cmcnpdel_node_add_head(CMCNP *cmcnp, CMCNPDEL_NODE *node, const uint32_t node_pos);

void cmcnpdel_node_add_tail(CMCNP *cmcnp, CMCNPDEL_NODE *node, const uint32_t node_pos);

void cmcnpdel_node_move_head(CMCNP *cmcnp, CMCNPDEL_NODE *node, const uint32_t node_pos);

void cmcnpdel_node_move_tail(CMCNP *cmcnp, CMCNPDEL_NODE *node, const uint32_t node_pos);

void cmcnpdel_node_rmv(CMCNP *cmcnp, CMCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdel_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cmcnpdel_list_print(LOG *log, const CMCNP *cmcnp);

#endif    /* _CMCNPDEL_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
