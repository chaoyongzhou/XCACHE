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

#ifndef    _CMCNPQUE_H
#define    _CMCNPQUE_H

#include "type.h"
#include "log.h"

#include "cmcnprb.h"
#include "cmcnp.inc"
#include "cmcnpque.inc"


void cmcnpque_node_init(CMCNPQUE_NODE *node, const uint32_t node_pos);

void cmcnpque_node_clean(CMCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpque_node_clone(const CMCNPQUE_NODE *node_src, CMCNPQUE_NODE *node_des);

void cmcnpque_node_print(LOG *log, const CMCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpque_node_is_empty(const CMCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpque_is_empty(const CMCNPQUE_NODE *head);

/*--------------------------------------------- QUE list operations ---------------------------------------------*/
void cmcnpque_node_add_head(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos);

void cmcnpque_node_add_tail(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos);

void cmcnpque_node_move_head(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos);

void cmcnpque_node_move_tail(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos);

void cmcnpque_node_rmv(CMCNP *cmcnp, CMCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpque_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cmcnpque_list_print(LOG *log, const CMCNP *cmcnp);

#endif    /* _CMCNPQUE_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
