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

#ifndef    _CMCNPLRU_H
#define    _CMCNPLRU_H

#include "type.h"
#include "log.h"

#include "cmcnprb.h"
#include "cmcnp.inc"
#include "cmcnplru.inc"


void cmcnplru_node_init(CMCNPLRU_NODE *node, const uint32_t node_pos);

void cmcnplru_node_clean(CMCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnplru_node_clone(const CMCNPLRU_NODE *node_src, CMCNPLRU_NODE *node_des);

void cmcnplru_node_print(LOG *log, const CMCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnplru_node_is_empty(const CMCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnplru_is_empty(const CMCNPLRU_NODE *head);

/*--------------------------------------------- LRU list operations ---------------------------------------------*/
void cmcnplru_node_add_head(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos);

void cmcnplru_node_add_tail(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos);

void cmcnplru_node_move_head(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos);

void cmcnplru_node_move_tail(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos);

void cmcnplru_node_rmv(CMCNP *cmcnp, CMCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnplru_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cmcnplru_list_print(LOG *log, const CMCNP *cmcnp);

#endif    /* _CMCNPLRU_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
