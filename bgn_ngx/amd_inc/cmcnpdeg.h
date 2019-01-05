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

#ifndef    _CMCNPDEG_H
#define    _CMCNPDEG_H

#include "type.h"
#include "log.h"

#include "cmcnprb.h"
#include "cmcnp.inc"
#include "cmcnpdeg.inc"


void cmcnpdeg_node_init(CMCNPDEG_NODE *node, const uint32_t node_pos);

void cmcnpdeg_node_clean(CMCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdeg_node_clone(const CMCNPDEG_NODE *node_src, CMCNPDEG_NODE *node_des);

void cmcnpdeg_node_print(LOG *log, const CMCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdeg_node_is_empty(const CMCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdeg_is_empty(const CMCNPDEG_NODE *head);

/*--------------------------------------------- DEG list operations ---------------------------------------------*/
void cmcnpdeg_node_add_head(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos);

void cmcnpdeg_node_add_tail(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos);

void cmcnpdeg_node_move_head(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos);

void cmcnpdeg_node_move_tail(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos);

void cmcnpdeg_node_rmv(CMCNP *cmcnp, CMCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cmcnpdeg_pool_init(CMCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cmcnpdeg_list_print(LOG *log, const CMCNP *cmcnp);

#endif    /* _CMCNPDEG_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
