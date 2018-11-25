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

#ifndef    _CDCNPDEL_H
#define    _CDCNPDEL_H

#include "type.h"
#include "log.h"

#include "cdcnprb.h"
#include "cdcnp.inc"
#include "cdcnpdel.inc"


void cdcnpdel_node_init(CDCNPDEL_NODE *node, const uint32_t node_pos);

void cdcnpdel_node_clean(CDCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdel_node_clone(const CDCNPDEL_NODE *node_src, CDCNPDEL_NODE *node_des);

void cdcnpdel_node_print(LOG *log, const CDCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdel_node_is_empty(const CDCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdel_is_empty(const CDCNPDEL_NODE *head);

/*--------------------------------------------- DEL list operations ---------------------------------------------*/
void cdcnpdel_node_add_head(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos);

void cdcnpdel_node_add_tail(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos);

void cdcnpdel_node_move_head(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos);

void cdcnpdel_node_move_tail(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos);

void cdcnpdel_node_rmv(CDCNP *cdcnp, CDCNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdel_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cdcnpdel_list_print(LOG *log, const CDCNP *cdcnp);

#endif    /* _CDCNPDEL_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
