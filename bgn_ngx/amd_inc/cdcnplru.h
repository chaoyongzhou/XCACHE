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

#ifndef    _CDCNPLRU_H
#define    _CDCNPLRU_H

#include "type.h"
#include "log.h"

#include "cdcnprb.h"
#include "cdcnp.inc"
#include "cdcnplru.inc"


void cdcnplru_node_init(CDCNPLRU_NODE *node, const uint32_t node_pos);

void cdcnplru_node_clean(CDCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnplru_node_clone(const CDCNPLRU_NODE *node_src, CDCNPLRU_NODE *node_des);

void cdcnplru_node_print(LOG *log, const CDCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnplru_node_is_empty(const CDCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnplru_is_empty(const CDCNPLRU_NODE *head);

/*--------------------------------------------- LRU list operations ---------------------------------------------*/
void cdcnplru_node_add_head(CDCNP *cdcnp, CDCNPLRU_NODE *node, const uint32_t node_pos);

void cdcnplru_node_add_tail(CDCNP *cdcnp, CDCNPLRU_NODE *node, const uint32_t node_pos);

void cdcnplru_node_move_head(CDCNP *cdcnp, CDCNPLRU_NODE *node, const uint32_t node_pos);

void cdcnplru_node_move_tail(CDCNP *cdcnp, CDCNPLRU_NODE *node, const uint32_t node_pos);

void cdcnplru_node_rmv(CDCNP *cdcnp, CDCNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnplru_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cdcnplru_list_print(LOG *log, const CDCNP *cdcnp);

#endif    /* _CDCNPLRU_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
