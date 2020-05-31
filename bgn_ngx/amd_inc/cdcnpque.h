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

#ifndef    _CDCNPQUE_H
#define    _CDCNPQUE_H

#include "type.h"
#include "log.h"

#include "cdcnprb.h"
#include "cdcnp.inc"
#include "cdcnpque.inc"

void cdcnpque_node_init(CDCNPQUE_NODE *node, const uint32_t node_pos);

void cdcnpque_node_clean(CDCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpque_node_clone(const CDCNPQUE_NODE *node_src, CDCNPQUE_NODE *node_des);

void cdcnpque_node_print(LOG *log, const CDCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpque_node_is_empty(const CDCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpque_is_empty(const CDCNPQUE_NODE *head);

/*--------------------------------------------- QUE list operations ---------------------------------------------*/
void cdcnpque_node_add_head(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos);

void cdcnpque_node_add_tail(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos);

void cdcnpque_node_move_head(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos);

void cdcnpque_node_move_tail(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos);

void cdcnpque_node_rmv(CDCNP *cdcnp, CDCNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpque_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cdcnpque_list_print(LOG *log, const CDCNP *cdcnp);

UINT32 cdcnpque_count(const CDCNP *cdcnp);

void cdcnpque_walk(const CDCNP *cdcnp, void *data, EC_BOOL (*walker)(const CDCNPQUE_NODE *, const uint32_t, void *));


#endif    /* _CDCNPQUE_H */


#ifdef __cplusplus
}
#endif/*__cplusplus*/
