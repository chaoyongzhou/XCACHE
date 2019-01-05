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

#ifndef    _CDCNPDEG_H
#define    _CDCNPDEG_H

#include "type.h"
#include "log.h"

#include "cdcnprb.h"
#include "cdcnp.inc"
#include "cdcnpdeg.inc"


void cdcnpdeg_node_init(CDCNPDEG_NODE *node, const uint32_t node_pos);

void cdcnpdeg_node_clean(CDCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdeg_node_clone(const CDCNPDEG_NODE *node_src, CDCNPDEG_NODE *node_des);

void cdcnpdeg_node_print(LOG *log, const CDCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdeg_node_is_empty(const CDCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdeg_is_empty(const CDCNPDEG_NODE *head);

/*--------------------------------------------- DEG list operations ---------------------------------------------*/
void cdcnpdeg_node_add_head(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos);

void cdcnpdeg_node_add_tail(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos);

void cdcnpdeg_node_move_head(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos);

void cdcnpdeg_node_move_tail(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos);

void cdcnpdeg_node_rmv(CDCNP *cdcnp, CDCNPDEG_NODE *node, const uint32_t node_pos);

EC_BOOL cdcnpdeg_pool_init(CDCNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cdcnpdeg_list_print(LOG *log, const CDCNP *cdcnp);

UINT32 cdcnpdeg_count(const CDCNP *cdcnp);

#endif    /* _CDCNPDEG_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
