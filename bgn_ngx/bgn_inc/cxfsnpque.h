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

#ifndef    _CXFSNPQUE_H
#define    _CXFSNPQUE_H

#include "type.h"
#include "log.h"

#include "cxfsnprb.h"
#include "cxfsnp.inc"
#include "cxfsnpque.inc"


void cxfsnpque_node_init(CXFSNPQUE_NODE *node, const uint32_t node_pos);

void cxfsnpque_node_clean(CXFSNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpque_node_clone(const CXFSNPQUE_NODE *node_src, CXFSNPQUE_NODE *node_des);

void cxfsnpque_node_print(LOG *log, const CXFSNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpque_node_is_empty(const CXFSNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpque_is_empty(const CXFSNPQUE_NODE *head);

/*--------------------------------------------- QUE list operations ---------------------------------------------*/
void cxfsnpque_node_add_head(CXFSNP *cxfsnp, CXFSNPQUE_NODE *node, const uint32_t node_pos);

void cxfsnpque_node_add_tail(CXFSNP *cxfsnp, CXFSNPQUE_NODE *node, const uint32_t node_pos);

void cxfsnpque_node_move_head(CXFSNP *cxfsnp, CXFSNPQUE_NODE *node, const uint32_t node_pos);

void cxfsnpque_node_move_tail(CXFSNP *cxfsnp, CXFSNPQUE_NODE *node, const uint32_t node_pos);

void cxfsnpque_node_rmv(CXFSNP *cxfsnp, CXFSNPQUE_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpque_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cxfsnpque_list_print(LOG *log, const CXFSNP *cxfsnp);

#endif    /* _CXFSNPQUE_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
