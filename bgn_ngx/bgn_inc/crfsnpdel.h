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

#ifndef    _CRFSNPDEL_H
#define    _CRFSNPDEL_H

#include "type.h"
#include "log.h"

#include "crfsnprb.h"
#include "crfsnp.inc"
#include "crfsnpdel.inc"


void crfsnpdel_node_init(CRFSNPDEL_NODE *node, const uint32_t node_pos);

void crfsnpdel_node_clean(CRFSNPDEL_NODE *node, const uint32_t node_pos);

void crfsnpdel_node_print(LOG *log, const CRFSNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL crfsnpdel_node_is_empty(const CRFSNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL crfsnpdel_is_empty(const CRFSNPDEL_NODE *head);

/*--------------------------------------------- DEL list operations ---------------------------------------------*/
void crfsnpdel_node_add_head(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos);

void crfsnpdel_node_add_tail(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos);

void crfsnpdel_node_move_head(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos);

void crfsnpdel_node_move_tail(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos);

void crfsnpdel_node_rmv(CRFSNP *crfsnp, CRFSNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL crfsnpdel_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void crfsnpdel_list_print(LOG *log, const CRFSNP *crfsnp);

#endif    /* _CRFSNPDEL_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
