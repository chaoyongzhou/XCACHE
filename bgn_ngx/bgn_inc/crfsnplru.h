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

#ifndef    _CRFSNPLRU_H
#define    _CRFSNPLRU_H

#include "type.h"
#include "log.h"

#include "crfsnprb.h"
#include "crfsnp.inc"
#include "crfsnplru.inc"


void crfsnplru_node_init(CRFSNPLRU_NODE *node, const uint32_t node_pos);

void crfsnplru_node_clean(CRFSNPLRU_NODE *node, const uint32_t node_pos);

void crfsnplru_node_print(LOG *log, const CRFSNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL crfsnplru_node_is_empty(const CRFSNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL crfsnplru_is_empty(const CRFSNPLRU_NODE *head);

/*--------------------------------------------- LRU list operations ---------------------------------------------*/
void crfsnplru_node_add_head(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos);

void crfsnplru_node_add_tail(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos);

void crfsnplru_node_move_head(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos);

void crfsnplru_node_move_tail(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos);

void crfsnplru_node_rmv(CRFSNP *crfsnp, CRFSNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL crfsnplru_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void crfsnplru_list_print(LOG *log, const CRFSNP *crfsnp);

#endif    /* _CRFSNPLRU_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
