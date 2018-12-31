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

#ifndef    _CXFSNPLRU_H
#define    _CXFSNPLRU_H

#include "type.h"
#include "log.h"

#include "cxfsnprb.h"
#include "cxfsnp.inc"
#include "cxfsnplru.inc"


void cxfsnplru_node_init(CXFSNPLRU_NODE *node, const uint32_t node_pos);

void cxfsnplru_node_clean(CXFSNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnplru_node_clone(const CXFSNPLRU_NODE *node_src, CXFSNPLRU_NODE *node_des);

void cxfsnplru_node_print(LOG *log, const CXFSNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnplru_node_is_empty(const CXFSNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnplru_is_empty(const CXFSNPLRU_NODE *head);

/*--------------------------------------------- LRU list operations ---------------------------------------------*/
void cxfsnplru_node_add_head(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos);

void cxfsnplru_node_add_tail(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos);

void cxfsnplru_node_move_head(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos);

void cxfsnplru_node_move_tail(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos);

void cxfsnplru_node_rmv(CXFSNP *cxfsnp, CXFSNPLRU_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnplru_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cxfsnplru_list_print(LOG *log, const CXFSNP *cxfsnp);

#endif    /* _CXFSNPLRU_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
