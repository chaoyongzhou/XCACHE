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

#ifndef    _CXFSNPDEL_H
#define    _CXFSNPDEL_H

#include "type.h"
#include "log.h"

#include "cxfsnprb.h"
#include "cxfsnp.inc"
#include "cxfsnpdel.inc"


void cxfsnpdel_node_init(CXFSNPDEL_NODE *node, const uint32_t node_pos);

void cxfsnpdel_node_clean(CXFSNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpdel_node_clone(const CXFSNPDEL_NODE *node_src, CXFSNPDEL_NODE *node_des);

void cxfsnpdel_node_print(LOG *log, const CXFSNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpdel_node_is_empty(const CXFSNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpdel_is_empty(const CXFSNPDEL_NODE *head);

/*--------------------------------------------- DEL list operations ---------------------------------------------*/
void cxfsnpdel_node_add_head(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos);

void cxfsnpdel_node_add_tail(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos);

void cxfsnpdel_node_move_head(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos);

void cxfsnpdel_node_move_tail(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos);

void cxfsnpdel_node_rmv(CXFSNP *cxfsnp, CXFSNPDEL_NODE *node, const uint32_t node_pos);

EC_BOOL cxfsnpdel_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

void cxfsnpdel_list_print(LOG *log, const CXFSNP *cxfsnp);

#endif    /* _CXFSNPDEL_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
