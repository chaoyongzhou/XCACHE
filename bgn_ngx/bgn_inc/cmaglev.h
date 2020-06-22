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

#ifndef _CMAGLEV_H
#define _CMAGLEV_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmaglev.inc"

CMAGLEV *cmaglev_new();

EC_BOOL cmaglev_init(CMAGLEV *cmaglev);

EC_BOOL cmaglev_clean(CMAGLEV *cmaglev);

EC_BOOL cmaglev_free(CMAGLEV *cmaglev);

CMAGLEV_QNODE *cmaglev_qnode_new();

EC_BOOL cmaglev_qnode_init(CMAGLEV_QNODE *qnode);

EC_BOOL cmaglev_qnode_clean(CMAGLEV_QNODE *qnode);

EC_BOOL cmaglev_qnode_free(CMAGLEV_QNODE *qnode);

EC_BOOL cmaglev_qnode_make(CMAGLEV_QNODE *qnode, const UINT32 ring_size, const UINT32 next_size);

CMAGLEV_RNODE *cmaglev_rnode_new();

EC_BOOL cmaglev_rnode_init(CMAGLEV_RNODE *cmaglev_rnode);

EC_BOOL cmaglev_rnode_clean(CMAGLEV_RNODE *cmaglev_rnode);

EC_BOOL cmaglev_rnode_free(CMAGLEV_RNODE *cmaglev_rnode);

CMAGLEV_RNODE *cmaglev_rnode_make(const uint32_t tcid);

const char *cmaglev_rnode_status(const CMAGLEV_RNODE *cmaglev_rnode);

EC_BOOL cmaglev_rnode_is_up(const CMAGLEV_RNODE *cmaglev_rnode);

void cmaglev_rnode_print(LOG *log, const CMAGLEV_RNODE *cmaglev_rnode);

EC_BOOL cmaglev_rnode_cmp_tcid(const CMAGLEV_RNODE *cmaglev_rnode_1st, const CMAGLEV_RNODE *cmaglev_rnode_2nd);

EC_BOOL cmaglev_add_node(CMAGLEV *cmaglev, const uint32_t tcid);

EC_BOOL cmaglev_del_node(CMAGLEV *cmaglev, const uint32_t tcid);

EC_BOOL cmaglev_up_node(CMAGLEV *cmaglev, const uint32_t tcid);

EC_BOOL cmaglev_down_node(CMAGLEV *cmaglev, const uint32_t tcid);

UINT32 cmaglev_add_rnode(CMAGLEV *cmaglev, const CMAGLEV_RNODE *rnode);

UINT32 cmaglev_count_rnode(CMAGLEV *cmaglev);

void cmaglev_permutation(UINT32 *permutation, UINT32 *tcid, UINT32 pos, UINT32 ring_size);

EC_BOOL cmaglev_populate(CMAGLEV *cmaglev, UINT32 ring_size);

EC_BOOL cmaglev_hash(CMAGLEV *cmaglev);

CMAGLEV_RNODE *cmaglev_lookup_rnode(CMAGLEV *cmaglev, const uint32_t hash);


#endif /*_CMAGLEV_H */
#ifdef __cplusplus
}
#endif/*__cplusplus*/
