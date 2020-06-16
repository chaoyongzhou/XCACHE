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

#ifndef _CCONHASH_H
#define _CCONHASH_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cconhash.inc"

CCONHASH_RNODE *cconhash_rnode_new();

CCONHASH_RNODE *cconhash_rnode_make(const uint32_t tcid, const uint16_t replicas);

EC_BOOL cconhash_rnode_init(CCONHASH_RNODE *cconhash_rnode);

EC_BOOL cconhash_rnode_clean(CCONHASH_RNODE *cconhash_rnode);

EC_BOOL cconhash_rnode_free(CCONHASH_RNODE *cconhash_rnode);

const char *cconhash_rnode_status(const CCONHASH_RNODE *cconhash_rnode);

EC_BOOL cconhash_rnode_is_up(const CCONHASH_RNODE *cconhash_rnode);

EC_BOOL cconhash_rnode_cmp_tcid(const CCONHASH_RNODE *cconhash_rnode_1st, const CCONHASH_RNODE *cconhash_rnode_2nd);

void cconhash_rnode_print(LOG *log, const CCONHASH_RNODE *cconhash_rnode);

CCONHASH_VNODE *cconhash_vnode_new();

CCONHASH_VNODE *cconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos);

EC_BOOL cconhash_vnode_set(CCONHASH_VNODE *cconhash_vnode, const uint32_t hash);

EC_BOOL cconhash_vnode_init(CCONHASH_VNODE *cconhash_vnode);

EC_BOOL cconhash_vnode_clean(CCONHASH_VNODE *cconhash_vnode);

EC_BOOL cconhash_vnode_free(CCONHASH_VNODE *cconhash_vnode);

EC_BOOL cconhash_vnode_clone(const CCONHASH_VNODE *cconhash_vnode_src, CCONHASH_VNODE *cconhash_vnode_des);

int cconhash_vnode_cmp(const CCONHASH_VNODE *cconhash_vnode_1st, const CCONHASH_VNODE *cconhash_vnode_2nd);

void cconhash_vnode_print(LOG *log, const CCONHASH_VNODE *cconhash_vnode);

EC_BOOL cconhash_vnodes_init(CCONHASH_VNODES *cconhash_vnodes, const uint32_t capacity);

EC_BOOL cconhash_vnodes_clean(CCONHASH_VNODES *cconhash_vnodes);

UINT32 cconhash_vnodes_num(const CCONHASH_VNODES *cconhash_vnodes);

EC_BOOL cconhash_vnodes_is_full(const CCONHASH_VNODES *cconhash_vnodes);

EC_BOOL cconhash_vnodes_is_empty(const CCONHASH_VNODES *cconhash_vnodes);

EC_BOOL cconhash_vnodes_expand(CCONHASH_VNODES *cconhash_vnodes);

EC_BOOL cconhash_vnodes_add(CCONHASH_VNODES *cconhash_vnodes, const CCONHASH_VNODE *cconhash_vnode);

EC_BOOL cconhash_vnodes_del(CCONHASH_VNODES *cconhash_vnodes, const uint32_t cconhash_rnode_pos);

EC_BOOL cconhash_vnodes_discard(CCONHASH_VNODES *cconhash_vnodes, const uint32_t cconhash_vnode_s_pos);

EC_BOOL cconhash_vnodes_sort(CCONHASH_VNODES *cconhash_vnodes);

CCONHASH_VNODE *cconhash_vnodes_lookup(CCONHASH_VNODES *cconhash_vnodes, const uint32_t hash);

void cconhash_vnodes_print(LOG *log, const CCONHASH_VNODES *cconhash_vnodes);

CCONHASH *cconhash_new(const UINT32 hash_id);

EC_BOOL cconhash_init(CCONHASH *cconhash, const UINT32 hash_id);

EC_BOOL cconhash_clean(CCONHASH *cconhash);

EC_BOOL cconhash_free(CCONHASH *cconhash);

void cconhash_print(LOG *log, const CCONHASH *cconhash);

void cconhash_print_rnode_vec(LOG *log, const CCONHASH *cconhash);

void cconhash_print_vnode_tree(LOG *log, const CCONHASH *cconhash);

UINT32 cconhash_add_rnode(CCONHASH *cconhash, const CCONHASH_RNODE *cconhash_rnode);

EC_BOOL cconhash_add_vnode(CCONHASH *cconhash, const CCONHASH_VNODE *cconhash_vnode);

EC_BOOL cconhash_del_vnodes(CCONHASH *cconhash, const uint32_t cconhash_rnode_pos);

EC_BOOL cconhash_discard_vnodes(CCONHASH *cconhash, const uint32_t cconhash_vnode_s_pos);

EC_BOOL cconhash_sort_vnodes(CCONHASH *cconhash);

EC_BOOL cconhash_add_vnode_replicas(CCONHASH *cconhash, const UINT32 cconhash_rnode_pos);

EC_BOOL cconhash_del_vnode_replicas(CCONHASH *cconhash, const UINT32 cconhash_rnode_pos);

EC_BOOL cconhash_add_node(CCONHASH *cconhash, const uint32_t tcid, const uint16_t replicas);

/*for any replica: replicas = 0*/
EC_BOOL cconhash_del_node(CCONHASH *cconhash, const uint32_t tcid);

EC_BOOL cconhash_up_node(CCONHASH *cconhash, const uint32_t tcid);

EC_BOOL cconhash_down_node(CCONHASH *cconhash, const uint32_t tcid);

EC_BOOL cconhash_has_node(const CCONHASH *cconhash, const uint32_t tcid);

CCONHASH_RNODE *cconhash_get_rnode(const CCONHASH *cconhash, const uint32_t tcid);

CCONHASH_RNODE *cconhash_lookup_rnode(const CCONHASH *cconhash, const uint32_t hash);


#endif /*_CCONHASH_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

