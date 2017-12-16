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

#ifndef _CHFSCONHASH_H
#define _CHFSCONHASH_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"
#include "chfsconhash.inc"

CHFSCONHASH_RNODE *chfsconhash_rnode_new();

CHFSCONHASH_RNODE *chfsconhash_rnode_make(const uint32_t tcid, const uint16_t replicas);

EC_BOOL chfsconhash_rnode_init(CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_clean(CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_free(CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_init_0(const UINT32 md_id, CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_clean_0(const UINT32 md_id, CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_free_0(const UINT32 md_id, CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_clone(const CHFSCONHASH_RNODE *chfsconhash_rnode_src, CHFSCONHASH_RNODE *chfsconhash_rnode_des);

const char *chfsconhash_rnode_status(const CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_is_up(const CHFSCONHASH_RNODE *chfsconhash_rnode);

EC_BOOL chfsconhash_rnode_is_equal(const CHFSCONHASH_RNODE *chfsconhash_rnode_1st, const CHFSCONHASH_RNODE *chfsconhash_rnode_2nd);

EC_BOOL chfsconhash_rnode_cmp_tcid(const CHFSCONHASH_RNODE *chfsconhash_rnode_1st, const CHFSCONHASH_RNODE *chfsconhash_rnode_2nd);

void chfsconhash_rnode_print(LOG *log, const CHFSCONHASH_RNODE *chfsconhash_rnode);

CHFSCONHASH_VNODE *chfsconhash_vnode_new();

CHFSCONHASH_VNODE *chfsconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos);

EC_BOOL chfsconhash_vnode_init(CHFSCONHASH_VNODE *chfsconhash_vnode);

EC_BOOL chfsconhash_vnode_clean(CHFSCONHASH_VNODE *chfsconhash_vnode);

EC_BOOL chfsconhash_vnode_free(CHFSCONHASH_VNODE *chfsconhash_vnode);

EC_BOOL chfsconhash_vnode_init_0(const UINT32 md_id, CHFSCONHASH_VNODE *chfsconhash_vnode);

EC_BOOL chfsconhash_vnode_clean_0(const UINT32 md_id, CHFSCONHASH_VNODE *chfsconhash_vnode);

EC_BOOL chfsconhash_vnode_free_0(const UINT32 md_id, CHFSCONHASH_VNODE *chfsconhash_vnode);

EC_BOOL chfsconhash_vnode_clone(const CHFSCONHASH_VNODE *chfsconhash_vnode_src, CHFSCONHASH_VNODE *chfsconhash_vnode_des);

EC_BOOL chfsconhash_vnode_is_equal(const CHFSCONHASH_VNODE *chfsconhash_vnode_1st, const CHFSCONHASH_VNODE *chfsconhash_vnode_2nd);

int chfsconhash_vnode_cmp(const CHFSCONHASH_VNODE *chfsconhash_vnode_1st, const CHFSCONHASH_VNODE *chfsconhash_vnode_2nd);

void chfsconhash_vnode_print(LOG *log, const CHFSCONHASH_VNODE *chfsconhash_vnode);

CHFSCONHASH *chfsconhash_new(const UINT32 hash_id);

EC_BOOL chfsconhash_init(CHFSCONHASH *chfsconhash, const UINT32 hash_id);

EC_BOOL chfsconhash_clean(CHFSCONHASH *chfsconhash);

EC_BOOL chfsconhash_free(CHFSCONHASH *chfsconhash);

void chfsconhash_print(LOG *log, const CHFSCONHASH *chfsconhash);

void chfsconhash_print_rnode_vec(LOG *log, const CHFSCONHASH *chfsconhash);

void chfsconhash_print_vnode_tree(LOG *log, const CHFSCONHASH *chfsconhash);

UINT32 chfsconhash_add_rnode(CHFSCONHASH *chfsconhash, const CHFSCONHASH_RNODE *chfsconhash_rnode);

CRB_NODE *chfsconhash_add_vnode(CHFSCONHASH *chfsconhash, const CHFSCONHASH_VNODE *chfsconhash_vnode);

EC_BOOL chfsconhash_add_vnode_replicas(CHFSCONHASH *chfsconhash, const UINT32 chfsconhash_rnode_pos);

EC_BOOL chfsconhash_del_vnode_replicas(CHFSCONHASH *chfsconhash, const UINT32 chfsconhash_rnode_pos);

EC_BOOL chfsconhash_add_node(CHFSCONHASH *chfsconhash, const uint32_t tcid, const uint16_t replicas);

/*for any replica: replicas = 0*/
EC_BOOL chfsconhash_del_node(CHFSCONHASH *chfsconhash, const uint32_t tcid);

EC_BOOL chfsconhash_up_node(CHFSCONHASH *chfsconhash, const uint32_t tcid);

EC_BOOL chfsconhash_down_node(CHFSCONHASH *chfsconhash, const uint32_t tcid);

EC_BOOL chfsconhash_has_node(const CHFSCONHASH *chfsconhash, const uint32_t tcid);

CHFSCONHASH_RNODE *chfsconhash_get_rnode(const CHFSCONHASH *chfsconhash, const uint32_t tcid);

CHFSCONHASH_RNODE *chfsconhash_lookup_rnode(const CHFSCONHASH *chfsconhash, const uint32_t hash);

EC_BOOL chfsconhash_flush_size(const CHFSCONHASH *chfsconhash, UINT32 *size);

EC_BOOL chfsconhash_rnode_flush(const CHFSCONHASH_RNODE *chfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL chfsconhash_rnode_load(CHFSCONHASH_RNODE *chfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL chfsconhash_flush_rnodes(const CHFSCONHASH *chfsconhash, int fd, UINT32 *offset);

EC_BOOL chfsconhash_load_rnodes(CHFSCONHASH *chfsconhash, int fd, UINT32 *offset);

EC_BOOL chfsconhash_vnode_flush(const CHFSCONHASH_VNODE *chfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL chfsconhash_vnode_load(CHFSCONHASH_VNODE *chfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL chfsconhash_flush_vnodes(const CHFSCONHASH *chfsconhash, int fd, UINT32 *offset);

EC_BOOL chfsconhash_load_vnodes(CHFSCONHASH *chfsconhash, int fd, UINT32 *offset);

EC_BOOL chfsconhash_flush(const CHFSCONHASH *chfsconhash, int fd, UINT32 *offset);

EC_BOOL chfsconhash_load(CHFSCONHASH *chfsconhash, int fd, UINT32 *offset);

EC_BOOL chfsconhash_rnodes_is_equal(const CHFSCONHASH *chfsconhash_1st, const CHFSCONHASH *chfsconhash_2nd);

EC_BOOL chfsconhash_vnodes_is_equal(const CHFSCONHASH *chfsconhash_1st, const CHFSCONHASH *chfsconhash_2nd);

EC_BOOL chfsconhash_is_equal(const CHFSCONHASH *chfsconhash_1st, const CHFSCONHASH *chfsconhash_2nd);

EC_BOOL chfsconhash_clone(const CHFSCONHASH *chfsconhash_src, CHFSCONHASH *chfsconhash_des);

#endif /*_CHFSCONHASH_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

