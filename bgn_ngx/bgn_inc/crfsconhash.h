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

#ifndef _CRFSCONHASH_H
#define _CRFSCONHASH_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"
#include "crfsconhash.inc"

CRFSCONHASH_RNODE *crfsconhash_rnode_new();

CRFSCONHASH_RNODE *crfsconhash_rnode_make(const uint32_t tcid, const uint16_t replicas);

EC_BOOL crfsconhash_rnode_init(CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_clean(CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_free(CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_init_0(const UINT32 md_id, CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_clean_0(const UINT32 md_id, CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_free_0(const UINT32 md_id, CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_clone(const CRFSCONHASH_RNODE *crfsconhash_rnode_src, CRFSCONHASH_RNODE *crfsconhash_rnode_des);

const char *crfsconhash_rnode_status(const CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_is_up(const CRFSCONHASH_RNODE *crfsconhash_rnode);

EC_BOOL crfsconhash_rnode_is_equal(const CRFSCONHASH_RNODE *crfsconhash_rnode_1st, const CRFSCONHASH_RNODE *crfsconhash_rnode_2nd);

EC_BOOL crfsconhash_rnode_cmp_tcid(const CRFSCONHASH_RNODE *crfsconhash_rnode_1st, const CRFSCONHASH_RNODE *crfsconhash_rnode_2nd);

void crfsconhash_rnode_print(LOG *log, const CRFSCONHASH_RNODE *crfsconhash_rnode);

CRFSCONHASH_VNODE *crfsconhash_vnode_new();

CRFSCONHASH_VNODE *crfsconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos);

EC_BOOL crfsconhash_vnode_init(CRFSCONHASH_VNODE *crfsconhash_vnode);

EC_BOOL crfsconhash_vnode_clean(CRFSCONHASH_VNODE *crfsconhash_vnode);

EC_BOOL crfsconhash_vnode_free(CRFSCONHASH_VNODE *crfsconhash_vnode);

EC_BOOL crfsconhash_vnode_init_0(const UINT32 md_id, CRFSCONHASH_VNODE *crfsconhash_vnode);

EC_BOOL crfsconhash_vnode_clean_0(const UINT32 md_id, CRFSCONHASH_VNODE *crfsconhash_vnode);

EC_BOOL crfsconhash_vnode_free_0(const UINT32 md_id, CRFSCONHASH_VNODE *crfsconhash_vnode);

EC_BOOL crfsconhash_vnode_clone(const CRFSCONHASH_VNODE *crfsconhash_vnode_src, CRFSCONHASH_VNODE *crfsconhash_vnode_des);

EC_BOOL crfsconhash_vnode_is_equal(const CRFSCONHASH_VNODE *crfsconhash_vnode_1st, const CRFSCONHASH_VNODE *crfsconhash_vnode_2nd);

int crfsconhash_vnode_cmp(const CRFSCONHASH_VNODE *crfsconhash_vnode_1st, const CRFSCONHASH_VNODE *crfsconhash_vnode_2nd);

void crfsconhash_vnode_print(LOG *log, const CRFSCONHASH_VNODE *crfsconhash_vnode);

CRFSCONHASH *crfsconhash_new(const UINT32 hash_id);

EC_BOOL crfsconhash_init(CRFSCONHASH *crfsconhash, const UINT32 hash_id);

EC_BOOL crfsconhash_clean(CRFSCONHASH *crfsconhash);

EC_BOOL crfsconhash_free(CRFSCONHASH *crfsconhash);

void crfsconhash_print(LOG *log, const CRFSCONHASH *crfsconhash);

void crfsconhash_print_rnode_vec(LOG *log, const CRFSCONHASH *crfsconhash);

void crfsconhash_print_vnode_tree(LOG *log, const CRFSCONHASH *crfsconhash);

UINT32 crfsconhash_add_rnode(CRFSCONHASH *crfsconhash, const CRFSCONHASH_RNODE *crfsconhash_rnode);

CRB_NODE *crfsconhash_add_vnode(CRFSCONHASH *crfsconhash, const CRFSCONHASH_VNODE *crfsconhash_vnode);

EC_BOOL crfsconhash_add_vnode_replicas(CRFSCONHASH *crfsconhash, const UINT32 crfsconhash_rnode_pos);

EC_BOOL crfsconhash_del_vnode_replicas(CRFSCONHASH *crfsconhash, const UINT32 crfsconhash_rnode_pos);

EC_BOOL crfsconhash_add_node(CRFSCONHASH *crfsconhash, const uint32_t tcid, const uint16_t replicas);

/*for any replica: replicas = 0*/
EC_BOOL crfsconhash_del_node(CRFSCONHASH *crfsconhash, const uint32_t tcid);

EC_BOOL crfsconhash_up_node(CRFSCONHASH *crfsconhash, const uint32_t tcid);

EC_BOOL crfsconhash_down_node(CRFSCONHASH *crfsconhash, const uint32_t tcid);

EC_BOOL crfsconhash_has_node(const CRFSCONHASH *crfsconhash, const uint32_t tcid);

CRFSCONHASH_RNODE *crfsconhash_get_rnode(const CRFSCONHASH *crfsconhash, const uint32_t tcid);

CRFSCONHASH_RNODE *crfsconhash_lookup_rnode(const CRFSCONHASH *crfsconhash, const uint32_t hash);

EC_BOOL crfsconhash_flush_size(const CRFSCONHASH *crfsconhash, UINT32 *size);

EC_BOOL crfsconhash_rnode_flush(const CRFSCONHASH_RNODE *crfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL crfsconhash_rnode_load(CRFSCONHASH_RNODE *crfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL crfsconhash_flush_rnodes(const CRFSCONHASH *crfsconhash, int fd, UINT32 *offset);

EC_BOOL crfsconhash_load_rnodes(CRFSCONHASH *crfsconhash, int fd, UINT32 *offset);

EC_BOOL crfsconhash_vnode_flush(const CRFSCONHASH_VNODE *crfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL crfsconhash_vnode_load(CRFSCONHASH_VNODE *crfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL crfsconhash_flush_vnodes(const CRFSCONHASH *crfsconhash, int fd, UINT32 *offset);

EC_BOOL crfsconhash_load_vnodes(CRFSCONHASH *crfsconhash, int fd, UINT32 *offset);

EC_BOOL crfsconhash_flush(const CRFSCONHASH *crfsconhash, int fd, UINT32 *offset);

EC_BOOL crfsconhash_load(CRFSCONHASH *crfsconhash, int fd, UINT32 *offset);

EC_BOOL crfsconhash_rnodes_is_equal(const CRFSCONHASH *crfsconhash_1st, const CRFSCONHASH *crfsconhash_2nd);

EC_BOOL crfsconhash_vnodes_is_equal(const CRFSCONHASH *crfsconhash_1st, const CRFSCONHASH *crfsconhash_2nd);

EC_BOOL crfsconhash_is_equal(const CRFSCONHASH *crfsconhash_1st, const CRFSCONHASH *crfsconhash_2nd);

EC_BOOL crfsconhash_clone(const CRFSCONHASH *crfsconhash_src, CRFSCONHASH *crfsconhash_des);

#endif /*_CRFSCONHASH_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

