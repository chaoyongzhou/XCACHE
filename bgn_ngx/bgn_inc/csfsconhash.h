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

#ifndef _CSFSCONHASH_H
#define _CSFSCONHASH_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"
#include "csfsconhash.inc"

CSFSCONHASH_RNODE *csfsconhash_rnode_new();

CSFSCONHASH_RNODE *csfsconhash_rnode_make(const uint32_t tcid, const uint16_t replicas);

EC_BOOL csfsconhash_rnode_init(CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_clean(CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_free(CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_init_0(const UINT32 md_id, CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_clean_0(const UINT32 md_id, CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_free_0(const UINT32 md_id, CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_clone(const CSFSCONHASH_RNODE *csfsconhash_rnode_src, CSFSCONHASH_RNODE *csfsconhash_rnode_des);

const char *csfsconhash_rnode_status(const CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_is_up(const CSFSCONHASH_RNODE *csfsconhash_rnode);

EC_BOOL csfsconhash_rnode_is_equal(const CSFSCONHASH_RNODE *csfsconhash_rnode_1st, const CSFSCONHASH_RNODE *csfsconhash_rnode_2nd);

EC_BOOL csfsconhash_rnode_cmp_tcid(const CSFSCONHASH_RNODE *csfsconhash_rnode_1st, const CSFSCONHASH_RNODE *csfsconhash_rnode_2nd);

void csfsconhash_rnode_print(LOG *log, const CSFSCONHASH_RNODE *csfsconhash_rnode);

CSFSCONHASH_VNODE *csfsconhash_vnode_new();

CSFSCONHASH_VNODE *csfsconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos);

EC_BOOL csfsconhash_vnode_init(CSFSCONHASH_VNODE *csfsconhash_vnode);

EC_BOOL csfsconhash_vnode_clean(CSFSCONHASH_VNODE *csfsconhash_vnode);

EC_BOOL csfsconhash_vnode_free(CSFSCONHASH_VNODE *csfsconhash_vnode);

EC_BOOL csfsconhash_vnode_init_0(const UINT32 md_id, CSFSCONHASH_VNODE *csfsconhash_vnode);

EC_BOOL csfsconhash_vnode_clean_0(const UINT32 md_id, CSFSCONHASH_VNODE *csfsconhash_vnode);

EC_BOOL csfsconhash_vnode_free_0(const UINT32 md_id, CSFSCONHASH_VNODE *csfsconhash_vnode);

EC_BOOL csfsconhash_vnode_clone(const CSFSCONHASH_VNODE *csfsconhash_vnode_src, CSFSCONHASH_VNODE *csfsconhash_vnode_des);

EC_BOOL csfsconhash_vnode_is_equal(const CSFSCONHASH_VNODE *csfsconhash_vnode_1st, const CSFSCONHASH_VNODE *csfsconhash_vnode_2nd);

int csfsconhash_vnode_cmp(const CSFSCONHASH_VNODE *csfsconhash_vnode_1st, const CSFSCONHASH_VNODE *csfsconhash_vnode_2nd);

void csfsconhash_vnode_print(LOG *log, const CSFSCONHASH_VNODE *csfsconhash_vnode);

CSFSCONHASH *csfsconhash_new(const UINT32 hash_id);

EC_BOOL csfsconhash_init(CSFSCONHASH *csfsconhash, const UINT32 hash_id);

EC_BOOL csfsconhash_clean(CSFSCONHASH *csfsconhash);

EC_BOOL csfsconhash_free(CSFSCONHASH *csfsconhash);

void csfsconhash_print(LOG *log, const CSFSCONHASH *csfsconhash);

void csfsconhash_print_rnode_vec(LOG *log, const CSFSCONHASH *csfsconhash);

void csfsconhash_print_vnode_tree(LOG *log, const CSFSCONHASH *csfsconhash);

UINT32 csfsconhash_add_rnode(CSFSCONHASH *csfsconhash, const CSFSCONHASH_RNODE *csfsconhash_rnode);

CRB_NODE *csfsconhash_add_vnode(CSFSCONHASH *csfsconhash, const CSFSCONHASH_VNODE *csfsconhash_vnode);

EC_BOOL csfsconhash_add_vnode_replicas(CSFSCONHASH *csfsconhash, const UINT32 csfsconhash_rnode_pos);

EC_BOOL csfsconhash_del_vnode_replicas(CSFSCONHASH *csfsconhash, const UINT32 csfsconhash_rnode_pos);

EC_BOOL csfsconhash_add_node(CSFSCONHASH *csfsconhash, const uint32_t tcid, const uint16_t replicas);

/*for any replica: replicas = 0*/
EC_BOOL csfsconhash_del_node(CSFSCONHASH *csfsconhash, const uint32_t tcid);

EC_BOOL csfsconhash_up_node(CSFSCONHASH *csfsconhash, const uint32_t tcid);

EC_BOOL csfsconhash_down_node(CSFSCONHASH *csfsconhash, const uint32_t tcid);

EC_BOOL csfsconhash_has_node(const CSFSCONHASH *csfsconhash, const uint32_t tcid);

CSFSCONHASH_RNODE *csfsconhash_get_rnode(const CSFSCONHASH *csfsconhash, const uint32_t tcid);

CSFSCONHASH_RNODE *csfsconhash_lookup_rnode(const CSFSCONHASH *csfsconhash, const uint32_t hash);

EC_BOOL csfsconhash_flush_size(const CSFSCONHASH *csfsconhash, UINT32 *size);

EC_BOOL csfsconhash_rnode_flush(const CSFSCONHASH_RNODE *csfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL csfsconhash_rnode_load(CSFSCONHASH_RNODE *csfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL csfsconhash_flush_rnodes(const CSFSCONHASH *csfsconhash, int fd, UINT32 *offset);

EC_BOOL csfsconhash_load_rnodes(CSFSCONHASH *csfsconhash, int fd, UINT32 *offset);

EC_BOOL csfsconhash_vnode_flush(const CSFSCONHASH_VNODE *csfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL csfsconhash_vnode_load(CSFSCONHASH_VNODE *csfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL csfsconhash_flush_vnodes(const CSFSCONHASH *csfsconhash, int fd, UINT32 *offset);

EC_BOOL csfsconhash_load_vnodes(CSFSCONHASH *csfsconhash, int fd, UINT32 *offset);

EC_BOOL csfsconhash_flush(const CSFSCONHASH *csfsconhash, int fd, UINT32 *offset);

EC_BOOL csfsconhash_load(CSFSCONHASH *csfsconhash, int fd, UINT32 *offset);

EC_BOOL csfsconhash_rnodes_is_equal(const CSFSCONHASH *csfsconhash_1st, const CSFSCONHASH *csfsconhash_2nd);

EC_BOOL csfsconhash_vnodes_is_equal(const CSFSCONHASH *csfsconhash_1st, const CSFSCONHASH *csfsconhash_2nd);

EC_BOOL csfsconhash_is_equal(const CSFSCONHASH *csfsconhash_1st, const CSFSCONHASH *csfsconhash_2nd);

EC_BOOL csfsconhash_clone(const CSFSCONHASH *csfsconhash_src, CSFSCONHASH *csfsconhash_des);

#endif /*_CSFSCONHASH_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

