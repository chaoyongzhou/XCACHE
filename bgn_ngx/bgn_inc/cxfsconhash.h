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

#ifndef _CXFSCONHASH_H
#define _CXFSCONHASH_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"
#include "cxfsconhash.inc"

CXFSCONHASH_RNODE *cxfsconhash_rnode_new();

CXFSCONHASH_RNODE *cxfsconhash_rnode_make(const uint32_t tcid, const uint16_t replicas);

EC_BOOL cxfsconhash_rnode_init(CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_clean(CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_free(CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_init_0(const UINT32 md_id, CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_clean_0(const UINT32 md_id, CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_free_0(const UINT32 md_id, CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_clone(const CXFSCONHASH_RNODE *cxfsconhash_rnode_src, CXFSCONHASH_RNODE *cxfsconhash_rnode_des);

const char *cxfsconhash_rnode_status(const CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_is_up(const CXFSCONHASH_RNODE *cxfsconhash_rnode);

EC_BOOL cxfsconhash_rnode_is_equal(const CXFSCONHASH_RNODE *cxfsconhash_rnode_1st, const CXFSCONHASH_RNODE *cxfsconhash_rnode_2nd);

EC_BOOL cxfsconhash_rnode_cmp_tcid(const CXFSCONHASH_RNODE *cxfsconhash_rnode_1st, const CXFSCONHASH_RNODE *cxfsconhash_rnode_2nd);

void cxfsconhash_rnode_print(LOG *log, const CXFSCONHASH_RNODE *cxfsconhash_rnode);

CXFSCONHASH_VNODE *cxfsconhash_vnode_new();

CXFSCONHASH_VNODE *cxfsconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos);

EC_BOOL cxfsconhash_vnode_init(CXFSCONHASH_VNODE *cxfsconhash_vnode);

EC_BOOL cxfsconhash_vnode_clean(CXFSCONHASH_VNODE *cxfsconhash_vnode);

EC_BOOL cxfsconhash_vnode_free(CXFSCONHASH_VNODE *cxfsconhash_vnode);

EC_BOOL cxfsconhash_vnode_init_0(const UINT32 md_id, CXFSCONHASH_VNODE *cxfsconhash_vnode);

EC_BOOL cxfsconhash_vnode_clean_0(const UINT32 md_id, CXFSCONHASH_VNODE *cxfsconhash_vnode);

EC_BOOL cxfsconhash_vnode_free_0(const UINT32 md_id, CXFSCONHASH_VNODE *cxfsconhash_vnode);

EC_BOOL cxfsconhash_vnode_clone(const CXFSCONHASH_VNODE *cxfsconhash_vnode_src, CXFSCONHASH_VNODE *cxfsconhash_vnode_des);

EC_BOOL cxfsconhash_vnode_is_equal(const CXFSCONHASH_VNODE *cxfsconhash_vnode_1st, const CXFSCONHASH_VNODE *cxfsconhash_vnode_2nd);

int cxfsconhash_vnode_cmp(const CXFSCONHASH_VNODE *cxfsconhash_vnode_1st, const CXFSCONHASH_VNODE *cxfsconhash_vnode_2nd);

void cxfsconhash_vnode_print(LOG *log, const CXFSCONHASH_VNODE *cxfsconhash_vnode);

CXFSCONHASH *cxfsconhash_new(const UINT32 hash_id);

EC_BOOL cxfsconhash_init(CXFSCONHASH *cxfsconhash, const UINT32 hash_id);

EC_BOOL cxfsconhash_clean(CXFSCONHASH *cxfsconhash);

EC_BOOL cxfsconhash_free(CXFSCONHASH *cxfsconhash);

void cxfsconhash_print(LOG *log, const CXFSCONHASH *cxfsconhash);

void cxfsconhash_print_rnode_vec(LOG *log, const CXFSCONHASH *cxfsconhash);

void cxfsconhash_print_vnode_tree(LOG *log, const CXFSCONHASH *cxfsconhash);

UINT32 cxfsconhash_add_rnode(CXFSCONHASH *cxfsconhash, const CXFSCONHASH_RNODE *cxfsconhash_rnode);

CRB_NODE *cxfsconhash_add_vnode(CXFSCONHASH *cxfsconhash, const CXFSCONHASH_VNODE *cxfsconhash_vnode);

EC_BOOL cxfsconhash_add_vnode_replicas(CXFSCONHASH *cxfsconhash, const UINT32 cxfsconhash_rnode_pos);

EC_BOOL cxfsconhash_del_vnode_replicas(CXFSCONHASH *cxfsconhash, const UINT32 cxfsconhash_rnode_pos);

EC_BOOL cxfsconhash_add_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid, const uint16_t replicas);

/*for any replica: replicas = 0*/
EC_BOOL cxfsconhash_del_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid);

EC_BOOL cxfsconhash_up_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid);

EC_BOOL cxfsconhash_down_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid);

EC_BOOL cxfsconhash_has_node(const CXFSCONHASH *cxfsconhash, const uint32_t tcid);

CXFSCONHASH_RNODE *cxfsconhash_get_rnode(const CXFSCONHASH *cxfsconhash, const uint32_t tcid);

CXFSCONHASH_RNODE *cxfsconhash_lookup_rnode(const CXFSCONHASH *cxfsconhash, const uint32_t hash);

EC_BOOL cxfsconhash_flush_size(const CXFSCONHASH *cxfsconhash, UINT32 *size);

EC_BOOL cxfsconhash_rnode_flush(const CXFSCONHASH_RNODE *cxfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_rnode_load(CXFSCONHASH_RNODE *cxfsconhash_rnode, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_flush_rnodes(const CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_load_rnodes(CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_vnode_flush(const CXFSCONHASH_VNODE *cxfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_vnode_load(CXFSCONHASH_VNODE *cxfsconhash_vnode, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_flush_vnodes(const CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_load_vnodes(CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_flush(const CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_load(CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset);

EC_BOOL cxfsconhash_rnodes_is_equal(const CXFSCONHASH *cxfsconhash_1st, const CXFSCONHASH *cxfsconhash_2nd);

EC_BOOL cxfsconhash_vnodes_is_equal(const CXFSCONHASH *cxfsconhash_1st, const CXFSCONHASH *cxfsconhash_2nd);

EC_BOOL cxfsconhash_is_equal(const CXFSCONHASH *cxfsconhash_1st, const CXFSCONHASH *cxfsconhash_2nd);

EC_BOOL cxfsconhash_clone(const CXFSCONHASH *cxfsconhash_src, CXFSCONHASH *cxfsconhash_des);

#endif /*_CXFSCONHASH_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

