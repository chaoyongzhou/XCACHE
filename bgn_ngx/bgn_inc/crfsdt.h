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

#ifndef _CRFSDT_H
#define _CRFSDT_H

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "log.h"

#include "cstring.h"
#include "clist.h"
#include "cvector.h"

#include "crfsdt.inc"

CRFSDT_PNODE *crfsdt_pnode_new();

EC_BOOL crfsdt_pnode_init(CRFSDT_PNODE *crfsdt_pnode);

EC_BOOL crfsdt_pnode_clean(CRFSDT_PNODE *crfsdt_pnode);

EC_BOOL crfsdt_pnode_free(CRFSDT_PNODE *crfsdt_pnode);

void crfsdt_pnode_print(LOG *log, const CRFSDT_PNODE *crfsdt_pnode);

int crfsdt_pnode_cmp(const CRFSDT_PNODE *crfsdt_pnode_1st, const CRFSDT_PNODE *crfsdt_pnode_2nd);

EC_BOOL crfsdt_pnode_set_path(CRFSDT_PNODE *crfsdt_pnode, const CSTRING *path);

EC_BOOL crfsdt_pnode_add_tcid(CRFSDT_PNODE *crfsdt_pnode, const UINT32 tcid);

EC_BOOL crfsdt_pnode_del_tcid(CRFSDT_PNODE *crfsdt_pnode, const UINT32 tcid);

EC_BOOL crfsdt_pnode_has_tcid(CRFSDT_PNODE *crfsdt_pnode, const UINT32 tcid);

EC_BOOL crfsdt_pnode_flush(const CRFSDT_PNODE *crfsdt_pnode, int fd, UINT32 *offset);

EC_BOOL crfsdt_pnode_load(CRFSDT_PNODE *crfsdt_pnode, int fd, UINT32 *offset);

CRFSDT_RNODE *crfsdt_rnode_new();

EC_BOOL crfsdt_rnode_init(CRFSDT_RNODE *crfsdt_rnode);

EC_BOOL crfsdt_rnode_clean(CRFSDT_RNODE *crfsdt_rnode);

EC_BOOL crfsdt_rnode_free(CRFSDT_RNODE *crfsdt_rnode);

void crfsdt_rnode_print(LOG *log, const CRFSDT_RNODE *crfsdt_rnode);

int crfsdt_rnode_cmp(const CRFSDT_RNODE *crfsdt_rnode_1st, const CRFSDT_RNODE *crfsdt_rnode_2nd);

EC_BOOL crfsdt_rnode_set_tcid(CRFSDT_RNODE *crfsdt_rnode, const UINT32 tcid);

EC_BOOL crfsdt_rnode_add_path(CRFSDT_RNODE *crfsdt_rnode, const CSTRING *path);

EC_BOOL crfsdt_rnode_del_path(CRFSDT_RNODE *crfsdt_rnode, const CSTRING *path);

EC_BOOL crfsdt_rnode_has_path(CRFSDT_RNODE *crfsdt_rnode, const CSTRING *path);

EC_BOOL crfsdt_rnode_flush(const CRFSDT_RNODE *crfsdt_rnode, int fd, UINT32 *offset);

EC_BOOL crfsdt_rnode_load(CRFSDT_RNODE *crfsdt_rnode, int fd, UINT32 *offset);

CRFSDT *crfsdt_new();

EC_BOOL crfsdt_init(CRFSDT *crfsdt);

EC_BOOL crfsdt_clean(CRFSDT *crfsdt);

EC_BOOL crfsdt_free(CRFSDT *crfsdt);

EC_BOOL crfsdt_reset(CRFSDT *crfsdt);

void crfsdt_print(LOG *log, const CRFSDT *crfsdt);

EC_BOOL crfsdt_is_empty(const CRFSDT *crfsdt);

CRFSDT_PNODE *crfsdt_search_pnode(const CRFSDT *crfsdt, const CSTRING *path);

CRFSDT_RNODE *crfsdt_search_rnode(const CRFSDT *crfsdt, const UINT32 tcid);

CRFSDT_PNODE *crfsdt_add_pnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

CRFSDT_RNODE *crfsdt_add_rnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

/*add path to some RFS*/
EC_BOOL crfsdt_add(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

CRFSDT_PNODE *crfsdt_del_pnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

CRFSDT_RNODE *crfsdt_del_rnode(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

/*del path from some RFS*/
EC_BOOL crfsdt_del(CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

EC_BOOL crfsdt_has_pnode(const CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

EC_BOOL crfsdt_has_rnode(const CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

EC_BOOL crfsdt_has(const CRFSDT *crfsdt, const UINT32 tcid, const CSTRING *path);

CRFSDT_PNODE *crfsdt_lookup_pnode(const CRFSDT *crfsdt, const CSTRING *path);

EC_BOOL crfsdt_flush(const CRFSDT *crfsdt, int fd, UINT32 *offset);

EC_BOOL crfsdt_load(CRFSDT *crfsdt, int fd, UINT32 *offset);

EC_BOOL crfsdt_clone(const CRFSDT *crfsdt_src, CRFSDT *crfsdt_des);

#endif /*_CRFSDT_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

