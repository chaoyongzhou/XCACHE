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

#ifndef _CPARACFG_H
#define _CPARACFG_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "type.h"

#include "cparacfg.inc"
#include "cxml.h"

#include "task.h"

#include "json.h"

CPARACFG_NODE *cparacfg_node_new();

EC_BOOL cparacfg_node_init(CPARACFG_NODE *cparacfg_node);

EC_BOOL cparacfg_node_clean(CPARACFG_NODE *cparacfg_node);

EC_BOOL cparacfg_node_free(CPARACFG_NODE *cparacfg_node);

EC_BOOL cparacfg_node_is_type(const CPARACFG_NODE *cparacfg_node, const char *type_name);

void cparacfg_node_print(LOG *log, const CPARACFG_NODE *cparacfg_node);

void cparacfg_node_print_plain(LOG *log, const CPARACFG_NODE *cparacfg_node);

EC_BOOL cparacfg_node_clone(const CPARACFG_NODE *cparacfg_node_src, CPARACFG_NODE *cparacfg_node_des);

CPARACFG *cparacfg_new(const UINT32 this_tcid, const UINT32 this_rank);

EC_BOOL cparacfg_clean(CPARACFG *cparacfg);

EC_BOOL cparacfg_free(CPARACFG *cparacfg);

EC_BOOL cparacfg_init(CPARACFG *cparacfg, const UINT32 this_tcid, const UINT32 this_rank);

CPARACFG_NODE *cparacfg_search(CPARACFG *cparacfg, const char *macro_name);

EC_BOOL cparacfg_add_node(CPARACFG *cparacfg, const UINT32 idx, const char *macro_name, const char *type_name, void *data);

EC_BOOL cparacfg_clone(const CPARACFG *cparacfg_src, CPARACFG *cparacfg_des);

EC_BOOL cparacfg_cmp(const CPARACFG *cparacfg_1st, const CPARACFG *cparacfg_2nd);

void cparacfg_print(LOG *log, const CPARACFG *cparacfg);

void cparacfg_json(json_object *obj, const CPARACFG *cparacfg);


#endif/*_CPARACFG_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/
