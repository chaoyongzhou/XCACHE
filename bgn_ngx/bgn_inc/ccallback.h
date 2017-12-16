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

#ifndef _CCALLBACK_H
#define _CCALLBACK_H

#include "type.h"
#include "mm.h"
#include "log.h"


typedef struct
{
    const char     *name;     /*always const string, never free*/ 
    UINT32          func;     /*callback function address*/
    UINT32          data;     /*extra data*/
}CCALLBACK_NODE;

#define CCALLBACK_NODE_NAME(ccallback_node)             ((ccallback_node)->name)
#define CCALLBACK_NODE_FUNC(ccallback_node)             ((ccallback_node)->func)
#define CCALLBACK_NODE_DATA(ccallback_node)             ((ccallback_node)->data)

typedef EC_BOOL (*CCALLBACK_RUNNER)(UINT32, CCALLBACK_NODE *);
typedef EC_BOOL (*CCALLBACK_FILTER)(const CCALLBACK_NODE *, const char *, const UINT32, const UINT32);

typedef struct
{
    const char *        name;
    CLIST               callback_nodes;     /*item is CCALLBACK_NODE*/
    CCALLBACK_RUNNER    callback_runner;
    CCALLBACK_FILTER    callback_filter;
}CCALLBACK_LIST;

#define CCALLBACK_LIST_NAME(ccallback_list)         ((ccallback_list)->name)
#define CCALLBACK_LIST_NODES(ccallback_list)        (&((ccallback_list)->callback_nodes))
#define CCALLBACK_LIST_RUNNER(ccallback_list)       ((ccallback_list)->callback_runner)
#define CCALLBACK_LIST_FILTER(ccallback_list)       ((ccallback_list)->callback_filter)

CCALLBACK_NODE *ccallback_node_new();

EC_BOOL ccallback_node_init(CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_clean(CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_free(CCALLBACK_NODE *ccallback_node);

void    ccallback_node_print(LOG *log, const CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_filter_default(const CCALLBACK_NODE *ccallback_node, const char *name, const UINT32 data, const UINT32 func);

EC_BOOL ccallback_node_runner_default(UINT32 unused, CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_list_init(CCALLBACK_LIST *ccallback_list);

EC_BOOL ccallback_list_clean(CCALLBACK_LIST *ccallback_list);

EC_BOOL ccallback_list_set_name(CCALLBACK_LIST *ccallback_list, const char *name);

EC_BOOL ccallback_list_set_runner(CCALLBACK_LIST *ccallback_list, CCALLBACK_RUNNER runner);

EC_BOOL ccallback_list_set_filter(CCALLBACK_LIST *ccallback_list, CCALLBACK_FILTER filter);

void    ccallback_list_print(LOG *log, const CCALLBACK_LIST *ccallback_list);

CCALLBACK_NODE *ccallback_list_search(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func);

CCALLBACK_NODE *ccallback_list_push(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func);

EC_BOOL ccallback_list_erase(CCALLBACK_LIST *ccallback_list, const char *name, const UINT32 data, const UINT32 func);

EC_BOOL ccallback_list_pop(CCALLBACK_LIST *ccallback_list);

EC_BOOL ccallback_list_reset(CCALLBACK_LIST *ccallback_list);

EC_BOOL ccallback_list_run_not_check(CCALLBACK_LIST *ccallback_list, UINT32 arg);

EC_BOOL ccallback_list_run_and_check(CCALLBACK_LIST *ccallback_list, UINT32 arg);

#endif/*_CCALLBACK_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

