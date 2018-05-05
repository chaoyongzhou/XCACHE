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

#ifndef _CBTIMER_H
#define _CBTIMER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <time.h>
#include <sys/time.h>

#include "type.h"
#include "clist.h"

#include "debug.h"
#include "task.inc"

#define CBTIMER_NEVER_EXPIRE        ((UINT32) 0)

typedef struct
{
    CSTRING *name;

    UINT32           expire_nsec; /*expire interval in seconds. 0 means never expire*/
    FUNC_ADDR_NODE * expire_func_addr_node;
    TASK_FUNC        expire_handler;

    UINT32           timeout_nsec;/*timeout interval in seconds*/
    FUNC_ADDR_NODE * timeout_func_addr_node;
    TASK_FUNC        timeout_handler;

    CTIMET   start_time;
    CTIMET   last_time;

}CBTIMER_NODE;

#define CBTIMER_NODE_NAME(cbtimer_node)                       ((cbtimer_node)->name)
#define CBTIMER_NODE_NAME_STR(cbtimer_node)                   (cstring_get_str(CBTIMER_NODE_NAME(cbtimer_node)))
#define CBTIMER_NODE_TIMEOUT_NSEC(cbtimer_node)               ((cbtimer_node)->timeout_nsec)
#define CBTIMER_NODE_TIMEOUT_HANDLER(cbtimer_node)            (&((cbtimer_node)->timeout_handler))
#define CBTIMER_NODE_TIMEOUT_FUNC_ADDR_NODE(cbtimer_node)     ((cbtimer_node)->timeout_func_addr_node)
#define CBTIMER_NODE_EXPIRE_NSEC(cbtimer_node)                ((cbtimer_node)->expire_nsec)
#define CBTIMER_NODE_EXPIRE_HANDLER(cbtimer_node)             (&((cbtimer_node)->expire_handler))
#define CBTIMER_NODE_EXPIRE_FUNC_ADDR_NODE(cbtimer_node)      ((cbtimer_node)->expire_func_addr_node)
#define CBTIMER_NODE_START_TIME(cbtimer_node)                 (((cbtimer_node)->start_time))
#define CBTIMER_NODE_LAST_TIME(cbtimer_node)                  (((cbtimer_node)->last_time))



/**
*
* new CBTIMER_NODE
*
**/
CBTIMER_NODE *cbtimer_node_new();

/**
*
* init CBTIMER_NODE
*
**/
EC_BOOL cbtimer_node_init(CBTIMER_NODE *cbtimer_node);

/**
*
* clean CBTIMER_NODE
*
**/
EC_BOOL cbtimer_node_clean(CBTIMER_NODE *cbtimer_node);

/**
*
* free CBTIMER_NODE
*
**/
EC_BOOL cbtimer_node_free(CBTIMER_NODE *cbtimer_node);

EC_BOOL cbtimer_node_is_timeout(const CBTIMER_NODE *cbtimer_node, const CTIMET cur_time);

EC_BOOL cbtimer_node_is_expire(const CBTIMER_NODE *cbtimer_node, const CTIMET cur_time);

EC_BOOL cbtimer_node_timeout_handle(CBTIMER_NODE *cbtimer_node);
EC_BOOL cbtimer_node_expire_handle(CBTIMER_NODE *cbtimer_node);

EC_BOOL cbtimer_node_match_name(const CBTIMER_NODE *cbtimer_node, const CSTRING *name);

CLIST * cbtimer_new();
EC_BOOL cbtimer_init(CLIST *cbtimer_node_list);
EC_BOOL cbtimer_clean(CLIST *cbtimer_node_list);
EC_BOOL cbtimer_free(CLIST *cbtimer_node_list);

/**
*
* register a cbtimer
* the handler must look like as EC_BOOL foo(...), i.e., the function return type is EC_BOOL
* when EC_TRUE is returned, wait for next timeout
* when EC_FALSE is returned, unregister it
*
**/
CBTIMER_NODE *cbtimer_add(CLIST *cbtimer_node_list, const UINT8 *name, const UINT32 expire_nsec, const UINT32 timeout_nsec, const UINT32 timeout_func_id, ...);

EC_BOOL cbtimer_del(CLIST *cbtimer_node_list, const UINT8 *name);

EC_BOOL cbtimer_register(CLIST *cbtimer_node_list, CBTIMER_NODE *cbtimer_node);

/**
*
* delete CBTIMER_NODE
*
**/
EC_BOOL cbtimer_unregister(CLIST *cbtimer_node_list, CBTIMER_NODE *cbtimer_node);

CBTIMER_NODE *cbtimer_search_by_name(CLIST *cbtimer_node_list, const CSTRING *name);

/**
*
* num of CBTIMER_NODE
*
**/
UINT32  cbtimer_num(CLIST *cbtimer_node_list);

EC_BOOL cbtimer_handle(CLIST *cbtimer_node_list);


#endif/* _CBTIMER_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

