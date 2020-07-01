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

#include "cvector.h"

typedef EC_BOOL (*CCALLBACK_RUNNER)(void *);

typedef struct
{
    const char                 *name;     /*always const string, never free*/
    void                       *func;     /*callback function address*/
    void                       *data;     /*arg*/
    uint32_t                    used_flag:1;
    uint32_t                    timer_flag:1;
    uint32_t                    rsvd01:31;
    uint32_t                    rsvd02;
}CCALLBACK_NODE;

#define CCALLBACK_NODE_NAME(ccallback_node)             ((ccallback_node)->name)
#define CCALLBACK_NODE_FUNC(ccallback_node)             ((ccallback_node)->func)
#define CCALLBACK_NODE_DATA(ccallback_node)             ((ccallback_node)->data)
#define CCALLBACK_NODE_USED_FLAG(ccallback_node)        ((ccallback_node)->used_flag)
#define CCALLBACK_NODE_TIMER_FLAG(ccallback_node)       ((ccallback_node)->timer_flag)


CCALLBACK_NODE *ccallback_node_new();

EC_BOOL ccallback_node_init(CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_clean(CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_free(CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_set(CCALLBACK_NODE *ccallback_node, const char *name, void *data, void *func);

EC_BOOL ccallback_node_is_used(const CCALLBACK_NODE *ccallback_node);

void    ccallback_node_print(LOG *log, const CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_run(CCALLBACK_NODE *ccallback_node);

EC_BOOL ccallback_node_runner_default(CCALLBACK_NODE *ccallback_node);


#endif/*_CCALLBACK_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

