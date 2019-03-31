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

#ifndef _CMSYNC_H
#define _CMSYNC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <math.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"

typedef struct
{
    void            *s_addr;
    void            *e_addr;

    void            *c_addr;
}CMSYNC_NODE;

#define CMSYNC_NODE_S_ADDR(cmsync_node)               ((cmsync_node)->s_addr)
#define CMSYNC_NODE_E_ADDR(cmsync_node)               ((cmsync_node)->e_addr)
#define CMSYNC_NODE_C_ADDR(cmsync_node)               ((cmsync_node)->c_addr)

CMSYNC_NODE *cmsync_node_new();

EC_BOOL cmsync_node_init(CMSYNC_NODE *cmsync_node);

EC_BOOL cmsync_node_clean(CMSYNC_NODE *cmsync_node);

EC_BOOL cmsync_node_free(CMSYNC_NODE *cmsync_node);

void cmsync_node_print(LOG *log, const CMSYNC_NODE *cmsync_node);

CMSYNC_NODE *cmsync_node_create(void *addr, const UINT32 size);

EC_BOOL cmsync_node_start(CMSYNC_NODE *cmsync_node);

EC_BOOL cmsync_node_end(CMSYNC_NODE *cmsync_node);

EC_BOOL cmsync_node_process(CMSYNC_NODE *cmsync_node, const UINT32 size);

UINT32 cmsync_node_space(const CMSYNC_NODE *cmsync_node);

UINT32 cmsync_node_left(const CMSYNC_NODE *cmsync_node);


#endif /*_CMSYNC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

