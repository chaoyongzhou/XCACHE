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

#ifndef    _CXFSNPATTR_H
#define    _CXFSNPATTR_H

#include "type.h"
#include "log.h"

#include "cxfsnprb.h"
#include "cxfsnp.inc"

EC_BOOL cxfsnpattr_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

#endif    /* _CXFSNPATTR_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
