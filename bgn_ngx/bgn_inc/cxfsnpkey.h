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

#ifndef    _CXFSNPKEY_H
#define    _CXFSNPKEY_H

#include "type.h"
#include "log.h"

#include "cxfsnprb.h"
#include "cxfsnp.inc"

EC_BOOL cxfsnpkey_pool_init(CXFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

#endif    /* _CXFSNPKEY_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
