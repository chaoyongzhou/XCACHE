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

#ifndef    _CRFSNPKEY_H
#define    _CRFSNPKEY_H

#include "type.h"
#include "log.h"

#include "crfsnprb.h"
#include "crfsnp.inc"

EC_BOOL crfsnpkey_pool_init(CRFSNPRB_POOL *pool, const uint32_t node_max_num, const uint32_t node_sizeof);

#endif    /* _CRFSNPKEY_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
