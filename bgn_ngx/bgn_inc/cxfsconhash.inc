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

#ifndef _CXFSCONHASH_INC
#define _CXFSCONHASH_INC

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"

#define CXFSCONHASH_DEFAULT_REPLICAS             ((uint16_t)32)
#define CXFSCONHASH_ANY_REPLICAS                 ((uint16_t) 0)
#define CXFSCONHASH_ERR_REPLICAS                 ((uint16_t)(~((uint16_t)0)))

#define CXFSCONHASH_RNODE_DEBUG                  (SWITCH_ON)

#define CXFSCONHASH_RNODE_IS_ERR                 ((uint16_t)0x0000)
#define CXFSCONHASH_RNODE_IS_UP                  ((uint16_t)0x0001)
#define CXFSCONHASH_RNODE_IS_DOWN                ((uint16_t)0x0002)

typedef struct
{
    uint16_t     replicas; /* number of replica virtual nodes */
    uint16_t     status;
    uint32_t     tcid;
#if(SWITCH_ON == CXFSCONHASH_RNODE_DEBUG)
    UINT32       counter; /*debug only!*/
#endif/*(SWITCH_ON == CXFSCONHASH_RNODE_DEBUG)*/
}CXFSCONHASH_RNODE;/*real node*/

#define CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode)           ((cxfsconhash_rnode)->replicas)
#define CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode)             ((cxfsconhash_rnode)->status)
#define CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)               ((cxfsconhash_rnode)->tcid)

#if(SWITCH_ON == CXFSCONHASH_RNODE_DEBUG)
#define CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode)            ((cxfsconhash_rnode)->counter)
#define CXFSCONHASH_RNODE_COUNTER_INC(cxfsconhash_rnode)        (CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode) += 1)
#define CXFSCONHASH_RNODE_COUNTER_SET(cxfsconhash_rnode, num)   (CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode) = (num))
#define CXFSCONHASH_RNODE_COUNTER_CLR(cxfsconhash_rnode)        (CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode) = 0)
#define CXFSCONHASH_RNODE_COUNTER_CLONE(cxfsconhash_rnode_src, cxfsconhash_rnode_des)   \
    CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode_des) = CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode_src)
#endif/*(SWITCH_ON == CXFSCONHASH_RNODE_DEBUG)*/

#if(SWITCH_OFF == CXFSCONHASH_RNODE_DEBUG)
#define CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode)                                   do{}while(0)
#define CXFSCONHASH_RNODE_COUNTER_INC(cxfsconhash_rnode)                               do{}while(0)
#define CXFSCONHASH_RNODE_COUNTER_SET(cxfsconhash_rnode, num)                          do{}while(0)
#define CXFSCONHASH_RNODE_COUNTER_CLR(cxfsconhash_rnode)                               do{}while(0)
#define CXFSCONHASH_RNODE_COUNTER_CLONE(cxfsconhash_rnode_src, cxfsconhash_rnode_des)  do{}while(0)
#endif/*(SWITCH_OFF == CXFSCONHASH_RNODE_DEBUG)*/

typedef struct
{
    uint32_t     hash; /*hash value of tcid.{x}*/
    uint32_t     pos;  /*CXFSCONHASH_NODE pos in CXFSCONHASH -> CVECTOR rnode_vec*/
}CXFSCONHASH_VNODE;/*virtual node*/

#define CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode)               ((cxfsconhash_vnode)->hash)
#define CXFSCONHASH_VNODE_POS(cxfsconhash_vnode)                ((cxfsconhash_vnode)->pos)

typedef struct
{
    CVECTOR      rnode_vec; /*item is CXFSCONHASH_RNODE*/
    CRB_TREE     vnode_tree;/*item is CXFSCONHASH_VNODE*/

    UINT32       hash_id;
    UINT32      (*hash_func)(const UINT32, const UINT8 *);
}CXFSCONHASH;

#define CXFSCONHASH_RNODE_VEC(cxfsconhash)               (&((cxfsconhash)->rnode_vec))
#define CXFSCONHASH_VNODE_TREE(cxfsconhash)              (&((cxfsconhash)->vnode_tree))
#define CXFSCONHASH_HASH_ID(cxfsconhash)                 ((cxfsconhash)->hash_id)
#define CXFSCONHASH_HASH_FUNC(cxfsconhash)               ((cxfsconhash)->hash_func)

#endif /*_CXFSCONHASH_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

