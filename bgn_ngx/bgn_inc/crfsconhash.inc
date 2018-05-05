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

#ifndef _CRFSCONHASH_INC
#define _CRFSCONHASH_INC

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"

#define CRFSCONHASH_DEFAULT_REPLICAS             ((uint16_t)32)
#define CRFSCONHASH_ANY_REPLICAS                 ((uint16_t) 0)
#define CRFSCONHASH_ERR_REPLICAS                 ((uint16_t)(~((uint16_t)0)))

#define CRFSCONHASH_RNODE_DEBUG                  (SWITCH_ON)

#define CRFSCONHASH_RNODE_IS_ERR                 ((uint16_t)0x0000)
#define CRFSCONHASH_RNODE_IS_UP                  ((uint16_t)0x0001)
#define CRFSCONHASH_RNODE_IS_DOWN                ((uint16_t)0x0002)

typedef struct
{
    uint16_t     replicas; /* number of replica virtual nodes */
    uint16_t     status;
    uint32_t     tcid;
#if(SWITCH_ON == CRFSCONHASH_RNODE_DEBUG)
    UINT32       counter; /*debug only!*/
#endif/*(SWITCH_ON == CRFSCONHASH_RNODE_DEBUG)*/
}CRFSCONHASH_RNODE;/*real node*/

#define CRFSCONHASH_RNODE_REPLICAS(crfsconhash_rnode)           ((crfsconhash_rnode)->replicas)
#define CRFSCONHASH_RNODE_STATUS(crfsconhash_rnode)             ((crfsconhash_rnode)->status)
#define CRFSCONHASH_RNODE_TCID(crfsconhash_rnode)               ((crfsconhash_rnode)->tcid)

#if(SWITCH_ON == CRFSCONHASH_RNODE_DEBUG)
#define CRFSCONHASH_RNODE_COUNTER(crfsconhash_rnode)            ((crfsconhash_rnode)->counter)
#define CRFSCONHASH_RNODE_COUNTER_INC(crfsconhash_rnode)        (CRFSCONHASH_RNODE_COUNTER(crfsconhash_rnode) += 1)
#define CRFSCONHASH_RNODE_COUNTER_SET(crfsconhash_rnode, num)   (CRFSCONHASH_RNODE_COUNTER(crfsconhash_rnode) = (num))
#define CRFSCONHASH_RNODE_COUNTER_CLR(crfsconhash_rnode)        (CRFSCONHASH_RNODE_COUNTER(crfsconhash_rnode) = 0)
#define CRFSCONHASH_RNODE_COUNTER_CLONE(crfsconhash_rnode_src, crfsconhash_rnode_des)   \
    CRFSCONHASH_RNODE_COUNTER(crfsconhash_rnode_des) = CRFSCONHASH_RNODE_COUNTER(crfsconhash_rnode_src)
#endif/*(SWITCH_ON == CRFSCONHASH_RNODE_DEBUG)*/

#if(SWITCH_OFF == CRFSCONHASH_RNODE_DEBUG)
#define CRFSCONHASH_RNODE_COUNTER(crfsconhash_rnode)                                   do{}while(0)
#define CRFSCONHASH_RNODE_COUNTER_INC(crfsconhash_rnode)                               do{}while(0)
#define CRFSCONHASH_RNODE_COUNTER_SET(crfsconhash_rnode, num)                          do{}while(0)
#define CRFSCONHASH_RNODE_COUNTER_CLR(crfsconhash_rnode)                               do{}while(0)
#define CRFSCONHASH_RNODE_COUNTER_CLONE(crfsconhash_rnode_src, crfsconhash_rnode_des)  do{}while(0)
#endif/*(SWITCH_OFF == CRFSCONHASH_RNODE_DEBUG)*/

typedef struct
{
    uint32_t     hash; /*hash value of tcid.{x}*/
    uint32_t     pos;  /*CRFSCONHASH_NODE pos in CRFSCONHASH -> CVECTOR rnode_vec*/
}CRFSCONHASH_VNODE;/*virtual node*/

#define CRFSCONHASH_VNODE_HASH(crfsconhash_vnode)               ((crfsconhash_vnode)->hash)
#define CRFSCONHASH_VNODE_POS(crfsconhash_vnode)                ((crfsconhash_vnode)->pos)

typedef struct
{
    CVECTOR      rnode_vec; /*item is CRFSCONHASH_RNODE*/
    CRB_TREE     vnode_tree;/*item is CRFSCONHASH_VNODE*/

    UINT32       hash_id;
    UINT32      (*hash_func)(const UINT32, const UINT8 *);
}CRFSCONHASH;

#define CRFSCONHASH_RNODE_VEC(crfsconhash)               (&((crfsconhash)->rnode_vec))
#define CRFSCONHASH_VNODE_TREE(crfsconhash)              (&((crfsconhash)->vnode_tree))
#define CRFSCONHASH_HASH_ID(crfsconhash)                 ((crfsconhash)->hash_id)
#define CRFSCONHASH_HASH_FUNC(crfsconhash)               ((crfsconhash)->hash_func)

#endif /*_CRFSCONHASH_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

