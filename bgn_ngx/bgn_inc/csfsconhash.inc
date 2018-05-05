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

#ifndef _CSFSCONHASH_INC
#define _CSFSCONHASH_INC

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"

#define CSFSCONHASH_DEFAULT_REPLICAS             ((uint16_t)32)
#define CSFSCONHASH_ANY_REPLICAS                 ((uint16_t) 0)
#define CSFSCONHASH_ERR_REPLICAS                 ((uint16_t)(~((uint16_t)0)))

#define CSFSCONHASH_RNODE_DEBUG                  (SWITCH_ON)

#define CSFSCONHASH_RNODE_IS_ERR                 ((uint16_t)0x0000)
#define CSFSCONHASH_RNODE_IS_UP                  ((uint16_t)0x0001)
#define CSFSCONHASH_RNODE_IS_DOWN                ((uint16_t)0x0002)

typedef struct
{
    uint16_t     replicas; /* number of replica virtual nodes */
    uint16_t     status;
    uint32_t     tcid;
#if(SWITCH_ON == CSFSCONHASH_RNODE_DEBUG)
    UINT32       counter; /*debug only!*/
#endif/*(SWITCH_ON == CSFSCONHASH_RNODE_DEBUG)*/
}CSFSCONHASH_RNODE;/*real node*/

#define CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode)           ((csfsconhash_rnode)->replicas)
#define CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode)             ((csfsconhash_rnode)->status)
#define CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)               ((csfsconhash_rnode)->tcid)

#if(SWITCH_ON == CSFSCONHASH_RNODE_DEBUG)
#define CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode)            ((csfsconhash_rnode)->counter)
#define CSFSCONHASH_RNODE_COUNTER_INC(csfsconhash_rnode)        (CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode) += 1)
#define CSFSCONHASH_RNODE_COUNTER_SET(csfsconhash_rnode, num)   (CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode) = (num))
#define CSFSCONHASH_RNODE_COUNTER_CLR(csfsconhash_rnode)        (CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode) = 0)
#define CSFSCONHASH_RNODE_COUNTER_CLONE(csfsconhash_rnode_src, csfsconhash_rnode_des)   \
    CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode_des) = CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode_src)
#endif/*(SWITCH_ON == CSFSCONHASH_RNODE_DEBUG)*/

#if(SWITCH_OFF == CSFSCONHASH_RNODE_DEBUG)
#define CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode)                                   do{}while(0)
#define CSFSCONHASH_RNODE_COUNTER_INC(csfsconhash_rnode)                               do{}while(0)
#define CSFSCONHASH_RNODE_COUNTER_SET(csfsconhash_rnode, num)                          do{}while(0)
#define CSFSCONHASH_RNODE_COUNTER_CLR(csfsconhash_rnode)                               do{}while(0)
#define CSFSCONHASH_RNODE_COUNTER_CLONE(csfsconhash_rnode_src, csfsconhash_rnode_des)  do{}while(0)
#endif/*(SWITCH_OFF == CSFSCONHASH_RNODE_DEBUG)*/

typedef struct
{
    uint32_t     hash; /*hash value of tcid.{x}*/
    uint32_t     pos;  /*CSFSCONHASH_NODE pos in CSFSCONHASH -> CVECTOR rnode_vec*/
}CSFSCONHASH_VNODE;/*virtual node*/

#define CSFSCONHASH_VNODE_HASH(csfsconhash_vnode)               ((csfsconhash_vnode)->hash)
#define CSFSCONHASH_VNODE_POS(csfsconhash_vnode)                ((csfsconhash_vnode)->pos)

typedef struct
{
    CVECTOR      rnode_vec; /*item is CSFSCONHASH_RNODE*/
    CRB_TREE     vnode_tree;/*item is CSFSCONHASH_VNODE*/

    UINT32       hash_id;
    UINT32      (*hash_func)(const UINT32, const UINT8 *);
}CSFSCONHASH;

#define CSFSCONHASH_RNODE_VEC(csfsconhash)               (&((csfsconhash)->rnode_vec))
#define CSFSCONHASH_VNODE_TREE(csfsconhash)              (&((csfsconhash)->vnode_tree))
#define CSFSCONHASH_HASH_ID(csfsconhash)                 ((csfsconhash)->hash_id)
#define CSFSCONHASH_HASH_FUNC(csfsconhash)               ((csfsconhash)->hash_func)

#endif /*_CSFSCONHASH_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

