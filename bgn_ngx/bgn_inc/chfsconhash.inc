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

#ifndef _CHFSCONHASH_INC
#define _CHFSCONHASH_INC

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"

#define CHFSCONHASH_DEFAULT_REPLICAS             ((uint16_t)32)
#define CHFSCONHASH_ANY_REPLICAS                 ((uint16_t) 0)
#define CHFSCONHASH_ERR_REPLICAS                 ((uint16_t)(~((uint16_t)0)))

#define CHFSCONHASH_RNODE_DEBUG                  (SWITCH_ON)

#define CHFSCONHASH_RNODE_IS_ERR                 ((uint16_t)0x0000) 
#define CHFSCONHASH_RNODE_IS_UP                  ((uint16_t)0x0001) 
#define CHFSCONHASH_RNODE_IS_DOWN                ((uint16_t)0x0002) 

typedef struct
{
    uint16_t     replicas; /* number of replica virtual nodes */
    uint16_t     status;
    uint32_t     tcid;
#if(SWITCH_ON == CHFSCONHASH_RNODE_DEBUG)    
    UINT32       counter; /*debug only!*/
#endif/*(SWITCH_ON == CHFSCONHASH_RNODE_DEBUG)*/    
}CHFSCONHASH_RNODE;/*real node*/

#define CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode)           ((chfsconhash_rnode)->replicas)
#define CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode)             ((chfsconhash_rnode)->status)
#define CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)               ((chfsconhash_rnode)->tcid)

#if(SWITCH_ON == CHFSCONHASH_RNODE_DEBUG)
#define CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode)            ((chfsconhash_rnode)->counter)
#define CHFSCONHASH_RNODE_COUNTER_INC(chfsconhash_rnode)        (CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode) += 1)
#define CHFSCONHASH_RNODE_COUNTER_SET(chfsconhash_rnode, num)   (CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode) = (num))
#define CHFSCONHASH_RNODE_COUNTER_CLR(chfsconhash_rnode)        (CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode) = 0)
#define CHFSCONHASH_RNODE_COUNTER_CLONE(chfsconhash_rnode_src, chfsconhash_rnode_des)   \
    CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode_des) = CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode_src)
#endif/*(SWITCH_ON == CHFSCONHASH_RNODE_DEBUG)*/

#if(SWITCH_OFF == CHFSCONHASH_RNODE_DEBUG)
#define CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode)                                   do{}while(0)
#define CHFSCONHASH_RNODE_COUNTER_INC(chfsconhash_rnode)                               do{}while(0)
#define CHFSCONHASH_RNODE_COUNTER_SET(chfsconhash_rnode, num)                          do{}while(0)
#define CHFSCONHASH_RNODE_COUNTER_CLR(chfsconhash_rnode)                               do{}while(0)
#define CHFSCONHASH_RNODE_COUNTER_CLONE(chfsconhash_rnode_src, chfsconhash_rnode_des)  do{}while(0)
#endif/*(SWITCH_OFF == CHFSCONHASH_RNODE_DEBUG)*/

typedef struct
{
    uint32_t     hash; /*hash value of tcid.{x}*/
    uint32_t     pos;  /*CHFSCONHASH_NODE pos in CHFSCONHASH -> CVECTOR rnode_vec*/
}CHFSCONHASH_VNODE;/*virtual node*/

#define CHFSCONHASH_VNODE_HASH(chfsconhash_vnode)               ((chfsconhash_vnode)->hash)
#define CHFSCONHASH_VNODE_POS(chfsconhash_vnode)                ((chfsconhash_vnode)->pos)

typedef struct
{
    CVECTOR      rnode_vec; /*item is CHFSCONHASH_RNODE*/
    CRB_TREE     vnode_tree;/*item is CHFSCONHASH_VNODE*/  

    UINT32       hash_id;
    UINT32      (*hash_func)(const UINT32, const UINT8 *);
}CHFSCONHASH;

#define CHFSCONHASH_RNODE_VEC(chfsconhash)               (&((chfsconhash)->rnode_vec))
#define CHFSCONHASH_VNODE_TREE(chfsconhash)              (&((chfsconhash)->vnode_tree))
#define CHFSCONHASH_HASH_ID(chfsconhash)                 ((chfsconhash)->hash_id)
#define CHFSCONHASH_HASH_FUNC(chfsconhash)               ((chfsconhash)->hash_func)

#endif /*_CHFSCONHASH_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

