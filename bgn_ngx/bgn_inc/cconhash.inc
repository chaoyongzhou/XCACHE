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

#ifndef _CCONHASH_INC
#define _CCONHASH_INC

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "crb.h"

#define CCONHASH_DEFAULT_REPLICAS             ((uint16_t)32)
#define CCONHASH_ANY_REPLICAS                 ((uint16_t) 0)
#define CCONHASH_ERR_REPLICAS                 ((uint16_t)(~((uint16_t)0)))

#define CCONHASH_RNODE_IS_ERR                 ((uint16_t)0x0000)
#define CCONHASH_RNODE_IS_UP                  ((uint16_t)0x0001)
#define CCONHASH_RNODE_IS_DOWN                ((uint16_t)0x0002)

typedef struct
{
    uint16_t     replicas; /* number of replica virtual nodes */
    uint16_t     status;
    uint32_t     tcid;
}CCONHASH_RNODE;/*real node*/

#define CCONHASH_RNODE_REPLICAS(cconhash_rnode)           ((cconhash_rnode)->replicas)
#define CCONHASH_RNODE_STATUS(cconhash_rnode)             ((cconhash_rnode)->status)
#define CCONHASH_RNODE_TCID(cconhash_rnode)               ((cconhash_rnode)->tcid)

typedef struct
{
    uint32_t     hash; /*hash value of tcid.{x}*/
    uint32_t     pos;  /*CCONHASH_NODE pos in CCONHASH -> CVECTOR rnode_vec*/
}CCONHASH_VNODE;/*virtual node*/

#define CCONHASH_VNODE_HASH(cconhash_vnode)               ((cconhash_vnode)->hash)
#define CCONHASH_VNODE_POS(cconhash_vnode)                ((cconhash_vnode)->pos)

typedef struct
{
    CVECTOR      rnode_vec; /*item is CCONHASH_RNODE*/
    CRB_TREE     vnode_tree;/*item is CCONHASH_VNODE*/

    UINT32       hash_id;
    UINT32      (*hash_func)(const UINT32, const UINT8 *);
}CCONHASH;

#define CCONHASH_RNODE_VEC(cconhash)               (&((cconhash)->rnode_vec))
#define CCONHASH_VNODE_TREE(cconhash)              (&((cconhash)->vnode_tree))
#define CCONHASH_HASH_ID(cconhash)                 ((cconhash)->hash_id)
#define CCONHASH_HASH_FUNC(cconhash)               ((cconhash)->hash_func)

#endif /*_CCONHASH_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

