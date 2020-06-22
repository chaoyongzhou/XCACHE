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

#ifndef _CMAGLEV_INC
#define _CMAGLEV_INC

#include <stdlib.h>
#include <stdio.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cvector.h"

#define CMAGLEV_MIN_RING_SIZE               (211)
#define CMAGLEV_MAX_RING_SIZE               (40009)

#define CMAGLEV_MAX_NEXT_SIZE               (64)

#define CMAGLEV_RNODE_IS_ERR                ((uint16_t)0x0000)
#define CMAGLEV_RNODE_IS_UP                 ((uint16_t)0x0001)
#define CMAGLEV_RNODE_IS_DOWN               ((uint16_t)0x0002)
#define CMAGLEV_ENTRY_ERR_INDEX             ((int)-1)

typedef struct
{
    uint16_t     status;
    uint16_t     rsvd;
    uint32_t     tcid;      /* xfs_tcid */
}CMAGLEV_RNODE;/*real node*/

#define CMAGLEV_RNODE_STATUS(cmaglev_rnode)             ((cmaglev_rnode)->status)
#define CMAGLEV_RNODE_TCID(cmaglev_rnode)               ((cmaglev_rnode)->tcid)

typedef struct
{
    int                 *entry;       /*ring_size len, used to query.
                                       *element in array save index of rnode-array
                                       */

    UINT32              *next;        /*intermediate value used to generate maglev-hash*/

    UINT32              *permutation; /*up-node-number * ring_size * 2,
                                       *intermediate value used to generate maglev-hash
                                       */
}CMAGLEV_QNODE;

#define CMAGLEV_QNODE_ENTRY(cmaglev_qnode)             ((cmaglev_qnode)->entry)
#define CMAGLEV_QNODE_NEXT(cmaglev_qnode)              ((cmaglev_qnode)->next)
#define CMAGLEV_QNODE_PERMUTATION(cmaglev_qnode)       ((cmaglev_qnode)->permutation)

typedef struct
{
    UINT32               ring_size;     /*a prime num, MIN_SIZE or MAX_SIZE*/
    CVECTOR              rnode_vec;     /*item is CMAGLEV_RNODE*/
    CMAGLEV_QNODE        qnode_item;    /**/
}CMAGLEV;

#define CMAGLEV_RING_SIZE(cmaglev)                      ((cmaglev)->ring_size)
#define CMAGLEV_RNODE_VEC(cmaglev)                      (&((cmaglev)->rnode_vec))
#define CMAGLEV_QNODE_ITEM(cmaglev)                     (&((cmaglev)->qnode_item))

#endif /*_CMAGLEV_INC*/
#ifdef __cplusplus
}
#endif/*__cplusplus*/

