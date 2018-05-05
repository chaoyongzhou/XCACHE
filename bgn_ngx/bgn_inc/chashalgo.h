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

#ifndef _CHASHALGO_H
#define _CHASHALGO_H

#include "type.h"

#define CHASH_SIMPLE_ALGO_ID        ((UINT32)   0)
#define CHASH_RS_ALGO_ID            ((UINT32)   1)
#define CHASH_JS_ALGO_ID            ((UINT32)   2)
#define CHASH_PJW_ALGO_ID           ((UINT32)   3)
#define CHASH_ELF_ALGO_ID           ((UINT32)   4)
#define CHASH_BKDR_ALGO_ID          ((UINT32)   5)
#define CHASH_SDBM_ALGO_ID          ((UINT32)   6)
#define CHASH_DJB_ALGO_ID           ((UINT32)   7)
#define CHASH_AP_ALGO_ID            ((UINT32)   8)
#define CHASH_CRC_ALGO_ID           ((UINT32)   9)
#define CHASH_MD5_ALGO_ID           ((UINT32)  10)
#define CHASH_ERR_ALGO_ID           ((UINT32)0xFF)/*8bits*/

typedef UINT32 (*CHASH_ALGO)(const UINT32, const UINT8 *);

typedef struct
{
    UINT32      chash_algo_id;
    CHASH_ALGO  chash_algo_func;
}CHASH_ALGO_NODE;

#define CHASH_ALGO_NODE_ID(chash_algo_node)           ((chash_algo_node)->chash_algo_id)
#define CHASH_ALGO_NODE_FUNC(chash_algo_node)         ((chash_algo_node)->chash_algo_func)


/* A Simple Hash Function */
UINT32 simple_hash(const UINT32 len, const UINT8 *str);

/* RS Hash Function */
UINT32 RS_hash(const UINT32 len, const UINT8 *str);

/* JS Hash Function */
UINT32 JS_hash(const UINT32 len, const UINT8 *str);

/* P. J. Weinberger Hash Function */
UINT32 PJW_hash(const UINT32 len, const UINT8 *str);

/* ELF Hash Function */
UINT32 ELF_hash(const UINT32 len, const UINT8 *str);

/* BKDR Hash Function */
UINT32 BKDR_hash(const UINT32 len, const UINT8 *str);

/* SDBM Hash Function */
UINT32 SDBM_hash(const UINT32 len, const UINT8 *str);

/* DJB Hash Function */
UINT32 DJB_hash(const UINT32 len, const UINT8 *str);

/* AP Hash Function */
UINT32 AP_hash(const UINT32 len, const UINT8 *str);

/* CRC Hash Function */
UINT32 CRC_hash(const UINT32 len, const UINT8 *str);

UINT32 MD5_hash(const UINT32 len, const UINT8 *str);

CHASH_ALGO chash_algo_fetch(const UINT32 chash_algo_id);


#endif /*_CHASHALGO_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

