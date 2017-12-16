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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcre.h>
#include <libgen.h>
#include <zlib.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "db_internal.h"

#include "keyvalue.h"

#include "cbtree.h"

static uint8_t *__cbtree_x_key_dup(const uint8_t *key, const word_t location);

static void __cbtree_x_key_free(uint8_t *key, const word_t location);

static void __cbtree_x_key_print(LOG *log, const uint8_t *key);

static uint32_t __cbtree_x_key_tlen(const uint8_t *key);

static int __cbtree_x_key_cmp(const uint8_t *key_1st, const uint8_t *key_2nd);

static EC_BOOL __cbtree_x_key_encode_size(const uint8_t *key, uint32_t *size);

static EC_BOOL __cbtree_x_key_encode(const uint8_t *key, uint8_t *buff, const uint32_t size, uint32_t *pos);

static EC_BOOL __cbtree_x_key_decode(uint8_t **key, uint8_t *buff, const uint32_t size, uint32_t *pos);

static void __cbtree_leaf_checker(CBTREE *cbtree, LOG *log);

EC_BOOL cbtree_verbose = EC_FALSE;

#define __CBTREE_DEBUG_BEG  if(EC_TRUE == cbtree_verbose) {
#define __CBTREE_DEBUG_END  }

#if 0
#define PRINT_BUFF(info, buff, beg, end) do{\
    UINT32 __pos;\
    dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "[%4d] %s: \n", (end) - (beg), info);\
    for(__pos = beg; __pos < (end); __pos ++)\
    {\
        sys_print(LOGSTDOUT, "%2x,", ((UINT8 *)buff)[ __pos ]);\
        if(0 == ((__pos - (beg)  + 1) % 8))\
        {\
            sys_print(LOGSTDOUT, "\n");\
        }\
    }\
    sys_print(LOGSTDOUT, "\n");\
}while(0)
#else
#define PRINT_BUFF(info, buff, beg, end) do{}while(0)
#endif

#if 0
#define CBTREE_SEARCH_KEY(this_cbtree, node, count, this_key, idx, result) do{\
    for ((idx) = 0;\
         (idx) < (count) && 0 > ((result) = cbtree_key_cmp((this_cbtree), CBTREE_NODE_KEY((node), (idx)), (this_key)));\
         (idx)++)\
    {\
        /*do nothing*/\
    }\
}while(0)
#else
#define CBTREE_SEARCH_KEY(this_cbtree, node, count, this_key, idx, result) do{\
    __cbtree_search_key(this_cbtree, node, count, this_key, &(idx), &(result));\
}while(0)
#endif


UINT32 g_cbtree_key_cmp_counter = 0;

static void __cbtree_search_key(const CBTREE *cbtree, const CBTREE_NODE *node, const uint8_t count, const CBTREE_KEY *key, uint8_t *idx, int *result)
{
    uint8_t lo;
    uint8_t hi;
    int     ret;
    uint8_t md;

    if(0 == count)
    {
        (*idx) = 0;
        (*result) = -3;
        return;
    }

    lo = 0;
    hi = count;
    md = 0;
    ret = -3;

    while(lo < hi)
    {
        md = (lo + hi)/2;
     
        ret = cbtree_key_cmp(cbtree, CBTREE_NODE_KEY(node, md), key);     
        if(0 == ret)
        {
            break;
        }     
        else if(0 < ret)
        {
           hi = md;
        }
        else if(0 > ret)
        {
           lo = md + 1;
        } 
    }

    if(0 > ret)
    {
        md ++;/*adjust by move forward one step*/
    }

    (*idx) = md;
    (*result) = ret;

    return;
}



static void __cbtree_x_key_print(LOG *log, const uint8_t *key)
{
    /*for debug*/
    if(NULL_PTR == key)
    {
        sys_print(log, "(null) ");
        return;     
    }
    sys_print(log, "%s", (const char *)key);
    return;
}

static uint8_t *__cbtree_x_key_dup(const uint8_t *key, const word_t location)
{
    uint8_t *key_dup;

    ASSERT(key_dup = (uint8_t *)safe_malloc(strlen((const char *)key) + 1, LOC_CBTREE_0001)); 
    BCOPY(key, key_dup, strlen((const char *)key) + 1);
    return (key_dup);
    //return keyDup(key, location);
    //return (uint8_t *)strdup((const char *)key);
 
}

static void __cbtree_x_key_free(uint8_t *key, const word_t location)
{
    //keyFree(key, location);
    //safe_free(key, location);
    //free(key);
    safe_free(key, LOC_CBTREE_0002);
    return;
}

static uint32_t __cbtree_x_key_tlen(const uint8_t *key)
{
    if(NULL_PTR == key)
    {
        return ((uint32_t)0);
    }
    return (uint32_t)(strlen((const char *)key) + 1);
}

static int __cbtree_x_key_cmp(const uint8_t *key_1st, const uint8_t *key_2nd)
{
    int ret;
    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_x_key_cmp: %s <--> %s\n", (const char *)key_1st, (const char *)key_2nd);
    ret = strcmp((const char *)key_1st, (const char *)key_2nd);
    if(0 > ret)
    {
        return (-1);
    }

    if(0 < ret)
    {
        return (1);
    }
    return (0);
}

static EC_BOOL __cbtree_x_key_encode_size(const uint8_t *key, uint32_t *pos)
{
    (*pos) += sizeof(uint32_t) + strlen((const char *)key) + 1;
    return (EC_TRUE);
}

static EC_BOOL __cbtree_x_key_encode(const uint8_t *key, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint32_t len;
    uint32_t beg_pos;

    beg_pos = (*pos);

    len = strlen((const char *)key) + 1;
    if(sizeof(uint32_t) + len > size - (*pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_x_key_encode: left room is %d bytes, no enough room to accept %d bytes\n",
                            size - (*pos), len + sizeof(uint32_t));
        return (EC_FALSE);
    }

    gdbPut32(buff, pos, len);
    //PRINT_BUFF("[DEBUG] __cbtree_x_key_encode:[1] ", buff, beg_pos, (*pos));
    gdbPut8s(buff, pos, key, len);
    //PRINT_BUFF("[DEBUG] __cbtree_x_key_encode:[2] ", buff, beg_pos, (*pos));
    return (EC_TRUE);
}

static EC_BOOL __cbtree_x_key_decode(uint8_t **key, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint32_t len;

    if(sizeof(uint32_t) > size - (*pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_x_key_decode: left room is %d bytes, insufficent to decode len info\n",
                            size - (*pos));
        return (EC_FALSE);
    }

    len = gdbGet32(buff, pos);

    if(len > size - (*pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_x_key_decode: left room is %d bytes, insufficent to decode %d bytes\n",
                            size - (*pos), len);
        return (EC_FALSE);
    }

    (*key) = (uint8_t *)safe_malloc(len, LOC_CBTREE_0003);
    if(NULL_PTR == (*key))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_x_key_decode: malloc %d bytes failed\n", len);
        return (EC_FALSE);
    }

    gdbGet8s(buff, pos, (*key), len);
    return (EC_TRUE);
}


EC_BOOL cbtree_key_op_init(CBTREE_KEY_OPERATOR *cbtree_key_op)
{
    CBTREE_KEY_OPERATOR_DUP(cbtree_key_op)              = NULL_PTR;
    CBTREE_KEY_OPERATOR_FREE(cbtree_key_op)             = NULL_PTR;
    CBTREE_KEY_OPERATOR_TLEN(cbtree_key_op)             = NULL_PTR;
    CBTREE_KEY_OPERATOR_CMP(cbtree_key_op)              = NULL_PTR;
    CBTREE_KEY_OPERATOR_PRINT(cbtree_key_op)            = NULL_PTR;
    CBTREE_KEY_OPERATOR_ENCODE_SIZE(cbtree_key_op)      = NULL_PTR;
    CBTREE_KEY_OPERATOR_ENCODE(cbtree_key_op)           = NULL_PTR;
    CBTREE_KEY_OPERATOR_DECODE(cbtree_key_op)           = NULL_PTR;
 
    return (EC_TRUE);
}

EC_BOOL cbtree_key_op_clean(CBTREE_KEY_OPERATOR *cbtree_key_op)
{
    CBTREE_KEY_OPERATOR_DUP(cbtree_key_op)              = NULL_PTR;
    CBTREE_KEY_OPERATOR_FREE(cbtree_key_op)             = NULL_PTR;
    CBTREE_KEY_OPERATOR_TLEN(cbtree_key_op)             = NULL_PTR;
    CBTREE_KEY_OPERATOR_CMP(cbtree_key_op)              = NULL_PTR;
    CBTREE_KEY_OPERATOR_PRINT(cbtree_key_op)            = NULL_PTR;
    CBTREE_KEY_OPERATOR_ENCODE_SIZE(cbtree_key_op)      = NULL_PTR;
    CBTREE_KEY_OPERATOR_ENCODE(cbtree_key_op)           = NULL_PTR;
    CBTREE_KEY_OPERATOR_DECODE(cbtree_key_op)           = NULL_PTR;
 
    return (EC_TRUE);
}

CBTREE_KEY *cbtree_key_new(const CBTREE *cbtree)
{
    CBTREE_KEY *cbtree_key;

    alloc_static_mem(MM_CBTREE_KEY, &cbtree_key, LOC_CBTREE_0004);
    if(NULL_PTR != cbtree_key)
    {
        cbtree_key_init(cbtree, cbtree_key);
    }

    return (cbtree_key);
}

EC_BOOL cbtree_key_init(const CBTREE *cbtree, CBTREE_KEY *cbtree_key)
{
    uint8_t ver; 

    CBTREE_KEY_OFFSET(cbtree_key) = CBTREE_ERR_OFFSET;
    for(ver = 0; ver < CBTREE_MAX_VER(cbtree); ver ++)
    {
        CBTREE_KEY_KV(cbtree_key, ver)  = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cbtree_key_clean(const CBTREE *cbtree, CBTREE_KEY *cbtree_key)
{
    uint8_t ver;
 
    for(ver = 0; ver < CBTREE_MAX_VER(cbtree); ver ++)
    {
        if(NULL_PTR != CBTREE_KEY_KV(cbtree_key, ver))
        {
            CBTREE_KEY_FREE_OP(cbtree)(CBTREE_KEY_KV(cbtree_key, ver), LOC_CBTREE_0005);
            CBTREE_KEY_KV(cbtree_key, ver) = NULL_PTR;
        }
    }
    CBTREE_KEY_OFFSET(cbtree_key) = CBTREE_ERR_OFFSET;

    return (EC_TRUE);
}

EC_BOOL cbtree_key_free(const CBTREE *cbtree, CBTREE_KEY *cbtree_key)
{
    if(NULL_PTR != cbtree_key)
    {
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_key_free: try to clean key %lx\n", cbtree_key);
        cbtree_key_clean(cbtree, cbtree_key);
        free_static_mem(MM_CBTREE_KEY, cbtree_key, LOC_CBTREE_0006);
    }

    return (EC_TRUE);
}

CBTREE_KEY *cbtree_key_make(const CBTREE *cbtree, const uint8_t *key)
{
    uint8_t    *dup_key;
    CBTREE_KEY *cbtree_key;

    cbtree_key = cbtree_key_new(cbtree);
    if(NULL_PTR == cbtree_key)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_make: new cbtree_key failed\n");
        return (NULL_PTR);
    }

    dup_key = CBTREE_KEY_DUP_OP(cbtree)(key, LOC_CBTREE_0007);
    if(NULL_PTR == dup_key)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_make: dup key failed\n");
        cbtree_key_free(cbtree, cbtree_key);
        return (NULL_PTR);
    }

    cbtree_key_push(cbtree, cbtree_key, dup_key);
    return (cbtree_key);
}

/*add or push key to cbtree_key*/
EC_BOOL cbtree_key_push(const CBTREE *cbtree, CBTREE_KEY *cbtree_key, const uint8_t *key)
{
    uint8_t ver;
    uint8_t *t_key_1;

    t_key_1 = CBTREE_KEY_KV(cbtree_key, 0);
    CBTREE_KEY_KV(cbtree_key, 0) = (uint8_t *)key;
 
    for(ver = 1; ver < CBTREE_MAX_VER(cbtree); ver ++)
    {
        XCHG(uint8_t *, CBTREE_KEY_KV(cbtree_key, ver), t_key_1);
    } 

    if(NULL_PTR != t_key_1)
    {
        CBTREE_KEY_FREE_OP(cbtree)(t_key_1, LOC_CBTREE_0008);
    }
    return (EC_TRUE);
}

EC_BOOL cbtree_key_update(const CBTREE *cbtree, CBTREE_KEY *cbtree_key_des, CBTREE_KEY *cbtree_key_src)
{
    uint8_t ver;
    uint8_t *t_key_1;

    t_key_1 = CBTREE_KEY_KV(cbtree_key_des, 0);
    CBTREE_KEY_KV(cbtree_key_des, 0) = CBTREE_KEY_KV(cbtree_key_src, 0);
 
    for(ver = 1; ver < CBTREE_MAX_VER(cbtree); ver ++)
    {
        XCHG(uint8_t *, CBTREE_KEY_KV(cbtree_key_des, ver), t_key_1);
    } 

    CBTREE_KEY_KV(cbtree_key_src, 0) = t_key_1;
    return (EC_TRUE);
}

void cbtree_key_print(LOG *log, const CBTREE *cbtree, const CBTREE_KEY *cbtree_key)
{
    /*for debug*/
 
    if(NULL_PTR == cbtree_key)
    {
        sys_print(log, "(null)");
        return;     
    }
    CBTREE_KEY_PRINT_OP(cbtree)(log, CBTREE_KEY_LATEST(cbtree_key));
 
    return;
}

int cbtree_key_cmp(const CBTREE *cbtree, const CBTREE_KEY *cbtree_key_1st, const CBTREE_KEY *cbtree_key_2nd)
{
    g_cbtree_key_cmp_counter ++;
    /*for debug*/
    //return keyCmp(key_1st, key_2nd);
    return CBTREE_KEY_CMP_OP(cbtree)(CBTREE_KEY_LATEST(cbtree_key_1st), CBTREE_KEY_LATEST(cbtree_key_2nd));
}

EC_BOOL cbtree_key_clone(const CBTREE *cbtree, const CBTREE_KEY *cbtree_key_src, CBTREE_KEY *cbtree_key_des)
{
    uint8_t ver;

    for(ver = 0; ver < CBTREE_MAX_VER(cbtree); ver ++)
    {
        if(NULL_PTR != CBTREE_KEY_KV(cbtree_key_src, ver))
        {
            uint8_t *key;
            key = CBTREE_KEY_DUP_OP(cbtree)(CBTREE_KEY_KV(cbtree_key_src, ver), LOC_CBTREE_0009);
            if(NULL_PTR == key)
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_clone: dup key of version %ld failed\n", ver);
                return (EC_FALSE);
            }
            CBTREE_KEY_KV(cbtree_key_des, ver) = key;
        }
    }
    return (EC_TRUE);
}

uint8_t *cbtree_key_dup_latest(const CBTREE *cbtree, const CBTREE_KEY * cbtree_key_src)
{
    return CBTREE_KEY_DUP_OP(cbtree)(CBTREE_KEY_LATEST(cbtree_key_src), LOC_CBTREE_0010);
}

CBTREE_KEY *cbtree_key_dup_all(const CBTREE *cbtree, const CBTREE_KEY * cbtree_key_src)
{
    CBTREE_KEY *cbtree_key_des;

    cbtree_key_des = cbtree_key_new(cbtree);
    if(NULL_PTR == cbtree_key_des)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_dup_all: new cbtree key failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cbtree_key_clone(cbtree, cbtree_key_src, cbtree_key_des))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_dup_all: clone cbtree key failed\n");
        cbtree_key_free(cbtree, cbtree_key_des);
        return (NULL_PTR);
    }

    return (cbtree_key_des);
}

uint32_t cbtree_key_tlen(const CBTREE *cbtree, const CBTREE_KEY * cbtree_key)
{
    uint8_t  ver;
    uint32_t tlen;

    if(NULL_PTR == cbtree_key)
    {
        return ((uint32_t)0);
    }

    tlen = 0;
    for(ver = 0; ver < CBTREE_MAX_VER(cbtree); ver ++)
    {
        if(NULL_PTR == CBTREE_KEY_KV(cbtree_key, ver))
        {
            break;
        }
     
        tlen += CBTREE_KEY_TLEN_OP(cbtree)(CBTREE_KEY_KV(cbtree_key, ver));
    }
    return (tlen);
}

CBTREE_NODE *cbtree_node_new(const CBTREE *cbtree)
{
    CBTREE_NODE *cbtree_node;

    alloc_static_mem(MM_CBTREE_NODE, &cbtree_node, LOC_CBTREE_0011);
    if(NULL_PTR != cbtree_node)
    {
        cbtree_node_init(cbtree, cbtree_node);
    }

    return (cbtree_node);
}

EC_BOOL cbtree_node_init(const CBTREE *cbtree, CBTREE_NODE *cbtree_node)
{
    uint8_t pos;
 
    CBTREE_NODE_COUNT(cbtree_node)  = 0;
    CBTREE_NODE_FLAG(cbtree_node)   = CBTREE_NODE_ERR_FLAG;
    CBTREE_NODE_OFFSET(cbtree_node) = CBTREE_ERR_OFFSET;

    for(pos = 0; pos < CBTREE_ORDER(cbtree); pos ++)
    {     
        CBTREE_NODE_CHILD(cbtree_node, pos) = NULL_PTR;/*for not-leaf node*/
        CBTREE_NODE_KEY(cbtree_node, pos)   = NULL_PTR;/*for leaf node*/
    }
 
    return (EC_TRUE);
}

EC_BOOL cbtree_node_clean(const CBTREE *cbtree, CBTREE_NODE *cbtree_node)
{
    uint8_t pos;

    if(! CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        for(pos = 0; pos <= CBTREE_NODE_COUNT(cbtree_node); pos ++)
        {
            cbtree_node_free(cbtree, CBTREE_NODE_CHILD(cbtree_node, pos));
            CBTREE_NODE_CHILD(cbtree_node, pos) = NULL_PTR; 
        }
    }

    if(CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        /*when it is leaf node, all its children all null, so ignore them*/
     
        for(pos = 0; pos < CBTREE_NODE_COUNT(cbtree_node); pos ++)
        {
            cbtree_key_free(cbtree, CBTREE_NODE_KEY(cbtree_node, pos));
            CBTREE_NODE_KEY(cbtree_node, pos) = NULL_PTR;
        }
    }

    CBTREE_NODE_COUNT(cbtree_node)  = 0;
    CBTREE_NODE_FLAG(cbtree_node)   = CBTREE_NODE_ERR_FLAG;
    CBTREE_NODE_OFFSET(cbtree_node) = CBTREE_ERR_OFFSET;
    return (EC_TRUE);
}

EC_BOOL cbtree_node_free(const CBTREE *cbtree, CBTREE_NODE *cbtree_node)
{
    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_free: try to free node %lx\n", cbtree_node);
    if(NULL_PTR != cbtree_node)
    {
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_free: try to clean node %lx\n", cbtree_node);
        cbtree_node_clean(cbtree, cbtree_node);
        free_static_mem(MM_CBTREE_NODE, cbtree_node, LOC_CBTREE_0012);
    }

    return (EC_TRUE);
}

/*set as the latest key*/
EC_BOOL cbtree_node_set_key(CBTREE *cbtree, CBTREE_NODE *cbtree_node, const uint8_t pos, const uint8_t *key)
{
    CBTREE_KEY *cbtree_key;

    cbtree_key = CBTREE_NODE_KEY(cbtree_node, pos);
    if(NULL_PTR == cbtree_key)
    {
        cbtree_key = cbtree_key_new(cbtree);
        if(NULL_PTR == cbtree_key)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_set_key: new cbtree_key failed\n");
            return (EC_FALSE);
        }

        cbtree_key_push(cbtree, cbtree_key, key);
        CBTREE_NODE_KEY(cbtree_node, pos) = cbtree_key;

        return (EC_TRUE);
    }
    cbtree_key_push(cbtree, cbtree_key, key);
    return (EC_TRUE);
}

/*get the latest key*/
uint8_t *cbtree_node_get_key(const CBTREE *cbtree, CBTREE_NODE *cbtree_node, const uint8_t pos)
{
    CBTREE_KEY *cbtree_key;

    cbtree_key = CBTREE_NODE_KEY(cbtree_node, pos);
    if(NULL_PTR == cbtree_key)
    {
        return (NULL_PTR);
    }

    return CBTREE_KEY_LATEST(cbtree_key);
}

uint32_t cbtree_node_count_tlen(const CBTREE *cbtree, const CBTREE_NODE *cbtree_node)
{
    uint32_t tlen;
    uint8_t  i;

    tlen = 0;
    for(i = 0; i < CBTREE_NODE_COUNT(cbtree_node); i ++)
    {
        tlen += cbtree_key_tlen(cbtree, CBTREE_NODE_KEY(cbtree_node, i));
    }
    return (tlen);
}

/*get right most leaf*/
CBTREE_NODE *cbtree_node_get_r_leaf(const CBTREE *cbtree, CBTREE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }
 
    while(! CBTREE_NODE_IS_LEAF(node))
    {
        node = CBTREE_NODE_CHILD(node, CBTREE_NODE_COUNT(node));
    }
    return (node);
}

/*get left most leaf*/
CBTREE_NODE *cbtree_node_get_l_leaf(const CBTREE *cbtree, CBTREE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }
 
    while(! CBTREE_NODE_IS_LEAF(node))
    {
        node = CBTREE_NODE_CHILD(node, 0);
    }
    return (node);
}

/*get right most key*/
CBTREE_KEY *cbtree_node_get_r_key(const CBTREE *cbtree, CBTREE_NODE *node)
{
    if(NULL_PTR == node)
    {
        return (NULL_PTR);
    }
 
    while(! CBTREE_NODE_IS_LEAF(node))
    {
        node = CBTREE_NODE_CHILD(node, CBTREE_NODE_COUNT(node));
    }

    ASSERT(0 < CBTREE_NODE_COUNT(node));
 
    return CBTREE_NODE_KEY(node, CBTREE_NODE_COUNT(node) - 1);
}


void cbtree_node_print(LOG *log, const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, uint8_t i, CBTREE_KEY_PRINTER key_printer)
{
    uint8_t j;

    if (NULL_PTR == cbtree_node)
    {
        //sys_log(log, "error:cbtree_node_print: cbtree_node is null\n");
        sys_print(log, "(null)\n");
        return ;
    }

    if(NULL_PTR == key_printer)
    {
        key_printer = cbtree_key_print;
    }

    for (j = i; j > 0; j--)
    {
        sys_print(log,"    ");
    }
    sys_print(log,"[.");

    for (j = 0; j < CBTREE_NODE_COUNT(cbtree_node); j++)
    {
        sys_print(log," ");
        key_printer(log, cbtree, CBTREE_NODE_KEY(cbtree_node, j));
        sys_print(log," .");
    }

    for (j = CBTREE_ORDER(cbtree) - CBTREE_NODE_COUNT(cbtree_node); j > 1; j--)
    {
        sys_print(log," _____ .");
    }

    sys_print(log,"] - ");
#if 1 
    /*node info*/
    sys_print(log, "node {%lx, %ld, %s} ", cbtree_node, CBTREE_NODE_COUNT(cbtree_node),
                    CBTREE_NODE_IS_LEAF(cbtree_node)?(const char *)"is_leaf":(const char *)"not_leaf");

    /*keys info*/
    sys_print(log, "keys: {");
    for (j = 0; j < CBTREE_NODE_COUNT(cbtree_node); j++)
    {
#if 0 
        sys_print(log, "(%lx: %lx,%lx,%lx), ",
                       CBTREE_NODE_KEY(cbtree_node, j),
                       CBTREE_KEY_KV(CBTREE_NODE_KEY(cbtree_node, j), 0),
                       CBTREE_KEY_KV(CBTREE_NODE_KEY(cbtree_node, j), 1),
                       CBTREE_KEY_KV(CBTREE_NODE_KEY(cbtree_node, j), 2)
                       );
#endif      
#if 0
        sys_print(log, "%lx, ",
                       CBTREE_NODE_KEY(cbtree_node, j)
                       );
#endif
#if 1
        uint8_t ver;
        sys_print(log, "(%lx: ",
                       CBTREE_NODE_KEY(cbtree_node, j)
                       );
        for(ver = 0; ver < CBTREE_MAX_VER(cbtree); ver ++)
        {
            if(ver + 1 < CBTREE_MAX_VER(cbtree))
            {
                if(NULL_PTR == CBTREE_NODE_KEY(cbtree_node, j))
                {
                    sys_print(log, "----,");
                }
                else
                {
                    sys_print(log, "%lx,", CBTREE_KEY_KV(CBTREE_NODE_KEY(cbtree_node, j), ver));
                }
            }
            else
            {
                if(NULL_PTR == CBTREE_NODE_KEY(cbtree_node, j))
                {
                    sys_print(log, "---");
                }
                else
                {
                    sys_print(log, "%lx", CBTREE_KEY_KV(CBTREE_NODE_KEY(cbtree_node, j), ver));
                }
            }
        }
        sys_print(log, "), ");
#endif
    }
    sys_print(log, "}, "); 

    if(/*!CBTREE_NODE_IS_LEAF(cbtree_node)*/1)
    {
        /*children info*/
        sys_print(log, "children: {");
        for (j = 0; j < CBTREE_NODE_COUNT(cbtree_node); j++)
        {
            sys_print(log, "%lx, ", CBTREE_NODE_CHILD(cbtree_node, j));
        } 
        if(!CBTREE_NODE_IS_LEAF(cbtree_node))
        {
            sys_print(log, "%lx, ", CBTREE_NODE_CHILD(cbtree_node, j));
        } 
        sys_print(log, "}, ");
    }
 
    /*next info*/
    if (CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        sys_print(log, "next: {%lx} ", CBTREE_NODE_CHILD(cbtree_node, CBTREE_ORDER(cbtree) - 1));
    }
#endif 
    sys_print(log, "\n");

    return;
}

CBTREE *cbtree_new(const uint8_t order, const uint8_t max_ver, const uint8_t key_type)
{
    CBTREE *cbtree;

    if(order > CBTREE_MAX_ORDER)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_new: overflow! order %ld > max supported order %ld\n", order, CBTREE_MAX_ORDER);
        return (NULL_PTR);
    }

    if(0 == order)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_new: order cannot be zero\n");
        return (NULL_PTR);
    } 

    if(max_ver > CBTREE_MAX_VERSION)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_new: overflow! max version %ld > max supported version %ld\n", max_ver, CBTREE_MAX_VERSION);
        return (NULL_PTR);
    }

    if(0 == max_ver)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_new: max version cannot be zero\n");
        return (NULL_PTR);
    }   

    alloc_static_mem(MM_CBTREE, &cbtree, LOC_CBTREE_0013);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_new: new cbtree failed\n");
        return (NULL_PTR);
    }
 
    if(EC_FALSE == cbtree_init(cbtree, order, max_ver, key_type))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_new: init cbtree failed\n");
        cbtree_free(cbtree);
        return (NULL_PTR);
    }

    //CBTREE_SET_DIRTY(cbtree);/*when cbtree is new, set it dirty*/

    return (cbtree);
}

EC_BOOL cbtree_init(CBTREE *cbtree, const uint8_t order, const uint8_t max_ver, const uint8_t key_type)
{
    CBTREE_SIZE(cbtree)        = (uint32_t)0;
    CBTREE_ORDER(cbtree)       = order;
    CBTREE_MAX_VER(cbtree)     = max_ver;
    CBTREE_MIN_LEAF(cbtree)    = (order / 2);
    CBTREE_MIN_INTR(cbtree)    = ((order + 1) / 2) - 1;
    CBTREE_HEIGHT(cbtree)      = (uint8_t)0;
    CBTREE_DIRTY(cbtree)       = CBTREE_ERR_FLAG;
    CBTREE_ROOT_NODE(cbtree)   = NULL_PTR;
    CBTREE_LEFT_LEAF(cbtree)   = NULL_PTR;
    CBTREE_TLEN(cbtree)        = (uint32_t)0;

    cbtree_key_op_init(CBTREE_KEY_OP(cbtree));

    switch(key_type)
    {
        case CBTREE_IS_GENERAL_STRING_TYPE:
            CBTREE_KEY_DUP_OP(cbtree)         = __cbtree_x_key_dup;
            CBTREE_KEY_FREE_OP(cbtree)        = __cbtree_x_key_free;
            CBTREE_KEY_TLEN_OP(cbtree)        = __cbtree_x_key_tlen;
            CBTREE_KEY_CMP_OP(cbtree)         = __cbtree_x_key_cmp;
            CBTREE_KEY_PRINT_OP(cbtree)       = __cbtree_x_key_print;
            CBTREE_KEY_ENCODE_SIZE_OP(cbtree) = __cbtree_x_key_encode_size;
            CBTREE_KEY_ENCODE_OP(cbtree)      = __cbtree_x_key_encode;
            CBTREE_KEY_DECODE_OP(cbtree)      = __cbtree_x_key_decode;
            break;
        case CBTREE_IS_BGT_ROOT_TABLE_TYPE:
        case CBTREE_IS_BGT_META_TABLE_TYPE:
        case CBTREE_IS_BGT_USER_TABLE_TYPE:     
            CBTREE_KEY_DUP_OP(cbtree)         = keyDup;
            CBTREE_KEY_FREE_OP(cbtree)        = keyFree;
            CBTREE_KEY_TLEN_OP(cbtree)        = keyLen;
            CBTREE_KEY_CMP_OP(cbtree)         = keyCmp;
            CBTREE_KEY_PRINT_OP(cbtree)       = keyPrint;
            CBTREE_KEY_ENCODE_SIZE_OP(cbtree) = keyEncodeSize;
            CBTREE_KEY_ENCODE_OP(cbtree)      = keyEncode;
            CBTREE_KEY_DECODE_OP(cbtree)      = keyDecode;
            break;
        case CBTREE_IS_BGT_COLF_TABLE_TYPE:  
            CBTREE_KEY_DUP_OP(cbtree)         = keyDup;
            CBTREE_KEY_FREE_OP(cbtree)        = keyFree;
            CBTREE_KEY_TLEN_OP(cbtree)        = keyLen;
            CBTREE_KEY_CMP_OP(cbtree)         = keyScopeCmp;/*xxx*/
            CBTREE_KEY_PRINT_OP(cbtree)       = keyPrint;
            CBTREE_KEY_ENCODE_SIZE_OP(cbtree) = keyEncodeSize;
            CBTREE_KEY_ENCODE_OP(cbtree)      = keyEncode;
            CBTREE_KEY_DECODE_OP(cbtree)      = keyDecode;     
            break;
        default:
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_init: not support key type %ld\n", key_type);
        return (EC_FALSE);
    }
 
    CBTREE_KEY_TYPE(cbtree) = key_type;
    return (EC_TRUE);
}

EC_BOOL cbtree_clean(CBTREE *cbtree)
{ 
    cbtree_node_free(cbtree, CBTREE_ROOT_NODE(cbtree));
    CBTREE_ROOT_NODE(cbtree)     = NULL_PTR;
    CBTREE_LEFT_LEAF(cbtree)     = NULL_PTR;
 
    CBTREE_SIZE(cbtree)          = (uint32_t)0;
    CBTREE_ORDER(cbtree)         = (uint8_t )0;
    CBTREE_MAX_VER(cbtree)       = (uint8_t )0;
    CBTREE_MIN_LEAF(cbtree)      = (uint8_t )0;
    CBTREE_MIN_INTR(cbtree)      = (uint8_t )0;
    CBTREE_DIRTY(cbtree)         = CBTREE_ERR_FLAG;
    CBTREE_TLEN(cbtree)          = (uint32_t)0;
                              
    CBTREE_KEY_TYPE(cbtree)      = CBTREE_IS_ERR_TYPE;

    cbtree_key_op_clean(CBTREE_KEY_OP(cbtree));

    return (EC_TRUE);
}

EC_BOOL cbtree_free(CBTREE *cbtree)
{
    if(NULL_PTR != cbtree)
    {
        cbtree_clean(cbtree);
        free_static_mem(MM_CBTREE, cbtree, LOC_CBTREE_0014);
    }
    return (EC_TRUE);
}

void cbtree_print_itself(LOG *log, const CBTREE *cbtree)
{
    sys_log(log, "cbtree_print_itself: tree order: %d, max ver %d, key type %d, tree size: %d, height %d, total key len: %d, %s dirty, root %lx, left leaf %lx\n",
                  CBTREE_ORDER(cbtree), CBTREE_MAX_VER(cbtree), CBTREE_KEY_TYPE(cbtree),
                  CBTREE_SIZE(cbtree), CBTREE_HEIGHT(cbtree), CBTREE_TLEN(cbtree),
                  (CBTREE_IS_DIRTY(cbtree)? (const char *)"is" : (const char *)"not"),
                  CBTREE_ROOT_NODE(cbtree), CBTREE_LEFT_LEAF(cbtree));
    return;
}

void cbtree_print(LOG *log, const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, uint8_t i, CBTREE_KEY_PRINTER key_printer)
{
    uint8_t j;

    if (NULL_PTR == cbtree)
    {
        sys_log(log, "error:cbtree_print: cbtree is null\n");
        return ;
    } 

    if(0 == i)
    {
        cbtree_print_itself(log, cbtree);
    } 

    if (NULL_PTR == cbtree_node)
    {
        sys_log(log, "error:cbtree_print: cbtree_node is null\n");
        return ;
    }

    if(NULL_PTR == key_printer)
    {
        key_printer = cbtree_key_print;
    }

    cbtree_node_print(log, cbtree, cbtree_node, i, key_printer);

    if (CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        return;
    }

    for (j = 0; j <= CBTREE_NODE_COUNT(cbtree_node); j++)
    {
        cbtree_print(log, cbtree, CBTREE_NODE_CHILD(cbtree_node, j), i + 1, key_printer);
    }

    return;
}

void cbtree_runthrough(LOG *log, const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, CBTREE_KEY_PRINTER key_printer)
{
    uint8_t j;

    if(NULL_PTR == cbtree_node)
    {
        sys_print(log, "\n");
        return;
    }

    if(! CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        sys_log(log, "error:cbtree_runthrough: NOT leaf!\n");
        return;
    }

    if(NULL_PTR == key_printer)
    {
        key_printer = cbtree_key_print;
    }

    for (j = 0; j < CBTREE_NODE_COUNT(cbtree_node); j++)
    {
        key_printer(log, cbtree, CBTREE_NODE_KEY(cbtree_node, j));
    }

    cbtree_runthrough(log, cbtree, CBTREE_NODE_CHILD(cbtree_node, CBTREE_ORDER(cbtree) - 1), key_printer);
    return;
}

EC_BOOL cbtree_checker(const CBTREE *cbtree, CBTREE_KEY_PRINTER key_printer, CBTREE_KEY **min_key, UINT32 *total_key_num)
{
    CBTREE_NODE *leaf_node;
    UINT32      leaf_idx;

    if(NULL_PTR == key_printer)
    {
        key_printer = cbtree_key_print;
    }  

    for(leaf_node = CBTREE_LEFT_LEAF(cbtree), leaf_idx = 0; NULL_PTR != leaf_node; leaf_node = CBTREE_NODE_CHILD(leaf_node, CBTREE_ORDER(cbtree) - 1), leaf_idx ++)
    {
        uint8_t j;
     
        if(! CBTREE_NODE_IS_LEAF(leaf_node))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_checker: NOT leaf!\n");
            return (EC_FALSE);
        } 

        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "leaf_idx: %ld, leaf_node %lx\n", leaf_idx, leaf_node);

        for (j = 0; j < CBTREE_NODE_COUNT(leaf_node); j++)
        {
            (*total_key_num) ++;
            if(0 < cbtree_key_cmp(cbtree, *min_key, CBTREE_NODE_KEY(leaf_node, j)))
            {
                sys_print(LOGSTDOUT, "cbtree_checker: FAILED ===> ");
                key_printer(LOGSTDOUT, cbtree, CBTREE_NODE_KEY(leaf_node, j));
                sys_print(LOGSTDOUT, "\n");
                return (EC_FALSE);
            }
            sys_print(LOGSTDOUT, ". ");
            (*min_key) = CBTREE_NODE_KEY(leaf_node, j);
        }     
    }

    sys_print(LOGSTDOUT, "\n");
    return (EC_TRUE);
}

EC_BOOL cbtree_check_in_depth(const CBTREE *cbtree, const CBTREE_NODE *cbtree_node, CBTREE_KEY_PRINTER key_printer)
{
    if(NULL_PTR == cbtree_node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_check_in_depth: cbtree_node is null\n");
        cbtree_print(LOGSTDOUT, cbtree, CBTREE_ROOT_NODE(cbtree), 0, key_printer);
        return (EC_FALSE);
    }
 
    if(CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        uint8_t i;
        CBTREE_KEY *key_1;

        key_1 = CBTREE_NODE_KEY(cbtree_node, 0);
        for(i = 1; i < CBTREE_NODE_COUNT(cbtree_node); i ++)
        {
            CBTREE_KEY *key_2;

            key_2 = CBTREE_NODE_KEY(cbtree_node, i);
            /*assert key_1 < key_2*/
            if(0 <= cbtree_key_cmp(cbtree, key_1, key_2))
            {
                sys_print(LOGSTDOUT, "cbtree_check_in_depth: [0] FAILED ===> ");
                cbtree_node_print(LOGSTDOUT, cbtree, cbtree_node, 0, key_printer);
                return (EC_FALSE);
            }
            key_1 = key_2;
        }
     
    }
    else
    {
        uint8_t j;
        CBTREE_KEY *key_of_cur;
        CBTREE_KEY *key_of_child;
     
        if(NULL_PTR == key_printer)
        {
            key_printer = cbtree_key_print;
        }
     
        /*check keys are in order*/
        key_of_cur = NULL_PTR;
        for(j = 0; j < CBTREE_NODE_COUNT(cbtree_node); j ++)
        {
            if(EC_FALSE == cbtree_check_in_depth(cbtree, CBTREE_NODE_CHILD(cbtree_node, j), key_printer))
            {
                cbtree_node_print(LOGSTDOUT, cbtree, cbtree_node, 0, key_printer);
                sys_print(LOGSTDOUT, "cbtree_check_in_depth: [1] FAILED\n");
                return (EC_FALSE);
            }
            key_of_child = cbtree_node_get_r_key(cbtree, CBTREE_NODE_CHILD(cbtree_node, j));

            /*assert key_of_cur < key_of_child*/
            if(NULL_PTR != key_of_cur &&  (0 <= cbtree_key_cmp(cbtree, key_of_cur, key_of_child)))
            {
                sys_print(LOGSTDOUT, "cbtree_check_in_depth: [2] FAILED ===> ");
                cbtree_node_print(LOGSTDOUT, cbtree, cbtree_node, 0, key_printer);
                key_printer(LOGSTDOUT, cbtree, key_of_cur);
                sys_print(LOGSTDOUT, "\n");             
                return (EC_FALSE);         
            }

            /*assert key_of_cur >= key_of_child*/
            key_of_cur = CBTREE_NODE_KEY(cbtree_node, j);
            if(0 > cbtree_key_cmp(cbtree, key_of_cur, key_of_child))
            {
                sys_print(LOGSTDOUT, "cbtree_check_in_depth: [3] FAILED ===> ");
                cbtree_node_print(LOGSTDOUT, cbtree, cbtree_node, 0, key_printer);
                key_printer(LOGSTDOUT, cbtree, key_of_cur);
                sys_print(LOGSTDOUT, "\n");             
                return (EC_FALSE);         
            }         
        } 

        if(EC_FALSE == cbtree_check_in_depth(cbtree, CBTREE_NODE_CHILD(cbtree_node, j), key_printer))
        {
            cbtree_node_print(LOGSTDOUT, cbtree, cbtree_node, 0, key_printer);
            sys_print(LOGSTDOUT, "cbtree_check_in_depth: [4] FAILED\n");
            return (EC_FALSE);
        }
        key_of_child = cbtree_node_get_r_key(cbtree, CBTREE_NODE_CHILD(cbtree_node, j));

        /*assert key_of_cur < key_of_child*/
        if(NULL_PTR != key_of_cur &&  (0 <= cbtree_key_cmp(cbtree, key_of_cur, key_of_child)))
        {
            sys_print(LOGSTDOUT, "cbtree_check_in_depth: [5] FAILED ===> ");
            cbtree_node_print(LOGSTDOUT, cbtree, cbtree_node, 0, key_printer);
            key_printer(LOGSTDOUT, cbtree, key_of_cur);
            sys_print(LOGSTDOUT, "\n");             
            return (EC_FALSE);         
        }     
    }
 
    return (EC_TRUE);
}

EC_BOOL cbtree_is_empty(const CBTREE *cbtree)
{
    if(NULL_PTR == cbtree || 0 == CBTREE_SIZE(cbtree))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

static EC_BOOL __cbtree_add_key(CBTREE *cbtree, CBTREE_NODE *root_node,
                                        CBTREE_KEY **insert_key, CBTREE_NODE **insert_node,
                                        uint8_t *split)
{
    uint8_t i;
    int result;
#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] #### __cbtree_add_key enter\n");

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_add_key: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGSTDNULL, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGSTDNULL, cbtree, (*insert_node), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_add_key: when enter: end: ===================================================================================================\n");
#endif

    result = -3;/*invalid*/
 
    *split = 0;
#if 0
    for (i = 0;
         i < CBTREE_NODE_COUNT(root_node) && 0 > (result = cbtree_key_cmp(cbtree, CBTREE_NODE_KEY(root_node, i), *insert_key));
         i++)
    {
        /*do nothing*/
    }
#else
    CBTREE_SEARCH_KEY(cbtree, root_node, CBTREE_NODE_COUNT(root_node), (*insert_key), i, result);
#endif
    if (i < CBTREE_NODE_COUNT(root_node) && 0 == result)
    {
        if (CBTREE_NODE_IS_LEAF(root_node))
        {
            CBTREE_NODE_CHILD(root_node, i) = (*insert_node);
            cbtree_key_update(cbtree, CBTREE_NODE_KEY(root_node, i), (*insert_key));
        }     
     
        return (EC_TRUE);
    } 

    //CBTREE_NODE_COUNT(root_node) ++;

    /*insert to middle, position is i*/
    if (i < CBTREE_NODE_COUNT(root_node))
    {
        uint32_t     j;
        CBTREE_KEY  *tmp_key_1;
        CBTREE_NODE *tmp_node_1;

        CBTREE_NODE_COUNT(root_node) ++;

        /*put in the insert_key*/
        /*TODO: put all key versions to tmp*/
        tmp_key_1 = CBTREE_NODE_KEY(root_node, i);
        CBTREE_NODE_KEY(root_node, i) = (*insert_key);
        (*insert_key) = NULL_PTR;
     
        j = i;
     
        for (i++; i < CBTREE_NODE_COUNT(root_node); i++)
        {
            XCHG(CBTREE_KEY *, CBTREE_NODE_KEY(root_node, i), tmp_key_1);
        }

        if (! CBTREE_NODE_IS_LEAF(root_node))
        {
            j++;

            //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] [0] j = %ld, root node is %s\n", j, CBTREE_NODE_LEAF_STR(root_node));

            /*put in the insert_node*/
            tmp_node_1 = CBTREE_NODE_CHILD(root_node, j);
            CBTREE_NODE_CHILD(root_node, j) = (*insert_node);

            for (j++; j <= CBTREE_NODE_COUNT(root_node); j++)
            {
                XCHG(CBTREE_NODE *, CBTREE_NODE_CHILD(root_node, j), tmp_node_1);
            }

            //sys_print(LOGSTDNULL, "\n\n");
            ASSERT(NULL_PTR != CBTREE_NODE_CHILD(root_node, 0));
        }     
    }
    /*insert to tail*/
    else
    {
        ASSERT(i == CBTREE_NODE_COUNT(root_node));
        CBTREE_NODE_COUNT(root_node) ++;
     
        CBTREE_NODE_KEY(root_node, i) = (*insert_key);
        (*insert_key) = NULL_PTR;

        if (CBTREE_NODE_IS_LEAF(root_node))
        {
            //CBTREE_NODE_CHILD(root_node, i + 1) = CBTREE_NODE_CHILD(root_node, i);
            //CBTREE_NODE_CHILD(root_node, i) = (*insert_node);
        }
        else
        {
            CBTREE_NODE_CHILD(root_node, i + 1) = (*insert_node);
            ASSERT(NULL_PTR != CBTREE_NODE_CHILD(root_node, 0));
        }
    }

#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_add_key: when leav: beg: ===================================================================================================\n");
    cbtree_print(LOGSTDNULL, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGSTDNULL, cbtree, (*insert_node), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_add_key: when leav: end: ===================================================================================================\n");

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] #### __cbtree_add_key leav\n");
    sys_print(LOGSTDNULL, "\n\n");
#endif 
    return (EC_TRUE);
}

static EC_BOOL __cbtree_split_node(CBTREE *cbtree, CBTREE_NODE *root_node,
                                        CBTREE_KEY **insert_key, CBTREE_NODE **insert_node,
                                        uint8_t *split)
{
    uint8_t i;
    uint8_t j;
    uint8_t div;

    CBTREE_KEY  *tmp_key_1;

    CBTREE_NODE *tmp_node_1;
    CBTREE_NODE *new_node;

    int result;

#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] #### __cbtree_split_node enter\n");

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_split_node: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGSTDNULL, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGSTDNULL, cbtree, (*insert_node), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_split_node: when enter: end: ===================================================================================================\n");
#endif

    /*root_node is full when reach here*/
 
    result = -3; 
    *split = 0;
#if 0 
    for (i = 0;
         i < (CBTREE_ORDER(cbtree) - 1) && 0 < (result = cbtree_key_cmp(cbtree, *insert_key, CBTREE_NODE_KEY(root_node, i)));
         i++)
    {
        /*do nothing*/
    }
#else
    CBTREE_SEARCH_KEY(cbtree, root_node, (CBTREE_ORDER(cbtree) - 1), (*insert_key), i, result);
#endif
    if (i < (CBTREE_ORDER(cbtree) - 1) && 0 == result)
    {
        if (CBTREE_NODE_IS_LEAF(root_node))
        {
            CBTREE_NODE_CHILD(root_node, i) = (*insert_node);
            cbtree_key_update(cbtree, CBTREE_NODE_KEY(root_node, i), (*insert_key));
        }
        return (EC_TRUE);
    }

    *split = 1;

    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [0] root_node:");
    //cbtree_node_print(LOGSTDNULL, cbtree, root_node, 0, NULL_PTR); 

    if (i < (CBTREE_ORDER(cbtree) - 1))
    {
        tmp_key_1 = CBTREE_NODE_KEY(root_node, i);
        CBTREE_NODE_KEY(root_node, i) = (*insert_key);
        (*insert_key) = NULL_PTR;
     
        j = i;

        for (i++; i < (CBTREE_ORDER(cbtree) - 1); i++)
        {
            XCHG(CBTREE_KEY *, CBTREE_NODE_KEY(root_node, i), tmp_key_1);
        }
#if 0/*it is okay! this is a high cost lesson: even the most tiny change without completely testing, developer will drop in big trouble!*/
        if (! CBTREE_NODE_IS_LEAF(root_node))
        {
            j++;
        }
     
        tmp_node_1 = CBTREE_NODE_CHILD(root_node, j);
        CBTREE_NODE_CHILD(root_node, j) = (*insert_node);

        for (j++; j <= (CBTREE_ORDER(cbtree) - 1); j++)
        {
            XCHG(CBTREE_NODE *, CBTREE_NODE_CHILD(root_node, j), tmp_node_1);
        }
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [1] tmp:");
        //cbtree_node_print(LOGSTDNULL, cbtree, tmp_node_1, 0, NULL_PTR);
        //ASSERT(NULL_PTR != CBTREE_NODE_CHILD(root_node, 0));
#endif   
#if 1
        if (! CBTREE_NODE_IS_LEAF(root_node))
        {
            j++;

            tmp_node_1 = CBTREE_NODE_CHILD(root_node, j);
            CBTREE_NODE_CHILD(root_node, j) = (*insert_node);

            for (j++; j <= (CBTREE_ORDER(cbtree) - 1); j++)
            {
                XCHG(CBTREE_NODE *, CBTREE_NODE_CHILD(root_node, j), tmp_node_1);
            }
            //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [1] tmp:");
            //cbtree_node_print(LOGSTDNULL, cbtree, tmp_node_1, 0, NULL_PTR);
            ASSERT(NULL_PTR != CBTREE_NODE_CHILD(root_node, 0));         
        }
        else
        {
            tmp_node_1 = CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1);
            //tmp_node_1 = CBTREE_NODE_CHILD(root_node, j);
            //CBTREE_NODE_CHILD(root_node, j) = (*insert_node);     
        }
#endif     

    }

    /*i >= (CBTREE_ORDER(cbtree) - 1)*/
    else
    {
        tmp_key_1 = (*insert_key);
        (*insert_key) = NULL_PTR;

        if (CBTREE_NODE_IS_LEAF(root_node))
        {
            tmp_node_1 = CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1);
            CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1) = (*insert_node);
        }
        else
        {
            tmp_node_1 = (*insert_node);
            ASSERT(NULL_PTR != CBTREE_NODE_CHILD(root_node, 0));
        }
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [2] tmp:");
        //cbtree_node_print(LOGSTDNULL, cbtree, tmp_node_1, 0, NULL_PTR);     
    }

    //dbg_log(SEC_0050_CBTREE, 5)(LOGSTDNULL, "beg: ===================================================================================================\n");
    //cbtree_print(LOGSTDNULL, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    //dbg_log(SEC_0050_CBTREE, 5)(LOGSTDNULL, "end: ===================================================================================================\n");

    /*split*/
    if (CBTREE_NODE_IS_LEAF(root_node))
    {
        div = (uint32_t)CBTREE_MIN_INTR(cbtree);
    }
    else
    {
        div = (uint32_t)CBTREE_MIN_LEAF(cbtree);
    }

    (*insert_key) = CBTREE_NODE_KEY(root_node, div);

    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [3] root_node:");
    //cbtree_node_print(LOGSTDNULL, cbtree, root_node, 0, NULL_PTR);

    /*make new insert_node*/
    new_node = cbtree_node_new(cbtree);
    if(NULL_PTR == new_node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_split_node: new cbtree node failed\n");
        return (EC_FALSE);
    }
    CBTREE_NODE_COUNT(new_node) = CBTREE_ORDER(cbtree) - 1 - div;
    if (CBTREE_NODE_IS_LEAF(root_node))
    {
        CBTREE_NODE_SET_LEAF(new_node);
    }

    i = div + 1;/*2*/

    for (j = 0; j < CBTREE_NODE_COUNT(new_node) - 1; j++, i++)
    {
        CBTREE_NODE_KEY(new_node, j)   = CBTREE_NODE_KEY(root_node, i);
        CBTREE_NODE_CHILD(new_node, j) = CBTREE_NODE_CHILD(root_node, i);
     
        CBTREE_NODE_KEY(root_node, i)   = NULL_PTR;
        CBTREE_NODE_CHILD(root_node, i) = NULL_PTR;
    }
#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [4] root_node:");
    cbtree_node_print(LOGSTDNULL, cbtree, root_node, 0, NULL_PTR);
 
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [5] new_node:");
    cbtree_node_print(LOGSTDNULL, cbtree, new_node, 0, NULL_PTR);

    dbg_log(SEC_0050_CBTREE, 5)(LOGSTDNULL, "i = %ld, j = %ld, div = %ld\n", i,j, div);
#endif     
    /*i = 2, j = 0, div = 1*/
    CBTREE_NODE_KEY(new_node, j)    = tmp_key_1;
    CBTREE_NODE_CHILD(new_node, j)  = CBTREE_NODE_CHILD(root_node, i); 
    CBTREE_NODE_CHILD(root_node, i) = NULL_PTR;

    if(CBTREE_NODE_IS_LEAF(root_node))
    {
        CBTREE_NODE_CHILD(new_node, CBTREE_ORDER(cbtree) - 1) = tmp_node_1;
    }
    else
    {
        CBTREE_NODE_CHILD(new_node, j + 1) = tmp_node_1;
        ASSERT(NULL_PTR != CBTREE_NODE_CHILD(new_node, 0));
    }   
#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [6] root_node:");
    cbtree_node_print(LOGSTDNULL, cbtree, root_node, 0, NULL_PTR);
 
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [7] new_node:");
    cbtree_node_print(LOGSTDNULL, cbtree, new_node, 0, NULL_PTR);
#endif
    (*insert_node) = new_node;
 
    if (CBTREE_NODE_IS_LEAF(root_node))
    {
        CBTREE_NODE_COUNT(root_node) = div + 1;
        CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1) = (*insert_node);
    }
    else
    {
        CBTREE_NODE_COUNT(root_node) = div;
        CBTREE_NODE_KEY(root_node, div) = NULL_PTR;
        ASSERT(NULL_PTR != CBTREE_NODE_CHILD(root_node, 0));
    }

#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [8] root_node:");
    cbtree_node_print(LOGSTDNULL, cbtree, root_node, 0, NULL_PTR);
 
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG]xxxxx [9] new_node:");
    cbtree_node_print(LOGSTDNULL, cbtree, new_node, 0, NULL_PTR); 

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_split_node: when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGSTDNULL, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGSTDNULL, cbtree, (*insert_node), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_split_node: when leave: end: ===================================================================================================\n");

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] #### __cbtree_split_node leave\n");
    sys_print(LOGSTDNULL, "\n\n");
#endif 
    return (EC_TRUE);
}

static EC_BOOL __cbtree_insert_key(CBTREE *cbtree, CBTREE_NODE * root_node, CBTREE_KEY **key,
                                    CBTREE_NODE **insert_node, uint8_t *split)
{
    EC_BOOL success;
#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] #### __cbtree_insert_key enter\n");
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_insert_key: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGSTDNULL, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGSTDNULL, cbtree, (*insert_node), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_insert_key: when enter: end: ===================================================================================================\n");
#endif

    success = EC_FALSE;

    if (CBTREE_NODE_IS_LEAF(root_node))
    {
        if (CBTREE_NODE_COUNT(root_node) < (CBTREE_ORDER(cbtree) - 1))
        {
            success = __cbtree_add_key(cbtree, root_node, key, insert_node, split);
        }
        else
        {
            success = __cbtree_split_node(cbtree, root_node, key, insert_node, split);
        }

        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] #### __cbtree_insert_key leave\n");

        return (success);
    }
    else
    {
        /* Internal node. */
        uint8_t i;
        int     result;
#if 0
#if 0/*original*/
        for (i = 0;
             i < CBTREE_NODE_COUNT(root_node) && 0 < (result = cbtree_key_cmp(cbtree, *key, CBTREE_NODE_KEY(root_node, i)));
             i++)
        {
            /*do nothing*/
        }
#endif    
#if 1/*original*/
        for (i = 0;
             i < CBTREE_NODE_COUNT(root_node) && 0 > (result = cbtree_key_cmp(cbtree, CBTREE_NODE_KEY(root_node, i), *key));
             i++)
        {
            /*do nothing*/
        }
#endif
#else
    CBTREE_SEARCH_KEY(cbtree, root_node, CBTREE_NODE_COUNT(root_node), (*key), i, result);
#endif

        success = __cbtree_insert_key(cbtree, CBTREE_NODE_CHILD(root_node, i), key, insert_node, split);
    }

    if (EC_TRUE == success && 1 == (*split))
    {
        if (CBTREE_NODE_COUNT(root_node) < (CBTREE_ORDER(cbtree) - 1))
        {
            __cbtree_add_key(cbtree, root_node, key, insert_node, split);
        }
        else
        {
            __cbtree_split_node(cbtree, root_node, key, insert_node, split);
        }
    }
#if 0 
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_insert_key: when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGSTDNULL, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGSTDNULL, cbtree, (*insert_node), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_insert_key: when leave: end: ===================================================================================================\n");
 
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] #### __cbtree_insert_key leave\n");
    sys_print(LOGSTDNULL, "\n\n");
#endif 
    return (success);
}

/*note: when return dup_key cannot be reused, ret_key can be free*/
static EC_BOOL __cbtree_insert_do(CBTREE *cbtree, CBTREE_KEY **insert_key)
{
    EC_BOOL  success;
    uint8_t  split;
    uint32_t tlen;

    CBTREE_NODE *insert_node; 

    tlen = cbtree_key_tlen(cbtree, (*insert_key));

    if(NULL_PTR == CBTREE_ROOT_NODE(cbtree))
    {
        insert_node = cbtree_node_new(cbtree);
        if(NULL_PTR == insert_node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_insert_do: new cbtree node failed\n");
            return (EC_FALSE);
        }
     
        CBTREE_NODE_COUNT(insert_node)  = 1;
        CBTREE_NODE_SET_LEAF(insert_node);

        CBTREE_NODE_KEY(insert_node, 0) = (*insert_key);
        (*insert_key) = NULL_PTR;
    
        CBTREE_ROOT_NODE(cbtree) = insert_node;
        CBTREE_LEFT_LEAF(cbtree) = insert_node;
        CBTREE_SIZE(cbtree) ++;
        CBTREE_HEIGHT(cbtree) ++;
        CBTREE_TLEN(cbtree) += tlen;
        CBTREE_SET_DIRTY(cbtree);
     
        return (EC_TRUE);
    }

    success = EC_FALSE;
    split = 0;

    insert_node = NULL_PTR;
 
    success = __cbtree_insert_key(cbtree, CBTREE_ROOT_NODE(cbtree), insert_key, &insert_node, &split);
    if (EC_FALSE == success)
    {
        return (EC_FALSE);
    }

    if (1 == split)
    {
        CBTREE_NODE *new_node;

        new_node = cbtree_node_new(cbtree);
        if(NULL_PTR == new_node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_insert_do: new cbtree_node failed\n");
            return (EC_FALSE);
        }

        CBTREE_NODE_KEY(new_node, 0) = (*insert_key);
        (*insert_key) = NULL_PTR;
     
        CBTREE_NODE_COUNT(new_node) = 1;

        if (NULL_PTR == CBTREE_ROOT_NODE(cbtree))
        {
            ASSERT(NULL_PTR == insert_node);
            CBTREE_NODE_CHILD(new_node, 0) = insert_node;
            CBTREE_NODE_SET_LEAF(new_node);

            CBTREE_ROOT_NODE(cbtree) = new_node;
            CBTREE_LEFT_LEAF(cbtree) = new_node;
            CBTREE_HEIGHT(cbtree) ++;
        }
        else
        {
            CBTREE_NODE_CHILD(new_node, 0) = CBTREE_ROOT_NODE(cbtree);
            CBTREE_NODE_CHILD(new_node, 1) = insert_node;

            CBTREE_ROOT_NODE(cbtree) = new_node;
            CBTREE_HEIGHT(cbtree) ++;
        }

    }

    /*a new leaf node was created in the tree*/
    if(NULL_PTR == (*insert_key))
    {
        CBTREE_SIZE(cbtree) ++;
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_insert: [1] cbtree tlen %d => \n", CBTREE_TLEN(cbtree));
        CBTREE_TLEN(cbtree) += tlen;
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_insert: [1] cbtree tlen %d <= \n", CBTREE_TLEN(cbtree));
        //CBTREE_TLEN(cbtree) -= cbtree_key_tlen(cbtree, insert_key);
        CBTREE_SET_DIRTY(cbtree);
    }
    /*updated a new leaf node only*/
    else
    {
        //CBTREE_SIZE(cbtree) ++;
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_insert: [2] cbtree tlen %d => \n", CBTREE_TLEN(cbtree));
        CBTREE_TLEN(cbtree) += tlen;
        CBTREE_TLEN(cbtree) -= cbtree_key_tlen(cbtree, (*insert_key));
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_insert: [2] cbtree tlen %d <= \n", CBTREE_TLEN(cbtree));
        CBTREE_SET_DIRTY(cbtree); 
    }

    ASSERT(NULL_PTR != CBTREE_LEFT_LEAF(cbtree)); 
    return (EC_TRUE);
}

void __cbtree_node_checker(CBTREE *cbtree, CBTREE_NODE *cbtree_node)
{
    uint8_t i;

    for(i = 0; i < CBTREE_NODE_COUNT(cbtree_node); i ++)
    {
        ASSERT(NULL_PTR != CBTREE_NODE_KEY(cbtree_node, i));
    }

    if(!CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        for(i = 0; i <= CBTREE_NODE_COUNT(cbtree_node); i ++)
        {
            ASSERT(NULL_PTR != CBTREE_NODE_CHILD(cbtree_node, i));
        }
    }
    return;
}

EC_BOOL cbtree_insert(CBTREE *cbtree, const uint8_t *key)
{
    CBTREE_KEY *insert_key;

    insert_key = cbtree_key_make(cbtree, key);
    if(NULL_PTR == insert_key)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_insert: make cbtree key by key %lx failed\n", key);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbtree_insert_do(cbtree, &insert_key))
    {
        cbtree_key_free(cbtree, insert_key);
        return (EC_FALSE);
    }

    cbtree_key_free(cbtree, insert_key);

    /*patch, reason unknown yet!*/
    if(NULL_PTR == CBTREE_LEFT_LEAF(cbtree))
    {
        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_insert: left leaf of tree %lx is null\n", cbtree);
        CBTREE_LEFT_LEAF(cbtree) = cbtree_node_get_l_leaf(cbtree, CBTREE_ROOT_NODE(cbtree));
    }

    //__cbtree_leaf_checker(cbtree, LOGSTDOUT);

    //__cbtree_node_checker(cbtree, CBTREE_ROOT_NODE(cbtree));
    return (EC_TRUE);
}

/*remove key from leaf node*/
static EC_BOOL __cbtree_rmv_key(CBTREE *cbtree, CBTREE_NODE *root_node, const CBTREE_KEY *key, CBTREE_KEY **del_key)
{
    uint8_t i;
    int result;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key: root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key: when enter: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

    ASSERT(CBTREE_NODE_IS_LEAF(root_node));

    result = -3;/*invalid*/
#if 0
    for (i = 0;
         i < CBTREE_NODE_COUNT(root_node) && 0 > (result = cbtree_key_cmp(cbtree, CBTREE_NODE_KEY(root_node, i), key));
         i++)
    {
        /*do nothing*/
    }
#else
    CBTREE_SEARCH_KEY(cbtree, root_node, CBTREE_NODE_COUNT(root_node), key, i, result);
#endif
    if (CBTREE_NODE_IS_LEAF(root_node) && i < CBTREE_NODE_COUNT(root_node) && 0 == result)
    {
        (*del_key) = CBTREE_NODE_KEY(root_node, i);

        //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key: root %lx key %d # saved to del_key as %lx\n", root_node, i, *del_key);
        //ASSERT(NULL_PTR == (*rmv_node));/*must be null*/
        //cbtree_key_free(CBTREE_NODE_KEY(root_node, i));

        for (; i < CBTREE_NODE_COUNT(root_node) - 1; i++)
        {
            CBTREE_NODE_KEY(root_node, i)   = CBTREE_NODE_KEY(root_node, i + 1);
            /*children of leaf node are all null*/
            //CBTREE_NODE_CHILD(root_node, i) = CBTREE_NODE_CHILD(root_node, i + 1);
        }

        CBTREE_NODE_KEY(root_node, i)       = NULL_PTR;
        //CBTREE_NODE_CHILD(root_node, i)     = CBTREE_NODE_CHILD(root_node, i + 1);
        //CBTREE_NODE_CHILD(root_node, i + 1) = NULL_PTR;

        CBTREE_NODE_COUNT(root_node)--;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key: when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key: root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key: when leave: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

static void __cbtree_rmv_key2(CBTREE *cbtree, CBTREE_NODE *root_node, uint8_t index)
{
    uint8_t i;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key2: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key2: root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key2: index: %d\n", index);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key2: when enter: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_rmv_key2: CBTREE_NODE_KEY(root_node:%lx, index:%ld) = %lx to free\n", root_node, index, CBTREE_NODE_KEY(root_node, index));
    //cbtree_key_free(CBTREE_NODE_KEY(root_node, index));
    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_rmv_key2: CBTREE_NODE_KEY(root_node:%lx, index:%ld) = %lx free done\n", root_node, index, CBTREE_NODE_KEY(root_node, index));
    for (i = index; i < CBTREE_NODE_COUNT(root_node) - 1; i++)
    {
        CBTREE_NODE_KEY(root_node, i)   = CBTREE_NODE_KEY(root_node, i + 1);
        CBTREE_NODE_CHILD(root_node, i) = CBTREE_NODE_CHILD(root_node, i + 1);
    }

    CBTREE_NODE_KEY(root_node, i)       = NULL_PTR;

    if(! (CBTREE_NODE_IS_LEAF(root_node) && i + 1 == CBTREE_ORDER(cbtree) - 1))/*debug: not move next leaf node pointer*/
    {
        CBTREE_NODE_CHILD(root_node, i)     = CBTREE_NODE_CHILD(root_node, i + 1);
        CBTREE_NODE_CHILD(root_node, i + 1) = NULL_PTR;
    }

    CBTREE_NODE_COUNT(root_node) --;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key2: when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_rmv_key2: when leave: end: ===================================================================================================\n");
__CBTREE_DEBUG_END
    return;
}

/*borrow one child and its left most key from prev node children to root node*/
static EC_BOOL __cbtree_borrow_right(CBTREE *cbtree, CBTREE_NODE *root_node, CBTREE_NODE *prev_node, uint8_t div, CBTREE_KEY *del_key)
{
    CBTREE_NODE *node;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: prev: ");
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: div %ld, prev_node count %ld\n", div, CBTREE_NODE_COUNT(prev_node));
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: when enter: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

    if (div >= CBTREE_NODE_COUNT(prev_node))/*now no right node of root_node*/
    {
__CBTREE_DEBUG_BEG 
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: root has no right neighbor\n");
__CBTREE_DEBUG_END     
        return (EC_FALSE);
    }

    /*note: root_node is the div-th child, and node is the div+1-th child of prev_node*/
    node = CBTREE_NODE_CHILD(prev_node, div + 1);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_borrow_right: child %d of previous node %lx is null\n", div + 1, prev_node);
        return (EC_FALSE);
    }

    if (CBTREE_NODE_IS_LEAF(node) && CBTREE_NODE_COUNT(node) > CBTREE_MIN_LEAF(cbtree))
    {
        /*node is leaf and has child to lend*/
        ASSERT(CBTREE_NODE_IS_LEAF(root_node));
        if(!CBTREE_NODE_IS_LEAF(root_node))
        {
            CBTREE_NODE_CHILD(root_node, CBTREE_NODE_COUNT(root_node) + 1) = CBTREE_NODE_CHILD(root_node, CBTREE_NODE_COUNT(root_node));
            //CBTREE_NODE_CHILD(root_node, CBTREE_NODE_COUNT(root_node))     = CBTREE_NODE_CHILD(node, 0);
            //CBTREE_NODE_CHILD(node, 0) = NULL_PTR;
            ASSERT(NULL_PTR == CBTREE_NODE_CHILD(node, 0));
            CBTREE_NODE_CHILD(root_node, CBTREE_NODE_COUNT(root_node)) = NULL_PTR;
        }
     
        CBTREE_NODE_KEY(root_node, CBTREE_NODE_COUNT(root_node)) = CBTREE_NODE_KEY(node, 0);
        CBTREE_NODE_KEY(prev_node, div) = CBTREE_NODE_KEY(root_node, CBTREE_NODE_COUNT(root_node));
        CBTREE_NODE_KEY(node, 0) = NULL_PTR;     

        //cbtree_key_free(CBTREE_NODE_KEY(prev_node, div));     
    }
    else if (!CBTREE_NODE_IS_LEAF(node) && CBTREE_NODE_COUNT(node) > CBTREE_MIN_INTR(cbtree))
    {
        if(del_key == CBTREE_NODE_KEY(prev_node, div))
        {
            CBTREE_NODE_KEY(root_node, CBTREE_NODE_COUNT(root_node)) =
                    cbtree_node_get_r_key(cbtree, CBTREE_NODE_CHILD(root_node, CBTREE_NODE_COUNT(root_node)));
            //CBTREE_NODE_KEY(prev_node, div) = NULL_PTR;
        }
        else
        {
            CBTREE_NODE_KEY(root_node, CBTREE_NODE_COUNT(root_node)) = CBTREE_NODE_KEY(prev_node, div);
            //CBTREE_NODE_KEY(prev_node, div) = CBTREE_NODE_KEY(node, 0);/*xxx*/
            //CBTREE_NODE_KEY(prev_node, div) = NULL_PTR;
        }

        //cbtree_key_free(CBTREE_NODE_KEY(prev_node, div));

        CBTREE_NODE_KEY(prev_node, div) = CBTREE_NODE_KEY(node, 0);
        CBTREE_NODE_CHILD(root_node, CBTREE_NODE_COUNT(root_node) + 1) = CBTREE_NODE_CHILD(node, 0);

        CBTREE_NODE_KEY(node, 0)   = NULL_PTR;
        CBTREE_NODE_CHILD(node, 0) = NULL_PTR;     
    }
    else
    {
__CBTREE_DEBUG_BEG 
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: borrowed nothing\n");
__CBTREE_DEBUG_END     
        return (EC_FALSE);
    }

    CBTREE_NODE_COUNT(root_node) ++;
    __cbtree_rmv_key2(cbtree, node, 0);

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR); 
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_right: when leave: end: ===================================================================================================\n");
__CBTREE_DEBUG_END
    return (EC_TRUE);
}

static EC_BOOL __cbtree_borrow_left(CBTREE *cbtree, CBTREE_NODE *root_node, CBTREE_NODE *prev_node, uint8_t div)
{
    uint8_t i;
    CBTREE_NODE *node;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: prev: ");
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: div %ld, prev_node count %ld\n", div, CBTREE_NODE_COUNT(prev_node));
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: when enter: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

    if (0 == div)/*now no left node of root_node*/
    {
__CBTREE_DEBUG_BEG 
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: root has no left neighbor\n");
__CBTREE_DEBUG_END     
        return (EC_FALSE);
    }
    node = CBTREE_NODE_CHILD(prev_node, div - 1);
    if(NULL_PTR == node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_borrow_left: node of child %d of previous node %lx is null\n", div - 1, prev_node);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: root_node %lx lend to prev_node %lx child %d: node %lx\n", root_node, prev_node, div - 1, node);

    if (CBTREE_NODE_IS_LEAF(node) && CBTREE_NODE_COUNT(node) > CBTREE_MIN_LEAF(cbtree))
    {
        /*root_node do: move right and make a room for borrowed node*/
        for (i = CBTREE_NODE_COUNT(root_node); i > 0; i--)
        {
            CBTREE_NODE_KEY(root_node, i)       = CBTREE_NODE_KEY(root_node, i - 1);
            CBTREE_NODE_CHILD(root_node, i + 1) = CBTREE_NODE_CHILD(root_node, i);
        }
        CBTREE_NODE_CHILD(root_node, 1) = CBTREE_NODE_CHILD(root_node, 0);
        CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(node, CBTREE_NODE_COUNT(node) - 1);
        CBTREE_NODE_CHILD(root_node, 0) = NULL_PTR;/*CBTREE_NODE_CHILD(node, CBTREE_NODE_COUNT(node) - 1);*//*due to node is leaf*/
        ASSERT(NULL_PTR == CBTREE_NODE_CHILD(node, CBTREE_NODE_COUNT(node) - 1));

        CBTREE_NODE_COUNT(root_node) ++;

        ASSERT(2 <= CBTREE_NODE_COUNT(node));
        CBTREE_NODE_KEY(prev_node, div - 1) = CBTREE_NODE_KEY(node, CBTREE_NODE_COUNT(node) - 2);
        CBTREE_NODE_KEY(node, CBTREE_NODE_COUNT(node) - 1) = NULL_PTR;
    }
    else if (!CBTREE_NODE_IS_LEAF(node) && CBTREE_NODE_COUNT(node) > CBTREE_MIN_INTR(cbtree))
    {
        for (i = CBTREE_NODE_COUNT(root_node); i > 0; i--)
        {
            CBTREE_NODE_KEY(root_node, i)       = CBTREE_NODE_KEY(root_node, i - 1);
            CBTREE_NODE_CHILD(root_node, i + 1) = CBTREE_NODE_CHILD(root_node, i);
        }
        CBTREE_NODE_CHILD(root_node, 1) = CBTREE_NODE_CHILD(root_node, 0);
        CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(prev_node, div - 1);
        CBTREE_NODE_CHILD(root_node, 0) = CBTREE_NODE_CHILD(node, CBTREE_NODE_COUNT(node));
        CBTREE_NODE_COUNT(root_node) ++;

        CBTREE_NODE_KEY(prev_node, div - 1) = CBTREE_NODE_KEY(node, CBTREE_NODE_COUNT(node) - 1);
        CBTREE_NODE_KEY(node, CBTREE_NODE_COUNT(node) - 1) = NULL_PTR;
        CBTREE_NODE_CHILD(node, CBTREE_NODE_COUNT(node))   = NULL_PTR;             
    }
    else
    {
__CBTREE_DEBUG_BEG 
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: borrowed nothing\n");
__CBTREE_DEBUG_END     
        return (EC_FALSE);
    }

    CBTREE_NODE_COUNT(node) --;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR); 
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_borrow_left: when leave: end: ===================================================================================================\n");
__CBTREE_DEBUG_END
    return (EC_TRUE);
}

static EC_BOOL __cbtree_merge_node(CBTREE *cbtree, CBTREE_NODE *root_node, CBTREE_NODE *prev_node, uint8_t div, CBTREE_KEY *del_key)
{
    uint8_t i, j;
    CBTREE_NODE *node;

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: prev: ");
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR); 
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: div %ld, prev_node count %ld\n", div, CBTREE_NODE_COUNT(prev_node));
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: when enter: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

    /* Try to merge the node with its left sibling. */
    if (div > 0)/*when root_node is not the left most child of prev_node*/
    {
        /*merge root_node to node and then free root_node*/
        node = CBTREE_NODE_CHILD(prev_node, div - 1);
        if(NULL_PTR == node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge_node: child %d of previous node %lx is null\n", div - 1, prev_node);
            return (EC_FALSE);
        }
    
        i    = CBTREE_NODE_COUNT(node);

        if (!CBTREE_NODE_IS_LEAF(root_node))
        {
            CBTREE_NODE_KEY(node, i) = CBTREE_NODE_KEY(prev_node, div - 1);

            if(CBTREE_NODE_KEY(prev_node, div) ==  del_key)
            {
                CBTREE_NODE_KEY(prev_node, div - 1) = cbtree_node_get_r_key(cbtree, root_node);/*xxx*/             
                //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [1] is to removed key\n");
            }
            else
            {
                CBTREE_NODE_KEY(prev_node, div - 1) = CBTREE_NODE_KEY(prev_node, div);/*xxx*/
                //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [1] is NOT to removed key\n");
            }         
         
            CBTREE_NODE_COUNT(node) ++;
            i++;

            for (j = 0; j < CBTREE_NODE_COUNT(root_node); j++, i++)
            {
                CBTREE_NODE_KEY(node, i)   = CBTREE_NODE_KEY(root_node, j);
                CBTREE_NODE_CHILD(node, i) = CBTREE_NODE_CHILD(root_node, j);
             
                CBTREE_NODE_COUNT(node)++;

                CBTREE_NODE_KEY(root_node, j)   = NULL_PTR;
                CBTREE_NODE_CHILD(root_node, j) = NULL_PTR;
            }    

            CBTREE_NODE_CHILD(node, i) = CBTREE_NODE_CHILD(root_node, j);
            CBTREE_NODE_CHILD(root_node, j) = NULL_PTR;         
        }
        //CBTREE_NODE_KEY(prev_node, div - 1) = cbtree_node_get_r_key(root_node);
        else
        {
            ASSERT(0 < CBTREE_NODE_COUNT(root_node));
            ASSERT(CBTREE_NODE_IS_LEAF(node));
         
            //CBTREE_NODE_KEY(prev_node, div - 1) = cbtree_node_get_r_key(root_node);
            CBTREE_NODE_KEY(prev_node, div - 1) = CBTREE_NODE_KEY(root_node, CBTREE_NODE_COUNT(root_node) - 1);
            //CBTREE_NODE_KEY(prev_node, div) = NULL_PTR;
         
            for (j = 0; j < CBTREE_NODE_COUNT(root_node); j++, i++)
            {
                CBTREE_NODE_KEY(node, i)   = CBTREE_NODE_KEY(root_node, j);
                //CBTREE_NODE_CHILD(node, i) = CBTREE_NODE_CHILD(root_node, j);
             
                CBTREE_NODE_COUNT(node)++;

                CBTREE_NODE_KEY(root_node, j) = NULL_PTR;
                //CBTREE_NODE_CHILD(root_node, j) = NULL_PTR;
            }

            CBTREE_NODE_CHILD(node, CBTREE_ORDER(cbtree) - 1) = CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1);
            CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1) = NULL_PTR;
        }

        CBTREE_NODE_COUNT(root_node) = 0;
        CBTREE_NODE_CHILD(prev_node, div)     = NULL_PTR;
        CBTREE_NODE_KEY(prev_node, div)       = NULL_PTR;     

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [2]: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR); 
    cbtree_node_print(LOGCONSOLE, cbtree, node, 0, NULL_PTR); 
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG]__cbtree_merge_node: div %ld, prev_node count %ld\n", div, CBTREE_NODE_COUNT(prev_node));
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [2]: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

        cbtree_node_free(cbtree, root_node);
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_node: [1] rmv prev %lx child %d (div = %d)\n", prev_node, div, div);
        __cbtree_rmv_key2(cbtree, prev_node, div);
    }
    else/*when root_node is the left most child of prev_node*/
    {
        /*merge node to root_node and then free node*/
        node = CBTREE_NODE_CHILD(prev_node, div + 1);
        if(NULL_PTR == node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge_node: child %d of previous node %lx is null\n", div + 1, prev_node);
            return (EC_FALSE);
        }
     
        i    = CBTREE_NODE_COUNT(root_node);/*0*/
        //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [2] i = %ld, root_node count %ld\n", i, CBTREE_NODE_COUNT(root_node));

        if (!CBTREE_NODE_IS_LEAF(root_node))
        {
            if(CBTREE_NODE_KEY(prev_node, div) == del_key)
            {
                CBTREE_NODE_KEY(root_node, i) = cbtree_node_get_r_key(cbtree, root_node);
                //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [2] is to removed key\n");
            }
            else
            {
                CBTREE_NODE_KEY(root_node, i) = CBTREE_NODE_KEY(prev_node, div);
                //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [2] is NOT to removed key\n");
            }
         
            CBTREE_NODE_COUNT(root_node)++;

            i++;

            for (j = 0; j < CBTREE_NODE_COUNT(node); j++, i++)
            {
                CBTREE_NODE_KEY(root_node, i)   = CBTREE_NODE_KEY(node, j);
                CBTREE_NODE_CHILD(root_node, i) = CBTREE_NODE_CHILD(node, j);
                CBTREE_NODE_COUNT(root_node)++;

                CBTREE_NODE_KEY(node, j)   = NULL_PTR;
                CBTREE_NODE_CHILD(node, j) = NULL_PTR;
            }
            CBTREE_NODE_CHILD(root_node, i) = CBTREE_NODE_CHILD(node, j);         
            CBTREE_NODE_CHILD(node, j) = NULL_PTR;
        }
        else
        {
            for (j = 0; j < CBTREE_NODE_COUNT(node); j++, i++)
            {
                CBTREE_NODE_KEY(root_node, i)   = CBTREE_NODE_KEY(node, j);
                //CBTREE_NODE_CHILD(root_node, i) = CBTREE_NODE_CHILD(node, j);
                CBTREE_NODE_COUNT(root_node)++;

                CBTREE_NODE_KEY(node, j) = NULL_PTR;
                //CBTREE_NODE_CHILD(node, j) = NULL_PTR;
            }
       
            CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1) = CBTREE_NODE_CHILD(node, CBTREE_ORDER(cbtree) - 1);
            CBTREE_NODE_CHILD(node, CBTREE_ORDER(cbtree) - 1) = NULL_PTR;       
        }

        CBTREE_NODE_COUNT(node) = 0;
     
        CBTREE_NODE_CHILD(prev_node, div + 1) = root_node;
        CBTREE_NODE_CHILD(prev_node, div)     = NULL_PTR;
        CBTREE_NODE_KEY(prev_node, div)       = NULL_PTR;

__CBTREE_DEBUG_BEG
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [5] root_node: ");
        cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: [5] prev_node: ");
        cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR) ;
__CBTREE_DEBUG_END

        cbtree_node_free(cbtree, node);

        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_node: [2] rmv prev %lx child %d (div = %d)\n", prev_node, div, div);

        __cbtree_rmv_key2(cbtree, prev_node, div);
    }

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR); 
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_merge_node: when leave: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

    return (EC_TRUE);
}


/*prev_node is the parent of root_node*/
static EC_BOOL __cbtree_delete(CBTREE *cbtree, CBTREE_NODE *root_node, CBTREE_NODE *prev_node,
         const CBTREE_KEY *key, uint8_t index, CBTREE_KEY **del_key, uint8_t *merged)
{
    EC_BOOL success;
    int     result;
    uint8_t i;
    if(NULL_PTR == root_node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_delete: root node is null\n");
        return (EC_FALSE);
    }

__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [0]when enter: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [0]root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [0]prev: ");
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [0]when enter: end: ===================================================================================================\n");
__CBTREE_DEBUG_END

    success = EC_FALSE;
    result  = (int)    -3;
    i       = (uint8_t)-1;

    if (CBTREE_NODE_IS_LEAF(root_node))
    {
        success = __cbtree_rmv_key(cbtree, root_node, key, del_key);
    }
    else
    {
        //uint8_t i;
#if 0
        for (i = 0;
             i < CBTREE_NODE_COUNT(root_node) && 0 > (result = cbtree_key_cmp(cbtree, CBTREE_NODE_KEY(root_node, i), key));
             i++)
        {
            /*do nothing*/
        }
#else
    CBTREE_SEARCH_KEY(cbtree, root_node, CBTREE_NODE_COUNT(root_node), key, i, result);
#endif     

        success = __cbtree_delete(cbtree, CBTREE_NODE_CHILD(root_node, i), root_node, key, i, del_key, merged);
    }

    if (EC_FALSE == success)
    {
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] error:__cbtree_delete: false\n");
        return (EC_FALSE);
    }

    if(root_node == CBTREE_ROOT_NODE(cbtree))
    {
        return (EC_TRUE);
    }
    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_delete: ### merge = %d, root %lx, prev %lx, index %d\n", *merged, root_node, prev_node, index);

#if 1
    if (
       (CBTREE_NODE_IS_LEAF(root_node)  && CBTREE_NODE_COUNT(root_node) >= CBTREE_MIN_LEAF(cbtree))
    || (!CBTREE_NODE_IS_LEAF(root_node) && CBTREE_NODE_COUNT(root_node) >= CBTREE_MIN_INTR(cbtree))
    )
    {
#if 1 
        if(NULL_PTR != prev_node && CBTREE_NODE_KEY(prev_node, index) == (*del_key))
        {
            //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [2]update prev %lx key %ld #, del_key %lx\n", prev_node, index, *del_key);
            CBTREE_NODE_KEY(prev_node, index) = cbtree_node_get_r_key(cbtree, root_node);
        }
        else
        {
            //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [2]NOT update prev %lx key %ld # where result = %d, del_key %lx\n", prev_node, index, result, *del_key);
        }
#endif     
__CBTREE_DEBUG_BEG
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [2]when leave: beg: ===================================================================================================\n");
        cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [2]root: ");
        cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [2]prev: ");
        cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR);
        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [2]when leave: end: ===================================================================================================\n");


        dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [2] return where tree root node (%lx, min_leaf %ld, min_intr %ld), root_node (%lx, %s, count %ld), merged %d\n",
                           CBTREE_ROOT_NODE(cbtree),  CBTREE_MIN_LEAF(cbtree), CBTREE_MIN_INTR(cbtree),
                           root_node, CBTREE_NODE_LEAF_STR(root_node), CBTREE_NODE_COUNT(root_node),
                           (*merged));
__CBTREE_DEBUG_END                        
        return (EC_TRUE);
    }
#endif 
    else
    {
        if (
           EC_TRUE == __cbtree_borrow_right(cbtree, root_node, prev_node, index, (*del_key))
        || EC_TRUE == __cbtree_borrow_left(cbtree, root_node, prev_node, index)
        )
        {
            *merged = 0;
        }
        else
        {
            *merged = 1;
            __cbtree_merge_node(cbtree, root_node, prev_node, index, (*del_key));
        }
    }

#if 1
    if(NULL_PTR != prev_node && CBTREE_NODE_KEY(prev_node, index) == (*del_key))
    {
        //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [3]update prev %lx key %ld #, del_key %lx\n", prev_node, index, *del_key);
        CBTREE_NODE_KEY(prev_node, index) = cbtree_node_get_r_key(cbtree, root_node);
    }
    else
    {
        //dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [3]NOT update prev %lx key %ld # where result = %d, del_key %lx\n", prev_node, index, result, *del_key);
    }
#endif  
 
__CBTREE_DEBUG_BEG
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [4]when leave: beg: ===================================================================================================\n");
    cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [4]root: ");
    cbtree_node_print(LOGCONSOLE, cbtree, root_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [4]prev: ");
    cbtree_node_print(LOGCONSOLE, cbtree, prev_node, 0, NULL_PTR);
    dbg_log(SEC_0050_CBTREE, 0)(LOGCONSOLE, "[DEBUG] __cbtree_delete: [4]when leave: end: ===================================================================================================\n");


    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_delete: [4] return\n");
__CBTREE_DEBUG_END 
    return (EC_TRUE);
}

/**
    http://en.wikipedia.org/wiki/B%2Btree

    Start at root, find leaf L where entry belongs.
    Remove the entry.
        If L is at least half-full, done!
        If L has fewer entries than it should,
            Try to re-distribute, borrowing from sibling (adjacent node with same parent as L).
            If re-distribution fails, merge L and sibling.
    If merge occurred, must delete entry (pointing to L or sibling) from parent of L.
    Merge could propagate to root, decreasing height.

**/
static EC_BOOL __cbtree_delete_key(CBTREE *cbtree, const CBTREE_KEY *rmv_key, CBTREE_KEY  **del_key)
{
    uint8_t i; 
    uint8_t merged;
    EC_BOOL success;
    int     result;

    CBTREE_NODE *root_node;

    if (NULL_PTR == cbtree || NULL_PTR == rmv_key)
    {
        return (EC_FALSE);
    }

    merged   = 0;
    success  = EC_FALSE;
 
    /* Read in the root node. */
    root_node = CBTREE_ROOT_NODE(cbtree);
    if(NULL_PTR == root_node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_delete_key: root node of tree is null\n");
        return (EC_FALSE);
    }
#if 0
    for (i = 0;
         i < CBTREE_NODE_COUNT(root_node) && 0 > (result = cbtree_key_cmp(cbtree, CBTREE_NODE_KEY(root_node, i), rmv_key));
         i++)
    {
        /*do nothing*/
    }
#else
    CBTREE_SEARCH_KEY(cbtree, root_node, CBTREE_NODE_COUNT(root_node), rmv_key, i, result);
#endif
    success = __cbtree_delete(cbtree, CBTREE_ROOT_NODE(cbtree), NULL_PTR, rmv_key, i, del_key, &merged);
    if (EC_FALSE == success)
    {
        return (EC_FALSE);
    }

    CBTREE_SIZE(cbtree) --;
    CBTREE_TLEN(cbtree) -= cbtree_key_tlen(cbtree, (*del_key));

    if (CBTREE_NODE_IS_LEAF(root_node) && 0 == CBTREE_NODE_COUNT(root_node))
    {
        CBTREE_ROOT_NODE(cbtree) = NULL_PTR;
        CBTREE_HEIGHT(cbtree) --;
        cbtree_node_free(cbtree, root_node);
    }
    else if (1 == merged && 0 == CBTREE_NODE_COUNT(root_node))/*decrease tree height*/
    {
        CBTREE_ROOT_NODE(cbtree) = CBTREE_NODE_CHILD(root_node, 0);
        CBTREE_NODE_CHILD(root_node, 0) = NULL_PTR;
        CBTREE_HEIGHT(cbtree) --;
        cbtree_node_free(cbtree, root_node);     

        CBTREE_SET_DIRTY(cbtree);
    }

    return (EC_TRUE);
}

EC_BOOL cbtree_delete(CBTREE *cbtree, const uint8_t *key)
{
    CBTREE_KEY  *rmv_key;
    CBTREE_KEY  *del_key;/*matched and removed key*/

    if (NULL_PTR == cbtree || NULL_PTR == key || NULL_PTR == CBTREE_ROOT_NODE(cbtree))
    {
        return (EC_FALSE);
    }
 
    rmv_key = cbtree_key_make(cbtree, key);
    if(NULL_PTR == rmv_key)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_delete: make cbtree_key by key %lx failed\n", key);
        return (EC_FALSE);
    }

    del_key = NULL_PTR;
    if(EC_FALSE == __cbtree_delete_key(cbtree, rmv_key, &del_key))
    {
        cbtree_key_free(cbtree, rmv_key);
        cbtree_key_free(cbtree, del_key);
        return (EC_FALSE);
    }

    cbtree_key_free(cbtree, rmv_key);
    cbtree_key_free(cbtree, del_key);

    return (EC_TRUE);
}

static CBTREE_KEY * __cbtree_search(CBTREE *cbtree, CBTREE_NODE *root_node, const CBTREE_KEY *key)
{
    while(NULL_PTR != root_node)
    {
        uint8_t i;
        int result;
 
        result = -3; /*invalid*/
#if 0
        for (i = 0;
             i < CBTREE_NODE_COUNT(root_node) && 0 > (result = cbtree_key_cmp(cbtree, CBTREE_NODE_KEY(root_node, i), key));
             i++)
        {
            /*do nothing*/
        }
#else
        CBTREE_SEARCH_KEY(cbtree, root_node, CBTREE_NODE_COUNT(root_node), key, i, result);
#endif
        if (i < CBTREE_NODE_COUNT(root_node) && 0 == result)
        {
            return CBTREE_NODE_KEY(root_node, i);
        }

        if (CBTREE_NODE_IS_LEAF(root_node))
        {
            return (NULL_PTR);
        }

        root_node = CBTREE_NODE_CHILD(root_node, i);
    }
    return (NULL_PTR);
}

CBTREE_KEY *cbtree_search(CBTREE *cbtree, const uint8_t *key)
{
    CBTREE_KEY *found_key;
    CBTREE_KEY *search_key;

    if(EC_TRUE == cbtree_is_empty(cbtree))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_search: cbtree is empty\n");
        return (NULL_PTR);
    }

    if (NULL_PTR == key)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_search: key is null\n");
        return (NULL_PTR);
    }

    search_key = cbtree_key_make(cbtree, key);
    if(NULL_PTR == search_key)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_search: make cbtree_key by key failed\n");
        return (NULL_PTR);
    }

    found_key = __cbtree_search(cbtree, CBTREE_ROOT_NODE(cbtree), search_key);
    if (NULL_PTR == found_key)
    {
        cbtree_key_free(cbtree, search_key);
        return (NULL_PTR);
    }

    cbtree_key_free(cbtree, search_key);
    return (found_key);
}

uint32_t cbtree_count_size(const CBTREE *cbtree)
{
    const CBTREE_NODE *cbtree_node;
    uint32_t size;

    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_count_size: tree basic info:\n");
    //cbtree_print_itself(LOGSTDOUT, cbtree);

    size = 0;
    cbtree_node = CBTREE_LEFT_LEAF(cbtree);
    while(NULL_PTR != cbtree_node)
    {     
        size += CBTREE_NODE_COUNT(cbtree_node);
#if 0     
        //ASSERT(CBTREE_NODE_IS_LEAF(cbtree_node));
        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_count_size: cbtree_node %lx, leaf flag %d, order %d, next is %lx\n",
                            cbtree_node, CBTREE_NODE_FLAG(cbtree_node), CBTREE_ORDER(cbtree), CBTREE_NODE_CHILD(cbtree_node, CBTREE_ORDER(cbtree) - 1));
#endif                         
        cbtree_node = CBTREE_NODE_CHILD(cbtree_node, CBTREE_ORDER(cbtree) - 1);
    }
    return (size);
}

uint32_t cbtree_count_tlen(const CBTREE *cbtree)
{
    const CBTREE_NODE *cbtree_node;
    uint32_t tlen;

    tlen = 0;
    cbtree_node = CBTREE_LEFT_LEAF(cbtree);
    while(NULL_PTR != cbtree_node)
    {
        tlen += cbtree_node_count_tlen(cbtree, cbtree_node);
        cbtree_node = CBTREE_NODE_CHILD(cbtree_node, CBTREE_ORDER(cbtree) - 1);
    }
    return (tlen);
}

uint8_t cbtree_count_height(const CBTREE *cbtree)
{
    const CBTREE_NODE *cbtree_node;
    uint8_t height;

    height = 0;

    cbtree_node = CBTREE_ROOT_NODE(cbtree);
    while(NULL_PTR != cbtree_node)
    {
        height ++;
        cbtree_node = CBTREE_NODE_CHILD(cbtree_node, 0);
    }
    return (height); 
}

/*split cbtree into 2 sons, left subtree is remain as cbtree, right subtree is cbtree_son*/
EC_BOOL cbtree_split0(CBTREE *cbtree, CBTREE **cbtree_son)
{
    CBTREE_NODE *root_node_src;
    CBTREE_NODE *root_node_des;
    CBTREE_NODE *right_most_leaf;
    CBTREE      *cbtree_des;
    uint8_t div;
    uint8_t i;
    uint8_t j;

    if(EC_TRUE == cbtree_is_empty(cbtree))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: cbtree is empty, refuse to split\n");
        return (EC_FALSE);
    }

    root_node_src = CBTREE_ROOT_NODE(cbtree);
    if (
       (CBTREE_NODE_IS_LEAF(root_node_src)  && CBTREE_NODE_COUNT(root_node_src) <= CBTREE_MIN_LEAF(cbtree))
    || (!CBTREE_NODE_IS_LEAF(root_node_src) && CBTREE_NODE_COUNT(root_node_src) <= CBTREE_MIN_INTR(cbtree))
    )
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: cbtree root node has no enough childs to split\n");
        return (EC_FALSE);
    }

    cbtree_des = cbtree_new(CBTREE_ORDER(cbtree), CBTREE_MAX_VER(cbtree), CBTREE_KEY_TYPE(cbtree));
    if(NULL_PTR == cbtree_des)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: new cbtree failed\n");
        return (EC_FALSE);
    }

    root_node_des = cbtree_node_new(cbtree_des);
    if(NULL_PTR == root_node_des)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: new cbtree_des root node failed\n");
        cbtree_free(cbtree_des);
        return (EC_FALSE);
    } 

    div = ((CBTREE_NODE_COUNT(root_node_src) + 1) / 2);
    i   = div - 1;

    right_most_leaf = cbtree_node_get_r_leaf(cbtree, CBTREE_NODE_CHILD(root_node_src, i));
    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_split: div = %d, i = %d, right_most_leaf = %lx\n", div, i, right_most_leaf);

    for(i = div, j = 0; i < CBTREE_NODE_COUNT(root_node_src); i ++, j ++)
    {
        CBTREE_NODE_KEY(root_node_des, j) = CBTREE_NODE_KEY(root_node_src, i);
        CBTREE_NODE_KEY(root_node_src, i) = NULL_PTR;

        CBTREE_NODE_CHILD(root_node_des, j) = CBTREE_NODE_CHILD(root_node_src, i);
        CBTREE_NODE_CHILD(root_node_src, i) = NULL_PTR;
    }

    if(CBTREE_NODE_IS_LEAF(root_node_src))
    {
        CBTREE_NODE_CHILD(root_node_des, CBTREE_ORDER(cbtree_des) - 1) = CBTREE_NODE_CHILD(root_node_src, CBTREE_ORDER(cbtree) - 1);
        CBTREE_NODE_CHILD(root_node_src, CBTREE_ORDER(cbtree) - 1) = NULL_PTR;     

        CBTREE_NODE_COUNT(root_node_des) += j;
        CBTREE_NODE_COUNT(root_node_src) -= j;       
    }
    else
    {
        CBTREE_NODE_CHILD(root_node_des, j) = CBTREE_NODE_CHILD(root_node_src, i);
        CBTREE_NODE_CHILD(root_node_src, i) = NULL_PTR; 

        CBTREE_NODE_KEY(root_node_src, div - 1) = NULL_PTR;

        CBTREE_NODE_COUNT(root_node_des) += j;
        CBTREE_NODE_COUNT(root_node_src) -= j + 1;
    }

    /*adjust cbtree*/
    if(0 == CBTREE_NODE_COUNT(root_node_src))
    {
        CBTREE_ROOT_NODE(cbtree) = CBTREE_NODE_CHILD(root_node_src, 0);
        CBTREE_NODE_CHILD(root_node_src, 0) = NULL_PTR;
        cbtree_node_free(cbtree, root_node_src); 
    }
    else
    {
        CBTREE_ROOT_NODE(cbtree_des) = root_node_des;
    } 
   
    CBTREE_ROOT_NODE(cbtree_des) = root_node_des;

    if(NULL_PTR != right_most_leaf)
    {
        CBTREE_LEFT_LEAF(cbtree_des) = CBTREE_NODE_CHILD(right_most_leaf, CBTREE_ORDER(cbtree) - 1);
        CBTREE_NODE_CHILD(right_most_leaf, CBTREE_ORDER(cbtree) - 1) = NULL_PTR;
    }
    else
    {
        CBTREE_LEFT_LEAF(cbtree_des) = root_node_des;
        CBTREE_NODE_SET_LEAF(root_node_des);
    }

    /*count num of leaves*/
    CBTREE_SIZE(cbtree_des) = CBTREE_SIZE(cbtree) - cbtree_count_size(cbtree);
    CBTREE_SIZE(cbtree)    -= CBTREE_SIZE(cbtree_des);

    /*count total len of keys*/
    CBTREE_TLEN(cbtree_des) = CBTREE_TLEN(cbtree) - cbtree_count_tlen(cbtree);
    CBTREE_TLEN(cbtree)    -= CBTREE_TLEN(cbtree_des);

    CBTREE_SET_DIRTY(cbtree);
    CBTREE_SET_DIRTY(cbtree_des);

    (*cbtree_son) = cbtree_des;

    return (EC_TRUE);
}

/*split cbtree into left subtree and right subtree, left subtree < right subtree*/
/*then cbtree take back right subtree, and cbtree_son take back left subtree*/
static EC_BOOL __cbtree_split(CBTREE *cbtree, CBTREE **left_sub_cbtree)
{
    CBTREE      *left_cbtree;
    CBTREE_NODE *root_node;/*node in cbtree to split*/
    CBTREE_NODE *left_root_node; 
    uint8_t      div;
    uint8_t      i;
    uint8_t      j;

    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_split: before split:\n");
    //cbtree_print(LOGSTDOUT, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);

    root_node = CBTREE_ROOT_NODE(cbtree);
    ASSERT(1 < CBTREE_NODE_COUNT(root_node));
 
    /*now 2 <= CBTREE_NODE_COUNT(root_node)*/
    div = ((CBTREE_NODE_COUNT(root_node) + 1) / 2);

    left_cbtree = cbtree_new(CBTREE_ORDER(cbtree), CBTREE_MAX_VER(cbtree), CBTREE_KEY_TYPE(cbtree));
    if(NULL_PTR == left_cbtree)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: new left_cbtree failed\n");
        return (EC_FALSE);
    }

    left_root_node = cbtree_node_new(left_cbtree);
    if(NULL_PTR == left_root_node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: new left_root_node failed\n");
        cbtree_free(left_cbtree);
        return (EC_FALSE);
    }

    if(CBTREE_NODE_IS_LEAF(root_node))
    {
        /*move first div keys from root_node to left_root_node*/
        for(i = 0; i < div; i ++)
        {
            CBTREE_NODE_KEY(left_root_node, i) = CBTREE_NODE_KEY(root_node, i);
        }

        /*move other keys of root_node to left with div skip*/
        for(j = 0; i < CBTREE_NODE_COUNT(root_node); j ++, i ++)
        {
            CBTREE_NODE_KEY(root_node, j)   = CBTREE_NODE_KEY(root_node, i);
        }

        /*clean up the left key space to null*/
        for(; j < CBTREE_NODE_COUNT(root_node); j ++)
        {
            CBTREE_NODE_KEY(root_node, j) = NULL_PTR;
        }

        CBTREE_NODE_COUNT(root_node)    -= div;
        CBTREE_NODE_COUNT(left_root_node) += div;
     
        /*set leaf of left_root_node*/
        CBTREE_NODE_CHILD(left_root_node, CBTREE_ORDER(cbtree) - 1) = NULL_PTR;
        CBTREE_NODE_SET_LEAF(left_root_node);

        CBTREE_ROOT_NODE(left_cbtree) = left_root_node;
        CBTREE_LEFT_LEAF(left_cbtree) = left_root_node;
    }
    else
    {
        CBTREE_NODE *right_most_leaf;/*right most leaf of left tree*/
     
        for(i = 0; i < div; i ++)
        {
            CBTREE_NODE_KEY(left_root_node, i)   = CBTREE_NODE_KEY(root_node, i);
            CBTREE_NODE_CHILD(left_root_node, i) = CBTREE_NODE_CHILD(root_node, i);
        }

        CBTREE_NODE_KEY(left_root_node, i - 1) = NULL_PTR;/*discard the last key of left_root_node*/

        for(j = 0; i < CBTREE_NODE_COUNT(root_node); j ++, i ++)
        {
            CBTREE_NODE_KEY(root_node, j)   = CBTREE_NODE_KEY(root_node, i);
            CBTREE_NODE_CHILD(root_node, j) = CBTREE_NODE_CHILD(root_node, i);
        }

        /*here j must be less than CBTREE_NODE_COUNT(root_node)*/
        CBTREE_NODE_KEY(root_node, j)   = NULL_PTR;
        CBTREE_NODE_CHILD(root_node, j) = CBTREE_NODE_CHILD(root_node, i);/*the last child*/
     
        for(j ++ ; j < CBTREE_NODE_COUNT(root_node); j ++)
        {
            CBTREE_NODE_KEY(root_node, j)   = NULL_PTR;
            CBTREE_NODE_CHILD(root_node, j) = NULL_PTR;
        }

        /*note: on intra node, must count < order*/
        ASSERT(j < CBTREE_ORDER(cbtree));
        CBTREE_NODE_CHILD(root_node, j) = NULL_PTR;

        CBTREE_NODE_COUNT(root_node)    -= div;
        CBTREE_NODE_COUNT(left_root_node) += div - 1;

        /*set root node of left tree*/
        CBTREE_ROOT_NODE(left_cbtree) = left_root_node;

        /*adjust leaf pointer*/
        right_most_leaf = cbtree_node_get_r_leaf(left_cbtree, left_root_node);
        CBTREE_LEFT_LEAF(left_cbtree) = CBTREE_LEFT_LEAF(cbtree);
        CBTREE_LEFT_LEAF(cbtree) = CBTREE_NODE_CHILD(right_most_leaf, CBTREE_ORDER(cbtree) - 1);
        CBTREE_NODE_CHILD(right_most_leaf, CBTREE_ORDER(cbtree) - 1) = NULL_PTR;

        /*adjust root node of left tree if necessary*/
        if(0 == CBTREE_NODE_COUNT(left_root_node))
        {
            CBTREE_ROOT_NODE(left_cbtree) = CBTREE_NODE_CHILD(left_root_node, 0);
            CBTREE_NODE_CHILD(left_root_node, 0) = NULL_PTR;
            cbtree_node_free(left_cbtree, left_root_node);
        }
    }

    /*count size of leaves*/
    CBTREE_SIZE(left_cbtree) = CBTREE_SIZE(cbtree) - cbtree_count_size(cbtree);
    CBTREE_SIZE(cbtree)     -= CBTREE_SIZE(left_cbtree);

    /*count total len of keys*/
    CBTREE_TLEN(left_cbtree) = CBTREE_TLEN(cbtree) - cbtree_count_tlen(cbtree);
    CBTREE_TLEN(cbtree)     -= CBTREE_TLEN(left_cbtree);

    CBTREE_HEIGHT(left_cbtree) = cbtree_count_height(left_cbtree);
    CBTREE_HEIGHT(cbtree)      = cbtree_count_height(cbtree);

    CBTREE_SET_DIRTY(left_cbtree);
    CBTREE_SET_DIRTY(cbtree); 

    (*left_sub_cbtree) = left_cbtree;
    return (EC_TRUE);
}

static EC_BOOL __cbtree_split_push_all(CBTREE *cbtree, CLIST *cached_key_list)
{ 
    while(EC_FALSE == clist_is_empty(cached_key_list))
    {
        CBTREE_KEY  *del_key;
     
        del_key = (CBTREE_KEY *)clist_pop_front(cached_key_list);
        if(NULL_PTR == del_key)
        {
            continue;
        }
        __cbtree_insert_do(cbtree, &del_key);
        ASSERT(NULL_PTR == del_key);/*when insert successfully, del_key will take back null pointer*/
#if 1
        if(NULL_PTR != del_key)
        {
            cbtree_key_free(cbtree, del_key);
        }
#endif
    }
 
    return (EC_TRUE);
}

static EC_BOOL __cbtree_split_cleanup(CBTREE *cbtree, CLIST *cached_key_list)
{ 
    while(EC_FALSE == clist_is_empty(cached_key_list))
    {
        CBTREE_KEY  *del_key;
     
        del_key = (CBTREE_KEY *)clist_pop_front(cached_key_list);
        if(NULL_PTR == del_key)
        {
            continue;
        }

        cbtree_key_free(cbtree, del_key);
    }
 
    return (EC_TRUE);
}

static EC_BOOL __cbtree_split_pop_min_key(CBTREE *cbtree, CLIST *cached_min_key_list)
{
    CBTREE_NODE *left_leaf;
    CBTREE_KEY  *del_key;
    CBTREE_KEY  *min_key;

    left_leaf = CBTREE_LEFT_LEAF(cbtree);
    min_key   = CBTREE_NODE_KEY(left_leaf, 0);
 
    del_key = NULL_PTR;
    __cbtree_delete_key(cbtree, min_key, &del_key);
 
    if(NULL_PTR != del_key)
    {
        clist_push_back_no_lock(cached_min_key_list, (void *)del_key);
    }

    return (EC_TRUE);
}


static EC_BOOL __cbtree_split_pop_max_key(CBTREE *cbtree, CLIST *cached_max_key_list)
{
    CBTREE_KEY  *del_key;
    CBTREE_KEY  *max_key;

    max_key = cbtree_node_get_r_key(cbtree, CBTREE_ROOT_NODE(cbtree));
 
    del_key = NULL_PTR;
    __cbtree_delete_key(cbtree, max_key, &del_key);
 
    if(NULL_PTR != del_key)
    {
        clist_push_back_no_lock(cached_max_key_list, (void *)del_key);
    }

    return (EC_TRUE);
}

EC_BOOL cbtree_split(CBTREE *cbtree, CBTREE **left_sub_cbtree)
{
    CBTREE      *left_cbtree;
    CBTREE_NODE *root_node;
    CLIST       *cached_min_key_list;/*cached key is the deleted minimu key of cbtree when top has only one key*/
    CLIST       *cached_max_key_list;/*cached key is the deleted maximum key of cbtree when top has only one key*/
    UINT32       flag;

    if(NULL_PTR == cbtree || NULL_PTR == CBTREE_ROOT_NODE(cbtree))
    {
        return (EC_FALSE);
    }

    cached_min_key_list = clist_new(MM_CBTREE_KEY, LOC_CBTREE_0015);
    if(NULL_PTR == cached_min_key_list)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: new cached_min_key_list failed\n");
        return (EC_FALSE);
    }

    cached_max_key_list = clist_new(MM_CBTREE_KEY, LOC_CBTREE_0016);
    if(NULL_PTR == cached_max_key_list)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: new cached_max_key_list failed\n");
        clist_free_no_lock(cached_min_key_list, LOC_CBTREE_0017);
        return (EC_FALSE);
    }

    for(root_node = CBTREE_ROOT_NODE(cbtree), flag = 1;
        NULL_PTR != root_node && 2 > CBTREE_NODE_COUNT(root_node);
        root_node = CBTREE_ROOT_NODE(cbtree), flag ^= 1)
    {
        if(flag & 1)
        {
            __cbtree_split_pop_min_key(cbtree, cached_min_key_list);
        }
        else
        {
            __cbtree_split_pop_max_key(cbtree, cached_max_key_list);
        }
#if 0     
        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG]cbtree_split: cbtree now size %d, min cached %ld, max cached %ld\n",
                            CBTREE_SIZE(cbtree),
                            clist_size(cached_min_key_list),
                            clist_size(cached_max_key_list)
                            );
#endif                         
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG]cbtree_split: cbtree now is\n");
        //cbtree_print(LOGCONSOLE, cbtree, CBTREE_ROOT_NODE(cbtree), 0, NULL_PTR);     
    }

    if(NULL_PTR == root_node || 2 > CBTREE_NODE_COUNT(root_node))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: cbtree %lx has no enough nodes to split\n", cbtree);
        __cbtree_split_push_all(cbtree, cached_min_key_list);
        __cbtree_split_push_all(cbtree, cached_max_key_list);
        __cbtree_split_cleanup(cbtree, cached_min_key_list);
        __cbtree_split_cleanup(cbtree, cached_max_key_list);
        clist_free_no_lock(cached_min_key_list, LOC_CBTREE_0018);
        clist_free_no_lock(cached_max_key_list, LOC_CBTREE_0019);
        return (EC_FALSE);
    }

    left_cbtree = NULL_PTR;
    if(EC_FALSE == __cbtree_split(cbtree, &left_cbtree))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_split: split cbtree %lx failed\n", cbtree);
        __cbtree_split_push_all(cbtree, cached_min_key_list);
        __cbtree_split_push_all(cbtree, cached_max_key_list);
        __cbtree_split_cleanup(cbtree, cached_min_key_list);
        __cbtree_split_cleanup(cbtree, cached_max_key_list);
        clist_free_no_lock(cached_min_key_list, LOC_CBTREE_0020);
        clist_free_no_lock(cached_max_key_list, LOC_CBTREE_0021);
        return (EC_FALSE);
    }

    ASSERT(NULL_PTR != left_cbtree);
    __cbtree_split_push_all(left_cbtree, cached_min_key_list);
    __cbtree_split_push_all(cbtree, cached_max_key_list);
 
    __cbtree_split_cleanup(cbtree, cached_min_key_list);
    __cbtree_split_cleanup(cbtree, cached_max_key_list);
    clist_free_no_lock(cached_min_key_list, LOC_CBTREE_0022);
    clist_free_no_lock(cached_max_key_list, LOC_CBTREE_0023);

    (*left_sub_cbtree) = left_cbtree;
    return (EC_TRUE);
}

#if 0

static void __cbtree_node_print(LOG *log, const CBTREE * tree, const CBTREE_NODE *node)
{
    cbtree_node_print(log, tree, node, 0, NULL_PTR);
#if 0
    uint8_t i;

    if(NULL_PTR == node)
    {
        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_node_print: node is null\n");
        return;
    }

    sys_print(log, "key      is: ");
    for(i = 0; i <= CBTREE_NODE_COUNT(node); i ++)
    {
        sys_print(log, "%8lx, ", CBTREE_NODE_KEY(node, i));
    }
    sys_print(log, "\n");

    sys_print(log, "children is: ");
    for(i = 0; i <= CBTREE_NODE_COUNT(node); i ++)
    {
        sys_print(log, "%8lx, ", CBTREE_NODE_CHILD(node, i));
    }
    sys_print(log, "\n"); 
#endif
    return;
}

static EC_BOOL __cbtree_merge_balance(CBTREE *des_tree, CBTREE_NODE *left_node, CBTREE_NODE *right_node, CBTREE_NODE **new_node)
{ 
    ASSERT(CBTREE_NODE_COUNT(left_node) + CBTREE_NODE_COUNT(right_node) >= CBTREE_ORDER(des_tree) - 1);
    ASSERT(!CBTREE_NODE_IS_LEAF(left_node));
    ASSERT(!CBTREE_NODE_IS_LEAF(right_node));

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_balance: left_node %lx, right_node %lx\n", left_node, right_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_balance:[1] left_node is\n");
    __cbtree_node_print(LOGSTDOUT,  des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_balance:[1] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);  

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_balance:[0] des_tree is\n");
    cbtree_print(LOGSTDOUT, des_tree, CBTREE_ROOT_NODE(des_tree), 0, NULL_PTR); 
 
    if(CBTREE_NODE_COUNT(left_node) > CBTREE_MIN_INTR(des_tree) + 1)/*move some keys and children from left_node to right_node*/
    {     
        uint8_t i;
        uint8_t j;
        uint8_t k;/*the num of keys expected to shift*/

        CBTREE_NODE *root_node;/*new root node of left*/

        root_node = cbtree_node_new(des_tree);
        if(NULL_PTR == root_node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge_balance: new cbtree node failed where left_node count %ld > min_intra %ld\n",
                                CBTREE_NODE_COUNT(left_node), CBTREE_MIN_INTR(des_tree));
            return (EC_FALSE);
        }
        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_balance:[A] new root_node %lx\n", root_node);

        k = CBTREE_NODE_COUNT(left_node) - CBTREE_MIN_INTR(des_tree);
        j = CBTREE_NODE_COUNT(right_node) + k;
        i = CBTREE_NODE_COUNT(right_node);

        CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);     
        for(j -- ; i -- > 0; j --)
        {
            CBTREE_NODE_KEY(right_node  , j) = CBTREE_NODE_KEY(right_node, i);
            CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);
        }
        //ASSERT(0 == i);
        //ASSERT(k == j);

        /*now i is zero, j is k - 1*/
        i = CBTREE_NODE_COUNT(left_node);
        //CBTREE_NODE_KEY(left_node, i) = cbtree_node_get_r_key(NULL_PTR, CBTREE_NODE_CHILD(left_node, i));
        for(j = k, i --; j -- > 0; i --)
        {
            CBTREE_NODE_KEY(right_node, j)   = CBTREE_NODE_KEY(left_node, i);
            CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(left_node, i); 

            CBTREE_NODE_KEY(left_node, i)   = NULL_PTR;
            CBTREE_NODE_CHILD(left_node, i) = NULL_PTR;
        }

        CBTREE_NODE_COUNT(left_node) -= k;
        CBTREE_NODE_COUNT(right_node)+= k;     

        /*note: root_node has zero key and one child*/
        //CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(left_node, i);
        CBTREE_NODE_CHILD(root_node, 0) = left_node;
        CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(left_node, CBTREE_NODE_COUNT(left_node) - 1);
        ASSERT(CBTREE_NODE_KEY(root_node, 0));
        CBTREE_NODE_COUNT(root_node) ++;
     
        CBTREE_NODE_KEY(left_node, CBTREE_NODE_COUNT(left_node) - 1) = NULL_PTR;
        CBTREE_NODE_COUNT(left_node) --;

        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_balance:[A] root_node is\n");
        __cbtree_node_print(LOGSTDNULL,  des_tree, root_node);       

        (*new_node) = root_node;
    }

    else if(CBTREE_NODE_COUNT(left_node) + 1 < CBTREE_MIN_INTR(des_tree))/*move some keys and children from right_node to left_node*/
    {
        uint8_t i;
        uint8_t j;
        uint8_t k;/*the num of keys expected to shift*/

        CBTREE_NODE *root_node;/*new root node of left*/

        root_node = cbtree_node_new(des_tree);
        if(NULL_PTR == root_node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge_balance: new cbtree node failed where left_node count %ld < min_intra %ld\n",
                                CBTREE_NODE_COUNT(left_node), CBTREE_MIN_INTR(des_tree));
            return (EC_FALSE);
        }
        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_balance:[B] new root_node %lx\n", root_node);

        k = CBTREE_MIN_INTR(des_tree) - CBTREE_NODE_COUNT(left_node);
        j = CBTREE_NODE_COUNT(left_node);
        i = 0;

        //CBTREE_NODE_KEY(left_node, j) = cbtree_node_get_r_key(NULL_PTR, CBTREE_NODE_CHILD(left_node, j));

        for(j ++; i < k; i ++, j ++)
        {
            CBTREE_NODE_KEY(left_node, j)   = CBTREE_NODE_KEY(right_node, i);
            CBTREE_NODE_CHILD(left_node, j) = CBTREE_NODE_CHILD(right_node, i);           
        }
        //CBTREE_NODE_KEY(left_node, j - 1) = NULL_PTR;

        for(j = 0; i <= CBTREE_NODE_COUNT(right_node); i ++, j ++)
        {
            CBTREE_NODE_KEY(right_node, j)   = CBTREE_NODE_KEY(right_node, i);
            CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);       
        }

        for(; j <= CBTREE_NODE_COUNT(right_node); j ++)
        {
            CBTREE_NODE_KEY(right_node, j)   = NULL_PTR;
            CBTREE_NODE_CHILD(right_node, j) = NULL_PTR;
        }

        CBTREE_NODE_COUNT(left_node) += k;
        CBTREE_NODE_COUNT(right_node)-= k;        

        /*note: root_node has zero key and one child*/
        //CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(left_node, i);
        CBTREE_NODE_CHILD(root_node, 0) = left_node;
        CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(left_node, CBTREE_NODE_COUNT(left_node));
        ASSERT(CBTREE_NODE_KEY(root_node, 0));
        CBTREE_NODE_COUNT(root_node) ++;
     
        CBTREE_NODE_KEY(left_node, CBTREE_NODE_COUNT(left_node)) = NULL_PTR;
        CBTREE_NODE_COUNT(left_node) --;    


        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_balance:[B] root_node is\n");
        __cbtree_node_print(LOGSTDNULL,  des_tree, root_node);             

        (*new_node) = root_node;
    }
    else
    {
        CBTREE_NODE *root_node;/*new root node of left*/

        root_node = cbtree_node_new(des_tree);
        if(NULL_PTR == root_node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge_balance: new cbtree node failed where left_node count %ld == min_intra %ld\n",
                                CBTREE_NODE_COUNT(left_node), CBTREE_MIN_INTR(des_tree));
            return (EC_FALSE);
        }
        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_balance:[C] new root_node %lx\n", root_node);

        CBTREE_NODE_CHILD(root_node, 0) = left_node;
        CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(left_node, CBTREE_NODE_COUNT(left_node) - 1);
        ASSERT(CBTREE_NODE_KEY(root_node, 0));
        CBTREE_NODE_COUNT(root_node) ++;

        CBTREE_NODE_KEY(left_node, CBTREE_NODE_COUNT(left_node) - 1) = NULL_PTR;
        CBTREE_NODE_COUNT(left_node) --;

        dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_balance:[C] root_node is\n");
        __cbtree_node_print(LOGSTDNULL, des_tree, root_node);       
     
        (*new_node) = root_node;
    }

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_balance:[4] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_balance:[4] des_tree is\n");
    cbtree_print(LOGSTDOUT, des_tree, CBTREE_ROOT_NODE(des_tree), 0, NULL_PTR);    
 
    return (EC_TRUE);
}

/*push all keys of leaf left_node to leaf right_node*/
static EC_BOOL __cbtree_merge_to_right_push_leaf(CBTREE *des_tree, CBTREE_NODE *left_node, CBTREE_NODE *right_node)
{
    uint8_t i;
    uint8_t j;
    uint8_t k;/*the num of keys expected to shift*/

    ASSERT(CBTREE_NODE_IS_LEAF(left_node));
    ASSERT(CBTREE_NODE_IS_LEAF(right_node));
 
    ASSERT(CBTREE_NODE_COUNT(left_node) + CBTREE_NODE_COUNT(right_node) <= CBTREE_ORDER(des_tree));

    k = CBTREE_NODE_COUNT(left_node);
    j = CBTREE_NODE_COUNT(right_node) + k;
    i = CBTREE_NODE_COUNT(right_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_leaf:[1] left_node is\n");
    __cbtree_node_print(LOGSTDNULL, des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_leaf:[1] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node); 

    CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);     
    for(j -- ; i -- > 0; j --)
    {    
        CBTREE_NODE_KEY(right_node  , j) = CBTREE_NODE_KEY(right_node, i);
    }

    /*now i is zero, j is k - 1*/
    i = CBTREE_NODE_COUNT(left_node);
    for(; i -- > 0; )
    {
        CBTREE_NODE_KEY(right_node, i)   = CBTREE_NODE_KEY(left_node, i);

        CBTREE_NODE_KEY(left_node, i)   = NULL_PTR;
    }

    CBTREE_NODE_CHILD(left_node, CBTREE_ORDER(des_tree) - 1) = NULL_PTR;

    CBTREE_NODE_COUNT(left_node)   = 0;
    CBTREE_NODE_COUNT(right_node) += k; 

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_leaf:[3] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);      

    cbtree_node_free(des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_leaf:[4] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);    

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_to_right_push_leaf:[4] des_tree is\n");
    cbtree_print(LOGSTDOUT, des_tree, CBTREE_ROOT_NODE(des_tree), 0, NULL_PTR);
    return (EC_TRUE);
}

/*push all keys and children of left_node to right_node*/
static EC_BOOL __cbtree_merge_to_right_push_all(CBTREE *des_tree, CBTREE_NODE *left_node, CBTREE_NODE *right_node)
{
    uint8_t i;
    uint8_t j;
    uint8_t k;/*the num of keys expected to shift*/

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_to_right_push_all: left_node %lx, right_node %lx\n", left_node, right_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_to_right_push_all:[0] des_tree is\n");
    cbtree_print(LOGSTDOUT, des_tree, CBTREE_ROOT_NODE(des_tree), 0, NULL_PTR);
 
    ASSERT(CBTREE_NODE_COUNT(left_node) + CBTREE_NODE_COUNT(right_node) < CBTREE_ORDER(des_tree));

    k = CBTREE_NODE_COUNT(left_node);
    j = CBTREE_NODE_COUNT(right_node) + k;
    i = CBTREE_NODE_COUNT(right_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_all:[1] left_node is\n");
    __cbtree_node_print(LOGSTDNULL, des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_all:[1] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node); 

    CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);     
    for(j -- ; i -- > 0; j --)
    {    
        CBTREE_NODE_KEY(right_node  , j) = CBTREE_NODE_KEY(right_node, i);
        CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);
    }

    /*now i is zero, j is k - 1*/
    i = CBTREE_NODE_COUNT(left_node);
    for(; i -- > 0; )
    {
        CBTREE_NODE_KEY(right_node, i)   = CBTREE_NODE_KEY(left_node, i);
        CBTREE_NODE_CHILD(right_node, i) = CBTREE_NODE_CHILD(left_node, i); 

        CBTREE_NODE_KEY(left_node, i)   = NULL_PTR;
        CBTREE_NODE_CHILD(left_node, i) = NULL_PTR;
    } 

    CBTREE_NODE_COUNT(left_node)   = 0;
    CBTREE_NODE_COUNT(right_node) += k; 

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_all:[3] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);      

    cbtree_node_free(des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_push_all:[4] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);    

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_to_right_push_all:[4] des_tree is\n");
    cbtree_print(LOGSTDOUT, des_tree, CBTREE_ROOT_NODE(des_tree), 0, NULL_PTR);
    return (EC_TRUE);
}

/*push all keys and children of right_node to left_node*/
static EC_BOOL __cbtree_merge_to_left_push_all(CBTREE *des_tree, CBTREE_NODE *left_node, CBTREE_NODE *right_node)
{
    uint8_t i;
    uint8_t j;
    uint8_t k;/*the num of keys expected to shift*/

    ASSERT(CBTREE_NODE_COUNT(left_node) + CBTREE_NODE_COUNT(right_node) + 1 < CBTREE_ORDER(des_tree));

    k = CBTREE_NODE_COUNT(right_node);
    j = CBTREE_NODE_COUNT(left_node);
    i = 0;

    CBTREE_NODE_KEY(left_node, j) = cbtree_node_get_r_key(NULL_PTR, CBTREE_NODE_CHILD(left_node, j));

    for(j ++; i < k; i ++, j ++)
    {
        CBTREE_NODE_KEY(left_node, j)   = CBTREE_NODE_KEY(right_node, i);
        CBTREE_NODE_CHILD(left_node, j) = CBTREE_NODE_CHILD(right_node, i);           
    }
    CBTREE_NODE_KEY(left_node, j - 1) = NULL_PTR;

    CBTREE_NODE_COUNT(left_node) += k;
    CBTREE_NODE_COUNT(right_node)-= k;

    cbtree_node_free(des_tree, right_node);
    return (EC_TRUE);
}

static EC_BOOL __cbtree_merge_to_right_at_leaf_level(CBTREE *des_tree, CBTREE_NODE *left_node, CBTREE_NODE *right_node, CBTREE_NODE **new_node)
{
    ASSERT(CBTREE_NODE_IS_LEAF(left_node));
    ASSERT(CBTREE_NODE_IS_LEAF(right_node));

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_to_right_at_leaf_level: left_node %lx, right_node %lx\n", left_node, right_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_at_leaf_level:[1] left_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_at_leaf_level:[1] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);  

    if(CBTREE_NODE_COUNT(left_node) + CBTREE_NODE_COUNT(right_node) <= CBTREE_ORDER(des_tree))
    {
        (*new_node) = NULL_PTR;
        return __cbtree_merge_to_right_push_leaf(des_tree, left_node, right_node);
    }
    else
    {
        CBTREE_NODE *root_node;/*new root node of left*/

        root_node = cbtree_node_new(des_tree);
        if(NULL_PTR == root_node)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge_to_right_at_leaf_level: new cbtree node failed\n");
            return (EC_FALSE);
        }

        CBTREE_NODE_CHILD(left_node, CBTREE_ORDER(des_tree) - 1) = right_node;

        /*note: root_node has zero key and one child*/
        CBTREE_NODE_CHILD(root_node, 0) = left_node;
        CBTREE_NODE_KEY(root_node, 0)   = CBTREE_NODE_KEY(left_node, CBTREE_NODE_COUNT(left_node) - 1);
        CBTREE_NODE_COUNT(root_node) ++;

        (*new_node) = root_node;
    }

    return (EC_TRUE);
}

static EC_BOOL __cbtree_merge_to_right_at_same_level(CBTREE *des_tree, CBTREE_NODE *left_node, CBTREE_NODE *right_node, const UINT32 limit, CBTREE_NODE **new_node)
{     
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_to_right_at_same_level: left_node %lx, right_node %lx\n", left_node, right_node);
 
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_at_same_level:[1] left_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right_at_same_level:[1] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);

    if(CBTREE_NODE_IS_LEAF(left_node))
    {
        ASSERT(CBTREE_NODE_IS_LEAF(right_node));

        CBTREE_NODE_COUNT(left_node) --;/*rollback*/

        return __cbtree_merge_to_right_at_leaf_level(des_tree, left_node, right_node, new_node);
    }
 
    ASSERT(!CBTREE_NODE_IS_LEAF(left_node));
    ASSERT(!CBTREE_NODE_IS_LEAF(right_node));
 
    if(CBTREE_NODE_COUNT(left_node) + CBTREE_NODE_COUNT(right_node) < limit)
    {
        (*new_node) = NULL_PTR;
        return __cbtree_merge_to_right_push_all(des_tree, left_node, right_node);
    }
 
    return __cbtree_merge_balance(des_tree, left_node, right_node, new_node);
}

static EC_BOOL __cbtree_merge_to_right(CBTREE *des_tree, CBTREE_NODE *left_node, CBTREE_NODE *right_node, const UINT32 height_delta, CBTREE_NODE **new_node)
{
    CBTREE_NODE *root_node;

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] __cbtree_merge_to_right: left_node %lx, right_node %lx\n", left_node, right_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right:[1] left_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, left_node);

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right:[1] right_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, right_node);
 
    if(0 == height_delta)
    {
        return __cbtree_merge_to_right_at_same_level(des_tree, left_node, right_node, CBTREE_ORDER(des_tree), new_node);
    }

    if(EC_FALSE == __cbtree_merge_to_right(des_tree, left_node, CBTREE_NODE_CHILD(right_node, 0), height_delta - 1, &root_node))
    {
        (*new_node) = NULL_PTR;
        return (EC_FALSE);
    }

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDNULL, "[DEBUG] __cbtree_merge_to_right:[1] root_node is\n");
    __cbtree_node_print(LOGSTDNULL,  des_tree, root_node);  

    if(NULL_PTR != root_node)
    {
        /*Oops, root_node has zero key and one child*/
        return __cbtree_merge_to_right_at_same_level(des_tree, root_node, right_node, CBTREE_ORDER(des_tree), new_node);
    }

    (*new_node) = NULL_PTR;
    return (EC_TRUE);
}

/*link leaf and accumulate size etc*/
static EC_BOOL __cbtree_merge_link(CBTREE *left_tree, CBTREE *right_tree, CBTREE *des_tree)
{
    CBTREE_NODE *right_most_leaf;/*right most leaf of left_tree*/
 
    CBTREE_SIZE(des_tree) = CBTREE_SIZE(left_tree) + CBTREE_SIZE(right_tree);
    CBTREE_TLEN(des_tree) = CBTREE_TLEN(left_tree) + CBTREE_TLEN(right_tree);

    right_most_leaf = cbtree_node_get_r_leaf(left_tree, CBTREE_ROOT_NODE(left_tree));
    CBTREE_NODE_CHILD(right_most_leaf, CBTREE_ORDER(left_tree) - 1) = CBTREE_LEFT_LEAF(right_tree);

    return (EC_TRUE);
}

static EC_BOOL __cbtree_merge(CBTREE *left_tree, CBTREE *right_tree, CBTREE **ret_tree)
{
    if(CBTREE_HEIGHT(left_tree) <= CBTREE_HEIGHT(right_tree))
    {
        CBTREE *des_tree;
        CBTREE_NODE *left_root_node;/*new root node*/
        CBTREE_NODE *right_root_node;/*new root node*/
        CBTREE_NODE *root_node;/*new root node*/
        UINT32 height_delta;
     
        des_tree = right_tree;
        height_delta = CBTREE_HEIGHT(right_tree) - CBTREE_HEIGHT(left_tree);
     
        __cbtree_merge_link(left_tree, right_tree, des_tree);\

        /*trick: pad one key*/
        left_root_node  = CBTREE_ROOT_NODE(left_tree);
        right_root_node = CBTREE_ROOT_NODE(right_tree);
        CBTREE_NODE_KEY(left_root_node, CBTREE_NODE_COUNT(left_root_node)) = cbtree_node_get_r_key(NULL_PTR, left_root_node);
        CBTREE_NODE_COUNT(left_root_node) ++;
    
        if(EC_FALSE == __cbtree_merge_to_right(des_tree, left_root_node, right_root_node, height_delta, &root_node))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge: merge to right tree failed\n");
            return (EC_FALSE);
        }

        if(NULL_PTR != root_node)
        {
            //CBTREE_NODE_KEY(root_node, 0)   = cbtree_node_get_r_key(NULL_PTR, root_node);
            CBTREE_NODE_CHILD(root_node, 1) = CBTREE_ROOT_NODE(des_tree);

            CBTREE_ROOT_NODE(des_tree) = root_node;
            CBTREE_SIZE(des_tree) ++;
        }

        CBTREE_LEFT_LEAF(des_tree) = cbtree_node_get_l_leaf(des_tree, CBTREE_ROOT_NODE(des_tree));

        (*ret_tree) = des_tree;
     
    }
    else
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_merge: merge to left tree not implemented yet\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

#if 0
/*merge right leaf node of right tree to left leaf node of left tree*/
static CBTREE_NODE *__cbtree_merge_leaf_left(CBTREE_NODE *left_node, CBTREE_NODE *right_node, uint8_t order)
{
    uint8_t left_count;
    uint8_t right_count;
    uint8_t div;
    uint8_t i;
    uint8_t j;
 
    left_count  = CBTREE_NODE_COUNT(left_node);
    right_count = CBTREE_NODE_COUNT(right_node);

    if(left_count + right_count < order)
    {
        j = left_count;
     
        for(i = 0; i < right_count; i ++, j ++)
        {
            CBTREE_NODE_KEY(left_node, j) = CBTREE_NODE_KEY(right_node, i);
            CBTREE_NODE_KEY(right_node, i) = NULL_PTR;xxx
        }
        for(j = left_count + right_count, i = right_count; j -- > left_count && i -- > 0;)
        {
            CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(right_node, i);
        }

        for(; j -- > 0;)
        {
            CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(left_node, j);
            CBTREE_NODE_KEY(left_node, j)  = NULL_PTR;
        }
     
        CBTREE_NODE_COUNT(right_node) += left_count;
        CBTREE_NODE_COUNT(left_node)   = 0;
 
        return (NULL_PTR);
    }

    div = (left_count + right_count) - order;
    for(j = order - 1, i = right_count; j -- > left_count - div && i -- > 0;)
    {
        CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(right_node, i);
    } 

    for(i = left_count; j -- > 0 && i -- > div;)
    {
        CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(left_node, i);
        CBTREE_NODE_KEY(left_node, i)  = NULL_PTR;
    }

    CBTREE_NODE_COUNT(right_node) += left_count - div;
    CBTREE_NODE_COUNT(left_node)   = div;
    CBTREE_NODE_FLAG(left_node) = CBTREE_NODE_ERR_FLAG;/*set it not leaf node*/

    return (left_node);
}

/*merge left leaf node of left tree to right leaf node of right tree*/
static CBTREE_NODE *__cbtree_merge_leaf_right(CBTREE *cbtree_left, CBTREE_NODE *left_node, CBTREE *cbtree_right, CBTREE_NODE *right_node)
{
    uint8_t left_count;
    uint8_t right_count;
    uint8_t order;
    uint8_t div;
    uint8_t i;
    uint8_t j;
 
    left_count  = CBTREE_NODE_COUNT(left_node);
    right_count = CBTREE_NODE_COUNT(right_node);
    order       = CBTREE_ORDER(cbtree_left);
 
    ASSERT(order == CBTREE_ORDER(cbtree_right));

    if(left_count + right_count < order)
    {
        for(j = left_count + right_count, i = right_count; j -- > left_count && i -- > 0;)
        {
            CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(right_node, i);
        }

        for(; j -- > 0;)
        {
            CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(left_node, j);
            CBTREE_NODE_KEY(left_node, j)  = NULL_PTR;
        }
     
        CBTREE_NODE_COUNT(right_node) += left_count;
        CBTREE_NODE_COUNT(left_node)   = 0;
 
        return (NULL_PTR);
    }

    div = (left_count + right_count) - order;
    for(j = order - 1, i = right_count; j -- > left_count - div && i -- > 0;)
    {
        CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(right_node, i);
    } 

    for(i = left_count; j -- > 0 && i -- > div;)
    {
        CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(left_node, i);
        CBTREE_NODE_KEY(left_node, i)  = NULL_PTR;
    }

    CBTREE_NODE_COUNT(right_node) += left_count - div;
    CBTREE_NODE_COUNT(left_node)   = div;
    CBTREE_NODE_FLAG(left_node) = CBTREE_NODE_ERR_FLAG;/*set it not leaf node*/

    return (left_node);
}

/*merge left node of left tree to right node of right tree*/
static CBTREE_NODE *__cbtree_merge_right(CBTREE *cbtree_left, CBTREE_NODE *left_node, CBTREE *cbtree_right, CBTREE_NODE *right_node)
{
    uint8_t left_count;
    uint8_t right_count;
    uint8_t order;
    uint8_t div;
    uint8_t i;
    uint8_t j; 

    CBTREE_NODE *right_most_leaf;

    if(CBTREE_NODE_IS_LEAF(left_node))
    {
        ASSERT(CBTREE_NODE_IS_LEAF(right_node));

        return __cbtree_merge_leaf_right(cbtree_left, left_node, cbtree_right, right_node);
    }

    left_count  = CBTREE_NODE_COUNT(left_node);
    right_count = CBTREE_NODE_COUNT(right_node);
    order       = CBTREE_ORDER(cbtree_left);
 
    ASSERT(order == CBTREE_ORDER(cbtree_right)); 

    if(left_count + right_count < order)
    {
        j = left_count + right_count;
        i = right_count;
        right_most_leaf =  cbtree_node_get_r_leaf(cbtree_left, left_node);
     
        CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);
     
        for(; j -- > left_count && i -- > 0;)
        {
            CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(right_node, i);
            CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);
        }

        CBTREE_NODE_KEY(left_node, j) = cbtree_node_get_r_key(cbtree_left, left_node);

        for(; j -- > 0;)
        {
            CBTREE_NODE_KEY(right_node, j)   = CBTREE_NODE_KEY(left_node, j);
            CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(left_node, j);
         
            CBTREE_NODE_KEY(left_node, j)   = NULL_PTR;
            CBTREE_NODE_CHILD(left_node, j) = NULL_PTR;
        }
     
        CBTREE_NODE_COUNT(right_node) += left_count;
        CBTREE_NODE_COUNT(left_node)   = 0;

        CBTREE_NODE_CHILD(right_most_leaf, order - 1) = CBTREE_LEFT_LEAF(cbtree_right);

        return (NULL_PTR);
    }

    div = (left_count + right_count) - order;
    j   = order - 1;
    i   = right_count;
 
    CBTREE_NODE_CHILD(right_most_leaf, order - 1) = CBTREE_LEFT_LEAF(cbtree_right);
 
    CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);     
    for(; j -- > left_count - div && i -- > 0;)
    {
        CBTREE_NODE_KEY(right_node, j) = CBTREE_NODE_KEY(right_node, i);
        CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(right_node, i);
    } 

    CBTREE_NODE_KEY(left_node, j) = cbtree_node_get_r_key(cbtree_left, left_node);
    for(i = left_count; j -- > 0 && i -- > div;)
    {
        CBTREE_NODE_KEY(right_node, j)   = CBTREE_NODE_KEY(left_node, i);
        CBTREE_NODE_CHILD(right_node, j) = CBTREE_NODE_CHILD(left_node, i);
     
        CBTREE_NODE_KEY(left_node, i)   = NULL_PTR;
        CBTREE_NODE_CHILD(left_node, i) = NULL_PTR;
    }

    CBTREE_NODE_COUNT(right_node) += left_count - div;
    CBTREE_NODE_COUNT(left_node) = div;
 
    return (left_node);
}

/*left tree and right tree has the same height*/
static CBTREE *__cbtree_merge_right_do(CBTREE *cbtree_left, CBTREE_NODE *left_root_node, CBTREE *cbtree_right, CBTREE_NODE *right_root_node, const uint8_t delta_height)
{
    if(0 == delta_height)
    {
        CBTREE_NODE *left_node;

        left_node = __cbtree_merge_right(cbtree_left, left_root_node, cbtree_right, right_root_node);
        if(NULL_PTR != left_node)
        {
            CBTREE_NODE_CHILD(left_node, CBTREE_NODE_COUNT(left_node)) = right_root_node;
            CBTREE_ROOT_NODE(cbtree_right) = left_node;
            CBTREE_LEFT_LEAF(cbtree_right) = cbtree_node_get_l_leaf(cbtree_right, left_node);
        }

        return (cbtree_right);
    }
    return __cbtree_merge_right_do(cbtree_left, left_root_node, cbtree_right, CBTREE_NODE_CHILD(right_root_node, 0), delta_height - 1);
}
#endif
CBTREE * cbtree_merge(CBTREE *cbtree_left, CBTREE *cbtree_right)
{
    CBTREE *cbtree_des;

    if(EC_FALSE == __cbtree_merge(cbtree_left, cbtree_right, &cbtree_des))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_merge: merge trees failed\n");
        return (NULL_PTR);
    }

    if(cbtree_des != cbtree_right)
    {
        CBTREE_ROOT_NODE(cbtree_right) = NULL_PTR;
        cbtree_free(cbtree_right);
    }

    if(cbtree_des != cbtree_left)
    {
        CBTREE_ROOT_NODE(cbtree_left) = NULL_PTR;
        cbtree_free(cbtree_left);
    } 
 
    //dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_merge: not implemented yet!\n");
    return (cbtree_des);
}

#endif
/*merge cbtree_left and cbtree_right where cbtree_left < cbtree_right*/
/*when return, do not use cbtree_left or cbtree_right again*/
CBTREE * cbtree_merge(CBTREE *cbtree_left, CBTREE *cbtree_right)
{
    CBTREE *cbtree_src;
    CBTREE *cbtree_des;
 
    CBTREE_NODE *leaf_node;

    if(CBTREE_SIZE(cbtree_left) <= CBTREE_SIZE(cbtree_right))
    {
        cbtree_src = cbtree_left;
        cbtree_des = cbtree_right;
    }
    else
    {
        cbtree_src = cbtree_right;
        cbtree_des = cbtree_left;
    }

    leaf_node = CBTREE_LEFT_LEAF(cbtree_src);
    for(leaf_node = CBTREE_LEFT_LEAF(cbtree_src); NULL_PTR != leaf_node; leaf_node = CBTREE_NODE_CHILD(leaf_node, CBTREE_ORDER(cbtree_src) - 1))
    {
        uint8_t i;

        for(i = 0; i < CBTREE_NODE_COUNT(leaf_node); i ++)
        {
            CBTREE_KEY *insert_key;
            insert_key = CBTREE_NODE_KEY(leaf_node, i);

            if(EC_FALSE == __cbtree_insert_do(cbtree_des, &insert_key))
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_merge: insert key to des tree %lx failed\n", cbtree_des);
                return (cbtree_des);
            }

            if(NULL_PTR != insert_key)
            {
                cbtree_key_free(cbtree_src, insert_key);
            }
            CBTREE_NODE_KEY(leaf_node, i) = NULL_PTR;
        }
    }

    cbtree_free(cbtree_src);
    return (cbtree_des);
}

EC_BOOL cbtree_key_encode_size(CBTREE *cbtree, CBTREE_KEY *cbtree_key, uint32_t *pos)
{
    uint8_t ver;
    uint8_t max_ver;
    uint32_t beg_pos;

    for(ver = 0, max_ver = 0; ver < CBTREE_MAX_VER(cbtree); ver ++, max_ver ++)
    {
        if(NULL_PTR == CBTREE_KEY_KV(cbtree_key, ver))
        {
            break;
        }
    }

    beg_pos = (*pos);

    (*pos) ++;/*max ver info*/
 
    for(ver = 0; ver < max_ver; ver ++)
    {
        if(EC_FALSE == CBTREE_KEY_ENCODE_SIZE_OP(cbtree)(CBTREE_KEY_KV(cbtree_key, ver), pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_encode_size: encode_size cbtree_key %lx ver %d # key %lx failed\n",
                                cbtree_key, ver, CBTREE_KEY_KV(cbtree_key, ver));
            return (EC_FALSE);
        }
    }

    if(CBTREE_KEY_MIN_SIZE > (*pos) - beg_pos)
    {
        uint32_t pad_len;
        pad_len = CBTREE_KEY_MIN_SIZE - ((*pos) - beg_pos);
        (*pos) += pad_len;
    } 

    return (EC_TRUE);
}

EC_BOOL cbtree_key_encode(CBTREE *cbtree, CBTREE_KEY *cbtree_key, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint8_t ver;
    uint8_t max_ver;
    uint32_t beg_pos;

    for(ver = 0, max_ver = 0; ver < CBTREE_MAX_VER(cbtree); ver ++, max_ver ++)
    {
        if(NULL_PTR == CBTREE_KEY_KV(cbtree_key, ver))
        {
            break;
        }
    }

    beg_pos = (*pos);

    if(sizeof(uint8_t) > size - (*pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_encode: left room is %d bytes, insufficient to accept ver info\n",
                            size - (*pos));
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_encode: size = %d, pos = %d\n", size, (*pos));
        return (EC_FALSE);
    }
 
    CBTREE_KEY_OFFSET(cbtree_key) = (*pos);
    gdbPut8(buff, pos, max_ver);
    //PRINT_BUFF("[DEBUG] cbtree_key_encode:[1] ", buff, beg_pos, (*pos));
 
    for(ver = 0; ver < max_ver; ver ++)
    {
        if(EC_FALSE == CBTREE_KEY_ENCODE_OP(cbtree)(CBTREE_KEY_KV(cbtree_key, ver), buff, size, pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_encode: encode cbtree_key %lx ver %d # key %lx failed\n",
                                cbtree_key, ver, CBTREE_KEY_KV(cbtree_key, ver));
            return (EC_FALSE);
        }
        //PRINT_BUFF("[DEBUG] cbtree_key_encode:[2] ", buff, beg_pos, (*pos));
    }

    if(CBTREE_KEY_MIN_SIZE > (*pos) - beg_pos)
    {
        uint32_t pad_len;
        pad_len = CBTREE_KEY_MIN_SIZE - ((*pos) - beg_pos);
     
        if(pad_len > size - (*pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_encode: left room is %d bytes, insufficient to accept %d pad info\n",
                                size - (*pos), pad_len);
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_encode: size = %d, pos = %d\n", size, (*pos));
            return (EC_FALSE);
        }
 
        gdbPutPad(buff, pos, (uint8_t)FILE_PAD_CHAR, pad_len);
    } 

    //PRINT_BUFF("[DEBUG] cbtree_key_encode: ", buff, beg_pos, (*pos));

    return (EC_TRUE);
}

/*WARNING: buff will be override, do not re-use it after return!*/
CBTREE_KEY * cbtree_key_decode(CBTREE *cbtree, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint8_t  max_ver;
    uint8_t  ver;
    uint32_t beg_pos;

    CBTREE_KEY *cbtree_key;
    CBTREE_KEY *cbtree_key_faked;
 
    if(sizeof(uint8_t) > size - (*pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_decode: left room is %d bytes, insufficient to decode ver info\n",
                            size - (*pos));
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_decode: size = %d, pos = %d\n", size, (*pos));
        return (NULL_PTR);
    }

    beg_pos = (*pos);

    cbtree_key_faked = (CBTREE_KEY *)(buff + (*pos));/*safe beginning buff*/

    max_ver = gdbGet8(buff, pos);
    if(max_ver > CBTREE_MAX_VERSION)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_decode: decoded version %d overflow the max supported version %d\n",
                            max_ver, CBTREE_MAX_VERSION);
        return (NULL_PTR);
    }

    cbtree_key = cbtree_key_new(cbtree);
    if(NULL_PTR == cbtree_key)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_decode: new cbtree_key failed\n");
        return (NULL_PTR);
    } 

    for(ver = 0; ver < max_ver; ver ++)
    {
        uint8_t *key;
        if(EC_FALSE == CBTREE_KEY_DECODE_OP(cbtree)(&key, buff, size, pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_decode: decode cbtree_key %lx ver %d # key failed\n",
                                cbtree_key, ver);
            cbtree_key_free(cbtree, cbtree_key);
            return (NULL_PTR);
        }

        CBTREE_KEY_KV(cbtree_key, ver) = key;
    }
    ASSERT(NULL_PTR != CBTREE_KEY_LATEST(cbtree_key));

    if(CBTREE_KEY_MIN_SIZE > (*pos) - beg_pos)
    {
        uint32_t pad_len;
        pad_len = CBTREE_KEY_MIN_SIZE - ((*pos) - beg_pos);
     
        if(pad_len > size - (*pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_decode: left room is %d bytes, insufficient to skip %d pad info\n",
                                size - (*pos), pad_len);
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_key_decode: size = %d, pos = %d\n", size, (*pos));
            cbtree_key_free(cbtree, cbtree_key);
            return (NULL_PTR);
        }
 
        gdbGetPad(buff, pos, NULL_PTR, pad_len);
    }  

    /*save cbtree_key address info to buff_beg*/
    CBTREE_KEY_PTR(cbtree_key_faked) = cbtree_key;/*trick!*/ 
    //ASSERT(NULL_PTR != CBTREE_KEY_LATEST(cbtree_key));
    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_key_decode: update ptr at offset %d, key %lx, encoded_size %d\n", beg_pos, cbtree_key, (*pos) - beg_pos);

    return (cbtree_key);
}

EC_BOOL cbtree_node_encode_size(CBTREE *cbtree, CBTREE_NODE *root_node, uint32_t *pos)
{
    uint8_t idx;
    uint32_t beg_pos;

    ASSERT(NULL_PTR != root_node);

    beg_pos = (*pos);

    if(CBTREE_NODE_IS_LEAF(root_node))
    {
        CBTREE_NODE *next_node;/*next leaf node*/
     
         next_node = CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1);
     
        (*pos) += 1 /*count*/
                + 1 /*flag*/
                + 2 /*rsvd*/
                + sizeof(uint32_t)/*next leaf node offset*/
                ;

        for(idx = CBTREE_NODE_COUNT(root_node); idx -- > 0;)
        {
            CBTREE_KEY *cbtree_key;
            cbtree_key = CBTREE_NODE_KEY(root_node, idx);
         
            if(EC_FALSE == cbtree_key_encode_size(cbtree, cbtree_key, pos))
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode_size: encode %d # key %lx of leaf node %lx failed\n",
                                    idx, cbtree_key, root_node);
                return (EC_FALSE);
            }
        }
    }
    else
    {
        /*encode in depth and from most right child to most left child*/
        for(idx = CBTREE_NODE_COUNT(root_node) + 1; idx -- > 0;)
        {
            CBTREE_NODE *child_node;
            child_node = CBTREE_NODE_CHILD(root_node, idx);
         
            if(EC_FALSE == cbtree_node_encode_size(cbtree, child_node, pos))
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode_size: encode intr node %lx child %d # %lx failed\n",
                                    root_node, idx, child_node);
                return (EC_FALSE);
            }
        }

        (*pos) += 1 /*count*/
                + 1 /*flag */
                + 2 /*rsvd */
                + 4 /*rsvd2*/             
                + sizeof(uint32_t) * (CBTREE_NODE_COUNT(root_node) + 1)/*children offset*/
                + sizeof(uint32_t) * (CBTREE_NODE_COUNT(root_node)) /*keys offset*/
                ;
    }

    if(CBTREE_NODE_MIN_SIZE > (*pos) - beg_pos)
    {
        uint32_t pad_len;
        pad_len = CBTREE_NODE_MIN_SIZE - ((*pos) - beg_pos);
        (*pos) += pad_len;
    }

    return (EC_TRUE);
}

EC_BOOL cbtree_node_encode(CBTREE *cbtree, CBTREE_NODE *root_node, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint8_t idx;
    uint32_t beg_pos;

    ASSERT(NULL_PTR != root_node);

    if(0)/*debug*/
    {
        if(CBTREE_NODE_IS_LEAF(root_node))
        {
            dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_encode: tree %lx, root_node %lx is leaf, order %d, next is %lx\n",
                                cbtree, root_node, CBTREE_ORDER(cbtree), CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1));
        }
    }

    beg_pos = (*pos);

    if(CBTREE_NODE_IS_LEAF(root_node))
    {
        CBTREE_NODE *next_node;/*next leaf node*/
     
        if(
          sizeof(uint8_t) /*count*/
        + sizeof(uint8_t) /*flag*/     
        + sizeof(uint16_t)/*rsvd*/
        + sizeof(uint32_t)/*next leaf node offset*/
        > size - (*pos)
        )
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: left room is %d bytes, insufficient to accept leaf node count,flag and next leaf node offset info\n",
                                size - (*pos));
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: size = %d, pos = %d\n", size, (*pos));
            return (EC_FALSE);
        }

        next_node = CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1);
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_encode: tree %lx, leaf %lx ---> next %lx\n", cbtree, root_node, next_node);
     
        CBTREE_NODE_OFFSET(root_node) = (*pos);/*encode leaf node from here*/

        gdbPut8(buff, pos, CBTREE_NODE_COUNT(root_node));
        gdbPut8(buff, pos, CBTREE_NODE_FLAG(root_node));
        gdbPutPad(buff, pos, (uint8_t)FILE_PAD_CHAR, sizeof(uint16_t)/* + sizeof(uint32_t)*/);

        if(NULL_PTR == next_node)
        {
            gdbPut32(buff, pos, (uint32_t)CBTREE_ERR_OFFSET);/*reach tail leaf node*/
            //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_encode: tree %lx, next_node %lx put next_offset = %d\n", cbtree, next_node, CBTREE_ERR_OFFSET);
        }
        else
        {
            gdbPut32(buff, pos, CBTREE_NODE_OFFSET(next_node));/*save next leaf node offset info*/         
            //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_encode: tree %lx, next_node %lx put next_offset = %d\n", cbtree, next_node, CBTREE_NODE_OFFSET(next_node));
        }

        for(idx = CBTREE_NODE_COUNT(root_node); idx -- > 0;)
        {
            CBTREE_KEY *cbtree_key;
            cbtree_key = CBTREE_NODE_KEY(root_node, idx);
         
            if(EC_FALSE == cbtree_key_encode(cbtree, cbtree_key, buff, size, pos))
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: encode %d # key %lx of leaf node %lx failed\n",
                                    idx, cbtree_key, root_node);
                return (EC_FALSE);
            }
        }
    }
    else
    {
        /*encode in depth and from most right child to most left child*/
        for(idx = CBTREE_NODE_COUNT(root_node) + 1; idx -- > 0;)
        {
            CBTREE_NODE *child_node;
            child_node = CBTREE_NODE_CHILD(root_node, idx);
         
            if(EC_FALSE == cbtree_node_encode(cbtree, child_node, buff, size, pos))
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: encode intr node %lx child %d # %lx failed\n",
                                    root_node, idx, child_node);
                return (EC_FALSE);
            }
        }
     
        if(
          sizeof(uint8_t) /*count*/
        + sizeof(uint8_t) /*flag*/
        + sizeof(uint16_t)/*rsvd*/
        + sizeof(uint32_t)/*rsvd2*/     
        + sizeof(uint32_t) * CBTREE_NODE_COUNT(root_node)       /*keys offset    */
        + sizeof(uint32_t) * (CBTREE_NODE_COUNT(root_node) + 1) /*children offset*/
        > size - (*pos)
        )
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: left room is %d bytes, insufficient to accept intr node count,flag info\n",
                                size - (*pos));
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: size = %d, pos = %d\n", size, (*pos));
            return (EC_FALSE);
        }
     
        CBTREE_NODE_OFFSET(root_node) = (*pos);/*encode internal node from here*/
     
        gdbPut8(buff, pos, CBTREE_NODE_COUNT(root_node));
        gdbPut8(buff, pos, CBTREE_NODE_FLAG(root_node));
        gdbPutPad(buff, pos, (uint8_t)FILE_PAD_CHAR, sizeof(uint16_t) + sizeof(uint32_t));
    
        /*encode children offset*/
        for(idx = CBTREE_NODE_COUNT(root_node) + 1; idx -- > 0;)
        {
            CBTREE_NODE *child_node;
            child_node = CBTREE_NODE_CHILD(root_node, idx);
            gdbPut32(buff, pos, CBTREE_NODE_OFFSET(child_node));
        }
     
        /*encode keys offset*/
        for(idx = CBTREE_NODE_COUNT(root_node); idx -- > 0;)
        {
            CBTREE_KEY *cbtree_key;
            cbtree_key = CBTREE_NODE_KEY(root_node, idx);
            gdbPut32(buff, pos, CBTREE_KEY_OFFSET(cbtree_key));
        }     
    }

    if(CBTREE_NODE_MIN_SIZE > (*pos) - beg_pos)
    {
        uint32_t pad_len;
        pad_len = CBTREE_NODE_MIN_SIZE - ((*pos) - beg_pos);
     
        if(pad_len > size - (*pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: left room is %d bytes, insufficient to accept %d pad info\n",
                                size - (*pos), pad_len);
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_encode: size = %d, pos = %d\n", size, (*pos));
            return (EC_FALSE);
        }
 
        gdbPutPad(buff, pos, (uint8_t)FILE_PAD_CHAR, pad_len);
    }

    //PRINT_BUFF("[DEBUG] cbtree_node_encode: ", buff, beg_pos, (*pos));
 
    return (EC_TRUE);
}

CBTREE_NODE *cbtree_node_decode(CBTREE *cbtree, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    CBTREE_NODE *root_node;
    CBTREE_NODE *root_node_faked;
    uint32_t beg_pos;
    uint8_t idx;
    uint8_t count;
    uint8_t flag;

    if(
      sizeof(uint8_t) /*count*/
    + sizeof(uint8_t) /*flag*/
    + sizeof(uint16_t)/*rsvd*/
    + sizeof(uint32_t)/*rsvd2 or offset*/ 
    > size - (*pos)
    )
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: left room is %d bytes, insufficient to decode node count,flag info\n",
                            size - (*pos));
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: size = %d, pos = %d\n", size, (*pos));                         
        return (NULL_PTR);
    }

    beg_pos = (*pos);
    root_node_faked = (CBTREE_NODE *)(buff + (*pos));/*save beginning buff*/

    root_node = cbtree_node_new(cbtree);
    if(NULL_PTR == root_node)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: new cbtree node failed\n");
        return (NULL_PTR);
    }

    count = gdbGet8(buff, pos);
    flag  = gdbGet8(buff, pos);
    gdbGetPad(buff, pos, NULL_PTR, sizeof(uint16_t)/* + sizeof(uint32_t)*/);

    /*set count and flag at first which will make the exceptional procedure smooth*/
    CBTREE_NODE_COUNT(root_node) = count;
    CBTREE_NODE_FLAG(root_node)  = flag; 

    if(CBTREE_NODE_LEAF_FLAG == flag)/*decode leaf node*/
    {
        CBTREE_NODE *next_node;/*next leaf node*/
        uint32_t next_node_offset;

        /*get next leaf node*/
        next_node_offset = gdbGet32(buff, pos);
        if(CBTREE_ERR_OFFSET == next_node_offset)
        {
            next_node = NULL_PTR;
        }
        else
        {
            next_node = CBTREE_NODE_PTR((CBTREE_NODE *)(buff + next_node_offset));
        }
        CBTREE_NODE_CHILD(root_node, CBTREE_ORDER(cbtree) - 1) = next_node;

        /*decode keys*/
        for(idx = count; idx -- > 0;)
        {
            CBTREE_KEY *cbtree_key;
            //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_decode: on leaf, [beg] tree %lx, key %d#, beg offset %d\n", cbtree, idx, (*pos));
         
            cbtree_key = cbtree_key_decode(cbtree, buff, size, pos);
            if(NULL_PTR == cbtree_key)
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: decode key # %d of leaf node at offset %d failed\n",
                                    idx, beg_pos);
                cbtree_node_free(cbtree, root_node);
                return (NULL_PTR);
            }         
            CBTREE_NODE_KEY(root_node, idx) = cbtree_key;
            //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_decode: on leaf, [end] tree %lx, key %d#, end offset %d => %lx\n", cbtree, idx, (*pos), cbtree_key);
         
            //ASSERT(NULL_PTR != CBTREE_KEY_LATEST(cbtree_key));
        }     
    }
    else/*decode intra node*/
    {
        gdbGetPad(buff, pos, NULL_PTR, /*sizeof(uint16_t) + */sizeof(uint32_t));
     
        if(
        + sizeof(uint32_t) * count       /*keys offset    */
        + sizeof(uint32_t) * (count + 1) /*children offset*/
        > size - (*pos)
        )
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: left room is %d bytes, insufficient to decode %d keys, children offset info\n",
                                size - (*pos), count);
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: size = %d, pos = %d\n", size, (*pos));
            cbtree_node_free(cbtree, root_node);
            return (NULL_PTR);
        }
    
        /*decode children*/
        for(idx = count + 1; idx -- > 0;)
        {
            uint32_t child_offset;
            CBTREE_NODE *child_node;

            /*decode child offset*/
            child_offset = gdbGet32(buff, pos);

            /*decode child*/
            child_node = cbtree_node_decode(cbtree, buff, size, &child_offset);
            if(NULL_PTR == child_node)
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: decode child failed\n");
                cbtree_node_free(cbtree, root_node);
                return (NULL_PTR);
            }
            CBTREE_NODE_CHILD(root_node, idx) = child_node;
        }

        /*get keys*/
        for(idx = count; idx -- > 0;)
        {
            uint32_t key_offset;
            CBTREE_KEY *cbtree_key;

            /*decode key offset*/
            key_offset = gdbGet32(buff, pos);

            /*get key from the offset*/
            cbtree_key = CBTREE_KEY_PTR((CBTREE_KEY *)(buff + key_offset));
            CBTREE_NODE_KEY(root_node, idx) = cbtree_key;
            //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_decode: on intra, tree %lx, key %d#, offset %d => %lx\n", cbtree, idx, key_offset, cbtree_key);
            //ASSERT(NULL_PTR != CBTREE_KEY_LATEST(cbtree_key));
        }     
    }

    if(CBTREE_NODE_MIN_SIZE > (*pos) - beg_pos)
    {
        uint32_t pad_len;
        pad_len = CBTREE_NODE_MIN_SIZE - ((*pos) - beg_pos);
     
        if(pad_len > size - (*pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: left room is %d bytes, insufficient to skip %d pad info\n",
                                size - (*pos), pad_len);
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_node_decode: size = %d, pos = %d\n", size, (*pos));
            cbtree_node_free(cbtree, root_node);
            return (NULL_PTR);
        }
 
        gdbGetPad(buff, pos, NULL_PTR, pad_len);
    }
 
    /*save cbtree_node address info to buff_beg*/
    CBTREE_NODE_PTR(root_node_faked) = root_node;/*trick!*/
    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_node_decode: update ptr at offset %d, encoded_size %d\n", beg_pos, (*pos) - beg_pos);
 
    return (root_node); 
}

EC_BOOL cbtree_encode_size(CBTREE *cbtree, uint32_t *pos)
{   
    (*pos) += CBTREE_HDR_OFFSET;
    if(NULL_PTR != cbtree && NULL_PTR != CBTREE_ROOT_NODE(cbtree))
    {
        CBTREE_NODE *root_node;

        root_node = CBTREE_ROOT_NODE(cbtree);
    
        if(EC_FALSE == cbtree_node_encode_size(cbtree, root_node, pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode_size: encode root node %lx failed\n", root_node);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

static void __cbtree_leaf_checker(CBTREE *cbtree, LOG *log)
{
    CBTREE_NODE *leaf_node;

    if(NULL_PTR == cbtree || NULL_PTR == CBTREE_LEFT_LEAF(cbtree))
    {
        return;
    }

    sys_log(log, "[DEBUG] __cbtree_leaf_checker: tree %lx basic info:\n", cbtree);
    cbtree_print_itself(log, cbtree); 

    leaf_node = CBTREE_LEFT_LEAF(cbtree);
    while(NULL_PTR != leaf_node)
    {
        sys_log(log, "[DEUBG] __cbtree_leaf_checker: tree %lx, leaf %lx ---> next %lx\n",
                            cbtree, leaf_node, CBTREE_NODE_CHILD(leaf_node, CBTREE_ORDER(cbtree) - 1));
        leaf_node = CBTREE_NODE_CHILD(leaf_node, CBTREE_ORDER(cbtree) - 1);
    }
    return;
}

EC_BOOL cbtree_encode(CBTREE *cbtree, uint8_t *buff, const uint32_t size, uint32_t *pos)
{
    uint32_t beg_pos;

    if(do_log(SEC_0050_CBTREE, 9))
    {
        __cbtree_leaf_checker(cbtree, LOGSTDOUT);
    }
 
    if(CBTREE_HDR_OFFSET > size - (*pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: left room is %d bytes, insufficient to accept cbtree header info\n",
                            size - (*pos));
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: size = %d, pos = %d\n", size, (*pos));
        return (EC_FALSE);
    } 

    if(NULL_PTR == cbtree)
    {
        beg_pos = (*pos);
     
        gdbPut32(buff, pos, (uint32_t)0);/*tree size*/
        gdbPut8(buff , pos, (uint8_t) 0);/*tree order*/
        gdbPut8(buff , pos, (uint8_t) 0);/*tree max version*/
        gdbPut8(buff , pos, (uint8_t) 0);/*tree height*/
        gdbPut8(buff , pos, CBTREE_IS_ERR_TYPE);/*tree key type*/
        gdbPut32(buff, pos, (uint32_t)0);/*tree total len of all keys*/
        gdbPut32(buff, pos, CBTREE_ERR_OFFSET);/*tree root node offset*/
        gdbPut32(buff, pos, CBTREE_ERR_OFFSET);/*tree left most node offset*/

        if(CBTREE_HDR_OFFSET < (*pos) - beg_pos)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: overhead cbtree header info!\n");
            return (EC_FALSE);         
        }
        gdbPutPad(buff, pos, (uint8_t)FILE_PAD_CHAR, CBTREE_HDR_OFFSET - (*pos));
    }

    else if(NULL_PTR == CBTREE_ROOT_NODE(cbtree))
    {
        beg_pos = (*pos);
     
        gdbPut32(buff, pos, CBTREE_SIZE(cbtree));/*tree size*/
        gdbPut8(buff , pos, CBTREE_ORDER(cbtree));/*tree order*/
        gdbPut8(buff , pos, CBTREE_MAX_VER(cbtree));/*tree max version*/
        gdbPut8(buff , pos, CBTREE_HEIGHT(cbtree));/*tree height*/
        gdbPut8(buff , pos, CBTREE_KEY_TYPE(cbtree));/*tree key type*/
        gdbPut32(buff, pos, CBTREE_TLEN(cbtree));/*tree total len of all keys*/
        gdbPut32(buff, pos, CBTREE_ERR_OFFSET);/*tree root node offset*/
        gdbPut32(buff, pos, CBTREE_ERR_OFFSET);/*tree left most node offset*/

        if(CBTREE_HDR_OFFSET < (*pos) - beg_pos)
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: overhead cbtree header info!\n");
            return (EC_FALSE);         
        }
        gdbPutPad(buff, pos, (uint8_t)FILE_PAD_CHAR, CBTREE_HDR_OFFSET - (*pos));
    }
    else
    {
        CBTREE_NODE *root_node;
        CBTREE_NODE *left_leaf;

        root_node = CBTREE_ROOT_NODE(cbtree);
        left_leaf = CBTREE_LEFT_LEAF(cbtree);
    
        if(EC_FALSE == cbtree_node_encode(cbtree, root_node, buff, size, pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: encode root node %lx failed\n", root_node);
            return (EC_FALSE);
        }

        if(CBTREE_HDR_OFFSET > size - (*pos))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: insufficient to accept cbtree header info\n");
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: size = %d, pos = %d\n", size, (*pos));
            return (EC_FALSE);         
        }

        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_encode: CBTREE_NODE_OFFSET(root_node) = %d\n", CBTREE_NODE_OFFSET(root_node));
        //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_encode: CBTREE_NODE_OFFSET(left_leaf) = %d\n", CBTREE_NODE_OFFSET(left_leaf));

        beg_pos = (*pos);

        gdbPut32(buff, pos, CBTREE_SIZE(cbtree));/*tree size*/
        gdbPut8(buff , pos, CBTREE_ORDER(cbtree));/*tree order*/
        gdbPut8(buff , pos, CBTREE_MAX_VER(cbtree));/*tree max version*/
        gdbPut8(buff , pos, CBTREE_HEIGHT(cbtree));/*tree height*/
        gdbPut8(buff , pos, CBTREE_KEY_TYPE(cbtree));/*tree key type*/
        gdbPut32(buff, pos, CBTREE_TLEN(cbtree));/*tree total len of all keys*/
        gdbPut32(buff, pos, CBTREE_NODE_OFFSET(root_node));/*tree root node offset*/
        gdbPut32(buff, pos, CBTREE_NODE_OFFSET(left_leaf));/*tree left most node offset*/   

        if(CBTREE_HDR_OFFSET > (*pos) - beg_pos)
        {
            uint32_t pad_len;
            pad_len = CBTREE_HDR_OFFSET - ((*pos) - beg_pos);
         
            if(pad_len > size - (*pos))
            {
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: left room is %d bytes, insufficient to accept %d pad info\n",
                                    size - (*pos), pad_len);
                dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_encode: size = %d, pos = %d\n", size, (*pos));
                return (EC_FALSE);
            }
     
            gdbPutPad(buff, pos, (uint8_t)FILE_PAD_CHAR, pad_len);
        }
        //PRINT_BUFF("[DEBUG] cbtree_encode: header: ", buff, beg_pos_t, (*pos));
    }

    PRINT_BUFF("[DEBUG] cbtree_encode: ", buff, beg_pos, (*pos));
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_encode: size = %d, pos = %d\n", size, (*pos));

    return (EC_TRUE);
}

CBTREE * cbtree_decode(uint8_t *buff, const uint32_t size)
{
    CBTREE *cbtree;

    uint32_t  tree_size;     
    uint8_t   tree_order;    
    uint8_t   tree_max_ver;
    uint8_t   tree_height;
    uint8_t   tree_key_type; 
    uint32_t  tree_tlen;
 
    uint32_t  beg_pos;
    uint32_t  cur_pos;
    uint32_t *pos;
    uint32_t  root_node_offset;
    uint32_t  left_node_offset;

    if(CBTREE_HDR_OFFSET > size)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_decode: left room is %d bytes, insufficient to decode cbtree header info\n",
                            size);     
        return (NULL_PTR);
    }

    beg_pos = (size - CBTREE_HDR_OFFSET);/*btree header info is at the tail of the buff*/
    pos     = &cur_pos;

    (*pos) = beg_pos;

    tree_size         = gdbGet32(buff, pos);/*tree size*/
    tree_order        = gdbGet8(buff , pos);/*tree order*/
    tree_max_ver      = gdbGet8(buff , pos);/*tree max version*/
    tree_height       = gdbGet8(buff , pos);/*tree height*/
    tree_key_type     = gdbGet8(buff , pos);/*tree key type*/
    tree_tlen         = gdbGet32(buff, pos);/*tree total len of all keys*/
    root_node_offset  = gdbGet32(buff, pos);/*tree root node offset*/
    left_node_offset  = gdbGet32(buff, pos);/*tree left most node offset*/
#if 0
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] tree_size        = %d\n", tree_size);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] tree_order       = %d\n", tree_order);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] tree_max_ver     = %d\n", tree_max_ver);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] tree_key_type    = %d\n", tree_key_type);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] tree_tlen        = %d\n", tree_tlen);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] root_node_offset = %d\n", root_node_offset);
    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] left_node_offset = %d\n", left_node_offset);
#endif
    if(CBTREE_HDR_OFFSET < (*pos) - beg_pos)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_decode: overhead cbtree header info!\n");
        return (NULL_PTR);         
    }

    gdbGetPad(buff, pos, NULL_PTR, CBTREE_HDR_OFFSET - (*pos)); 

    if(
       0 == tree_size
    || 0 == tree_order
    || 0 == tree_max_ver
    || CBTREE_IS_ERR_TYPE == tree_key_type
    )
    {
        return (NULL_PTR);
    }

    cbtree = cbtree_new(tree_order, tree_max_ver, tree_key_type);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_decode: new cbtree failed\n");
        return (NULL_PTR);
    } 

    CBTREE_SIZE(cbtree)   = tree_size;
    CBTREE_HEIGHT(cbtree) = tree_height;
    CBTREE_TLEN(cbtree)   = tree_tlen; 
 
    if(
       CBTREE_ERR_OFFSET != root_node_offset
    && CBTREE_ERR_OFFSET != left_node_offset
    )
    {
        (*pos) = root_node_offset;
        CBTREE_ROOT_NODE(cbtree) = cbtree_node_decode(cbtree, buff, size, pos);
        if(NULL_PTR == CBTREE_ROOT_NODE(cbtree))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_decode: decode root node at offset %d failed\n", root_node_offset);
            cbtree_free(cbtree);
            return (NULL_PTR);
        }
     
        CBTREE_LEFT_LEAF(cbtree) = CBTREE_NODE_PTR((CBTREE_NODE *)(buff + left_node_offset));     
        if(NULL_PTR == CBTREE_LEFT_LEAF(cbtree))
        {
            dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_decode: get left leaf node at offset %d failed\n", left_node_offset);
            cbtree_free(cbtree);
            return (NULL_PTR);
        }
    }
 
    return (cbtree);
}

static EC_BOOL __cbtree_key_is_equal(const CBTREE *cbtree, const CBTREE_KEY *cbtree_key_1st, const CBTREE_KEY *cbtree_key_2nd)
{
    if(cbtree_key_1st == cbtree_key_2nd)
    {
        return (EC_TRUE);
    }
 
    if(NULL_PTR == cbtree_key_1st && NULL_PTR == cbtree_key_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cbtree_key_1st || NULL_PTR == cbtree_key_2nd)
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_key_is_equal: cbtree_key_1st = %lx but cbtree_key_2nd = %lx\n",
                            cbtree_key_1st,
                            cbtree_key_2nd);
        return (EC_FALSE);
    }

    if(0 != cbtree_key_cmp(cbtree, cbtree_key_1st, cbtree_key_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_key_is_equal: cbtree_key_1st = %lx not equal to cbtree_key_2nd = %lx\n",
                            cbtree_key_1st,
                            cbtree_key_2nd);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

static EC_BOOL __cbtree_node_is_equal(const CBTREE *cbtree, const CBTREE_NODE *cbtree_node_1st, const CBTREE_NODE *cbtree_node_2nd)
{
    UINT32    idx;
    uint8_t   count;
    uint8_t   flag;
 
    if(cbtree_node_1st == cbtree_node_2nd)
    {
        return (EC_TRUE);
    }
 
    if(NULL_PTR == cbtree_node_1st && NULL_PTR == cbtree_node_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cbtree_node_1st || NULL_PTR == cbtree_node_2nd)
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_node_is_equal: cbtree_node_1st = %lx but cbtree_node_2nd = %lx\n",
                            cbtree_node_1st,
                            cbtree_node_2nd);
        return (EC_FALSE);
    }

    if(CBTREE_NODE_COUNT(cbtree_node_1st) != CBTREE_NODE_COUNT(cbtree_node_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_node_is_equal: cbtree_node_1st %lx count = %d but cbtree_node_2nd %lx count = %d\n",
                            cbtree_node_1st, CBTREE_NODE_COUNT(cbtree_node_1st),
                            cbtree_node_2nd, CBTREE_NODE_COUNT(cbtree_node_2nd));
        return (EC_FALSE);
    }

    count = CBTREE_NODE_COUNT(cbtree_node_1st);

    if(CBTREE_NODE_FLAG(cbtree_node_1st) != CBTREE_NODE_FLAG(cbtree_node_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_node_is_equal: cbtree_node_1st %lx flag = %d but cbtree_node_2nd %lx flag = %d\n",
                            cbtree_node_1st, CBTREE_NODE_FLAG(cbtree_node_1st),
                            cbtree_node_2nd, CBTREE_NODE_FLAG(cbtree_node_2nd));
        return (EC_FALSE);
    } 

    flag = CBTREE_NODE_FLAG(cbtree_node_1st);

    for(idx = 0; idx < count; idx ++)
    {
        CBTREE_KEY *cbtree_key_1st;
        CBTREE_KEY *cbtree_key_2nd;

        cbtree_key_1st = CBTREE_NODE_KEY(cbtree_node_1st, idx);
        cbtree_key_2nd = CBTREE_NODE_KEY(cbtree_node_2nd, idx);
     
        if(EC_FALSE == __cbtree_key_is_equal(cbtree, cbtree_key_1st, cbtree_key_2nd))
        {
            dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_node_is_equal: mismatched key %d #: cbtree_node_1st %lx key %lx and cbtree_node_2nd %lx key %lx\n",
                               idx,
                               cbtree_node_1st, cbtree_key_1st,
                               cbtree_node_2nd, cbtree_key_2nd);
            return (EC_FALSE);
        }
    }

    if(CBTREE_NODE_LEAF_FLAG == flag)
    {
        return (EC_TRUE);
    }

    for(idx = 0; idx <= count; idx ++)
    {
        CBTREE_NODE *child_node_1st;
        CBTREE_NODE *child_node_2nd;

        child_node_1st = CBTREE_NODE_CHILD(cbtree_node_1st, idx);
        child_node_2nd = CBTREE_NODE_CHILD(cbtree_node_2nd, idx);
     
        if(EC_FALSE == __cbtree_node_is_equal(cbtree, child_node_1st, child_node_2nd))
        {
            dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_node_is_equal: mismatched child %d #: cbtree_node_1st %lx child %lx and cbtree_node_2nd %lx child %lx\n",
                               idx,
                               cbtree_node_1st, child_node_1st,
                               cbtree_node_2nd, child_node_2nd);
            return (EC_FALSE);
        }
    } 
 
    return (EC_TRUE);
}

static EC_BOOL __cbtree_is_equal(const CBTREE *cbtree_1st, const CBTREE *cbtree_2nd)
{
    if(cbtree_1st == cbtree_2nd)
    {
        return (EC_TRUE);
    }
 
    if(NULL_PTR == cbtree_1st && NULL_PTR == cbtree_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cbtree_1st || NULL_PTR == cbtree_2nd)
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st = %lx but cbtree_2nd = %lx\n",
                            cbtree_1st,
                            cbtree_2nd);
        return (EC_FALSE);
    }

    if(CBTREE_SIZE(cbtree_1st) != CBTREE_SIZE(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx size = %d but cbtree_2nd %lx size = %d\n",
                            cbtree_1st, CBTREE_SIZE(cbtree_1st),
                            cbtree_2nd, CBTREE_SIZE(cbtree_2nd));
        return (EC_FALSE);
    }

    if(CBTREE_ORDER(cbtree_1st) != CBTREE_ORDER(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx order = %d but cbtree_2nd %lx order = %d\n",
                            cbtree_1st, CBTREE_ORDER(cbtree_1st),
                            cbtree_2nd, CBTREE_ORDER(cbtree_2nd));
        return (EC_FALSE);
    } 

    if(CBTREE_MAX_VER(cbtree_1st) != CBTREE_MAX_VER(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx max ver = %d but cbtree_2nd %lx max ver = %d\n",
                            cbtree_1st, CBTREE_MAX_VER(cbtree_1st),
                            cbtree_2nd, CBTREE_MAX_VER(cbtree_2nd));
        return (EC_FALSE);
    } 

    if(CBTREE_HEIGHT(cbtree_1st) != CBTREE_HEIGHT(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx height = %d but cbtree_2nd %lx height = %d\n",
                            cbtree_1st, CBTREE_HEIGHT(cbtree_1st),
                            cbtree_2nd, CBTREE_HEIGHT(cbtree_2nd));
        return (EC_FALSE);
    } 

    if(CBTREE_KEY_TYPE(cbtree_1st) != CBTREE_KEY_TYPE(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx key type = %d but cbtree_2nd %lx key type = %d\n",
                            cbtree_1st, CBTREE_KEY_TYPE(cbtree_1st),
                            cbtree_2nd, CBTREE_KEY_TYPE(cbtree_2nd));
        return (EC_FALSE);
    }

    if(CBTREE_MIN_LEAF(cbtree_1st) != CBTREE_MIN_LEAF(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx min_leaf = %d but cbtree_2nd %lx min_leaf = %d\n",
                            cbtree_1st, CBTREE_MIN_LEAF(cbtree_1st),
                            cbtree_2nd, CBTREE_MIN_LEAF(cbtree_2nd));
        return (EC_FALSE);
    }   

    if(CBTREE_MIN_INTR(cbtree_1st) != CBTREE_MIN_INTR(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "cbtree_cmp: cbtree_1st %lx min_intr = %d but cbtree_2nd %lx min_intr = %d\n",
                            cbtree_1st, CBTREE_MIN_INTR(cbtree_1st),
                            cbtree_2nd, CBTREE_MIN_INTR(cbtree_2nd));
        return (EC_FALSE);
    }   

    if(CBTREE_TLEN(cbtree_1st) != CBTREE_TLEN(cbtree_2nd))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx total len = %d but cbtree_2nd %lx total len = %d\n",
                            cbtree_1st, CBTREE_TLEN(cbtree_1st),
                            cbtree_2nd, CBTREE_TLEN(cbtree_2nd));
        return (EC_FALSE);
    }

    if(EC_FALSE == __cbtree_node_is_equal(cbtree_1st, CBTREE_ROOT_NODE(cbtree_1st), CBTREE_ROOT_NODE(cbtree_2nd)))
    {
        dbg_log(SEC_0050_CBTREE, 5)(LOGSTDOUT, "__cbtree_is_equal: cbtree_1st %lx root_node not equal to cbtree_2nd %lx root_node\n",
                            cbtree_1st,
                            cbtree_2nd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cbtree_is_equal(const CBTREE *cbtree_1st, const CBTREE *cbtree_2nd)
{
    return __cbtree_is_equal(cbtree_1st, cbtree_2nd);
}

EC_BOOL cbtree_is_dirty(const CBTREE *cbtree)
{
    if(CBTREE_IS_DIRTY(cbtree))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cbtree_set_dirty(CBTREE *cbtree)
{
    CBTREE_SET_DIRTY(cbtree);
    return (EC_TRUE);
}

EC_BOOL cbtree_clear_dirty(CBTREE *cbtree)
{
    CBTREE_CLR_DIRTY(cbtree);
    return (EC_TRUE);
}

/*flush cbtree to posix file*/
EC_BOOL cbtree_flush_posix(CBTREE *cbtree, int fd)
{
    uint8_t *buff;
    uint32_t size;
    uint32_t pos;
    uint32_t counter;
    UINT32   offset;

    if(-1 == fd)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_posix: invalid fd\n");
        return (EC_FALSE);
    } 

    size = sizeof(uint32_t);/*save the total len of encoded buff*/
    if(EC_FALSE == cbtree_encode_size(cbtree, &size))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_posix: encode_size of cbtree %lx failed\n", cbtree);
        return (EC_FALSE);
    }

    buff = (uint8_t *)safe_malloc(size, LOC_CBTREE_0024);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_posix: malloc %d bytes failed\n", size);     
        return (EC_FALSE);
    }

    pos = 0;
    if(EC_FALSE == cbtree_encode(cbtree, buff + sizeof(uint32_t), size - sizeof(uint32_t), &pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_posix: encode cbtree %lx to buff %lx with size %d failed\n",
                           cbtree, buff + sizeof(uint32_t), size - sizeof(uint32_t));
        safe_free(buff, LOC_CBTREE_0025);
        return (EC_FALSE);
    }

    counter = 0;
    gdbPut32(buff, &counter, pos);/*save the encoded buff len at the first 32bits*/

    offset = 0;
    if(EC_FALSE == c_file_flush(fd, &offset, (UINT32)(pos + sizeof(uint32_t)), buff))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_posix: flush %d bytes to fd %d failed\n", pos + sizeof(uint32_t), fd);
        safe_free(buff, LOC_CBTREE_0026);
        return (EC_FALSE);
    }

    safe_free(buff, LOC_CBTREE_0027);
 
    return (EC_TRUE);
}

EC_BOOL cbtree_flush_hsdfs(CBTREE *cbtree, const CSTRING *fname_cstr, const UINT32 cdfs_md_id)
{ 
    uint32_t  encoded_size;
    uint32_t  encoded_pos;
    uint8_t  *encoded_buff;
 
    word_t    compressed_len;
    uint8_t  *compressed_buff;
    uint32_t  counter;
    CBYTES    cbytes;

    encoded_size = 0;
    if(EC_FALSE == cbtree_encode_size(cbtree, &encoded_size))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_hsdfs: encode_size of cbtree %lx failed\n", cbtree);
        return (EC_FALSE);
    }

    /*make encoding buff ready*/
    encoded_buff = (uint8_t *)safe_malloc(encoded_size, LOC_CBTREE_0028);
    if(NULL == encoded_buff)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_hsdfs: alloc %d bytes encoding buff failed\n", encoded_size);
        return (EC_FALSE);
    }

    /*encoding*/
    encoded_pos = 0;
    if(EC_FALSE == cbtree_encode(cbtree, encoded_buff, encoded_size, &encoded_pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_hsdfs: encode cbtree %lx to buff %lx with size %d failed\n",
                           cbtree, encoded_buff, encoded_size);
        safe_free(encoded_buff, LOC_CBTREE_0029);
        return (EC_FALSE);
    }

    /*make compression buff ready*/
    compressed_len = encoded_pos + sizeof(uint32_t);
    compressed_buff = (uint8_t *)safe_malloc(compressed_len, LOC_CBTREE_0030);
    if(NULL == compressed_buff)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_hsdfs: alloc %d bytes compression buff failed\n", compressed_len);
        safe_free(encoded_buff, LOC_CBTREE_0031);
        return (EC_FALSE);
    }

    counter = 0;
    gdbPut32(compressed_buff, &counter, encoded_pos);/*encoded len info saved at the first 4B*/

    /*compressing*/
    if(Z_OK != compress(compressed_buff + counter, &compressed_len, encoded_buff, encoded_pos))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_hsdfs: compress buff %lx size %d to buff %lx failed\n",
                            encoded_buff, encoded_pos, compressed_buff + counter);
     
        safe_free(encoded_buff, LOC_CBTREE_0032);
        safe_free(compressed_buff, LOC_CBTREE_0033);
        return (EC_FALSE);
    }

    safe_free(encoded_buff, LOC_CBTREE_0034);/*free memory as fast as possible*/

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_flush_hsdfs: compress %d bytes => %d bytes, rate = %.2f\n",
                       encoded_pos, compressed_len, (compressed_len + 0.0)/(encoded_pos + 0.0));

    /*flush compressed buff to hsdfs*/
    cbytes_init(&cbytes);
    cbytes_mount(&cbytes, compressed_len, compressed_buff);
    if(EC_FALSE == cdfs_update(cdfs_md_id, fname_cstr, &cbytes))
    {
        cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
        safe_free(compressed_buff, LOC_CBTREE_0035);
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush_hsdfs: update %s with %ld bytes failed\n",
                            (char *)cstring_get_str(fname_cstr), compressed_len);
        return (EC_FALSE);
    }

    cbytes_umount(&cbytes, NULL_PTR, NULL_PTR);
    safe_free(compressed_buff, LOC_CBTREE_0036);

    return (EC_TRUE);
}

/*for posix only*/
EC_BOOL cbtree_flush(CBTREE *cbtree, const char *fname)
{
    int      fd;
    int      flags;

    flags = (O_RDWR | O_CREAT);
    fd = c_file_open(fname, flags, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush: open file %s with flags %d failed\n", fname, flags);
        return (EC_FALSE);
    }

    if(EC_FALSE == cbtree_flush_posix(cbtree, fd))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_flush: flush cbtree %lx to file %s failed\n", cbtree, fname);
        c_file_close(fd);
        return (EC_FALSE);
    }
 
    c_file_close(fd);
    return (EC_TRUE);
}

/*load cbtree from posix file*/
CBTREE * cbtree_load_posix(int fd)
{
    uint8_t *buff;
    uint32_t size;
    uint32_t counter;
    uint32_t f_size;

    CBTREE  *cbtree;
    UINT32   offset;

    if(-1 == fd)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_posix: invalid fd\n");
        return (NULL_PTR);
    }

    /*fetch length and encoded buff size and check validity */
    f_size = (uint32_t)lseek(fd, 0, SEEK_END);
    if(sizeof(uint32_t) > f_size)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_posix: fd %d size %d is invalid\n", fd, f_size);
        return (NULL_PTR);
    }

    offset = 0;

    if(EC_FALSE == c_file_load(fd, &offset, sizeof(uint32_t), (uint8_t *)&size))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_posix: read encoded buff size info from fd %d failed\n", fd);
        return (NULL_PTR);
    }

    counter = 0;
    size = gdbGet32((uint8_t *)&size, &counter);

    if(size + sizeof(uint32_t) > f_size)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_posix: fd %d size %d is less than the expected encoded buff size %d plus 4B len info\n",
                            fd, f_size, size);
        return (NULL_PTR);
    }

    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_load: f_size = %d, encoded_size = %d\n", f_size, size);

    /*load encoded buff from file*/
    buff = (uint8_t *)safe_malloc(size , LOC_CBTREE_0037);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_posix: malloc %d bytes failed\n", size);     
        return (NULL_PTR);
    }

    if(EC_FALSE == c_file_load(fd, &offset, size, buff))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_posix: load %d bytes of encoded buff plus 4B from fd %d failed\n", size, fd);
        safe_free(buff, LOC_CBTREE_0038);
        return (NULL_PTR);
    } 

    /*decode cbtree from buff*/
    cbtree = cbtree_decode(buff, size);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_posix: decode cbtree from buff with size %d loading from fd %d failed\n", size, fd);
        safe_free(buff, LOC_CBTREE_0039);
        return (NULL_PTR);
    } 

    safe_free(buff, LOC_CBTREE_0040);
 
    return (cbtree);
}

/*load cbtree from hsdfs file*/
CBTREE * cbtree_load_hsdfs(const UINT32 cdfs_md_id, const CSTRING *fname_cstr)
{
    word_t   compressed_len;
    uint8_t *compressed_buf;

    uint32_t encoded_len;
    word_t   encoded_len_t;
    uint8_t *encoded_buf;

    uint32_t counter;

    CBYTES  *cbytes;
    CBTREE  *cbtree;

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_hsdfs: new cbytes failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdfs_read(cdfs_md_id, fname_cstr, cbytes))
    {
        cbytes_free(cbytes);
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_hsdfs: read file %s failed\n", (char *)cstring_get_str(fname_cstr));
        return (NULL_PTR);
    }

    compressed_buf = cbytes_buf(cbytes);
    compressed_len = cbytes_len(cbytes);

    //dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_load_hsdfs: cdfs_read get cbytes len %ld\n", compressed_len);

    counter = 0;
    encoded_len = gdbGet32(compressed_buf, &counter);
    encoded_buf = (uint8_t *)safe_malloc(encoded_len, LOC_CBTREE_0041);
    if(NULL_PTR == encoded_buf)
    {
        cbytes_free(cbytes);
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_hsdfs: malloc %d bytes encoded buf failed\n", encoded_len);
        return (NULL_PTR);
    }

    encoded_len_t = encoded_len;
    if(Z_OK != uncompress(encoded_buf, &encoded_len_t, compressed_buf + counter, compressed_len - counter))
    {
        cbytes_free(cbytes);
        safe_free(encoded_buf, LOC_CBTREE_0042);
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_hsdfs: uncompress %d bytes to encoded buf with len %ld failed\n", compressed_len - counter, encoded_len_t);
        return (NULL_PTR);
    }
    ASSERT(encoded_len_t <= ((uint32_t)~0));
    encoded_len = encoded_len_t;/*shit!*/

    cbytes_free(cbytes);/*free memory as fast as possible*/ 

    dbg_log(SEC_0050_CBTREE, 9)(LOGSTDOUT, "[DEBUG] cbtree_load_hsdfs: uncompress %d bytes => %d bytes, rate = %.2f\n",
                       compressed_len - counter, encoded_len, (compressed_len - counter + 0.0)/(encoded_len + 0.0));

    /*decode cbtree from buff*/
    cbtree = cbtree_decode(encoded_buf, encoded_len);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load_hsdfs: decode cbtree from buff with size %d loading from %s failed\n",
                            encoded_len, (char *)cstring_get_str(fname_cstr));
        safe_free(encoded_buf, LOC_CBTREE_0043);
        return (NULL_PTR);
    } 

    safe_free(encoded_buf, LOC_CBTREE_0044);
 
    return (cbtree);
}

/*for posix only*/
CBTREE * cbtree_load(const char *fname)
{
    int      fd;
    int      flags;

    CBTREE  *cbtree;

    flags = (O_RDWR);
    fd = c_file_open(fname, flags, 0666);
    if(-1 == fd)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load: open file %s with flags %d failed\n", fname, flags);
        return (NULL_PTR);
    }

    cbtree = cbtree_load_posix(fd);
    if(NULL_PTR == cbtree)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_load: load cbtree from file %s failed\n", fname);
        c_file_close(fd);
        return (NULL_PTR);
    }

    c_file_close(fd);
    return (cbtree);
}

static EC_BOOL __cbtree_key_scan(CBTREE *cbtree, CBTREE_KEY *cbtree_key,
                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                     const UINT32 func_para_num, const UINT32 key_pos,
                     const UINT32 handler_func_addr,
                     UINT32 *func_para_value)
{
    uint8_t *key;

    key = CBTREE_KEY_LATEST(cbtree_key);

    func_para_value[ key_pos ] = (UINT32)key;

    if(EC_FALSE == dbg_caller(handler_func_addr, func_para_num, func_para_value, (UINT32 *)handler_retval_addr))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_key_scan: dbg_caller failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != handler_retval_checker
    && NULL_PTR != handler_retval_addr
    && EC_FALSE == handler_retval_checker(handler_retval_addr))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

static EC_BOOL __cbtree_node_scan(CBTREE *cbtree, CBTREE_NODE *cbtree_node,
                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                     const UINT32 func_para_num, const UINT32 key_pos,
                     const UINT32 handler_func_addr,
                     UINT32 *func_para_value)
{
    uint8_t idx;

    if(! CBTREE_NODE_IS_LEAF(cbtree_node))
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:__cbtree_node_scan: node %lx is NOT leaf!\n", cbtree_node);
        return (EC_FALSE);
    }

    for (idx = 0; idx < CBTREE_NODE_COUNT(cbtree_node); idx++)
    {
        CBTREE_KEY *cbtree_key;
        cbtree_key = CBTREE_NODE_KEY(cbtree_node, idx);
     
        if(EC_FALSE == __cbtree_key_scan(cbtree, cbtree_key,
                                          handler_retval_addr, handler_retval_checker,
                                          func_para_num, key_pos,
                                          handler_func_addr,
                                          func_para_value))
        {
            return (EC_FALSE);
        }
    } 

    return (EC_TRUE);
}

static EC_BOOL __cbtree_scan(CBTREE *cbtree,
                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                     const UINT32 func_para_num, const UINT32 key_pos,
                     const UINT32 handler_func_addr,
                     UINT32 *func_para_value)
{
    CBTREE_NODE *node;

    node = CBTREE_LEFT_LEAF(cbtree);
    while(NULL_PTR != node)
    {
        if(EC_FALSE == __cbtree_node_scan(cbtree, node,
                                          handler_retval_addr, handler_retval_checker,
                                          func_para_num, key_pos,
                                          handler_func_addr,
                                          func_para_value))
        {
            return (EC_FALSE);
        }
        node = CBTREE_NODE_CHILD(node, CBTREE_ORDER(cbtree) - 1);
    }

    return (EC_TRUE);
}

/*key_pos range from 0 to func_para_num - 1*/
EC_BOOL cbtree_scan(CBTREE *cbtree,
                     void *handler_retval_addr, EC_BOOL (*handler_retval_checker)(const void *),
                     const UINT32 func_para_num, const UINT32 key_pos,
                     const UINT32 handler_func_addr,...)
{
    UINT32 func_para_value[ MAX_NUM_OF_FUNC_PARAS ];
    UINT32 index;

    va_list ap;

    if(0 == handler_func_addr)
    {
        return (EC_TRUE);
    }

    if(0 == func_para_num)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_scan: func_para_num must be larger than 1\n");
        return (EC_FALSE);
    }

    if(MAX_NUM_OF_FUNC_PARAS < func_para_num)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_scan: func_para_num %ld overflow which must be smaller than %ld\n",
                           func_para_num, MAX_NUM_OF_FUNC_PARAS);
        return (EC_FALSE);
    }

    if(key_pos >= func_para_num)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_scan: invalid setting where key_pos %ld >= func_para_num %ld\n",
                           key_pos, func_para_num);
        return (EC_FALSE);
    }

    va_start(ap, handler_func_addr);
    for( index = 0; index < func_para_num; index ++ )
    {
        func_para_value[ index ] = va_arg(ap, UINT32);
    }
    va_end(ap);

    return __cbtree_scan(cbtree,
                     handler_retval_addr, handler_retval_checker,
                     func_para_num, key_pos,
                     handler_func_addr,
                     (UINT32 *)func_para_value);
}

uint8_t *cbtree_make_kv(const char *row, const char *colf, const char *colq, const ctime_t ts, uint8_t type)
{
    KeyValue keyValue;
    uint8_t *key_buff;

    keyValueInitHs(&keyValue,
                   0,
                   (uint16_t)strlen(row), (const uint8_t *)(row),
                   (uint8_t )strlen(colf), (const uint8_t *)(colf),
                   (uint16_t)strlen(colq), (const uint8_t *)(colq),
                   (ts),
                   (uint8_t)type,
                   NULL_PTR);

    key_buff = kvNewHs(&keyValue, LOC_CBTREE_0045);
    if(NULL_PTR == key_buff)
    {
        dbg_log(SEC_0050_CBTREE, 0)(LOGSTDOUT, "error:cbtree_make_kv: failed to alloc %d bytes for key\n", keyValueGettLenHs(&keyValue));
        return (NULL_PTR);
    }
    kvPutHs(key_buff, &keyValue);

    return (key_buff);
}

EC_BOOL cbtree_free_kv(uint8_t *kv)
{
    kvFreeHs(kv, LOC_CBTREE_0046);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

