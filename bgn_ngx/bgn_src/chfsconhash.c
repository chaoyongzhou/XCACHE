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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cmpic.inc"
#include "cmisc.h"

#include "crb.h"
#include "chashalgo.h"
#include "chfsconhash.h"

CHFSCONHASH_RNODE *chfsconhash_rnode_new()
{
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    alloc_static_mem(MM_CHFSCONHASH_RNODE, &chfsconhash_rnode, LOC_CHFSCONHASH_0001);
    if(NULL_PTR != chfsconhash_rnode)
    {
        chfsconhash_rnode_init(chfsconhash_rnode);
    }
    return (chfsconhash_rnode);
}

CHFSCONHASH_RNODE *chfsconhash_rnode_make(const uint32_t tcid, const uint16_t replicas)
{
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    alloc_static_mem(MM_CHFSCONHASH_RNODE, &chfsconhash_rnode, LOC_CHFSCONHASH_0002);
    if(NULL_PTR != chfsconhash_rnode)
    {
        CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode) = replicas;
        CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode)   = CHFSCONHASH_RNODE_IS_UP;
        CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)     = tcid;

        CHFSCONHASH_RNODE_COUNTER_CLR(chfsconhash_rnode);
    }
    return (chfsconhash_rnode);
}

EC_BOOL chfsconhash_rnode_init(CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode) = 0;
    CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode)   = CHFSCONHASH_RNODE_IS_ERR;
    CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;

    CHFSCONHASH_RNODE_COUNTER_CLR(chfsconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL chfsconhash_rnode_clean(CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode) = 0;
    CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode)   = CHFSCONHASH_RNODE_IS_ERR;
    CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;

    CHFSCONHASH_RNODE_COUNTER_CLR(chfsconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL chfsconhash_rnode_free(CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    if(NULL_PTR != chfsconhash_rnode)
    {
        chfsconhash_rnode_clean(chfsconhash_rnode);
        free_static_mem(MM_CHFSCONHASH_RNODE, chfsconhash_rnode, LOC_CHFSCONHASH_0003);
    }
    return (EC_TRUE);
}

EC_BOOL chfsconhash_rnode_init_0(const UINT32 md_id, CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    return chfsconhash_rnode_init(chfsconhash_rnode);
}

EC_BOOL chfsconhash_rnode_clean_0(const UINT32 md_id, CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    return chfsconhash_rnode_clean(chfsconhash_rnode);
}

EC_BOOL chfsconhash_rnode_free_0(const UINT32 md_id, CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    return chfsconhash_rnode_free(chfsconhash_rnode);
}

EC_BOOL chfsconhash_rnode_clone(const CHFSCONHASH_RNODE *chfsconhash_rnode_src, CHFSCONHASH_RNODE *chfsconhash_rnode_des)
{
    CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode_des) = CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode_src);
    CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode_des)   = CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode_src);
    CHFSCONHASH_RNODE_TCID(chfsconhash_rnode_des)     = CHFSCONHASH_RNODE_TCID(chfsconhash_rnode_src);

    CHFSCONHASH_RNODE_COUNTER_CLONE(chfsconhash_rnode_src, chfsconhash_rnode_des);
    return (EC_TRUE);
}

const char *chfsconhash_rnode_status(const CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    if(CHFSCONHASH_RNODE_IS_UP == CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        return (const char *)"UP";
    }
    if(CHFSCONHASH_RNODE_IS_DOWN == CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        return (const char *)"DOWN";
    }

    if(CHFSCONHASH_RNODE_IS_ERR == CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

EC_BOOL chfsconhash_rnode_is_up(const CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    if(CHFSCONHASH_RNODE_IS_UP == CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL chfsconhash_rnode_is_equal(const CHFSCONHASH_RNODE *chfsconhash_rnode_1st, const CHFSCONHASH_RNODE *chfsconhash_rnode_2nd)
{
    if(NULL_PTR == chfsconhash_rnode_1st && NULL_PTR == chfsconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == chfsconhash_rnode_1st || NULL_PTR == chfsconhash_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode_1st) != CHFSCONHASH_RNODE_TCID(chfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#if 1
    if(CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode_1st) != CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#endif
    return (EC_TRUE);
}

EC_BOOL chfsconhash_rnode_cmp_tcid(const CHFSCONHASH_RNODE *chfsconhash_rnode_1st, const CHFSCONHASH_RNODE *chfsconhash_rnode_2nd)
{
    if(NULL_PTR == chfsconhash_rnode_1st && NULL_PTR == chfsconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == chfsconhash_rnode_1st || NULL_PTR == chfsconhash_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode_1st) != CHFSCONHASH_RNODE_TCID(chfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void chfsconhash_rnode_print(LOG *log, const CHFSCONHASH_RNODE *chfsconhash_rnode)
{
#if(SWITCH_OFF == CHFSCONHASH_RNODE_DEBUG)
    sys_log(log, "chfsconhash_rnode %p: tcid %s, replicas %u, status %s\n",
                    chfsconhash_rnode,
                    c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                    CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                    chfsconhash_rnode_status(chfsconhash_rnode)
                   );
#endif/*(SWITCH_OFF == CHFSCONHASH_RNODE_DEBUG)*/
#if(SWITCH_ON == CHFSCONHASH_RNODE_DEBUG)
    sys_log(log, "chfsconhash_rnode %p: tcid %s, replicas %u, status %s, counter %ld\n",
                    chfsconhash_rnode,
                    c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                    CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                    chfsconhash_rnode_status(chfsconhash_rnode),
                    CHFSCONHASH_RNODE_COUNTER(chfsconhash_rnode)
                   );
#endif/*(SWITCH_ON == CHFSCONHASH_RNODE_DEBUG)*/
    return;
}

CHFSCONHASH_VNODE *chfsconhash_vnode_new()
{
    CHFSCONHASH_VNODE *chfsconhash_vnode;
    alloc_static_mem(MM_CHFSCONHASH_VNODE, &chfsconhash_vnode, LOC_CHFSCONHASH_0004);
    if(NULL_PTR != chfsconhash_vnode)
    {
        chfsconhash_vnode_init(chfsconhash_vnode);
    }
    return (chfsconhash_vnode);
}

CHFSCONHASH_VNODE *chfsconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos)
{
    CHFSCONHASH_VNODE *chfsconhash_vnode;
    alloc_static_mem(MM_CHFSCONHASH_VNODE, &chfsconhash_vnode, LOC_CHFSCONHASH_0005);
    if(NULL_PTR != chfsconhash_vnode)
    {
        CHFSCONHASH_VNODE_HASH(chfsconhash_vnode) = hash;
        CHFSCONHASH_VNODE_POS(chfsconhash_vnode)  = rnode_pos;
    }
    return (chfsconhash_vnode);
}

EC_BOOL chfsconhash_vnode_init(CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    CHFSCONHASH_VNODE_HASH(chfsconhash_vnode) = 0;
    CHFSCONHASH_VNODE_POS(chfsconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL chfsconhash_vnode_clean(CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    CHFSCONHASH_VNODE_HASH(chfsconhash_vnode) = 0;
    CHFSCONHASH_VNODE_POS(chfsconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL chfsconhash_vnode_free(CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    if(NULL_PTR != chfsconhash_vnode)
    {
        chfsconhash_vnode_clean(chfsconhash_vnode);
        free_static_mem(MM_CHFSCONHASH_VNODE, chfsconhash_vnode, LOC_CHFSCONHASH_0006);
    }
    return (EC_TRUE);
}

EC_BOOL chfsconhash_vnode_init_0(const UINT32 md_id, CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    return chfsconhash_vnode_init(chfsconhash_vnode);
}

EC_BOOL chfsconhash_vnode_clean_0(const UINT32 md_id, CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    return chfsconhash_vnode_clean(chfsconhash_vnode);
}

EC_BOOL chfsconhash_vnode_free_0(const UINT32 md_id, CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    return chfsconhash_vnode_free(chfsconhash_vnode);
}

EC_BOOL chfsconhash_vnode_clone(const CHFSCONHASH_VNODE *chfsconhash_vnode_src, CHFSCONHASH_VNODE *chfsconhash_vnode_des)
{
    CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_des) = CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_src);
    CHFSCONHASH_VNODE_POS(chfsconhash_vnode_des)  = CHFSCONHASH_VNODE_POS(chfsconhash_vnode_src);
    return (EC_TRUE);
}

EC_BOOL chfsconhash_vnode_is_equal(const CHFSCONHASH_VNODE *chfsconhash_vnode_1st, const CHFSCONHASH_VNODE *chfsconhash_vnode_2nd)
{
    if(NULL_PTR == chfsconhash_vnode_1st && NULL_PTR == chfsconhash_vnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == chfsconhash_vnode_1st || NULL_PTR == chfsconhash_vnode_2nd)
    {
        return (EC_FALSE);
    }

    if(do_log(SEC_0162_CHFSCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chfsconhash_vnode_is_equal: check them:\n");
        chfsconhash_vnode_print(LOGSTDOUT, chfsconhash_vnode_1st);
        chfsconhash_vnode_print(LOGSTDOUT, chfsconhash_vnode_2nd);
    }

    if(CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_1st) != CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_2nd))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 6)(LOGSTDOUT, "[DEBUG] chfsconhash_vnode_is_equal: hash: %x != %x\n",
                           CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_1st),
                           CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_2nd));
        return (EC_FALSE);
    }
#if 1
    if(CHFSCONHASH_VNODE_POS(chfsconhash_vnode_1st) != CHFSCONHASH_VNODE_POS(chfsconhash_vnode_2nd))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 6)(LOGSTDOUT, "[DEBUG] chfsconhash_vnode_is_equal: pos: %u != %u\n",
                           CHFSCONHASH_VNODE_POS(chfsconhash_vnode_1st),
                           CHFSCONHASH_VNODE_POS(chfsconhash_vnode_2nd));
        return (EC_FALSE);
    }
#endif
    return (EC_TRUE);
}

int chfsconhash_vnode_cmp(const CHFSCONHASH_VNODE *chfsconhash_vnode_1st, const CHFSCONHASH_VNODE *chfsconhash_vnode_2nd)
{
    if(CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_1st) > CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_2nd))
    {
        return (1);
    }

    if(CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_1st) < CHFSCONHASH_VNODE_HASH(chfsconhash_vnode_2nd))
    {
        return (-1);
    }
    return (0);
}

void chfsconhash_vnode_print(LOG *log, const CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    sys_log(log, "chfsconhash_vnode %p: hash %x, rnode pos %u\n",
                    chfsconhash_vnode,
                    CHFSCONHASH_VNODE_HASH(chfsconhash_vnode),
                    CHFSCONHASH_VNODE_POS(chfsconhash_vnode)
                   );
    return;
}

CHFSCONHASH *chfsconhash_new(const UINT32 hash_id)
{
    CHFSCONHASH *chfsconhash;

    alloc_static_mem(MM_CHFSCONHASH, &chfsconhash, LOC_CHFSCONHASH_0007);
    if(NULL_PTR == chfsconhash)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_new: alloc chfsconhash failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == chfsconhash_init(chfsconhash, hash_id))
    {
        free_static_mem(MM_CHFSCONHASH, chfsconhash, LOC_CHFSCONHASH_0008);
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_new: init chfsconhash failed\n");
        return (NULL_PTR);
    }

    return (chfsconhash);
}

EC_BOOL chfsconhash_init(CHFSCONHASH *chfsconhash, const UINT32 hash_id)
{
    CHFSCONHASH_HASH_FUNC(chfsconhash) = chash_algo_fetch(hash_id);
    if(NULL_PTR == CHFSCONHASH_HASH_FUNC(chfsconhash))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_init: invalid hash_id %ld\n", hash_id);
        return (EC_FALSE);
    }
    CHFSCONHASH_HASH_ID(chfsconhash)   = hash_id;

    cvector_init(CHFSCONHASH_RNODE_VEC(chfsconhash), 0, MM_CHFSCONHASH_RNODE, CVECTOR_LOCK_ENABLE, LOC_CHFSCONHASH_0009);
    crb_tree_init(CHFSCONHASH_VNODE_TREE(chfsconhash), (CRB_DATA_CMP)chfsconhash_vnode_cmp, (CRB_DATA_FREE)chfsconhash_vnode_free,(CRB_DATA_PRINT)chfsconhash_vnode_print);

    return (EC_TRUE);
}

EC_BOOL chfsconhash_clean(CHFSCONHASH *chfsconhash)
{
    cvector_clean(CHFSCONHASH_RNODE_VEC(chfsconhash), (CVECTOR_DATA_CLEANER)chfsconhash_rnode_free, LOC_CHFSCONHASH_0010);
    crb_tree_clean(CHFSCONHASH_VNODE_TREE(chfsconhash));

    CHFSCONHASH_HASH_ID(chfsconhash)   = CHASH_ERR_ALGO_ID;
    CHFSCONHASH_HASH_FUNC(chfsconhash) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL chfsconhash_free(CHFSCONHASH *chfsconhash)
{
    if(NULL_PTR != chfsconhash)
    {
        chfsconhash_clean(chfsconhash);
        free_static_mem(MM_CHFSCONHASH, chfsconhash, LOC_CHFSCONHASH_0011);
    }
    return (EC_TRUE);
}

void chfsconhash_print(LOG *log, const CHFSCONHASH *chfsconhash)
{
    sys_log(log, "chfsconhash %p: hash_id %ld, rnode num %ld, vnode num %u\n",
                    chfsconhash,
                    CHFSCONHASH_HASH_ID(chfsconhash),
                    cvector_size(CHFSCONHASH_RNODE_VEC(chfsconhash)),
                    crb_tree_node_num(CHFSCONHASH_VNODE_TREE(chfsconhash))
                    );

    if(do_log(SEC_0162_CHFSCONHASH, 6))
    {
        sys_log(log, "chfsconhash %p: rnode vec:\n", chfsconhash);
        cvector_print(log, CHFSCONHASH_RNODE_VEC(chfsconhash), (CVECTOR_DATA_PRINT)chfsconhash_rnode_print);
    }

    if(do_log(SEC_0162_CHFSCONHASH, 7))
    {
        sys_log(log, "chfsconhash %p: vnode tree:\n", chfsconhash);
        crb_tree_print(log, CHFSCONHASH_VNODE_TREE(chfsconhash));
    }

    return;
}

void chfsconhash_print_rnode_vec(LOG *log, const CHFSCONHASH *chfsconhash)
{
    sys_log(log, "chfsconhash %p: hash_id %ld\n",
                    chfsconhash,
                    CHFSCONHASH_HASH_ID(chfsconhash));

    sys_log(log, "chfsconhash %p: rnode vec:\n", chfsconhash);
    cvector_print(log, CHFSCONHASH_RNODE_VEC(chfsconhash), (CVECTOR_DATA_PRINT)chfsconhash_rnode_print);

    return;
}

void chfsconhash_print_vnode_tree(LOG *log, const CHFSCONHASH *chfsconhash)
{
    sys_log(log, "chfsconhash %p: hash_id %ld\n",
                    chfsconhash,
                    CHFSCONHASH_HASH_ID(chfsconhash));

    sys_log(log, "chfsconhash %p: vnode tree:\n", chfsconhash);
    crb_tree_print(log, CHFSCONHASH_VNODE_TREE(chfsconhash));

    return;
}

UINT32 chfsconhash_add_rnode(CHFSCONHASH *chfsconhash, const CHFSCONHASH_RNODE *chfsconhash_rnode)
{
    return cvector_add(CHFSCONHASH_RNODE_VEC(chfsconhash), (void *)chfsconhash_rnode);
}

CRB_NODE *chfsconhash_add_vnode(CHFSCONHASH *chfsconhash, const CHFSCONHASH_VNODE *chfsconhash_vnode)
{
    return crb_tree_insert_data(CHFSCONHASH_VNODE_TREE(chfsconhash), (void *)chfsconhash_vnode);
}

STATIC_CAST static uint32_t __chfsconhash_hash_vnode(CHFSCONHASH *chfsconhash, const uint32_t tcid, const uint16_t replica, const UINT32 salt)
{
    char     str[64];
    uint32_t len;
    uint32_t hash;

    len  = snprintf(str, sizeof(str), "%s.%u.%ld", c_word_to_ipv4(tcid), (uint32_t)(replica * replica), salt);
    hash = (uint32_t)CHFSCONHASH_HASH_FUNC(chfsconhash)(len, (UINT8 *)str);

    return (hash);
}

EC_BOOL chfsconhash_add_vnode_replicas(CHFSCONHASH *chfsconhash, const UINT32 chfsconhash_rnode_pos)
{
    CHFSCONHASH_RNODE *chfsconhash_rnode;

    uint32_t tcid;
    uint16_t replica;

    chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos);
    if(NULL_PTR == chfsconhash_rnode)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: not found rnode at pos %ld\n",
                           chfsconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (chfsconhash_rnode_pos >> 16));

    tcid = CHFSCONHASH_RNODE_TCID(chfsconhash_rnode);
    for(replica = 0; replica < CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode); replica ++)
    {
        uint32_t hash;

        CHFSCONHASH_VNODE *chfsconhash_vnode;
        CRB_NODE          *crb_node;

        hash = __chfsconhash_hash_vnode(chfsconhash, tcid, replica, chfsconhash_rnode_pos);

        chfsconhash_vnode = chfsconhash_vnode_make(hash, (uint16_t)chfsconhash_rnode_pos);
        if(NULL_PTR == chfsconhash_vnode)
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)chfsconhash_rnode_pos);
            return (EC_FALSE);
        }

        crb_node = crb_tree_insert_data(CHFSCONHASH_VNODE_TREE(chfsconhash), (void *)chfsconhash_vnode);
        if(NULL_PTR == crb_node)
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: insert vnode (hash %x, tcid %s, replica %u, rnode pos %u) to rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)chfsconhash_rnode_pos);
            chfsconhash_vnode_free(chfsconhash_vnode);
            return (EC_FALSE);
        }

        /*fix*/
        if(chfsconhash_vnode != CRB_NODE_DATA(crb_node))
        {
            CHFSCONHASH_VNODE *chfsconhash_vnode_duplicate;
            CHFSCONHASH_RNODE *chfsconhash_rnode_duplicate;

            chfsconhash_vnode_duplicate = (CHFSCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
            chfsconhash_rnode_duplicate = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), CHFSCONHASH_VNODE_POS(chfsconhash_vnode_duplicate));

            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: found duplicate vnode:\n");

            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: found duplicate vnode:[1]\n");
            chfsconhash_vnode_print(LOGSTDOUT, chfsconhash_vnode);
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: found duplicate rnode:[1]\n");
            chfsconhash_rnode_print(LOGSTDOUT, chfsconhash_rnode);

            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: found duplicate vnode:[2]\n");
            chfsconhash_vnode_print(LOGSTDOUT, chfsconhash_vnode_duplicate);
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: found duplicate rnode:[2]\n");
            chfsconhash_rnode_print(LOGSTDOUT, chfsconhash_rnode_duplicate);

            chfsconhash_vnode_free(chfsconhash_vnode);

            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_vnode_replicas: pls make sure hash is unique!\n");
            exit( 5 );
        }
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_del_vnode_replicas(CHFSCONHASH *chfsconhash, const UINT32 chfsconhash_rnode_pos)
{
    CHFSCONHASH_RNODE *chfsconhash_rnode;

    uint32_t tcid;
    uint16_t replica;

    chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos);
    if(NULL_PTR == chfsconhash_rnode)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_del_vnode_replicas: not found rnode at pos %ld\n",
                           chfsconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (chfsconhash_rnode_pos >> 16));

    tcid = CHFSCONHASH_RNODE_TCID(chfsconhash_rnode);
    for(replica = 0; replica < CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode); replica ++)
    {
        uint32_t hash;

        CHFSCONHASH_VNODE *chfsconhash_vnode;

        hash = __chfsconhash_hash_vnode(chfsconhash, tcid, replica, chfsconhash_rnode_pos);

        chfsconhash_vnode = chfsconhash_vnode_make(hash, (uint16_t)chfsconhash_rnode_pos);
        if(NULL_PTR == chfsconhash_vnode)
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_del_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)chfsconhash_rnode_pos);
            return (EC_FALSE);
        }

        if(EC_FALSE == crb_tree_delete_data(CHFSCONHASH_VNODE_TREE(chfsconhash), (void *)chfsconhash_vnode))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_del_vnode_replicas: del vnode (hash %x, tcid %s, replica %u, rnode pos %u) from rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)chfsconhash_rnode_pos);
            chfsconhash_vnode_free(chfsconhash_vnode);
            return (EC_FALSE);
        }

        chfsconhash_vnode_free(chfsconhash_vnode);
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_add_node(CHFSCONHASH *chfsconhash, const uint32_t tcid, const uint16_t replicas)
{
    CHFSCONHASH_RNODE  chfsconhash_rnode_t;
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    UINT32             chfsconhash_rnode_pos;

    CHFSCONHASH_RNODE_TCID(&chfsconhash_rnode_t) = tcid;
    chfsconhash_rnode_pos = cvector_search_front(CHFSCONHASH_RNODE_VEC(chfsconhash),
                                                 (void *)&chfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)chfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS != chfsconhash_rnode_pos)
    {
        chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos);

        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_node: found rnode (tcid %s, replicas %u, status %s)\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_FALSE);
    }

    chfsconhash_rnode = chfsconhash_rnode_make(tcid, replicas);
    if(NULL_PTR == chfsconhash_rnode)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_node: make rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(tcid), replicas);
        return (EC_FALSE);
    }

    /*add rnode*/
    chfsconhash_rnode_pos = chfsconhash_add_rnode(chfsconhash, chfsconhash_rnode);
    if(CVECTOR_ERR_POS == chfsconhash_rnode_pos)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_node: add rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));

        chfsconhash_rnode_free(chfsconhash_rnode);
        return (EC_FALSE);
    }

    ASSERT(0 == (chfsconhash_rnode_pos >> 16));
#if 1
    /*add vnode replicas*/
    if(EC_FALSE == chfsconhash_add_vnode_replicas(chfsconhash, chfsconhash_rnode_pos))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_add_node: add vnode replicas of rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode));

        chfsconhash_del_vnode_replicas(chfsconhash, chfsconhash_rnode_pos);/*roll back*/

        cvector_set(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos, NULL_PTR);
        chfsconhash_rnode_free(chfsconhash_rnode);
        return (EC_FALSE);
    }
#endif
    dbg_log(SEC_0162_CHFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] chfsconhash_add_node: rnode (tcid %s, replicas %u, status %s) add => OK\n",
                       c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                       CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                       chfsconhash_rnode_status(chfsconhash_rnode));
    return (EC_TRUE);
}

/*for any replica: replicas = 0*/
EC_BOOL chfsconhash_del_node(CHFSCONHASH *chfsconhash, const uint32_t tcid)
{
    CHFSCONHASH_RNODE  chfsconhash_rnode_t;
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    UINT32             chfsconhash_rnode_pos;

    CHFSCONHASH_RNODE_TCID(&chfsconhash_rnode_t) = tcid;
    chfsconhash_rnode_pos = cvector_search_front(CHFSCONHASH_RNODE_VEC(chfsconhash),
                                                 (void *)&chfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)chfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == chfsconhash_rnode_pos)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_del_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos);

    ASSERT(0 == (chfsconhash_rnode_pos >> 16));

    /*del vnode replicas*/
    if(EC_FALSE == chfsconhash_del_vnode_replicas(chfsconhash, chfsconhash_rnode_pos))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_del_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_FALSE);
    }

    dbg_log(SEC_0162_CHFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] chfsconhash_del_node: rnode (tcid %s, replicas %u, status %s) del => OK\n",
                       c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                       CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                       chfsconhash_rnode_status(chfsconhash_rnode));

    /*del rnode*/
    cvector_set(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos, NULL_PTR);
    chfsconhash_rnode_free(chfsconhash_rnode);

    return (EC_TRUE);
}

EC_BOOL chfsconhash_up_node(CHFSCONHASH *chfsconhash, const uint32_t tcid)
{
    CHFSCONHASH_RNODE  chfsconhash_rnode_t;
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    UINT32             chfsconhash_rnode_pos;

    CHFSCONHASH_RNODE_TCID(&chfsconhash_rnode_t) = tcid;
    chfsconhash_rnode_pos = cvector_search_front(CHFSCONHASH_RNODE_VEC(chfsconhash),
                                                 (void *)&chfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)chfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == chfsconhash_rnode_pos)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_up_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (chfsconhash_rnode_pos >> 16));

    chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos);

    if(CHFSCONHASH_RNODE_IS_UP == CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] chfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) is already up\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_TRUE);
    }
#if 0
    if(CHFSCONHASH_RNODE_IS_DOWN != CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) is not down\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_FALSE);
    }
#endif

    if(CHFSCONHASH_ERR_REPLICAS == CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode)
    || CHFSCONHASH_ANY_REPLICAS == CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) has invalid replica\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_FALSE);
    }

    /*add vnode replicas*/
    if(EC_FALSE == chfsconhash_add_vnode_replicas(chfsconhash, chfsconhash_rnode_pos))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_up_node: add vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));

        chfsconhash_del_vnode_replicas(chfsconhash, chfsconhash_rnode_pos);/*roll back*/
        return (EC_FALSE);
    }

    CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode) = CHFSCONHASH_RNODE_IS_UP; /*set up*/

    dbg_log(SEC_0162_CHFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] chfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) set up => OK\n",
                       c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                       CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                       chfsconhash_rnode_status(chfsconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL chfsconhash_down_node(CHFSCONHASH *chfsconhash, const uint32_t tcid)
{
    CHFSCONHASH_RNODE  chfsconhash_rnode_t;
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    UINT32             chfsconhash_rnode_pos;

    CHFSCONHASH_RNODE_TCID(&chfsconhash_rnode_t) = tcid;
    chfsconhash_rnode_pos = cvector_search_front(CHFSCONHASH_RNODE_VEC(chfsconhash),
                                                 (void *)&chfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)chfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == chfsconhash_rnode_pos)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_down_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (chfsconhash_rnode_pos >> 16));

    chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos);

    if(CHFSCONHASH_RNODE_IS_DOWN == CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] chfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) is already down\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_TRUE);
    }
#if 0
    if(CHFSCONHASH_RNODE_IS_UP != CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) is not up\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_FALSE);
    }
#endif
    /*del vnode replicas*/
    if(EC_FALSE == chfsconhash_del_vnode_replicas(chfsconhash, chfsconhash_rnode_pos))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_down_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                           CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                           chfsconhash_rnode_status(chfsconhash_rnode));
        return (EC_FALSE);
    }

    CHFSCONHASH_RNODE_STATUS(chfsconhash_rnode) = CHFSCONHASH_RNODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0162_CHFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] chfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) set down => OK\n",
                       c_word_to_ipv4(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode)),
                       CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode),
                       chfsconhash_rnode_status(chfsconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL chfsconhash_has_node(const CHFSCONHASH *chfsconhash, const uint32_t tcid)
{
    CHFSCONHASH_RNODE  chfsconhash_rnode_t;
    UINT32             chfsconhash_rnode_pos;

    CHFSCONHASH_RNODE_TCID(&chfsconhash_rnode_t) = tcid;
    chfsconhash_rnode_pos = cvector_search_front(CHFSCONHASH_RNODE_VEC(chfsconhash),
                                                 (void *)&chfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)chfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == chfsconhash_rnode_pos)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 9)(LOGSTDOUT, "info:chfsconhash_has_node: tcid %s is not in rnode\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CHFSCONHASH_RNODE *chfsconhash_get_rnode(const CHFSCONHASH *chfsconhash, const uint32_t tcid)
{
    CHFSCONHASH_RNODE  chfsconhash_rnode_t;
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    UINT32             chfsconhash_rnode_pos;

    CHFSCONHASH_RNODE_TCID(&chfsconhash_rnode_t) = tcid;
    chfsconhash_rnode_pos = cvector_search_front(CHFSCONHASH_RNODE_VEC(chfsconhash),
                                                 (void *)&chfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)chfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == chfsconhash_rnode_pos)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_get_rnode: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode_pos);
    return (chfsconhash_rnode);
}

CHFSCONHASH_RNODE *chfsconhash_lookup_rnode(const CHFSCONHASH *chfsconhash, const uint32_t hash)
{
    CHFSCONHASH_VNODE  chfsconhash_vnode_t;
    CHFSCONHASH_VNODE *chfsconhash_vnode;
    CHFSCONHASH_RNODE *chfsconhash_rnode;
    CRB_NODE *crb_node;

    if(EC_TRUE == crb_tree_is_empty(CHFSCONHASH_VNODE_TREE(chfsconhash)))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_lookup_rnode: vnode tree is empty\n");
        return (NULL_PTR);
    }

    CHFSCONHASH_VNODE_HASH(&chfsconhash_vnode_t) = hash;
    crb_node = crb_tree_lookup_data(CHFSCONHASH_VNODE_TREE(chfsconhash), (void *)&chfsconhash_vnode_t);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_lookup_rnode: hash %x, should never reach here due to rbtree be circled\n",
                           hash);
        return (NULL_PTR);
    }

    chfsconhash_vnode = (CHFSCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
    if(NULL_PTR == chfsconhash_vnode)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_lookup_rnode: hash %x, crb_node %p, should never reach here due to CRB_NODE_DATA be null!\n",
                           hash, crb_node);
        return (NULL_PTR);
    }
#if 0
    if(do_log(SEC_0162_CHFSCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] chfsconhash_lookup_rnode: hash %x => vnode ", hash);
        chfsconhash_vnode_print(LOGSTDOUT, chfsconhash_vnode);
    }
#endif
    chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash),
                                                         CHFSCONHASH_VNODE_POS(chfsconhash_vnode));
    if(NULL_PTR == chfsconhash_rnode)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_lookup_rnode: hash %x, rnode_pos %u, should never reach here due to rnode not existing\n",
                           hash, CHFSCONHASH_VNODE_POS(chfsconhash_vnode));
        return (NULL_PTR);
    }
    return (chfsconhash_rnode);
}

EC_BOOL chfsconhash_flush_size(const CHFSCONHASH *chfsconhash, UINT32 *size)
{
    (*size) = sizeof(UINT32) /*hash_id*/
            + sizeof(UINT32) /*rnode_vec size*/
            + cvector_size(CHFSCONHASH_RNODE_VEC(chfsconhash)) * (
                                                                    sizeof(uint16_t) /*replicas*/
                                                                  + sizeof(uint32_t) /*tcid*/
                                                                  )
            + sizeof(uint32_t) /*vnode_tree size*/
            + crb_tree_node_num(CHFSCONHASH_VNODE_TREE(chfsconhash)) * (
                                                                     sizeof(uint32_t) /*hash*/
                                                                   + sizeof(uint32_t) /*pos*/
                                                                   );
    return (EC_FALSE);
}

EC_BOOL chfsconhash_rnode_flush(const CHFSCONHASH_RNODE *chfsconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    if(NULL_PTR == chfsconhash_rnode)
    {
        uint32_t     tcid;
        uint16_t     replicas;

        replicas = CHFSCONHASH_ERR_REPLICAS;
        tcid     = (uint32_t)CMPI_ERROR_TCID;

        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(replicas)))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_rnode_flush: flush replicas at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(tcid)))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_rnode_flush: flush tcid at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
    }
    else
    {
        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode))))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_rnode_flush: flush replicas at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode))))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_rnode_flush: flush tcid at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL chfsconhash_rnode_load(CHFSCONHASH_RNODE *chfsconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_rnode_load: load replicas at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_RNODE_TCID(chfsconhash_rnode))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_rnode_load: load tcid at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_flush_rnodes(const CHFSCONHASH *chfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    UINT32   rnode_num;
    UINT32   rnode_pos;

    rnode_num = cvector_size(CHFSCONHASH_RNODE_VEC(chfsconhash));

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_flush_rnodes: flush rnode_num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CHFSCONHASH_RNODE *chfsconhash_rnode;
        chfsconhash_rnode = (CHFSCONHASH_RNODE *)cvector_get(CHFSCONHASH_RNODE_VEC(chfsconhash), rnode_pos);
        if(EC_FALSE == chfsconhash_rnode_flush(chfsconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_flush_rnodes: flush rnode %ld# at offset %ld of fd %d failed\n", rnode_pos, (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_load_rnodes(CHFSCONHASH *chfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    UINT32   rnode_num;
    UINT32   rnode_pos;

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load_rnodes: load rnode_num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CHFSCONHASH_RNODE *chfsconhash_rnode;

        chfsconhash_rnode = chfsconhash_rnode_new();
        if(NULL_PTR == chfsconhash_rnode)
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load_rnodes: new rnode at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        if(EC_FALSE == chfsconhash_rnode_load(chfsconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load_rnodes: load rnode %ld# at offset %ld of fd %d failed\n", rnode_pos, (*offset), fd);
            chfsconhash_rnode_free(chfsconhash_rnode);
            return (EC_FALSE);
        }

        if(CHFSCONHASH_ERR_REPLICAS == CHFSCONHASH_RNODE_REPLICAS(chfsconhash_rnode)
        && ((uint32_t)CMPI_ERROR_TCID) == CHFSCONHASH_RNODE_TCID(chfsconhash_rnode))
        {
            cvector_push(CHFSCONHASH_RNODE_VEC(chfsconhash), NULL_PTR);
            chfsconhash_rnode_free(chfsconhash_rnode);
        }
        else
        {
            cvector_push(CHFSCONHASH_RNODE_VEC(chfsconhash), chfsconhash_rnode);
        }
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_vnode_flush(const CHFSCONHASH_VNODE *chfsconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_VNODE_HASH(chfsconhash_vnode))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_vnode_flush: flush hash at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_VNODE_POS(chfsconhash_vnode))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_vnode_flush: flush pos at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_vnode_load(CHFSCONHASH_VNODE *chfsconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_VNODE_HASH(chfsconhash_vnode))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_vnode_load: load hash at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_VNODE_POS(chfsconhash_vnode))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_vnode_load: load pos at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __chfsconhash_flush_vnodes_inorder(const CHFSCONHASH *chfsconhash, const CRB_NODE *node, int fd, UINT32 *offset)
{
    CHFSCONHASH_VNODE *chfsconhash_vnode;
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_FALSE == __chfsconhash_flush_vnodes_inorder(chfsconhash, CRB_NODE_LEFT(node), fd, offset))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:__chfsconhash_flush_vnodes_inorder: flush left subtree %p at offset %ld of fd %d failed\n", CRB_NODE_LEFT(node), (*offset), fd);
            return (EC_FALSE);
        }
    }

    chfsconhash_vnode = (CHFSCONHASH_VNODE *)CRB_NODE_DATA(node);
    if(NULL_PTR == chfsconhash_vnode)
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:__chfsconhash_flush_vnodes_inorder: data of crb node %p is null at offset %ld of fd %d failed\n", node, (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsconhash_vnode_flush(chfsconhash_vnode, fd, offset))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:__chfsconhash_flush_vnodes_inorder: flush vnode %p at offset %ld of fd %d failed\n", chfsconhash_vnode, (*offset), fd);
        return (EC_FALSE);
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_FALSE == __chfsconhash_flush_vnodes_inorder(chfsconhash, CRB_NODE_RIGHT(node), fd, offset))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:__chfsconhash_flush_vnodes_inorder: flush right subtree %p at offset %ld of fd %d failed\n", CRB_NODE_RIGHT(node), (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_flush_vnodes(const CHFSCONHASH *chfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    uint32_t   vnode_num;

    vnode_num = crb_tree_node_num(CHFSCONHASH_VNODE_TREE(chfsconhash));

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_flush_vnodes: flush vnode num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == __chfsconhash_flush_vnodes_inorder(chfsconhash, CRB_TREE_ROOT(CHFSCONHASH_VNODE_TREE(chfsconhash)), fd, offset))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_flush_vnodes: flush vnode tree at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_load_vnodes(CHFSCONHASH *chfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    uint32_t   vnode_num;
    uint32_t   vnode_pos;

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load_vnodes: load vnode num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(vnode_pos = 0; vnode_pos < vnode_num; vnode_pos ++)
    {
        CHFSCONHASH_VNODE *chfsconhash_vnode;

        chfsconhash_vnode = chfsconhash_vnode_new();
        if(NULL_PTR == chfsconhash_vnode)
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load_vnodes: new vnode at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        if(EC_FALSE == chfsconhash_vnode_load(chfsconhash_vnode, fd, offset))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load_vnodes: load vnode %u# at offset %ld of fd %d failed\n", vnode_pos, (*offset), fd);
            chfsconhash_vnode_free(chfsconhash_vnode);
            return (EC_FALSE);
        }

        if(NULL_PTR == chfsconhash_add_vnode(chfsconhash, chfsconhash_vnode))
        {
            dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load_vnodes: add vnode %u# at offset %ld of fd %d failed\n", vnode_pos, (*offset), fd);
            chfsconhash_vnode_free(chfsconhash_vnode);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_flush(const CHFSCONHASH *chfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*flush hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_HASH_ID(chfsconhash))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_flush: flush hash id at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rnode vec*/
    if(EC_FALSE == chfsconhash_flush_rnodes(chfsconhash, fd, offset))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_flush: flush rnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush vnode tree*/
    if(EC_FALSE == chfsconhash_flush_vnodes(chfsconhash, fd, offset))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_flush: flush vnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_load(CHFSCONHASH *chfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*load hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CHFSCONHASH_HASH_ID(chfsconhash))))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load: load hash id at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    CHFSCONHASH_HASH_FUNC(chfsconhash) = chash_algo_fetch(CHFSCONHASH_HASH_ID(chfsconhash));
    if(NULL_PTR == CHFSCONHASH_HASH_FUNC(chfsconhash))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load: invalid hash id %ld\n", CHFSCONHASH_HASH_ID(chfsconhash));
        return (EC_FALSE);
    }

    /*load rnode vec*/
    if(EC_FALSE == chfsconhash_load_rnodes(chfsconhash, fd, offset))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load: load rnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load vnode tree*/
    if(EC_FALSE == chfsconhash_load_vnodes(chfsconhash, fd, offset))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "error:chfsconhash_load: load vnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_rnodes_is_equal(const CHFSCONHASH *chfsconhash_1st, const CHFSCONHASH *chfsconhash_2nd)
{
    return cvector_cmp(CHFSCONHASH_RNODE_VEC(chfsconhash_1st),
                       CHFSCONHASH_RNODE_VEC(chfsconhash_2nd),
                       (CVECTOR_DATA_CMP)chfsconhash_rnode_is_equal);
}

EC_BOOL chfsconhash_vnodes_is_equal(const CHFSCONHASH *chfsconhash_1st, const CHFSCONHASH *chfsconhash_2nd)
{
    return crb_tree_cmp(CHFSCONHASH_VNODE_TREE(chfsconhash_1st),
                        CHFSCONHASH_VNODE_TREE(chfsconhash_2nd),
                        (CRB_DATA_IS_EQUAL)chfsconhash_vnode_is_equal);
}

EC_BOOL chfsconhash_is_equal(const CHFSCONHASH *chfsconhash_1st, const CHFSCONHASH *chfsconhash_2nd)
{
    if(CHFSCONHASH_HASH_ID(chfsconhash_1st) != CHFSCONHASH_HASH_ID(chfsconhash_2nd))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "chfsconhash_is_equal: hash id: %ld != %ld\n",
                           CHFSCONHASH_HASH_ID(chfsconhash_1st),
                           CHFSCONHASH_HASH_ID(chfsconhash_2nd));
        return (EC_FALSE);
    }

    if(CHFSCONHASH_HASH_FUNC(chfsconhash_1st) != CHFSCONHASH_HASH_FUNC(chfsconhash_2nd))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "chfsconhash_is_equal: hash func: %p != %p\n",
                           CHFSCONHASH_HASH_FUNC(chfsconhash_1st),
                           CHFSCONHASH_HASH_FUNC(chfsconhash_2nd));
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsconhash_rnodes_is_equal(chfsconhash_1st, chfsconhash_2nd))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "chfsconhash_is_equal: rnodes is not equal\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chfsconhash_vnodes_is_equal(chfsconhash_1st, chfsconhash_2nd))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "chfsconhash_is_equal: vnodes is not equal\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chfsconhash_clone(const CHFSCONHASH *chfsconhash_src, CHFSCONHASH *chfsconhash_des)
{
    cvector_clone(CHFSCONHASH_RNODE_VEC(chfsconhash_src),
                  CHFSCONHASH_RNODE_VEC(chfsconhash_des),
                  (CVECTOR_DATA_MALLOC)chfsconhash_rnode_new,
                  (CVECTOR_DATA_CLONE)chfsconhash_rnode_clone);

    if(EC_FALSE == crb_tree_clone(CHFSCONHASH_VNODE_TREE(chfsconhash_src),
                                   CHFSCONHASH_VNODE_TREE(chfsconhash_des),
                                   (CRB_DATA_NEW)chfsconhash_vnode_new,
                                   (CRB_DATA_CLONE)chfsconhash_vnode_clone))
    {
        dbg_log(SEC_0162_CHFSCONHASH, 0)(LOGSTDOUT, "chfsconhash_clone: clone vnodes failed\n");
        return (EC_FALSE);
    }

    CHFSCONHASH_HASH_ID(chfsconhash_des)   = CHFSCONHASH_HASH_ID(chfsconhash_src);
    CHFSCONHASH_HASH_FUNC(chfsconhash_des) = CHFSCONHASH_HASH_FUNC(chfsconhash_src);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

