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
#include "cconhash.h"

CCONHASH_RNODE *cconhash_rnode_new()
{
    CCONHASH_RNODE *cconhash_rnode;
    alloc_static_mem(MM_CCONHASH_RNODE, &cconhash_rnode, LOC_CCONHASH_0001);
    if(NULL_PTR != cconhash_rnode)
    {
        cconhash_rnode_init(cconhash_rnode);
    }
    return (cconhash_rnode);
}

CCONHASH_RNODE *cconhash_rnode_make(const uint32_t tcid, const uint16_t replicas)
{
    CCONHASH_RNODE *cconhash_rnode;
    alloc_static_mem(MM_CCONHASH_RNODE, &cconhash_rnode, LOC_CCONHASH_0002);
    if(NULL_PTR != cconhash_rnode)
    {
        CCONHASH_RNODE_REPLICAS(cconhash_rnode) = replicas;
        CCONHASH_RNODE_STATUS(cconhash_rnode)   = CCONHASH_RNODE_IS_UP;
        CCONHASH_RNODE_TCID(cconhash_rnode)     = tcid;

        CCONHASH_RNODE_COUNTER_CLR(cconhash_rnode);
    }
    return (cconhash_rnode);
}

EC_BOOL cconhash_rnode_init(CCONHASH_RNODE *cconhash_rnode)
{
    CCONHASH_RNODE_REPLICAS(cconhash_rnode) = 0;
    CCONHASH_RNODE_STATUS(cconhash_rnode)   = CCONHASH_RNODE_IS_ERR;
    CCONHASH_RNODE_TCID(cconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;

    CCONHASH_RNODE_COUNTER_CLR(cconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL cconhash_rnode_clean(CCONHASH_RNODE *cconhash_rnode)
{
    CCONHASH_RNODE_REPLICAS(cconhash_rnode) = 0;
    CCONHASH_RNODE_STATUS(cconhash_rnode)   = CCONHASH_RNODE_IS_ERR;
    CCONHASH_RNODE_TCID(cconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;

    CCONHASH_RNODE_COUNTER_CLR(cconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL cconhash_rnode_free(CCONHASH_RNODE *cconhash_rnode)
{
    if(NULL_PTR != cconhash_rnode)
    {
        cconhash_rnode_clean(cconhash_rnode);
        free_static_mem(MM_CCONHASH_RNODE, cconhash_rnode, LOC_CCONHASH_0003);
    }
    return (EC_TRUE);
}

EC_BOOL cconhash_rnode_init_0(const UINT32 md_id, CCONHASH_RNODE *cconhash_rnode)
{
    return cconhash_rnode_init(cconhash_rnode);
}

EC_BOOL cconhash_rnode_clean_0(const UINT32 md_id, CCONHASH_RNODE *cconhash_rnode)
{
    return cconhash_rnode_clean(cconhash_rnode);
}

EC_BOOL cconhash_rnode_free_0(const UINT32 md_id, CCONHASH_RNODE *cconhash_rnode)
{
    return cconhash_rnode_free(cconhash_rnode);
}

EC_BOOL cconhash_rnode_clone(const CCONHASH_RNODE *cconhash_rnode_src, CCONHASH_RNODE *cconhash_rnode_des)
{
    CCONHASH_RNODE_REPLICAS(cconhash_rnode_des) = CCONHASH_RNODE_REPLICAS(cconhash_rnode_src);
    CCONHASH_RNODE_STATUS(cconhash_rnode_des)   = CCONHASH_RNODE_STATUS(cconhash_rnode_src);
    CCONHASH_RNODE_TCID(cconhash_rnode_des)     = CCONHASH_RNODE_TCID(cconhash_rnode_src);

    CCONHASH_RNODE_COUNTER_CLONE(cconhash_rnode_src, cconhash_rnode_des);
    return (EC_TRUE);
}

const char *cconhash_rnode_status(const CCONHASH_RNODE *cconhash_rnode)
{
    if(CCONHASH_RNODE_IS_UP == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        return (const char *)"UP";
    }
    if(CCONHASH_RNODE_IS_DOWN == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        return (const char *)"DOWN";
    }

    if(CCONHASH_RNODE_IS_ERR == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

EC_BOOL cconhash_rnode_is_up(const CCONHASH_RNODE *cconhash_rnode)
{
    if(CCONHASH_RNODE_IS_UP == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cconhash_rnode_is_equal(const CCONHASH_RNODE *cconhash_rnode_1st, const CCONHASH_RNODE *cconhash_rnode_2nd)
{
    if(NULL_PTR == cconhash_rnode_1st && NULL_PTR == cconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cconhash_rnode_1st || NULL_PTR == cconhash_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CCONHASH_RNODE_TCID(cconhash_rnode_1st) != CCONHASH_RNODE_TCID(cconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#if 1
    if(CCONHASH_RNODE_REPLICAS(cconhash_rnode_1st) != CCONHASH_RNODE_REPLICAS(cconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#endif
    return (EC_TRUE);
}

EC_BOOL cconhash_rnode_cmp_tcid(const CCONHASH_RNODE *cconhash_rnode_1st, const CCONHASH_RNODE *cconhash_rnode_2nd)
{
    if(NULL_PTR == cconhash_rnode_1st && NULL_PTR == cconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cconhash_rnode_1st || NULL_PTR == cconhash_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CCONHASH_RNODE_TCID(cconhash_rnode_1st) != CCONHASH_RNODE_TCID(cconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void cconhash_rnode_print(LOG *log, const CCONHASH_RNODE *cconhash_rnode)
{
#if(SWITCH_OFF == CCONHASH_RNODE_DEBUG)
    sys_log(log, "cconhash_rnode %p: tcid %s, replicas %u, status %s\n",
                    cconhash_rnode,
                    c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                    CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                    cconhash_rnode_status(cconhash_rnode)
                   );
#endif/*(SWITCH_OFF == CCONHASH_RNODE_DEBUG)*/
#if(SWITCH_ON == CCONHASH_RNODE_DEBUG)
    sys_log(log, "cconhash_rnode %p: tcid %s, replicas %u, status %s, counter %ld\n",
                    cconhash_rnode,
                    c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                    CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                    cconhash_rnode_status(cconhash_rnode),
                    CCONHASH_RNODE_COUNTER(cconhash_rnode)
                   );
#endif/*(SWITCH_ON == CCONHASH_RNODE_DEBUG)*/
    return;
}

CCONHASH_VNODE *cconhash_vnode_new()
{
    CCONHASH_VNODE *cconhash_vnode;
    alloc_static_mem(MM_CCONHASH_VNODE, &cconhash_vnode, LOC_CCONHASH_0004);
    if(NULL_PTR != cconhash_vnode)
    {
        cconhash_vnode_init(cconhash_vnode);
    }
    return (cconhash_vnode);
}

CCONHASH_VNODE *cconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos)
{
    CCONHASH_VNODE *cconhash_vnode;
    alloc_static_mem(MM_CCONHASH_VNODE, &cconhash_vnode, LOC_CCONHASH_0005);
    if(NULL_PTR != cconhash_vnode)
    {
        CCONHASH_VNODE_HASH(cconhash_vnode) = hash;
        CCONHASH_VNODE_POS(cconhash_vnode)  = rnode_pos;
    }
    return (cconhash_vnode);
}

EC_BOOL cconhash_vnode_init(CCONHASH_VNODE *cconhash_vnode)
{
    CCONHASH_VNODE_HASH(cconhash_vnode) = 0;
    CCONHASH_VNODE_POS(cconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cconhash_vnode_clean(CCONHASH_VNODE *cconhash_vnode)
{
    CCONHASH_VNODE_HASH(cconhash_vnode) = 0;
    CCONHASH_VNODE_POS(cconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cconhash_vnode_free(CCONHASH_VNODE *cconhash_vnode)
{
    if(NULL_PTR != cconhash_vnode)
    {
        cconhash_vnode_clean(cconhash_vnode);
        free_static_mem(MM_CCONHASH_VNODE, cconhash_vnode, LOC_CCONHASH_0006);
    }
    return (EC_TRUE);
}

EC_BOOL cconhash_vnode_init_0(const UINT32 md_id, CCONHASH_VNODE *cconhash_vnode)
{
    return cconhash_vnode_init(cconhash_vnode);
}

EC_BOOL cconhash_vnode_clean_0(const UINT32 md_id, CCONHASH_VNODE *cconhash_vnode)
{
    return cconhash_vnode_clean(cconhash_vnode);
}

EC_BOOL cconhash_vnode_free_0(const UINT32 md_id, CCONHASH_VNODE *cconhash_vnode)
{
    return cconhash_vnode_free(cconhash_vnode);
}

EC_BOOL cconhash_vnode_clone(const CCONHASH_VNODE *cconhash_vnode_src, CCONHASH_VNODE *cconhash_vnode_des)
{
    CCONHASH_VNODE_HASH(cconhash_vnode_des) = CCONHASH_VNODE_HASH(cconhash_vnode_src);
    CCONHASH_VNODE_POS(cconhash_vnode_des)  = CCONHASH_VNODE_POS(cconhash_vnode_src);
    return (EC_TRUE);
}

EC_BOOL cconhash_vnode_is_equal(const CCONHASH_VNODE *cconhash_vnode_1st, const CCONHASH_VNODE *cconhash_vnode_2nd)
{
    if(NULL_PTR == cconhash_vnode_1st && NULL_PTR == cconhash_vnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cconhash_vnode_1st || NULL_PTR == cconhash_vnode_2nd)
    {
        return (EC_FALSE);
    }

    if(do_log(SEC_0050_CCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cconhash_vnode_is_equal: check them:\n");
        cconhash_vnode_print(LOGSTDOUT, cconhash_vnode_1st);
        cconhash_vnode_print(LOGSTDOUT, cconhash_vnode_2nd);
    }

    if(CCONHASH_VNODE_HASH(cconhash_vnode_1st) != CCONHASH_VNODE_HASH(cconhash_vnode_2nd))
    {
        dbg_log(SEC_0050_CCONHASH, 6)(LOGSTDOUT, "[DEBUG] cconhash_vnode_is_equal: hash: %x != %x\n",
                           CCONHASH_VNODE_HASH(cconhash_vnode_1st),
                           CCONHASH_VNODE_HASH(cconhash_vnode_2nd));
        return (EC_FALSE);
    }
#if 1
    if(CCONHASH_VNODE_POS(cconhash_vnode_1st) != CCONHASH_VNODE_POS(cconhash_vnode_2nd))
    {
        dbg_log(SEC_0050_CCONHASH, 6)(LOGSTDOUT, "[DEBUG] cconhash_vnode_is_equal: pos: %u != %u\n",
                           CCONHASH_VNODE_POS(cconhash_vnode_1st),
                           CCONHASH_VNODE_POS(cconhash_vnode_2nd));
        return (EC_FALSE);
    }
#endif
    return (EC_TRUE);
}

int cconhash_vnode_cmp(const CCONHASH_VNODE *cconhash_vnode_1st, const CCONHASH_VNODE *cconhash_vnode_2nd)
{
    if(CCONHASH_VNODE_HASH(cconhash_vnode_1st) > CCONHASH_VNODE_HASH(cconhash_vnode_2nd))
    {
        return (1);
    }

    if(CCONHASH_VNODE_HASH(cconhash_vnode_1st) < CCONHASH_VNODE_HASH(cconhash_vnode_2nd))
    {
        return (-1);
    }
    return (0);
}

void cconhash_vnode_print(LOG *log, const CCONHASH_VNODE *cconhash_vnode)
{
    sys_log(log, "cconhash_vnode %p: hash %x, rnode pos %u\n",
                    cconhash_vnode,
                    CCONHASH_VNODE_HASH(cconhash_vnode),
                    CCONHASH_VNODE_POS(cconhash_vnode)
                   );
    return;
}

CCONHASH *cconhash_new(const UINT32 hash_id)
{
    CCONHASH *cconhash;

    alloc_static_mem(MM_CCONHASH, &cconhash, LOC_CCONHASH_0007);
    if(NULL_PTR == cconhash)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_new: alloc cconhash failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cconhash_init(cconhash, hash_id))
    {
        free_static_mem(MM_CCONHASH, cconhash, LOC_CCONHASH_0008);
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_new: init cconhash failed\n");
        return (NULL_PTR);
    }

    return (cconhash);
}

EC_BOOL cconhash_init(CCONHASH *cconhash, const UINT32 hash_id)
{
    CCONHASH_HASH_FUNC(cconhash) = chash_algo_fetch(hash_id);
    if(NULL_PTR == CCONHASH_HASH_FUNC(cconhash))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_init: invalid hash_id %ld\n", hash_id);
        return (EC_FALSE);
    }
    CCONHASH_HASH_ID(cconhash)   = hash_id;

    cvector_init(CCONHASH_RNODE_VEC(cconhash), 0, MM_CCONHASH_RNODE, CVECTOR_LOCK_ENABLE, LOC_CCONHASH_0009);
    crb_tree_init(CCONHASH_VNODE_TREE(cconhash), (CRB_DATA_CMP)cconhash_vnode_cmp, (CRB_DATA_FREE)cconhash_vnode_free,(CRB_DATA_PRINT)cconhash_vnode_print);

    return (EC_TRUE);
}

EC_BOOL cconhash_clean(CCONHASH *cconhash)
{
    cvector_clean(CCONHASH_RNODE_VEC(cconhash), (CVECTOR_DATA_CLEANER)cconhash_rnode_free, LOC_CCONHASH_0010);
    crb_tree_clean(CCONHASH_VNODE_TREE(cconhash));

    CCONHASH_HASH_ID(cconhash)   = CHASH_ERR_ALGO_ID;
    CCONHASH_HASH_FUNC(cconhash) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL cconhash_free(CCONHASH *cconhash)
{
    if(NULL_PTR != cconhash)
    {
        cconhash_clean(cconhash);
        free_static_mem(MM_CCONHASH, cconhash, LOC_CCONHASH_0011);
    }
    return (EC_TRUE);
}

void cconhash_print(LOG *log, const CCONHASH *cconhash)
{
    sys_log(log, "cconhash %p: hash_id %ld, rnode num %ld, vnode num %u\n",
                    cconhash,
                    CCONHASH_HASH_ID(cconhash),
                    cvector_size(CCONHASH_RNODE_VEC(cconhash)),
                    crb_tree_node_num(CCONHASH_VNODE_TREE(cconhash))
                    );

    if(do_log(SEC_0050_CCONHASH, 6))
    {
        sys_log(log, "cconhash %p: rnode vec:\n", cconhash);
        cvector_print(log, CCONHASH_RNODE_VEC(cconhash), (CVECTOR_DATA_PRINT)cconhash_rnode_print);
    }

    if(do_log(SEC_0050_CCONHASH, 7))
    {
        sys_log(log, "cconhash %p: vnode tree:\n", cconhash);
        crb_tree_print(log, CCONHASH_VNODE_TREE(cconhash));
    }

    return;
}

void cconhash_print_rnode_vec(LOG *log, const CCONHASH *cconhash)
{
    sys_log(log, "cconhash %p: hash_id %ld\n",
                    cconhash,
                    CCONHASH_HASH_ID(cconhash));

    sys_log(log, "cconhash %p: rnode vec:\n", cconhash);
    cvector_print(log, CCONHASH_RNODE_VEC(cconhash), (CVECTOR_DATA_PRINT)cconhash_rnode_print);

    return;
}

void cconhash_print_vnode_tree(LOG *log, const CCONHASH *cconhash)
{
    sys_log(log, "cconhash %p: hash_id %ld\n",
                    cconhash,
                    CCONHASH_HASH_ID(cconhash));

    sys_log(log, "cconhash %p: vnode tree:\n", cconhash);
    crb_tree_print(log, CCONHASH_VNODE_TREE(cconhash));

    return;
}

UINT32 cconhash_add_rnode(CCONHASH *cconhash, const CCONHASH_RNODE *cconhash_rnode)
{
    return cvector_add(CCONHASH_RNODE_VEC(cconhash), (void *)cconhash_rnode);
}

CRB_NODE *cconhash_add_vnode(CCONHASH *cconhash, const CCONHASH_VNODE *cconhash_vnode)
{
    return crb_tree_insert_data(CCONHASH_VNODE_TREE(cconhash), (void *)cconhash_vnode);
}

STATIC_CAST static uint32_t __cconhash_hash_vnode(CCONHASH *cconhash, const uint32_t tcid, const uint16_t replica, const UINT32 salt)
{
    char     str[64];
    uint32_t len;
    uint32_t hash;

    len  = snprintf(str, sizeof(str), "%s.%u.%ld", c_word_to_ipv4(tcid), (uint32_t)(replica * replica), salt);
    hash = (uint32_t)CCONHASH_HASH_FUNC(cconhash)(len, (UINT8 *)str);

    return (hash);
}

EC_BOOL cconhash_add_vnode_replicas(CCONHASH *cconhash, const UINT32 cconhash_rnode_pos)
{
    CCONHASH_RNODE *cconhash_rnode;

    uint32_t tcid;
    uint16_t replica;

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);
    if(NULL_PTR == cconhash_rnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: not found rnode at pos %ld\n",
                           cconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (cconhash_rnode_pos >> 16));

    tcid = CCONHASH_RNODE_TCID(cconhash_rnode);
    for(replica = 0; replica < CCONHASH_RNODE_REPLICAS(cconhash_rnode); replica ++)
    {
        uint32_t hash;

        CCONHASH_VNODE *cconhash_vnode;
        CRB_NODE          *crb_node;

        hash = __cconhash_hash_vnode(cconhash, tcid, replica, cconhash_rnode_pos);

        cconhash_vnode = cconhash_vnode_make(hash, (uint16_t)cconhash_rnode_pos);
        if(NULL_PTR == cconhash_vnode)
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cconhash_rnode_pos);
            return (EC_FALSE);
        }

        crb_node = crb_tree_insert_data(CCONHASH_VNODE_TREE(cconhash), (void *)cconhash_vnode);
        if(NULL_PTR == crb_node)
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: insert vnode (hash %x, tcid %s, replica %u, rnode pos %u) to rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cconhash_rnode_pos);
            cconhash_vnode_free(cconhash_vnode);
            return (EC_FALSE);
        }

        /*fix*/
        if(cconhash_vnode != CRB_NODE_DATA(crb_node))
        {
            CCONHASH_VNODE *cconhash_vnode_duplicate;
            CCONHASH_RNODE *cconhash_rnode_duplicate;

            cconhash_vnode_duplicate = (CCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
            cconhash_rnode_duplicate = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), CCONHASH_VNODE_POS(cconhash_vnode_duplicate));

            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: found duplicate vnode:\n");

            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: found duplicate vnode:[1]\n");
            cconhash_vnode_print(LOGSTDOUT, cconhash_vnode);
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: found duplicate rnode:[1]\n");
            cconhash_rnode_print(LOGSTDOUT, cconhash_rnode);

            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: found duplicate vnode:[2]\n");
            cconhash_vnode_print(LOGSTDOUT, cconhash_vnode_duplicate);
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: found duplicate rnode:[2]\n");
            cconhash_rnode_print(LOGSTDOUT, cconhash_rnode_duplicate);

            cconhash_vnode_free(cconhash_vnode);

            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: pls make sure hash is unique!\n");
            exit( 5 );
        }
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_del_vnode_replicas(CCONHASH *cconhash, const UINT32 cconhash_rnode_pos)
{
    CCONHASH_RNODE *cconhash_rnode;

    uint32_t tcid;
    uint16_t replica;

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);
    if(NULL_PTR == cconhash_rnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_del_vnode_replicas: not found rnode at pos %ld\n",
                           cconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (cconhash_rnode_pos >> 16));

    tcid = CCONHASH_RNODE_TCID(cconhash_rnode);
    for(replica = 0; replica < CCONHASH_RNODE_REPLICAS(cconhash_rnode); replica ++)
    {
        uint32_t hash;

        CCONHASH_VNODE *cconhash_vnode;

        hash = __cconhash_hash_vnode(cconhash, tcid, replica, cconhash_rnode_pos);

        cconhash_vnode = cconhash_vnode_make(hash, (uint16_t)cconhash_rnode_pos);
        if(NULL_PTR == cconhash_vnode)
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_del_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cconhash_rnode_pos);
            return (EC_FALSE);
        }

        if(EC_FALSE == crb_tree_delete_data(CCONHASH_VNODE_TREE(cconhash), (void *)cconhash_vnode))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_del_vnode_replicas: del vnode (hash %x, tcid %s, replica %u, rnode pos %u) from rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cconhash_rnode_pos);
            cconhash_vnode_free(cconhash_vnode);
            return (EC_FALSE);
        }

        cconhash_vnode_free(cconhash_vnode);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_add_node(CCONHASH *cconhash, const uint32_t tcid, const uint16_t replicas)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    CCONHASH_RNODE *cconhash_rnode;
    UINT32             cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS != cconhash_rnode_pos)
    {
        cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: found rnode (tcid %s, replicas %u, status %s)\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    cconhash_rnode = cconhash_rnode_make(tcid, replicas);
    if(NULL_PTR == cconhash_rnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: make rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(tcid), replicas);
        return (EC_FALSE);
    }

    /*add rnode*/
    cconhash_rnode_pos = cconhash_add_rnode(cconhash, cconhash_rnode);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: add rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));

        cconhash_rnode_free(cconhash_rnode);
        return (EC_FALSE);
    }

    ASSERT(0 == (cconhash_rnode_pos >> 16));
#if 1
    /*add vnode replicas*/
    if(EC_FALSE == cconhash_add_vnode_replicas(cconhash, cconhash_rnode_pos))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: add vnode replicas of rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode));

        cconhash_del_vnode_replicas(cconhash, cconhash_rnode_pos);/*roll back*/

        cvector_set(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos, NULL_PTR);
        cconhash_rnode_free(cconhash_rnode);
        return (EC_FALSE);
    }
#endif
    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_add_node: rnode (tcid %s, replicas %u, status %s) add => OK\n",
                       c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                       CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                       cconhash_rnode_status(cconhash_rnode));
    return (EC_TRUE);
}

/*for any replica: replicas = 0*/
EC_BOOL cconhash_del_node(CCONHASH *cconhash, const uint32_t tcid)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    CCONHASH_RNODE *cconhash_rnode;
    UINT32             cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_del_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

    ASSERT(0 == (cconhash_rnode_pos >> 16));

    /*del vnode replicas*/
    if(EC_FALSE == cconhash_del_vnode_replicas(cconhash, cconhash_rnode_pos))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_del_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_del_node: rnode (tcid %s, replicas %u, status %s) del => OK\n",
                       c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                       CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                       cconhash_rnode_status(cconhash_rnode));

    /*del rnode*/
    cvector_set(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos, NULL_PTR);
    cconhash_rnode_free(cconhash_rnode);

    return (EC_TRUE);
}

EC_BOOL cconhash_up_node(CCONHASH *cconhash, const uint32_t tcid)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    CCONHASH_RNODE *cconhash_rnode;
    UINT32             cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_up_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (cconhash_rnode_pos >> 16));

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

    if(CCONHASH_RNODE_IS_UP == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_up_node: rnode (tcid %s, replicas %u, status %s) is already up\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_TRUE);
    }
#if 0
    if(CCONHASH_RNODE_IS_DOWN != CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_up_node: rnode (tcid %s, replicas %u, status %s) is not down\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }
#endif

    if(CCONHASH_ERR_REPLICAS == CCONHASH_RNODE_REPLICAS(cconhash_rnode)
    || CCONHASH_ANY_REPLICAS == CCONHASH_RNODE_REPLICAS(cconhash_rnode))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_up_node: rnode (tcid %s, replicas %u, status %s) has invalid replica\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    /*add vnode replicas*/
    if(EC_FALSE == cconhash_add_vnode_replicas(cconhash, cconhash_rnode_pos))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_up_node: add vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));

        cconhash_del_vnode_replicas(cconhash, cconhash_rnode_pos);/*roll back*/
        return (EC_FALSE);
    }

    CCONHASH_RNODE_STATUS(cconhash_rnode) = CCONHASH_RNODE_IS_UP; /*set up*/

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_up_node: rnode (tcid %s, replicas %u, status %s) set up => OK\n",
                       c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                       CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                       cconhash_rnode_status(cconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL cconhash_down_node(CCONHASH *cconhash, const uint32_t tcid)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    CCONHASH_RNODE *cconhash_rnode;
    UINT32             cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_down_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (cconhash_rnode_pos >> 16));

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

    if(CCONHASH_RNODE_IS_DOWN == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_down_node: rnode (tcid %s, replicas %u, status %s) is already down\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_TRUE);
    }
#if 0
    if(CCONHASH_RNODE_IS_UP != CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_down_node: rnode (tcid %s, replicas %u, status %s) is not up\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }
#endif
    /*del vnode replicas*/
    if(EC_FALSE == cconhash_del_vnode_replicas(cconhash, cconhash_rnode_pos))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_down_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    CCONHASH_RNODE_STATUS(cconhash_rnode) = CCONHASH_RNODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_down_node: rnode (tcid %s, replicas %u, status %s) set down => OK\n",
                       c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                       CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                       cconhash_rnode_status(cconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL cconhash_has_node(const CCONHASH *cconhash, const uint32_t tcid)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    UINT32             cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "info:cconhash_has_node: tcid %s is not in rnode\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CCONHASH_RNODE *cconhash_get_rnode(const CCONHASH *cconhash, const uint32_t tcid)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    CCONHASH_RNODE *cconhash_rnode;
    UINT32             cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_get_rnode: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);
    return (cconhash_rnode);
}

CCONHASH_RNODE *cconhash_lookup_rnode(const CCONHASH *cconhash, const uint32_t hash)
{
    CCONHASH_VNODE  cconhash_vnode_t;
    CCONHASH_VNODE *cconhash_vnode;
    CCONHASH_RNODE *cconhash_rnode;
    CRB_NODE *crb_node;

    if(EC_TRUE == crb_tree_is_empty(CCONHASH_VNODE_TREE(cconhash)))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_lookup_rnode: vnode tree is empty\n");
        return (NULL_PTR);
    }

    CCONHASH_VNODE_HASH(&cconhash_vnode_t) = hash;
    crb_node = crb_tree_lookup_data(CCONHASH_VNODE_TREE(cconhash), (void *)&cconhash_vnode_t);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_lookup_rnode: hash %x, should never reach here due to rbtree be circled\n",
                           hash);
        return (NULL_PTR);
    }

    cconhash_vnode = (CCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
    if(NULL_PTR == cconhash_vnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_lookup_rnode: hash %x, crb_node %p, should never reach here due to CRB_NODE_DATA be null!\n",
                           hash, crb_node);
        return (NULL_PTR);
    }
#if 0
    if(do_log(SEC_0050_CCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cconhash_lookup_rnode: hash %x => vnode ", hash);
        cconhash_vnode_print(LOGSTDOUT, cconhash_vnode);
    }
#endif
    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash),
                                                         CCONHASH_VNODE_POS(cconhash_vnode));
    if(NULL_PTR == cconhash_rnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_lookup_rnode: hash %x, rnode_pos %u, should never reach here due to rnode not existing\n",
                           hash, CCONHASH_VNODE_POS(cconhash_vnode));
        return (NULL_PTR);
    }
    return (cconhash_rnode);
}

EC_BOOL cconhash_flush_size(const CCONHASH *cconhash, UINT32 *size)
{
    (*size) = sizeof(UINT32) /*hash_id*/
            + sizeof(UINT32) /*rnode_vec size*/
            + cvector_size(CCONHASH_RNODE_VEC(cconhash)) * (
                                                                    sizeof(uint16_t) /*replicas*/
                                                                  + sizeof(uint32_t) /*tcid*/
                                                                  )
            + sizeof(uint32_t) /*vnode_tree size*/
            + crb_tree_node_num(CCONHASH_VNODE_TREE(cconhash)) * (
                                                                     sizeof(uint32_t) /*hash*/
                                                                   + sizeof(uint32_t) /*pos*/
                                                                   );
    return (EC_FALSE);
}

EC_BOOL cconhash_rnode_flush(const CCONHASH_RNODE *cconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    if(NULL_PTR == cconhash_rnode)
    {
        uint32_t     tcid;
        uint16_t     replicas;

        replicas = CCONHASH_ERR_REPLICAS;
        tcid     = (uint32_t)CMPI_ERROR_TCID;

        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(replicas)))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_rnode_flush: flush replicas at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(tcid)))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_rnode_flush: flush tcid at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
    }
    else
    {
        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CCONHASH_RNODE_REPLICAS(cconhash_rnode))))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_rnode_flush: flush replicas at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CCONHASH_RNODE_TCID(cconhash_rnode))))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_rnode_flush: flush tcid at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cconhash_rnode_load(CCONHASH_RNODE *cconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CCONHASH_RNODE_REPLICAS(cconhash_rnode))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_rnode_load: load replicas at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CCONHASH_RNODE_TCID(cconhash_rnode))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_rnode_load: load tcid at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_flush_rnodes(const CCONHASH *cconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    UINT32   rnode_num;
    UINT32   rnode_pos;

    rnode_num = cvector_size(CCONHASH_RNODE_VEC(cconhash));

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_flush_rnodes: flush rnode_num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CCONHASH_RNODE *cconhash_rnode;
        cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), rnode_pos);
        if(EC_FALSE == cconhash_rnode_flush(cconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_flush_rnodes: flush rnode %ld# at offset %ld of fd %d failed\n", rnode_pos, (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_load_rnodes(CCONHASH *cconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    UINT32   rnode_num;
    UINT32   rnode_pos;

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load_rnodes: load rnode_num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CCONHASH_RNODE *cconhash_rnode;

        cconhash_rnode = cconhash_rnode_new();
        if(NULL_PTR == cconhash_rnode)
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load_rnodes: new rnode at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        if(EC_FALSE == cconhash_rnode_load(cconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load_rnodes: load rnode %ld# at offset %ld of fd %d failed\n", rnode_pos, (*offset), fd);
            cconhash_rnode_free(cconhash_rnode);
            return (EC_FALSE);
        }

        if(CCONHASH_ERR_REPLICAS == CCONHASH_RNODE_REPLICAS(cconhash_rnode)
        && ((uint32_t)CMPI_ERROR_TCID) == CCONHASH_RNODE_TCID(cconhash_rnode))
        {
            cvector_push(CCONHASH_RNODE_VEC(cconhash), NULL_PTR);
            cconhash_rnode_free(cconhash_rnode);
        }
        else
        {
            cvector_push(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_vnode_flush(const CCONHASH_VNODE *cconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CCONHASH_VNODE_HASH(cconhash_vnode))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_vnode_flush: flush hash at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CCONHASH_VNODE_POS(cconhash_vnode))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_vnode_flush: flush pos at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_vnode_load(CCONHASH_VNODE *cconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CCONHASH_VNODE_HASH(cconhash_vnode))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_vnode_load: load hash at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CCONHASH_VNODE_POS(cconhash_vnode))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_vnode_load: load pos at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cconhash_flush_vnodes_inorder(const CCONHASH *cconhash, const CRB_NODE *node, int fd, UINT32 *offset)
{
    CCONHASH_VNODE *cconhash_vnode;
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_FALSE == __cconhash_flush_vnodes_inorder(cconhash, CRB_NODE_LEFT(node), fd, offset))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:__cconhash_flush_vnodes_inorder: flush left subtree %p at offset %ld of fd %d failed\n", CRB_NODE_LEFT(node), (*offset), fd);
            return (EC_FALSE);
        }
    }

    cconhash_vnode = (CCONHASH_VNODE *)CRB_NODE_DATA(node);
    if(NULL_PTR == cconhash_vnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:__cconhash_flush_vnodes_inorder: data of crb node %p is null at offset %ld of fd %d failed\n", node, (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == cconhash_vnode_flush(cconhash_vnode, fd, offset))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:__cconhash_flush_vnodes_inorder: flush vnode %p at offset %ld of fd %d failed\n", cconhash_vnode, (*offset), fd);
        return (EC_FALSE);
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_FALSE == __cconhash_flush_vnodes_inorder(cconhash, CRB_NODE_RIGHT(node), fd, offset))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:__cconhash_flush_vnodes_inorder: flush right subtree %p at offset %ld of fd %d failed\n", CRB_NODE_RIGHT(node), (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_flush_vnodes(const CCONHASH *cconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    uint32_t   vnode_num;

    vnode_num = crb_tree_node_num(CCONHASH_VNODE_TREE(cconhash));

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_flush_vnodes: flush vnode num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cconhash_flush_vnodes_inorder(cconhash, CRB_TREE_ROOT(CCONHASH_VNODE_TREE(cconhash)), fd, offset))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_flush_vnodes: flush vnode tree at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_load_vnodes(CCONHASH *cconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    uint32_t   vnode_num;
    uint32_t   vnode_pos;

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load_vnodes: load vnode num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(vnode_pos = 0; vnode_pos < vnode_num; vnode_pos ++)
    {
        CCONHASH_VNODE *cconhash_vnode;

        cconhash_vnode = cconhash_vnode_new();
        if(NULL_PTR == cconhash_vnode)
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load_vnodes: new vnode at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        if(EC_FALSE == cconhash_vnode_load(cconhash_vnode, fd, offset))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load_vnodes: load vnode %u# at offset %ld of fd %d failed\n", vnode_pos, (*offset), fd);
            cconhash_vnode_free(cconhash_vnode);
            return (EC_FALSE);
        }

        if(NULL_PTR == cconhash_add_vnode(cconhash, cconhash_vnode))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load_vnodes: add vnode %u# at offset %ld of fd %d failed\n", vnode_pos, (*offset), fd);
            cconhash_vnode_free(cconhash_vnode);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_flush(const CCONHASH *cconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*flush hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CCONHASH_HASH_ID(cconhash))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_flush: flush hash id at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rnode vec*/
    if(EC_FALSE == cconhash_flush_rnodes(cconhash, fd, offset))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_flush: flush rnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush vnode tree*/
    if(EC_FALSE == cconhash_flush_vnodes(cconhash, fd, offset))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_flush: flush vnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_load(CCONHASH *cconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*load hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CCONHASH_HASH_ID(cconhash))))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load: load hash id at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    CCONHASH_HASH_FUNC(cconhash) = chash_algo_fetch(CCONHASH_HASH_ID(cconhash));
    if(NULL_PTR == CCONHASH_HASH_FUNC(cconhash))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load: invalid hash id %ld\n", CCONHASH_HASH_ID(cconhash));
        return (EC_FALSE);
    }

    /*load rnode vec*/
    if(EC_FALSE == cconhash_load_rnodes(cconhash, fd, offset))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load: load rnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load vnode tree*/
    if(EC_FALSE == cconhash_load_vnodes(cconhash, fd, offset))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_load: load vnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_rnodes_is_equal(const CCONHASH *cconhash_1st, const CCONHASH *cconhash_2nd)
{
    return cvector_cmp(CCONHASH_RNODE_VEC(cconhash_1st),
                       CCONHASH_RNODE_VEC(cconhash_2nd),
                       (CVECTOR_DATA_CMP)cconhash_rnode_is_equal);
}

EC_BOOL cconhash_vnodes_is_equal(const CCONHASH *cconhash_1st, const CCONHASH *cconhash_2nd)
{
    return crb_tree_cmp(CCONHASH_VNODE_TREE(cconhash_1st),
                        CCONHASH_VNODE_TREE(cconhash_2nd),
                        (CRB_DATA_IS_EQUAL)cconhash_vnode_is_equal);
}

EC_BOOL cconhash_is_equal(const CCONHASH *cconhash_1st, const CCONHASH *cconhash_2nd)
{
    if(CCONHASH_HASH_ID(cconhash_1st) != CCONHASH_HASH_ID(cconhash_2nd))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "cconhash_is_equal: hash id: %ld != %ld\n",
                           CCONHASH_HASH_ID(cconhash_1st),
                           CCONHASH_HASH_ID(cconhash_2nd));
        return (EC_FALSE);
    }

    if(CCONHASH_HASH_FUNC(cconhash_1st) != CCONHASH_HASH_FUNC(cconhash_2nd))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "cconhash_is_equal: hash func: %p != %p\n",
                           CCONHASH_HASH_FUNC(cconhash_1st),
                           CCONHASH_HASH_FUNC(cconhash_2nd));
        return (EC_FALSE);
    }

    if(EC_FALSE == cconhash_rnodes_is_equal(cconhash_1st, cconhash_2nd))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "cconhash_is_equal: rnodes is not equal\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cconhash_vnodes_is_equal(cconhash_1st, cconhash_2nd))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "cconhash_is_equal: vnodes is not equal\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_clone(const CCONHASH *cconhash_src, CCONHASH *cconhash_des)
{
    cvector_clone(CCONHASH_RNODE_VEC(cconhash_src),
                  CCONHASH_RNODE_VEC(cconhash_des),
                  (CVECTOR_DATA_MALLOC)cconhash_rnode_new,
                  (CVECTOR_DATA_CLONE)cconhash_rnode_clone);

    if(EC_FALSE == crb_tree_clone(CCONHASH_VNODE_TREE(cconhash_src),
                                   CCONHASH_VNODE_TREE(cconhash_des),
                                   (CRB_DATA_NEW)cconhash_vnode_new,
                                   (CRB_DATA_CLONE)cconhash_vnode_clone))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "cconhash_clone: clone vnodes failed\n");
        return (EC_FALSE);
    }

    CCONHASH_HASH_ID(cconhash_des)   = CCONHASH_HASH_ID(cconhash_src);
    CCONHASH_HASH_FUNC(cconhash_des) = CCONHASH_HASH_FUNC(cconhash_src);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

