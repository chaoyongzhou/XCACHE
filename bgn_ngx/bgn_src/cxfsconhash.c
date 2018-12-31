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
#include "cxfsconhash.h"

CXFSCONHASH_RNODE *cxfsconhash_rnode_new()
{
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    alloc_static_mem(MM_CXFSCONHASH_RNODE, &cxfsconhash_rnode, LOC_CXFSCONHASH_0001);
    if(NULL_PTR != cxfsconhash_rnode)
    {
        cxfsconhash_rnode_init(cxfsconhash_rnode);
    }
    return (cxfsconhash_rnode);
}

CXFSCONHASH_RNODE *cxfsconhash_rnode_make(const uint32_t tcid, const uint16_t replicas)
{
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    alloc_static_mem(MM_CXFSCONHASH_RNODE, &cxfsconhash_rnode, LOC_CXFSCONHASH_0002);
    if(NULL_PTR != cxfsconhash_rnode)
    {
        CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode) = replicas;
        CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode)   = CXFSCONHASH_RNODE_IS_UP;
        CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)     = tcid;

        CXFSCONHASH_RNODE_COUNTER_CLR(cxfsconhash_rnode);
    }
    return (cxfsconhash_rnode);
}

EC_BOOL cxfsconhash_rnode_init(CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode) = 0;
    CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode)   = CXFSCONHASH_RNODE_IS_ERR;
    CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;

    CXFSCONHASH_RNODE_COUNTER_CLR(cxfsconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_rnode_clean(CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode) = 0;
    CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode)   = CXFSCONHASH_RNODE_IS_ERR;
    CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;

    CXFSCONHASH_RNODE_COUNTER_CLR(cxfsconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_rnode_free(CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    if(NULL_PTR != cxfsconhash_rnode)
    {
        cxfsconhash_rnode_clean(cxfsconhash_rnode);
        free_static_mem(MM_CXFSCONHASH_RNODE, cxfsconhash_rnode, LOC_CXFSCONHASH_0003);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_rnode_init_0(const UINT32 md_id, CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    return cxfsconhash_rnode_init(cxfsconhash_rnode);
}

EC_BOOL cxfsconhash_rnode_clean_0(const UINT32 md_id, CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    return cxfsconhash_rnode_clean(cxfsconhash_rnode);
}

EC_BOOL cxfsconhash_rnode_free_0(const UINT32 md_id, CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    return cxfsconhash_rnode_free(cxfsconhash_rnode);
}

EC_BOOL cxfsconhash_rnode_clone(const CXFSCONHASH_RNODE *cxfsconhash_rnode_src, CXFSCONHASH_RNODE *cxfsconhash_rnode_des)
{
    CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode_des) = CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode_src);
    CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode_des)   = CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode_src);
    CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode_des)     = CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode_src);

    CXFSCONHASH_RNODE_COUNTER_CLONE(cxfsconhash_rnode_src, cxfsconhash_rnode_des);
    return (EC_TRUE);
}

const char *cxfsconhash_rnode_status(const CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    if(CXFSCONHASH_RNODE_IS_UP == CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        return (const char *)"UP";
    }
    if(CXFSCONHASH_RNODE_IS_DOWN == CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        return (const char *)"DOWN";
    }

    if(CXFSCONHASH_RNODE_IS_ERR == CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

EC_BOOL cxfsconhash_rnode_is_up(const CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    if(CXFSCONHASH_RNODE_IS_UP == CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cxfsconhash_rnode_is_equal(const CXFSCONHASH_RNODE *cxfsconhash_rnode_1st, const CXFSCONHASH_RNODE *cxfsconhash_rnode_2nd)
{
    if(NULL_PTR == cxfsconhash_rnode_1st && NULL_PTR == cxfsconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cxfsconhash_rnode_1st || NULL_PTR == cxfsconhash_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode_1st) != CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#if 1
    if(CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode_1st) != CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#endif
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_rnode_cmp_tcid(const CXFSCONHASH_RNODE *cxfsconhash_rnode_1st, const CXFSCONHASH_RNODE *cxfsconhash_rnode_2nd)
{
    if(NULL_PTR == cxfsconhash_rnode_1st && NULL_PTR == cxfsconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cxfsconhash_rnode_1st || NULL_PTR == cxfsconhash_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode_1st) != CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void cxfsconhash_rnode_print(LOG *log, const CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
#if(SWITCH_OFF == CXFSCONHASH_RNODE_DEBUG)
    sys_log(log, "cxfsconhash_rnode %p: tcid %s, replicas %u, status %s\n",
                    cxfsconhash_rnode,
                    c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                    CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                    cxfsconhash_rnode_status(cxfsconhash_rnode)
                   );
#endif/*(SWITCH_OFF == CXFSCONHASH_RNODE_DEBUG)*/
#if(SWITCH_ON == CXFSCONHASH_RNODE_DEBUG)
    sys_log(log, "cxfsconhash_rnode %p: tcid %s, replicas %u, status %s, counter %ld\n",
                    cxfsconhash_rnode,
                    c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                    CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                    cxfsconhash_rnode_status(cxfsconhash_rnode),
                    CXFSCONHASH_RNODE_COUNTER(cxfsconhash_rnode)
                   );
#endif/*(SWITCH_ON == CXFSCONHASH_RNODE_DEBUG)*/
    return;
}

CXFSCONHASH_VNODE *cxfsconhash_vnode_new()
{
    CXFSCONHASH_VNODE *cxfsconhash_vnode;
    alloc_static_mem(MM_CXFSCONHASH_VNODE, &cxfsconhash_vnode, LOC_CXFSCONHASH_0004);
    if(NULL_PTR != cxfsconhash_vnode)
    {
        cxfsconhash_vnode_init(cxfsconhash_vnode);
    }
    return (cxfsconhash_vnode);
}

CXFSCONHASH_VNODE *cxfsconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos)
{
    CXFSCONHASH_VNODE *cxfsconhash_vnode;
    alloc_static_mem(MM_CXFSCONHASH_VNODE, &cxfsconhash_vnode, LOC_CXFSCONHASH_0005);
    if(NULL_PTR != cxfsconhash_vnode)
    {
        CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode) = hash;
        CXFSCONHASH_VNODE_POS(cxfsconhash_vnode)  = rnode_pos;
    }
    return (cxfsconhash_vnode);
}

EC_BOOL cxfsconhash_vnode_init(CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode) = 0;
    CXFSCONHASH_VNODE_POS(cxfsconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_vnode_clean(CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode) = 0;
    CXFSCONHASH_VNODE_POS(cxfsconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_vnode_free(CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    if(NULL_PTR != cxfsconhash_vnode)
    {
        cxfsconhash_vnode_clean(cxfsconhash_vnode);
        free_static_mem(MM_CXFSCONHASH_VNODE, cxfsconhash_vnode, LOC_CXFSCONHASH_0006);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_vnode_init_0(const UINT32 md_id, CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    return cxfsconhash_vnode_init(cxfsconhash_vnode);
}

EC_BOOL cxfsconhash_vnode_clean_0(const UINT32 md_id, CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    return cxfsconhash_vnode_clean(cxfsconhash_vnode);
}

EC_BOOL cxfsconhash_vnode_free_0(const UINT32 md_id, CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    return cxfsconhash_vnode_free(cxfsconhash_vnode);
}

EC_BOOL cxfsconhash_vnode_clone(const CXFSCONHASH_VNODE *cxfsconhash_vnode_src, CXFSCONHASH_VNODE *cxfsconhash_vnode_des)
{
    CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_des) = CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_src);
    CXFSCONHASH_VNODE_POS(cxfsconhash_vnode_des)  = CXFSCONHASH_VNODE_POS(cxfsconhash_vnode_src);
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_vnode_is_equal(const CXFSCONHASH_VNODE *cxfsconhash_vnode_1st, const CXFSCONHASH_VNODE *cxfsconhash_vnode_2nd)
{
    if(NULL_PTR == cxfsconhash_vnode_1st && NULL_PTR == cxfsconhash_vnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == cxfsconhash_vnode_1st || NULL_PTR == cxfsconhash_vnode_2nd)
    {
        return (EC_FALSE);
    }

    if(do_log(SEC_0199_CXFSCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfsconhash_vnode_is_equal: check them:\n");
        cxfsconhash_vnode_print(LOGSTDOUT, cxfsconhash_vnode_1st);
        cxfsconhash_vnode_print(LOGSTDOUT, cxfsconhash_vnode_2nd);
    }

    if(CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_1st) != CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_2nd))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 6)(LOGSTDOUT, "[DEBUG] cxfsconhash_vnode_is_equal: hash: %x != %x\n",
                           CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_1st),
                           CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_2nd));
        return (EC_FALSE);
    }
#if 1
    if(CXFSCONHASH_VNODE_POS(cxfsconhash_vnode_1st) != CXFSCONHASH_VNODE_POS(cxfsconhash_vnode_2nd))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 6)(LOGSTDOUT, "[DEBUG] cxfsconhash_vnode_is_equal: pos: %u != %u\n",
                           CXFSCONHASH_VNODE_POS(cxfsconhash_vnode_1st),
                           CXFSCONHASH_VNODE_POS(cxfsconhash_vnode_2nd));
        return (EC_FALSE);
    }
#endif
    return (EC_TRUE);
}

int cxfsconhash_vnode_cmp(const CXFSCONHASH_VNODE *cxfsconhash_vnode_1st, const CXFSCONHASH_VNODE *cxfsconhash_vnode_2nd)
{
    if(CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_1st) > CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_2nd))
    {
        return (1);
    }

    if(CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_1st) < CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode_2nd))
    {
        return (-1);
    }
    return (0);
}

void cxfsconhash_vnode_print(LOG *log, const CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    sys_log(log, "cxfsconhash_vnode %p: hash %x, rnode pos %u\n",
                    cxfsconhash_vnode,
                    CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode),
                    CXFSCONHASH_VNODE_POS(cxfsconhash_vnode)
                   );
    return;
}

CXFSCONHASH *cxfsconhash_new(const UINT32 hash_id)
{
    CXFSCONHASH *cxfsconhash;

    alloc_static_mem(MM_CXFSCONHASH, &cxfsconhash, LOC_CXFSCONHASH_0007);
    if(NULL_PTR == cxfsconhash)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_new: alloc cxfsconhash failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsconhash_init(cxfsconhash, hash_id))
    {
        free_static_mem(MM_CXFSCONHASH, cxfsconhash, LOC_CXFSCONHASH_0008);
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_new: init cxfsconhash failed\n");
        return (NULL_PTR);
    }

    return (cxfsconhash);
}

EC_BOOL cxfsconhash_init(CXFSCONHASH *cxfsconhash, const UINT32 hash_id)
{
    CXFSCONHASH_HASH_FUNC(cxfsconhash) = chash_algo_fetch(hash_id);
    if(NULL_PTR == CXFSCONHASH_HASH_FUNC(cxfsconhash))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_init: invalid hash_id %ld\n", hash_id);
        return (EC_FALSE);
    }
    CXFSCONHASH_HASH_ID(cxfsconhash)   = hash_id;

    cvector_init(CXFSCONHASH_RNODE_VEC(cxfsconhash), 0, MM_CXFSCONHASH_RNODE, CVECTOR_LOCK_ENABLE, LOC_CXFSCONHASH_0009);
    crb_tree_init(CXFSCONHASH_VNODE_TREE(cxfsconhash), (CRB_DATA_CMP)cxfsconhash_vnode_cmp, (CRB_DATA_FREE)cxfsconhash_vnode_free,(CRB_DATA_PRINT)cxfsconhash_vnode_print);

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_clean(CXFSCONHASH *cxfsconhash)
{
    cvector_clean(CXFSCONHASH_RNODE_VEC(cxfsconhash), (CVECTOR_DATA_CLEANER)cxfsconhash_rnode_free, LOC_CXFSCONHASH_0010);
    crb_tree_clean(CXFSCONHASH_VNODE_TREE(cxfsconhash));

    CXFSCONHASH_HASH_ID(cxfsconhash)   = CHASH_ERR_ALGO_ID;
    CXFSCONHASH_HASH_FUNC(cxfsconhash) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_free(CXFSCONHASH *cxfsconhash)
{
    if(NULL_PTR != cxfsconhash)
    {
        cxfsconhash_clean(cxfsconhash);
        free_static_mem(MM_CXFSCONHASH, cxfsconhash, LOC_CXFSCONHASH_0011);
    }
    return (EC_TRUE);
}

void cxfsconhash_print(LOG *log, const CXFSCONHASH *cxfsconhash)
{
    sys_log(log, "cxfsconhash %p: hash_id %ld, rnode num %ld, vnode num %u\n",
                    cxfsconhash,
                    CXFSCONHASH_HASH_ID(cxfsconhash),
                    cvector_size(CXFSCONHASH_RNODE_VEC(cxfsconhash)),
                    crb_tree_node_num(CXFSCONHASH_VNODE_TREE(cxfsconhash))
                    );

    if(do_log(SEC_0199_CXFSCONHASH, 6))
    {
        sys_log(log, "cxfsconhash %p: rnode vec:\n", cxfsconhash);
        cvector_print(log, CXFSCONHASH_RNODE_VEC(cxfsconhash), (CVECTOR_DATA_PRINT)cxfsconhash_rnode_print);
    }

    if(do_log(SEC_0199_CXFSCONHASH, 7))
    {
        sys_log(log, "cxfsconhash %p: vnode tree:\n", cxfsconhash);
        crb_tree_print(log, CXFSCONHASH_VNODE_TREE(cxfsconhash));
    }

    return;
}

void cxfsconhash_print_rnode_vec(LOG *log, const CXFSCONHASH *cxfsconhash)
{
    sys_log(log, "cxfsconhash %p: hash_id %ld\n",
                    cxfsconhash,
                    CXFSCONHASH_HASH_ID(cxfsconhash));

    sys_log(log, "cxfsconhash %p: rnode vec:\n", cxfsconhash);
    cvector_print(log, CXFSCONHASH_RNODE_VEC(cxfsconhash), (CVECTOR_DATA_PRINT)cxfsconhash_rnode_print);

    return;
}

void cxfsconhash_print_vnode_tree(LOG *log, const CXFSCONHASH *cxfsconhash)
{
    sys_log(log, "cxfsconhash %p: hash_id %ld\n",
                    cxfsconhash,
                    CXFSCONHASH_HASH_ID(cxfsconhash));

    sys_log(log, "cxfsconhash %p: vnode tree:\n", cxfsconhash);
    crb_tree_print(log, CXFSCONHASH_VNODE_TREE(cxfsconhash));

    return;
}

UINT32 cxfsconhash_add_rnode(CXFSCONHASH *cxfsconhash, const CXFSCONHASH_RNODE *cxfsconhash_rnode)
{
    return cvector_add(CXFSCONHASH_RNODE_VEC(cxfsconhash), (void *)cxfsconhash_rnode);
}

CRB_NODE *cxfsconhash_add_vnode(CXFSCONHASH *cxfsconhash, const CXFSCONHASH_VNODE *cxfsconhash_vnode)
{
    return crb_tree_insert_data(CXFSCONHASH_VNODE_TREE(cxfsconhash), (void *)cxfsconhash_vnode);
}

STATIC_CAST static uint32_t __cxfsconhash_hash_vnode(CXFSCONHASH *cxfsconhash, const uint32_t tcid, const uint16_t replica, const UINT32 salt)
{
    char     str[64];
    uint32_t len;
    uint32_t hash;

    len  = snprintf(str, sizeof(str), "%s.%u.%ld", c_word_to_ipv4(tcid), (uint32_t)(replica * replica), salt);
    hash = (uint32_t)CXFSCONHASH_HASH_FUNC(cxfsconhash)(len, (UINT8 *)str);

    return (hash);
}

EC_BOOL cxfsconhash_add_vnode_replicas(CXFSCONHASH *cxfsconhash, const UINT32 cxfsconhash_rnode_pos)
{
    CXFSCONHASH_RNODE *cxfsconhash_rnode;

    uint32_t tcid;
    uint16_t replica;

    cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos);
    if(NULL_PTR == cxfsconhash_rnode)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: not found rnode at pos %ld\n",
                           cxfsconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (cxfsconhash_rnode_pos >> 16));

    tcid = CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode);
    for(replica = 0; replica < CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode); replica ++)
    {
        uint32_t hash;

        CXFSCONHASH_VNODE *cxfsconhash_vnode;
        CRB_NODE          *crb_node;

        hash = __cxfsconhash_hash_vnode(cxfsconhash, tcid, replica, cxfsconhash_rnode_pos);

        cxfsconhash_vnode = cxfsconhash_vnode_make(hash, (uint16_t)cxfsconhash_rnode_pos);
        if(NULL_PTR == cxfsconhash_vnode)
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cxfsconhash_rnode_pos);
            return (EC_FALSE);
        }

        crb_node = crb_tree_insert_data(CXFSCONHASH_VNODE_TREE(cxfsconhash), (void *)cxfsconhash_vnode);
        if(NULL_PTR == crb_node)
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: insert vnode (hash %x, tcid %s, replica %u, rnode pos %u) to rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cxfsconhash_rnode_pos);
            cxfsconhash_vnode_free(cxfsconhash_vnode);
            return (EC_FALSE);
        }

        /*fix*/
        if(cxfsconhash_vnode != CRB_NODE_DATA(crb_node))
        {
            CXFSCONHASH_VNODE *cxfsconhash_vnode_duplicate;
            CXFSCONHASH_RNODE *cxfsconhash_rnode_duplicate;

            cxfsconhash_vnode_duplicate = (CXFSCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
            cxfsconhash_rnode_duplicate = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), CXFSCONHASH_VNODE_POS(cxfsconhash_vnode_duplicate));

            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: found duplicate vnode:\n");

            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: found duplicate vnode:[1]\n");
            cxfsconhash_vnode_print(LOGSTDOUT, cxfsconhash_vnode);
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: found duplicate rnode:[1]\n");
            cxfsconhash_rnode_print(LOGSTDOUT, cxfsconhash_rnode);

            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: found duplicate vnode:[2]\n");
            cxfsconhash_vnode_print(LOGSTDOUT, cxfsconhash_vnode_duplicate);
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: found duplicate rnode:[2]\n");
            cxfsconhash_rnode_print(LOGSTDOUT, cxfsconhash_rnode_duplicate);

            cxfsconhash_vnode_free(cxfsconhash_vnode);

            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_vnode_replicas: pls make sure hash is unique!\n");
            exit( 5 );
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_del_vnode_replicas(CXFSCONHASH *cxfsconhash, const UINT32 cxfsconhash_rnode_pos)
{
    CXFSCONHASH_RNODE *cxfsconhash_rnode;

    uint32_t tcid;
    uint16_t replica;

    cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos);
    if(NULL_PTR == cxfsconhash_rnode)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_del_vnode_replicas: not found rnode at pos %ld\n",
                           cxfsconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (cxfsconhash_rnode_pos >> 16));

    tcid = CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode);
    for(replica = 0; replica < CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode); replica ++)
    {
        uint32_t hash;

        CXFSCONHASH_VNODE *cxfsconhash_vnode;

        hash = __cxfsconhash_hash_vnode(cxfsconhash, tcid, replica, cxfsconhash_rnode_pos);

        cxfsconhash_vnode = cxfsconhash_vnode_make(hash, (uint16_t)cxfsconhash_rnode_pos);
        if(NULL_PTR == cxfsconhash_vnode)
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_del_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cxfsconhash_rnode_pos);
            return (EC_FALSE);
        }

        if(EC_FALSE == crb_tree_delete_data(CXFSCONHASH_VNODE_TREE(cxfsconhash), (void *)cxfsconhash_vnode))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_del_vnode_replicas: del vnode (hash %x, tcid %s, replica %u, rnode pos %u) from rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cxfsconhash_rnode_pos);
            cxfsconhash_vnode_free(cxfsconhash_vnode);
            return (EC_FALSE);
        }

        cxfsconhash_vnode_free(cxfsconhash_vnode);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_add_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid, const uint16_t replicas)
{
    CXFSCONHASH_RNODE  cxfsconhash_rnode_t;
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    UINT32             cxfsconhash_rnode_pos;

    CXFSCONHASH_RNODE_TCID(&cxfsconhash_rnode_t) = tcid;
    cxfsconhash_rnode_pos = cvector_search_front(CXFSCONHASH_RNODE_VEC(cxfsconhash),
                                                 (void *)&cxfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cxfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS != cxfsconhash_rnode_pos)
    {
        cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos);

        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_node: found rnode (tcid %s, replicas %u, status %s)\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_FALSE);
    }

    cxfsconhash_rnode = cxfsconhash_rnode_make(tcid, replicas);
    if(NULL_PTR == cxfsconhash_rnode)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_node: make rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(tcid), replicas);
        return (EC_FALSE);
    }

    /*add rnode*/
    cxfsconhash_rnode_pos = cxfsconhash_add_rnode(cxfsconhash, cxfsconhash_rnode);
    if(CVECTOR_ERR_POS == cxfsconhash_rnode_pos)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_node: add rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));

        cxfsconhash_rnode_free(cxfsconhash_rnode);
        return (EC_FALSE);
    }

    ASSERT(0 == (cxfsconhash_rnode_pos >> 16));
#if 1
    /*add vnode replicas*/
    if(EC_FALSE == cxfsconhash_add_vnode_replicas(cxfsconhash, cxfsconhash_rnode_pos))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_add_node: add vnode replicas of rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode));

        cxfsconhash_del_vnode_replicas(cxfsconhash, cxfsconhash_rnode_pos);/*roll back*/

        cvector_set(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos, NULL_PTR);
        cxfsconhash_rnode_free(cxfsconhash_rnode);
        return (EC_FALSE);
    }
#endif
    dbg_log(SEC_0199_CXFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] cxfsconhash_add_node: rnode (tcid %s, replicas %u, status %s) add => OK\n",
                       c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                       CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                       cxfsconhash_rnode_status(cxfsconhash_rnode));
    return (EC_TRUE);
}

/*for any replica: replicas = 0*/
EC_BOOL cxfsconhash_del_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid)
{
    CXFSCONHASH_RNODE  cxfsconhash_rnode_t;
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    UINT32             cxfsconhash_rnode_pos;

    CXFSCONHASH_RNODE_TCID(&cxfsconhash_rnode_t) = tcid;
    cxfsconhash_rnode_pos = cvector_search_front(CXFSCONHASH_RNODE_VEC(cxfsconhash),
                                                 (void *)&cxfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cxfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cxfsconhash_rnode_pos)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_del_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos);

    ASSERT(0 == (cxfsconhash_rnode_pos >> 16));

    /*del vnode replicas*/
    if(EC_FALSE == cxfsconhash_del_vnode_replicas(cxfsconhash, cxfsconhash_rnode_pos))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_del_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_FALSE);
    }

    dbg_log(SEC_0199_CXFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] cxfsconhash_del_node: rnode (tcid %s, replicas %u, status %s) del => OK\n",
                       c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                       CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                       cxfsconhash_rnode_status(cxfsconhash_rnode));

    /*del rnode*/
    cvector_set(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos, NULL_PTR);
    cxfsconhash_rnode_free(cxfsconhash_rnode);

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_up_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid)
{
    CXFSCONHASH_RNODE  cxfsconhash_rnode_t;
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    UINT32             cxfsconhash_rnode_pos;

    CXFSCONHASH_RNODE_TCID(&cxfsconhash_rnode_t) = tcid;
    cxfsconhash_rnode_pos = cvector_search_front(CXFSCONHASH_RNODE_VEC(cxfsconhash),
                                                 (void *)&cxfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cxfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cxfsconhash_rnode_pos)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_up_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (cxfsconhash_rnode_pos >> 16));

    cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos);

    if(CXFSCONHASH_RNODE_IS_UP == CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] cxfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) is already up\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_TRUE);
    }
#if 0
    if(CXFSCONHASH_RNODE_IS_DOWN != CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) is not down\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_FALSE);
    }
#endif

    if(CXFSCONHASH_ERR_REPLICAS == CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode)
    || CXFSCONHASH_ANY_REPLICAS == CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) has invalid replica\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_FALSE);
    }

    /*add vnode replicas*/
    if(EC_FALSE == cxfsconhash_add_vnode_replicas(cxfsconhash, cxfsconhash_rnode_pos))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_up_node: add vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));

        cxfsconhash_del_vnode_replicas(cxfsconhash, cxfsconhash_rnode_pos);/*roll back*/
        return (EC_FALSE);
    }

    CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode) = CXFSCONHASH_RNODE_IS_UP; /*set up*/

    dbg_log(SEC_0199_CXFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] cxfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) set up => OK\n",
                       c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                       CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                       cxfsconhash_rnode_status(cxfsconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_down_node(CXFSCONHASH *cxfsconhash, const uint32_t tcid)
{
    CXFSCONHASH_RNODE  cxfsconhash_rnode_t;
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    UINT32             cxfsconhash_rnode_pos;

    CXFSCONHASH_RNODE_TCID(&cxfsconhash_rnode_t) = tcid;
    cxfsconhash_rnode_pos = cvector_search_front(CXFSCONHASH_RNODE_VEC(cxfsconhash),
                                                 (void *)&cxfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cxfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cxfsconhash_rnode_pos)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_down_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (cxfsconhash_rnode_pos >> 16));

    cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos);

    if(CXFSCONHASH_RNODE_IS_DOWN == CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] cxfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) is already down\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_TRUE);
    }
#if 0
    if(CXFSCONHASH_RNODE_IS_UP != CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) is not up\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_FALSE);
    }
#endif
    /*del vnode replicas*/
    if(EC_FALSE == cxfsconhash_del_vnode_replicas(cxfsconhash, cxfsconhash_rnode_pos))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_down_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                           CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                           cxfsconhash_rnode_status(cxfsconhash_rnode));
        return (EC_FALSE);
    }

    CXFSCONHASH_RNODE_STATUS(cxfsconhash_rnode) = CXFSCONHASH_RNODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0199_CXFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] cxfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) set down => OK\n",
                       c_word_to_ipv4(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode)),
                       CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode),
                       cxfsconhash_rnode_status(cxfsconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_has_node(const CXFSCONHASH *cxfsconhash, const uint32_t tcid)
{
    CXFSCONHASH_RNODE  cxfsconhash_rnode_t;
    UINT32             cxfsconhash_rnode_pos;

    CXFSCONHASH_RNODE_TCID(&cxfsconhash_rnode_t) = tcid;
    cxfsconhash_rnode_pos = cvector_search_front(CXFSCONHASH_RNODE_VEC(cxfsconhash),
                                                 (void *)&cxfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cxfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cxfsconhash_rnode_pos)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 9)(LOGSTDOUT, "info:cxfsconhash_has_node: tcid %s is not in rnode\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CXFSCONHASH_RNODE *cxfsconhash_get_rnode(const CXFSCONHASH *cxfsconhash, const uint32_t tcid)
{
    CXFSCONHASH_RNODE  cxfsconhash_rnode_t;
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    UINT32             cxfsconhash_rnode_pos;

    CXFSCONHASH_RNODE_TCID(&cxfsconhash_rnode_t) = tcid;
    cxfsconhash_rnode_pos = cvector_search_front(CXFSCONHASH_RNODE_VEC(cxfsconhash),
                                                 (void *)&cxfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cxfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cxfsconhash_rnode_pos)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_get_rnode: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode_pos);
    return (cxfsconhash_rnode);
}

CXFSCONHASH_RNODE *cxfsconhash_lookup_rnode(const CXFSCONHASH *cxfsconhash, const uint32_t hash)
{
    CXFSCONHASH_VNODE  cxfsconhash_vnode_t;
    CXFSCONHASH_VNODE *cxfsconhash_vnode;
    CXFSCONHASH_RNODE *cxfsconhash_rnode;
    CRB_NODE *crb_node;

    if(EC_TRUE == crb_tree_is_empty(CXFSCONHASH_VNODE_TREE(cxfsconhash)))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_lookup_rnode: vnode tree is empty\n");
        return (NULL_PTR);
    }

    CXFSCONHASH_VNODE_HASH(&cxfsconhash_vnode_t) = hash;
    crb_node = crb_tree_lookup_data(CXFSCONHASH_VNODE_TREE(cxfsconhash), (void *)&cxfsconhash_vnode_t);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_lookup_rnode: hash %x, should never reach here due to rbtree be circled\n",
                           hash);
        return (NULL_PTR);
    }

    cxfsconhash_vnode = (CXFSCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
    if(NULL_PTR == cxfsconhash_vnode)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_lookup_rnode: hash %x, crb_node %p, should never reach here due to CRB_NODE_DATA be null!\n",
                           hash, crb_node);
        return (NULL_PTR);
    }
#if 0
    if(do_log(SEC_0199_CXFSCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfsconhash_lookup_rnode: hash %x => vnode ", hash);
        cxfsconhash_vnode_print(LOGSTDOUT, cxfsconhash_vnode);
    }
#endif
    cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash),
                                                         CXFSCONHASH_VNODE_POS(cxfsconhash_vnode));
    if(NULL_PTR == cxfsconhash_rnode)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_lookup_rnode: hash %x, rnode_pos %u, should never reach here due to rnode not existing\n",
                           hash, CXFSCONHASH_VNODE_POS(cxfsconhash_vnode));
        return (NULL_PTR);
    }
    return (cxfsconhash_rnode);
}

EC_BOOL cxfsconhash_flush_size(const CXFSCONHASH *cxfsconhash, UINT32 *size)
{
    (*size) = sizeof(UINT32) /*hash_id*/
            + sizeof(UINT32) /*rnode_vec size*/
            + cvector_size(CXFSCONHASH_RNODE_VEC(cxfsconhash)) * (
                                                                    sizeof(uint16_t) /*replicas*/
                                                                  + sizeof(uint32_t) /*tcid*/
                                                                  )
            + sizeof(uint32_t) /*vnode_tree size*/
            + crb_tree_node_num(CXFSCONHASH_VNODE_TREE(cxfsconhash)) * (
                                                                     sizeof(uint32_t) /*hash*/
                                                                   + sizeof(uint32_t) /*pos*/
                                                                   );
    return (EC_FALSE);
}

EC_BOOL cxfsconhash_rnode_flush(const CXFSCONHASH_RNODE *cxfsconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    if(NULL_PTR == cxfsconhash_rnode)
    {
        uint32_t     tcid;
        uint16_t     replicas;

        replicas = CXFSCONHASH_ERR_REPLICAS;
        tcid     = (uint32_t)CMPI_ERROR_TCID;

        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(replicas)))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_rnode_flush: flush replicas at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(tcid)))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_rnode_flush: flush tcid at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
    }
    else
    {
        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode))))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_rnode_flush: flush replicas at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode))))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_rnode_flush: flush tcid at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfsconhash_rnode_load(CXFSCONHASH_RNODE *cxfsconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_rnode_load: load replicas at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_rnode_load: load tcid at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_flush_rnodes(const CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    UINT32   rnode_num;
    UINT32   rnode_pos;

    rnode_num = cvector_size(CXFSCONHASH_RNODE_VEC(cxfsconhash));

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_flush_rnodes: flush rnode_num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CXFSCONHASH_RNODE *cxfsconhash_rnode;
        cxfsconhash_rnode = (CXFSCONHASH_RNODE *)cvector_get(CXFSCONHASH_RNODE_VEC(cxfsconhash), rnode_pos);
        if(EC_FALSE == cxfsconhash_rnode_flush(cxfsconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_flush_rnodes: flush rnode %ld# at offset %ld of fd %d failed\n", rnode_pos, (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_load_rnodes(CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    UINT32   rnode_num;
    UINT32   rnode_pos;

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load_rnodes: load rnode_num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CXFSCONHASH_RNODE *cxfsconhash_rnode;

        cxfsconhash_rnode = cxfsconhash_rnode_new();
        if(NULL_PTR == cxfsconhash_rnode)
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load_rnodes: new rnode at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsconhash_rnode_load(cxfsconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load_rnodes: load rnode %ld# at offset %ld of fd %d failed\n", rnode_pos, (*offset), fd);
            cxfsconhash_rnode_free(cxfsconhash_rnode);
            return (EC_FALSE);
        }

        if(CXFSCONHASH_ERR_REPLICAS == CXFSCONHASH_RNODE_REPLICAS(cxfsconhash_rnode)
        && ((uint32_t)CMPI_ERROR_TCID) == CXFSCONHASH_RNODE_TCID(cxfsconhash_rnode))
        {
            cvector_push(CXFSCONHASH_RNODE_VEC(cxfsconhash), NULL_PTR);
            cxfsconhash_rnode_free(cxfsconhash_rnode);
        }
        else
        {
            cvector_push(CXFSCONHASH_RNODE_VEC(cxfsconhash), cxfsconhash_rnode);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_vnode_flush(const CXFSCONHASH_VNODE *cxfsconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_vnode_flush: flush hash at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_VNODE_POS(cxfsconhash_vnode))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_vnode_flush: flush pos at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_vnode_load(CXFSCONHASH_VNODE *cxfsconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_VNODE_HASH(cxfsconhash_vnode))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_vnode_load: load hash at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_VNODE_POS(cxfsconhash_vnode))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_vnode_load: load pos at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsconhash_flush_vnodes_inorder(const CXFSCONHASH *cxfsconhash, const CRB_NODE *node, int fd, UINT32 *offset)
{
    CXFSCONHASH_VNODE *cxfsconhash_vnode;
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_FALSE == __cxfsconhash_flush_vnodes_inorder(cxfsconhash, CRB_NODE_LEFT(node), fd, offset))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:__cxfsconhash_flush_vnodes_inorder: flush left subtree %p at offset %ld of fd %d failed\n", CRB_NODE_LEFT(node), (*offset), fd);
            return (EC_FALSE);
        }
    }

    cxfsconhash_vnode = (CXFSCONHASH_VNODE *)CRB_NODE_DATA(node);
    if(NULL_PTR == cxfsconhash_vnode)
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:__cxfsconhash_flush_vnodes_inorder: data of crb node %p is null at offset %ld of fd %d failed\n", node, (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsconhash_vnode_flush(cxfsconhash_vnode, fd, offset))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:__cxfsconhash_flush_vnodes_inorder: flush vnode %p at offset %ld of fd %d failed\n", cxfsconhash_vnode, (*offset), fd);
        return (EC_FALSE);
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_FALSE == __cxfsconhash_flush_vnodes_inorder(cxfsconhash, CRB_NODE_RIGHT(node), fd, offset))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:__cxfsconhash_flush_vnodes_inorder: flush right subtree %p at offset %ld of fd %d failed\n", CRB_NODE_RIGHT(node), (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_flush_vnodes(const CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    uint32_t   vnode_num;

    vnode_num = crb_tree_node_num(CXFSCONHASH_VNODE_TREE(cxfsconhash));

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_flush_vnodes: flush vnode num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cxfsconhash_flush_vnodes_inorder(cxfsconhash, CRB_TREE_ROOT(CXFSCONHASH_VNODE_TREE(cxfsconhash)), fd, offset))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_flush_vnodes: flush vnode tree at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_load_vnodes(CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    uint32_t   vnode_num;
    uint32_t   vnode_pos;

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load_vnodes: load vnode num at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(vnode_pos = 0; vnode_pos < vnode_num; vnode_pos ++)
    {
        CXFSCONHASH_VNODE *cxfsconhash_vnode;

        cxfsconhash_vnode = cxfsconhash_vnode_new();
        if(NULL_PTR == cxfsconhash_vnode)
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load_vnodes: new vnode at offset %ld of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsconhash_vnode_load(cxfsconhash_vnode, fd, offset))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load_vnodes: load vnode %u# at offset %ld of fd %d failed\n", vnode_pos, (*offset), fd);
            cxfsconhash_vnode_free(cxfsconhash_vnode);
            return (EC_FALSE);
        }

        if(NULL_PTR == cxfsconhash_add_vnode(cxfsconhash, cxfsconhash_vnode))
        {
            dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load_vnodes: add vnode %u# at offset %ld of fd %d failed\n", vnode_pos, (*offset), fd);
            cxfsconhash_vnode_free(cxfsconhash_vnode);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_flush(const CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*flush hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_HASH_ID(cxfsconhash))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_flush: flush hash id at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush rnode vec*/
    if(EC_FALSE == cxfsconhash_flush_rnodes(cxfsconhash, fd, offset))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_flush: flush rnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush vnode tree*/
    if(EC_FALSE == cxfsconhash_flush_vnodes(cxfsconhash, fd, offset))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_flush: flush vnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_load(CXFSCONHASH *cxfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*load hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CXFSCONHASH_HASH_ID(cxfsconhash))))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load: load hash id at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    CXFSCONHASH_HASH_FUNC(cxfsconhash) = chash_algo_fetch(CXFSCONHASH_HASH_ID(cxfsconhash));
    if(NULL_PTR == CXFSCONHASH_HASH_FUNC(cxfsconhash))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load: invalid hash id %ld\n", CXFSCONHASH_HASH_ID(cxfsconhash));
        return (EC_FALSE);
    }

    /*load rnode vec*/
    if(EC_FALSE == cxfsconhash_load_rnodes(cxfsconhash, fd, offset))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load: load rnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*load vnode tree*/
    if(EC_FALSE == cxfsconhash_load_vnodes(cxfsconhash, fd, offset))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "error:cxfsconhash_load: load vnodes at offset %ld of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_rnodes_is_equal(const CXFSCONHASH *cxfsconhash_1st, const CXFSCONHASH *cxfsconhash_2nd)
{
    return cvector_cmp(CXFSCONHASH_RNODE_VEC(cxfsconhash_1st),
                       CXFSCONHASH_RNODE_VEC(cxfsconhash_2nd),
                       (CVECTOR_DATA_CMP)cxfsconhash_rnode_is_equal);
}

EC_BOOL cxfsconhash_vnodes_is_equal(const CXFSCONHASH *cxfsconhash_1st, const CXFSCONHASH *cxfsconhash_2nd)
{
    return crb_tree_cmp(CXFSCONHASH_VNODE_TREE(cxfsconhash_1st),
                        CXFSCONHASH_VNODE_TREE(cxfsconhash_2nd),
                        (CRB_DATA_IS_EQUAL)cxfsconhash_vnode_is_equal);
}

EC_BOOL cxfsconhash_is_equal(const CXFSCONHASH *cxfsconhash_1st, const CXFSCONHASH *cxfsconhash_2nd)
{
    if(CXFSCONHASH_HASH_ID(cxfsconhash_1st) != CXFSCONHASH_HASH_ID(cxfsconhash_2nd))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "cxfsconhash_is_equal: hash id: %ld != %ld\n",
                           CXFSCONHASH_HASH_ID(cxfsconhash_1st),
                           CXFSCONHASH_HASH_ID(cxfsconhash_2nd));
        return (EC_FALSE);
    }

    if(CXFSCONHASH_HASH_FUNC(cxfsconhash_1st) != CXFSCONHASH_HASH_FUNC(cxfsconhash_2nd))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "cxfsconhash_is_equal: hash func: %p != %p\n",
                           CXFSCONHASH_HASH_FUNC(cxfsconhash_1st),
                           CXFSCONHASH_HASH_FUNC(cxfsconhash_2nd));
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsconhash_rnodes_is_equal(cxfsconhash_1st, cxfsconhash_2nd))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "cxfsconhash_is_equal: rnodes is not equal\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsconhash_vnodes_is_equal(cxfsconhash_1st, cxfsconhash_2nd))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "cxfsconhash_is_equal: vnodes is not equal\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsconhash_clone(const CXFSCONHASH *cxfsconhash_src, CXFSCONHASH *cxfsconhash_des)
{
    cvector_clone(CXFSCONHASH_RNODE_VEC(cxfsconhash_src),
                  CXFSCONHASH_RNODE_VEC(cxfsconhash_des),
                  (CVECTOR_DATA_MALLOC)cxfsconhash_rnode_new,
                  (CVECTOR_DATA_CLONE)cxfsconhash_rnode_clone);

    if(EC_FALSE == crb_tree_clone(CXFSCONHASH_VNODE_TREE(cxfsconhash_src),
                                   CXFSCONHASH_VNODE_TREE(cxfsconhash_des),
                                   (CRB_DATA_NEW)cxfsconhash_vnode_new,
                                   (CRB_DATA_CLONE)cxfsconhash_vnode_clone))
    {
        dbg_log(SEC_0199_CXFSCONHASH, 0)(LOGSTDOUT, "cxfsconhash_clone: clone vnodes failed\n");
        return (EC_FALSE);
    }

    CXFSCONHASH_HASH_ID(cxfsconhash_des)   = CXFSCONHASH_HASH_ID(cxfsconhash_src);
    CXFSCONHASH_HASH_FUNC(cxfsconhash_des) = CXFSCONHASH_HASH_FUNC(cxfsconhash_src);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

