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
#include "csfsconhash.h"

CSFSCONHASH_RNODE *csfsconhash_rnode_new()
{
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    alloc_static_mem(MM_CSFSCONHASH_RNODE, &csfsconhash_rnode, LOC_CSFSCONHASH_0001);
    if(NULL_PTR != csfsconhash_rnode)
    {
        csfsconhash_rnode_init(csfsconhash_rnode);
    }
    return (csfsconhash_rnode);
}

CSFSCONHASH_RNODE *csfsconhash_rnode_make(const uint32_t tcid, const uint16_t replicas)
{
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    alloc_static_mem(MM_CSFSCONHASH_RNODE, &csfsconhash_rnode, LOC_CSFSCONHASH_0002);
    if(NULL_PTR != csfsconhash_rnode)
    {
        CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode) = replicas;
        CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode)   = CSFSCONHASH_RNODE_IS_UP;
        CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)     = tcid;
     
        CSFSCONHASH_RNODE_COUNTER_CLR(csfsconhash_rnode);
    }
    return (csfsconhash_rnode);
}

EC_BOOL csfsconhash_rnode_init(CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode) = 0;
    CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode)   = CSFSCONHASH_RNODE_IS_ERR;
    CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;
 
    CSFSCONHASH_RNODE_COUNTER_CLR(csfsconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL csfsconhash_rnode_clean(CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode) = 0;
    CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode)   = CSFSCONHASH_RNODE_IS_ERR;
    CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;

    CSFSCONHASH_RNODE_COUNTER_CLR(csfsconhash_rnode);
    return (EC_TRUE);
}

EC_BOOL csfsconhash_rnode_free(CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    if(NULL_PTR != csfsconhash_rnode)
    {
        csfsconhash_rnode_clean(csfsconhash_rnode);
        free_static_mem(MM_CSFSCONHASH_RNODE, csfsconhash_rnode, LOC_CSFSCONHASH_0003);
    }
    return (EC_TRUE);
}

EC_BOOL csfsconhash_rnode_init_0(const UINT32 md_id, CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    return csfsconhash_rnode_init(csfsconhash_rnode);
}

EC_BOOL csfsconhash_rnode_clean_0(const UINT32 md_id, CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    return csfsconhash_rnode_clean(csfsconhash_rnode);
}

EC_BOOL csfsconhash_rnode_free_0(const UINT32 md_id, CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    return csfsconhash_rnode_free(csfsconhash_rnode);
}

EC_BOOL csfsconhash_rnode_clone(const CSFSCONHASH_RNODE *csfsconhash_rnode_src, CSFSCONHASH_RNODE *csfsconhash_rnode_des)
{
    CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode_des) = CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode_src);
    CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode_des)   = CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode_src);
    CSFSCONHASH_RNODE_TCID(csfsconhash_rnode_des)     = CSFSCONHASH_RNODE_TCID(csfsconhash_rnode_src);

    CSFSCONHASH_RNODE_COUNTER_CLONE(csfsconhash_rnode_src, csfsconhash_rnode_des);
    return (EC_TRUE);
}

const char *csfsconhash_rnode_status(const CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    if(CSFSCONHASH_RNODE_IS_UP == CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {
        return (const char *)"UP";
    }
    if(CSFSCONHASH_RNODE_IS_DOWN == CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {
        return (const char *)"DOWN";
    }

    if(CSFSCONHASH_RNODE_IS_ERR == CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

EC_BOOL csfsconhash_rnode_is_up(const CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    if(CSFSCONHASH_RNODE_IS_UP == CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL csfsconhash_rnode_is_equal(const CSFSCONHASH_RNODE *csfsconhash_rnode_1st, const CSFSCONHASH_RNODE *csfsconhash_rnode_2nd)
{
    if(NULL_PTR == csfsconhash_rnode_1st && NULL_PTR == csfsconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == csfsconhash_rnode_1st || NULL_PTR == csfsconhash_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode_1st) != CSFSCONHASH_RNODE_TCID(csfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#if 1
    if(CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode_1st) != CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
#endif 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_rnode_cmp_tcid(const CSFSCONHASH_RNODE *csfsconhash_rnode_1st, const CSFSCONHASH_RNODE *csfsconhash_rnode_2nd)
{
    if(NULL_PTR == csfsconhash_rnode_1st && NULL_PTR == csfsconhash_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == csfsconhash_rnode_1st || NULL_PTR == csfsconhash_rnode_2nd)
    {
        return (EC_FALSE);
    } 
 
    if(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode_1st) != CSFSCONHASH_RNODE_TCID(csfsconhash_rnode_2nd))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

void csfsconhash_rnode_print(LOG *log, const CSFSCONHASH_RNODE *csfsconhash_rnode)
{
#if(SWITCH_OFF == CSFSCONHASH_RNODE_DEBUG)
    sys_log(log, "csfsconhash_rnode %p: tcid %s, replicas %u, status %s\n",
                    csfsconhash_rnode,
                    c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                    CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                    csfsconhash_rnode_status(csfsconhash_rnode)
                   );
#endif/*(SWITCH_OFF == CSFSCONHASH_RNODE_DEBUG)*/                
#if(SWITCH_ON == CSFSCONHASH_RNODE_DEBUG)
    sys_log(log, "csfsconhash_rnode %p: tcid %s, replicas %u, status %s, counter %ld\n",
                    csfsconhash_rnode,
                    c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                    CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                    csfsconhash_rnode_status(csfsconhash_rnode),
                    CSFSCONHASH_RNODE_COUNTER(csfsconhash_rnode)
                   );
#endif/*(SWITCH_ON == CSFSCONHASH_RNODE_DEBUG)*/
    return;
}

CSFSCONHASH_VNODE *csfsconhash_vnode_new()
{
    CSFSCONHASH_VNODE *csfsconhash_vnode;
    alloc_static_mem(MM_CSFSCONHASH_VNODE, &csfsconhash_vnode, LOC_CSFSCONHASH_0004);
    if(NULL_PTR != csfsconhash_vnode)
    {
        csfsconhash_vnode_init(csfsconhash_vnode);
    }
    return (csfsconhash_vnode);
}

CSFSCONHASH_VNODE *csfsconhash_vnode_make(const uint32_t hash, const uint16_t rnode_pos)
{
    CSFSCONHASH_VNODE *csfsconhash_vnode;
    alloc_static_mem(MM_CSFSCONHASH_VNODE, &csfsconhash_vnode, LOC_CSFSCONHASH_0005);
    if(NULL_PTR != csfsconhash_vnode)
    {
        CSFSCONHASH_VNODE_HASH(csfsconhash_vnode) = hash;
        CSFSCONHASH_VNODE_POS(csfsconhash_vnode)  = rnode_pos;
    }
    return (csfsconhash_vnode);
}

EC_BOOL csfsconhash_vnode_init(CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    CSFSCONHASH_VNODE_HASH(csfsconhash_vnode) = 0;
    CSFSCONHASH_VNODE_POS(csfsconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL csfsconhash_vnode_clean(CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    CSFSCONHASH_VNODE_HASH(csfsconhash_vnode) = 0;
    CSFSCONHASH_VNODE_POS(csfsconhash_vnode)  = (uint32_t)CVECTOR_ERR_POS;
    return (EC_TRUE);
}

EC_BOOL csfsconhash_vnode_free(CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    if(NULL_PTR != csfsconhash_vnode)
    {
        csfsconhash_vnode_clean(csfsconhash_vnode);
        free_static_mem(MM_CSFSCONHASH_VNODE, csfsconhash_vnode, LOC_CSFSCONHASH_0006);
    }
    return (EC_TRUE);
}

EC_BOOL csfsconhash_vnode_init_0(const UINT32 md_id, CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    return csfsconhash_vnode_init(csfsconhash_vnode);
}

EC_BOOL csfsconhash_vnode_clean_0(const UINT32 md_id, CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    return csfsconhash_vnode_clean(csfsconhash_vnode);
}

EC_BOOL csfsconhash_vnode_free_0(const UINT32 md_id, CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    return csfsconhash_vnode_free(csfsconhash_vnode);
}

EC_BOOL csfsconhash_vnode_clone(const CSFSCONHASH_VNODE *csfsconhash_vnode_src, CSFSCONHASH_VNODE *csfsconhash_vnode_des)
{
    CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_des) = CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_src);
    CSFSCONHASH_VNODE_POS(csfsconhash_vnode_des)  = CSFSCONHASH_VNODE_POS(csfsconhash_vnode_src);
    return (EC_TRUE);
}

EC_BOOL csfsconhash_vnode_is_equal(const CSFSCONHASH_VNODE *csfsconhash_vnode_1st, const CSFSCONHASH_VNODE *csfsconhash_vnode_2nd)
{
    if(NULL_PTR == csfsconhash_vnode_1st && NULL_PTR == csfsconhash_vnode_2nd)
    {
        return (EC_TRUE);
    }

    if(NULL_PTR == csfsconhash_vnode_1st || NULL_PTR == csfsconhash_vnode_2nd)
    {
        return (EC_FALSE);
    }

    if(do_log(SEC_0170_CSFSCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfsconhash_vnode_is_equal: check them:\n");
        csfsconhash_vnode_print(LOGSTDOUT, csfsconhash_vnode_1st);
        csfsconhash_vnode_print(LOGSTDOUT, csfsconhash_vnode_2nd);
    }

    if(CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_1st) != CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_2nd))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 6)(LOGSTDOUT, "[DEBUG] csfsconhash_vnode_is_equal: hash: %x != %x\n",
                           CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_1st),
                           CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_2nd));
        return (EC_FALSE);
    }
#if 1
    if(CSFSCONHASH_VNODE_POS(csfsconhash_vnode_1st) != CSFSCONHASH_VNODE_POS(csfsconhash_vnode_2nd))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 6)(LOGSTDOUT, "[DEBUG] csfsconhash_vnode_is_equal: pos: %u != %u\n",
                           CSFSCONHASH_VNODE_POS(csfsconhash_vnode_1st),
                           CSFSCONHASH_VNODE_POS(csfsconhash_vnode_2nd)); 
        return (EC_FALSE);
    }
#endif 
    return (EC_TRUE);
}

int csfsconhash_vnode_cmp(const CSFSCONHASH_VNODE *csfsconhash_vnode_1st, const CSFSCONHASH_VNODE *csfsconhash_vnode_2nd)
{
    if(CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_1st) > CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_2nd))
    {
        return (1);
    }

    if(CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_1st) < CSFSCONHASH_VNODE_HASH(csfsconhash_vnode_2nd))
    {
        return (-1);
    } 
    return (0);
}

void csfsconhash_vnode_print(LOG *log, const CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    sys_log(log, "csfsconhash_vnode %p: hash %x, rnode pos %u\n",
                    csfsconhash_vnode,
                    CSFSCONHASH_VNODE_HASH(csfsconhash_vnode),
                    CSFSCONHASH_VNODE_POS(csfsconhash_vnode)
                   );
    return;
}

CSFSCONHASH *csfsconhash_new(const UINT32 hash_id)
{
    CSFSCONHASH *csfsconhash;
 
    alloc_static_mem(MM_CSFSCONHASH, &csfsconhash, LOC_CSFSCONHASH_0007);
    if(NULL_PTR == csfsconhash)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_new: alloc csfsconhash failed\n");
        return (NULL_PTR);
    }
 
    if(EC_FALSE == csfsconhash_init(csfsconhash, hash_id))
    {
        free_static_mem(MM_CSFSCONHASH, csfsconhash, LOC_CSFSCONHASH_0008);
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_new: init csfsconhash failed\n");
        return (NULL_PTR);
    }
 
    return (csfsconhash);
}

EC_BOOL csfsconhash_init(CSFSCONHASH *csfsconhash, const UINT32 hash_id)
{
    CSFSCONHASH_HASH_FUNC(csfsconhash) = chash_algo_fetch(hash_id);
    if(NULL_PTR == CSFSCONHASH_HASH_FUNC(csfsconhash))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_init: invalid hash_id %ld\n", hash_id);
        return (EC_FALSE);
    }
    CSFSCONHASH_HASH_ID(csfsconhash)   = hash_id;

    cvector_init(CSFSCONHASH_RNODE_VEC(csfsconhash), 0, MM_CSFSCONHASH_RNODE, CVECTOR_LOCK_ENABLE, LOC_CSFSCONHASH_0009);
    crb_tree_init(CSFSCONHASH_VNODE_TREE(csfsconhash), (CRB_DATA_CMP)csfsconhash_vnode_cmp, (CRB_DATA_FREE)csfsconhash_vnode_free,(CRB_DATA_PRINT)csfsconhash_vnode_print);
 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_clean(CSFSCONHASH *csfsconhash)
{
    cvector_clean(CSFSCONHASH_RNODE_VEC(csfsconhash), (CVECTOR_DATA_CLEANER)csfsconhash_rnode_free, LOC_CSFSCONHASH_0010);
    crb_tree_clean(CSFSCONHASH_VNODE_TREE(csfsconhash));

    CSFSCONHASH_HASH_ID(csfsconhash)   = CHASH_ERR_ALGO_ID;
    CSFSCONHASH_HASH_FUNC(csfsconhash) = NULL_PTR;
    return (EC_TRUE);
}

EC_BOOL csfsconhash_free(CSFSCONHASH *csfsconhash)
{
    if(NULL_PTR != csfsconhash)
    {
        csfsconhash_clean(csfsconhash);
        free_static_mem(MM_CSFSCONHASH, csfsconhash, LOC_CSFSCONHASH_0011);
    }
    return (EC_TRUE);
}

void csfsconhash_print(LOG *log, const CSFSCONHASH *csfsconhash)
{
    sys_log(log, "csfsconhash %p: hash_id %ld, rnode num %ld, vnode num %u\n",
                    csfsconhash,
                    CSFSCONHASH_HASH_ID(csfsconhash),
                    cvector_size(CSFSCONHASH_RNODE_VEC(csfsconhash)),
                    crb_tree_node_num(CSFSCONHASH_VNODE_TREE(csfsconhash))
                    );

    if(do_log(SEC_0170_CSFSCONHASH, 6))
    {
        sys_log(log, "csfsconhash %p: rnode vec:\n", csfsconhash);
        cvector_print(log, CSFSCONHASH_RNODE_VEC(csfsconhash), (CVECTOR_DATA_PRINT)csfsconhash_rnode_print);
    }

    if(do_log(SEC_0170_CSFSCONHASH, 7))
    {
        sys_log(log, "csfsconhash %p: vnode tree:\n", csfsconhash);
        crb_tree_print(log, CSFSCONHASH_VNODE_TREE(csfsconhash));
    } 
 
    return;
}

void csfsconhash_print_rnode_vec(LOG *log, const CSFSCONHASH *csfsconhash)
{
    sys_log(log, "csfsconhash %p: hash_id %ld\n",
                    csfsconhash,
                    CSFSCONHASH_HASH_ID(csfsconhash));

    sys_log(log, "csfsconhash %p: rnode vec:\n", csfsconhash);
    cvector_print(log, CSFSCONHASH_RNODE_VEC(csfsconhash), (CVECTOR_DATA_PRINT)csfsconhash_rnode_print);
 
    return;
}

void csfsconhash_print_vnode_tree(LOG *log, const CSFSCONHASH *csfsconhash)
{
    sys_log(log, "csfsconhash %p: hash_id %ld\n",
                    csfsconhash,
                    CSFSCONHASH_HASH_ID(csfsconhash));
                 
    sys_log(log, "csfsconhash %p: vnode tree:\n", csfsconhash);
    crb_tree_print(log, CSFSCONHASH_VNODE_TREE(csfsconhash));
 
    return;
}

UINT32 csfsconhash_add_rnode(CSFSCONHASH *csfsconhash, const CSFSCONHASH_RNODE *csfsconhash_rnode)
{
    return cvector_add(CSFSCONHASH_RNODE_VEC(csfsconhash), (void *)csfsconhash_rnode);
}

CRB_NODE *csfsconhash_add_vnode(CSFSCONHASH *csfsconhash, const CSFSCONHASH_VNODE *csfsconhash_vnode)
{
    return crb_tree_insert_data(CSFSCONHASH_VNODE_TREE(csfsconhash), (void *)csfsconhash_vnode);
}

static uint32_t __csfsconhash_hash_vnode(CSFSCONHASH *csfsconhash, const uint32_t tcid, const uint16_t replica, const UINT32 salt)
{
    char     str[64];
    uint32_t len;
    uint32_t hash;
 
    len  = snprintf(str, sizeof(str), "%s.%u.%ld", c_word_to_ipv4(tcid), (uint32_t)(replica * replica), salt);
    hash = (uint32_t)CSFSCONHASH_HASH_FUNC(csfsconhash)(len, (UINT8 *)str);

    return (hash);
}

EC_BOOL csfsconhash_add_vnode_replicas(CSFSCONHASH *csfsconhash, const UINT32 csfsconhash_rnode_pos)
{
    CSFSCONHASH_RNODE *csfsconhash_rnode;
 
    uint32_t tcid;
    uint16_t replica;

    csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos);
    if(NULL_PTR == csfsconhash_rnode)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: not found rnode at pos %ld\n",
                           csfsconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (csfsconhash_rnode_pos >> 16));

    tcid = CSFSCONHASH_RNODE_TCID(csfsconhash_rnode);
    for(replica = 0; replica < CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode); replica ++)
    {
        uint32_t hash;
     
        CSFSCONHASH_VNODE *csfsconhash_vnode;
        CRB_NODE          *crb_node;

        hash = __csfsconhash_hash_vnode(csfsconhash, tcid, replica, csfsconhash_rnode_pos);

        csfsconhash_vnode = csfsconhash_vnode_make(hash, (uint16_t)csfsconhash_rnode_pos);
        if(NULL_PTR == csfsconhash_vnode)
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)csfsconhash_rnode_pos);
            return (EC_FALSE);
        }

        crb_node = crb_tree_insert_data(CSFSCONHASH_VNODE_TREE(csfsconhash), (void *)csfsconhash_vnode);
        if(NULL_PTR == crb_node)
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: insert vnode (hash %x, tcid %s, replica %u, rnode pos %u) to rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)csfsconhash_rnode_pos);
            csfsconhash_vnode_free(csfsconhash_vnode);
            return (EC_FALSE);
        }

        /*fix*/
        if(csfsconhash_vnode != CRB_NODE_DATA(crb_node))
        {
            CSFSCONHASH_VNODE *csfsconhash_vnode_duplicate;
            CSFSCONHASH_RNODE *csfsconhash_rnode_duplicate;
         
            csfsconhash_vnode_duplicate = (CSFSCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
            csfsconhash_rnode_duplicate = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), CSFSCONHASH_VNODE_POS(csfsconhash_vnode_duplicate));
         
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: found duplicate vnode:\n");
         
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: found duplicate vnode:[1]\n");
            csfsconhash_vnode_print(LOGSTDOUT, csfsconhash_vnode);
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: found duplicate rnode:[1]\n");
            csfsconhash_rnode_print(LOGSTDOUT, csfsconhash_rnode);
         
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: found duplicate vnode:[2]\n");
            csfsconhash_vnode_print(LOGSTDOUT, csfsconhash_vnode_duplicate);
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: found duplicate rnode:[2]\n");
            csfsconhash_rnode_print(LOGSTDOUT, csfsconhash_rnode_duplicate);
         
            csfsconhash_vnode_free(csfsconhash_vnode);

            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_vnode_replicas: pls make sure hash is unique!\n");
            exit( 5 );
        }
    }

    return (EC_TRUE);
}

EC_BOOL csfsconhash_del_vnode_replicas(CSFSCONHASH *csfsconhash, const UINT32 csfsconhash_rnode_pos)
{
    CSFSCONHASH_RNODE *csfsconhash_rnode;
 
    uint32_t tcid;
    uint16_t replica;

    csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos);
    if(NULL_PTR == csfsconhash_rnode)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_del_vnode_replicas: not found rnode at pos %ld\n",
                           csfsconhash_rnode_pos);
        return (EC_FALSE);
    }

    ASSERT(0 == (csfsconhash_rnode_pos >> 16));

    tcid = CSFSCONHASH_RNODE_TCID(csfsconhash_rnode);
    for(replica = 0; replica < CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode); replica ++)
    {
        uint32_t hash;
     
        CSFSCONHASH_VNODE *csfsconhash_vnode;
     
        hash = __csfsconhash_hash_vnode(csfsconhash, tcid, replica, csfsconhash_rnode_pos);

        csfsconhash_vnode = csfsconhash_vnode_make(hash, (uint16_t)csfsconhash_rnode_pos);
        if(NULL_PTR == csfsconhash_vnode)
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_del_vnode_replicas: make vnode (hash %x, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)csfsconhash_rnode_pos);
            return (EC_FALSE);
        }

        if(EC_FALSE == crb_tree_delete_data(CSFSCONHASH_VNODE_TREE(csfsconhash), (void *)csfsconhash_vnode))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_del_vnode_replicas: del vnode (hash %x, tcid %s, replica %u, rnode pos %u) from rbtree failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)csfsconhash_rnode_pos);
            csfsconhash_vnode_free(csfsconhash_vnode);
            return (EC_FALSE);
        }
     
        csfsconhash_vnode_free(csfsconhash_vnode);
    }

    return (EC_TRUE);
}

EC_BOOL csfsconhash_add_node(CSFSCONHASH *csfsconhash, const uint32_t tcid, const uint16_t replicas)
{
    CSFSCONHASH_RNODE  csfsconhash_rnode_t;
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    UINT32             csfsconhash_rnode_pos;

    CSFSCONHASH_RNODE_TCID(&csfsconhash_rnode_t) = tcid;
    csfsconhash_rnode_pos = cvector_search_front(CSFSCONHASH_RNODE_VEC(csfsconhash),
                                                 (void *)&csfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)csfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS != csfsconhash_rnode_pos)
    {
        csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos);

        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_node: found rnode (tcid %s, replicas %u, status %s)\n",
                           c_word_to_ipv4(tcid),
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
        return (EC_FALSE);
    }
 
    csfsconhash_rnode = csfsconhash_rnode_make(tcid, replicas);
    if(NULL_PTR == csfsconhash_rnode)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_node: make rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(tcid), replicas);
        return (EC_FALSE);
    }

    /*add rnode*/
    csfsconhash_rnode_pos = csfsconhash_add_rnode(csfsconhash, csfsconhash_rnode);
    if(CVECTOR_ERR_POS == csfsconhash_rnode_pos)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_node: add rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
                        
        csfsconhash_rnode_free(csfsconhash_rnode);
        return (EC_FALSE);
    }

    ASSERT(0 == (csfsconhash_rnode_pos >> 16));
#if 1
    /*add vnode replicas*/
    if(EC_FALSE == csfsconhash_add_vnode_replicas(csfsconhash, csfsconhash_rnode_pos))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_add_node: add vnode replicas of rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode));

        csfsconhash_del_vnode_replicas(csfsconhash, csfsconhash_rnode_pos);/*roll back*/
     
        cvector_set(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos, NULL_PTR);
        csfsconhash_rnode_free(csfsconhash_rnode);
        return (EC_FALSE);
    }
#endif
    dbg_log(SEC_0170_CSFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] csfsconhash_add_node: rnode (tcid %s, replicas %u, status %s) add => OK\n",
                       c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                       CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                       csfsconhash_rnode_status(csfsconhash_rnode)); 
    return (EC_TRUE);
}

/*for any replica: replicas = 0*/
EC_BOOL csfsconhash_del_node(CSFSCONHASH *csfsconhash, const uint32_t tcid)
{
    CSFSCONHASH_RNODE  csfsconhash_rnode_t;
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    UINT32             csfsconhash_rnode_pos;

    CSFSCONHASH_RNODE_TCID(&csfsconhash_rnode_t) = tcid;
    csfsconhash_rnode_pos = cvector_search_front(CSFSCONHASH_RNODE_VEC(csfsconhash),
                                                 (void *)&csfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)csfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == csfsconhash_rnode_pos)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_del_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos);
 
    ASSERT(0 == (csfsconhash_rnode_pos >> 16));

    /*del vnode replicas*/
    if(EC_FALSE == csfsconhash_del_vnode_replicas(csfsconhash, csfsconhash_rnode_pos))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_del_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));     
        return (EC_FALSE);
    }

    dbg_log(SEC_0170_CSFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] csfsconhash_del_node: rnode (tcid %s, replicas %u, status %s) del => OK\n",
                       c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                       CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                       csfsconhash_rnode_status(csfsconhash_rnode));
                    
    /*del rnode*/
    cvector_set(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos, NULL_PTR);
    csfsconhash_rnode_free(csfsconhash_rnode);
 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_up_node(CSFSCONHASH *csfsconhash, const uint32_t tcid)
{
    CSFSCONHASH_RNODE  csfsconhash_rnode_t;
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    UINT32             csfsconhash_rnode_pos;

    CSFSCONHASH_RNODE_TCID(&csfsconhash_rnode_t) = tcid;
    csfsconhash_rnode_pos = cvector_search_front(CSFSCONHASH_RNODE_VEC(csfsconhash),
                                                 (void *)&csfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)csfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == csfsconhash_rnode_pos)
    {    
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_up_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (csfsconhash_rnode_pos >> 16));

    csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos);

    if(CSFSCONHASH_RNODE_IS_UP == CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {    
        dbg_log(SEC_0170_CSFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] csfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) is already up\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
        return (EC_TRUE);
    }
#if 0 
    if(CSFSCONHASH_RNODE_IS_DOWN != CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {    
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) is not down\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
        return (EC_FALSE);
    }
#endif 

    if(CSFSCONHASH_ERR_REPLICAS == CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode)
    || CSFSCONHASH_ANY_REPLICAS == CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode))
    {    
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) has invalid replica\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
        return (EC_FALSE);
    }

    /*add vnode replicas*/
    if(EC_FALSE == csfsconhash_add_vnode_replicas(csfsconhash, csfsconhash_rnode_pos))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_up_node: add vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));

        csfsconhash_del_vnode_replicas(csfsconhash, csfsconhash_rnode_pos);/*roll back*/
        return (EC_FALSE);
    }

    CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode) = CSFSCONHASH_RNODE_IS_UP; /*set up*/

    dbg_log(SEC_0170_CSFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] csfsconhash_up_node: rnode (tcid %s, replicas %u, status %s) set up => OK\n",
                       c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                       CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                       csfsconhash_rnode_status(csfsconhash_rnode));
                    
    return (EC_TRUE);
}

EC_BOOL csfsconhash_down_node(CSFSCONHASH *csfsconhash, const uint32_t tcid)
{
    CSFSCONHASH_RNODE  csfsconhash_rnode_t;
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    UINT32             csfsconhash_rnode_pos;

    CSFSCONHASH_RNODE_TCID(&csfsconhash_rnode_t) = tcid;
    csfsconhash_rnode_pos = cvector_search_front(CSFSCONHASH_RNODE_VEC(csfsconhash),
                                                 (void *)&csfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)csfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == csfsconhash_rnode_pos)
    {    
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_down_node: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (csfsconhash_rnode_pos >> 16));

    csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos);

    if(CSFSCONHASH_RNODE_IS_DOWN == CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {    
        dbg_log(SEC_0170_CSFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] csfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) is already down\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
        return (EC_TRUE);
    }
#if 0 
    if(CSFSCONHASH_RNODE_IS_UP != CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode))
    {    
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) is not up\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
        return (EC_FALSE);
    }
#endif
    /*del vnode replicas*/
    if(EC_FALSE == csfsconhash_del_vnode_replicas(csfsconhash, csfsconhash_rnode_pos))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_down_node: del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                           CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                           csfsconhash_rnode_status(csfsconhash_rnode));
        return (EC_FALSE);
    }

    CSFSCONHASH_RNODE_STATUS(csfsconhash_rnode) = CSFSCONHASH_RNODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0170_CSFSCONHASH, 9)(LOGSTDOUT, "[DEBUG] csfsconhash_down_node: rnode (tcid %s, replicas %u, status %s) set down => OK\n",
                       c_word_to_ipv4(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode)),
                       CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode),
                       csfsconhash_rnode_status(csfsconhash_rnode));
                    
    return (EC_TRUE);
}

EC_BOOL csfsconhash_has_node(const CSFSCONHASH *csfsconhash, const uint32_t tcid)
{
    CSFSCONHASH_RNODE  csfsconhash_rnode_t;
    UINT32             csfsconhash_rnode_pos;

    CSFSCONHASH_RNODE_TCID(&csfsconhash_rnode_t) = tcid;
    csfsconhash_rnode_pos = cvector_search_front(CSFSCONHASH_RNODE_VEC(csfsconhash),
                                                 (void *)&csfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)csfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == csfsconhash_rnode_pos)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 9)(LOGSTDOUT, "info:csfsconhash_has_node: tcid %s is not in rnode\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

CSFSCONHASH_RNODE *csfsconhash_get_rnode(const CSFSCONHASH *csfsconhash, const uint32_t tcid)
{
    CSFSCONHASH_RNODE  csfsconhash_rnode_t;
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    UINT32             csfsconhash_rnode_pos;

    CSFSCONHASH_RNODE_TCID(&csfsconhash_rnode_t) = tcid;
    csfsconhash_rnode_pos = cvector_search_front(CSFSCONHASH_RNODE_VEC(csfsconhash),
                                                 (void *)&csfsconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)csfsconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == csfsconhash_rnode_pos)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_get_rnode: not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (NULL_PTR);
    }

    csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode_pos);
    return (csfsconhash_rnode);
}

CSFSCONHASH_RNODE *csfsconhash_lookup_rnode(const CSFSCONHASH *csfsconhash, const uint32_t hash)
{
    CSFSCONHASH_VNODE  csfsconhash_vnode_t;
    CSFSCONHASH_VNODE *csfsconhash_vnode;
    CSFSCONHASH_RNODE *csfsconhash_rnode;
    CRB_NODE *crb_node;

    if(EC_TRUE == crb_tree_is_empty(CSFSCONHASH_VNODE_TREE(csfsconhash)))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_lookup_rnode: vnode tree is empty\n"); 
        return (NULL_PTR); 
    }

    CSFSCONHASH_VNODE_HASH(&csfsconhash_vnode_t) = hash;
    crb_node = crb_tree_lookup_data(CSFSCONHASH_VNODE_TREE(csfsconhash), (void *)&csfsconhash_vnode_t);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_lookup_rnode: hash %x, should never reach here due to rbtree be circled\n",
                           hash); 
        return (NULL_PTR);
    }

    csfsconhash_vnode = (CSFSCONHASH_VNODE *)CRB_NODE_DATA(crb_node);
    if(NULL_PTR == csfsconhash_vnode)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_lookup_rnode: hash %x, crb_node %p, should never reach here due to CRB_NODE_DATA be null!\n",
                           hash, crb_node); 
        return (NULL_PTR);
    } 
#if 0
    if(do_log(SEC_0170_CSFSCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] csfsconhash_lookup_rnode: hash %x => vnode ", hash);
        csfsconhash_vnode_print(LOGSTDOUT, csfsconhash_vnode);
    }
#endif
    csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash),
                                                         CSFSCONHASH_VNODE_POS(csfsconhash_vnode));
    if(NULL_PTR == csfsconhash_rnode)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_lookup_rnode: hash %x, rnode_pos %u, should never reach here due to rnode not existing\n",
                           hash, CSFSCONHASH_VNODE_POS(csfsconhash_vnode)); 
        return (NULL_PTR);
    }
    return (csfsconhash_rnode);
}

EC_BOOL csfsconhash_flush_size(const CSFSCONHASH *csfsconhash, UINT32 *size)
{
    (*size) = sizeof(UINT32) /*hash_id*/
            + sizeof(UINT32) /*rnode_vec size*/
            + cvector_size(CSFSCONHASH_RNODE_VEC(csfsconhash)) * (
                                                                    sizeof(uint16_t) /*replicas*/
                                                                  + sizeof(uint32_t) /*tcid*/
                                                                  )
            + sizeof(uint32_t) /*vnode_tree size*/
            + crb_tree_node_num(CSFSCONHASH_VNODE_TREE(csfsconhash)) * (
                                                                     sizeof(uint32_t) /*hash*/
                                                                   + sizeof(uint32_t) /*pos*/
                                                                   );
    return (EC_FALSE);
}

EC_BOOL csfsconhash_rnode_flush(const CSFSCONHASH_RNODE *csfsconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/
 
    if(NULL_PTR == csfsconhash_rnode)
    {
        uint32_t     tcid;
        uint16_t     replicas;
 
        replicas = CSFSCONHASH_ERR_REPLICAS;
        tcid     = (uint32_t)CMPI_ERROR_TCID;

        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(replicas)))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_rnode_flush: flush replicas at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(tcid)))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_rnode_flush: flush tcid at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }     
    }
    else
    {
        osize = sizeof(uint16_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode))))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_rnode_flush: flush replicas at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }

        osize = sizeof(uint32_t);
        if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode))))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_rnode_flush: flush tcid at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }     
    }
    return (EC_TRUE);
}

EC_BOOL csfsconhash_rnode_load(CSFSCONHASH_RNODE *csfsconhash_rnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint16_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_rnode_load: load replicas at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_RNODE_TCID(csfsconhash_rnode))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_rnode_load: load tcid at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsconhash_flush_rnodes(const CSFSCONHASH *csfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/
 
    UINT32   rnode_num;
    UINT32   rnode_pos;

    rnode_num = cvector_size(CSFSCONHASH_RNODE_VEC(csfsconhash));
 
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_flush_rnodes: flush rnode_num at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CSFSCONHASH_RNODE *csfsconhash_rnode;
        csfsconhash_rnode = (CSFSCONHASH_RNODE *)cvector_get(CSFSCONHASH_RNODE_VEC(csfsconhash), rnode_pos);
        if(EC_FALSE == csfsconhash_rnode_flush(csfsconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_flush_rnodes: flush rnode %u# at offset %u of fd %d failed\n", rnode_pos, (*offset), fd);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE); 
}

EC_BOOL csfsconhash_load_rnodes(CSFSCONHASH *csfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/
 
    UINT32   rnode_num;
    UINT32   rnode_pos;

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(rnode_num)))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load_rnodes: load rnode_num at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    for(rnode_pos = 0; rnode_pos < rnode_num; rnode_pos ++)
    {
        CSFSCONHASH_RNODE *csfsconhash_rnode;

        csfsconhash_rnode = csfsconhash_rnode_new();
        if(NULL_PTR == csfsconhash_rnode)
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load_rnodes: new rnode at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
     
        if(EC_FALSE == csfsconhash_rnode_load(csfsconhash_rnode, fd, offset))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load_rnodes: load rnode %u# at offset %u of fd %d failed\n", rnode_pos, (*offset), fd);
            csfsconhash_rnode_free(csfsconhash_rnode);
            return (EC_FALSE);
        }
     
        if(CSFSCONHASH_ERR_REPLICAS == CSFSCONHASH_RNODE_REPLICAS(csfsconhash_rnode)
        && ((uint32_t)CMPI_ERROR_TCID) == CSFSCONHASH_RNODE_TCID(csfsconhash_rnode))
        {
            cvector_push(CSFSCONHASH_RNODE_VEC(csfsconhash), NULL_PTR);
            csfsconhash_rnode_free(csfsconhash_rnode);
        }
        else
        {
            cvector_push(CSFSCONHASH_RNODE_VEC(csfsconhash), csfsconhash_rnode);
        }
    }

    return (EC_TRUE); 
}

EC_BOOL csfsconhash_vnode_flush(const CSFSCONHASH_VNODE *csfsconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_VNODE_HASH(csfsconhash_vnode))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_vnode_flush: flush hash at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_VNODE_POS(csfsconhash_vnode))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_vnode_flush: flush pos at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_vnode_load(CSFSCONHASH_VNODE *csfsconhash_vnode, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_VNODE_HASH(csfsconhash_vnode))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_vnode_load: load hash at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    osize = sizeof(uint32_t);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_VNODE_POS(csfsconhash_vnode))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_vnode_load: load pos at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

static EC_BOOL __csfsconhash_flush_vnodes_inorder(const CSFSCONHASH *csfsconhash, const CRB_NODE *node, int fd, UINT32 *offset)
{
    CSFSCONHASH_VNODE *csfsconhash_vnode;
    if(NULL_PTR == node)
    {
        return (EC_TRUE);
    }
 
    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_FALSE == __csfsconhash_flush_vnodes_inorder(csfsconhash, CRB_NODE_LEFT(node), fd, offset))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:__csfsconhash_flush_vnodes_inorder: flush left subtree %p at offset %u of fd %d failed\n", CRB_NODE_LEFT(node), (*offset), fd);
            return (EC_FALSE);
        }
    }

    csfsconhash_vnode = (CSFSCONHASH_VNODE *)CRB_NODE_DATA(node);
    if(NULL_PTR == csfsconhash_vnode)
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:__csfsconhash_flush_vnodes_inorder: data of crb node %p is null at offset %u of fd %d failed\n", node, (*offset), fd);
        return (EC_FALSE);
    }
 
    if(EC_FALSE == csfsconhash_vnode_flush(csfsconhash_vnode, fd, offset))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:__csfsconhash_flush_vnodes_inorder: flush vnode %p at offset %u of fd %d failed\n", csfsconhash_vnode, (*offset), fd);
        return (EC_FALSE);
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_FALSE == __csfsconhash_flush_vnodes_inorder(csfsconhash, CRB_NODE_RIGHT(node), fd, offset))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:__csfsconhash_flush_vnodes_inorder: flush right subtree %p at offset %u of fd %d failed\n", CRB_NODE_RIGHT(node), (*offset), fd);
            return (EC_FALSE);
        }
    } 
 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_flush_vnodes(const CSFSCONHASH *csfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/
 
    uint32_t   vnode_num;
 
    vnode_num = crb_tree_node_num(CSFSCONHASH_VNODE_TREE(csfsconhash));

    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_flush_vnodes: flush vnode num at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    if(EC_FALSE == __csfsconhash_flush_vnodes_inorder(csfsconhash, CRB_TREE_ROOT(CSFSCONHASH_VNODE_TREE(csfsconhash)), fd, offset))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_flush_vnodes: flush vnode tree at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL csfsconhash_load_vnodes(CSFSCONHASH *csfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/
 
    uint32_t   vnode_num;
    uint32_t   vnode_pos;
 
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(vnode_num)))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load_vnodes: load vnode num at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    for(vnode_pos = 0; vnode_pos < vnode_num; vnode_pos ++)
    {
        CSFSCONHASH_VNODE *csfsconhash_vnode;

        csfsconhash_vnode = csfsconhash_vnode_new();
        if(NULL_PTR == csfsconhash_vnode)
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load_vnodes: new vnode at offset %u of fd %d failed\n", (*offset), fd);
            return (EC_FALSE);
        }
     
        if(EC_FALSE == csfsconhash_vnode_load(csfsconhash_vnode, fd, offset))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load_vnodes: load vnode %u# at offset %u of fd %d failed\n", vnode_pos, (*offset), fd);
            csfsconhash_vnode_free(csfsconhash_vnode);
            return (EC_FALSE);
        }     

        if(NULL_PTR == csfsconhash_add_vnode(csfsconhash, csfsconhash_vnode))
        {
            dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load_vnodes: add vnode %u# at offset %u of fd %d failed\n", vnode_pos, (*offset), fd);
            csfsconhash_vnode_free(csfsconhash_vnode);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL csfsconhash_flush(const CSFSCONHASH *csfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*flush hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_flush(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_HASH_ID(csfsconhash))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_flush: flush hash id at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 

    /*flush rnode vec*/
    if(EC_FALSE == csfsconhash_flush_rnodes(csfsconhash, fd, offset))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_flush: flush rnodes at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }

    /*flush vnode tree*/
    if(EC_FALSE == csfsconhash_flush_vnodes(csfsconhash, fd, offset))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_flush: flush vnodes at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_load(CSFSCONHASH *csfsconhash, int fd, UINT32 *offset)
{
    UINT32   osize;/*write once size*/

    /*load hash_id*/
    osize = sizeof(UINT32);
    if(EC_FALSE == c_file_load(fd, offset, osize, (uint8_t *)&(CSFSCONHASH_HASH_ID(csfsconhash))))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load: load hash id at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    CSFSCONHASH_HASH_FUNC(csfsconhash) = chash_algo_fetch(CSFSCONHASH_HASH_ID(csfsconhash));
    if(NULL_PTR == CSFSCONHASH_HASH_FUNC(csfsconhash))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load: invalid hash id %ld\n", CSFSCONHASH_HASH_ID(csfsconhash));
        return (EC_FALSE);
    } 

    /*load rnode vec*/
    if(EC_FALSE == csfsconhash_load_rnodes(csfsconhash, fd, offset))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load: load rnodes at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    } 

    /*load vnode tree*/
    if(EC_FALSE == csfsconhash_load_vnodes(csfsconhash, fd, offset))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "error:csfsconhash_load: load vnodes at offset %u of fd %d failed\n", (*offset), fd);
        return (EC_FALSE);
    }
 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_rnodes_is_equal(const CSFSCONHASH *csfsconhash_1st, const CSFSCONHASH *csfsconhash_2nd)
{
    return cvector_cmp(CSFSCONHASH_RNODE_VEC(csfsconhash_1st),
                       CSFSCONHASH_RNODE_VEC(csfsconhash_2nd),
                       (CVECTOR_DATA_CMP)csfsconhash_rnode_is_equal);
}

EC_BOOL csfsconhash_vnodes_is_equal(const CSFSCONHASH *csfsconhash_1st, const CSFSCONHASH *csfsconhash_2nd)
{
    return crb_tree_cmp(CSFSCONHASH_VNODE_TREE(csfsconhash_1st),
                        CSFSCONHASH_VNODE_TREE(csfsconhash_2nd),
                        (CRB_DATA_IS_EQUAL)csfsconhash_vnode_is_equal);
}

EC_BOOL csfsconhash_is_equal(const CSFSCONHASH *csfsconhash_1st, const CSFSCONHASH *csfsconhash_2nd)
{
    if(CSFSCONHASH_HASH_ID(csfsconhash_1st) != CSFSCONHASH_HASH_ID(csfsconhash_2nd))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "csfsconhash_is_equal: hash id: %u != %u\n",
                           CSFSCONHASH_HASH_ID(csfsconhash_1st),
                           CSFSCONHASH_HASH_ID(csfsconhash_2nd));
        return (EC_FALSE);
    }

    if(CSFSCONHASH_HASH_FUNC(csfsconhash_1st) != CSFSCONHASH_HASH_FUNC(csfsconhash_2nd))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "csfsconhash_is_equal: hash func: %p != %p\n",
                           CSFSCONHASH_HASH_FUNC(csfsconhash_1st),
                           CSFSCONHASH_HASH_FUNC(csfsconhash_2nd));
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsconhash_rnodes_is_equal(csfsconhash_1st, csfsconhash_2nd))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "csfsconhash_is_equal: rnodes is not equal\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == csfsconhash_vnodes_is_equal(csfsconhash_1st, csfsconhash_2nd))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "csfsconhash_is_equal: vnodes is not equal\n");
        return (EC_FALSE);
    } 
 
    return (EC_TRUE);
}

EC_BOOL csfsconhash_clone(const CSFSCONHASH *csfsconhash_src, CSFSCONHASH *csfsconhash_des)
{
    cvector_clone(CSFSCONHASH_RNODE_VEC(csfsconhash_src),
                  CSFSCONHASH_RNODE_VEC(csfsconhash_des),
                  (CVECTOR_DATA_MALLOC)csfsconhash_rnode_new,
                  (CVECTOR_DATA_CLONE)csfsconhash_rnode_clone);

    if(EC_FALSE == crb_tree_clone(CSFSCONHASH_VNODE_TREE(csfsconhash_src),
                                   CSFSCONHASH_VNODE_TREE(csfsconhash_des),
                                   (CRB_DATA_NEW)csfsconhash_vnode_new,
                                   (CRB_DATA_CLONE)csfsconhash_vnode_clone))
    {
        dbg_log(SEC_0170_CSFSCONHASH, 0)(LOGSTDOUT, "csfsconhash_clone: clone vnodes failed\n");
        return (EC_FALSE);
    }

    CSFSCONHASH_HASH_ID(csfsconhash_des)   = CSFSCONHASH_HASH_ID(csfsconhash_src);
    CSFSCONHASH_HASH_FUNC(csfsconhash_des) = CSFSCONHASH_HASH_FUNC(csfsconhash_src);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

