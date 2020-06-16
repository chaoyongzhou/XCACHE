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
#include "cparacfg.inc"
#include "chashalgo.h"

#include "task.h"

#include "cconhash.h"

#if 0
#define CCONHASH_ASSERT(condition)   ASSERT(condition)
#else
#define CCONHASH_ASSERT(condition)   do{}while(0)
#endif

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
    }
    return (cconhash_rnode);
}

EC_BOOL cconhash_rnode_init(CCONHASH_RNODE *cconhash_rnode)
{
    if(NULL_PTR != cconhash_rnode)
    {
        CCONHASH_RNODE_REPLICAS(cconhash_rnode) = 0;
        CCONHASH_RNODE_STATUS(cconhash_rnode)   = CCONHASH_RNODE_IS_ERR;
        CCONHASH_RNODE_TCID(cconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;
    }
    return (EC_TRUE);
}

EC_BOOL cconhash_rnode_clean(CCONHASH_RNODE *cconhash_rnode)
{
    if(NULL_PTR != cconhash_rnode)
    {
        CCONHASH_RNODE_REPLICAS(cconhash_rnode) = 0;
        CCONHASH_RNODE_STATUS(cconhash_rnode)   = CCONHASH_RNODE_IS_ERR;
        CCONHASH_RNODE_TCID(cconhash_rnode)     = (uint32_t)CMPI_ERROR_TCID;
    }
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
    sys_log(log, "cconhash_rnode %p: tcid %s, replicas %u, status %s\n",
                    cconhash_rnode,
                    c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                    CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                    cconhash_rnode_status(cconhash_rnode)
                   );
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
        CCONHASH_VNODE_HASH(cconhash_vnode)     = hash;
        CCONHASH_VNODE_POS(cconhash_vnode)      = rnode_pos;
    }
    return (cconhash_vnode);
}

EC_BOOL cconhash_vnode_set(CCONHASH_VNODE *cconhash_vnode, const uint32_t hash)
{
    if(NULL_PTR != cconhash_vnode)
    {
        CCONHASH_VNODE_HASH(cconhash_vnode)     = hash;
        CCONHASH_VNODE_POS(cconhash_vnode)      = (uint32_t)CVECTOR_ERR_POS;

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cconhash_vnode_init(CCONHASH_VNODE *cconhash_vnode)
{
    if(NULL_PTR != cconhash_vnode)
    {
        CCONHASH_VNODE_HASH(cconhash_vnode)     = 0;
        CCONHASH_VNODE_POS(cconhash_vnode)      = (uint32_t)CVECTOR_ERR_POS;
    }
    return (EC_TRUE);
}

EC_BOOL cconhash_vnode_clean(CCONHASH_VNODE *cconhash_vnode)
{
    if(NULL_PTR != cconhash_vnode)
    {
        CCONHASH_VNODE_HASH(cconhash_vnode)     = 0;
        CCONHASH_VNODE_POS(cconhash_vnode)      = (uint32_t)CVECTOR_ERR_POS;
    }
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

EC_BOOL cconhash_vnode_clone(const CCONHASH_VNODE *cconhash_vnode_src, CCONHASH_VNODE *cconhash_vnode_des)
{
    if(NULL_PTR != cconhash_vnode_src && NULL_PTR != cconhash_vnode_des)
    {
        CCONHASH_VNODE_HASH(cconhash_vnode_des) = CCONHASH_VNODE_HASH(cconhash_vnode_src);
        CCONHASH_VNODE_POS(cconhash_vnode_des)  = CCONHASH_VNODE_POS(cconhash_vnode_src);
    }
    return (EC_TRUE);
}

int cconhash_vnode_cmp(const CCONHASH_VNODE *cconhash_vnode_1st, const CCONHASH_VNODE *cconhash_vnode_2nd)
{
    if(CCONHASH_VNODE_HASH(cconhash_vnode_1st) >= CCONHASH_VNODE_HASH(cconhash_vnode_2nd))
    {
        return (1);
    }

    if(CCONHASH_VNODE_HASH(cconhash_vnode_1st) >= CCONHASH_VNODE_HASH(cconhash_vnode_2nd))
    {
        return (-1);
    }
    return (0);
}

STATIC_CAST static int __cconhash_vnode_cmp(const void *vnode_ptr_1st, const void *vnode_ptr_2nd)
{
    return cconhash_vnode_cmp(*(const CCONHASH_VNODE **)vnode_ptr_1st,
                              *(const CCONHASH_VNODE **)vnode_ptr_2nd);
}

void cconhash_vnode_print(LOG *log, const CCONHASH_VNODE *cconhash_vnode)
{
    if(NULL_PTR != cconhash_vnode)
    {
        sys_log(log, "cconhash_vnode %p: hash %u, rnode pos %u\n",
                        cconhash_vnode,
                        CCONHASH_VNODE_HASH(cconhash_vnode),
                        CCONHASH_VNODE_POS(cconhash_vnode)
                       );
    }
    return;
}

EC_BOOL cconhash_vnodes_init(CCONHASH_VNODES *cconhash_vnodes, const uint32_t capacity)
{
    if(NULL_PTR != cconhash_vnodes)
    {
        UINT32                nbytes;

        nbytes = (((UINT32)capacity) * sizeof(CCONHASH_VNODE *));

        CCONHASH_VNODES_NODES(cconhash_vnodes) = safe_malloc(nbytes, LOC_CCONHASH_0004);
        if(NULL_PTR == CCONHASH_VNODES_NODES(cconhash_vnodes))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_vnodes_init: "
                                                     "alloc %u vnodes failed\n",
                                                     capacity);
            return (EC_FALSE);
        }

        CCONHASH_VNODES_CAPACITY(cconhash_vnodes) = capacity;
        CCONHASH_VNODES_SIZE(cconhash_vnodes)     = 0;
    }
    return (EC_TRUE);
}

EC_BOOL cconhash_vnodes_clean(CCONHASH_VNODES *cconhash_vnodes)
{
    if(NULL_PTR != cconhash_vnodes)
    {
        if(NULL_PTR != CCONHASH_VNODES_NODES(cconhash_vnodes))
        {
            uint32_t    pos;
            uint32_t    size;

            size = CCONHASH_VNODES_SIZE(cconhash_vnodes);
            for(pos = 0; pos < size; pos ++)
            {
                cconhash_vnode_free(CCONHASH_VNODES_NODES(cconhash_vnodes)[ pos ]);
                CCONHASH_VNODES_NODES(cconhash_vnodes)[ pos ] = NULL_PTR;
            }

            safe_free(CCONHASH_VNODES_NODES(cconhash_vnodes), LOC_CCONHASH_0005);
            CCONHASH_VNODES_NODES(cconhash_vnodes) = NULL_PTR;
        }

        CCONHASH_VNODES_CAPACITY(cconhash_vnodes) = 0;
        CCONHASH_VNODES_SIZE(cconhash_vnodes)     = 0;
    }
    return (EC_TRUE);
}

UINT32 cconhash_vnodes_num(const CCONHASH_VNODES *cconhash_vnodes)
{
    if(NULL_PTR != cconhash_vnodes)
    {
        return CCONHASH_VNODES_SIZE(cconhash_vnodes);
    }

    return (0);
}

EC_BOOL cconhash_vnodes_is_full(const CCONHASH_VNODES *cconhash_vnodes)
{
    if(CCONHASH_VNODES_SIZE(cconhash_vnodes) == CCONHASH_VNODES_CAPACITY(cconhash_vnodes))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cconhash_vnodes_is_empty(const CCONHASH_VNODES *cconhash_vnodes)
{
    if(0 == CCONHASH_VNODES_SIZE(cconhash_vnodes))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cconhash_vnodes_expand(CCONHASH_VNODES *cconhash_vnodes)
{
    if(NULL_PTR != cconhash_vnodes)
    {
        uint32_t      capacity_src;
        uint32_t      capacity_des;
        uint32_t      nbytes_src;
        uint32_t      nbytes_des;
        void         *data_src;
        void         *data_des;

        capacity_src = CCONHASH_VNODES_CAPACITY(cconhash_vnodes);
        capacity_des = (capacity_src + CMON_CONHASH_REPLICAS);
        data_src     = CCONHASH_VNODES_NODES(cconhash_vnodes);

        nbytes_des   = (capacity_des * sizeof(CCONHASH_VNODE *));
        data_des     = safe_malloc(nbytes_des, LOC_CCONHASH_0004);

        if(NULL_PTR == data_des)
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_vnodes_expand: "
                                                     "expand capacity %u to %u failed\n",
                                                     capacity_src,
                                                     capacity_des);
            return (EC_FALSE);
        }

        nbytes_src = (capacity_src * sizeof(CCONHASH_VNODE *));
        BCOPY(data_src, data_des, nbytes_src);

        safe_free(data_src, LOC_CCONHASH_0004);

        CCONHASH_VNODES_NODES(cconhash_vnodes)    = data_des;
        CCONHASH_VNODES_CAPACITY(cconhash_vnodes) = capacity_des;
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_vnodes_add(CCONHASH_VNODES *cconhash_vnodes, const CCONHASH_VNODE *cconhash_vnode)
{
    if(NULL_PTR != cconhash_vnodes && NULL_PTR != cconhash_vnode)
    {
        uint32_t    pos;

        if(EC_TRUE == cconhash_vnodes_is_full(cconhash_vnodes)
        && EC_FALSE == cconhash_vnodes_expand(cconhash_vnodes))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_vnodes_add: "
                                                     "vnodes are full (%u, %u) and expand failed\n",
                                                     CCONHASH_VNODES_SIZE(cconhash_vnodes),
                                                     CCONHASH_VNODES_CAPACITY(cconhash_vnodes));

            return (EC_FALSE);
        }

        pos = CCONHASH_VNODES_SIZE(cconhash_vnodes);
        CCONHASH_VNODES_NODES(cconhash_vnodes)[ pos ] = (void *)cconhash_vnode;

        CCONHASH_VNODES_SIZE(cconhash_vnodes) ++;
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_vnodes_del(CCONHASH_VNODES *cconhash_vnodes, const uint32_t cconhash_rnode_pos)
{
    uint32_t    i;
    uint32_t    j;
    uint32_t    size;

    ASSERT(NULL_PTR != cconhash_vnodes);

    i    = 0;
    j    = 0;
    size = CCONHASH_VNODES_SIZE(cconhash_vnodes);

    for(;i < size; i ++)
    {
        CCONHASH_VNODE *cconhash_vnode;

        cconhash_vnode = CCONHASH_VNODES_NODES(cconhash_vnodes)[ i ];
        if(cconhash_rnode_pos == CCONHASH_VNODE_POS(cconhash_vnode))
        {
            CCONHASH_VNODES_NODES(cconhash_vnodes)[ i ] = NULL_PTR;
            cconhash_vnode_free(cconhash_vnode);
            continue;
        }

        while(j < i && NULL_PTR != CCONHASH_VNODES_NODES(cconhash_vnodes)[ j ])
        {
            j ++;
        }

        if(j < i)
        {
            CCONHASH_VNODES_NODES(cconhash_vnodes)[ j ] = CCONHASH_VNODES_NODES(cconhash_vnodes)[ i ];
            CCONHASH_VNODES_NODES(cconhash_vnodes)[ i ] = NULL_PTR;
            j ++;
        }
    }

    CCONHASH_VNODES_SIZE(cconhash_vnodes) = j; /*update*/

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_vnodes_del: "
                                             "vnodes %u => %u\n",
                                             size, j);
    return (EC_TRUE);
}

EC_BOOL cconhash_vnodes_discard(CCONHASH_VNODES *cconhash_vnodes, const uint32_t cconhash_vnode_s_pos)
{
    uint32_t    pos;
    uint32_t    size;

    size = CCONHASH_VNODES_SIZE(cconhash_vnodes);

    for(pos = size; pos -- > cconhash_vnode_s_pos;)
    {
        CCONHASH_VNODE *cconhash_vnode;

        cconhash_vnode = CCONHASH_VNODES_NODES(cconhash_vnodes)[ pos ];
        cconhash_vnode_free(cconhash_vnode);
    }

    CCONHASH_VNODES_SIZE(cconhash_vnodes) = pos;

    return (EC_TRUE);
}


EC_BOOL cconhash_vnodes_sort(CCONHASH_VNODES *cconhash_vnodes)
{
    qsort((void *)CCONHASH_VNODES_NODES(cconhash_vnodes),
            CCONHASH_VNODES_SIZE(cconhash_vnodes), sizeof(void *), __cconhash_vnode_cmp);

    return (EC_TRUE);
}

CCONHASH_VNODE *cconhash_vnodes_lookup(const CCONHASH_VNODES *cconhash_vnodes, const uint32_t hash)
{
    uint32_t        lo;
    uint32_t        hi;
    uint32_t        mid;
    uint32_t        size;

    /*note: vnodes descend in hash*/

    size = CCONHASH_VNODES_SIZE(cconhash_vnodes);

    if(0 == size)
    {
        return (NULL_PTR);
    }

    lo = 0;
    hi = size - 1;

    while (lo < hi)
    {
        CCONHASH_VNODE *cconhash_vnode_lo;
        CCONHASH_VNODE *cconhash_vnode_hi;
        CCONHASH_VNODE *cconhash_vnode_mid;

        cconhash_vnode_lo = CCONHASH_VNODES_NODES(cconhash_vnodes)[ lo ];
        cconhash_vnode_hi = CCONHASH_VNODES_NODES(cconhash_vnodes)[ hi ];

        if(hash <= CCONHASH_VNODE_HASH(cconhash_vnode_lo)
        || hash >  CCONHASH_VNODE_HASH(cconhash_vnode_hi))
        {
            return (cconhash_vnode_lo);
        }

        /* perfect match */
        if(hash == CCONHASH_VNODE_HASH(cconhash_vnode_hi))
        {
            return (cconhash_vnode_hi);
        }

        mid = (lo + hi) / 2;

        cconhash_vnode_mid = CCONHASH_VNODES_NODES(cconhash_vnodes)[ mid ];

        /* perfect match */
        if(0 < mid)
        {
            CCONHASH_VNODE *cconhash_vnode_prev;

            cconhash_vnode_prev = CCONHASH_VNODES_NODES(cconhash_vnodes)[ mid - 1 ];

            if (hash <= CCONHASH_VNODE_HASH(cconhash_vnode_mid)
            &&  hash > CCONHASH_VNODE_HASH(cconhash_vnode_prev))
            {
                return (cconhash_vnode_mid);
            }
        }
        else
        {
            if (hash <= CCONHASH_VNODE_HASH(cconhash_vnode_mid))
            {
                return (cconhash_vnode_mid);
            }
        }

        if(hash == CCONHASH_VNODE_HASH(cconhash_vnode_mid))
        {
            return (cconhash_vnode_mid);
        }

        if(hash > CCONHASH_VNODE_HASH(cconhash_vnode_mid))
        {
            lo = mid + 1;
        }
        else
        {
      	    hi = mid;
  	    }
    }

    return CCONHASH_VNODES_NODES(cconhash_vnodes)[ hi ];
}

void cconhash_vnodes_print(LOG *log, const CCONHASH_VNODES *cconhash_vnodes)
{
    if(NULL_PTR != cconhash_vnodes)
    {
        uint32_t        pos;

        sys_log(log, "cconhash_vnodes %p: capacity %u, size %u\n",
                        cconhash_vnodes,
                        CCONHASH_VNODES_CAPACITY(cconhash_vnodes),
                        CCONHASH_VNODES_SIZE(cconhash_vnodes)
                       );

        for(pos = 0; pos < CCONHASH_VNODES_SIZE(cconhash_vnodes); pos ++)
        {
            CCONHASH_VNODE *cconhash_vnode;

            cconhash_vnode = CCONHASH_VNODES_NODES(cconhash_vnodes)[ pos ];

            //cconhash_vnode_print(log, cconhash_vnode);

            sys_log(log, "[%u] cconhash_vnode %p: hash %u, rnode pos %u\n",
                          pos,
                          cconhash_vnode,
                          CCONHASH_VNODE_HASH(cconhash_vnode),
                          CCONHASH_VNODE_POS(cconhash_vnode)
                         );
        }
    }
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
    if(NULL_PTR != cconhash)
    {
        uint32_t    vnode_num_default;

        CCONHASH_HASH_FUNC(cconhash) = chash_algo_fetch(hash_id);
        if(NULL_PTR == CCONHASH_HASH_FUNC(cconhash))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_init: "
                                                     "invalid hash_id %ld\n",
                                                     hash_id);
            return (EC_FALSE);
        }
        CCONHASH_HASH_ID(cconhash)   = hash_id;

        cvector_init(CCONHASH_RNODE_VEC(cconhash), 0,
                        MM_CCONHASH_RNODE, CVECTOR_LOCK_ENABLE, LOC_CCONHASH_0009);

        /* default: 160 vnodes/disk * 8 disks/device * 8 device */
        vnode_num_default = CPARACFG_CMON_CONHASH_REPLICAS_DEF * 8 * 8;
        cconhash_vnodes_init(CCONHASH_VNODE_LIST(cconhash), vnode_num_default);
    }
    return (EC_TRUE);
}

EC_BOOL cconhash_clean(CCONHASH *cconhash)
{
    if(NULL_PTR != cconhash)
    {
        cvector_clean(CCONHASH_RNODE_VEC(cconhash),
                        (CVECTOR_DATA_CLEANER)cconhash_rnode_free, LOC_CCONHASH_0010);
        cconhash_vnodes_clean(CCONHASH_VNODE_LIST(cconhash));

        CCONHASH_HASH_ID(cconhash)    = CHASH_ERR_ALGO_ID;
        CCONHASH_HASH_FUNC(cconhash)  = NULL_PTR;
    }
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
    if(NULL_PTR != cconhash)
    {
        sys_log(log, "cconhash %p: hash_id %ld, rnode num %ld, vnode num %ld\n",
                        cconhash,
                        CCONHASH_HASH_ID(cconhash),
                        cvector_size(CCONHASH_RNODE_VEC(cconhash)),
                        cconhash_vnodes_num(CCONHASH_VNODE_LIST(cconhash))
                        );

        if(do_log(SEC_0050_CCONHASH, 6))
        {
            sys_log(log, "cconhash %p: rnode vec:\n", cconhash);
            cvector_print(log, CCONHASH_RNODE_VEC(cconhash),
                                (CVECTOR_DATA_PRINT)cconhash_rnode_print);
        }

        if(do_log(SEC_0050_CCONHASH, 7))
        {
            sys_log(log, "cconhash %p: vnode tree:\n", cconhash);
            cconhash_vnodes_print(log, CCONHASH_VNODE_LIST(cconhash));
        }
    }

    return;
}

void cconhash_print_rnode_vec(LOG *log, const CCONHASH *cconhash)
{
    if(NULL_PTR != cconhash)
    {
        sys_log(log, "cconhash %p: hash_id %ld\n",
                        cconhash,
                        CCONHASH_HASH_ID(cconhash));

        sys_log(log, "cconhash %p: rnode vec:\n", cconhash);
        cvector_print(log, CCONHASH_RNODE_VEC(cconhash),
                    (CVECTOR_DATA_PRINT)cconhash_rnode_print);
    }
    return;
}

void cconhash_print_vnode_tree(LOG *log, const CCONHASH *cconhash)
{
    if(NULL_PTR != cconhash)
    {
        sys_log(log, "cconhash %p: hash_id %ld\n",
                        cconhash,
                        CCONHASH_HASH_ID(cconhash));

        sys_log(log, "cconhash %p: vnode tree:\n", cconhash);
        cconhash_vnodes_print(log, CCONHASH_VNODE_LIST(cconhash));
    }
    return;
}

UINT32 cconhash_add_rnode(CCONHASH *cconhash, const CCONHASH_RNODE *cconhash_rnode)
{
    return cvector_add(CCONHASH_RNODE_VEC(cconhash), (void *)cconhash_rnode);
}

EC_BOOL cconhash_add_vnode(CCONHASH *cconhash, const CCONHASH_VNODE *cconhash_vnode)
{
    return cconhash_vnodes_add(CCONHASH_VNODE_LIST(cconhash), cconhash_vnode);
}

EC_BOOL cconhash_del_vnodes(CCONHASH *cconhash, const uint32_t cconhash_rnode_pos)
{
    return cconhash_vnodes_del(CCONHASH_VNODE_LIST(cconhash), cconhash_rnode_pos);
}

EC_BOOL cconhash_discard_vnodes(CCONHASH *cconhash, const uint32_t cconhash_vnode_s_pos)
{
    return cconhash_vnodes_discard(CCONHASH_VNODE_LIST(cconhash), cconhash_vnode_s_pos);
}

EC_BOOL cconhash_sort_vnodes(CCONHASH *cconhash)
{
    return cconhash_vnodes_sort(CCONHASH_VNODE_LIST(cconhash));
}

STATIC_CAST static uint32_t __cconhash_hash_vnode(CCONHASH *cconhash, const uint32_t tcid, const uint16_t replica, const UINT32 salt)
{
    uint64_t sid;
    uint32_t len;
    uint32_t hash;

    sid = ((((uint64_t)tcid) << 32) | (((uint64_t)replica) << 16) | (((uint64_t)salt) & 0xFFFF));
    len = 8; /*64bits*/
    hash = (uint32_t)CCONHASH_HASH_FUNC(cconhash)(len, (UINT8 *)&sid);

    return (hash);
}

EC_BOOL cconhash_add_vnode_replicas(CCONHASH *cconhash, const UINT32 cconhash_rnode_pos)
{
    CCONHASH_RNODE *cconhash_rnode;

    uint32_t        vnode_s_pos;  /*vnode start pos*/
    uint32_t        tcid;
    uint16_t        replica;

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);
    if(NULL_PTR == cconhash_rnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: "
                           "not found rnode at pos %ld\n",
                           cconhash_rnode_pos);
        return (EC_FALSE);
    }

    CCONHASH_ASSERT(0 == (cconhash_rnode_pos >> 16));

    /*save start pos*/
    vnode_s_pos = cconhash_vnodes_num(CCONHASH_VNODE_LIST(cconhash));

    tcid = CCONHASH_RNODE_TCID(cconhash_rnode);
    for(replica = 0; replica < CCONHASH_RNODE_REPLICAS(cconhash_rnode); replica ++)
    {
        CCONHASH_VNODE    *cconhash_vnode;
        uint32_t           hash;

        hash = __cconhash_hash_vnode(cconhash, tcid, replica, cconhash_rnode_pos);

        cconhash_vnode = cconhash_vnode_make(hash, (uint16_t)cconhash_rnode_pos);
        if(NULL_PTR == cconhash_vnode)
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: "
                               "make vnode (hash %u, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cconhash_rnode_pos);

            /*roll back*/
            cconhash_discard_vnodes(cconhash, vnode_s_pos);
            return (EC_FALSE);
        }

        if(EC_FALSE == cconhash_add_vnode(cconhash, cconhash_vnode))
        {
            dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_vnode_replicas: "
                               "add vnode (hash %u, tcid %s, replica %u, rnode pos %u) failed\n",
                               hash, c_word_to_ipv4(tcid), replica, (uint16_t)cconhash_rnode_pos);

            /*roll back*/
            cconhash_discard_vnodes(cconhash, vnode_s_pos);
            cconhash_vnode_free(cconhash_vnode);
            return (EC_FALSE);
        }

        dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_add_vnode_replicas: "
                           "add vnode (hash %u, tcid %s, replica %u, rnode pos %u) done\n",
                           hash, c_word_to_ipv4(tcid), replica, (uint16_t)cconhash_rnode_pos);
    }

    if(0 < replica)
    {
        return cconhash_sort_vnodes(cconhash);
    }

    return (EC_TRUE);
}

EC_BOOL cconhash_del_vnode_replicas(CCONHASH *cconhash, const UINT32 cconhash_rnode_pos)
{
    return cconhash_del_vnodes(cconhash, cconhash_rnode_pos);
}

EC_BOOL cconhash_add_node(CCONHASH *cconhash, const uint32_t tcid, const uint16_t replicas)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    CCONHASH_RNODE *cconhash_rnode;
    UINT32          cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                             (void *)&cconhash_rnode_t,
                                             (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS != cconhash_rnode_pos)
    {
        cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: "
                          "found rnode (tcid %s, replicas %u, status %s)\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    cconhash_rnode = cconhash_rnode_make(tcid, replicas);
    if(NULL_PTR == cconhash_rnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: "
                           "make rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(tcid), replicas);
        return (EC_FALSE);
    }

    /*add rnode*/
    cconhash_rnode_pos = cconhash_add_rnode(cconhash, cconhash_rnode);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: "
                           "add rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));

        cconhash_rnode_free(cconhash_rnode);
        return (EC_FALSE);
    }

    CCONHASH_ASSERT(0 == (cconhash_rnode_pos >> 16));

#if 1
    /*add vnode replicas*/
    if(EC_FALSE == cconhash_add_vnode_replicas(cconhash, cconhash_rnode_pos))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_add_node: "
                           "add vnode replicas of rnode (tcid %s, replicas %u) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode));

        cvector_set(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos, NULL_PTR);
        cconhash_rnode_free(cconhash_rnode);
        return (EC_FALSE);
    }
#endif

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_add_node: "
                       "rnode (tcid %s, replicas %u, status %s) add => OK\n",
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
    UINT32          cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "[DEBUG] cconhash_del_node: "
                           "not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_TRUE);
    }

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

    CCONHASH_ASSERT(0 == (cconhash_rnode_pos >> 16));

    /*del vnode replicas*/
    if(EC_FALSE == cconhash_del_vnode_replicas(cconhash, cconhash_rnode_pos))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_del_node: "
                          "del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_del_node: "
                       "rnode (tcid %s, replicas %u, status %s) del => OK\n",
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
    UINT32          cconhash_rnode_pos;

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

    CCONHASH_ASSERT(0 == (cconhash_rnode_pos >> 16));

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

    if(CCONHASH_RNODE_IS_UP == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_up_node: "
                           "rnode (tcid %s, replicas %u, status %s) is already up\n",
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
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_up_node: "
                           "rnode (tcid %s, replicas %u, status %s) has invalid replica\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    /*add vnode replicas*/
    if(EC_FALSE == cconhash_add_vnode_replicas(cconhash, cconhash_rnode_pos))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_up_node: "
                           "add vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));

        return (EC_FALSE);
    }

    CCONHASH_RNODE_STATUS(cconhash_rnode) = CCONHASH_RNODE_IS_UP; /*set up*/

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_up_node: "
                       "rnode (tcid %s, replicas %u, status %s) set up => OK\n",
                       c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                       CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                       cconhash_rnode_status(cconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL cconhash_down_node(CCONHASH *cconhash, const uint32_t tcid)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    CCONHASH_RNODE *cconhash_rnode;
    UINT32          cconhash_rnode_pos;

    CCONHASH_RNODE_TCID(&cconhash_rnode_t) = tcid;
    cconhash_rnode_pos = cvector_search_front(CCONHASH_RNODE_VEC(cconhash),
                                                 (void *)&cconhash_rnode_t,
                                                 (CVECTOR_DATA_CMP)cconhash_rnode_cmp_tcid);
    if(CVECTOR_ERR_POS == cconhash_rnode_pos)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_down_node: "
                           "not found rnode with tcid %s\n",
                           c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    CCONHASH_ASSERT(0 == (cconhash_rnode_pos >> 16));

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash), cconhash_rnode_pos);

    if(CCONHASH_RNODE_IS_DOWN == CCONHASH_RNODE_STATUS(cconhash_rnode))
    {
        dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_down_node: "
                           "rnode (tcid %s, replicas %u, status %s) is already down\n",
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
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_down_node: "
                           "del vnode replicas of rnode (tcid %s, replicas %u, status %s) failed\n",
                           c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                           CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                           cconhash_rnode_status(cconhash_rnode));
        return (EC_FALSE);
    }

    CCONHASH_RNODE_STATUS(cconhash_rnode) = CCONHASH_RNODE_IS_DOWN; /*set down*/

    dbg_log(SEC_0050_CCONHASH, 9)(LOGSTDOUT, "[DEBUG] cconhash_down_node: "
                       "rnode (tcid %s, replicas %u, status %s) set down => OK\n",
                       c_word_to_ipv4(CCONHASH_RNODE_TCID(cconhash_rnode)),
                       CCONHASH_RNODE_REPLICAS(cconhash_rnode),
                       cconhash_rnode_status(cconhash_rnode));

    return (EC_TRUE);
}

EC_BOOL cconhash_has_node(const CCONHASH *cconhash, const uint32_t tcid)
{
    CCONHASH_RNODE  cconhash_rnode_t;
    UINT32          cconhash_rnode_pos;

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
    UINT32          cconhash_rnode_pos;

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
    CCONHASH_VNODE *cconhash_vnode;
    CCONHASH_RNODE *cconhash_rnode;

    if(EC_TRUE == cconhash_vnodes_is_empty(CCONHASH_VNODE_LIST(cconhash)))
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_lookup_rnode: vnode list is empty\n");
        return (NULL_PTR);
    }

    cconhash_vnode = cconhash_vnodes_lookup(CCONHASH_VNODE_LIST(cconhash), hash);
    if(NULL_PTR == cconhash_vnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_lookup_rnode: "
                           "hash %u, should never reach here due to vnodes are circled\n",
                           hash);
        return (NULL_PTR);
    }


    if(do_log(SEC_0050_CCONHASH, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cconhash_lookup_rnode: hash %u => vnode \n", hash);
        cconhash_vnode_print(LOGSTDOUT, cconhash_vnode);
    }

    cconhash_rnode = (CCONHASH_RNODE *)cvector_get(CCONHASH_RNODE_VEC(cconhash),
                                                         CCONHASH_VNODE_POS(cconhash_vnode));
    if(NULL_PTR == cconhash_rnode)
    {
        dbg_log(SEC_0050_CCONHASH, 0)(LOGSTDOUT, "error:cconhash_lookup_rnode: "
                           "hash %u, rnode_pos %u, should never reach here due to rnode not existing\n",
                           hash, CCONHASH_VNODE_POS(cconhash_vnode));
        return (NULL_PTR);
    }
    return (cconhash_rnode);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

