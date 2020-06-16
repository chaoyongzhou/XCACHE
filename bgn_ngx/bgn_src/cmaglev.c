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

#include "chashalgo.h"

#include "cvector.h"
#include "cmaglev.h"

CMAGLEV *cmaglev_new()
{
    CMAGLEV *cmaglev;

    alloc_static_mem(MM_CMAGLEV, &cmaglev, LOC_CMAGLEV_0001);

    if (NULL_PTR == cmaglev)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_new: "
                                                "alloc cmaglev failed\n");

        return (NULL_PTR);
    }

    if (EC_FALSE == cmaglev_init(cmaglev))
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_new: "
                                                "init cmaglev failed\n");

        cmaglev_free(cmaglev);
        return (NULL_PTR);
    }

    return cmaglev;
}

EC_BOOL cmaglev_init(CMAGLEV *cmaglev)
{
    if (NULL_PTR != cmaglev)
    {
        CMAGLEV_RING_SIZE(cmaglev) = CMAGLEV_MIN_RING_SIZE;

        cvector_init(CMAGLEV_RNODE_VEC(cmaglev), CMAGLEV_MAX_NEXT_SIZE,
                        MM_CMAGLEV_RNODE, CVECTOR_LOCK_ENABLE, LOC_CMAGLEV_0002);

        if (EC_FALSE == cmaglev_qnode_make(CMAGLEV_QNODE_ITEM(cmaglev),
                                    CMAGLEV_RING_SIZE(cmaglev), CMAGLEV_MAX_NEXT_SIZE))
        {
            cmaglev_qnode_clean(CMAGLEV_QNODE_ITEM(cmaglev));

            return (EC_FALSE);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cmaglev_clean(CMAGLEV *cmaglev)
{
    if (NULL_PTR != cmaglev)
    {
        CMAGLEV_RING_SIZE(cmaglev) = 0;

        cvector_clean(CMAGLEV_RNODE_VEC(cmaglev),
                        (CVECTOR_DATA_CLEANER)cmaglev_rnode_free, LOC_CMAGLEV_0009);

        cmaglev_qnode_clean(CMAGLEV_QNODE_ITEM(cmaglev));
    }

    return (EC_TRUE);
}

EC_BOOL cmaglev_free(CMAGLEV *cmaglev)
{
    if (NULL_PTR != cmaglev)
    {
        cmaglev_clean(cmaglev);
    }

    return (EC_TRUE);
}

CMAGLEV_QNODE *cmaglev_qnode_new()
{
    CMAGLEV_QNODE *qnode;

    alloc_static_mem(MM_CMAGLEV_QNODE, &qnode, LOC_CMAGLEV_0009);
    if (NULL_PTR == qnode)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_qnode_new: "
                                                "alloc qnode failed\n");

        return (NULL_PTR);
    }

    if (EC_FALSE == cmaglev_qnode_init(qnode))
    {
        free_static_mem(MM_CMAGLEV_QNODE, qnode, LOC_CMAGLEV_0011);
        return (NULL_PTR);
    }

    return (qnode);
}

EC_BOOL cmaglev_qnode_init(CMAGLEV_QNODE *qnode)
{
    if (NULL_PTR != qnode)
    {
        CMAGLEV_QNODE_ENTRY(qnode)       = NULL_PTR;
        CMAGLEV_QNODE_NEXT(qnode)        = NULL_PTR;
        CMAGLEV_QNODE_PERMUTATION(qnode) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cmaglev_qnode_clean(CMAGLEV_QNODE *qnode)
{
    if (NULL_PTR != qnode)
    {
        if (NULL_PTR != CMAGLEV_QNODE_ENTRY(qnode))
        {
            safe_free(CMAGLEV_QNODE_ENTRY(qnode), LOC_CMAGLEV_0007);
            CMAGLEV_QNODE_ENTRY(qnode) = NULL_PTR;
        }

        if (NULL_PTR != CMAGLEV_QNODE_NEXT(qnode))
        {
            safe_free(CMAGLEV_QNODE_NEXT(qnode), LOC_CMAGLEV_0007);
            CMAGLEV_QNODE_NEXT(qnode) = NULL_PTR;
        }

        if (NULL_PTR != CMAGLEV_QNODE_PERMUTATION(qnode))
        {
            safe_free(CMAGLEV_QNODE_NEXT(qnode), LOC_CMAGLEV_0007);
            CMAGLEV_QNODE_PERMUTATION(qnode) = NULL_PTR;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cmaglev_qnode_free(CMAGLEV_QNODE *qnode)
{
    if (NULL_PTR != qnode)
    {
        cmaglev_qnode_clean(qnode);
    }

    return (EC_TRUE);
}

EC_BOOL cmaglev_qnode_make(CMAGLEV_QNODE *qnode, const UINT32 ring_size, const UINT32 next_size)
{
    if (NULL_PTR != qnode)
    {
        UINT32      size;

        size = ring_size * next_size * sizeof(int);
        CMAGLEV_QNODE_ENTRY(qnode) = (int *)safe_malloc(size, LOC_CMAGLEV_0003);
        if (NULL_PTR == CMAGLEV_QNODE_ENTRY(qnode))
        {
            return (EC_FALSE);
        }

        size = next_size * sizeof(UINT32);
        CMAGLEV_QNODE_NEXT(qnode) = (UINT32 *)safe_malloc(size, LOC_CMAGLEV_0004);
        if (NULL_PTR == CMAGLEV_QNODE_NEXT(qnode))
        {
            return (EC_FALSE);
        }

        size = next_size * ring_size * sizeof(UINT32) * 2;
        CMAGLEV_QNODE_PERMUTATION(qnode) = (UINT32 *)safe_malloc(size, LOC_CMAGLEV_0005);
        if (NULL_PTR == CMAGLEV_QNODE_PERMUTATION(qnode))
        {
            return (EC_FALSE);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}


CMAGLEV_RNODE *cmaglev_rnode_new()
{
    CMAGLEV_RNODE *cmaglev_rnode;

    alloc_static_mem(MM_CMAGLEV_RNODE, &cmaglev_rnode, LOC_CMAGLEV_0009);
    if (NULL_PTR == cmaglev_rnode)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_rnode_new: "
                                                "alloc rnode failed\n");

        return (NULL_PTR);
    }

    if (EC_FALSE == cmaglev_rnode_init(cmaglev_rnode))
    {
        free_static_mem(MM_CMAGLEV_RNODE, cmaglev_rnode, LOC_CMAGLEV_0011);
        return NULL_PTR;
    }

    return cmaglev_rnode;
}

EC_BOOL cmaglev_rnode_init(CMAGLEV_RNODE *cmaglev_rnode)
{
    if (NULL_PTR != cmaglev_rnode)
    {
        CMAGLEV_RNODE_STATUS(cmaglev_rnode) = CMAGLEV_RNODE_IS_ERR;
        CMAGLEV_RNODE_TCID(cmaglev_rnode)   = (uint32_t)CMPI_ERROR_TCID;
    }

    return (EC_TRUE);
}

EC_BOOL cmaglev_rnode_clean(CMAGLEV_RNODE *cmaglev_rnode)
{
    if (NULL_PTR != cmaglev_rnode)
    {
        CMAGLEV_RNODE_STATUS(cmaglev_rnode) = CMAGLEV_RNODE_IS_ERR;
        CMAGLEV_RNODE_TCID(cmaglev_rnode)   = (uint32_t)CMPI_ERROR_TCID;
    }

    return (EC_TRUE);
}

EC_BOOL cmaglev_rnode_free(CMAGLEV_RNODE *cmaglev_rnode)
{
    if(NULL_PTR != cmaglev_rnode)
    {
        cmaglev_rnode_clean(cmaglev_rnode);
        free_static_mem(MM_CMAGLEV_RNODE, cmaglev_rnode, LOC_CMAGLEV_0011);
    }

    return (EC_TRUE);
}

CMAGLEV_RNODE *cmaglev_rnode_make(const uint32_t tcid)
{
    CMAGLEV_RNODE *cmaglev_rnode;

    alloc_static_mem(MM_CMAGLEV_RNODE, &cmaglev_rnode, LOC_CMAGLEV_0010);
    if (NULL_PTR == cmaglev_rnode)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_rnode_make: "
                                                "alloc rnode failed\n");

        return (NULL_PTR);
    }

    CMAGLEV_RNODE_STATUS(cmaglev_rnode) = CMAGLEV_RNODE_IS_UP;
    CMAGLEV_RNODE_TCID(cmaglev_rnode)   = tcid;

    return (cmaglev_rnode);
}

const char *cmaglev_rnode_status(const CMAGLEV_RNODE *cmaglev_rnode)
{
    if (NULL_PTR == cmaglev_rnode)
    {
        return (const char *)"UNKOWN";
    }

    if (CMAGLEV_RNODE_IS_UP == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
    {
        return (const char *)"UP";
    }

    if (CMAGLEV_RNODE_IS_DOWN == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
    {
        return (const char *)"DOWN";
    }

    if (CMAGLEV_RNODE_IS_ERR == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
    {
        return (const char *)"ERR";
    }

    return (const char *)"UNKOWN";
}

EC_BOOL cmaglev_rnode_is_up(const CMAGLEV_RNODE *cmaglev_rnode)
{
    if (NULL_PTR == cmaglev_rnode)
    {
        return (EC_FALSE);
    }

    if (CMAGLEV_RNODE_IS_UP == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void cmaglev_rnode_print(LOG *log, const CMAGLEV_RNODE *cmaglev_rnode)
{
    if (NULL_PTR != cmaglev_rnode)
    {
        sys_log(log, "cmaglev_rnode %p: "
                     "tcid %s, status %u\n",
                     cmaglev_rnode,
                     c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)),
                     CMAGLEV_RNODE_STATUS(cmaglev_rnode));
    }

    return;
}

EC_BOOL cmaglev_rnode_cmp_tcid(const CMAGLEV_RNODE *cmaglev_rnode_1st, const CMAGLEV_RNODE *cmaglev_rnode_2nd)
{
    if(NULL_PTR == cmaglev_rnode_1st && NULL_PTR == cmaglev_rnode_2nd)
    {
        return (EC_TRUE);
    }

    if (NULL_PTR == cmaglev_rnode_1st || NULL_PTR == cmaglev_rnode_2nd)
    {
        return (EC_FALSE);
    }

    if (CMAGLEV_RNODE_TCID(cmaglev_rnode_1st) != CMAGLEV_RNODE_TCID(cmaglev_rnode_2nd))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cmaglev_add_node(CMAGLEV *cmaglev, const uint32_t tcid)
{
    CMAGLEV_RNODE  cmaglev_rnode_t;
    CMAGLEV_RNODE *cmaglev_rnode;
    UINT32         pos;

    CMAGLEV_RNODE_TCID(&cmaglev_rnode_t) = tcid;
    pos = cvector_search_front(CMAGLEV_RNODE_VEC(cmaglev), (void *)&cmaglev_rnode_t,
                               (CVECTOR_DATA_CMP)cmaglev_rnode_cmp_tcid);

    if (CVECTOR_ERR_POS != pos)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_add_node: "
                            "found duplicate rnode (tcid %s)\n",
                            c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    /* alloc memory for new cmaglev_rnode */
    cmaglev_rnode = cmaglev_rnode_make(tcid);
    if (NULL_PTR == cmaglev_rnode)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_add_node: "
                            "make rnode (tcid %s) failed\n",
                            c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_add_node: "
                            "make rnode succ (tcid %s)\n",
                            c_word_to_ipv4(tcid));

    /* push new cmaglev_rnode to cmaglev_rnode vector */
    pos = cmaglev_add_rnode(cmaglev, cmaglev_rnode);
    if (CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_add_node: "
                           "add rnode (tcid %s, status %u) failed\n",
                           c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)),
                           CMAGLEV_RNODE_STATUS(cmaglev_rnode));

        cmaglev_rnode_free(cmaglev_rnode);
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_add_rnode: "
                         "add rnode (tcid %s) succ \n",
                         c_word_to_ipv4(tcid));

    return (EC_TRUE);
}

EC_BOOL cmaglev_del_node(CMAGLEV *cmaglev, const uint32_t tcid)
{
    CMAGLEV_RNODE  cmaglev_rnode_t;
    CMAGLEV_RNODE *cmaglev_rnode;
    UINT32         pos;

    CMAGLEV_RNODE_TCID(&cmaglev_rnode_t) = tcid;
    pos = cvector_search_front(CMAGLEV_RNODE_VEC(cmaglev), (void *)&cmaglev_rnode_t,
                               (CVECTOR_DATA_CMP)cmaglev_rnode_cmp_tcid);

    if (CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "[DEBUG] cmaglev_del_node: "
                            "not found rnode (tcid %s)\n",
                            c_word_to_ipv4(tcid));
        return (EC_TRUE);
    }

    cmaglev_rnode = (CMAGLEV_RNODE *)cvector_get(CMAGLEV_RNODE_VEC(cmaglev), pos);
    if (NULL_PTR == cmaglev_rnode)
    {
        return (EC_FALSE);
    }

    ASSERT(0 == (pos >> 16));

    /* free qnode in item*/
    cvector_set(CMAGLEV_RNODE_VEC(cmaglev), pos, NULL_PTR);
    cmaglev_rnode_free(cmaglev_rnode);

    return (EC_TRUE);
}

EC_BOOL cmaglev_up_node(CMAGLEV *cmaglev, const uint32_t tcid)
{
    CMAGLEV_RNODE  cmaglev_rnode_t;
    CMAGLEV_RNODE *cmaglev_rnode;
    UINT32         pos;

    CMAGLEV_RNODE_TCID(&cmaglev_rnode_t) = tcid;
    pos = cvector_search_front(CMAGLEV_RNODE_VEC(cmaglev), (void *)&cmaglev_rnode_t,
                               (CVECTOR_DATA_CMP)cmaglev_rnode_cmp_tcid);

    if (CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_up_node: "
                            "not found rnode with tcid %s\n",
                            c_word_to_ipv4(tcid));
        return (EC_FALSE);
    }

    ASSERT(0 == (pos >> 16));

    cmaglev_rnode = (CMAGLEV_RNODE *)cvector_get(CMAGLEV_RNODE_VEC(cmaglev), pos);

    if (CMAGLEV_RNODE_IS_UP == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
    {
        dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_up_node: "
                        "rnode (tcid %s) is already up\n",
                        c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)));
        return (EC_TRUE);
    }

    CMAGLEV_RNODE_STATUS(cmaglev_rnode) = CMAGLEV_RNODE_IS_UP; /*set up*/

    /*regenerate maglev-hash*/
    if (EC_FALSE == cmaglev_hash(cmaglev))
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_up_node: "
                        "reset maglev-hash(tcid %s) failed\n",
                        c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_up_node: "
                        "rnode (tcid %s) set down => OK\n",
                        c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)));

    return (EC_TRUE);

}

EC_BOOL cmaglev_down_node(CMAGLEV *cmaglev, const uint32_t tcid)
{
    CMAGLEV_RNODE   cmaglev_rnode_t;
    CMAGLEV_RNODE  *cmaglev_rnode;
    UINT32          pos;

    CMAGLEV_RNODE_TCID(&cmaglev_rnode_t) = tcid;
    pos = cvector_search_front(CMAGLEV_RNODE_VEC(cmaglev), (void *)&cmaglev_rnode_t,
                               (CVECTOR_DATA_CMP)cmaglev_rnode_cmp_tcid);

    if (CVECTOR_ERR_POS == pos)
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_down_node: "
                            "not found rnode with tcid %s\n",
                            c_word_to_ipv4(tcid));

        return (EC_FALSE);
    }

    ASSERT(0 == (pos >> 16));

    cmaglev_rnode = (CMAGLEV_RNODE *)cvector_get(CMAGLEV_RNODE_VEC(cmaglev), pos);

    if (CMAGLEV_RNODE_IS_DOWN == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
    {
        dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_down_node: "
                            "rnode (tcid %s, status %u) is already down\n",
                            c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)),
                            CMAGLEV_RNODE_STATUS(cmaglev_rnode));
        return (EC_TRUE);
    }

    CMAGLEV_RNODE_STATUS(cmaglev_rnode) = CMAGLEV_RNODE_IS_DOWN; /*set down*/

    /*regenerate maglev-hash*/
    if (EC_FALSE == cmaglev_hash(cmaglev))
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_down_node: "
                           "reset maglev-hash(tcid %s) failed\n",
                           c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_down_node: "
                       "rnode (tcid %s) set down => OK\n",
                       c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)));

    return (EC_TRUE);
}

UINT32 cmaglev_add_rnode(CMAGLEV *cmaglev, const CMAGLEV_RNODE *rnode)
{
    return cvector_add(CMAGLEV_RNODE_VEC(cmaglev), (void *)rnode);
}

UINT32 cmaglev_count_rnode(CMAGLEV *cmaglev)
{
    return cvector_size(CMAGLEV_RNODE_VEC(cmaglev));
}

void cmaglev_permutation(UINT32 *permutation, UINT32 *tcid, UINT32 pos, UINT32 ring_size)
{
    UINT32 offset;
    UINT32 skip;

    ASSERT(1 < ring_size);

    offset = MURMUR_hash(4, (UINT8 *)tcid) % ring_size;
    skip   = DJB_hash(4, (UINT8 *)tcid) % (ring_size - 1) + 1;

    permutation[2 * pos    ] = offset;
    permutation[2 * pos + 1] = skip;

    return;
}

void cmaglev_populate(CMAGLEV *cmaglev, UINT32 ring_size)
{
    CMAGLEV_RNODE   *cmaglev_rnode;
    CMAGLEV_QNODE   *cmaglev_qnode;

    UINT32           offset;
    UINT32           skip;
    UINT32           cur;

    UINT32           runs;
    UINT32           up_index;
    UINT32           pos;

    cmaglev_qnode = CMAGLEV_QNODE_ITEM(cmaglev);

    runs = 0;

    while(1)
    {
        up_index = 0;
        for (pos = 0; pos < cvector_size(CMAGLEV_RNODE_VEC(cmaglev)); pos ++)
        {
            cmaglev_rnode = (CMAGLEV_RNODE *)cvector_get(CMAGLEV_RNODE_VEC(cmaglev), pos);
            if(NULL_PTR == cmaglev_rnode
            || CMAGLEV_RNODE_IS_UP != CMAGLEV_RNODE_STATUS(cmaglev_rnode))
            {
                continue;
            }

            offset = CMAGLEV_QNODE_PERMUTATION(cmaglev_qnode)[2 * up_index    ];
            skip   = CMAGLEV_QNODE_PERMUTATION(cmaglev_qnode)[2 * up_index + 1];

            cur = (offset + CMAGLEV_QNODE_NEXT(cmaglev_qnode)[ up_index ] * skip) % ring_size;

            while (CMAGLEV_QNODE_ENTRY(cmaglev_qnode)[cur] >= 0 && runs < ring_size)
            {
                CMAGLEV_QNODE_NEXT(cmaglev_qnode)[ up_index ] += 1;
                cur = (offset + CMAGLEV_QNODE_NEXT(cmaglev_qnode)[ up_index ] * skip) % ring_size;
            }

            CMAGLEV_QNODE_ENTRY(cmaglev_qnode)[ cur ] = pos;
            CMAGLEV_QNODE_NEXT(cmaglev_qnode)[ up_index ] += 1;

            runs ++;
            up_index ++;

            if (runs >= ring_size)
            {
                return;
            }
        }
    }

    return;
}

EC_BOOL cmaglev_hash(CMAGLEV *cmaglev)
{
    UINT32           ring_size;
    CMAGLEV_QNODE   *cmaglev_qnode;
    CMAGLEV_RNODE   *cmaglev_rnode;

    UINT32           up_num;
    UINT32           up_index;
    UINT32           vec_size;
    UINT32           pos;

    cmaglev_qnode = CMAGLEV_QNODE_ITEM(cmaglev);

    vec_size  = cvector_size(CMAGLEV_RNODE_VEC(cmaglev));
    ring_size = CMAGLEV_RING_SIZE(cmaglev);

    memset(CMAGLEV_QNODE_ENTRY(cmaglev_qnode), 0, vec_size * sizeof(int));
    memset(CMAGLEV_QNODE_NEXT(cmaglev_qnode),  0, vec_size * sizeof(UINT32));
    memset(CMAGLEV_QNODE_PERMUTATION(cmaglev_qnode), 0,
                        ring_size  * vec_size * sizeof(UINT32) * 2);

    up_num = 0;

    /* find up node number in cmaglev_rnode_vec */
    for (pos = 0; pos < vec_size; pos ++)
    {
        cmaglev_rnode = (CMAGLEV_RNODE *)cvector_get(CMAGLEV_RNODE_VEC(cmaglev), pos);
        if (NULL_PTR != cmaglev_rnode
        && CMAGLEV_RNODE_IS_UP == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
        {
            dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_hash:"
                                "%ld up, tcid: %s\n",
                                pos,
                                c_word_to_ipv4(CMAGLEV_RNODE_TCID(cmaglev_rnode)));
            up_num ++;
        }
    }

    up_index = 0;

    /* permutation */
    for (pos = 0; pos < vec_size; pos ++)
    {
        cmaglev_rnode = (CMAGLEV_RNODE *)cvector_get(CMAGLEV_RNODE_VEC(cmaglev), pos);

        if (NULL_PTR != cmaglev_rnode
        && CMAGLEV_RNODE_IS_UP == CMAGLEV_RNODE_STATUS(cmaglev_rnode))
        {
            cmaglev_permutation(CMAGLEV_QNODE_PERMUTATION(cmaglev_qnode),
                                (UINT32 *)(&(CMAGLEV_RNODE_TCID(cmaglev_rnode))),
                                up_index, ring_size);
            up_index++;
        }
    }

    /* populate */
    for (pos = 0; pos < up_num; pos++)
    {
         CMAGLEV_QNODE_NEXT(cmaglev_qnode)[pos] = 0;
    }

    for (pos = 0; pos < CMAGLEV_RING_SIZE(cmaglev); pos++)
    {
         CMAGLEV_QNODE_ENTRY(cmaglev_qnode)[pos] = -1;
    }

    cmaglev_populate(cmaglev, ring_size);

    return (EC_TRUE);
}

CMAGLEV_RNODE *cmaglev_lookup_rnode(CMAGLEV *cmaglev, const uint32_t hash)
{
    CMAGLEV_QNODE *cmaglev_qnode;
    CMAGLEV_RNODE *cmaglev_rnode;

    UINT32         cur;
    UINT32         pos;

    cmaglev_qnode  = CMAGLEV_QNODE_ITEM(cmaglev);

    if (NULL_PTR == CMAGLEV_QNODE_ENTRY(cmaglev_qnode))
    {
        dbg_log(SEC_0174_CMAGLEV, 0)(LOGSTDOUT, "error:cmaglev_lookup_rnode: "
                            "qnode entry is empty\n");
        return (NULL_PTR);
    }

    cur = hash % CMAGLEV_RING_SIZE(cmaglev);
    pos = CMAGLEV_QNODE_ENTRY(cmaglev_qnode)[cur];

    dbg_log(SEC_0174_CMAGLEV, 9)(LOGSTDOUT, "[DEBUG] cmaglev_lookup_rnode: "
                         "hash: %u, cur: %ld, pos: %ld, ring_size: %ld\n",
                         hash, cur, pos, CMAGLEV_RING_SIZE(cmaglev));

    cmaglev_rnode = (CMAGLEV_RNODE *)cvector_get(CMAGLEV_RNODE_VEC(cmaglev), pos);

    return (cmaglev_rnode);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

