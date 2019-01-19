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

#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "task.h"
#include "cepoll.h"
#include "coroutine.h"
#include "camd.h"

#if (SWITCH_ON == CAMD_ASSERT_SWITCH)
#define CAMD_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CAMD_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CAMD_ASSERT_SWITCH)
#define CAMD_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CAMD_ASSERT_SWITCH)*/

#if 0
#define CAMD_CRC32(data, len)   c_crc32_long((data), (len))
#else
#define CAMD_CRC32(data, len)   0
#endif

STATIC_CAST const char *__camd_op_str(const UINT32 op)
{
    if(CAMD_OP_RD == op)
    {
        return ((const char *)"RD");
    }

    if(CAMD_OP_WR == op)
    {
        return ((const char *)"WR");
    }

    if(CAMD_OP_RW == op)
    {
        return ((const char *)"RW");
    }

    if(CAMD_OP_ERR == op)
    {
        return ((const char *)"ERR");
    }

    return ((const char *)"UNKNOWN");
}


/*----------------------------------- camd mem cache (posix memalign) interface -----------------------------------*/
static UINT32 g_camd_mem_cache_counter = 0;
STATIC_CAST static UINT8 *__camd_mem_cache_new(const UINT32 size)
{
    if(g_camd_mem_cache_counter < CAMD_MEM_CACHE_MAX_NUM)
    {
        UINT8    *mem_cache;

        mem_cache = (UINT8 *)c_memalign_new(size, CAMD_MEM_CACHE_ALIGN_SIZE_NBYTES);
        if(NULL_PTR == mem_cache)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:__camd_mem_cache_new: alloc memory failed\n");

            return (NULL_PTR);
        }

        rlog(SEC_0125_CAMD, 8)(LOGSTDOUT, "[DEBUG] __camd_mem_cache_new: mem_cache = %p\n", mem_cache);
        g_camd_mem_cache_counter ++;
        return (mem_cache);
    }

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:__camd_mem_cache_new: counter %ld reached max\n",
                                         g_camd_mem_cache_counter);

    return (NULL_PTR);
}

STATIC_CAST static EC_BOOL __camd_mem_cache_free(UINT8 *mem_cache)
{
    if(NULL_PTR != mem_cache)
    {
        rlog(SEC_0125_CAMD, 8)(LOGSTDOUT, "[DEBUG] __camd_mem_cache_free: mem_cache = %p\n", mem_cache);
        c_memalign_free(mem_cache);
        g_camd_mem_cache_counter --;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_mem_cache_check(UINT8 *mem_cache)
{
    UINT32      addr;
    UINT32      mask;

    addr = ((UINT32)mem_cache);
    mask = (CAMD_MEM_CACHE_ALIGN_SIZE_NBYTES - 1);

    if(0 == (addr & mask))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void camd_mem_cache_counter_print(LOG *log)
{
    sys_log(log, "g_camd_mem_cache_counter: %ld\n", g_camd_mem_cache_counter);
}

/*----------------------------------- camd page interface -----------------------------------*/

CAMD_PAGE *camd_page_new()
{
    CAMD_PAGE *camd_page;

    alloc_static_mem(MM_CAMD_PAGE, &camd_page, LOC_CAMD_0001);
    if(NULL_PTR == camd_page)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    camd_page_init(camd_page);
    return (camd_page);
}

EC_BOOL camd_page_init(CAMD_PAGE *camd_page)
{
    CAMD_PAGE_FD(camd_page)                 = ERR_FD;

    CAMD_PAGE_F_S_OFFSET(camd_page)         = 0;
    CAMD_PAGE_F_E_OFFSET(camd_page)         = 0;

    CAMD_PAGE_F_T_OFFSET(camd_page)         = 0;

    CAMD_PAGE_OP(camd_page)                 = CAMD_OP_ERR;

    CAMD_PAGE_TIMEOUT_NSEC(camd_page)       = 0;

    CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)     = BIT_FALSE;
    CAMD_PAGE_SSD_LOADED_FLAG(camd_page)    = BIT_FALSE;
    CAMD_PAGE_SSD_LOADING_FLAG(camd_page)   = BIT_FALSE;

    CAMD_PAGE_SATA_DIRTY_FLAG(camd_page)    = BIT_FALSE;
    CAMD_PAGE_SATA_LOADED_FLAG(camd_page)   = BIT_FALSE;
    CAMD_PAGE_SATA_LOADING_FLAG(camd_page)  = BIT_FALSE;

    CAMD_PAGE_MEM_FLUSHED_FLAG(camd_page)   = BIT_FALSE;
    CAMD_PAGE_MEM_CACHE_FLAG(camd_page)     = BIT_FALSE;

    CAMD_PAGE_M_CACHE(camd_page)            = NULL_PTR;

    CAMD_PAGE_CAMD_MD(camd_page)            = NULL_PTR;
    CAMD_PAGE_MOUNTED_PAGES(camd_page)      = NULL_PTR;
    CAMD_PAGE_MOUNTED_TREE_IDX(camd_page)   = CAMD_PAGE_TREE_IDX_ERR;

    clist_init(CAMD_PAGE_OWNERS(camd_page), MM_CAMD_NODE, LOC_CAMD_0002);

    return (EC_TRUE);
}

EC_BOOL camd_page_clean(CAMD_PAGE *camd_page)
{
    if(NULL_PTR != camd_page)
    {
        /*clean up owners*/
        camd_page_cleanup_nodes(camd_page);

        if(NULL_PTR != CAMD_PAGE_M_CACHE(camd_page))
        {
            if(BIT_FALSE == CAMD_PAGE_MEM_CACHE_FLAG(camd_page))
            {
                __camd_mem_cache_free(CAMD_PAGE_M_CACHE(camd_page));
            }

            CAMD_PAGE_M_CACHE(camd_page) = NULL_PTR;
        }

        if(NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page)
        && NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page)
        && CAMD_PAGE_TREE_IDX_ERR != CAMD_PAGE_MOUNTED_TREE_IDX(camd_page))
        {
            CAMD_MD     *camd_md;

            camd_md = CAMD_PAGE_CAMD_MD(camd_page);
            camd_del_page(camd_md, CAMD_PAGE_MOUNTED_TREE_IDX(camd_page), camd_page);
        }

        CAMD_PAGE_FD(camd_page)                 = ERR_FD;

        CAMD_PAGE_F_S_OFFSET(camd_page)         = 0;
        CAMD_PAGE_F_E_OFFSET(camd_page)         = 0;

        CAMD_PAGE_F_T_OFFSET(camd_page)         = 0;

        CAMD_PAGE_OP(camd_page)                 = CAMD_OP_ERR;

        CAMD_PAGE_TIMEOUT_NSEC(camd_page)       = 0;

        CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)     = BIT_FALSE;
        CAMD_PAGE_SSD_LOADED_FLAG(camd_page)    = BIT_FALSE;
        CAMD_PAGE_SSD_LOADING_FLAG(camd_page)   = BIT_FALSE;

        CAMD_PAGE_SATA_DIRTY_FLAG(camd_page)    = BIT_FALSE;
        CAMD_PAGE_SATA_LOADED_FLAG(camd_page)   = BIT_FALSE;
        CAMD_PAGE_SATA_LOADING_FLAG(camd_page)  = BIT_FALSE;

        CAMD_PAGE_MEM_FLUSHED_FLAG(camd_page)   = BIT_FALSE;
        CAMD_PAGE_MEM_CACHE_FLAG(camd_page)     = BIT_FALSE;

        CAMD_PAGE_CAMD_MD(camd_page)            = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL camd_page_free(CAMD_PAGE *camd_page)
{
    if(NULL_PTR != camd_page)
    {
        camd_page_clean(camd_page);
        free_static_mem(MM_CAMD_PAGE, camd_page, LOC_CAMD_0003);
    }
    return (EC_TRUE);
}

void camd_page_print(LOG *log, const CAMD_PAGE *camd_page)
{
    sys_log(log, "camd_page_print: camd_page %p: page range [%ld, %ld), "
                 "ssd dirty %u, ssd loaded %u, ssd loading %u, "
                 "sata dirty %u, sata loaded %u, sata loading %u, "
                 "mem flushed %u, mem cache page %u,"
                 "m_cache %p, mounted pages %p, mounted page tree %lx, "
                 "timeout %ld seconds\n",
                 camd_page,
                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                 CAMD_PAGE_SSD_DIRTY_FLAG(camd_page),
                 CAMD_PAGE_SSD_LOADED_FLAG(camd_page),
                 CAMD_PAGE_SSD_LOADING_FLAG(camd_page),
                 CAMD_PAGE_SATA_DIRTY_FLAG(camd_page),
                 CAMD_PAGE_SATA_LOADED_FLAG(camd_page),
                 CAMD_PAGE_SATA_LOADING_FLAG(camd_page),
                 CAMD_PAGE_MEM_FLUSHED_FLAG(camd_page),
                 CAMD_PAGE_MEM_CACHE_FLAG(camd_page),
                 CAMD_PAGE_M_CACHE(camd_page),
                 CAMD_PAGE_MOUNTED_PAGES(camd_page),
                 CAMD_PAGE_MOUNTED_TREE_IDX(camd_page),
                 CAMD_PAGE_TIMEOUT_NSEC(camd_page));

    sys_log(log, "camd_page_print: camd_page %p: owners:\n", camd_page);
    clist_print(log, CAMD_PAGE_OWNERS(camd_page), (CLIST_DATA_DATA_PRINT)camd_node_print);

    return;
}

int camd_page_cmp(const CAMD_PAGE *camd_page_1st, const CAMD_PAGE *camd_page_2nd)
{
    if(CAMD_PAGE_FD(camd_page_1st) == CAMD_PAGE_FD(camd_page_2nd))
    {
        if(CAMD_PAGE_F_E_OFFSET(camd_page_1st) <= CAMD_PAGE_F_S_OFFSET(camd_page_2nd))
        {
            return (-1);
        }

        if(CAMD_PAGE_F_S_OFFSET(camd_page_1st) >= CAMD_PAGE_F_E_OFFSET(camd_page_2nd))
        {
            return (1);
        }

        CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page_1st) == CAMD_PAGE_F_S_OFFSET(camd_page_2nd));
        CAMD_ASSERT(CAMD_PAGE_F_E_OFFSET(camd_page_1st) == CAMD_PAGE_F_E_OFFSET(camd_page_2nd));

        return (0);
    }

    if(CAMD_PAGE_FD(camd_page_1st) < CAMD_PAGE_FD(camd_page_2nd))
    {
        return (-1);
    }

    return (1);
}

EC_BOOL camd_page_add_node(CAMD_PAGE *camd_page, CAMD_NODE *camd_node)
{
    CAMD_ASSERT(NULL_PTR == CAMD_NODE_MOUNTED_OWNERS(camd_node));

    /*mount*/
    CAMD_NODE_MOUNTED_OWNERS(camd_node) = clist_push_back(CAMD_PAGE_OWNERS(camd_page), (void *)camd_node);
    if(NULL_PTR == CAMD_NODE_MOUNTED_OWNERS(camd_node))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_add_node: "
                         "add node %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                         "to page [%ld, %ld) failed\n",
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node),
                         CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                         CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                         __camd_op_str(CAMD_NODE_OP(camd_node)),
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        return (EC_FALSE);
    }

    CAMD_NODE_CAMD_PAGE(camd_node) = camd_page; /*bind*/

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_add_node: "
                     "add node %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "to page [%ld, %ld) done\n",
                     CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                     CAMD_NODE_SEQ_NO(camd_node),
                     CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                     CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                     __camd_op_str(CAMD_NODE_OP(camd_node)),
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    return (EC_TRUE);
}

EC_BOOL camd_page_del_node(CAMD_PAGE *camd_page, CAMD_NODE *camd_node)
{
    CAMD_ASSERT(NULL_PTR != CAMD_NODE_MOUNTED_OWNERS(camd_node));

    clist_erase(CAMD_PAGE_OWNERS(camd_page), CAMD_NODE_MOUNTED_OWNERS(camd_node));
    CAMD_NODE_MOUNTED_OWNERS(camd_node) = NULL_PTR; /*umount*/
    CAMD_NODE_CAMD_PAGE(camd_node)      = NULL_PTR; /*unbind*/

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_del_node: "
                     "del node %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "from page [%ld, %ld) done\n",
                     CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                     CAMD_NODE_SEQ_NO(camd_node),
                     CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                     CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                     __camd_op_str(CAMD_NODE_OP(camd_node)),
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    return (EC_TRUE);
}

EC_BOOL camd_page_cleanup_nodes(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    /*clean up owners*/
    while(NULL_PTR != (camd_node = camd_page_pop_node_back(camd_page)))
    {
        if(NULL_PTR != CAMD_NODE_CAMD_REQ(camd_node))
        {
            CAMD_REQ     *camd_req;

            camd_req = CAMD_NODE_CAMD_REQ(camd_node);

            CAMD_REQ_NODE_NUM(camd_req) --; /*dec*/

            /*update upper offset at most*/
            if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_E_OFFSET(camd_req))
            {
                CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
            }
        }

        camd_node_free(camd_node);
    }

    return (EC_TRUE);
}

CAMD_NODE *camd_page_pop_node_front(CAMD_PAGE *camd_page)
{
    CAMD_NODE *camd_node;

    camd_node = clist_pop_front(CAMD_PAGE_OWNERS(camd_page));
    if(NULL_PTR == camd_node)
    {
        return (NULL_PTR);
    }

    CAMD_NODE_MOUNTED_OWNERS(camd_node) = NULL_PTR; /*umount*/
    CAMD_NODE_CAMD_PAGE(camd_node)      = NULL_PTR; /*ubind*/

    return (camd_node);
}

CAMD_NODE *camd_page_pop_node_back(CAMD_PAGE *camd_page)
{
    CAMD_NODE *camd_node;

    camd_node = clist_pop_back(CAMD_PAGE_OWNERS(camd_page));
    if(NULL_PTR == camd_node)
    {
        return (NULL_PTR);
    }

    CAMD_NODE_MOUNTED_OWNERS(camd_node) = NULL_PTR; /*umount*/
    CAMD_NODE_CAMD_PAGE(camd_node)      = NULL_PTR; /*ubind*/

    return (camd_node);
}

EC_BOOL camd_page_timeout(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_timeout: "
                     "page [%ld, %ld) timeout\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_timeout(camd_node);
    }

    return (EC_TRUE);
}

EC_BOOL camd_page_terminate(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_terminate: "
                     "page [%ld, %ld) terminate\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_terminate(camd_node);
    }

    return (EC_TRUE);
}

EC_BOOL camd_page_complete(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_complete: "
                     "page [%ld, %ld) complete\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_complete(camd_node);
    }

    return (EC_TRUE);
}

/**
 * process when page is in mem cache
 *
 * note:
 *   camd_page_process calling path is not only
 *      scenario 1: camd_process -> camd_process_pages -> camd_process_page -> camd_page_process,
 *   but also
 *      scenario 2: caio_process -> camd_page_load_sata_aio_complete -> camd_page_process
                 or caio_process -> camd_page_load_ssd_aio_complete  -> camd_page_process
 *
 *   for scenario 1, camd_add_page called in camd_page_process would add page to standby tree,
 *   and then camd_process_pages switch active tree and standby tree,
 *   and then camd_req_dispatch_node search active tree to check page existing.
 *   everything is ok.
 *
 *   for scenario 2, camd_add_page called in camd_page_process would add page to standby tree,
 *   and nobody trigger camd_process_pages to switch active tree and standby tree,
 *   meanwhile if camd_req_dispatch_node search active tree to check page existing which is residing
 *   on standby tree, we would have 2 same pages in camd: one in active tree, the other in standby tree.
 *   this scenario should be prohibitted.
 *
 *   one solution is transfering the re-try page tree index to camd_page_process which would be used by
 *   camd_add_page.
 *
 *   for scenario 1, transfer the standby tree index
 *   for scenario 2, transfer the active tree index
 *
**/

EC_BOOL camd_page_process(CAMD_PAGE *camd_page, const UINT32 retry_page_tree_idx)
{
    CAMD_NODE       *camd_node;
    uint32_t         page_dirty_flag;

    page_dirty_flag = BIT_FALSE;/*init*/

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        if(CAMD_OP_RD == CAMD_NODE_OP(camd_node))
        {
            CAMD_ASSERT(NULL_PTR != CAMD_PAGE_M_CACHE(camd_page));

            if(NULL_PTR != CAMD_NODE_M_BUFF(camd_node))
            {
                dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                                "[RD] node %ld/%ld of req %ld, "
                                "copy from page [%ld, %ld) to app cache [%ld, %ld)\n",
                                CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                                CAMD_NODE_SEQ_NO(camd_node),
                                CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                                CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node));

                /*copy data from mem cache to application mem buff*/
                FCOPY(CAMD_PAGE_M_CACHE(camd_page) + CAMD_NODE_B_S_OFFSET(camd_node),
                      CAMD_NODE_M_BUFF(camd_node),
                      CAMD_NODE_B_E_OFFSET(camd_node) - CAMD_NODE_B_S_OFFSET(camd_node));
            }

            camd_node_complete(camd_node);
        }

        else if(CAMD_OP_WR == CAMD_NODE_OP(camd_node))
        {
            CAMD_ASSERT(NULL_PTR != CAMD_PAGE_M_CACHE(camd_page));
            CAMD_ASSERT(NULL_PTR != CAMD_NODE_M_BUFF(camd_node));

            dbg_log(SEC_0125_CAMD, 7)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                            "[WR] node %ld/%ld of req %ld, "
                            "copy from app [%ld, %ld) to page [%ld, %ld) [crc %u] \n",
                            CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                            CAMD_NODE_SEQ_NO(camd_node),
                            CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                            CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                            CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                      CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page))
                            );

            /*copy data from application mem buff to mem cache*/
            FCOPY(CAMD_NODE_M_BUFF(camd_node),
                  CAMD_PAGE_M_CACHE(camd_page) + CAMD_NODE_B_S_OFFSET(camd_node),
                  CAMD_NODE_B_E_OFFSET(camd_node) - CAMD_NODE_B_S_OFFSET(camd_node));

            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                            "[WR] node %ld/%ld of req %ld, "
                            "copy from app [%ld, %ld) to page [%ld, %ld) => [crc %u]\n",
                            CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                            CAMD_NODE_SEQ_NO(camd_node),
                            CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                            CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                            CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                      CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

            camd_node_complete(camd_node);

            page_dirty_flag = BIT_TRUE;
        }
        else
        {
            /*should never reach here*/
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                             "invalid op: node %ld/%ld of req %ld, "
                             "block range [%ld, %ld), file range [%ld, %ld) op %s "
                             "in page [%ld, %ld)\n",
                             CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                             CAMD_NODE_SEQ_NO(camd_node),
                             CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                             CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                             __camd_op_str(CAMD_NODE_OP(camd_node)),
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            camd_node_free(camd_node);
            camd_page_terminate(camd_page);
            camd_page_free(camd_page);
            return (EC_FALSE);
        }
    }

    if(BIT_TRUE == page_dirty_flag)
    {
        CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)  = BIT_TRUE;
        CAMD_PAGE_SATA_DIRTY_FLAG(camd_page) = BIT_TRUE;
    }
    else
    {
        if(BIT_TRUE == CAMD_PAGE_SATA_LOADED_FLAG(camd_page))
        {
            /*if loaded from sata, then flush to ssd*/
            CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)  = BIT_TRUE;
        }
    }

    if(EC_FALSE == camd_page_notify_timeout(camd_page))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                         "page [%ld, %ld) notify timeout nodes failed\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        camd_page_terminate(camd_page);
        camd_page_free(camd_page);
        return (EC_FALSE);
    }

    /*flush sata or ssd or dirty page to mem cache*/
    while(BIT_TRUE == CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)
    || BIT_TRUE == CAMD_PAGE_SATA_DIRTY_FLAG(camd_page)
    || (BIT_FALSE == CAMD_PAGE_MEM_FLUSHED_FLAG(camd_page)
    && (BIT_TRUE == CAMD_PAGE_SATA_LOADED_FLAG(camd_page)
    || BIT_TRUE == CAMD_PAGE_SSD_LOADED_FLAG(camd_page))))
    {
        CAMD_MD     *camd_md;

        /*flush dirty page or sata loaded page or ssd loaded page to mem cache*/
        if(EC_TRUE == camd_page_flush_mem(camd_page))
        {
            CAMD_PAGE_MEM_FLUSHED_FLAG(camd_page) = BIT_TRUE; /*set flag*/

            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                             "flush page [%ld, %ld) [crc %u] to mem cache done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                             CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page), CMCPGB_PAGE_SIZE_NBYTES));

            break; /*fall through*/
        }

        /*exception*/

        camd_page_purge_ssd(camd_page); /*purge from ssd*/

        /*if flush mem failed, try to flush sata directly*/
        if(BIT_TRUE == CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)
        || BIT_TRUE == CAMD_PAGE_SATA_DIRTY_FLAG(camd_page))
        {
            if(EC_TRUE == camd_page_flush_sata_dio(camd_page))/*dio*/
            {
                dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                                 "flush page [%ld, %ld) to mem cache failed => flush sata dio done\n",
                                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

                CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)  = BIT_FALSE; /*clear flag*/
                CAMD_PAGE_SATA_DIRTY_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

                break;/*fall through*/
            }

            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                             "flush page [%ld, %ld) to mem cache failed => flush sata dio failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        }

        /*if both flush mem and flush sata failed, retry later*/

        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                         "flush page [%ld, %ld) to mem cache failed => retry\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));


        CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
        camd_md = CAMD_PAGE_CAMD_MD(camd_page);

        /*retry*/
        camd_add_page(camd_md, retry_page_tree_idx, camd_page);

        return (EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                     "process page [%ld, %ld) done\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    camd_page_free(camd_page);
    return (EC_TRUE);
}

EC_BOOL camd_page_load_sata_aio_timeout(CAMD_PAGE *camd_page)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_sata_aio_timeout: "
                     "load page [%ld, %ld) [crc %u] timeout\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                     CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                 CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

    if(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page)
    && NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page)
    && CAMD_PAGE_TREE_IDX_ERR != CAMD_PAGE_MOUNTED_TREE_IDX(camd_page))
    {
        CAMD_MD     *camd_md;

        camd_md = CAMD_PAGE_CAMD_MD(camd_page);
        camd_del_page(camd_md, CAMD_PAGE_MOUNTED_TREE_IDX(camd_page), camd_page);
    }

    CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    camd_page_timeout(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

EC_BOOL camd_page_load_sata_aio_terminate(CAMD_PAGE *camd_page)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_sata_aio_terminate: "
                     "load page [%ld, %ld) [crc %u] terminated\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                     CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                  CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

    /*retry*/
    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page); /*reset*/
    if(EC_TRUE == c_file_pread(CAMD_PAGE_FD(camd_page),
                    &CAMD_PAGE_F_T_OFFSET(camd_page),
                    CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                    CAMD_PAGE_M_CACHE(camd_page)))
    {
        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_sata_aio_terminate: "
                         "load page [%ld, %ld) [crc %u] retry and succ => complete\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                         CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                    CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

        return camd_page_load_sata_aio_complete(camd_page);
    }

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_load_sata_aio_terminate: "
                     "load page [%ld, %ld) retry and failed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    if(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page)
    && NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page)
    && CAMD_PAGE_TREE_IDX_ERR != CAMD_PAGE_MOUNTED_TREE_IDX(camd_page))
    {
        CAMD_MD     *camd_md;

        camd_md = CAMD_PAGE_CAMD_MD(camd_page);
        camd_del_page(camd_md, CAMD_PAGE_MOUNTED_TREE_IDX(camd_page), camd_page);
    }

    CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    camd_page_terminate(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

EC_BOOL camd_page_load_sata_aio_complete(CAMD_PAGE *camd_page)
{
    CAMD_MD     *camd_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_sata_aio_complete: "
                     "load page [%ld, %ld) [crc %u] completed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                     CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                  CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

    CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    if(NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page)
    && CAMD_PAGE_TREE_IDX_ERR != CAMD_PAGE_MOUNTED_TREE_IDX(camd_page))
    {
        camd_del_page(camd_md, CAMD_PAGE_MOUNTED_TREE_IDX(camd_page), camd_page);
    }

    CAMD_PAGE_SATA_LOADED_FLAG(camd_page)  = BIT_TRUE;  /*set sata loaded*/
    CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/
    CAMD_PAGE_SATA_DIRTY_FLAG(camd_page)   = BIT_FALSE; /*clear flag*/

    /*free camd page determined by process*/
    camd_page_process(camd_page, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md));

    return (EC_TRUE);
}

/*load page from sata to mem cache*/
EC_BOOL camd_page_load_sata_aio(CAMD_PAGE *camd_page)
{
    CAMD_MD         *camd_md;
    CAIO_MD         *caio_md;
    CAIO_CB          caio_cb;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);
    CAMD_ASSERT(NULL_PTR != CAMD_MD_CAIO_MD(camd_md));

    caio_md = CAMD_MD_CAIO_MD(camd_md);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_PAGE_TIMEOUT_NSEC(camd_page),
                                (CAIO_CALLBACK)camd_page_load_sata_aio_timeout, (void *)camd_page);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_load_sata_aio_terminate, (void *)camd_page);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_load_sata_aio_complete, (void *)camd_page);

    /*init temp offset*/
    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);

    CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

    if(EC_TRUE == caio_file_read(caio_md,
                    CAMD_PAGE_FD(camd_page),
                    &CAMD_PAGE_F_T_OFFSET(camd_page),
                    CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                    CAMD_PAGE_M_CACHE(camd_page),
                    &caio_cb))
    {
        return (EC_TRUE);
    }

    /*WARNING: exception would be handled in terminate, */
    /*         and page cannot be accessed again! => do not output log*/

    return (EC_FALSE);
}

EC_BOOL camd_page_notify_timeout(CAMD_PAGE *camd_page)
{
    CLIST_DATA      *clist_data;
    uint64_t         cur_ts;

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_notify_timeout: "
                     "page [%ld, %ld) notify the timeout nodes\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    cur_ts = c_get_cur_time_msec();

    CLIST_LOOP_NEXT(CAMD_PAGE_OWNERS(camd_page), clist_data)
    {
        CAMD_NODE       *camd_node;

        camd_node = (CAMD_NODE *)CLIST_DATA_DATA(clist_data);
        CAMD_ASSERT(clist_data == CAMD_NODE_MOUNTED_OWNERS(camd_node));
        if(cur_ts >= CAMD_NODE_NTIME_MS(camd_node))
        {
            clist_data = CLIST_DATA_PREV(clist_data);

            camd_page_del_node(camd_page, camd_node);

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_notify_timeout: "
                             "notify node %ld/%ld of req %ld timeout\n",
                             CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                             CAMD_NODE_SEQ_NO(camd_node));

            camd_node_timeout(camd_node);
        }
    }

    /*not free page*/

    return (EC_TRUE);
}

/*aio flush timeout*/
EC_BOOL camd_page_flush_sata_aio_timeout(CAMD_PAGE *camd_page)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_sata_aio_timeout: "
                     "flush page [%ld, %ld) timeout\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));


    camd_page_timeout(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*aio flush terminate*/
EC_BOOL camd_page_flush_sata_aio_terminate(CAMD_PAGE *camd_page)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_sata_aio_terminate: "
                     "flush page [%ld, %ld) terminated\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    /*retry*/
    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page); /*reset*/
    if(EC_TRUE == c_file_pwrite(CAMD_PAGE_FD(camd_page),
                               &CAMD_PAGE_F_T_OFFSET(camd_page),
                               CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                               CAMD_PAGE_M_CACHE(camd_page)))
    {
        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_sata_aio_terminate: "
                         "flush page [%ld, %ld) [crc %u] retry and succ => complete\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                         CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                      CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

        return camd_page_flush_sata_aio_complete(camd_page);
    }

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_flush_sata_aio_terminate: "
                     "flush page [%ld, %ld) retry and failed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));


    camd_page_terminate(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*aio flush complete*/
EC_BOOL camd_page_flush_sata_aio_complete(CAMD_PAGE *camd_page)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_sata_aio_complete: "
                     "flush page [%ld, %ld) [crc %u] completed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                     CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                  CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

    CAMD_ASSERT(CAMD_PAGE_F_T_OFFSET(camd_page) == CAMD_PAGE_F_E_OFFSET(camd_page));

    camd_page_complete(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*flush page to sata*/
EC_BOOL camd_page_flush_sata_aio(CAMD_PAGE *camd_page)
{
    CAMD_MD         *camd_md;
    CAIO_MD         *caio_md;
    CAIO_CB          caio_cb;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CAIO_MD(camd_md));

    caio_md = CAMD_MD_CAIO_MD(camd_md);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_PAGE_TIMEOUT_NSEC(camd_page),
                                (CAIO_CALLBACK)camd_page_flush_sata_aio_timeout, (void *)camd_page);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_flush_sata_aio_terminate, (void *)camd_page);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_flush_sata_aio_complete, (void *)camd_page);

    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);/*init*/
    CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

    if(EC_TRUE == caio_file_write(caio_md,
                    CAMD_PAGE_FD(camd_page),
                    &CAMD_PAGE_F_T_OFFSET(camd_page),
                    CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                    CAMD_PAGE_M_CACHE(camd_page),
                    &caio_cb))
    {
        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_sata_aio: "
                         "submit flushing page [%ld, %ld) to sata done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        return (EC_TRUE);
    }

    /*WARNING: exception would be handled in terminate, */
    /*         and camd_sata cannot be accessed again! => do not output log*/

    return (EC_FALSE);
}

/*dio flush: sync model*/
EC_BOOL camd_page_flush_sata_dio(CAMD_PAGE *camd_page)
{
    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);/*init*/

    if(EC_FALSE == c_file_pwrite(CAMD_PAGE_FD(camd_page),
                        &CAMD_PAGE_F_T_OFFSET(camd_page),
                        CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                        CAMD_PAGE_M_CACHE(camd_page)))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_flush_sata_dio: "
                         "dio flush page [%ld, %ld) to sata failed\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        return(EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_sata_dio: "
                     "dio flush page [%ld, %ld) [crc %u] to sata done\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                     CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));
    return (EC_TRUE);
}

/*aio flush timeout*/
EC_BOOL camd_page_flush_ssd_aio_timeout(CAMD_PAGE *camd_page)
{
    CAMD_MD         *camd_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_aio_timeout: "
                     "flush page [%ld, %ld) timeout\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    /*make sure cmc would not flush the page to ssd*/
    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        CMC_MD          *cmc_md;
        UINT32           offset;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

        /*let cmc flush this page to ssd later*/
        if(EC_FALSE == cmc_file_set_ssd_dirty(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "warn:camd_page_flush_ssd_aio_timeout: "
                             "set ssd dirty page [%ld, %ld) failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            /*ignore error*/
        }
        else
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_aio_timeout: "
                             "set ssd dirty page [%ld, %ld) done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        }
    }

    camd_page_timeout(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*aio flush terminate*/
EC_BOOL camd_page_flush_ssd_aio_terminate(CAMD_PAGE *camd_page)
{
    CAMD_MD         *camd_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_aio_terminate: "
                     "flush page [%ld, %ld) terminated\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    /*make sure cmc would not flush the page to ssd*/
    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        CMC_MD          *cmc_md;
        UINT32           offset;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

        /*let cmc flush this page to ssd later*/
        if(EC_FALSE == cmc_file_set_ssd_dirty(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "warn:camd_page_flush_ssd_aio_terminate: "
                             "set ssd dirty page [%ld, %ld) failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            /*ignore error*/
        }
        else
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_aio_terminate: "
                             "set ssd dirty page [%ld, %ld) done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        }
    }

    camd_page_terminate(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*aio flush complete*/
EC_BOOL camd_page_flush_ssd_aio_complete(CAMD_PAGE *camd_page)
{
    CAMD_MD         *camd_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_aio_complete: "
                     "flush page [%ld, %ld) [crc %u] completed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                     CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                  CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));

    CAMD_ASSERT(CAMD_PAGE_F_T_OFFSET(camd_page) == CAMD_PAGE_F_E_OFFSET(camd_page));

    CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    /*make sure cmc would not flush the page to ssd*/
    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md)
    && BIT_TRUE == CAMD_PAGE_SATA_DIRTY_FLAG(camd_page))
    {
        CMC_MD          *cmc_md;
        UINT32           offset;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

        /*let cmc not flush this page to ssd*/
        if(EC_FALSE == cmc_file_set_ssd_not_dirty(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "warn:camd_page_flush_ssd_aio_complete: "
                             "set ssd not dirty page [%ld, %ld) failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            /*ignore error*/
        }
        else
        {
            dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_aio_complete: "
                             "set ssd not dirty page [%ld, %ld) done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        }
    }

    /*make sure cdc would flush the page to sata later*/
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        CDC_MD          *cdc_md;
        UINT32           offset;

        cdc_md = CAMD_MD_CDC_MD(camd_md);

        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

        /*let cdc not flush this page to sata*/
        if(EC_FALSE == cdc_file_set_sata_not_flushed(cdc_md, &offset, CDCPGB_PAGE_SIZE_NBYTES))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "warn:camd_page_flush_sata_aio_complete: "
                             "set sata not flushed page [%ld, %ld) failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            /*ignore error*/
        }
        else
        {
            dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_sata_aio_complete: "
                             "set sata not flushed page [%ld, %ld) done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        }
    }

    camd_page_complete(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*flush page to ssd*/
EC_BOOL camd_page_flush_ssd_aio(CAMD_PAGE *camd_page)
{
    CAMD_MD         *camd_md;
    CDC_MD          *cdc_md;
    CAIO_CB          caio_cb;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    cdc_md = CAMD_MD_CDC_MD(camd_md);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_PAGE_TIMEOUT_NSEC(camd_page),
                                (CAIO_CALLBACK)camd_page_flush_ssd_aio_timeout, (void *)camd_page);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_flush_ssd_aio_terminate, (void *)camd_page);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_flush_ssd_aio_complete, (void *)camd_page);

    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);/*init*/
    CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

    if(EC_TRUE == cdc_file_write_aio(cdc_md,
                    &CAMD_PAGE_F_T_OFFSET(camd_page),
                    CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                    CAMD_PAGE_M_CACHE(camd_page),
                    BIT_TRUE, /*default sata dirty flag*/
                    &caio_cb))
    {
        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_aio: "
                         "submit flushing page [%ld, %ld) [crc %u] to ssd done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                         CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));
       return (EC_TRUE);
    }

    /*WARNING: exception would be handled in terminate, */
    /*         and page cannot be accessed again! => do not output log*/

    return (EC_FALSE);
}

/*dio flush: sync model*/
EC_BOOL camd_page_flush_ssd_dio(CAMD_PAGE *camd_page)
{
    CAMD_MD         *camd_md;
    CDC_MD          *cdc_md;

    CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));
    cdc_md  = CAMD_MD_CDC_MD(camd_md);

    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);/*init*/

    if(EC_FALSE == c_file_pwrite(CDC_MD_SSD_FD(cdc_md),
                &CAMD_PAGE_F_T_OFFSET(camd_page),
                CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                CAMD_PAGE_M_CACHE(camd_page)))
    {
        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "error:camd_page_flush_ssd_dio: "
                         "dio flush page [%ld, %ld) to ssd failed\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        return (EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_ssd_dio: "
                     "dio flush page [%ld, %ld) [crc %u] to ssd done\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                     CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page),
                                  CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page)));
    return (EC_TRUE);
}

EC_BOOL camd_page_flush_mem(CAMD_PAGE *camd_page)
{
    CAMD_MD                *camd_md;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    /*flush to mem cache*/
    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md)
    && BIT_FALSE == CAMD_PAGE_MEM_CACHE_FLAG(camd_page))
    {
        CMC_MD          *cmc_md;
        UINT32           offset;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        offset = CAMD_PAGE_F_S_OFFSET(camd_page);
        if(EC_FALSE == cmc_file_write(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES, CAMD_PAGE_M_CACHE(camd_page)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_flush_mem: "
                             "flush page [%ld, %ld) to mem cache failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            /*delete dirty page*/
            offset = CAMD_PAGE_F_S_OFFSET(camd_page);
            if(EC_FALSE == cmc_file_delete(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_flush_mem: "
                                 "del page [%ld, %ld) from mem cache failed\n",
                                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
            }
            else
            {
                dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_mem: "
                                 "del page [%ld, %ld) from mem cache done\n",
                                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
            }

            return (EC_FALSE);
        }

        if(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES != offset)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_flush_mem: "
                             "flush page [%ld, %ld) to mem cache failed, expected offset %ld != %ld\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                             CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES, offset);

            offset = CAMD_PAGE_F_S_OFFSET(camd_page);
            if(EC_FALSE == cmc_file_delete(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_flush_mem: "
                                 "del page [%ld, %ld) from mem cache failed\n",
                                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
                return (EC_FALSE);
            }

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_mem: "
                             "del page [%ld, %ld) from mem cache done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
            return (EC_TRUE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_mem: "
                         "flush page [%ld, %ld) [crc %u] to mem cache done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                         CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page), CMCPGB_PAGE_SIZE_NBYTES));

        /*return (EC_TRUE);*/
    }

    /*set ssd dirty flag and sata dirty flag if need*/
    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        CMC_MD          *cmc_md;
        CMCNP_KEY        cmcnp_key;
        CMCNP_ITEM      *cmcnp_item;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(CAMD_PAGE_F_S_OFFSET(camd_page) >> CMCPGB_PAGE_SIZE_NBITS);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(CAMD_PAGE_F_E_OFFSET(camd_page) >> CMCPGB_PAGE_SIZE_NBITS);

        cmcnp_item = cmc_find(cmc_md, &cmcnp_key);
        if(NULL_PTR != cmcnp_item)
        {
            if(BIT_TRUE == CAMD_PAGE_SSD_DIRTY_FLAG(camd_page))
            {
                CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item) = BIT_TRUE;
            }
            /*else, do not change ssd dirty flag of item*/

            if(BIT_TRUE == CAMD_PAGE_SATA_DIRTY_FLAG(camd_page))
            {
                CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item) = BIT_TRUE;
                CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item)  = BIT_TRUE;
            }
            /*else, do not change sata dirty flag of item*/

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_mem: "
                             "page [%ld, %ld) set ssd dirty %u, sata dirty %u done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                             CMCNP_ITEM_SSD_DIRTY_FLAG(cmcnp_item),
                             CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item));
        }

        if(BIT_TRUE == CAMD_PAGE_SSD_DIRTY_FLAG(camd_page)
        || BIT_TRUE == CAMD_PAGE_SATA_DIRTY_FLAG(camd_page))
        {
            cfc_inc_traffic(CAMD_MD_MEM_FC(camd_md), CMCPGB_PAGE_SIZE_NBYTES);
        }

        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL camd_page_purge_ssd(CAMD_PAGE *camd_page)
{
    CAMD_MD                *camd_md;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        UINT32      offset;

        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

        if(EC_FALSE == cdc_file_delete(CAMD_MD_CDC_MD(camd_md), &offset, CDCPGB_PAGE_SIZE_NBYTES))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_purge_ssd: "
                             "purge page [%ld, %ld) from ssd cache failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_purge_ssd: "
                         "purge page [%ld, %ld) from ssd cache done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL camd_page_load_ssd_aio_timeout(CAMD_PAGE *camd_page)
{
   dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_ssd_aio_timeout: "
                     "load page [%ld, %ld) timeout\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    if(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page)
    && NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page)
    && CAMD_PAGE_TREE_IDX_ERR != CAMD_PAGE_MOUNTED_TREE_IDX(camd_page))
    {
        CAMD_MD     *camd_md;

        camd_md = CAMD_PAGE_CAMD_MD(camd_page);
        camd_del_page(camd_md, CAMD_PAGE_MOUNTED_TREE_IDX(camd_page), camd_page);
    }

    CAMD_PAGE_SSD_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    camd_page_timeout(camd_page);
    camd_page_free(camd_page);
    return (EC_TRUE);
}

EC_BOOL camd_page_load_ssd_aio_terminate(CAMD_PAGE *camd_page)
{
    CAMD_MD     *camd_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_ssd_aio_terminate: "
                     "ssd load page [%ld, %ld) terminated => sata loading\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    CAMD_PAGE_SSD_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    /*load page from sata to mem cache*/
    if(EC_FALSE == camd_page_load_sata_aio(camd_page))
    {
        /*page cannot be accessed again => do not output log*/
        return (EC_FALSE);
    }

    cfc_inc_traffic(CAMD_MD_SATA_READ_FC(camd_md), CMCPGB_PAGE_SIZE_NBYTES);

    /*add page to active page tree*/
    camd_add_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page);
    CAMD_PAGE_SATA_LOADING_FLAG(camd_page)  = BIT_TRUE; /*set flag*/

    dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_load_ssd_aio_terminate: "
                                         "submit sata loading page [%ld, %ld) done\n",
                                         CAMD_PAGE_F_S_OFFSET(camd_page),
                                         CAMD_PAGE_F_E_OFFSET(camd_page));

    return (EC_TRUE);
}

EC_BOOL camd_page_load_ssd_aio_complete(CAMD_PAGE *camd_page)
{
    CAMD_MD     *camd_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_ssd_aio_complete: "
                     "load page [%ld, %ld) completed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    CAMD_ASSERT(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page));
    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    if(NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page)
    && CAMD_PAGE_TREE_IDX_ERR != CAMD_PAGE_MOUNTED_TREE_IDX(camd_page))
    {
        camd_del_page(camd_md, CAMD_PAGE_MOUNTED_TREE_IDX(camd_page), camd_page);
    }

    CAMD_PAGE_SSD_LOADED_FLAG(camd_page)  = BIT_TRUE;  /*set ssd loaded*/
    CAMD_PAGE_SSD_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    /*free camd page determined by process*/
    camd_page_process(camd_page, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md));

    return (EC_TRUE);
}

/*load page from ssd to mem cache*/
EC_BOOL camd_page_load_ssd_aio(CAMD_PAGE *camd_page)
{
    CAMD_MD                *camd_md;
    CDC_MD                 *cdc_md;
    CAIO_CB                 caio_cb;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);
    cdc_md  = CAMD_MD_CDC_MD(camd_md);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_PAGE_TIMEOUT_NSEC(camd_page),
                                (CAIO_CALLBACK)camd_page_load_ssd_aio_timeout, (void *)camd_page);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_load_ssd_aio_terminate, (void *)camd_page);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_page_load_ssd_aio_complete, (void *)camd_page);

    /*init temp offset*/
    CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);

    CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

    return cdc_file_read_aio(cdc_md,
                          &CAMD_PAGE_F_T_OFFSET(camd_page),
                          CDCPGB_PAGE_SIZE_NBYTES,
                          CAMD_PAGE_M_CACHE(camd_page),
                          &caio_cb);
}

/*----------------------------------- camd node interface -----------------------------------*/

CAMD_NODE *camd_node_new()
{
    CAMD_NODE *camd_node;

    alloc_static_mem(MM_CAMD_NODE, &camd_node, LOC_CAMD_0004);
    if(NULL_PTR == camd_node)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_node_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    camd_node_init(camd_node);
    return (camd_node);
}

EC_BOOL camd_node_init(CAMD_NODE *camd_node)
{
    CAMD_NODE_CAMD_REQ(camd_node)       = NULL_PTR;
    CAMD_NODE_CAMD_PAGE(camd_node)      = NULL_PTR;

    CAMD_NODE_SEQ_NO(camd_node)         = 0;
    CAMD_NODE_SUB_SEQ_NO(camd_node)     = 0;
    CAMD_NODE_SUB_SEQ_NUM(camd_node)    = 0;
    CAMD_NODE_OP(camd_node)             = CAMD_OP_ERR;

    CAMD_NODE_CAMD_MD(camd_node)        = NULL_PTR;
    CAMD_NODE_FD(camd_node)             = ERR_FD;
    CAMD_NODE_M_CACHE(camd_node)        = NULL_PTR;
    CAMD_NODE_M_BUFF(camd_node)         = NULL_PTR;
    CAMD_NODE_F_S_OFFSET(camd_node)     = 0;
    CAMD_NODE_F_E_OFFSET(camd_node)     = 0;
    CAMD_NODE_B_S_OFFSET(camd_node)     = 0;
    CAMD_NODE_B_E_OFFSET(camd_node)     = 0;
    CAMD_NODE_TIMEOUT_NSEC(camd_node)   = 0;
    CAMD_NODE_NTIME_MS(camd_node)       = 0;

    CAMD_NODE_MOUNTED_NODES(camd_node)  = NULL_PTR;
    CAMD_NODE_MOUNTED_OWNERS(camd_node) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL camd_node_clean(CAMD_NODE *camd_node)
{
    if(NULL_PTR != camd_node)
    {
        if(NULL_PTR != CAMD_NODE_MOUNTED_NODES(camd_node)
        && NULL_PTR != CAMD_NODE_CAMD_REQ(camd_node))
        {
            camd_req_del_node(CAMD_NODE_CAMD_REQ(camd_node), camd_node);
        }

        if(NULL_PTR != CAMD_NODE_MOUNTED_OWNERS(camd_node)
        && NULL_PTR != CAMD_NODE_CAMD_PAGE(camd_node))
        {
            camd_page_del_node(CAMD_NODE_CAMD_PAGE(camd_node), camd_node);
        }

        CAMD_NODE_CAMD_REQ(camd_node)       = NULL_PTR;
        CAMD_NODE_CAMD_PAGE(camd_node)      = NULL_PTR;

        CAMD_NODE_SEQ_NO(camd_node)         = 0;
        CAMD_NODE_SUB_SEQ_NO(camd_node)     = 0;
        CAMD_NODE_SUB_SEQ_NUM(camd_node)    = 0;
        CAMD_NODE_OP(camd_node)             = CAMD_OP_ERR;

        CAMD_NODE_CAMD_MD(camd_node)        = NULL_PTR;
        CAMD_NODE_FD(camd_node)             = ERR_FD;
        CAMD_NODE_M_CACHE(camd_node)        = NULL_PTR;
        CAMD_NODE_M_BUFF(camd_node)         = NULL_PTR;
        CAMD_NODE_F_S_OFFSET(camd_node)     = 0;
        CAMD_NODE_F_E_OFFSET(camd_node)     = 0;
        CAMD_NODE_B_S_OFFSET(camd_node)     = 0;
        CAMD_NODE_B_E_OFFSET(camd_node)     = 0;
        CAMD_NODE_TIMEOUT_NSEC(camd_node)   = 0;
        CAMD_NODE_NTIME_MS(camd_node)       = 0;
    }

    return (EC_TRUE);
}

EC_BOOL camd_node_free(CAMD_NODE *camd_node)
{
    if(NULL_PTR != camd_node)
    {
        camd_node_clean(camd_node);
        free_static_mem(MM_CAMD_NODE, camd_node, LOC_CAMD_0005);
    }
    return (EC_TRUE);
}

EC_BOOL camd_node_is(const CAMD_NODE *camd_node, const UINT32 sub_seq_no)
{
    if(sub_seq_no == CAMD_NODE_SUB_SEQ_NO(camd_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void camd_node_print(LOG *log, const CAMD_NODE *camd_node)
{
    sys_log(log, "camd_node_print: camd_node %p: req %p, mounted at %p\n",
                 camd_node,
                 CAMD_NODE_CAMD_REQ(camd_node), CAMD_NODE_MOUNTED_NODES(camd_node));

    sys_log(log, "camd_node_print: camd_node %p: page %p, mounted at %p\n",
                 camd_node,
                 CAMD_NODE_CAMD_PAGE(camd_node), CAMD_NODE_MOUNTED_OWNERS(camd_node));

    sys_log(log, "camd_node_print: camd_node %p: seq no %ld, sub seq no %ld, sub seq num %ld, op %s\n",
                 camd_node,
                 CAMD_NODE_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NO(camd_node),
                 CAMD_NODE_SUB_SEQ_NUM(camd_node),
                 __camd_op_str(CAMD_NODE_OP(camd_node)));

    sys_log(log, "camd_node_print: camd_node %p: fd %d, m_cache %p, m_buff %p, "
                 "file range [%ld, %ld), block range [%ld, %ld), "
                 "timeout %ld seconds, next access time %ld\n",
                 camd_node, CAMD_NODE_FD(camd_node),
                 CAMD_NODE_M_CACHE(camd_node), CAMD_NODE_M_BUFF(camd_node),
                 CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                 CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                 CAMD_NODE_TIMEOUT_NSEC(camd_node), CAMD_NODE_NTIME_MS(camd_node));

    return;
}

EC_BOOL camd_node_timeout(CAMD_NODE *camd_node)
{
    CAMD_REQ        *camd_req;

    if(do_log(SEC_0125_CAMD, 9))
    {
        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_node_timeout: "
                         "node %ld/%ld of req %ld => timeout\n",
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node));
        camd_node_print(LOGSTDOUT, camd_node);

        camd_req_print(LOGSTDOUT, CAMD_NODE_CAMD_REQ(camd_node));
    }

    CAMD_ASSERT(NULL_PTR != CAMD_NODE_CAMD_REQ(camd_node));
    camd_req = CAMD_NODE_CAMD_REQ(camd_node);

    /*update parent request*/
    if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_E_OFFSET(camd_req))
    {
        CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
    }

    camd_req_del_node(camd_req, camd_node);
    camd_node_free(camd_node);

    return camd_req_timeout(camd_req);
}

EC_BOOL camd_node_terminate(CAMD_NODE *camd_node)
{
    CAMD_REQ        *camd_req;

    if(do_log(SEC_0125_CAMD, 9))
    {
        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_node_terminate: "
                         "node %ld/%ld of req %ld => terminate\n",
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node));
        camd_node_print(LOGSTDOUT, camd_node);
    }

    CAMD_ASSERT(NULL_PTR != CAMD_NODE_CAMD_REQ(camd_node));
    camd_req = CAMD_NODE_CAMD_REQ(camd_node);

    /*update parent request*/
    if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_E_OFFSET(camd_req))
    {
        CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
    }

    camd_req_del_node(camd_req, camd_node);
    camd_node_free(camd_node);

    return camd_req_terminate(camd_req);
}

EC_BOOL camd_node_complete(CAMD_NODE *camd_node)
{
    CAMD_REQ        *camd_req;

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_node_complete: "
                     "node %ld/%ld of req %ld => complete\n",
                     CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                     CAMD_NODE_SEQ_NO(camd_node));

    CAMD_ASSERT(NULL_PTR != CAMD_NODE_CAMD_REQ(camd_node));
    camd_req = CAMD_NODE_CAMD_REQ(camd_node);

    /*update parent request*/
    CAMD_REQ_SUCC_NUM(camd_req) ++;

    camd_req_del_node(camd_req, camd_node);
    camd_node_free(camd_node);

    if(CAMD_REQ_SUCC_NUM(camd_req) >= CAMD_REQ_NODE_NUM(camd_req))
    {
        return camd_req_complete(camd_req);
    }

    return (EC_TRUE);
}

/*----------------------------------- camd req interface -----------------------------------*/

CAMD_REQ *camd_req_new()
{
    CAMD_REQ *camd_req;

    alloc_static_mem(MM_CAMD_REQ, &camd_req, LOC_CAMD_0006);
    if(NULL_PTR == camd_req)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    camd_req_init(camd_req);
    return (camd_req);
}

EC_BOOL camd_req_init(CAMD_REQ *camd_req)
{
    caio_cb_init(CAMD_REQ_CAIO_CB(camd_req));

    CAMD_REQ_SEQ_NO(camd_req)                   = 0;
    CAMD_REQ_OP(camd_req)                       = CAMD_OP_ERR;

    CAMD_REQ_SUB_SEQ_NUM(camd_req)              = 0;
    CAMD_REQ_NODE_NUM(camd_req)                 = 0;
    CAMD_REQ_SUCC_NUM(camd_req)                 = 0;
    CAMD_REQ_U_E_OFFSET(camd_req)               = 0;

    CAMD_REQ_CAMD_MD(camd_req)                  = NULL_PTR;
    CAMD_REQ_FD(camd_req)                       = ERR_FD;
    CAMD_REQ_M_CACHE(camd_req)                  = NULL_PTR;
    CAMD_REQ_M_BUFF(camd_req)                   = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)                   = NULL_PTR;
    CAMD_REQ_F_S_OFFSET(camd_req)               = 0;
    CAMD_REQ_F_E_OFFSET(camd_req)               = 0;
    CAMD_REQ_TIMEOUT_NSEC(camd_req)             = 0;
    CAMD_REQ_NTIME_MS(camd_req)                 = 0;

    CAMD_REQ_S_MSEC(camd_req)                   = 0;
    CAMD_REQ_E_MSEC(camd_req)                   = 0;

    CAMD_REQ_POST_EVENT_HANDLER(camd_req)       = NULL_PTR;
    CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req)  = NULL_PTR;

    clist_init(CAMD_REQ_NODES(camd_req), MM_CAMD_NODE, LOC_CAMD_0007);

    CAMD_REQ_MOUNTED_REQS(camd_req)             = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL camd_req_clean(CAMD_REQ *camd_req)
{
    if(NULL_PTR != camd_req)
    {
        if(NULL_PTR != CAMD_REQ_MOUNTED_REQS(camd_req)
        && NULL_PTR != CAMD_REQ_CAMD_MD(camd_req))
        {
            camd_del_req(CAMD_REQ_CAMD_MD(camd_req), camd_req);
        }

        if(NULL_PTR != CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req))
        {
            camd_req_del_post_event(camd_req);
        }

        camd_req_cleanup_nodes(camd_req);

        caio_cb_clean(CAMD_REQ_CAIO_CB(camd_req));

        CAMD_REQ_SEQ_NO(camd_req)                   = 0;
        CAMD_REQ_OP(camd_req)                       = CAMD_OP_ERR;

        CAMD_REQ_SUB_SEQ_NUM(camd_req)              = 0;
        CAMD_REQ_NODE_NUM(camd_req)                 = 0;
        CAMD_REQ_SUCC_NUM(camd_req)                 = 0;
        CAMD_REQ_U_E_OFFSET(camd_req)               = 0;

        CAMD_REQ_CAMD_MD(camd_req)                  = NULL_PTR;
        CAMD_REQ_FD(camd_req)                       = ERR_FD;
        CAMD_REQ_M_CACHE(camd_req)                  = NULL_PTR;
        CAMD_REQ_M_BUFF(camd_req)                   = NULL_PTR;
        CAMD_REQ_OFFSET(camd_req)                   = NULL_PTR;
        CAMD_REQ_F_S_OFFSET(camd_req)               = 0;
        CAMD_REQ_F_E_OFFSET(camd_req)               = 0;
        CAMD_REQ_TIMEOUT_NSEC(camd_req)             = 0;
        CAMD_REQ_NTIME_MS(camd_req)                 = 0;

        CAMD_REQ_S_MSEC(camd_req)                   = 0;
        CAMD_REQ_E_MSEC(camd_req)                   = 0;
    }

    return (EC_TRUE);
}

EC_BOOL camd_req_free(CAMD_REQ *camd_req)
{
    if(NULL_PTR != camd_req)
    {
        camd_req_clean(camd_req);
        free_static_mem(MM_CAMD_REQ, camd_req, LOC_CAMD_0008);
    }
    return (EC_TRUE);
}

EC_BOOL camd_req_exec_timeout_handler(CAMD_REQ *camd_req)
{
    if(NULL_PTR != camd_req)
    {
        CAIO_CB     caio_cb;

        CAMD_REQ_E_MSEC(camd_req) = c_get_cur_time_msec();

        dbg_log(SEC_0125_CAMD, 1)(LOGSTDOUT, "[DEBUG] camd_req_exec_timeout_handler: "
                                             "req %ld, op %s, fd %d, file range [%ld, %ld), "
                                             "sub %ld, succ %ld, "
                                             "elapsed %ld msec\n",
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)),
                                             CAMD_REQ_FD(camd_req),
                                             CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                                             CAMD_REQ_SUB_SEQ_NUM(camd_req), CAMD_REQ_SUCC_NUM(camd_req),
                                             CAMD_REQ_E_MSEC(camd_req) - CAMD_REQ_S_MSEC(camd_req));

        caio_cb_clone(CAMD_REQ_CAIO_CB(camd_req), &caio_cb);
        camd_req_free(camd_req);

        return caio_cb_exec_timeout_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL camd_req_exec_terminate_handler(CAMD_REQ *camd_req)
{
    if(NULL_PTR != camd_req)
    {
        CAIO_CB     caio_cb;

        CAMD_REQ_E_MSEC(camd_req) = c_get_cur_time_msec();

        dbg_log(SEC_0125_CAMD, 1)(LOGSTDOUT, "[DEBUG] camd_req_exec_terminate_handler: "
                                             "req %ld, op %s, fd %d, file range [%ld, %ld), "
                                             "sub %ld, succ %ld, "
                                             "elapsed %ld msec\n",
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)),
                                             CAMD_REQ_FD(camd_req),
                                             CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                                             CAMD_REQ_SUB_SEQ_NUM(camd_req), CAMD_REQ_SUCC_NUM(camd_req),
                                             CAMD_REQ_E_MSEC(camd_req) - CAMD_REQ_S_MSEC(camd_req));

        caio_cb_clone(CAMD_REQ_CAIO_CB(camd_req), &caio_cb);
        camd_req_free(camd_req);

        return caio_cb_exec_terminate_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL camd_req_exec_complete_handler(CAMD_REQ *camd_req)
{
    if(NULL_PTR != camd_req)
    {
        CAIO_CB     caio_cb;

        CAMD_REQ_E_MSEC(camd_req) = c_get_cur_time_msec();

        dbg_log(SEC_0125_CAMD, 1)(LOGSTDOUT, "[DEBUG] camd_req_exec_complete_handler: "
                                             "req %ld, op %s, fd %d, file range [%ld, %ld), "
                                             "sub %ld, succ %ld, "
                                             "elapsed %ld msec\n",
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)),
                                             CAMD_REQ_FD(camd_req),
                                             CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                                             CAMD_REQ_SUB_SEQ_NUM(camd_req), CAMD_REQ_SUCC_NUM(camd_req),
                                             CAMD_REQ_E_MSEC(camd_req) - CAMD_REQ_S_MSEC(camd_req));

        caio_cb_clone(CAMD_REQ_CAIO_CB(camd_req), &caio_cb);
        camd_req_free(camd_req);

        return caio_cb_exec_complete_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL camd_req_set_post_event(CAMD_REQ *camd_req, CAMD_EVENT_HANDLER handler)
{
    CAMD_MD     *camd_md;

    if(NULL_PTR == CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req))
    {
        CAMD_ASSERT(NULL_PTR != CAMD_REQ_CAMD_MD(camd_req));

        camd_md = CAMD_REQ_CAMD_MD(camd_req);

        CAMD_REQ_POST_EVENT_HANDLER(camd_req) = handler;

        CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req) =
                clist_push_back(CAMD_MD_POST_EVENT_REQS(camd_md), (void *)camd_req);
    }
    return (EC_TRUE);
}

EC_BOOL camd_req_del_post_event(CAMD_REQ *camd_req)
{
    CAMD_MD         *camd_md;

    CAMD_ASSERT(NULL_PTR != CAMD_REQ_CAMD_MD(camd_req));

    camd_md = CAMD_REQ_CAMD_MD(camd_req);

    CAMD_REQ_POST_EVENT_HANDLER(camd_req) = NULL_PTR;

    if(NULL_PTR != CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req))
    {
        clist_erase(CAMD_MD_POST_EVENT_REQS(camd_md), CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req));
        CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL camd_req_is(const CAMD_REQ *camd_req, const UINT32 seq_no)
{
    if(seq_no == CAMD_REQ_SEQ_NO(camd_req))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


void camd_req_print(LOG *log, const CAMD_REQ *camd_req)
{
    sys_log(log, "camd_req_print: camd_req %p: caio_cb: \n", camd_req);
    caio_cb_print(log, CAMD_REQ_CAIO_CB(camd_req));

    sys_log(log, "camd_req_print: camd_req %p: seq no %ld, sub seq num %ld, op %s\n",
                 camd_req, CAMD_REQ_SEQ_NO(camd_req), CAMD_REQ_SUB_SEQ_NUM(camd_req),
                 __camd_op_str(CAMD_REQ_OP(camd_req)));

    sys_log(log, "camd_req_print: camd_req %p: fd %d, m_cache %p, m_buff %p, offset %p (%ld), range [%ld, %ld), "
                 "timeout %ld seconds, next access time %ld\n",
                 camd_req, CAMD_REQ_FD(camd_req), CAMD_REQ_M_CACHE(camd_req), CAMD_REQ_M_BUFF(camd_req),
                 CAMD_REQ_OFFSET(camd_req), (*CAMD_REQ_OFFSET(camd_req)),
                 CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                 CAMD_REQ_TIMEOUT_NSEC(camd_req), CAMD_REQ_NTIME_MS(camd_req));

    sys_log(log, "camd_req_print: camd_req %p: nodes: \n", camd_req);
    clist_print(log, CAMD_REQ_NODES(camd_req), (CLIST_DATA_DATA_PRINT)camd_node_print);
    return;
}

EC_BOOL camd_req_cleanup_nodes(CAMD_REQ *camd_req)
{
    CAMD_NODE       *camd_node;

    /*clean up nodes*/
    while(NULL_PTR != (camd_node = camd_req_pop_node_back(camd_req)))
    {
        camd_node_free(camd_node);
    }

    return (EC_TRUE);
}

EC_BOOL camd_req_push_node_back(CAMD_REQ *camd_req, CAMD_NODE *camd_node)
{
    CAMD_ASSERT(CAMD_NODE_SEQ_NO(camd_node) == CAMD_REQ_SEQ_NO(camd_req));

    /*mount*/
    CAMD_NODE_MOUNTED_NODES(camd_node) = clist_push_back(CAMD_REQ_NODES(camd_req), (void *)camd_node);
    if(NULL_PTR == CAMD_NODE_MOUNTED_NODES(camd_node))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_push_node_back: push node %ld to req %ld, op %s failed\n",
                                             CAMD_NODE_SUB_SEQ_NO(camd_node),
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)));
        return (EC_FALSE);
    }

    CAMD_NODE_CAMD_REQ(camd_node) = camd_req; /*bind*/

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_push_node_back: push node %ld to req %ld, op %s done\n",
                                         CAMD_NODE_SUB_SEQ_NO(camd_node),
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));
    return (EC_TRUE);
}

CAMD_NODE *camd_req_pop_node_back(CAMD_REQ *camd_req)
{
    if(NULL_PTR != camd_req)
    {
        CAMD_NODE *camd_node;

        camd_node = clist_pop_back(CAMD_REQ_NODES(camd_req));
        if(NULL_PTR != camd_node)
        {
            CAMD_ASSERT(CAMD_NODE_CAMD_REQ(camd_node) == camd_req);

            CAMD_NODE_MOUNTED_NODES(camd_node) = NULL_PTR; /*umount*/
            CAMD_NODE_CAMD_REQ(camd_node)      = NULL_PTR; /*unbind*/
            return (camd_node);
        }
        return (NULL_PTR);
    }

    return (NULL_PTR);
}

EC_BOOL camd_req_push_node_front(CAMD_REQ *camd_req, CAMD_NODE *camd_node)
{
    CAMD_ASSERT(CAMD_NODE_SEQ_NO(camd_node) == CAMD_REQ_SEQ_NO(camd_req));

    /*mount*/
    CAMD_NODE_MOUNTED_NODES(camd_node) = clist_push_front(CAMD_REQ_NODES(camd_req), (void *)camd_node);
    if(NULL_PTR == CAMD_NODE_MOUNTED_NODES(camd_node))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_push_node_front: push node %ld to req %ld, op %s failed\n",
                                             CAMD_NODE_SUB_SEQ_NO(camd_node),
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)));
        return (EC_FALSE);
    }

    CAMD_NODE_CAMD_REQ(camd_node) = camd_req; /*bind*/

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_push_node_front: push node %ld to req %ld, op %s done\n",
                                         CAMD_NODE_SUB_SEQ_NO(camd_node),
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));
    return (EC_TRUE);
}

CAMD_NODE *camd_req_pop_node_front(CAMD_REQ *camd_req)
{
    if(NULL_PTR != camd_req)
    {
        CAMD_NODE *camd_node;

        camd_node = clist_pop_front(CAMD_REQ_NODES(camd_req));
        if(NULL_PTR != camd_node)
        {
            CAMD_ASSERT(CAMD_NODE_CAMD_REQ(camd_node) == camd_req);

            CAMD_NODE_MOUNTED_NODES(camd_node) = NULL_PTR; /*umount*/
            CAMD_NODE_CAMD_REQ(camd_node)      = NULL_PTR; /*unbind*/
            return (camd_node);
        }
        return (NULL_PTR);
    }

    return (NULL_PTR);
}

EC_BOOL camd_req_del_node(CAMD_REQ *camd_req, CAMD_NODE *camd_node)
{
    CAMD_ASSERT(CAMD_NODE_SEQ_NO(camd_node) == CAMD_REQ_SEQ_NO(camd_req));

    if(NULL_PTR != CAMD_NODE_MOUNTED_NODES(camd_node))
    {
        clist_erase(CAMD_REQ_NODES(camd_req), CAMD_NODE_MOUNTED_NODES(camd_node));
        CAMD_NODE_MOUNTED_NODES(camd_node) = NULL_PTR; /*umount*/
        CAMD_NODE_CAMD_REQ(camd_node)      = NULL_PTR; /*unbind*/

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_del_node: pop node %ld from req %ld, op %s done\n",
                                             CAMD_NODE_SUB_SEQ_NO(camd_node),
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)));

    }
    return (EC_TRUE);
}

EC_BOOL camd_req_reorder_sub_seq_no(CAMD_REQ *camd_req)
{
    UINT32       sub_seq_no;
    UINT32       sub_seq_num;
    CLIST_DATA  *clist_data;

    sub_seq_no  = 0;
    sub_seq_num = CAMD_REQ_SUB_SEQ_NUM(camd_req);

    CLIST_LOOP_NEXT(CAMD_REQ_NODES(camd_req), clist_data)
    {
        CAMD_NODE *camd_node;

        camd_node = (CAMD_NODE *)CLIST_DATA_DATA(clist_data);

        CAMD_NODE_SUB_SEQ_NO(camd_node)  = ++ sub_seq_no;
        CAMD_NODE_SUB_SEQ_NUM(camd_node) = sub_seq_num;
    }

    CAMD_ASSERT(sub_seq_no == sub_seq_num);

    return (EC_TRUE);
}

EC_BOOL camd_req_make_read_op(CAMD_REQ *camd_req)
{
    UINT32              f_s_offset;
    UINT32              f_e_offset;

    UINT8              *m_buff;

    CAMD_ASSERT(NULL_PTR != CAMD_REQ_CAMD_MD(camd_req));

    f_s_offset = CAMD_REQ_F_S_OFFSET(camd_req);
    f_e_offset = CAMD_REQ_F_E_OFFSET(camd_req);
    m_buff     = (UINT8 *)CAMD_REQ_M_BUFF(camd_req);

    while(f_s_offset < f_e_offset)
    {
        UINT32              b_s_offset;
        UINT32              b_e_offset;

        CAMD_NODE          *camd_node;

        b_s_offset = f_s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK);
        f_s_offset = f_s_offset & (~((UINT32)CMCPGB_PAGE_SIZE_MASK)); /*align to page starting*/

        b_e_offset = DMIN(f_s_offset + CMCPGB_PAGE_SIZE_NBYTES, f_e_offset) & ((UINT32)CMCPGB_PAGE_SIZE_MASK);
        if(0 == b_e_offset) /*adjust to next page boundary*/
        {
            b_e_offset = CMCPGB_PAGE_SIZE_NBYTES;
        }

        /*set up sub request*/
        camd_node = camd_node_new();
        if(NULL_PTR == camd_node)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:camd_req_make_read_op: "
                                                 "new camd_node failed\n");
            return (EC_FALSE);
        }

        CAMD_NODE_OP(camd_node)           = CAMD_OP_RD;

        /*inherited data from camd req*/
        CAMD_NODE_CAMD_REQ(camd_node)     = camd_req;
        CAMD_NODE_SEQ_NO(camd_node)       = CAMD_REQ_SEQ_NO(camd_req);
        CAMD_NODE_SUB_SEQ_NO(camd_node)   = ++ CAMD_REQ_SUB_SEQ_NUM(camd_req);
        CAMD_NODE_CAMD_MD(camd_node)      = CAMD_REQ_CAMD_MD(camd_req);
        CAMD_NODE_FD(camd_node)           = CAMD_REQ_FD(camd_req);
        CAMD_NODE_M_CACHE(camd_node)      = NULL_PTR;
        CAMD_NODE_M_BUFF(camd_node)       = m_buff;
        CAMD_NODE_F_S_OFFSET(camd_node)   = f_s_offset;
        CAMD_NODE_F_E_OFFSET(camd_node)   = f_s_offset + CMCPGB_PAGE_SIZE_NBYTES;
        CAMD_NODE_B_S_OFFSET(camd_node)   = b_s_offset;
        CAMD_NODE_B_E_OFFSET(camd_node)   = b_e_offset;
        CAMD_NODE_TIMEOUT_NSEC(camd_node) = CAMD_REQ_TIMEOUT_NSEC(camd_req);
        CAMD_NODE_NTIME_MS(camd_node)     = CAMD_REQ_NTIME_MS(camd_req);

        /*bind: push back & mount*/
        if(EC_FALSE == camd_req_push_node_back(camd_req, camd_node))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_make_read_op: "
                                                 "push node %ld to req %ld, op %s failed\n",
                                                 CAMD_NODE_SUB_SEQ_NO(camd_node),
                                                 CAMD_REQ_SEQ_NO(camd_req),
                                                 __camd_op_str(CAMD_REQ_OP(camd_req)));
            camd_node_free(camd_node);
            return (EC_FALSE);
        }

        m_buff     += b_e_offset - b_s_offset;
        f_s_offset += CMCPGB_PAGE_SIZE_NBYTES;/*align to next page starting*/
    }

    return (EC_TRUE);
}

EC_BOOL camd_req_make_write_op(CAMD_REQ *camd_req)
{
    UINT32              f_s_offset;
    UINT32              f_e_offset;

    UINT8              *m_buff;

    CAMD_ASSERT(NULL_PTR != CAMD_REQ_CAMD_MD(camd_req));

    f_s_offset = CAMD_REQ_F_S_OFFSET(camd_req);
    f_e_offset = CAMD_REQ_F_E_OFFSET(camd_req);
    m_buff     = (UINT8 *)CAMD_REQ_M_BUFF(camd_req);

    while(f_s_offset < f_e_offset)
    {
        UINT32              b_s_offset;
        UINT32              b_e_offset;

        CAMD_NODE          *camd_node;

        b_s_offset  = f_s_offset & ((UINT32)CMCPGB_PAGE_SIZE_MASK);
        f_s_offset  = f_s_offset & (~((UINT32)CMCPGB_PAGE_SIZE_MASK)); /*align to page starting*/

        b_e_offset  = DMIN(f_s_offset + CMCPGB_PAGE_SIZE_NBYTES, f_e_offset) & ((UINT32)CMCPGB_PAGE_SIZE_MASK);
        if(0 == b_e_offset) /*adjust to next page boundary*/
        {
            b_e_offset = CMCPGB_PAGE_SIZE_NBYTES;
        }

        /*set up sub request*/
        camd_node = camd_node_new();
        if(NULL_PTR == camd_node)
        {
            dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:camd_req_make_write_op: "
                                                 "new camd_node failed\n");
            return (EC_FALSE);
        }

        CAMD_NODE_OP(camd_node)           = CAMD_OP_WR;

        /*inherited data from camd req*/
        CAMD_NODE_CAMD_REQ(camd_node)     = camd_req;
        CAMD_NODE_SEQ_NO(camd_node)       = CAMD_REQ_SEQ_NO(camd_req);
        CAMD_NODE_SUB_SEQ_NO(camd_node)   = ++ CAMD_REQ_SUB_SEQ_NUM(camd_req);
        CAMD_NODE_CAMD_MD(camd_node)      = CAMD_REQ_CAMD_MD(camd_req);
        CAMD_NODE_FD(camd_node)           = CAMD_REQ_FD(camd_req);
        CAMD_NODE_M_CACHE(camd_node)      = NULL_PTR;
        CAMD_NODE_M_BUFF(camd_node)       = m_buff;
        CAMD_NODE_F_S_OFFSET(camd_node)   = f_s_offset;
        CAMD_NODE_F_E_OFFSET(camd_node)   = f_s_offset + CMCPGB_PAGE_SIZE_NBYTES;
        CAMD_NODE_B_S_OFFSET(camd_node)   = b_s_offset;
        CAMD_NODE_B_E_OFFSET(camd_node)   = b_e_offset;
        CAMD_NODE_TIMEOUT_NSEC(camd_node) = CAMD_REQ_TIMEOUT_NSEC(camd_req);
        CAMD_NODE_NTIME_MS(camd_node)     = CAMD_REQ_NTIME_MS(camd_req);

        /*bind: push back & mount*/
        if(EC_FALSE == camd_req_push_node_back(camd_req, camd_node))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_make_write_op: "
                                                 "push node %ld to req %ld, op %s failed\n",
                                                 CAMD_NODE_SUB_SEQ_NO(camd_node),
                                                 CAMD_REQ_SEQ_NO(camd_req),
                                                 __camd_op_str(CAMD_REQ_OP(camd_req)));
            camd_node_free(camd_node);
            return (EC_FALSE);
        }

        m_buff     += b_e_offset - b_s_offset;
        f_s_offset += CMCPGB_PAGE_SIZE_NBYTES;/*align to next page starting*/
    }

    return (EC_TRUE);
}

EC_BOOL camd_req_make_read(CAMD_REQ *camd_req)
{
    if(EC_FALSE == camd_req_make_read_op(camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_make_read: "
                                             "make read op of req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));
        return (EC_FALSE);
    }

    /*here re-order always for debug purpose due to recording sub seq num info in node*/
    camd_req_reorder_sub_seq_no(camd_req);

    CAMD_REQ_NODE_NUM(camd_req) = CAMD_REQ_SUB_SEQ_NUM(camd_req); /*init*/

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_make_read: "
                                         "make %ld ops of req %ld, op %s done\n",
                                         CAMD_REQ_SUB_SEQ_NUM(camd_req),
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));

    return (EC_TRUE);
}

EC_BOOL camd_req_make_write(CAMD_REQ *camd_req)
{
    UINT32              camd_node_num;
    UINT32              s_offset;
    UINT32              e_offset;
    UINT32              rd_flag;

    if(EC_FALSE == camd_req_make_write_op(camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_make_write: "
                                             "make write op of req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));
        return (EC_FALSE);
    }

    s_offset = CAMD_REQ_F_S_OFFSET(camd_req);
    e_offset = CAMD_REQ_F_E_OFFSET(camd_req);

    CAMD_ASSERT(clist_size(CAMD_REQ_NODES(camd_req)) == CAMD_REQ_SUB_SEQ_NUM(camd_req));

    camd_node_num = clist_size(CAMD_REQ_NODES(camd_req)); /*save node num*/
    rd_flag       = BIT_FALSE; /*init*/

    if(1 == camd_node_num)
    {
        if((((UINT32)CMCPGB_PAGE_SIZE_MASK) & s_offset) || (((UINT32)CMCPGB_PAGE_SIZE_MASK) & e_offset))
        {
            CAMD_NODE          *camd_node;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read sub request*/
            camd_node = camd_node_new();
            if(NULL_PTR == camd_node)
            {
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:camd_req_make_write: "
                                                     "new camd_node failed\n");
                return (EC_FALSE);
            }

            /*the unique page*/
            f_s_offset = s_offset & (~((UINT32)CMCPGB_PAGE_SIZE_MASK)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = CMCPGB_PAGE_SIZE_NBYTES;

            CAMD_NODE_OP(camd_node)           = CAMD_OP_RD;

            /*inherited data from camd req*/
            CAMD_NODE_CAMD_REQ(camd_node)     = camd_req;
            CAMD_NODE_SEQ_NO(camd_node)       = CAMD_REQ_SEQ_NO(camd_req);
            CAMD_NODE_SUB_SEQ_NO(camd_node)   = ++ CAMD_REQ_SUB_SEQ_NUM(camd_req); /*would re-order later*/
            CAMD_NODE_CAMD_MD(camd_node)      = CAMD_REQ_CAMD_MD(camd_req);
            CAMD_NODE_FD(camd_node)           = CAMD_REQ_FD(camd_req);
            CAMD_NODE_M_CACHE(camd_node)      = NULL_PTR;
            CAMD_NODE_M_BUFF(camd_node)       = NULL_PTR; /*inherit only for write operation*/
            CAMD_NODE_F_S_OFFSET(camd_node)   = f_s_offset;
            CAMD_NODE_F_E_OFFSET(camd_node)   = f_s_offset + CMCPGB_PAGE_SIZE_NBYTES;
            CAMD_NODE_B_S_OFFSET(camd_node)   = b_s_offset;
            CAMD_NODE_B_E_OFFSET(camd_node)   = b_e_offset;
            CAMD_NODE_TIMEOUT_NSEC(camd_node) = CAMD_REQ_TIMEOUT_NSEC(camd_req);
            CAMD_NODE_NTIME_MS(camd_node)     = CAMD_REQ_NTIME_MS(camd_req);

            /*push front & bind*/
            camd_req_push_node_front(camd_req, camd_node);

            rd_flag = BIT_TRUE;
        }
    }

    if(1 < camd_node_num)
    {
        if(((UINT32)CMCPGB_PAGE_SIZE_MASK) & s_offset)
        {
            CAMD_NODE          *camd_node;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read aio request*/
            camd_node = camd_node_new();
            if(NULL_PTR == camd_node)
            {
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:camd_req_make_write: "
                                                     "new camd_node failed\n");
                return (EC_FALSE);
            }

            /*the first page*/
            f_s_offset = s_offset & (~((UINT32)CMCPGB_PAGE_SIZE_MASK)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = CMCPGB_PAGE_SIZE_NBYTES;

            CAMD_NODE_OP(camd_node)           = CAMD_OP_RD;

            /*inherited data from camd req*/
            CAMD_NODE_CAMD_REQ(camd_node)     = camd_req;
            CAMD_NODE_SEQ_NO(camd_node)       = CAMD_REQ_SEQ_NO(camd_req);
            CAMD_NODE_SUB_SEQ_NO(camd_node)   = ++ CAMD_REQ_SUB_SEQ_NUM(camd_req); /*would re-order later*/
            CAMD_NODE_CAMD_MD(camd_node)      = CAMD_REQ_CAMD_MD(camd_req);
            CAMD_NODE_FD(camd_node)           = CAMD_REQ_FD(camd_req);
            CAMD_NODE_M_CACHE(camd_node)      = NULL_PTR;
            CAMD_NODE_M_BUFF(camd_node)       = NULL_PTR; /*inherit only for write operation*/
            CAMD_NODE_F_S_OFFSET(camd_node)   = f_s_offset;
            CAMD_NODE_F_E_OFFSET(camd_node)   = f_s_offset + CMCPGB_PAGE_SIZE_NBYTES;
            CAMD_NODE_B_S_OFFSET(camd_node)   = b_s_offset;
            CAMD_NODE_B_E_OFFSET(camd_node)   = b_e_offset;
            CAMD_NODE_TIMEOUT_NSEC(camd_node) = CAMD_REQ_TIMEOUT_NSEC(camd_req);
            CAMD_NODE_NTIME_MS(camd_node)     = CAMD_REQ_NTIME_MS(camd_req);

            /*bind: push front & mount*/
            camd_req_push_node_front(camd_req, camd_node);

            rd_flag = BIT_TRUE;
        }

        if(((UINT32)CMCPGB_PAGE_SIZE_MASK) & e_offset)
        {
            CAMD_NODE          *camd_node;
            CAMD_NODE          *camd_node_saved;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read sub request*/
            camd_node = camd_node_new();
            if(NULL_PTR == camd_node)
            {
                dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "error:camd_req_make_write: "
                                                     "new camd_node failed\n");
                return (EC_FALSE);
            }

            /*the last page*/
            f_s_offset = e_offset & (~((UINT32)CMCPGB_PAGE_SIZE_MASK)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = CMCPGB_PAGE_SIZE_NBYTES;

            CAMD_NODE_OP(camd_node)           = CAMD_OP_RD;

            /*inherited data from camd req*/
            CAMD_NODE_CAMD_REQ(camd_node)     = camd_req;
            CAMD_NODE_SEQ_NO(camd_node)       = CAMD_REQ_SEQ_NO(camd_req);
            CAMD_NODE_SUB_SEQ_NO(camd_node)   = ++ CAMD_REQ_SUB_SEQ_NUM(camd_req); /*would re-order later*/
            CAMD_NODE_CAMD_MD(camd_node)      = CAMD_REQ_CAMD_MD(camd_req);
            CAMD_NODE_FD(camd_node)           = CAMD_REQ_FD(camd_req);
            CAMD_NODE_M_CACHE(camd_node)      = NULL_PTR;
            CAMD_NODE_M_BUFF(camd_node)       = NULL_PTR; /*inherit only for write operation*/
            CAMD_NODE_F_S_OFFSET(camd_node)   = f_s_offset;
            CAMD_NODE_F_E_OFFSET(camd_node)   = f_s_offset + CMCPGB_PAGE_SIZE_NBYTES;
            CAMD_NODE_B_S_OFFSET(camd_node)   = b_s_offset;
            CAMD_NODE_B_E_OFFSET(camd_node)   = b_e_offset;
            CAMD_NODE_TIMEOUT_NSEC(camd_node) = CAMD_REQ_TIMEOUT_NSEC(camd_req);
            CAMD_NODE_NTIME_MS(camd_node)     = CAMD_REQ_NTIME_MS(camd_req);

            /*pop the last one and save it*/
            camd_node_saved  = camd_req_pop_node_back(camd_req);

            /*bind: push back & mount*/
            camd_req_push_node_back(camd_req, camd_node);

            /*bind: push back & mount the saved one*/
            camd_req_push_node_back(camd_req, camd_node_saved);

            rd_flag = BIT_TRUE;
        }
    }

    CAMD_ASSERT(clist_size(CAMD_REQ_NODES(camd_req)) == CAMD_REQ_SUB_SEQ_NUM(camd_req));

    /*if some read op inserted, re-order sub seq no. */
    /*here re-order always for debug purpose due to recording sub seq num info in node*/
    if(BIT_TRUE == rd_flag)
    {
        camd_req_reorder_sub_seq_no(camd_req);
    }
    else
    {
        camd_req_reorder_sub_seq_no(camd_req);
    }

    CAMD_REQ_NODE_NUM(camd_req) = CAMD_REQ_SUB_SEQ_NUM(camd_req); /*init*/

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_make_write: "
                                         "make %ld ops of req %ld, op %s done\n",
                                         CAMD_REQ_SUB_SEQ_NUM(camd_req),
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));
    return (EC_TRUE);
}

EC_BOOL camd_req_timeout(CAMD_REQ *camd_req)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_timeout: "
                     "req %ld, file range [%ld, %ld), op %s, "
                     "timeout %ld seconds, next access time %ld => timeout\n",
                     CAMD_REQ_SEQ_NO(camd_req),
                     CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                     __camd_op_str(CAMD_REQ_OP(camd_req)),
                     CAMD_REQ_TIMEOUT_NSEC(camd_req), CAMD_REQ_NTIME_MS(camd_req));

    /*determine offset & clean up nodes*/
    while(NULL_PTR != (camd_node = camd_req_pop_node_back(camd_req)))
    {
        /*update upper offset at most*/
        if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_E_OFFSET(camd_req))
        {
            CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
        }

        camd_node_free(camd_node);
    }

    if(CAMD_REQ_U_E_OFFSET(camd_req) < CAMD_REQ_F_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_REQ_F_S_OFFSET(camd_req);
    }

    (*CAMD_REQ_OFFSET(camd_req)) = CAMD_REQ_U_E_OFFSET(camd_req);

    /*post timeout event*/
    camd_req_set_post_event(camd_req, (CAMD_EVENT_HANDLER)camd_req_exec_timeout_handler);

    return (EC_TRUE);
}

EC_BOOL camd_req_terminate(CAMD_REQ *camd_req)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_terminate: "
                     "req %ld, file range [%ld, %ld), op %s terminate\n",
                     CAMD_REQ_SEQ_NO(camd_req),
                     CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                     __camd_op_str(CAMD_REQ_OP(camd_req)));

    /*determine offset & clean up nodes*/
    while(NULL_PTR != (camd_node = camd_req_pop_node_back(camd_req)))
    {
        /*update upper offset at most*/
        if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_E_OFFSET(camd_req))
        {
            CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
        }

        camd_node_free(camd_node);
    }

    if(CAMD_REQ_U_E_OFFSET(camd_req) < CAMD_REQ_F_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_REQ_F_S_OFFSET(camd_req);
    }

    (*CAMD_REQ_OFFSET(camd_req)) = CAMD_REQ_U_E_OFFSET(camd_req);

    /*post terminate event*/
    camd_req_set_post_event(camd_req, (CAMD_EVENT_HANDLER)camd_req_exec_terminate_handler);

    return (EC_TRUE);
}

EC_BOOL camd_req_complete(CAMD_REQ *camd_req)
{
    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_complete: "
                     "req %ld, file range [%ld, %ld), op %s complete\n",
                     CAMD_REQ_SEQ_NO(camd_req),
                     CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                     __camd_op_str(CAMD_REQ_OP(camd_req)));

    /*determine offset*/

    /*check validity*/
    CAMD_ASSERT(0 == clist_size(CAMD_REQ_NODES(camd_req)));
    CAMD_ASSERT(CAMD_REQ_SUCC_NUM(camd_req) == CAMD_REQ_SUB_SEQ_NUM(camd_req));

    if(CAMD_REQ_U_E_OFFSET(camd_req) < CAMD_REQ_F_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_E_OFFSET(camd_req) = CAMD_REQ_F_S_OFFSET(camd_req);
    }

    (*CAMD_REQ_OFFSET(camd_req)) = CAMD_REQ_U_E_OFFSET(camd_req);

    /*post complete event*/
    camd_req_set_post_event(camd_req, (CAMD_EVENT_HANDLER)camd_req_exec_complete_handler);

    return (EC_TRUE);
}

EC_BOOL camd_req_dispatch_node(CAMD_REQ *camd_req, CAMD_NODE *camd_node)
{
    CAMD_MD     *camd_md;
    CAMD_PAGE   *camd_page;

    camd_md = CAMD_REQ_CAMD_MD(camd_req);

    camd_page = camd_search_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), CAMD_NODE_FD(camd_node),
                                CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node));
    if(NULL_PTR != camd_page)
    {
        if(EC_FALSE == camd_page_add_node(camd_page, camd_node))
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "error:camd_req_dispatch_node: "
                             "dispatch node %ld/%ld of req %ld, op %s to existing page [%ld, %ld) failed\n",
                             CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                             CAMD_NODE_SEQ_NO(camd_node),
                             __camd_op_str(CAMD_NODE_OP(camd_node)),
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_dispatch_node: "
                         "dispatch node %ld/%ld of req %ld, op %s to existing page [%ld, %ld) done\n",
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node),
                         __camd_op_str(CAMD_NODE_OP(camd_node)),
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        return (EC_TRUE);
    }

    CAMD_ASSERT(NULL_PTR == camd_search_page(camd_md, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md),
                                CAMD_NODE_FD(camd_node),
                                CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node)));

    /*create new page*/

    camd_page = camd_page_new();
    if(NULL_PTR == camd_page)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_dispatch_node: "
                         "new page [%ld, %ld) for node %ld/%ld of req %ld, op %s failed\n",
                         CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node),
                         __camd_op_str(CAMD_NODE_OP(camd_node)));

        return (EC_FALSE);
    }

    /*inherited data from node*/
    CAMD_PAGE_FD(camd_page)             = CAMD_NODE_FD(camd_node);
    CAMD_PAGE_F_S_OFFSET(camd_page)     = CAMD_NODE_F_S_OFFSET(camd_node);
    CAMD_PAGE_F_E_OFFSET(camd_page)     = CAMD_NODE_F_E_OFFSET(camd_node);
    CAMD_PAGE_OP(camd_page)             = CAMD_NODE_OP(camd_node);
    CAMD_PAGE_TIMEOUT_NSEC(camd_page)   = CAMD_AIO_TIMEOUT_NSEC_DEFAULT;
    CAMD_PAGE_CAMD_MD(camd_page)        = CAMD_NODE_CAMD_MD(camd_node);

    /*add page to camd module*/
    if(EC_FALSE == camd_add_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_dispatch_node: "
                         "add page [%ld, %ld) to camd module failed\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));


        camd_page_free(camd_page);
        return (EC_FALSE);
    }

    /*add node to page*/
    if(EC_FALSE == camd_page_add_node(camd_page, camd_node))
    {
        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "error:camd_req_dispatch_node: "
                         "dispatch node %ld/%ld of req %ld, op %s to new page [%ld, %ld) failed\n",
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node),
                         __camd_op_str(CAMD_NODE_OP(camd_node)),
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        camd_del_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page);
        camd_page_free(camd_page);
        return (EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_dispatch_node: "
                     "dispatch node %ld/%ld of req %ld, op %s to new page [%ld, %ld) done\n",
                     CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                     CAMD_NODE_SEQ_NO(camd_node),
                     __camd_op_str(CAMD_NODE_OP(camd_node)),
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    return (EC_TRUE);
}

EC_BOOL camd_req_cancel_node(CAMD_REQ *camd_req, CAMD_NODE *camd_node)
{
    if(NULL_PTR != CAMD_NODE_MOUNTED_OWNERS(camd_node)
    && NULL_PTR != CAMD_NODE_CAMD_PAGE(camd_node))
    {
        /*delete node from page*/
        camd_page_del_node(CAMD_NODE_CAMD_PAGE(camd_node), camd_node);
    }

    /*delete node from req*/
    camd_req_del_node(camd_req, camd_node);

    CAMD_ASSERT(CAMD_NODE_SEQ_NO(camd_node) == CAMD_REQ_SEQ_NO(camd_req));

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_cancel_node: "
                    "cancel node %ld/%ld of req %ld, op %s done\n",
                    CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                    CAMD_NODE_SEQ_NO(camd_node),
                    __camd_op_str(CAMD_REQ_OP(camd_req)));

    return (EC_TRUE);
}

/*----------------------------------- camd module interface -----------------------------------*/

CAMD_MD *camd_start(const int sata_disk_fd, const UINT32 sata_disk_size /*in byte*/,
                       const UINT32 mem_disk_size /*in byte*/,
                       const int ssd_disk_fd, const UINT32 ssd_disk_offset, const UINT32 ssd_disk_size/*in byte*/)
{
    CAMD_MD      *camd_md;
    UINT32        aio_model;

    aio_model = CAIO_MODEL_CHOICE;

    /* initialize new one camd module */
    camd_md = safe_malloc(sizeof(CAMD_MD), LOC_CAMD_0009);
    if(NULL_PTR == camd_md)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: malloc camd module failed\n");
        return (NULL_PTR);
    }

    CAMD_MD_CAIO_MD(camd_md) = NULL_PTR;
    CAMD_MD_CMC_MD(camd_md)  = NULL_PTR;
    CAMD_MD_CDC_MD(camd_md)  = NULL_PTR;
    CAMD_MD_SEQ_NO(camd_md)  = 0;

    clist_init(CAMD_MD_REQ_LIST(camd_md), MM_CAMD_REQ, LOC_CAMD_0010);

    CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md) = 0;   /*set page tree[0] is active*/
    crb_tree_init(CAMD_MD_PAGE_TREE(camd_md, 0), /*init active page tree*/
                  (CRB_DATA_CMP)camd_page_cmp,
                  (CRB_DATA_FREE)NULL_PTR, /*note: not define*/
                  (CRB_DATA_PRINT)camd_page_print);

    crb_tree_init(CAMD_MD_PAGE_TREE(camd_md, 1), /*init standby page tree*/
                  (CRB_DATA_CMP)camd_page_cmp,
                  (CRB_DATA_FREE)NULL_PTR, /*note: not define*/
                  (CRB_DATA_PRINT)camd_page_print);

    clist_init(CAMD_MD_POST_EVENT_REQS(camd_md), MM_CAMD_REQ, LOC_CAMD_0011);

    CAMD_MD_CAIO_MD(camd_md) = caio_start(aio_model);
    if(NULL_PTR == CAMD_MD_CAIO_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: start caio module failed\n");

        camd_end(camd_md);
        return (NULL_PTR);
    }

    if(ERR_FD != sata_disk_fd && 0 != sata_disk_size)
    {
        caio_add_disk(CAMD_MD_CAIO_MD(camd_md), sata_disk_fd, &CAMD_SATA_AIO_REQ_MAX_NUM_RAW);
    }

    if(0 != mem_disk_size)
    {
        CAMD_MD_CMC_MD(camd_md) = cmc_start(mem_disk_size, sata_disk_size);
        if(NULL_PTR == CAMD_MD_CMC_MD(camd_md))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: start cmc module failed\n");

            camd_end(camd_md);
            return (NULL_PTR);
        }
    }

    if(ERR_FD != ssd_disk_fd && 0 != ssd_disk_size)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "[DEBUG] camd_start: "
                                             "ssd_disk_fd = %d, ssd_disk_size = %ld\n",
                                             ssd_disk_fd, ssd_disk_size);

        if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
        {
            /*set degrade callback*/
            cmc_set_degrade_callback(CAMD_MD_CMC_MD(camd_md),
                                    (CMCNP_DEGRADE_CALLBACK)camd_ssd_flush, (void *)camd_md);
        }

        if(SWITCH_ON == CAMD_SYNC_CDC_SWITCH)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "[DEBUG] amd_start: cdc disable aio\n");

            CAMD_MD_CDC_MD(camd_md) = cdc_start(ssd_disk_fd, ssd_disk_offset, ssd_disk_size,
                                                sata_disk_fd, sata_disk_size);
            if(NULL_PTR == CAMD_MD_CDC_MD(camd_md))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: start cdc module failed\n");

                camd_end(camd_md);
                return (NULL_PTR);
            }
            /*cdc not bind aio => cdc disable aio*/
        }
        else
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "[DEBUG] camd_start: cdc enable aio\n");

            CAMD_MD_CDC_MD(camd_md) = cdc_start(ssd_disk_fd, ssd_disk_offset, ssd_disk_size,
                                                sata_disk_fd, sata_disk_size);
            if(NULL_PTR == CAMD_MD_CDC_MD(camd_md))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: start cdc module failed\n");

                camd_end(camd_md);
                return (NULL_PTR);
            }

            caio_add_disk(CAMD_MD_CAIO_MD(camd_md), ssd_disk_fd, &CAMD_SSD_AIO_REQ_MAX_NUM_RAW);

            if(SWITCH_ON == CDC_BIND_AIO_SWITCH)
            {
                /*async model*/
                /*cdc bind aio => cdc enable aio*/
                if(EC_FALSE == cdc_bind_aio(CAMD_MD_CDC_MD(camd_md), CAMD_MD_CAIO_MD(camd_md)))
                {
                    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: bind caio module to cdc module failed\n");

                    camd_end(camd_md);
                    return (NULL_PTR);
                }
            }
        }

        cdc_set_degrade_callback(CAMD_MD_CDC_MD(camd_md),
                                 (CDCNP_DEGRADE_CALLBACK)camd_sata_flush, (void *)camd_md);
    }
    else /*no ssd cache*/
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "[DEBUG] camd_start: "
                                             "no ssd cache\n");

        if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
        {
            /*set degrade callback*/
            cmc_set_degrade_callback(CAMD_MD_CMC_MD(camd_md),
                                    (CMCNP_DEGRADE_CALLBACK)camd_sata_degrade, (void *)camd_md);
        }
    }

    CAMD_MD_FORCE_DIO_FLAG(camd_md) = BIT_FALSE;
    CAMD_MD_SATA_DISK_FD(camd_md)   = sata_disk_fd;

    cfc_init(CAMD_MD_SATA_READ_FC(camd_md));
    cfc_init(CAMD_MD_SATA_WRITE_FC(camd_md));
    cfc_init(CAMD_MD_SSD_FC(camd_md));
    cfc_init(CAMD_MD_MEM_FC(camd_md));
    cfc_init(CAMD_MD_AMD_READ_FC(camd_md));
    cfc_init(CAMD_MD_AMD_WRITE_FC(camd_md));

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_start: start camd module %p\n", camd_md);

    return (camd_md);
}

void camd_end(CAMD_MD *camd_md)
{
    if(NULL_PTR != camd_md)
    {
        while(EC_FALSE == camd_try_quit(camd_md))
        {
            c_usleep(20 /*msec*/, LOC_NONE_BASE);
        }

        camd_poll(camd_md);

        camd_cleanup_pages(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md));
        camd_cleanup_pages(camd_md, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md));
        CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md) = 0;

        camd_cleanup_reqs(camd_md);
        camd_cleanup_post_event_reqs(camd_md);

        if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
        {
            if(SWITCH_OFF == CAMD_SYNC_CDC_SWITCH
            && SWITCH_ON == CDC_BIND_AIO_SWITCH)
            {
                cdc_unbind_aio(CAMD_MD_CDC_MD(camd_md));
            }
            cdc_end(CAMD_MD_CDC_MD(camd_md));
            CAMD_MD_CDC_MD(camd_md) = NULL_PTR;
        }

        if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
        {
            caio_end(CAMD_MD_CAIO_MD(camd_md));
            CAMD_MD_CAIO_MD(camd_md) = NULL_PTR;
        }

        if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
        {
            cmc_end(CAMD_MD_CMC_MD(camd_md));
            CAMD_MD_CMC_MD(camd_md) = NULL_PTR;
        }

        CAMD_MD_SEQ_NO(camd_md) = 0;

        CAMD_MD_FORCE_DIO_FLAG(camd_md) = BIT_FALSE;
        CAMD_MD_SATA_DISK_FD(camd_md)   = ERR_FD;

        cfc_clean(CAMD_MD_SATA_READ_FC(camd_md));
        cfc_clean(CAMD_MD_SATA_WRITE_FC(camd_md));
        cfc_clean(CAMD_MD_SSD_FC(camd_md));
        cfc_clean(CAMD_MD_MEM_FC(camd_md));
        cfc_clean(CAMD_MD_AMD_READ_FC(camd_md));
        cfc_clean(CAMD_MD_AMD_WRITE_FC(camd_md));

        safe_free(camd_md, LOC_CAMD_0012);
    }

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "[DEBUG] camd_end: stop camd module %p\n", camd_md);

    return;
}

EC_BOOL camd_create(const CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        if(EC_FALSE == cdc_create(CAMD_MD_CDC_MD(camd_md)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_create: create cdc failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_create: create cdc done\n");
        return (EC_TRUE);
    }
    return (EC_TRUE);
}

EC_BOOL camd_load(const CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        if(EC_FALSE == cdc_load(CAMD_MD_CDC_MD(camd_md)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_load: load cdc failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_load: load cdc done\n");
        return (EC_TRUE);
    }
    return (EC_TRUE);
}


void camd_print(LOG *log, const CAMD_MD *camd_md)
{
    if(NULL_PTR != camd_md)
    {
        sys_log(log, "camd_print: camd_md %p: caio_md :\n", camd_md);
        caio_print(log, CAMD_MD_CAIO_MD(camd_md));

        sys_log(log, "camd_print: camd_md %p: cmc_md :\n", camd_md);
        cmc_print(log, CAMD_MD_CMC_MD(camd_md));

        sys_log(log, "camd_print: camd_md %p: seq_no: %ld\n", camd_md, CAMD_MD_SEQ_NO(camd_md));

        sys_log(log, "camd_print: camd_md %p: %ld reqs:\n",
                     camd_md, clist_size(CAMD_MD_REQ_LIST(camd_md)));
        if(0)
        {
            camd_show_reqs(log, camd_md);
        }

        sys_log(log, "camd_print: camd_md %p: %u active pages:\n",
                     camd_md, crb_tree_node_num(CAMD_MD_PAGE_TREE(camd_md, 0)));

        sys_log(log, "camd_print: camd_md %p: %u standby pages:\n",
                     camd_md, crb_tree_node_num(CAMD_MD_PAGE_TREE(camd_md, 1)));
        if(0)
        {
            camd_show_pages(log, camd_md);
        }

        sys_log(log, "camd_print: camd_md %p: %ld post event reqs: \n",
                     camd_md, clist_size(CAMD_MD_POST_EVENT_REQS(camd_md)));

        if(0)
        {
            camd_show_post_event_reqs(log, camd_md);
        }
    }

    return;
}

/*note: register eventfd and event handler to epoll READ event*/
int camd_get_eventfd(CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        return caio_get_eventfd(CAMD_MD_CAIO_MD(camd_md));
    }

    return (ERR_FD);
}

/*note: register eventfd and event handler to epoll READ event*/
EC_BOOL camd_event_handler(CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        return caio_event_handler(CAMD_MD_CAIO_MD(camd_md));
    }

    return (EC_TRUE);
}

int camd_cdc_get_eventfd(CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        return cdc_get_eventfd(CAMD_MD_CDC_MD(camd_md));
    }

    return (ERR_FD);
}

EC_BOOL camd_cdc_event_handler(CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        return cdc_event_handler(CAMD_MD_CDC_MD(camd_md));
    }

    return (EC_TRUE);
}

EC_BOOL camd_try_quit(CAMD_MD *camd_md)
{
    static UINT32  warning_counter = 0; /*suppress warning report*/

    CAMD_MD_FORCE_DIO_FLAG(camd_md) = BIT_TRUE; /*set force dio*/

    camd_process(camd_md); /*process once*/

    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        if(EC_FALSE == caio_try_quit(CAMD_MD_CAIO_MD(camd_md)))
        {
            if(0 == (warning_counter % 1000))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_try_quit:"
                                                     "caio try quit failed\n");

            }
            warning_counter ++;

            return (EC_FALSE);
        }
    }

    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        if(EC_FALSE == cmc_try_quit(CAMD_MD_CMC_MD(camd_md)))
        {
            if(0 == (warning_counter % 1000))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_try_quit:"
                                                     "cmc try quit failed\n");
            }

            warning_counter ++;

            return (EC_FALSE);
        }
    }

    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        if(EC_FALSE == cdc_try_quit(CAMD_MD_CDC_MD(camd_md)))
        {
            if(0 == (warning_counter % 1000))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_try_quit:"
                                                     "cdc try quit failed\n");
            }

            warning_counter ++;

            return (EC_FALSE);
        }
    }

    warning_counter = 0;

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "[DEBUG] camd_try_quit: succ\n");

    return (EC_TRUE);
}

/*for debug*/
EC_BOOL camd_poll(CAMD_MD *camd_md)
{
    camd_process_pages(camd_md);
    camd_process_events(camd_md);
    camd_process_reqs(camd_md);

    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        caio_poll(CAMD_MD_CAIO_MD(camd_md));
    }

    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        /*not need poll, process only*/
        cmc_process(CAMD_MD_CMC_MD(camd_md), (uint64_t)0, (uint64_t)~0, (uint64_t)~0);
    }

    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        cdc_poll(CAMD_MD_CDC_MD(camd_md));
    }

    return (EC_TRUE);
}

/*for debug only!*/
EC_BOOL camd_poll_debug(CAMD_MD *camd_md)
{
    camd_process_pages(camd_md);
    camd_process_events(camd_md);
    camd_process_reqs(camd_md);

    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        caio_poll(CAMD_MD_CAIO_MD(camd_md));
    }

    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        /*not need poll, process only*/
        //cmc_process(CAMD_MD_CMC_MD(camd_md), (uint64_t)0, (uint64_t)~0, (uint64_t)~0);
    }

    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        cdc_poll_debug(CAMD_MD_CDC_MD(camd_md));
    }

    return (EC_TRUE);
}
void camd_process(CAMD_MD *camd_md)
{
    uint64_t    ssd_traffic_bps;
    uint64_t    mem_traffic_bps;
    uint64_t    amd_read_traffic_bps;
    uint64_t    amd_write_traffic_bps;
    uint64_t    sata_read_traffic_bps;
    uint64_t    sata_write_traffic_bps;

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CAIO_MD(camd_md)); /*for debug checking*/
    CAMD_ASSERT(NULL_PTR != CAMD_MD_CMC_MD(camd_md));  /*for debug checking*/
    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));  /*for debug checking*/

    camd_process_pages(camd_md);
    camd_process_events(camd_md);
    camd_process_reqs(camd_md);

    if(BIT_FALSE == CAMD_MD_FORCE_DIO_FLAG(camd_md))
    {
        ssd_traffic_bps        = cfc_get_speed(CAMD_MD_SSD_FC(camd_md));
        mem_traffic_bps        = cfc_get_speed(CAMD_MD_MEM_FC(camd_md));
        amd_read_traffic_bps   = cfc_get_speed(CAMD_MD_AMD_READ_FC(camd_md));
        amd_write_traffic_bps  = cfc_get_speed(CAMD_MD_AMD_WRITE_FC(camd_md));
        sata_read_traffic_bps  = cfc_get_speed(CAMD_MD_SATA_READ_FC(camd_md));
        sata_write_traffic_bps = cfc_get_speed(CAMD_MD_SATA_WRITE_FC(camd_md));
    }
    else
    {
        ssd_traffic_bps        = ((uint64_t)~0);
        mem_traffic_bps        = ((uint64_t)~0);
        amd_read_traffic_bps   = ((uint64_t) 0); /*no read*/
        amd_write_traffic_bps  = ((uint64_t) 0); /*no write*/
        sata_read_traffic_bps  = ((uint64_t) 0); /*no read*/
        sata_write_traffic_bps = ((uint64_t) 0); /*no write*/
    }

    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        caio_process(CAMD_MD_CAIO_MD(camd_md));
    }

    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        if(0 == amd_read_traffic_bps)
        {
            if(0 < mem_traffic_bps)
            {
                mem_traffic_bps = DMAX(mem_traffic_bps, CMC_DEGRADE_TRAFFIC_30MB);
            }

            /*else mem_traffic_bps is 0*/
        }

        cmc_process(CAMD_MD_CMC_MD(camd_md), mem_traffic_bps,
                    amd_read_traffic_bps, amd_write_traffic_bps);
    }

    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        if(amd_write_traffic_bps < CDC_DEGRADE_TRAFFIC_10MB)
        {
            ssd_traffic_bps = DMAX(ssd_traffic_bps, CDC_DEGRADE_TRAFFIC_20MB);
        }
        cdc_process(CAMD_MD_CDC_MD(camd_md), ssd_traffic_bps,
                    amd_read_traffic_bps, amd_write_traffic_bps,
                    sata_read_traffic_bps, sata_write_traffic_bps);
    }

    if(1)
    {
        static uint64_t              time_msec_handled = 0; /*init*/
        uint64_t                     time_msec_cur;
        uint64_t                     time_msec_interval;

        time_msec_cur = c_get_cur_time_msec(); /*current time in msec*/

        /*memory breath*/
        time_msec_interval = 60 * 1000;
        if(time_msec_cur >= time_msec_handled + time_msec_interval)
        {
            breathing_static_mem(); /*breath memory per minute*/

            if(0 == time_msec_handled)
            {
                time_msec_handled = time_msec_cur;
            }
            else
            {
                /*note:
                 *   here time_msec_handled inc 60 but not update to time_msec_cur
                 *   to avoid time deviation accumulated
                 */
                time_msec_handled += time_msec_interval;
            }
        }

        /*flow control*/
        time_msec_interval = CAMD_FLOW_CONTROL_NSEC * 1000;
        cfc_calc_speed(CAMD_MD_SATA_READ_FC(camd_md), time_msec_cur, time_msec_interval);
        cfc_calc_speed(CAMD_MD_SATA_WRITE_FC(camd_md), time_msec_cur, time_msec_interval);
        cfc_calc_speed(CAMD_MD_SSD_FC(camd_md), time_msec_cur, time_msec_interval);
        cfc_calc_speed(CAMD_MD_MEM_FC(camd_md), time_msec_cur, time_msec_interval);
        cfc_calc_speed(CAMD_MD_AMD_READ_FC(camd_md), time_msec_cur, time_msec_interval);
        cfc_calc_speed(CAMD_MD_AMD_WRITE_FC(camd_md), time_msec_cur, time_msec_interval);
    }

    return;
}

void camd_process_reqs(CAMD_MD *camd_md)
{
    camd_process_timeout_reqs(camd_md);
    return;
}

/*check and process timeout reqs*/
void camd_process_timeout_reqs(CAMD_MD *camd_md)
{
    CLIST_DATA      *clist_data;

    UINT32           req_num;
    uint64_t         cur_time_ms;

    cur_time_ms = c_get_cur_time_msec();
    req_num     = 0;

    CLIST_LOOP_NEXT(CAMD_MD_REQ_LIST(camd_md), clist_data)
    {
        CAMD_REQ       *camd_req;

        camd_req = (CAMD_REQ *)CLIST_DATA_DATA(clist_data);
        CAMD_ASSERT(CAMD_REQ_MOUNTED_REQS(camd_req) == clist_data);

        if(cur_time_ms >= CAMD_REQ_NTIME_MS(camd_req))
        {
            clist_data = CLIST_DATA_PREV(clist_data);

            req_num ++;

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_timeout_reqs: "
                             "req %ld, file range [%ld, %ld), op %s timeout\n",
                             CAMD_REQ_SEQ_NO(camd_req),
                             CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req),
                             __camd_op_str(CAMD_REQ_OP(camd_req)));

            camd_del_req(camd_md, camd_req);
            camd_req_timeout(camd_req);
        }
    }

    dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_timeout_reqs: process %ld timeout reqs\n", req_num);

    return;
}


void camd_process_pages(CAMD_MD *camd_md)
{
    CAMD_PAGE       *camd_page;

    UINT32           active_page_tree_idx;
    UINT32           standby_page_tree_idx;

    active_page_tree_idx  = CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md);
    standby_page_tree_idx = CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md);

    while(NULL_PTR != (camd_page = camd_pop_first_page(camd_md, active_page_tree_idx)))
    {
        if(BIT_TRUE == CAMD_PAGE_SATA_LOADING_FLAG(camd_page)
        || BIT_TRUE == CAMD_PAGE_SSD_LOADING_FLAG(camd_page))
        {
            /*add to standby page tree temporarily*/
            camd_add_page(camd_md, standby_page_tree_idx, camd_page);
            continue;
        }

        camd_process_page(camd_md, camd_page);
    }

    /*switch page tree*/
    CAMD_MD_SWITCH_PAGE_TREE(camd_md);

    CAMD_ASSERT(EC_FALSE == camd_has_page(camd_md, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md)));

    return;
}

void camd_process_page(CAMD_MD *camd_md, CAMD_PAGE *camd_page)
{
    /*retry page*/
    if(BIT_TRUE == CAMD_PAGE_MEM_CACHE_FLAG(camd_page)
    || BIT_TRUE == CAMD_PAGE_SATA_LOADED_FLAG(camd_page)
    || BIT_TRUE == CAMD_PAGE_SSD_LOADED_FLAG(camd_page))
    {
        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                             "process page [%ld, %ld) again\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));

        /*page life cycle is determined by process => not need to free page*/

        camd_page_process(camd_page, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md));

        /*here page may not be accessable => not output log info*/
        return;
    }

    /*check page in mem cache*/
    while(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        CMC_MD      *cmc_md;
        CMCNP_KEY    cmcnp_key;
        UINT32       offset;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        CAMD_ASSERT(0 == (CAMD_PAGE_F_S_OFFSET(camd_page) & ((UINT32)CMCPGB_PAGE_SIZE_MASK)));
        CAMD_ASSERT(0 == (CAMD_PAGE_F_E_OFFSET(camd_page) & ((UINT32)CMCPGB_PAGE_SIZE_MASK)));

        CMCNP_KEY_S_PAGE(&cmcnp_key) = (uint32_t)(CAMD_PAGE_F_S_OFFSET(camd_page) >> CMCPGB_PAGE_SIZE_NBITS);
        CMCNP_KEY_E_PAGE(&cmcnp_key) = (uint32_t)(CAMD_PAGE_F_E_OFFSET(camd_page) >> CMCPGB_PAGE_SIZE_NBITS);

        if(EC_FALSE == cmc_search(cmc_md, &cmcnp_key))
        {
            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                 "mem miss page [%ld, %ld)\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            /*fall through to aio*/
            break;
        }

        /*load page from mem cache*/
        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

        if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
        {
            /*scenario: shortcut to mem cache page*/
            CAMD_PAGE_M_CACHE(camd_page) = cmc_file_locate(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES);
            if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
            {
                dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                     "mem hit page [%ld, %ld) "
                                                     "but locate failed\n",
                                                     CAMD_PAGE_F_S_OFFSET(camd_page),
                                                     CAMD_PAGE_F_E_OFFSET(camd_page));

                /*fall through to aio*/
                break;
            }

            CAMD_ASSERT(EC_TRUE == __camd_mem_cache_check(CAMD_PAGE_M_CACHE(camd_page)));

            CAMD_PAGE_MEM_CACHE_FLAG(camd_page) = BIT_TRUE;

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                 "mem hit page [%ld, %ld) "
                                                 "locate done\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            if(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES != offset)
            {
                dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                     "mem hit page [%ld, %ld) "
                                                     "but expected offset %ld != %ld\n",
                                                     CAMD_PAGE_F_S_OFFSET(camd_page),
                                                     CAMD_PAGE_F_E_OFFSET(camd_page),
                                                     CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES,
                                                     offset);

                CAMD_PAGE_M_CACHE(camd_page)        = NULL_PTR; /*clear*/
                CAMD_PAGE_MEM_CACHE_FLAG(camd_page) = BIT_FALSE;/*clear*/

                /*fall through to aio*/
                break;
            }

            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                 "mem hit page [%ld, %ld) [crc %u] %p\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page),
                                                 CAMD_CRC32(CAMD_PAGE_M_CACHE(camd_page), CMCPGB_PAGE_SIZE_NBYTES),
                                                 CAMD_PAGE_M_CACHE(camd_page));
        }

        /*page life cycle is determined by process => not need to free page*/
        if(EC_FALSE == camd_page_process(camd_page, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: "
                                                 "process page [%ld, %ld) failed\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));
            return;
        }

        /*here page may not be accessable => not output log info*/
        return;
    }

    if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
    {
        CAMD_PAGE_M_CACHE(camd_page) = __camd_mem_cache_new(CMCPGB_PAGE_SIZE_NBYTES);
        if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: "
                             "new mem cache for page [%ld, %ld) failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            camd_page_terminate(camd_page);
            camd_page_free(camd_page);
            return;
        }
    }

    /*optimize: reduce ssd or sata loading*/
    if(CAMD_OP_WR == CAMD_PAGE_OP(camd_page)
    && CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page))
    {
        /*page life cycle is determined by process => not need to free page*/
        if(EC_FALSE == camd_page_process(camd_page, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: "
                                                 "process page [%ld, %ld) failed\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));
            return;
        }

        /*here page may not be accessable => not output log info*/
        return;
    }

    /*check page in ssd cache*/
    while(NULL_PTR != CAMD_MD_CDC_MD(camd_md)
    && BIT_FALSE == CAMD_PAGE_SSD_LOADED_FLAG(camd_page))
    {
        CDC_MD      *cdc_md;
        CDCNP_KEY    cdcnp_key;

        cdc_md = CAMD_MD_CDC_MD(camd_md);

        CAMD_ASSERT(0 == (CAMD_PAGE_F_S_OFFSET(camd_page) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
        CAMD_ASSERT(0 == (CAMD_PAGE_F_E_OFFSET(camd_page) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

        CDCNP_KEY_S_PAGE(&cdcnp_key) = (CAMD_PAGE_F_S_OFFSET(camd_page) >> CDCPGB_PAGE_SIZE_NBITS);
        CDCNP_KEY_E_PAGE(&cdcnp_key) = (CAMD_PAGE_F_E_OFFSET(camd_page) >> CDCPGB_PAGE_SIZE_NBITS);

        if(EC_FALSE == cdc_search(cdc_md, &cdcnp_key))
        {
            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                 "ssd miss page [%ld, %ld)\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            /*fall through to aio*/
            break;
        }

        dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                             "ssd hit page [%ld, %ld)\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));

        /*aio load page from ssd*/
        if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md)
        && BIT_FALSE == CAMD_MD_FORCE_DIO_FLAG(camd_md))
        {
            if(EC_FALSE == camd_page_load_ssd_aio(camd_page))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: "
                                                     "submit ssd loading page [%ld, %ld) failed\n",
                                                     CAMD_PAGE_F_S_OFFSET(camd_page),
                                                     CAMD_PAGE_F_E_OFFSET(camd_page));

                /*fall through to aio*/
                break;
            }

            /*add page to standby page tree temporarily*/
            camd_add_page(camd_md, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md), camd_page);
            CAMD_PAGE_SSD_LOADING_FLAG(camd_page)  = BIT_TRUE; /*set flag*/

            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                 "submit ssd loading page [%ld, %ld) done\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));
        }
        else/*direct io load page from ssd*/
        {
            UINT32      offset;

            offset = CAMD_PAGE_F_S_OFFSET(camd_page);
            if(EC_FALSE == cdc_file_read(cdc_md, &offset, CDCPGB_PAGE_SIZE_NBYTES, CAMD_PAGE_M_CACHE(camd_page)))
            {
                dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                     "ssd hit page [%ld, %ld) "
                                                     "but read failed\n",
                                                     CAMD_PAGE_F_S_OFFSET(camd_page),
                                                     CAMD_PAGE_F_E_OFFSET(camd_page));

                /*fall through to aio*/
                break;
            }

            if(CAMD_PAGE_F_S_OFFSET(camd_page) + CDCPGB_PAGE_SIZE_NBYTES != offset)
            {
                dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                                     "ssd hit page [%ld, %ld) "
                                                     "but expected offset %ld != %ld\n",
                                                     CAMD_PAGE_F_S_OFFSET(camd_page),
                                                     CAMD_PAGE_F_E_OFFSET(camd_page),
                                                     CAMD_PAGE_F_S_OFFSET(camd_page) + CDCPGB_PAGE_SIZE_NBYTES,
                                                     offset);

                /*fall through to aio*/
                break;
            }

            CAMD_PAGE_SSD_LOADED_FLAG(camd_page) = BIT_TRUE; /*set ssd loaded*/

            /*page life cycle is determined by process => not need to free page*/
            if(EC_FALSE == camd_page_process(camd_page, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md)))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: "
                                                     "process page [%ld, %ld) failed\n",
                                                     CAMD_PAGE_F_S_OFFSET(camd_page),
                                                     CAMD_PAGE_F_E_OFFSET(camd_page));
                return;
            }
        }

        /*here page may not be accessable => not output log info*/
        return;
    }

    if(BIT_FALSE == CAMD_MD_FORCE_DIO_FLAG(camd_md))
    {
        /*load page from sata to mem cache*/
        if(EC_FALSE == camd_page_load_sata_aio(camd_page))
        {
            /*page cannot be accessed again => do not output log*/
            return;
        }

        cfc_inc_traffic(CAMD_MD_SATA_READ_FC(camd_md), CMCPGB_PAGE_SIZE_NBYTES);

        /*add page to standby page tree temporarily*/
        camd_add_page(camd_md, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md), camd_page);
        CAMD_PAGE_SATA_LOADING_FLAG(camd_page)  = BIT_TRUE; /*set flag*/

        dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: "
                                             "submit sata loading page [%ld, %ld) done\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));

        /*camd_page would be free later*/
    }
    else /*dio*/
    {
        /*init temp offset*/
        CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);

        CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

        cfc_inc_traffic(CAMD_MD_SATA_READ_FC(camd_md), CMCPGB_PAGE_SIZE_NBYTES);

        if(EC_TRUE == c_file_pread(CAMD_PAGE_FD(camd_page),
                                  &CAMD_PAGE_F_T_OFFSET(camd_page),
                                  CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                                  CAMD_PAGE_M_CACHE(camd_page)))
        {
            CAMD_PAGE_SATA_LOADED_FLAG(camd_page)  = BIT_TRUE;  /*set sata loaded*/
            CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

            /*free camd page determined by process*/
            camd_page_process(camd_page, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md));
        }
        else
        {
            CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

            camd_page_terminate(camd_page);
            camd_page_free(camd_page);
        }
    }
    return;
}

void camd_process_events(CAMD_MD *camd_md)
{
    camd_process_post_event_reqs(camd_md, CAMD_PROCESS_EVENT_ONCE_NUM);

    return;
}

void camd_process_post_event_reqs(CAMD_MD *camd_md, const UINT32 process_event_max_num)
{
    CAMD_REQ        *camd_req;
    UINT32           counter;
    UINT32           event_num;
    UINT32           max_num;

    event_num = clist_size(CAMD_MD_POST_EVENT_REQS(camd_md));
    max_num   = DMIN(event_num, process_event_max_num);
    counter   = 0;

    while(counter < max_num
    && NULL_PTR != (camd_req = clist_pop_front(CAMD_MD_POST_EVENT_REQS(camd_md))))
    {
        CAMD_EVENT_HANDLER      handler;

        counter ++;

        CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req) = NULL_PTR;

        handler = CAMD_REQ_POST_EVENT_HANDLER(camd_req);  /*save*/
        CAMD_REQ_POST_EVENT_HANDLER(camd_req) = NULL_PTR; /*clear*/

        /*note: node may be push back to list*/
        handler(camd_req);
    }

    dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_post_event_reqs: process %ld reqs\n", counter);

    return;
}

void camd_show_pages(LOG *log, const CAMD_MD *camd_md)
{
    //crb_tree_print(log, CAMD_MD_PAGE_TREE(camd_md));
    crb_tree_print_in_order(log, CAMD_MD_PAGE_TREE(camd_md, 0));
    crb_tree_print_in_order(log, CAMD_MD_PAGE_TREE(camd_md, 1));
    return;
}

void camd_show_post_event_reqs(LOG *log, const CAMD_MD *camd_md)
{
    clist_print(log, CAMD_MD_POST_EVENT_REQS(camd_md), (CLIST_DATA_DATA_PRINT)camd_req_print);
    return;
}

void camd_show_page(LOG *log, const CAMD_MD *camd_md, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CAMD_PAGE   *camd_page;

    camd_page = camd_search_page((CAMD_MD *)camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), fd, f_s_offset, f_e_offset);
    if(NULL_PTR == camd_page)
    {
        sys_log(log, "camd_show_req: (no matched req)\n");
        return;
    }

    camd_page_print(log, camd_page);
    return;
}


void camd_show_reqs(LOG *log, const CAMD_MD *camd_md)
{
    clist_print(log, CAMD_MD_REQ_LIST(camd_md), (CLIST_DATA_DATA_PRINT)camd_req_print);
    return;
}

void camd_show_req(LOG *log, const CAMD_MD *camd_md, const UINT32 seq_no)
{
    CAMD_REQ  *camd_req;

    camd_req = clist_search_data_front(CAMD_MD_REQ_LIST(camd_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)camd_req_is);


    if(NULL_PTR == camd_req)
    {
        sys_log(log, "camd_show_req: (none)\n");
        return;
    }

    camd_req_print(log, camd_req);
    return;
}

void camd_show_node(LOG *log, const CAMD_MD *camd_md, const UINT32 seq_no, const UINT32 sub_seq_no)
{
    CAMD_REQ  *camd_req;
    CAMD_NODE *camd_node;

    camd_req = clist_search_data_front(CAMD_MD_REQ_LIST(camd_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)camd_req_is);


    if(NULL_PTR == camd_req)
    {
        sys_log(log, "camd_show_req: (no matched req)\n");
        return;
    }

    camd_node = clist_search_data_front(CAMD_REQ_NODES(camd_req), (const void *)sub_seq_no,
                                        (CLIST_DATA_DATA_CMP)camd_node_is);

    if(NULL_PTR == camd_node)
    {
        sys_log(log, "camd_show_req: (none)\n");
        return;
    }

    camd_node_print(log, camd_node);
    return;
}

EC_BOOL camd_submit_req(CAMD_MD *camd_md, CAMD_REQ *camd_req)
{
    /*add req to request list of camd module*/
    if(EC_FALSE == camd_add_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_submit_req: add req %ld, op %s failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)));
        return (EC_FALSE);
    }

    /*make r/w ops of req*/
    if(EC_FALSE == camd_make_req_op(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_submit_req: make ops of req %ld, op %s failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)));
        return (EC_FALSE);
    }

    /*dispatch req which would bind each r/w op to specific page*/
    if(EC_FALSE == camd_dispatch_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_submit_req: dispatch req %ld, op %s failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_submit_req: submit req %ld, op %s done\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));
    return (EC_TRUE);
}

EC_BOOL camd_add_req(CAMD_MD *camd_md, CAMD_REQ *camd_req)
{
    CAMD_ASSERT(NULL_PTR == CAMD_REQ_MOUNTED_REQS(camd_req));

    /*push back*/
    CAMD_REQ_MOUNTED_REQS(camd_req) = clist_push_back(CAMD_MD_REQ_LIST(camd_md), (void *)camd_req);
    if(NULL_PTR == CAMD_REQ_MOUNTED_REQS(camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_add_req: push req %ld, op %s failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req),
                                             __camd_op_str(CAMD_REQ_OP(camd_req)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_add_req: push req %ld, op %s done\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));
    return (EC_TRUE);
}

EC_BOOL camd_del_req(CAMD_MD *camd_md, CAMD_REQ *camd_req)
{
    if(NULL_PTR != CAMD_REQ_MOUNTED_REQS(camd_req))
    {
        clist_erase(CAMD_MD_REQ_LIST(camd_md), CAMD_REQ_MOUNTED_REQS(camd_req));
        CAMD_REQ_MOUNTED_REQS(camd_req) = NULL_PTR;

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_del_req: req %ld, op %s\n",
                     CAMD_REQ_SEQ_NO(camd_req),
                     __camd_op_str(CAMD_REQ_OP(camd_req)));

    }
    return (EC_TRUE);
}

EC_BOOL camd_make_req_op(CAMD_MD *camd_md, CAMD_REQ *camd_req)
{
    if(CAMD_OP_RD == CAMD_REQ_OP(camd_req))
    {
        if(EC_FALSE == camd_req_make_read(camd_req))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_make_req_op: make read req %ld ops failed\n",
                                                 CAMD_REQ_SEQ_NO(camd_req));
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_make_req_op: make read req %ld ops done\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        return (EC_TRUE);
    }

    if(CAMD_OP_WR == CAMD_REQ_OP(camd_req))
    {
        if(EC_FALSE == camd_req_make_write(camd_req))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_make_req_op: make write req %ld ops failed\n",
                                                 CAMD_REQ_SEQ_NO(camd_req));
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_make_req_op: make write req %ld ops done\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        return (EC_TRUE);
    }

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_make_req_op: invalid req %ld, op %s\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));
    return (EC_FALSE);
}

EC_BOOL camd_dispatch_req(CAMD_MD *camd_md, CAMD_REQ *camd_req)
{
    CLIST_DATA  *clist_data;

    CLIST_LOOP_NEXT(CAMD_REQ_NODES(camd_req), clist_data)
    {
        CAMD_NODE *camd_node;

        camd_node = (CAMD_NODE *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == camd_req_dispatch_node(camd_req, camd_node))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_dispatch_req: "
                                                 "dispatch %ld of req %ld, op %s failed\n",
                                                 CAMD_NODE_SUB_SEQ_NO(camd_node),
                                                 CAMD_REQ_SEQ_NO(camd_req),
                                                 __camd_op_str(CAMD_REQ_OP(camd_req)));

            camd_cancel_req(camd_md, camd_req);

            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_dispatch_req: "
                                         "dispatch req %ld, op %s done\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));

    return (EC_TRUE);
}

EC_BOOL camd_cancel_req(CAMD_MD *camd_md, CAMD_REQ *camd_req)
{
    CAMD_NODE *camd_node;

    while(NULL_PTR != (camd_node = camd_req_pop_node_back(camd_req)))
    {
        camd_req_cancel_node(camd_req, camd_node);
        camd_node_free(camd_node);
    }

    /*delete post event regarding this req*/
    camd_req_del_post_event(camd_req);

    /*delete req from camd module*/
    camd_del_req(camd_md, camd_req);

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_cancel_req: "
                                         "cancel req %ld, op %s done\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)));
    return (EC_TRUE);
}

EC_BOOL camd_add_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, CAMD_PAGE *camd_page)
{
    CRB_NODE    *crb_node;

    CAMD_ASSERT(NULL_PTR == CAMD_PAGE_MOUNTED_PAGES(camd_page));

    crb_node = crb_tree_insert_data(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx), (void *)camd_page);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_add_page: add page [%ld, %ld) failed\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != camd_page) /*found duplicate*/
    {
        CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) == CAMD_PAGE_F_S_OFFSET((CAMD_PAGE *)CRB_NODE_DATA(crb_node)));
        CAMD_ASSERT(CAMD_PAGE_F_E_OFFSET(camd_page) == CAMD_PAGE_F_E_OFFSET((CAMD_PAGE *)CRB_NODE_DATA(crb_node)));

        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_add_page: found duplicate page [%ld, %ld)\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));
        return (EC_FALSE);
    }

    CAMD_PAGE_MOUNTED_PAGES(camd_page)    = crb_node;
    CAMD_PAGE_MOUNTED_TREE_IDX(camd_page) = page_tree_idx;

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_add_page: add page [%ld, %ld) done\n",
                                         CAMD_PAGE_F_S_OFFSET(camd_page),
                                         CAMD_PAGE_F_E_OFFSET(camd_page));
    return (EC_TRUE);
}

EC_BOOL camd_del_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, CAMD_PAGE *camd_page)
{
    if(NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page))
    {
        CAMD_ASSERT(page_tree_idx == CAMD_PAGE_MOUNTED_TREE_IDX(camd_page));

        crb_tree_erase(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx), CAMD_PAGE_MOUNTED_PAGES(camd_page));
        CAMD_PAGE_MOUNTED_PAGES(camd_page)    = NULL_PTR;
        CAMD_PAGE_MOUNTED_TREE_IDX(camd_page) = CAMD_PAGE_TREE_IDX_ERR;

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_del_page: del page [%ld, %ld) done\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));
    }
    return (EC_TRUE);
}

EC_BOOL camd_has_page(CAMD_MD *camd_md, const UINT32 page_tree_idx)
{
    if(EC_TRUE == crb_tree_is_empty(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx)))
    {
        return (EC_FALSE); /*no page*/
    }

    return (EC_TRUE); /*has page*/
}

CAMD_PAGE *camd_pop_first_page(CAMD_MD *camd_md, const UINT32 page_tree_idx)
{
    CRB_NODE    *crb_node;
    CAMD_PAGE   *camd_page;

    crb_node = (CRB_NODE *)crb_tree_first_node(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx));
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    camd_page = crb_tree_erase(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx), crb_node);
    CAMD_ASSERT(CAMD_PAGE_MOUNTED_PAGES(camd_page) == crb_node);
    CAMD_PAGE_MOUNTED_PAGES(camd_page)    = NULL_PTR;
    CAMD_PAGE_MOUNTED_TREE_IDX(camd_page) = CAMD_PAGE_TREE_IDX_ERR;

    return (camd_page);
}

CAMD_PAGE *camd_pop_last_page(CAMD_MD *camd_md, const UINT32 page_tree_idx)
{
    CRB_NODE    *crb_node;
    CAMD_PAGE   *camd_page;

    crb_node = (CRB_NODE *)crb_tree_last_node(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx));
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    camd_page = crb_tree_erase(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx), crb_node);
    CAMD_ASSERT(CAMD_PAGE_MOUNTED_PAGES(camd_page) == crb_node);
    CAMD_PAGE_MOUNTED_PAGES(camd_page)    = NULL_PTR;
    CAMD_PAGE_MOUNTED_TREE_IDX(camd_page) = CAMD_PAGE_TREE_IDX_ERR;

    return (camd_page);
}

CAMD_PAGE *camd_search_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CAMD_PAGE       camd_page_t;
    CRB_NODE       *crb_node;

    CAMD_PAGE_FD(&camd_page_t)         = fd;
    CAMD_PAGE_F_S_OFFSET(&camd_page_t) = f_s_offset;
    CAMD_PAGE_F_E_OFFSET(&camd_page_t) = f_e_offset;

    crb_node = crb_tree_search_data(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx), (void *)&camd_page_t);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    return ((CAMD_PAGE *)CRB_NODE_DATA(crb_node));
}

EC_BOOL camd_cleanup_pages(CAMD_MD *camd_md, const UINT32 page_tree_idx)
{
    CAMD_PAGE        *camd_page;

    while(NULL_PTR != (camd_page = camd_pop_first_page(camd_md, page_tree_idx)))
    {
        camd_page_free(camd_page);
    }

    return (EC_TRUE);
}

EC_BOOL camd_cleanup_reqs(CAMD_MD *camd_md)
{
    CAMD_REQ        *camd_req;

    while(NULL_PTR != (camd_req = clist_pop_front(CAMD_MD_REQ_LIST(camd_md))))
    {
        CAMD_REQ_MOUNTED_REQS(camd_req) = NULL_PTR;

        camd_req_free(camd_req);
    }

    return (EC_TRUE);
}

EC_BOOL camd_cleanup_post_event_reqs(CAMD_MD *camd_md)
{
    CAMD_REQ        *camd_req;

    while(NULL_PTR != (camd_req = clist_pop_front(CAMD_MD_POST_EVENT_REQS(camd_md))))
    {
        CAMD_REQ_POST_EVENT_HANDLER(camd_req)      = NULL_PTR;
        CAMD_REQ_MOUNTED_POST_EVENT_REQS(camd_req) = NULL_PTR;

        camd_req_free(camd_req);
    }

    return (EC_TRUE);
}

CAMD_REQ *camd_search_req(CAMD_MD *camd_md, const UINT32 seq_no)
{
    CAMD_REQ       *camd_req;

    camd_req = clist_search_data_front(CAMD_MD_REQ_LIST(camd_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)camd_req_is);

    return (camd_req);
}

/*------------------------ callback interface: flush page from cmc to ssd -----------------------------*/
CAMD_SSD *camd_ssd_new()
{
    CAMD_SSD *camd_ssd;

    alloc_static_mem(MM_CAMD_SSD, &camd_ssd, LOC_CAMD_0013);
    if(NULL_PTR == camd_ssd)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    camd_ssd_init(camd_ssd);
    return (camd_ssd);
}

EC_BOOL camd_ssd_init(CAMD_SSD *camd_ssd)
{
    CAMD_SSD_F_S_OFFSET(camd_ssd)         = 0;
    CAMD_SSD_F_E_OFFSET(camd_ssd)         = 0;

    CAMD_SSD_TIMEOUT_NSEC(camd_ssd)       = 0;

    CAMD_SSD_CAMD_MD(camd_ssd)            = NULL_PTR;

    cmcnp_key_init(CAMD_SSD_CMCNP_KEY(camd_ssd));

    return (EC_TRUE);
}

EC_BOOL camd_ssd_clean(CAMD_SSD *camd_ssd)
{
    if(NULL_PTR != camd_ssd)
    {
        CAMD_SSD_F_S_OFFSET(camd_ssd)         = 0;
        CAMD_SSD_F_E_OFFSET(camd_ssd)         = 0;

        CAMD_SSD_TIMEOUT_NSEC(camd_ssd)       = 0;

        CAMD_SSD_CAMD_MD(camd_ssd)            = NULL_PTR;

        cmcnp_key_clean(CAMD_SSD_CMCNP_KEY(camd_ssd));
    }

    return (EC_TRUE);
}

EC_BOOL camd_ssd_free(CAMD_SSD *camd_ssd)
{
    if(NULL_PTR != camd_ssd)
    {
        camd_ssd_clean(camd_ssd);
        free_static_mem(MM_CAMD_SSD, camd_ssd, LOC_CAMD_0014);
    }
    return (EC_TRUE);
}

void camd_ssd_print(LOG *log, const CAMD_SSD *camd_ssd)
{
    sys_log(log, "camd_ssd_print: camd_ssd %p: file range [%ld, %ld), "
                 "key [%u, %u), "
                 "timeout %ld seconds\n",
                 camd_ssd,
                 CAMD_SSD_F_S_OFFSET(camd_ssd), CAMD_SSD_F_E_OFFSET(camd_ssd),
                 CMCNP_KEY_S_PAGE(CAMD_SSD_CMCNP_KEY(camd_ssd)),
                 CMCNP_KEY_E_PAGE(CAMD_SSD_CMCNP_KEY(camd_ssd)),
                 CAMD_SSD_TIMEOUT_NSEC(camd_ssd));

    return;
}

/*flush mem cache page to ssd timeout*/
EC_BOOL camd_ssd_flush_timeout(CAMD_SSD *camd_ssd)
{
    //CAMD_MD     *camd_md;
    //CMC_MD      *cmc_md;

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "fatal error:camd_ssd_flush_timeout: "
                     "flush page [%ld, %ld) timeout\n",
                     CAMD_SSD_F_S_OFFSET(camd_ssd), CAMD_SSD_F_E_OFFSET(camd_ssd));

    //CAMD_ASSERT(NULL_PTR != CAMD_SSD_CAMD_MD(camd_ssd));
    //camd_md = CAMD_SSD_CAMD_MD(camd_ssd);

    //CAMD_ASSERT(NULL_PTR != CAMD_MD_CMC_MD(camd_md));
    //cmc_md = CAMD_MD_CMC_MD(camd_md);

    camd_ssd_free(camd_ssd);
    return (EC_TRUE);
}

/*flush mem cache page to ssd terminate*/
EC_BOOL camd_ssd_flush_terminate(CAMD_SSD *camd_ssd)
{
    //CAMD_MD     *camd_md;
    //CMC_MD      *cmc_md;

    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "fatal error:camd_ssd_flush_terminate: "
                     "flush page [%ld, %ld) terminated\n",
                     CAMD_SSD_F_S_OFFSET(camd_ssd), CAMD_SSD_F_E_OFFSET(camd_ssd));

    //CAMD_ASSERT(NULL_PTR != CAMD_SSD_CAMD_MD(camd_ssd));
    //camd_md = CAMD_SSD_CAMD_MD(camd_ssd);

    //CAMD_ASSERT(NULL_PTR != CAMD_MD_CMC_MD(camd_md));
    //cmc_md = CAMD_MD_CMC_MD(camd_md);

    camd_ssd_free(camd_ssd);
    return (EC_TRUE);
}

/*flush mem cache page to ssd complete*/
EC_BOOL camd_ssd_flush_complete(CAMD_SSD *camd_ssd)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_flush_complete: "
                     "flush page [%ld, %ld) completed\n",
                     CAMD_SSD_F_S_OFFSET(camd_ssd), CAMD_SSD_F_E_OFFSET(camd_ssd));

    /*
    * note:
    *
    *   when aio flush from cmc to cdc,
    *   data and sata dirty flag should be transfered to cdc in atomic operation
    *
    *   thus it is not necessary to set cdc sata dirty flag afer flush
    *
    */

    camd_ssd_free(camd_ssd);

    return (EC_TRUE);
}


/*flush one page to ssd when cmc scan deg list*/
EC_BOOL camd_ssd_flush(CAMD_MD *camd_md, const CMCNP_KEY *cmcnp_key, const CMCNP_ITEM *cmcnp_item,
                            const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no)
{
    CMC_MD          *cmc_md;
    CDC_MD          *cdc_md;

    UINT8           *buff;
    UINT32           f_s_offset;
    UINT32           f_e_offset;
    UINT32           offset;
    UINT32           wsize;

    /*check cmc validity*/
    if(NULL_PTR == CAMD_MD_CMC_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cmc is null\n");
        return (EC_FALSE);
    }

    cmc_md = CAMD_MD_CMC_MD(camd_md);
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cmc np is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cmc dn is null\n");
        return (EC_FALSE);
    }

    /*check cdc validity*/
    if(NULL_PTR == CAMD_MD_CDC_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cdc is null\n");
        return (EC_FALSE);
    }

    cdc_md = CAMD_MD_CDC_MD(camd_md);
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cdc np is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cdc dn is null\n");
        return (EC_FALSE);
    }

    buff = cmcdn_node_locate(CMC_MD_DN(cmc_md), disk_no, block_no, page_no);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: "
                                             "locate mem (disk %u, block %u, page %u) failed\n",
                                             disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    CAMD_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    f_s_offset = (((UINT32)CMCNP_KEY_S_PAGE(cmcnp_key)) << ((UINT32)CDCPGB_PAGE_SIZE_NBITS));
    f_e_offset = (((UINT32)CMCNP_KEY_E_PAGE(cmcnp_key)) << ((UINT32)CDCPGB_PAGE_SIZE_NBITS));
    offset     = (f_s_offset);
    wsize      = (f_e_offset - f_s_offset);

    if(BIT_TRUE == CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item)) /*xxx*/
    {
        cfc_inc_traffic(CAMD_MD_SSD_FC(camd_md), wsize);
    }

    if(BIT_TRUE == CAMD_MD_FORCE_DIO_FLAG(camd_md))
    {
        if(EC_FALSE == cdc_file_write(cdc_md, &offset, wsize, buff))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: "
                                                 "dio flush page [%ld, %ld) to ssd failed\n",
                                                 f_s_offset, f_e_offset);

            return (EC_FALSE);
        }

        if(BIT_TRUE == CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item))
        {
            offset = (f_s_offset); /*reset*/
            cdc_file_set_sata_dirty(cdc_md, &offset, wsize);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_flush: "
                                             "dio flush page [%ld, %ld) to ssd done\n",
                                             f_s_offset, f_e_offset);
    }
    else if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        CAMD_SSD        *camd_ssd;
        CAIO_CB          caio_cb;

        camd_ssd = camd_ssd_new();
        if(NULL_PTR == camd_ssd)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: "
                                                 "new camd_ssd failed\n");
            return (EC_FALSE);
        }

        /*init*/
        CAMD_SSD_F_S_OFFSET(camd_ssd)       = f_s_offset;
        CAMD_SSD_F_E_OFFSET(camd_ssd)       = f_e_offset;
        CAMD_SSD_TIMEOUT_NSEC(camd_ssd)     = CAMD_AIO_TIMEOUT_NSEC_DEFAULT;
        CAMD_SSD_CAMD_MD(camd_ssd)          = camd_md;

        cmcnp_key_clone(cmcnp_key, CAMD_SSD_CMCNP_KEY(camd_ssd));

        caio_cb_init(&caio_cb);
        caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_SSD_TIMEOUT_NSEC(camd_ssd),
                                    (CAIO_CALLBACK)camd_ssd_flush_timeout, (void *)camd_ssd);

        caio_cb_set_terminate_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_ssd_flush_terminate, (void *)camd_ssd);
        caio_cb_set_complete_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_ssd_flush_complete, (void *)camd_ssd);

        if(EC_FALSE == cdc_file_write_aio(cdc_md, &offset, wsize, buff,
                                          CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item), &caio_cb))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: "
                                                 "aio flush page [%ld, %ld) to ssd failed\n",
                                                 f_s_offset, f_e_offset);
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_flush: "
                                             "aio flush page [%ld, %ld) [crc %u] to ssd done\n",
                                             f_s_offset, f_e_offset,
                                             CAMD_CRC32(buff, wsize));
    }
    else
    {
        if(EC_FALSE == cdc_file_write(cdc_md, &offset, wsize, buff))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: "
                                                 "flush page [%ld, %ld) to ssd failed\n",
                                                 f_s_offset, f_e_offset);

            return (EC_FALSE);
        }

        if(BIT_TRUE == CMCNP_ITEM_SATA_DIRTY_FLAG(cmcnp_item))
        {
            offset = (f_s_offset); /*reset*/
            cdc_file_set_sata_dirty(cdc_md, &offset, wsize);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_flush: "
                                             "flush page [%ld, %ld) [crc %u] to ssd done\n",
                                             f_s_offset, f_e_offset,
                                             CAMD_CRC32(buff, wsize));
    }

    return (EC_TRUE);
}

/*------------------------ callback interface: flush page from ssd to sata ----------------------------*/

CAMD_SATA *camd_sata_new()
{
    CAMD_SATA *camd_sata;

    alloc_static_mem(MM_CAMD_SATA, &camd_sata, LOC_CAMD_0015);
    if(NULL_PTR == camd_sata)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    camd_sata_init(camd_sata);
    return (camd_sata);
}

EC_BOOL camd_sata_init(CAMD_SATA *camd_sata)
{
    CAMD_SATA_FD(camd_sata)                 = ERR_FD;

    CAMD_SATA_F_S_OFFSET(camd_sata)         = 0;
    CAMD_SATA_F_E_OFFSET(camd_sata)         = 0;

    CAMD_SATA_F_T_OFFSET(camd_sata)         = 0;

    CAMD_SATA_TIMEOUT_NSEC(camd_sata)       = 0;

    CAMD_SATA_CAMD_MD(camd_sata)            = NULL_PTR;

    CAMD_SATA_M_BUFF(camd_sata)             = NULL_PTR;
    cdcnp_key_init(CAMD_SATA_CDCNP_KEY(camd_sata));

    return (EC_TRUE);
}

EC_BOOL camd_sata_clean(CAMD_SATA *camd_sata)
{
    if(NULL_PTR != camd_sata)
    {
        CAMD_SATA_FD(camd_sata)                 = ERR_FD;

        CAMD_SATA_F_S_OFFSET(camd_sata)         = 0;
        CAMD_SATA_F_E_OFFSET(camd_sata)         = 0;

        CAMD_SATA_F_T_OFFSET(camd_sata)         = 0;

        CAMD_SATA_TIMEOUT_NSEC(camd_sata)       = 0;

        CAMD_SATA_CAMD_MD(camd_sata)            = NULL_PTR;

        if(NULL_PTR != CAMD_SATA_M_BUFF(camd_sata))
        {
            __camd_mem_cache_free(CAMD_SATA_M_BUFF(camd_sata));
            CAMD_SATA_M_BUFF(camd_sata) = NULL_PTR;
        }

        cdcnp_key_clean(CAMD_SATA_CDCNP_KEY(camd_sata));
    }

    return (EC_TRUE);
}

EC_BOOL camd_sata_free(CAMD_SATA *camd_sata)
{
    if(NULL_PTR != camd_sata)
    {
        camd_sata_clean(camd_sata);
        free_static_mem(MM_CAMD_SATA, camd_sata, LOC_CAMD_0016);
    }
    return (EC_TRUE);
}

void camd_sata_print(LOG *log, const CAMD_SATA *camd_sata)
{
    sys_log(log, "camd_sata_print: camd_sata %p: sata range [%ld, %ld), "
                 "key [%u, %u)"
                 "timeout %ld seconds\n",
                 camd_sata,
                 CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata),
                 CDCNP_KEY_S_PAGE(CAMD_SATA_CDCNP_KEY(camd_sata)),
                 CDCNP_KEY_E_PAGE(CAMD_SATA_CDCNP_KEY(camd_sata)),
                 CAMD_SATA_TIMEOUT_NSEC(camd_sata));

    return;
}

/*flush memory to sata timeout*/
EC_BOOL camd_sata_flush_timeout(CAMD_SATA *camd_sata)
{
    CAMD_MD      *camd_md;
    CDC_MD       *cdc_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush_timeout: "
                     "flush page [%ld, %ld) [crc %u] timeout\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata),
                     CAMD_CRC32(CAMD_SATA_M_BUFF(camd_sata),
                                  CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata)));

    CAMD_ASSERT(NULL_PTR != CAMD_SATA_CAMD_MD(camd_sata));
    camd_md = CAMD_SATA_CAMD_MD(camd_sata);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));
    cdc_md = CAMD_MD_CDC_MD(camd_md);

    /*do not retry*/

    /*restore flag*/
    cdcnp_set_sata_not_flushed(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));
    cdcnp_set_sata_dirty(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));

    camd_sata_free(camd_sata);
    return (EC_TRUE);
}

/*flush memory to sata terminate*/
EC_BOOL camd_sata_flush_terminate(CAMD_SATA *camd_sata)
{
    CAMD_MD      *camd_md;
    CDC_MD       *cdc_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush_terminate: "
                     "flush page [%ld, %ld) [crc %u] terminated\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata),
                     CAMD_CRC32(CAMD_SATA_M_BUFF(camd_sata),
                                  CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata)));

    CAMD_ASSERT(NULL_PTR != CAMD_SATA_CAMD_MD(camd_sata));
    camd_md = CAMD_SATA_CAMD_MD(camd_sata);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));
    cdc_md = CAMD_MD_CDC_MD(camd_md);

    /*do not retry*/

    /*restore flag*/
    cdcnp_set_sata_not_flushed(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));
    cdcnp_set_sata_dirty(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));

    camd_sata_free(camd_sata);
    return (EC_TRUE);
}

/*flush memory to sata complete*/
EC_BOOL camd_sata_flush_complete(CAMD_SATA *camd_sata)
{
    CAMD_MD      *camd_md;
    CDC_MD       *cdc_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush_complete: "
                     "flush page [%ld, %ld) [crc %u] completed\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata),
                     CAMD_CRC32(CAMD_SATA_M_BUFF(camd_sata),
                                  CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata)));

    CAMD_ASSERT(CAMD_SATA_F_T_OFFSET(camd_sata) == CAMD_SATA_F_E_OFFSET(camd_sata));

    CAMD_ASSERT(NULL_PTR != CAMD_SATA_CAMD_MD(camd_sata));
    camd_md = CAMD_SATA_CAMD_MD(camd_sata);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));
    cdc_md = CAMD_MD_CDC_MD(camd_md);

    /*set flag*/
    cdcnp_set_sata_flushed(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));

    camd_sata_free(camd_sata);

    return (EC_TRUE);
}

/*load ssd cache page to memory timeout*/
EC_BOOL camd_ssd_load_timeout(CAMD_SATA *camd_sata)
{
    CAMD_MD      *camd_md;
    CDC_MD       *cdc_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_load_timeout: "
                     "load page [%ld, %ld) timeout\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata));

    CAMD_ASSERT(NULL_PTR != CAMD_SATA_CAMD_MD(camd_sata));
    camd_md = CAMD_SATA_CAMD_MD(camd_sata);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));
    cdc_md = CAMD_MD_CDC_MD(camd_md);

    /*restore flag*/
    cdcnp_set_sata_not_flushed(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));
    cdcnp_set_sata_dirty(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));

    camd_sata_free(camd_sata);
    return (EC_TRUE);
}

/*load ssd cache page to memory terminate*/
EC_BOOL camd_ssd_load_terminate(CAMD_SATA *camd_sata)
{
    CAMD_MD      *camd_md;
    CDC_MD       *cdc_md;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_load_terminate: "
                     "load page [%ld, %ld) terminated\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata));

    CAMD_ASSERT(NULL_PTR != CAMD_SATA_CAMD_MD(camd_sata));
    camd_md = CAMD_SATA_CAMD_MD(camd_sata);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));
    cdc_md = CAMD_MD_CDC_MD(camd_md);

    /*restore flag*/
    cdcnp_set_sata_not_flushed(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));
    cdcnp_set_sata_dirty(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));

    camd_sata_free(camd_sata);
    return (EC_TRUE);
}

/*load ssd cache page to memory complete*/
EC_BOOL camd_ssd_load_complete(CAMD_SATA *camd_sata)
{
    CAMD_MD      *camd_md;
    CDC_MD       *cdc_md;
    CAIO_MD      *caio_md;

    CAIO_CB       caio_cb;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_load_complete: "
                     "load page [%ld, %ld) [crc %u] completed\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata),
                     CAMD_CRC32(CAMD_SATA_M_BUFF(camd_sata),
                                  CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata)));

    CAMD_ASSERT(CAMD_SATA_F_T_OFFSET(camd_sata) == CAMD_SATA_F_E_OFFSET(camd_sata));

    CAMD_ASSERT(NULL_PTR != CAMD_SATA_CAMD_MD(camd_sata));
    camd_md = CAMD_SATA_CAMD_MD(camd_sata);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CAIO_MD(camd_md));
    caio_md = CAMD_MD_CAIO_MD(camd_md);

    CAMD_ASSERT(NULL_PTR != CAMD_MD_CDC_MD(camd_md));
    cdc_md = CAMD_MD_CDC_MD(camd_md);

    if(ERR_FD == CDC_MD_SATA_FD(cdc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_load_complete: sata fd is null\n");

       /*restore flag*/
        cdcnp_set_sata_not_flushed(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));
        cdcnp_set_sata_dirty(CDC_MD_NP(cdc_md), CAMD_SATA_CDCNP_KEY(camd_sata));

        camd_sata_free(camd_sata);
        return (EC_FALSE);
    }

    /*flush to sata*/

    caio_cb_init(&caio_cb);
    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_SATA_TIMEOUT_NSEC(camd_sata),
                                (CAIO_CALLBACK)camd_sata_flush_timeout, (void *)camd_sata);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_sata_flush_terminate, (void *)camd_sata);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)camd_sata_flush_complete, (void *)camd_sata);

    CAMD_SATA_F_T_OFFSET(camd_sata) = CAMD_SATA_F_S_OFFSET(camd_sata); /*reset*/

    if(EC_TRUE == caio_file_write(caio_md,
                                    CDC_MD_SATA_FD(cdc_md),
                                    &CAMD_SATA_F_T_OFFSET(camd_sata),
                                    CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata),
                                    CAMD_SATA_M_BUFF(camd_sata),
                                    &caio_cb))
    {
        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_ssd_load_complete: "
                                             "aio flush page [%ld, %ld) to sata done\n",
                                             CAMD_SATA_F_S_OFFSET(camd_sata),
                                             CAMD_SATA_F_E_OFFSET(camd_sata));

        return (EC_TRUE);
    }

    /*WARNING: exception would be handled in terminate, */
    /*         and camd_sata cannot be accessed again! => do not output log*/

    return (EC_FALSE);
}

/*flush ssd page to sata when cdc scan deg list before retire it*/
EC_BOOL camd_sata_flush(CAMD_MD *camd_md, const CDCNP_KEY *cdcnp_key)
{
    CDC_MD          *cdc_md;

    UINT32           f_s_offset;
    UINT32           f_e_offset;
    UINT32           offset;
    UINT32           rsize;

    f_s_offset = (((UINT32)CDCNP_KEY_S_PAGE(cdcnp_key)) << ((UINT32)CDCPGB_PAGE_SIZE_NBITS));
    f_e_offset = (((UINT32)CDCNP_KEY_E_PAGE(cdcnp_key)) << ((UINT32)CDCPGB_PAGE_SIZE_NBITS));
    offset     = (f_s_offset);
    rsize      = (f_e_offset - f_s_offset);

    if(NULL_PTR == CAMD_MD_CDC_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: cdc is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CAMD_MD_CAIO_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: camd has no caio\n");
        return (EC_FALSE);
    }

    cdc_md  = CAMD_MD_CDC_MD(camd_md);

    if(ERR_FD == CDC_MD_SATA_FD(cdc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: sata fd is null\n");
        return (EC_FALSE);
    }

    /*direct io ssd and sata*/
    if(BIT_TRUE == CAMD_MD_FORCE_DIO_FLAG(camd_md))
    {
        CAMD_SATA       *camd_sata;

        CAMD_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

        camd_sata = camd_sata_new();
        if(NULL_PTR == camd_sata)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "new camd_sata failed\n");
            return (EC_FALSE);
        }

        CAMD_SATA_M_BUFF(camd_sata) = __camd_mem_cache_new(rsize);
        if(NULL_PTR == CAMD_SATA_M_BUFF(camd_sata))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "new mem cache with %ld bytes failed\n",
                                                 rsize);
            camd_sata_free(camd_sata);
            return (EC_FALSE);
        }

        /*init*/
        CAMD_SATA_FD(camd_sata)             = CDC_MD_SATA_FD(cdc_md);
        CAMD_SATA_F_S_OFFSET(camd_sata)     = f_s_offset;
        CAMD_SATA_F_E_OFFSET(camd_sata)     = f_e_offset;
        CAMD_SATA_F_T_OFFSET(camd_sata)     = offset;
        CAMD_SATA_TIMEOUT_NSEC(camd_sata)   = CAMD_AIO_TIMEOUT_NSEC_DEFAULT;
        CAMD_SATA_CAMD_MD(camd_sata)        = camd_md;
        cdcnp_key_clone(cdcnp_key, CAMD_SATA_CDCNP_KEY(camd_sata));

        if(EC_FALSE == cdc_file_read(cdc_md,
                                    &CAMD_SATA_F_T_OFFSET(camd_sata),
                                    CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata),
                                    CAMD_SATA_M_BUFF(camd_sata)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "dio load page [%ld, %ld) from ssd failed\n",
                                                 f_s_offset, f_e_offset);
            camd_sata_free(camd_sata);
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush: "
                                             "dio load page [%ld, %ld) from ssd done\n",
                                             f_s_offset, f_e_offset);

        CAMD_SATA_F_T_OFFSET(camd_sata) = CAMD_SATA_F_S_OFFSET(camd_sata); /*reset*/

        /*flush to sata*/
        if(EC_FALSE == c_file_pwrite(CDC_MD_SATA_FD(cdc_md),
                                    &CAMD_SATA_F_T_OFFSET(camd_sata),
                                    CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata),
                                    CAMD_SATA_M_BUFF(camd_sata)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "dio flush page [%ld, %ld) to sata failed\n",
                                                 f_s_offset, f_e_offset);
            camd_sata_free(camd_sata);
            return (EC_FALSE);
        }

        cdc_file_set_sata_flushed(cdc_md, &offset, f_e_offset - f_s_offset);

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush: "
                                             "dio flush page [%ld, %ld) to sata done\n",
                                             f_s_offset, f_e_offset);
        camd_sata_free(camd_sata);
    }
    else if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        CAMD_SATA       *camd_sata;

        CAIO_CB          caio_cb;

        CAMD_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

        camd_sata = camd_sata_new();
        if(NULL_PTR == camd_sata)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "new camd_sata failed\n");
            return (EC_FALSE);
        }

        /*init*/
        CAMD_SATA_FD(camd_sata)             = CDC_MD_SATA_FD(cdc_md);
        CAMD_SATA_F_S_OFFSET(camd_sata)     = f_s_offset;
        CAMD_SATA_F_E_OFFSET(camd_sata)     = f_e_offset;
        CAMD_SATA_F_T_OFFSET(camd_sata)     = offset;
        CAMD_SATA_TIMEOUT_NSEC(camd_sata)   = CAMD_AIO_TIMEOUT_NSEC_DEFAULT;
        CAMD_SATA_CAMD_MD(camd_sata)        = camd_md;
        cdcnp_key_clone(cdcnp_key, CAMD_SATA_CDCNP_KEY(camd_sata));

        CAMD_SATA_M_BUFF(camd_sata) = __camd_mem_cache_new(rsize);
        if(NULL_PTR == CAMD_SATA_M_BUFF(camd_sata))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "new mem cache with %ld bytes failed\n",
                                                 rsize);
            camd_sata_free(camd_sata);
            return (EC_FALSE);
        }

        /*load from ssd and then flush to sata*/

        caio_cb_init(&caio_cb);
        caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_SATA_TIMEOUT_NSEC(camd_sata),
                                    (CAIO_CALLBACK)camd_ssd_load_timeout, (void *)camd_sata);

        caio_cb_set_terminate_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_ssd_load_terminate, (void *)camd_sata);
        caio_cb_set_complete_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_ssd_load_complete, (void *)camd_sata);

        if(EC_FALSE == cdc_file_load_aio(cdc_md,
                                        &CAMD_SATA_F_T_OFFSET(camd_sata),
                                        CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata),
                                        CAMD_SATA_M_BUFF(camd_sata),
                                        &caio_cb))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "aio load page [%ld, %ld) from ssd failed\n",
                                                 f_s_offset, f_e_offset);
            camd_sata_free(camd_sata);
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush: "
                                             "aio load page [%ld, %ld) from ssd done\n",
                                             f_s_offset, f_e_offset);
    }
    else /*direct io ssd*/
    {
        CAMD_SATA       *camd_sata;

        CAIO_CB          caio_cb;

        CAMD_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

        camd_sata = camd_sata_new();
        if(NULL_PTR == camd_sata)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "new camd_sata failed\n");
            return (EC_FALSE);
        }

        CAMD_SATA_M_BUFF(camd_sata) = __camd_mem_cache_new(rsize);
        if(NULL_PTR == CAMD_SATA_M_BUFF(camd_sata))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "new mem cache with %ld bytes failed\n",
                                                 rsize);
            camd_sata_free(camd_sata);
            return (EC_FALSE);
        }

        /*init*/
        CAMD_SATA_FD(camd_sata)             = CDC_MD_SATA_FD(cdc_md);
        CAMD_SATA_F_S_OFFSET(camd_sata)     = f_s_offset;
        CAMD_SATA_F_E_OFFSET(camd_sata)     = f_e_offset;
        CAMD_SATA_F_T_OFFSET(camd_sata)     = offset;
        CAMD_SATA_TIMEOUT_NSEC(camd_sata)   = CAMD_AIO_TIMEOUT_NSEC_DEFAULT;
        CAMD_SATA_CAMD_MD(camd_sata)        = camd_md;
        cdcnp_key_clone(cdcnp_key, CAMD_SATA_CDCNP_KEY(camd_sata));

        if(EC_FALSE == cdc_file_read(cdc_md,
                                    &CAMD_SATA_F_T_OFFSET(camd_sata),
                                    CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata),
                                    CAMD_SATA_M_BUFF(camd_sata)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_flush: "
                                                 "dio load page [%ld, %ld) from ssd failed\n",
                                                 f_s_offset, f_e_offset);
            camd_sata_free(camd_sata);
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush: "
                                             "dio load page [%ld, %ld) [crc %u] from ssd done\n",
                                             f_s_offset, f_e_offset,
                                             CAMD_CRC32(CAMD_SATA_M_BUFF(camd_sata),
                                                          f_e_offset - f_s_offset));

        CAMD_SATA_F_T_OFFSET(camd_sata) = CAMD_SATA_F_S_OFFSET(camd_sata); /*reset*/

        /*flush to sata*/

        caio_cb_init(&caio_cb);
        caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_SATA_TIMEOUT_NSEC(camd_sata),
                                    (CAIO_CALLBACK)camd_sata_flush_timeout, (void *)camd_sata);

        caio_cb_set_terminate_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_sata_flush_terminate, (void *)camd_sata);
        caio_cb_set_complete_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_sata_flush_complete, (void *)camd_sata);

        if(EC_FALSE == caio_file_write(CAMD_MD_CAIO_MD(camd_md),
                                        CDC_MD_SATA_FD(cdc_md),
                                        &CAMD_SATA_F_T_OFFSET(camd_sata),
                                        CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata),
                                        CAMD_SATA_M_BUFF(camd_sata),
                                        &caio_cb))
        {
            /*WARNING: exception would be handled in terminate, */
            /*         and camd_sata cannot be accessed again! => do not output log*/

            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_flush: "
                                             "aio flush page [%ld, %ld) [crc %u] to sata done\n",
                                             CAMD_SATA_F_S_OFFSET(camd_sata),
                                             CAMD_SATA_F_E_OFFSET(camd_sata),
                                             CAMD_CRC32(CAMD_SATA_M_BUFF(camd_sata),
                                                    CAMD_SATA_F_E_OFFSET(camd_sata) - CAMD_SATA_F_S_OFFSET(camd_sata)));
    }

    return (EC_TRUE);
}

/*flush mem cache page to sata timeout*/
EC_BOOL camd_sata_degrade_timeout(CAMD_SATA *camd_sata)
{
    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "fata error:camd_sata_degrade_timeout: "
                     "flush page [%ld, %ld) timeout\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata));

    camd_sata_free(camd_sata);
    return (EC_TRUE);
}

/*flush mem cache page to sata terminate*/
EC_BOOL camd_sata_degrade_terminate(CAMD_SATA *camd_sata)
{
    dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "fatal error:camd_sata_degrade_terminate: "
                     "flush page [%ld, %ld) terminated\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata));

    camd_sata_free(camd_sata);
    return (EC_TRUE);
}

/*flush mem cache page to sata complete*/
EC_BOOL camd_sata_degrade_complete(CAMD_SATA *camd_sata)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_degrade_complete: "
                     "flush page [%ld, %ld) completed\n",
                     CAMD_SATA_F_S_OFFSET(camd_sata), CAMD_SATA_F_E_OFFSET(camd_sata));

    camd_sata_free(camd_sata);

    return (EC_TRUE);
}


/*flush one page to sata when cmc scan deg list*/
EC_BOOL camd_sata_degrade(CAMD_MD *camd_md, const CMCNP_KEY *cmcnp_key, const CMCNP_ITEM *cmcnp_item,
                            const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no)
{
    CMC_MD          *cmc_md;

    UINT8           *buff;
    UINT32           f_s_offset;
    UINT32           f_e_offset;
    UINT32           offset;
    UINT32           wsize;

    int              sata_disk_fd;

    if(ERR_FD == CAMD_MD_SATA_DISK_FD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: no sata disk fd\n");
        return (EC_FALSE);
    }
    sata_disk_fd = CAMD_MD_SATA_DISK_FD(camd_md);

    /*check cmc validity*/
    if(NULL_PTR == CAMD_MD_CMC_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: cmc is null\n");
        return (EC_FALSE);
    }

    cmc_md = CAMD_MD_CMC_MD(camd_md);
    if(NULL_PTR == CMC_MD_NP(cmc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: cmc np is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CMC_MD_DN(cmc_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: cmc dn is null\n");
        return (EC_FALSE);
    }

    buff = cmcdn_node_locate(CMC_MD_DN(cmc_md), disk_no, block_no, page_no);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: "
                                             "locate mem (disk %u, block %u, page %u) failed\n",
                                             disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    CAMD_ASSERT(CMCNP_KEY_S_PAGE(cmcnp_key) + 1 == CMCNP_KEY_E_PAGE(cmcnp_key));

    f_s_offset = (((UINT32)CMCNP_KEY_S_PAGE(cmcnp_key)) << ((UINT32)CDCPGB_PAGE_SIZE_NBITS));
    f_e_offset = (((UINT32)CMCNP_KEY_E_PAGE(cmcnp_key)) << ((UINT32)CDCPGB_PAGE_SIZE_NBITS));
    offset     = (f_s_offset);
    wsize      = (f_e_offset - f_s_offset);

    cfc_inc_traffic(CAMD_MD_SATA_WRITE_FC(camd_md), wsize);

    if(BIT_TRUE == CAMD_MD_FORCE_DIO_FLAG(camd_md))
    {
        if(EC_FALSE == c_file_pwrite(sata_disk_fd, &offset, wsize, buff))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: "
                                                 "dio flush page [%ld, %ld) to sata failed\n",
                                                 f_s_offset, f_e_offset);

            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_degrade: "
                                             "dio flush page [%ld, %ld) to sata done\n",
                                             f_s_offset, f_e_offset);
    }
    else if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        CAIO_MD          *caio_md;
        CAMD_SATA        *camd_sata;
        CAIO_CB           caio_cb;
        UINT8            *m_buff;

        caio_md = CAMD_MD_CAIO_MD(camd_md);

        m_buff = __camd_mem_cache_new(wsize);
        if(NULL_PTR == m_buff)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: "
                                                 "new %ld bytes failed\n",
                                                 wsize);
            return (EC_FALSE);
        }
        FCOPY(buff, m_buff, wsize); /*clone*/

        camd_sata = camd_sata_new();
        if(NULL_PTR == camd_sata)
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: "
                                                 "new camd_sata failed\n");
            __camd_mem_cache_free(m_buff);
            return (EC_FALSE);
        }

        /*init*/
        CAMD_SATA_FD(camd_sata)             = sata_disk_fd;
        CAMD_SATA_F_S_OFFSET(camd_sata)     = f_s_offset;
        CAMD_SATA_F_E_OFFSET(camd_sata)     = f_e_offset;
        CAMD_SATA_M_BUFF(camd_sata)         = m_buff;
        CAMD_SATA_TIMEOUT_NSEC(camd_sata)   = CAMD_AIO_TIMEOUT_NSEC_DEFAULT;
        CAMD_SATA_CAMD_MD(camd_sata)        = camd_md;

        caio_cb_init(&caio_cb);
        caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_SATA_TIMEOUT_NSEC(camd_sata),
                                    (CAIO_CALLBACK)camd_sata_degrade_timeout, (void *)camd_sata);

        caio_cb_set_terminate_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_sata_degrade_terminate, (void *)camd_sata);
        caio_cb_set_complete_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_sata_degrade_complete, (void *)camd_sata);

        if(EC_FALSE == caio_file_write(caio_md, sata_disk_fd, &offset, wsize, m_buff, &caio_cb))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: "
                                                 "aio flush page [%ld, %ld) to sata failed\n",
                                                 f_s_offset, f_e_offset);
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_degrade: "
                                             "aio flush page [%ld, %ld) [crc %u] to sata done\n",
                                             f_s_offset, f_e_offset,
                                             CAMD_CRC32(m_buff, wsize));
    }
    else
    {
        if(EC_FALSE == c_file_pwrite(sata_disk_fd, &offset, wsize, buff))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_sata_degrade: "
                                                 "flush page [%ld, %ld) to sata failed\n",
                                                 f_s_offset, f_e_offset);

            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_sata_degrade: "
                                             "flush page [%ld, %ld) [crc %u] to sata done\n",
                                             f_s_offset, f_e_offset,
                                             CAMD_CRC32(buff, wsize));
    }

    return (EC_TRUE);
}

/*----------------------------------- camd external interface -----------------------------------*/

EC_BOOL camd_file_read_aio(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CAMD_REQ  *camd_req;

    CAMD_ASSERT(NULL_PTR != offset);

    camd_req = camd_req_new();
    if(NULL_PTR == camd_req)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read_aio: new camd_req failed\n");

        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    if(EC_FALSE == caio_cb_clone(caio_cb, CAMD_REQ_CAIO_CB(camd_req)))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read_aio: clone caio_cb to camd_req failed\n");

        camd_req_free(camd_req);
        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    CAMD_REQ_S_MSEC(camd_req) = c_get_cur_time_msec();

    CAMD_REQ_SEQ_NO(camd_req)       = ++ CAMD_MD_SEQ_NO(camd_md);
    CAMD_REQ_OP(camd_req)           = CAMD_OP_RD;

    CAMD_REQ_CAMD_MD(camd_req)      = camd_md;
    CAMD_REQ_FD(camd_req)           = fd;
    CAMD_REQ_M_BUFF(camd_req)       = buff;
    CAMD_REQ_M_CACHE(camd_req)      = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)       = offset;
    CAMD_REQ_F_S_OFFSET(camd_req)   = (*offset);
    CAMD_REQ_F_E_OFFSET(camd_req)   = (*offset) + rsize;
    CAMD_REQ_U_E_OFFSET(camd_req)   = CAMD_REQ_F_E_OFFSET(camd_req);
    CAMD_REQ_TIMEOUT_NSEC(camd_req) = CAIO_CB_TIMEOUT_NSEC(caio_cb);
    CAMD_REQ_NTIME_MS(camd_req)     = c_get_cur_time_msec() + CAIO_CB_TIMEOUT_NSEC(caio_cb) * 1000;

    if(EC_FALSE == camd_submit_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read_aio: submit req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    cfc_inc_traffic(CAMD_MD_AMD_READ_FC(camd_md), rsize);

    dbg_log(SEC_0125_CAMD, 1)(LOGSTDOUT, "[DEBUG] camd_file_read_aio: "
                                         "submit req %ld, op %s, fd %d, file range [%ld, %ld) done\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)),
                                         CAMD_REQ_FD(camd_req),
                                         CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req));

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_file_read_aio: submit req %ld done\n",
                                         CAMD_REQ_SEQ_NO(camd_req));

    return (EC_TRUE);
}

EC_BOOL camd_file_write_aio(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 wsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CAMD_REQ  *camd_req;

    CAMD_ASSERT(NULL_PTR != offset);

    camd_req = camd_req_new();
    if(NULL_PTR == camd_req)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write_aio: new camd_req failed\n");

        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    if(EC_FALSE == caio_cb_clone(caio_cb, CAMD_REQ_CAIO_CB(camd_req)))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write_aio: clone caio_cb to camd_req failed\n");

        camd_req_free(camd_req);
        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    CAMD_REQ_S_MSEC(camd_req) = c_get_cur_time_msec();

    CAMD_REQ_SEQ_NO(camd_req)       = ++ CAMD_MD_SEQ_NO(camd_md);
    CAMD_REQ_OP(camd_req)           = CAMD_OP_WR;

    CAMD_REQ_CAMD_MD(camd_req)      = camd_md;
    CAMD_REQ_FD(camd_req)           = fd;
    CAMD_REQ_M_BUFF(camd_req)       = buff;
    CAMD_REQ_M_CACHE(camd_req)      = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)       = offset;
    CAMD_REQ_F_S_OFFSET(camd_req)   = (*offset);
    CAMD_REQ_F_E_OFFSET(camd_req)   = (*offset) + wsize;
    CAMD_REQ_U_E_OFFSET(camd_req)   = CAMD_REQ_F_E_OFFSET(camd_req);
    CAMD_REQ_TIMEOUT_NSEC(camd_req) = CAIO_CB_TIMEOUT_NSEC(caio_cb);
    CAMD_REQ_NTIME_MS(camd_req)     = c_get_cur_time_msec() + CAIO_CB_TIMEOUT_NSEC(caio_cb) * 1000;

    if(EC_FALSE == camd_submit_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write_aio: submit req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    cfc_inc_traffic(CAMD_MD_AMD_WRITE_FC(camd_md), wsize);

    dbg_log(SEC_0125_CAMD, 1)(LOGSTDOUT, "[DEBUG] camd_file_write_aio: "
                                         "submit req %ld, op %s, fd %d, file range [%ld, %ld) done\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)),
                                         CAMD_REQ_FD(camd_req),
                                         CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req));

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_file_write_aio: submit req %ld done\n",
                                         CAMD_REQ_SEQ_NO(camd_req));

    return (EC_TRUE);
}

EC_BOOL camd_file_delete(CAMD_MD *camd_md, UINT32 *offset, const UINT32 dsize)
{
    CAMD_ASSERT(NULL_PTR != offset);

    /*delete from mem cache*/
    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        CMC_MD          *cmc_md;
        UINT32           s_offset;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        s_offset = (*offset); /*saved*/
        if(EC_FALSE == cmc_file_delete(cmc_md, offset, dsize))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_delete: "
                                                 "mem delete from offset %ld, size %ld failed\n",
                                                 s_offset, dsize);
            return (EC_FALSE);
        }

        if(s_offset + dsize != (*offset))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "warn:camd_file_delete: "
                                                 "mem delete from offset %ld, expected size %ld but %ld\n",
                                                 s_offset, dsize, (*offset) - s_offset);
            return (EC_TRUE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_file_delete: "
                                             "mem delete from offset %ld, size %ld done\n",
                                             s_offset, dsize);
    }

    /*delete from ssd cache*/
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        CDC_MD          *cdc_md;
        UINT32           s_offset;

        cdc_md = CAMD_MD_CDC_MD(camd_md);

        s_offset = (*offset); /*saved*/
        if(EC_FALSE == cdc_file_delete(cdc_md, offset, dsize))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_delete: "
                                                 "ssd delete from offset %ld, size %ld failed\n",
                                                 s_offset, dsize);
            return (EC_FALSE);
        }

        if(s_offset + dsize != (*offset))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "warn:camd_file_delete: "
                                                 "ssd delete from offset %ld, expected size %ld but %ld\n",
                                                 s_offset, dsize, (*offset) - s_offset);
            return (EC_TRUE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_file_delete: "
                                             "ssd delete from offset %ld, size %ld done\n",
                                             s_offset, dsize);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_read_timeout(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0017);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_read_terminate(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0018);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_read_complete(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0019);
    return (EC_TRUE);
}

EC_BOOL camd_file_read(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    CAIO_CB              caio_cb;
    COROUTINE_COND       coroutine_cond;

    CAMD_REQ            *camd_req;

    CAMD_ASSERT(NULL_PTR != offset);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_AIO_TIMEOUT_NSEC_DEFAULT /*seconds*/,
                                (CAIO_CALLBACK)__camd_file_read_timeout, (void *)&coroutine_cond);

    caio_cb_set_terminate_handler(&caio_cb, (CAIO_CALLBACK)__camd_file_read_terminate, (void *)&coroutine_cond);
    caio_cb_set_complete_handler(&caio_cb, (CAIO_CALLBACK)__camd_file_read_complete, (void *)&coroutine_cond);

    camd_req = camd_req_new();
    if(NULL_PTR == camd_req)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read: new camd_req failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == caio_cb_clone(&caio_cb, CAMD_REQ_CAIO_CB(camd_req)))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read: clone caio_cb to camd_req failed\n");

        camd_req_free(camd_req);
        return (EC_FALSE);
    }

    CAMD_REQ_S_MSEC(camd_req) = c_get_cur_time_msec();

    CAMD_REQ_SEQ_NO(camd_req)       = ++ CAMD_MD_SEQ_NO(camd_md);
    CAMD_REQ_OP(camd_req)           = CAMD_OP_RD;

    CAMD_REQ_CAMD_MD(camd_req)      = camd_md;
    CAMD_REQ_FD(camd_req)           = fd;
    CAMD_REQ_M_BUFF(camd_req)       = buff;
    CAMD_REQ_M_CACHE(camd_req)      = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)       = offset;
    CAMD_REQ_F_S_OFFSET(camd_req)   = (*offset);
    CAMD_REQ_F_E_OFFSET(camd_req)   = (*offset) + rsize;
    CAMD_REQ_U_E_OFFSET(camd_req)   = CAMD_REQ_F_E_OFFSET(camd_req);
    CAMD_REQ_TIMEOUT_NSEC(camd_req) = CAIO_CB_TIMEOUT_NSEC(&caio_cb);
    CAMD_REQ_NTIME_MS(camd_req)     = c_get_cur_time_msec() + CAIO_CB_TIMEOUT_NSEC(&caio_cb) * 1000;

    if(EC_FALSE == camd_submit_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read: submit req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    }

    coroutine_cond_init(&coroutine_cond, 0 /*never timeout*/, LOC_CAMD_0020);
    coroutine_cond_reserve(&coroutine_cond, 1, LOC_CAMD_0021);
    coroutine_cond_wait(&coroutine_cond, LOC_CAMD_0022);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read: "
                                             "submit req %ld but coroutine was cancelled\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    } else { /*normal*/
        /*do nothing*/
    }

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_file_read: submit req %ld done\n",
                                         CAMD_REQ_SEQ_NO(camd_req));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_write_timeout(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0023);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_write_terminate(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0024);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_write_complete(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0025);
    return (EC_TRUE);
}

EC_BOOL camd_file_write(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff)
{
    CAIO_CB              caio_cb;
    COROUTINE_COND       coroutine_cond;

    CAMD_REQ            *camd_req;

    CAMD_ASSERT(NULL_PTR != offset);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_AIO_TIMEOUT_NSEC_DEFAULT /*seconds*/,
                                (CAIO_CALLBACK)__camd_file_write_timeout, (void *)&coroutine_cond);

    caio_cb_set_terminate_handler(&caio_cb, (CAIO_CALLBACK)__camd_file_write_terminate, (void *)&coroutine_cond);
    caio_cb_set_complete_handler(&caio_cb, (CAIO_CALLBACK)__camd_file_write_complete, (void *)&coroutine_cond);

    camd_req = camd_req_new();
    if(NULL_PTR == camd_req)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write: new camd_req failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == caio_cb_clone(&caio_cb, CAMD_REQ_CAIO_CB(camd_req)))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write: clone caio_cb to camd_req failed\n");

        camd_req_free(camd_req);
        return (EC_FALSE);
    }

    CAMD_REQ_S_MSEC(camd_req) = c_get_cur_time_msec();

    CAMD_REQ_SEQ_NO(camd_req)       = ++ CAMD_MD_SEQ_NO(camd_md);
    CAMD_REQ_OP(camd_req)           = CAMD_OP_WR;

    CAMD_REQ_CAMD_MD(camd_req)      = camd_md;
    CAMD_REQ_FD(camd_req)           = fd;
    CAMD_REQ_M_BUFF(camd_req)       = (UINT8 *)buff;
    CAMD_REQ_M_CACHE(camd_req)      = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)       = offset;
    CAMD_REQ_F_S_OFFSET(camd_req)   = (*offset);
    CAMD_REQ_F_E_OFFSET(camd_req)   = (*offset) + wsize;
    CAMD_REQ_U_E_OFFSET(camd_req)   = CAMD_REQ_F_E_OFFSET(camd_req);
    CAMD_REQ_TIMEOUT_NSEC(camd_req) = CAIO_CB_TIMEOUT_NSEC(&caio_cb);
    CAMD_REQ_NTIME_MS(camd_req)     = c_get_cur_time_msec() + CAIO_CB_TIMEOUT_NSEC(&caio_cb) * 1000;

    if(EC_FALSE == camd_submit_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write: submit req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    }

    cfc_inc_traffic(CAMD_MD_AMD_WRITE_FC(camd_md), wsize);

    dbg_log(SEC_0125_CAMD, 1)(LOGSTDOUT, "[DEBUG] camd_file_write: "
                                         "submit req %ld, op %s, fd %d, file range [%ld, %ld) done\n",
                                         CAMD_REQ_SEQ_NO(camd_req),
                                         __camd_op_str(CAMD_REQ_OP(camd_req)),
                                         CAMD_REQ_FD(camd_req),
                                         CAMD_REQ_F_S_OFFSET(camd_req), CAMD_REQ_F_E_OFFSET(camd_req));

    coroutine_cond_init(&coroutine_cond, 0 /*never timeout*/, LOC_CAMD_0026);
    coroutine_cond_reserve(&coroutine_cond, 1, LOC_CAMD_0027);
    coroutine_cond_wait(&coroutine_cond, LOC_CAMD_0028);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write: "
                                             "submit req %ld but coroutine was cancelled\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    } else { /*normal*/
        /*do nothing*/
    }

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_file_write: submit req %ld done\n",
                                         CAMD_REQ_SEQ_NO(camd_req));

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

