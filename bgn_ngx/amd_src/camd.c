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

#include "camd.h"

#if (SWITCH_ON == CAMD_ASSERT_SWITCH)
#define CAMD_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CAMD_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CAMD_ASSERT_SWITCH)
#define CAMD_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CAMD_ASSERT_SWITCH)*/

#define CAMD_PAGE_SHORTCUT_SWITCH   SWITCH_OFF

/*----------------------------------- unit test interface -----------------------------------*/

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
    UINT8    *mem_cache;

    mem_cache = (UINT8 *)c_memalign_new(size, CAMD_MEM_CACHE_ALIGN_SIZE_NBYTES);
    if(NULL_PTR == mem_cache)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:__camd_mem_cache_new: alloc memory failed\n");

        return (NULL_PTR);
    }

    dbg_log(SEC_0125_CAMD, 8)(LOGSTDOUT, "[DEBUG] __camd_mem_cache_new: mem_cache = %p\n", mem_cache);
    g_camd_mem_cache_counter ++;
    return (mem_cache);
}

STATIC_CAST static EC_BOOL __camd_mem_cache_free(UINT8 *mem_cache)
{
    if(NULL_PTR != mem_cache)
    {
        dbg_log(SEC_0125_CAMD, 8)(LOGSTDOUT, "[DEBUG] __camd_mem_cache_free: mem_cache = %p\n", mem_cache);
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

    CAMD_PAGE_TIMEOUT_NSEC(camd_page)       = 0;

    CAMD_PAGE_DIRTY_FLAG(camd_page)         = BIT_FALSE;
    CAMD_PAGE_SATA_LOADED_FLAG(camd_page)   = BIT_FALSE;
    CAMD_PAGE_SSD_LOADED_FLAG(camd_page)    = BIT_FALSE;
    CAMD_PAGE_SATA_LOADING_FLAG(camd_page)  = BIT_FALSE;
    CAMD_PAGE_MEM_CACHE_FLAG(camd_page)     = BIT_FALSE;

    CAMD_PAGE_M_CACHE(camd_page)            = NULL_PTR;

    CAMD_PAGE_CAMD_MD(camd_page)            = NULL_PTR;
    CAMD_PAGE_MOUNTED_PAGES(camd_page)      = NULL_PTR;

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
        && NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page))
        {
            CAMD_MD     *camd_md;

            camd_md = CAMD_PAGE_CAMD_MD(camd_page);
            camd_del_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page);
        }

        CAMD_PAGE_FD(camd_page)                 = ERR_FD;

        CAMD_PAGE_F_S_OFFSET(camd_page)         = 0;
        CAMD_PAGE_F_E_OFFSET(camd_page)         = 0;

        CAMD_PAGE_F_T_OFFSET(camd_page)         = 0;

        CAMD_PAGE_TIMEOUT_NSEC(camd_page)       = 0;

        CAMD_PAGE_DIRTY_FLAG(camd_page)         = BIT_FALSE;
        CAMD_PAGE_SATA_LOADED_FLAG(camd_page)   = BIT_FALSE;
        CAMD_PAGE_SSD_LOADED_FLAG(camd_page)    = BIT_FALSE;
        CAMD_PAGE_SATA_LOADING_FLAG(camd_page)  = BIT_FALSE;
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
                 "dirty %s, sata loaded %s, sata loading %s, ssd loaded %s, mem cache page %s,"
                 "m_cache %p, mounted pages %p, "
                 "timeout %ld seconds\n",
                 camd_page,
                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page),
                 (const char *)c_bit_bool_str(CAMD_PAGE_DIRTY_FLAG(camd_page)),
                 (const char *)c_bit_bool_str(CAMD_PAGE_SATA_LOADED_FLAG(camd_page)),
                 (const char *)c_bit_bool_str(CAMD_PAGE_SATA_LOADING_FLAG(camd_page)),
                 (const char *)c_bit_bool_str(CAMD_PAGE_SSD_LOADED_FLAG(camd_page)),
                 (const char *)c_bit_bool_str(CAMD_PAGE_MEM_CACHE_FLAG(camd_page)),
                 CAMD_PAGE_M_CACHE(camd_page),
                 CAMD_PAGE_MOUNTED_PAGES(camd_page),
                 CAMD_PAGE_TIMEOUT_NSEC(camd_page));

    sys_log(log, "camd_page_print: camd_page %p: owners:\n", camd_page);
    clist_print(log, CAMD_PAGE_OWNERS(camd_page), (CLIST_DATA_DATA_PRINT)camd_node_print);

    return;
}

int camd_page_cmp(const CAMD_PAGE *camd_page_1st, const CAMD_PAGE *camd_page_2nd)
{
    CAMD_ASSERT(CAMD_PAGE_FD(camd_page_1st) == CAMD_PAGE_FD(camd_page_2nd)
         || ANY_FD == CAMD_PAGE_FD(camd_page_1st)
         || ANY_FD == CAMD_PAGE_FD(camd_page_2nd));

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
                     "add node (%p) %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "to page [%ld, %ld) done\n", camd_node,
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
                     "del node (%p) %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "from page [%ld, %ld) done\n", camd_node,
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

/*process when page is in mem cache*/
EC_BOOL camd_page_process(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        if(CAMD_OP_RD == CAMD_NODE_OP(camd_node))
        {
            CAMD_ASSERT(NULL_PTR != CAMD_PAGE_M_CACHE(camd_page));

            if(NULL_PTR != CAMD_NODE_M_BUFF(camd_node))
            {
                dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                                "[RD] node %ld/%ld of req %ld, "
                                "copy from page cache %p [%ld, %ld) to app cache %p [%ld, %ld)\n",
                                CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                                CAMD_NODE_SEQ_NO(camd_node),
                                CAMD_PAGE_M_CACHE(camd_page),
                                CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                                CAMD_NODE_M_BUFF(camd_node),
                                (UINT32)0,
                                CAMD_NODE_B_E_OFFSET(camd_node) - CAMD_NODE_B_S_OFFSET(camd_node));

                dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                                "[RD] node %ld/%ld of req %ld, "
                                "copy from page [%ld, %ld) to app cache [%ld, %ld)\n",
                                CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                                CAMD_NODE_SEQ_NO(camd_node),
                                CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node),
                                CAMD_NODE_F_S_OFFSET(camd_node),
                                CAMD_NODE_F_E_OFFSET(camd_node));

                /*copy data from mem cache to application mem buff*/
                BCOPY(CAMD_PAGE_M_CACHE(camd_page) + CAMD_NODE_B_S_OFFSET(camd_node),
                      CAMD_NODE_M_BUFF(camd_node),
                      CAMD_NODE_B_E_OFFSET(camd_node) - CAMD_NODE_B_S_OFFSET(camd_node));
            }

            camd_node_complete(camd_node);
        }

        else if(CAMD_OP_WR == CAMD_NODE_OP(camd_node))
        {
            CAMD_ASSERT(NULL_PTR != CAMD_PAGE_M_CACHE(camd_page));
            CAMD_ASSERT(NULL_PTR != CAMD_NODE_M_BUFF(camd_node));

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                            "[WR] node %ld/%ld of req %ld, "
                            "copy from app cache %p [%ld, %ld) to page cache %p [%ld, %ld)\n",
                            CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                            CAMD_NODE_SEQ_NO(camd_node),
                            CAMD_NODE_M_BUFF(camd_node),
                            (UINT32)0,
                            CAMD_NODE_B_E_OFFSET(camd_node) - CAMD_NODE_B_S_OFFSET(camd_node),
                            CAMD_PAGE_M_CACHE(camd_page),
                            CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node));

            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                            "[WR] node %ld/%ld of req %ld, "
                            "copy from app [%ld, %ld) to page [%ld, %ld)\n",
                            CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                            CAMD_NODE_SEQ_NO(camd_node),
                            CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node),
                            CAMD_NODE_B_S_OFFSET(camd_node), CAMD_NODE_B_E_OFFSET(camd_node));

            /*copy data from application mem buff to mem cache*/
            BCOPY(CAMD_NODE_M_BUFF(camd_node),
                  CAMD_PAGE_M_CACHE(camd_page) + CAMD_NODE_B_S_OFFSET(camd_node),
                  CAMD_NODE_B_E_OFFSET(camd_node) - CAMD_NODE_B_S_OFFSET(camd_node));

            camd_node_complete(camd_node);

            CAMD_PAGE_DIRTY_FLAG(camd_page) = BIT_TRUE; /*set dirty*/
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
            camd_page_free(camd_page);
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == camd_page_notify_timeout(camd_page))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                         "page [%ld, %ld) notify timeout nodes failed\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        camd_page_free(camd_page);
        return (EC_FALSE);
    }

    /*flush sata or dirty page to mem cache*/
    if(BIT_TRUE == CAMD_PAGE_DIRTY_FLAG(camd_page)
    || BIT_TRUE == CAMD_PAGE_SATA_LOADED_FLAG(camd_page)
    || BIT_TRUE == CAMD_PAGE_SSD_LOADED_FLAG(camd_page))
    {
        /*flush dirty page or sata loaded page or ssd loaded page to mem cache*/
        if(EC_FALSE == camd_page_flush_mem(camd_page))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                             "flush page [%ld, %ld) to mem cache failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            camd_page_free(camd_page);
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                         "flush page [%ld, %ld) to mem cache done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
    }

    /*page loaded from sata => do nothing*/
    if(BIT_TRUE == CAMD_PAGE_SATA_LOADED_FLAG(camd_page))
    {
        CAMD_PAGE_SATA_LOADED_FLAG(camd_page) = BIT_FALSE; /*clear flag*/
    }

    /*page loaded from ssd => purge it if dirty*/
    if(BIT_TRUE == CAMD_PAGE_SSD_LOADED_FLAG(camd_page))
    {
        if(BIT_TRUE == CAMD_PAGE_DIRTY_FLAG(camd_page))
        {
            if(EC_FALSE == camd_page_purge_ssd(camd_page))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                                 "purge page [%ld, %ld) from ssd cache failed\n",
                                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

                camd_page_free(camd_page);
                return (EC_FALSE);
            }

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                             "purge page [%ld, %ld) from ssd cache done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        }

        CAMD_PAGE_SSD_LOADED_FLAG(camd_page) = BIT_FALSE; /*clear flag*/
    }

    /*flush dirty page to sata*/
    if(BIT_TRUE == CAMD_PAGE_DIRTY_FLAG(camd_page))
    {
        if(EC_FALSE == camd_page_flush_aio(camd_page))
        {
            /*not flush aio*/
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_page_process: "
                             "submit flushing page [%ld, %ld) to disk failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

            camd_page_free(camd_page);
            return (EC_FALSE);
        }

        CAMD_PAGE_DIRTY_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

        dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                         "submit flushing page [%ld, %ld) to disk done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        /*page would be free later*/
        return (EC_TRUE);
    }

    dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_page_process: "
                     "process page [%ld, %ld) done\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    camd_page_free(camd_page);
    return (EC_TRUE);
}

EC_BOOL camd_page_load_aio_timeout(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_aio_timeout: "
                     "load page [%ld, %ld) timeout\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    if(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page)
    && NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page))
    {
        CAMD_MD     *camd_md;

        camd_md = CAMD_PAGE_CAMD_MD(camd_page);
        camd_del_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page);
    }

    CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_timeout(camd_node);
    }

    camd_page_free(camd_page);
    return (EC_TRUE);
}

EC_BOOL camd_page_load_aio_terminate(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_aio_terminate: "
                     "load page [%ld, %ld) terminated\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    if(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page)
    && NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page))
    {
        CAMD_MD     *camd_md;

        camd_md = CAMD_PAGE_CAMD_MD(camd_page);
        camd_del_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page);
    }

    CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_terminate(camd_node);
    }

    camd_page_free(camd_page);
    return (EC_TRUE);
}

EC_BOOL camd_page_load_aio_complete(CAMD_PAGE *camd_page)
{
    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_load_aio_complete: "
                     "load page [%ld, %ld) completed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

   if(NULL_PTR != CAMD_PAGE_CAMD_MD(camd_page)
    && NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page))
    {
        CAMD_MD     *camd_md;

        camd_md = CAMD_PAGE_CAMD_MD(camd_page);
        camd_del_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page);
    }

    CAMD_PAGE_SATA_LOADED_FLAG(camd_page)  = BIT_TRUE; /*set sata loaded*/
    CAMD_PAGE_SATA_LOADING_FLAG(camd_page) = BIT_FALSE; /*clear flag*/

    /*free camd page determined by process*/
    camd_page_process(camd_page);

    return (EC_TRUE);
}

/*load page from disk to mem cache*/
EC_BOOL camd_page_load_aio(CAMD_PAGE *camd_page)
{
    CAMD_MD                *camd_md;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        CAIO_MD         *caio_md;
        CAIO_CB          caio_cb;

        caio_md = CAMD_MD_CAIO_MD(camd_md);

        caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_PAGE_TIMEOUT_NSEC(camd_page),
                                    (CAIO_CALLBACK)camd_page_load_aio_timeout, (void *)camd_page);

        caio_cb_set_terminate_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_page_load_aio_terminate, (void *)camd_page);
        caio_cb_set_complete_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_page_load_aio_complete, (void *)camd_page);

        /*init temp offset*/
        CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);

        CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

        caio_file_read(caio_md,
                        CAMD_PAGE_FD(camd_page),
                        &CAMD_PAGE_F_T_OFFSET(camd_page),
                        CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                        CAMD_PAGE_M_CACHE(camd_page),
                        &caio_cb);

        /*note: ignore returned value*/
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL camd_page_notify_timeout(CAMD_PAGE *camd_page)
{
    CLIST_DATA      *clist_data;
    CTIMET           cur_ts;

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_notify_timeout: "
                     "page [%ld, %ld) notify the timeout nodes\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    cur_ts = camd_default_get_time();

    CLIST_LOOP_NEXT(CAMD_PAGE_OWNERS(camd_page), clist_data)
    {
        CAMD_NODE       *camd_node;

        camd_node = (CAMD_NODE *)CLIST_DATA_DATA(clist_data);
        CAMD_ASSERT(clist_data == CAMD_NODE_MOUNTED_OWNERS(camd_node));
        if(cur_ts >= CAMD_NODE_NTIME_TS(camd_node))
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
EC_BOOL camd_page_flush_aio_timeout(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_aio_timeout: "
                     "flush page [%ld, %ld) timeout\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_timeout(camd_node);
    }

    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*aio flush terminate*/
EC_BOOL camd_page_flush_aio_terminate(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_aio_terminate: "
                     "flush page [%ld, %ld) terminated\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_terminate(camd_node);
    }

    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*aio flush complete*/
EC_BOOL camd_page_flush_aio_complete(CAMD_PAGE *camd_page)
{
    CAMD_NODE       *camd_node;

    dbg_log(SEC_0125_CAMD, 6)(LOGSTDOUT, "[DEBUG] camd_page_flush_aio_complete: "
                     "flush page [%ld, %ld) completed\n",
                     CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

    CAMD_ASSERT(CAMD_PAGE_F_T_OFFSET(camd_page) == CAMD_PAGE_F_E_OFFSET(camd_page));

    while(NULL_PTR != (camd_node = camd_page_pop_node_front(camd_page)))
    {
        camd_node_complete(camd_node);
    }

    camd_page_free(camd_page);
    return (EC_TRUE);
}

/*flush page to disk*/
EC_BOOL camd_page_flush_aio(CAMD_PAGE *camd_page)
{
    CAMD_MD                *camd_md;

    camd_md = CAMD_PAGE_CAMD_MD(camd_page);

    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        CAIO_MD         *caio_md;
        CAIO_CB          caio_cb;

        caio_md = CAMD_MD_CAIO_MD(camd_md);

        caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_PAGE_TIMEOUT_NSEC(camd_page),
                                    (CAIO_CALLBACK)camd_page_flush_aio_timeout, (void *)camd_page);

        caio_cb_set_terminate_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_page_flush_aio_terminate, (void *)camd_page);
        caio_cb_set_complete_handler(&caio_cb,
                                    (CAIO_CALLBACK)camd_page_flush_aio_complete, (void *)camd_page);

        CAMD_PAGE_F_T_OFFSET(camd_page) = CAMD_PAGE_F_S_OFFSET(camd_page);/*init*/
        CAMD_ASSERT(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES == CAMD_PAGE_F_E_OFFSET(camd_page));

        caio_file_write(caio_md,
                        CAMD_PAGE_FD(camd_page),
                        &CAMD_PAGE_F_T_OFFSET(camd_page),
                        CAMD_PAGE_F_E_OFFSET(camd_page) - CAMD_PAGE_F_S_OFFSET(camd_page),
                        CAMD_PAGE_M_CACHE(camd_page),
                        &caio_cb);

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_aio: "
                         "submit flushing page [%ld, %ld) to disk done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        /*note: ignore returned value*/

        return (EC_TRUE);
    }

    return (EC_FALSE);
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

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_mem: "
                         "flush page [%ld, %ld) to mem cache done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        /*return (EC_TRUE);*/
    }

    /*set flush ssd flag if need*/
    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        CMC_MD          *cmc_md;
        UINT32           offset;

        cmc_md = CAMD_MD_CMC_MD(camd_md);

        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

        /***********************************************************
         * file is dirty => flush to ssd
         * file is loaded from sata => flush to ssd
         * file is loaded from ssd and dirty => flush to ssd
         * otherwise, do not flush to ssd
        ***********************************************************/
        if(BIT_TRUE == CAMD_PAGE_DIRTY_FLAG(camd_page)
        || BIT_TRUE == CAMD_PAGE_SATA_LOADED_FLAG(camd_page))
        {
            if(EC_FALSE == cmc_file_set_flush(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES))
            {
                dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "warn:camd_page_flush_mem: "
                                 "set ssd flush flag of page [%ld, %ld) failed\n",
                                 CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

                return (EC_TRUE); /*ignore error*/
            }

            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_flush_mem: "
                             "set ssd flush flag of page [%ld, %ld) done\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        }
        return (EC_TRUE);
    }

    return (EC_TRUE);
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

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_page_purge_ssd: "
                         "purge page [%ld, %ld) from ssd cache done\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
        return (EC_TRUE);
    }

    return (EC_TRUE);
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
    CAMD_NODE_NTIME_TS(camd_node)       = 0;

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
        CAMD_NODE_NTIME_TS(camd_node)       = 0;
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
                 CAMD_NODE_TIMEOUT_NSEC(camd_node), CAMD_NODE_NTIME_TS(camd_node));

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
    if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_S_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
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
    if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_S_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
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

    if(CAMD_REQ_SUCC_NUM(camd_req) == CAMD_REQ_SUB_SEQ_NUM(camd_req))
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
    CAMD_REQ_SUCC_NUM(camd_req)                 = 0;
    CAMD_REQ_U_S_OFFSET(camd_req)               = 0;

    CAMD_REQ_CAMD_MD(camd_req)                  = NULL_PTR;
    CAMD_REQ_FD(camd_req)                       = ERR_FD;
    CAMD_REQ_M_CACHE(camd_req)                  = NULL_PTR;
    CAMD_REQ_M_BUFF(camd_req)                   = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)                   = NULL_PTR;
    CAMD_REQ_F_S_OFFSET(camd_req)               = 0;
    CAMD_REQ_F_E_OFFSET(camd_req)               = 0;
    CAMD_REQ_TIMEOUT_NSEC(camd_req)             = 0;
    CAMD_REQ_NTIME_TS(camd_req)                 = 0;

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
        CAMD_REQ_SUCC_NUM(camd_req)                 = 0;
        CAMD_REQ_U_S_OFFSET(camd_req)               = 0;

        CAMD_REQ_CAMD_MD(camd_req)                  = NULL_PTR;
        CAMD_REQ_FD(camd_req)                       = ERR_FD;
        CAMD_REQ_M_CACHE(camd_req)                  = NULL_PTR;
        CAMD_REQ_M_BUFF(camd_req)                   = NULL_PTR;
        CAMD_REQ_OFFSET(camd_req)                   = NULL_PTR;
        CAMD_REQ_F_S_OFFSET(camd_req)               = 0;
        CAMD_REQ_F_E_OFFSET(camd_req)               = 0;
        CAMD_REQ_TIMEOUT_NSEC(camd_req)             = 0;
        CAMD_REQ_NTIME_TS(camd_req)                 = 0;
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
                 CAMD_REQ_TIMEOUT_NSEC(camd_req), CAMD_REQ_NTIME_TS(camd_req));

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
        CAMD_NODE_NTIME_TS(camd_node)     = CAMD_REQ_NTIME_TS(camd_req);

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
        CAMD_NODE_NTIME_TS(camd_node)     = CAMD_REQ_NTIME_TS(camd_req);

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
            CAMD_NODE_NTIME_TS(camd_node)     = CAMD_REQ_NTIME_TS(camd_req);

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
            CAMD_NODE_NTIME_TS(camd_node)     = CAMD_REQ_NTIME_TS(camd_req);

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
            CAMD_NODE_NTIME_TS(camd_node)     = CAMD_REQ_NTIME_TS(camd_req);

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
                     CAMD_REQ_TIMEOUT_NSEC(camd_req), CAMD_REQ_NTIME_TS(camd_req));

    /*determine offset & clean up nodes*/
    while(NULL_PTR != (camd_node = camd_req_pop_node_back(camd_req)))
    {
        /*update upper offset at most*/
        if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_S_OFFSET(camd_req))
        {
            CAMD_REQ_U_S_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
        }

        camd_node_free(camd_node);
    }

    if(CAMD_REQ_U_S_OFFSET(camd_req) < CAMD_REQ_F_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_S_OFFSET(camd_req) = CAMD_REQ_F_S_OFFSET(camd_req);
    }

    (*CAMD_REQ_OFFSET(camd_req)) = CAMD_REQ_U_S_OFFSET(camd_req);

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
        if(CAMD_NODE_F_S_OFFSET(camd_node) < CAMD_REQ_U_S_OFFSET(camd_req))
        {
            CAMD_REQ_U_S_OFFSET(camd_req) = CAMD_NODE_F_S_OFFSET(camd_node);
        }

        camd_node_free(camd_node);
    }

    if(CAMD_REQ_U_S_OFFSET(camd_req) < CAMD_REQ_F_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_S_OFFSET(camd_req) = CAMD_REQ_F_S_OFFSET(camd_req);
    }

    (*CAMD_REQ_OFFSET(camd_req)) = CAMD_REQ_U_S_OFFSET(camd_req);

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

    if(CAMD_REQ_U_S_OFFSET(camd_req) < CAMD_REQ_F_S_OFFSET(camd_req))
    {
        CAMD_REQ_U_S_OFFSET(camd_req) = CAMD_REQ_F_S_OFFSET(camd_req);
    }

    (*CAMD_REQ_OFFSET(camd_req)) = CAMD_REQ_U_S_OFFSET(camd_req);

    /*post complete event*/
    camd_req_set_post_event(camd_req, (CAMD_EVENT_HANDLER)camd_req_exec_complete_handler);

    return (EC_TRUE);
}

EC_BOOL camd_req_dispatch_node(CAMD_REQ *camd_req, CAMD_NODE *camd_node)
{
    CAMD_MD     *camd_md;
    CAMD_PAGE   *camd_page;

    camd_md = CAMD_REQ_CAMD_MD(camd_req);

    camd_page = camd_search_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md),
                                CAMD_NODE_F_S_OFFSET(camd_node), CAMD_NODE_F_E_OFFSET(camd_node));
    if(NULL_PTR != camd_page)
    {
        if(EC_FALSE == camd_page_add_node(camd_page, camd_node))
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "error:camd_req_dispatch_node: "
                             "dispatch node %ld/%ld of req %ld, op %s to page [%ld, %ld) failed\n",
                             CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                             CAMD_NODE_SEQ_NO(camd_node),
                             __camd_op_str(CAMD_NODE_OP(camd_node)),
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_dispatch_node: "
                         "dispatch node %ld/%ld of req %ld, op %s to page [%ld, %ld) done\n",
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node),
                         __camd_op_str(CAMD_NODE_OP(camd_node)),
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        return (EC_TRUE);
    }

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
    CAMD_PAGE_TIMEOUT_NSEC(camd_page)   = CAMD_AIO_TIMEOUT_NSEC_DEFAULT;
    CAMD_PAGE_CAMD_MD(camd_page)        = CAMD_NODE_CAMD_MD(camd_node);

#if (SWITCH_OFF == CAMD_PAGE_SHORTCUT_SWITCH)
    /*scenario: not shortcut to mem cache*/
    CAMD_PAGE_M_CACHE(camd_page) = __camd_mem_cache_new(CMCPGB_PAGE_SIZE_NBYTES);
    if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_req_dispatch_node: "
                         "new mem cache for page [%ld, %ld) failed\n",
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));


        camd_page_free(camd_page);
        return (EC_FALSE);
    }
#endif /*(SWITCH_OFF == CAMD_PAGE_SHORTCUT_SWITCH)*/

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
                         "dispatch node %ld/%ld of req %ld, op %s to page [%ld, %ld) failed\n",
                         CAMD_NODE_SUB_SEQ_NO(camd_node), CAMD_NODE_SUB_SEQ_NUM(camd_node),
                         CAMD_NODE_SEQ_NO(camd_node),
                         __camd_op_str(CAMD_NODE_OP(camd_node)),
                         CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));

        camd_del_page(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), camd_page);
        camd_page_free(camd_page);
        return (EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_req_dispatch_node: "
                     "dispatch node %ld/%ld of req %ld, op %s to page [%ld, %ld) done\n",
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

CAMD_MD *camd_start(const UINT32 sata_disk_size /*in GB*/, const UINT32 mem_disk_size /*in MB*/,
                       const int ssd_disk_fd, const UINT32 ssd_disk_offset, const UINT32 ssd_disk_size/*in GB*/)
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

    CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md) = 0; /*set page tree[0] is active*/
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

    if(0 != mem_disk_size)
    {
        CAMD_MD_CMC_MD(camd_md) = cmc_start(sata_disk_size, mem_disk_size);
        if(NULL_PTR == CAMD_MD_CMC_MD(camd_md))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: start cmc module failed\n");

            camd_end(camd_md);
            return (NULL_PTR);
        }
    }

    if(ERR_FD != ssd_disk_fd && 0 != ssd_disk_size)
    {
        if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
        {
            /*set retire callback*/
            cmc_set_retire_callback(CAMD_MD_CMC_MD(camd_md),
                                    (CMCNP_RETIRE_CALLBACK)camd_ssd_flush, (void *)camd_md);
        }

        CAMD_MD_CDC_MD(camd_md) = cdc_start(ssd_disk_fd, ssd_disk_offset, ssd_disk_size);
        if(NULL_PTR == CAMD_MD_CDC_MD(camd_md))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_start: start cdc module failed\n");

            camd_end(camd_md);
            return (NULL_PTR);
        }
    }

    if(NULL_PTR != task_brd_default_get_cepoll())
    {
        /*set epoll*/
        cepoll_set_event(task_brd_default_get_cepoll(),
                         camd_get_eventfd(camd_md),
                         CEPOLL_RD_EVENT,
                         (const char *)"camd_event_handler",
                         (CEPOLL_EVENT_HANDLER)camd_event_handler,
                         (void *)camd_md);

        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)camd_process,
                            (void *)camd_md);
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_start: start camd module %p\n", camd_md);

    return (camd_md);
}

void camd_end(CAMD_MD *camd_md)
{
    if(NULL_PTR != camd_md)
    {
        camd_poll(camd_md);

        camd_cleanup_pages(camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md));
        camd_cleanup_pages(camd_md, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md));
        CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md) = 0;

        camd_cleanup_reqs(camd_md);
        camd_cleanup_post_event_reqs(camd_md);

        if(NULL_PTR != task_brd_default_get_cepoll())
        {
            cepoll_del_event(task_brd_default_get_cepoll(),
                             camd_get_eventfd(camd_md),
                             CEPOLL_RD_EVENT);
        }

        task_brd_process_del(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)camd_process,
                            (void *)camd_md);

        if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
        {
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

        safe_free(camd_md, LOC_CAMD_0012);
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_end: stop camd module %p\n", camd_md);

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

EC_BOOL camd_flush(const CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        if(EC_FALSE == cdc_flush(CAMD_MD_CDC_MD(camd_md)))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_flush: flush cdc failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_flush: flush cdc done\n");
        return (EC_TRUE);
    }
    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_flush: cdc is null\n");
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

/*note: register eventfd and event handler of CDC aio to epoll READ event*/
int camd_get_cdc_eventfd(CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        return cdc_get_eventfd(CAMD_MD_CDC_MD(camd_md));
    }

    return (ERR_FD);
}

/*note: register eventfd and event handler of CDC aio to epoll READ event*/
EC_BOOL camd_cdc_event_handler(CAMD_MD *camd_md)
{
    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        return cdc_event_handler(CAMD_MD_CDC_MD(camd_md));
    }

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
        cmc_process(CAMD_MD_CMC_MD(camd_md));
    }

    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        cdc_poll(CAMD_MD_CDC_MD(camd_md));
    }

    return (EC_TRUE);
}

void camd_process(CAMD_MD *camd_md)
{
    camd_process_pages(camd_md);
    camd_process_events(camd_md);
    camd_process_reqs(camd_md);

    if(NULL_PTR != CAMD_MD_CAIO_MD(camd_md))
    {
        caio_process(CAMD_MD_CAIO_MD(camd_md));
    }

    if(NULL_PTR != CAMD_MD_CMC_MD(camd_md))
    {
        cmc_process(CAMD_MD_CMC_MD(camd_md));
    }

    if(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        cdc_process(CAMD_MD_CDC_MD(camd_md));
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
    CTIMET           cur_ts;

    cur_ts  = camd_default_get_time();
    req_num = 0;

    CLIST_LOOP_NEXT(CAMD_MD_REQ_LIST(camd_md), clist_data)
    {
        CAMD_REQ       *camd_req;

        camd_req = (CAMD_REQ *)CLIST_DATA_DATA(clist_data);
        CAMD_ASSERT(CAMD_REQ_MOUNTED_REQS(camd_req) == clist_data);

        if(cur_ts >= CAMD_REQ_NTIME_TS(camd_req))
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

    rlog(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_timeout_reqs: process %ld timeout reqs\n", req_num);

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
        if(BIT_TRUE == CAMD_PAGE_SATA_LOADING_FLAG(camd_page))
        {
            /*add to standby page tree temporarily*/
            camd_add_page(camd_md, standby_page_tree_idx, camd_page);
            continue;
        }

        camd_process_page(camd_md, camd_page);
    }

    /*switch page tree*/
    CAMD_MD_SWITCH_PAGE_TREE(camd_md);

    return;
}

void camd_process_page(CAMD_MD *camd_md, CAMD_PAGE *camd_page)
{
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
            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: mem miss page [%ld, %ld)\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            /*fall through to aio*/
            break;
        }

        /*TODO: optimize => shortcut to page of cmc cache without reading*/

        /*load page from mem cache*/
        offset = CAMD_PAGE_F_S_OFFSET(camd_page);

#if (SWITCH_ON == CAMD_PAGE_SHORTCUT_SWITCH)
        /*scenario: shortcut to mem cache page*/
        CAMD_PAGE_M_CACHE(camd_page) = cmc_file_locate(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES);
        if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: mem hit page [%ld, %ld) "
                                                 "but locate failed\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            /*fall through to aio*/
            break;
        }

        CAMD_ASSERT(EC_TRUE == __camd_mem_cache_check(CAMD_PAGE_M_CACHE(camd_page)));

        CAMD_PAGE_MEM_CACHE_FLAG(camd_page) = BIT_TRUE;

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: mem hit page [%ld, %ld) "
                                             "locate done\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));
#endif /*(SWITCH_ON == CAMD_PAGE_SHORTCUT_SWITCH)*/

#if (SWITCH_OFF == CAMD_PAGE_SHORTCUT_SWITCH)
        if(EC_FALSE == cmc_file_read(cmc_md, &offset, CMCPGB_PAGE_SIZE_NBYTES, CAMD_PAGE_M_CACHE(camd_page)))
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: mem hit page [%ld, %ld) "
                                                 "but read failed\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            /*fall through to aio*/
            break;
        }
#endif /*(SWITCH_OFF == CAMD_PAGE_SHORTCUT_SWITCH)*/

        if(CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES != offset)
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: mem hit page [%ld, %ld) "
                                                 "but expected offset %ld != %ld\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page),
                                                 CAMD_PAGE_F_S_OFFSET(camd_page) + CMCPGB_PAGE_SIZE_NBYTES,
                                                 offset);

#if (SWITCH_ON == CAMD_PAGE_SHORTCUT_SWITCH)
            CAMD_PAGE_M_CACHE(camd_page)        = NULL_PTR; /*clear*/
            CAMD_PAGE_MEM_CACHE_FLAG(camd_page) = BIT_FALSE;/*clear*/
#endif /*(SWITCH_ON == CAMD_PAGE_SHORTCUT_SWITCH)*/

            /*fall through to aio*/
            break;
        }

        dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: mem hit page [%ld, %ld)\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));

        /*page life cycle is determined by process => not need to free page*/
        if(EC_FALSE == camd_page_process(camd_page))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: process page [%ld, %ld) failed\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));
            return;
        }

        /*here page may not be accessable => not output log info*/
        return;
    }

#if (SWITCH_ON == CAMD_PAGE_SHORTCUT_SWITCH)
    if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
    {
        CAMD_PAGE_M_CACHE(camd_page) = __camd_mem_cache_new(CMCPGB_PAGE_SIZE_NBYTES);
        if(NULL_PTR == CAMD_PAGE_M_CACHE(camd_page))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: "
                             "new mem cache for page [%ld, %ld) failed\n",
                             CAMD_PAGE_F_S_OFFSET(camd_page), CAMD_PAGE_F_E_OFFSET(camd_page));


            camd_page_free(camd_page);
            return;
        }
    }
#endif/*(SWITCH_ON == CAMD_PAGE_SHORTCUT_SWITCH)*/

    /*check page in ssd cache*/
    while(NULL_PTR != CAMD_MD_CDC_MD(camd_md))
    {
        CDC_MD      *cdc_md;
        CDCNP_KEY    cdcnp_key;
        UINT32       offset;

        cdc_md = CAMD_MD_CDC_MD(camd_md);

        CAMD_ASSERT(0 == (CAMD_PAGE_F_S_OFFSET(camd_page) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));
        CAMD_ASSERT(0 == (CAMD_PAGE_F_E_OFFSET(camd_page) & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

        CDCNP_KEY_S_PAGE(&cdcnp_key) = (CAMD_PAGE_F_S_OFFSET(camd_page) >> CDCPGB_PAGE_SIZE_NBITS);
        CDCNP_KEY_E_PAGE(&cdcnp_key) = (CAMD_PAGE_F_E_OFFSET(camd_page) >> CDCPGB_PAGE_SIZE_NBITS);

        if(EC_FALSE == cdc_search(cdc_md, &cdcnp_key))
        {
            dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: ssd miss page [%ld, %ld)\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            /*fall through to aio*/
            break;
        }

        /*load page from ssd cache*/
        offset = CAMD_PAGE_F_S_OFFSET(camd_page);
        if(EC_FALSE == cdc_file_read(cdc_md, &offset, CDCPGB_PAGE_SIZE_NBYTES, CAMD_PAGE_M_CACHE(camd_page)))
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: ssd hit page [%ld, %ld) "
                                                 "but read failed\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));

            /*fall through to aio*/
            break;
        }

        if(CAMD_PAGE_F_S_OFFSET(camd_page) + CDCPGB_PAGE_SIZE_NBYTES != offset)
        {
            dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_page: ssd hit page [%ld, %ld) "
                                                 "but expected offset %ld != %ld\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page),
                                                 CAMD_PAGE_F_S_OFFSET(camd_page) + CDCPGB_PAGE_SIZE_NBYTES,
                                                 offset);

            /*fall through to aio*/
            break;
        }

        CAMD_PAGE_SSD_LOADED_FLAG(camd_page) = BIT_TRUE; /*set ssd loaded*/

        dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: ssd hit page [%ld, %ld)\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));

        /*page life cycle is determined by process => not need to free page*/
        if(EC_FALSE == camd_page_process(camd_page))
        {
            dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: process page [%ld, %ld) failed\n",
                                                 CAMD_PAGE_F_S_OFFSET(camd_page),
                                                 CAMD_PAGE_F_E_OFFSET(camd_page));
            return;
        }

        /*here page may not be accessable => not output log info*/
        return;
    }

    /*load page from sata to mem cache*/
    if(EC_FALSE == camd_page_load_aio(camd_page))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_process_page: submit loading page [%ld, %ld) failed\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));

        camd_page_free(camd_page);
        return;
    }

    /*add page to standby page tree temporarily*/
    camd_add_page(camd_md, CAMD_MD_STANDBY_PAGE_TREE_IDX(camd_md), camd_page);
    CAMD_PAGE_SATA_LOADING_FLAG(camd_page)  = BIT_TRUE; /*set flag*/

    dbg_log(SEC_0125_CAMD, 5)(LOGSTDOUT, "[DEBUG] camd_process_page: submit loading page [%ld, %ld) done\n",
                                         CAMD_PAGE_F_S_OFFSET(camd_page),
                                         CAMD_PAGE_F_E_OFFSET(camd_page));

    /*camd_page would be free later*/
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

    rlog(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_process_post_event_reqs: process %ld reqs\n", counter);

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

void camd_show_page(LOG *log, const CAMD_MD *camd_md, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CAMD_PAGE   *camd_page;

    camd_page = camd_search_page((CAMD_MD *)camd_md, CAMD_MD_ACTIVE_PAGE_TREE_IDX(camd_md), f_s_offset, f_e_offset);
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

    CAMD_PAGE_MOUNTED_PAGES(camd_page) = crb_node;

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_add_page: add page [%ld, %ld) done\n",
                                         CAMD_PAGE_F_S_OFFSET(camd_page),
                                         CAMD_PAGE_F_E_OFFSET(camd_page));
    return (EC_TRUE);
}

EC_BOOL camd_del_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, CAMD_PAGE *camd_page)
{
    if(NULL_PTR != CAMD_PAGE_MOUNTED_PAGES(camd_page))
    {
        crb_tree_erase(CAMD_MD_PAGE_TREE(camd_md, page_tree_idx), CAMD_PAGE_MOUNTED_PAGES(camd_page));
        CAMD_PAGE_MOUNTED_PAGES(camd_page) = NULL_PTR;

        dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_del_page: del page [%ld, %ld) done\n",
                                             CAMD_PAGE_F_S_OFFSET(camd_page),
                                             CAMD_PAGE_F_E_OFFSET(camd_page));
    }
    return (EC_TRUE);
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
    CAMD_PAGE_MOUNTED_PAGES(camd_page) = NULL_PTR;

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
    CAMD_PAGE_MOUNTED_PAGES(camd_page) = NULL_PTR;

    return (camd_page);
}

CAMD_PAGE *camd_search_page(CAMD_MD *camd_md, const UINT32 page_tree_idx, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CAMD_PAGE       camd_page_t;
    CRB_NODE       *crb_node;

    CAMD_PAGE_FD(&camd_page_t)         = ANY_FD;
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

/*flush one page when cmc retire it*/
EC_BOOL camd_ssd_flush(CAMD_MD *camd_md, const CMCNP_KEY *cmcnp_key, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no)
{
    CMC_MD          *cmc_md;
    CDC_MD          *cdc_md;

    UINT8           *buff;
    UINT32           offset;
    UINT32           offset_t;
    UINT32           wsize;

    if(NULL_PTR == CAMD_MD_CMC_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cmc is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CAMD_MD_CDC_MD(camd_md))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: cdc is null\n");
        return (EC_FALSE);
    }

    cmc_md = CAMD_MD_CMC_MD(camd_md);
    cdc_md = CAMD_MD_CDC_MD(camd_md);

    buff = cmcdn_node_locate(CMC_MD_DN(cmc_md), disk_no, block_no, page_no);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: "
                                             "locate (disk %u, block %u, page %u) failed\n",
                                             disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    offset   = (((UINT32)CMCNP_KEY_S_PAGE(cmcnp_key)) << ((UINT32)CDCPGB_PAGE_SIZE_NBITS));
    offset_t = offset;
    wsize    = CDCPGB_PAGE_SIZE_NBYTES;

    if(EC_FALSE == cdc_file_write(cdc_md, &offset_t, wsize, buff))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_ssd_flush: "
                                             "flush ssd to offset %ld, size %ld failed\n",
                                             offset, wsize);
        return (EC_FALSE);
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_ssd_flush: "
                                         "flush ssd to offset %ld, size %ld done\n",
                                         offset, wsize);
    return (EC_TRUE);
}

/*----------------------------------- camd external interface -----------------------------------*/
STATIC_CAST static EC_BOOL __camd_file_read_timeout(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0013);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_read_terminate(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0014);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_read_complete(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0015);
    return (EC_TRUE);
}

EC_BOOL camd_file_read(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    CAIO_CB              caio_cb;
    COROUTINE_COND       coroutine_cond;

    CAMD_REQ            *camd_req;

    CAMD_ASSERT(NULL_PTR != offset);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_AIO_TIMEOUT_NSEC_DEFAULT /*seconds*/,
                                (CAMD_CALLBACK)__camd_file_read_timeout, (void *)&coroutine_cond);

    caio_cb_set_terminate_handler(&caio_cb, (CAMD_CALLBACK)__camd_file_read_terminate, (void *)&coroutine_cond);
    caio_cb_set_complete_handler(&caio_cb, (CAMD_CALLBACK)__camd_file_read_complete, (void *)&coroutine_cond);

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

    CAMD_REQ_SEQ_NO(camd_req)       = ++ CAMD_MD_SEQ_NO(camd_md);
    CAMD_REQ_OP(camd_req)           = CAMD_OP_RD;

    CAMD_REQ_CAMD_MD(camd_req)      = camd_md;
    CAMD_REQ_FD(camd_req)           = fd;
    CAMD_REQ_M_BUFF(camd_req)       = buff;
    CAMD_REQ_M_CACHE(camd_req)      = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)       = offset;
    CAMD_REQ_F_S_OFFSET(camd_req)   = (*offset);
    CAMD_REQ_F_E_OFFSET(camd_req)   = (*offset) + rsize;
    CAMD_REQ_U_S_OFFSET(camd_req)   = CAMD_REQ_F_E_OFFSET(camd_req);
    CAMD_REQ_TIMEOUT_NSEC(camd_req) = CAIO_CB_TIMEOUT_NSEC(&caio_cb);
    CAMD_REQ_NTIME_TS(camd_req)     = caio_default_get_time() + CAIO_CB_TIMEOUT_NSEC(&caio_cb);

    if(EC_FALSE == camd_submit_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read: submit req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    }

    coroutine_cond_init(&coroutine_cond, 0 /*never timeout*/, LOC_CAMD_0016);
    coroutine_cond_reserve(&coroutine_cond, 1, LOC_CAMD_0017);
    coroutine_cond_wait(&coroutine_cond, LOC_CAMD_0018);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_read: "
                                             "submit req %ld but coroutine was cancelled\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    } else { /*normal*/
        /*do nothing*/
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_file_read: submit req %ld done\n",
                                         CAMD_REQ_SEQ_NO(camd_req));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_write_timeout(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0019);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_write_terminate(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0020);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __camd_file_write_complete(COROUTINE_COND *coroutine_cond)
{
    coroutine_cond_release(coroutine_cond, LOC_CAMD_0021);
    return (EC_TRUE);
}

EC_BOOL camd_file_write(CAMD_MD *camd_md, int fd, UINT32 *offset, const UINT32 wsize, const UINT8 *buff)
{
    CAIO_CB              caio_cb;
    COROUTINE_COND       coroutine_cond;

    CAMD_REQ            *camd_req;

    CAMD_ASSERT(NULL_PTR != offset);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CAMD_AIO_TIMEOUT_NSEC_DEFAULT /*seconds*/,
                                (CAMD_CALLBACK)__camd_file_write_timeout, (void *)&coroutine_cond);

    caio_cb_set_terminate_handler(&caio_cb, (CAMD_CALLBACK)__camd_file_write_terminate, (void *)&coroutine_cond);
    caio_cb_set_complete_handler(&caio_cb, (CAMD_CALLBACK)__camd_file_write_complete, (void *)&coroutine_cond);

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

    CAMD_REQ_SEQ_NO(camd_req)       = ++ CAMD_MD_SEQ_NO(camd_md);
    CAMD_REQ_OP(camd_req)           = CAMD_OP_WR;

    CAMD_REQ_CAMD_MD(camd_req)      = camd_md;
    CAMD_REQ_FD(camd_req)           = fd;
    CAMD_REQ_M_BUFF(camd_req)       = (UINT8 *)buff;
    CAMD_REQ_M_CACHE(camd_req)      = NULL_PTR;
    CAMD_REQ_OFFSET(camd_req)       = offset;
    CAMD_REQ_F_S_OFFSET(camd_req)   = (*offset);
    CAMD_REQ_F_E_OFFSET(camd_req)   = (*offset) + wsize;
    CAMD_REQ_U_S_OFFSET(camd_req)   = CAMD_REQ_F_E_OFFSET(camd_req);
    CAMD_REQ_TIMEOUT_NSEC(camd_req) = CAIO_CB_TIMEOUT_NSEC(&caio_cb);
    CAMD_REQ_NTIME_TS(camd_req)     = caio_default_get_time() + CAIO_CB_TIMEOUT_NSEC(&caio_cb);

    if(EC_FALSE == camd_submit_req(camd_md, camd_req))
    {
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write: submit req %ld failed\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    }

    coroutine_cond_init(&coroutine_cond, 0 /*never timeout*/, LOC_CAMD_0022);
    coroutine_cond_reserve(&coroutine_cond, 1, LOC_CAMD_0023);
    coroutine_cond_wait(&coroutine_cond, LOC_CAMD_0024);

    __COROUTINE_IF_EXCEPTION() {/*exception*/
        dbg_log(SEC_0125_CAMD, 0)(LOGSTDOUT, "error:camd_file_write: "
                                             "submit req %ld but coroutine was cancelled\n",
                                             CAMD_REQ_SEQ_NO(camd_req));

        camd_req_free(camd_req);
        return (EC_FALSE);
    } else { /*normal*/
        /*do nothing*/
    }

    dbg_log(SEC_0125_CAMD, 9)(LOGSTDOUT, "[DEBUG] camd_file_write: submit req %ld done\n",
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


#ifdef __cplusplus
}
#endif/*__cplusplus*/

