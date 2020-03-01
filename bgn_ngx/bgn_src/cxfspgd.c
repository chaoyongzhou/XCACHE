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
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "task.h"

#include "cmisc.h"
#include "real.h"

#include "cxfspgrb.h"
#include "cxfspgb.h"
#include "cxfspgd.h"

/*page-cache disk:1TB = 2^14 page-cache block*/

/************************************************************************************************
  comment:
  ========
   1. if one block can assign max pages with page model, then put the block into page model
      RB tree of disk
   2. one block was in at most one RB tree
************************************************************************************************/

#if (SWITCH_ON == CXFS_ASSERT_SWITCH)
#define CXFSPGD_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CXFS_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CXFS_ASSERT_SWITCH)
#define CXFSPGD_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CXFS_ASSERT_SWITCH)*/

static CXFSPGD_CFG g_cxfspgd_cfg_tbl[] = {
    {(const char *)"64M"  , (const char *)"CXFSPGD_064MB_BLOCK_NUM", CXFSPGD_064MB_BLOCK_NUM, 0, 0 },
    {(const char *)"128M" , (const char *)"CXFSPGD_128MB_BLOCK_NUM", CXFSPGD_128MB_BLOCK_NUM, 0, 0 },
    {(const char *)"256M" , (const char *)"CXFSPGD_256MB_BLOCK_NUM", CXFSPGD_256MB_BLOCK_NUM, 0, 0 },
    {(const char *)"512M" , (const char *)"CXFSPGD_512MB_BLOCK_NUM", CXFSPGD_512MB_BLOCK_NUM, 0, 0 },
    {(const char *)"1G"   , (const char *)"CXFSPGD_001GB_BLOCK_NUM", CXFSPGD_001GB_BLOCK_NUM, 0, 0 },
    {(const char *)"2G"   , (const char *)"CXFSPGD_002GB_BLOCK_NUM", CXFSPGD_002GB_BLOCK_NUM, 0, 0 },
    {(const char *)"4G"   , (const char *)"CXFSPGD_004GB_BLOCK_NUM", CXFSPGD_004GB_BLOCK_NUM, 0, 0 },
    {(const char *)"8G"   , (const char *)"CXFSPGD_008GB_BLOCK_NUM", CXFSPGD_008GB_BLOCK_NUM, 0, 0 },
    {(const char *)"16G"  , (const char *)"CXFSPGD_016GB_BLOCK_NUM", CXFSPGD_016GB_BLOCK_NUM, 0, 0 },
    {(const char *)"32G"  , (const char *)"CXFSPGD_032GB_BLOCK_NUM", CXFSPGD_032GB_BLOCK_NUM, 0, 0 },
    {(const char *)"64G"  , (const char *)"CXFSPGD_064GB_BLOCK_NUM", CXFSPGD_064GB_BLOCK_NUM, 0, 0 },
    {(const char *)"128G" , (const char *)"CXFSPGD_128GB_BLOCK_NUM", CXFSPGD_128GB_BLOCK_NUM, 0, 0 },
    {(const char *)"256G" , (const char *)"CXFSPGD_256GB_BLOCK_NUM", CXFSPGD_256GB_BLOCK_NUM, 0, 0 },
    {(const char *)"512G" , (const char *)"CXFSPGD_512GB_BLOCK_NUM", CXFSPGD_512GB_BLOCK_NUM, 0, 0 },
    {(const char *)"1T"   , (const char *)"CXFSPGD_001TB_BLOCK_NUM", CXFSPGD_001TB_BLOCK_NUM, 0, 0 },
};

static uint8_t g_cxfspgd_cfg_tbl_len = (uint8_t)(sizeof(g_cxfspgd_cfg_tbl)/sizeof(g_cxfspgd_cfg_tbl[0]));

const char *cxfspgd_model_str(const uint16_t pgd_block_num)
{
    uint8_t cxfspgd_model;

    for(cxfspgd_model = 0; cxfspgd_model < g_cxfspgd_cfg_tbl_len; cxfspgd_model ++)
    {
        CXFSPGD_CFG *cxfspgd_cfg;

        cxfspgd_cfg = &(g_cxfspgd_cfg_tbl[ cxfspgd_model ]);
        if(pgd_block_num == CXFSPGD_CFG_BLOCK_NUM(cxfspgd_cfg))
        {
            return CXFSPGD_CFG_MODEL_STR(cxfspgd_cfg);
        }
    }

    return (const char *)"unkown";
}

uint16_t cxfspgd_model_get(const char *model_str)
{
    uint8_t cxfspgd_model;

    for(cxfspgd_model = 0; cxfspgd_model < g_cxfspgd_cfg_tbl_len; cxfspgd_model ++)
    {
        CXFSPGD_CFG *cxfspgd_cfg;
        cxfspgd_cfg = &(g_cxfspgd_cfg_tbl[ cxfspgd_model ]);

        if(0 == strcasecmp(CXFSPGD_CFG_MODEL_STR(cxfspgd_cfg), model_str))
        {
            return CXFSPGD_CFG_BLOCK_NUM(cxfspgd_cfg);
        }
    }
    return (CXFSPGD_ERROR_BLOCK_NUM);
}

STATIC_CAST static uint16_t __cxfspgd_page_model_first_block(const CXFSPGD *cxfspgd, const uint16_t page_model)
{
    uint16_t node_pos;
    const CXFSPGRB_NODE *node;

    node_pos = cxfspgrb_tree_first_node(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model));
    if(CXFSPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:__cxfspgd_page_model_first_block: no free page in page model %u\n", page_model);
        return (CXFSPGRB_ERR_POS);
    }

    node = CXFSPGRB_POOL_NODE(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), node_pos);
    return (CXFSPGRB_NODE_DATA(node));
}

STATIC_CAST static uint16_t __cxfspgd_page_model_get(const CXFSPGD *cxfspgd, const uint16_t assign_bitmap)
{
    uint16_t page_model;
    uint16_t e;

    for(page_model = 0, e = 1; CXFSPGB_MODEL_NUM > page_model && 0 == (assign_bitmap & e); page_model ++, e <<= 1)
    {
      /*do nothing*/
    }
    return (page_model);
}

STATIC_CAST static CXFSPGB *__cxfspgd_block(CXFSPGD *cxfspgd, const uint16_t  block_no)
{
    return (CXFSPGB *)(((void *)CXFSPGD_HEADER(cxfspgd)) + CXFSPGD_HDR_SIZE + block_no * CXFSPGB_SIZE);
}

CXFSPGD_HDR *cxfspgd_hdr_new(uint8_t *base, const uint16_t block_num)
{
    CXFSPGD_HDR *cxfspgd_hdr;
    uint16_t  page_model;

    cxfspgd_hdr = (CXFSPGD_HDR *)base;

    if(EC_FALSE == cxfspgrb_pool_init(CXFSPGD_HDR_CXFSPGRB_POOL(cxfspgd_hdr), block_num))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_hdr_new: init cxfspgrb pool failed where block_num = %u\n", block_num);
        return (NULL_PTR);
    }

    for(page_model = 0; CXFSPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CXFSPGD_HDR_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd_hdr, page_model) = CXFSPGRB_ERR_POS;
    }

    CXFSPGD_HDR_ASSIGN_BITMAP(cxfspgd_hdr) = 0;

    CXFSPGD_HDR_PAGE_BLOCK_MAX_NUM(cxfspgd_hdr) = block_num;

    /*statistics*/
    CXFSPGD_HDR_PAGE_MAX_NUM(cxfspgd_hdr)          = block_num * CXFSPGD_BLOCK_PAGE_NUM;
    CXFSPGD_HDR_PAGE_USED_NUM(cxfspgd_hdr)         = 0;
    CXFSPGD_HDR_PAGE_ACTUAL_USED_SIZE(cxfspgd_hdr) = 0;

    return (cxfspgd_hdr);
}

CXFSPGD *cxfspgd_new(uint8_t *base, const uint16_t block_num)
{
    CXFSPGD      *cxfspgd;
    uint16_t   block_no;

    if(CXFSPGD_MAX_BLOCK_NUM < block_num)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_new: block_num %u overflow\n", block_num);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CXFSPGD, &cxfspgd, LOC_CXFSPGD_0001);
    if(NULL_PTR == cxfspgd)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_new:malloc cxfspgd failed\n");
        return (NULL_PTR);
    }

    cxfspgd_init(cxfspgd);

    CXFSPGD_FSIZE(cxfspgd)  = cxfspgd_size(block_num);

    CXFSPGD_HEADER(cxfspgd) = cxfspgd_hdr_new(base, block_num);
    if(NULL_PTR == CXFSPGD_HEADER(cxfspgd))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_new: new cxfspgd header failed\n");
        cxfspgd_free(cxfspgd);
        return (NULL_PTR);
    }

    /*init blocks*/
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no) = __cxfspgd_block(cxfspgd, block_no);
        cxfspgb_init(CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no), CXFSPGD_BLOCK_PAGE_MODEL);
        cxfspgd_add_block(cxfspgd, block_no, CXFSPGD_BLOCK_PAGE_MODEL);

        if(0 == ((block_no + 1) % 1000))
        {
            dbg_log(SEC_0202_CXFSPGD, 3)(LOGSTDOUT, "info:cxfspgd_new: init block %u - %u done\n",
                                                 block_no - 999, block_no);
        }
    }
    dbg_log(SEC_0202_CXFSPGD, 3)(LOGSTDOUT, "info:cxfspgd_new: init %u blocks done\n", block_num);

    return (cxfspgd);
}

EC_BOOL cxfspgd_free(CXFSPGD *cxfspgd)
{
    if(NULL_PTR != cxfspgd)
    {
        UINT32 block_num;
        UINT32 block_no;

        /*clean blocks*/
        block_num = CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd);
        for(block_no = 0; block_no < block_num; block_no ++)
        {
            CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no) = NULL_PTR;
        }

        CXFSPGD_HEADER(cxfspgd) = NULL_PTR;

        free_static_mem(MM_CXFSPGD, cxfspgd, LOC_CXFSPGD_0002);
    }

    return (EC_TRUE);
}

CXFSPGD *cxfspgd_open(UINT8 *base, const UINT32 size)
{
    CXFSPGD      *cxfspgd;

    uint16_t      block_num;
    uint16_t      block_no;

    alloc_static_mem(MM_CXFSPGD, &cxfspgd, LOC_CXFSPGD_0003);
    if(NULL_PTR == cxfspgd)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_open:malloc cxfspgd failed\n");
        return (NULL_PTR);
    }

    cxfspgd_init(cxfspgd);

    CXFSPGD_FSIZE(cxfspgd)  = size;
    CXFSPGD_HEADER(cxfspgd) = (CXFSPGD_HDR *)base;

    /*init blocks*/
    block_num = CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd);
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no) = __cxfspgd_block(cxfspgd, block_no);
    }

    return (cxfspgd);
}

EC_BOOL cxfspgd_close(CXFSPGD *cxfspgd)
{
    if(NULL_PTR != cxfspgd)
    {
        /*clean blocks*/
        if(NULL_PTR != CXFSPGD_HEADER(cxfspgd))
        {
            UINT32 block_num;
            UINT32 block_no;

            block_num = CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd);
            for(block_no = 0; block_no < block_num; block_no ++)
            {
                CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no) = NULL_PTR;
            }
        }

        CXFSPGD_HEADER(cxfspgd) = NULL_PTR;

        free_static_mem(MM_CXFSPGD, cxfspgd, LOC_CXFSPGD_0004);
    }
    return (EC_TRUE);
}


/* one disk = 1TB */
EC_BOOL cxfspgd_init(CXFSPGD *cxfspgd)
{
    uint16_t block_no;

    CXFSPGD_FSIZE(cxfspgd)  = 0;
    CXFSPGD_HEADER(cxfspgd) = NULL_PTR;

    for(block_no = 0; block_no < CXFSPGD_MAX_BLOCK_NUM; block_no ++)
    {
        CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no) = NULL_PTR;
    }

    return (EC_TRUE);
}

void cxfspgd_clean(CXFSPGD *cxfspgd)
{
    uint16_t block_no;

    CXFSPGD_FSIZE(cxfspgd)  = 0;
    CXFSPGD_HEADER(cxfspgd) = NULL_PTR;

    for(block_no = 0; block_no < CXFSPGD_MAX_BLOCK_NUM; block_no ++)
    {
        CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no) = NULL_PTR;
    }

    return;
}

/*add one free block into pool*/
EC_BOOL cxfspgd_add_block(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_model)
{
    if(CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd) <= block_no)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_add_block: block_no %u overflow where block max num is %u\n", block_no, CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd));
        return (EC_FALSE);
    }

    /*insert block_no to rbtree*/
    if(CXFSPGRB_ERR_POS == cxfspgrb_tree_insert_data(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), &(CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model)), block_no))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_add_block: add block_no %u to rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd) |= (uint16_t)(~((1 << page_model) - 1)) & CXFSPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free block from pool*/
EC_BOOL cxfspgd_del_block(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_model)
{
    /*del block_no from rbtree*/
    if(EC_FALSE == cxfspgrb_tree_delete_data(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), &(CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model)), block_no))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_del_block: del block_no %u from rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CXFSPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model_t))/*this page-model is empty*/
        )
        {
            CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cxfspgd_assign_block(CXFSPGD *cxfspgd, uint16_t *page_model, uint16_t *block_no)
{
    uint16_t block_no_t;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd) & mask))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:__cxfspgd_assign_block: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd), mask);
        return (EC_FALSE);
    }

    while(CXFSPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CXFSPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:__cxfspgd_assign_block: no free block available from page model %u\n", *page_model);
        return (EC_FALSE);
    }

    block_no_t = __cxfspgd_page_model_first_block(cxfspgd, page_model_t);
    if(CXFSPGRB_ERR_POS == block_no_t)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:__cxfspgd_assign_block: no free block in page model %u\n", page_model_t);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;
    (*block_no)   = block_no_t;

    return (EC_TRUE);
}

EC_BOOL cxfspgd_new_space(CXFSPGD *cxfspgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no)
{
    CXFSPGB    *cxfspgb;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t e;
    uint16_t t;
    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t block_no_t;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CXFSPGD_ASSERT(0 < size);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);
    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDNULL, "[DEBUG] cxfspgd_new_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CXFSPGD_ASSERT(CXFSPGB_064MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CXFSPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDNULL, "[DEBUG] cxfspgd_new_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CXFSPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDNULL, "[DEBUG] cxfspgd_new_space: page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   page_num_need, page_model, (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model)));

    for(;;)/*Oops! fix inconsistency between cxfspgd and cxfspgb*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;

        if(EC_FALSE == __cxfspgd_assign_block(cxfspgd, &page_model_t, &block_no_t))
        {
            dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_new_space: assign one block from page model %u failed\n", page_model_t);
            return (EC_FALSE);
        }

        cxfspgb = CXFSPGD_BLOCK_NODE(cxfspgd, block_no_t);
        pgb_assign_bitmap_old = CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb);

        if(EC_TRUE == cxfspgb_new_space(cxfspgb, size, &page_no_t))
        {
            page_model = page_model_t; /*re-init page_model*/
            break;
        }

        /*find inconsistent, fix it!*/
        cxfspgd_del_block(cxfspgd, block_no_t, page_model_t);

        while(CXFSPGB_MODEL_NUM > page_model_t
           && 0 == (pgb_assign_bitmap_old & (uint16_t)(1 << page_model_t))
           )
        {
             page_model_t ++;
        }
        CXFSPGD_ASSERT(CXFSPGB_MODEL_NUM > page_model_t);
        cxfspgd_add_block(cxfspgd, block_no_t, page_model_t);

        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "warn:cxfspgd_new_space: block %u relocation to page model %u\n", block_no_t, page_model_t);
    }

    pgb_assign_bitmap_new = CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb);

    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_new_space: block_no_t %u: pgb bitmap %x => %x\n", block_no_t, pgb_assign_bitmap_old, pgb_assign_bitmap_new);

    /*pgb_assign_bitmap changes may make pgd_assign_bitmap changes*/
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_new_space: before delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)),
        //                    c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)));

        cxfspgd_del_block(cxfspgd, block_no_t, page_model);

        //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_new_space: after  delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)),
        //                    c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)));

        if(EC_FALSE == cxfspgb_is_full(cxfspgb))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CXFSPGB_MODEL_NUM > page_model_t
               && 0 == (pgb_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }
            CXFSPGD_ASSERT(CXFSPGB_MODEL_NUM > page_model_t);
            //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_new_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            cxfspgd_add_block(cxfspgd, block_no_t, page_model_t);
            //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_new_space: block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
            //                    block_no_t,
            //                    c_uint16_t_to_bin_str(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)),
            //                    c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CXFSPGD_PAGE_USED_NUM(cxfspgd)         += page_num_need;
    CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd) += size;

    CXFSPGD_ASSERT(EC_TRUE == cxfspgd_check(cxfspgd));

    dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_new_space: pgd_page_used_num %u due to increment %u\n",
                        CXFSPGD_PAGE_USED_NUM(cxfspgd), page_num_need);
    dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_new_space: pgd_actual_used_size %"PRId64" due to increment %u\n",
                        CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd), size);

    return (EC_TRUE);
}

EC_BOOL cxfspgd_free_space(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    CXFSPGB    *cxfspgb;

    uint16_t page_num_used;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CXFSPGD_ASSERT(0 < size);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    cxfspgb = CXFSPGD_BLOCK_NODE(cxfspgd, block_no);
    pgb_assign_bitmap_old = CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb);

    if(EC_FALSE == cxfspgb_free_space(cxfspgb, page_no, size))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_free_space: block_no %u free space of page_no %u, size %u failed\n",
                           block_no, page_no, size);
        return (EC_FALSE);
    }

    pgb_assign_bitmap_new = CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb);

    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        uint16_t page_model_old;
        uint16_t page_model_new;

        page_model_old = __cxfspgd_page_model_get(cxfspgd, pgb_assign_bitmap_old);
        page_model_new = __cxfspgd_page_model_get(cxfspgd, pgb_assign_bitmap_new);

        if(CXFSPGB_MODEL_NUM > page_model_old)
        {
            cxfspgd_del_block(cxfspgd, block_no, page_model_old);
        }

        if(EC_FALSE == cxfspgd_add_block(cxfspgd, block_no, page_model_new))
        {
            dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_free_space: add block %d, page_model_new %u failed, fix it!\n",
                                block_no, page_model_new);
            abort();
        }
    }

    page_num_used = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);

    CXFSPGD_PAGE_USED_NUM(cxfspgd)         -= page_num_used;
    CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd) -= size;

    dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_free_space: pgd_page_used_num %u due to decrement %u\n",
                        CXFSPGD_PAGE_USED_NUM(cxfspgd), page_num_used);
    dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_free_space: pgd_actual_used_size %"PRId64" due to decrement %u\n",
                        CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd), size);

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cxfspgd_extract_block(CXFSPGD *cxfspgd, uint16_t *page_model, const uint16_t block_no)
{
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd) & mask))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:__cxfspgd_extract_block: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd), mask);
        return (EC_FALSE);
    }

    while(CXFSPGB_MODEL_NUM > page_model_t
       && (EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model_t))
       || CXFSPGRB_ERR_POS == cxfspgrb_tree_search_data(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model_t), block_no))
       )
    {
        page_model_t --;
    }

    if(CXFSPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:__cxfspgd_extract_block: no free block %u\n", block_no);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;

    return (EC_TRUE);
}

EC_BOOL cxfspgd_reserve_space(CXFSPGD *cxfspgd, const uint32_t size, const uint16_t block_no, const uint16_t page_no)
{
    CXFSPGB    *cxfspgb;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t e;
    uint16_t t;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CXFSPGD_ASSERT(0 < size);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_reserve_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);
    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDNULL, "[DEBUG] cxfspgd_reserve_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CXFSPGD_ASSERT(CXFSPGB_064MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CXFSPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDNULL, "[DEBUG] cxfspgd_reserve_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CXFSPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDNULL, "[DEBUG] cxfspgd_reserve_space: page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   page_num_need, page_model, (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model)));

    if(1)
    {
        uint16_t page_model_t;

        page_model_t = page_model;

        if(EC_FALSE == __cxfspgd_extract_block(cxfspgd, &page_model_t, block_no))
        {
            dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_reserve_space: extract block %u from page model %u failed\n", block_no, page_model_t);
            return (EC_FALSE);
        }

        cxfspgb = CXFSPGD_BLOCK_NODE(cxfspgd, block_no);
        pgb_assign_bitmap_old = CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb);

        if(EC_FALSE == cxfspgb_reserve_page(cxfspgb, size, page_no))
        {
            dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_reserve_space: reserve size %u, page %u from block %u failed\n", size, page_no, block_no);
            return (EC_FALSE);
        }

        page_model = page_model_t; /*re-init page_model*/
    }

    pgb_assign_bitmap_new = CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb);

    //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_reserve_space: block_no_t %u: pgb bitmap %x => %x\n", block_no_t, pgb_assign_bitmap_old, pgb_assign_bitmap_new);

    /*pgb_assign_bitmap changes may make pgd_assign_bitmap changes*/
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_reserve_space: before delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)),
        //                    c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)));

        cxfspgd_del_block(cxfspgd, block_no, page_model);

        //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_reserve_space: after  delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)),
        //                    c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)));

        if(EC_FALSE == cxfspgb_is_full(cxfspgb))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CXFSPGB_MODEL_NUM > page_model_t
               && 0 == (pgb_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CXFSPGD_ASSERT(CXFSPGB_MODEL_NUM > page_model_t);
            //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_reserve_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            cxfspgd_add_block(cxfspgd, block_no, page_model_t);
            //dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_reserve_space: block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
            //                    block_no_t,
            //                    c_uint16_t_to_bin_str(CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)),
            //                    c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)));
        }
        else
        {
            /*do nothing*/
        }
    }

    CXFSPGD_PAGE_USED_NUM(cxfspgd)         += page_num_need;
    CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd) += size;

    CXFSPGD_ASSERT(EC_TRUE == cxfspgd_check(cxfspgd));

    dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_reserve_space: pgd_page_used_num %u due to increment %u\n",
                        CXFSPGD_PAGE_USED_NUM(cxfspgd), page_num_need);
    dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_reserve_space: pgd_actual_used_size %"PRId64" due to increment %u\n",
                        CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd), size);

    return (EC_TRUE);
}

EC_BOOL cxfspgd_release_space(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    return cxfspgd_free_space(cxfspgd, block_no, page_no, size);
}

EC_BOOL cxfspgd_is_full(const CXFSPGD *cxfspgd)
{
    if(CXFSPGD_PAGE_USED_NUM(cxfspgd) == CXFSPGD_PAGE_MAX_NUM(cxfspgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cxfspgd_is_empty(const CXFSPGD *cxfspgd)
{
    if(0 == CXFSPGD_PAGE_USED_NUM(cxfspgd) && 0 < CXFSPGD_PAGE_MAX_NUM(cxfspgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*compute cxfspgd current page model support up to*/
uint16_t cxfspgd_page_model(const CXFSPGD *cxfspgd)
{
    uint16_t page_model;
    uint16_t pgd_assign_bitmap;
    uint16_t e;

    pgd_assign_bitmap = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);
    for(page_model = 0, e = 1; CXFSPGB_MODEL_NUM > page_model && 0 == (pgd_assign_bitmap & e); e <<= 1, page_model ++)
    {
        /*do nothing*/
    }

    dbg_log(SEC_0202_CXFSPGD, 9)(LOGSTDOUT, "[DEBUG] cxfspgd_page_model: cxfspgd %p: assign bitmap %s ==> page_model %u\n",
                       cxfspgd, c_uint16_t_to_bin_str(pgd_assign_bitmap), page_model);

    return (page_model);
}

/*disk meta data size*/
UINT32 cxfspgd_size(const uint16_t block_num)
{
    return (((UINT32)CXFSPGD_HDR_SIZE) + ((UINT32)block_num) * ((UINT32)CXFSPGB_SIZE));
}

EC_BOOL cxfspgd_check(const CXFSPGD *cxfspgd)
{
    uint16_t  pgd_assign_bitmap;
    uint16_t  pgb_assign_bitmap;/*all pgb's bitmap*/
    uint16_t  block_no;
    uint16_t  block_num;

    uint64_t  pgd_actual_used_size;
    uint64_t  pgb_actual_used_size;/*all pgb's used size*/

    uint32_t  pgd_page_max_num;
    uint32_t  pgb_page_max_num;/*all pgb's page max num*/

    uint32_t  pgd_page_used_num;
    uint32_t  pgb_page_used_num;/*all pgb's page used num*/

    pgd_assign_bitmap    = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);
    pgd_actual_used_size = CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd);
    pgd_page_max_num     = CXFSPGD_PAGE_MAX_NUM(cxfspgd);
    pgd_page_used_num    = CXFSPGD_PAGE_USED_NUM(cxfspgd);
    block_num = CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd);

    pgb_assign_bitmap    = 0;
    pgb_actual_used_size = 0;
    pgb_page_max_num     = 0;
    pgb_page_used_num    = 0;

    for(block_no = 0; block_no < block_num; block_no ++)
    {
        pgb_assign_bitmap    |= CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(CXFSPGD_BLOCK_NODE(cxfspgd, block_no));
        pgb_actual_used_size += CXFSPGB_PAGE_ACTUAL_USED_SIZE(CXFSPGD_BLOCK_NODE(cxfspgd, block_no));
        pgb_page_max_num     += CXFSPGB_PAGE_MAX_NUM(CXFSPGD_BLOCK_NODE(cxfspgd, block_no));
        pgb_page_used_num    += CXFSPGB_PAGE_USED_NUM(CXFSPGD_BLOCK_NODE(cxfspgd, block_no));
    }

    if(pgd_assign_bitmap != pgb_assign_bitmap)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_check: inconsistent bitmap: pgd_assign_bitmap = %s, pgb_assign_bitmap = %s\n",
                           c_uint16_t_to_bin_str(pgd_assign_bitmap), c_uint16_t_to_bin_str(pgb_assign_bitmap));
        return (EC_FALSE);
    }

    if(pgd_actual_used_size != pgb_actual_used_size)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_check: inconsistent actual used size: pgd_actual_used_size = %"PRId64", pgb_actual_used_size = %"PRId64"\n",
                            pgd_actual_used_size, pgb_actual_used_size);
        return (EC_FALSE);
    }

    if(pgd_page_max_num != pgb_page_max_num)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_check: inconsistent page max num: pgd_page_max_num = %u, pgb_page_max_num = %u\n",
                            pgd_page_max_num, pgb_page_max_num);
        return (EC_FALSE);
    }

    if(pgd_page_used_num != pgb_page_used_num)
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_check: inconsistent page used num: pgd_page_used_num = %u, pgb_page_used_num = %u\n",
                            pgd_page_used_num, pgb_page_used_num);
        return (EC_FALSE);
    }

    /*check block table*/
    for(block_no = 0; block_no < CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd); block_no ++)
    {
        if(EC_FALSE == cxfspgb_check(CXFSPGD_BLOCK_NODE(cxfspgd, block_no)))
        {
            dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_check: check CXFSPGD_BLOCK_NODE of block_no %u failed\n", block_no);
            return (EC_FALSE);
        }
    }
    dbg_log(SEC_0202_CXFSPGD, 5)(LOGSTDOUT, "cxfspgd_check: cxfspgd %p check passed\n", cxfspgd);
    return (EC_TRUE);
}

void cxfspgd_print(LOG *log, const CXFSPGD *cxfspgd)
{
    uint16_t  page_model;
    char     *page_desc;
    REAL      used_size;
    REAL      occupied_size;
    REAL      ratio_size;
    REAL      ratio_page;

    CXFSPGD_ASSERT(NULL_PTR != cxfspgd);

    //cxfspgrb_pool_print(log, CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd));

    if(0)
    {
        for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
        {
            sys_log(log, "cxfspgd_print: page_model %u, block root_pos %u\n",
                         page_model,
                         CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model));
            cxfspgrb_tree_print(log, CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd), CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model));
            sys_log(log, "----------------------------------------------------------\n");
        }
    }
    used_size     = (0.0 + CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd));
    occupied_size = (0.0 + (((uint64_t)CXFSPGD_PAGE_USED_NUM(cxfspgd)) << CXFSPGB_PAGE_BIT_SIZE));
    ratio_size    = (EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size));

    ratio_page    = ((0.0 + CXFSPGD_PAGE_USED_NUM(cxfspgd)) / (0.0 + CXFSPGD_PAGE_MAX_NUM(cxfspgd)));

    page_desc     = CXFSPCB_PAGE_DESC;

/*
    sys_log(log, "cxfspgd_print: cxfspgd %p, ratio %.2f\n",
                 cxfspgd,
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );
*/
    sys_log(log, "cxfspgd_print: cxfspgd %p, block num %u, %s, page max num %u, page used num %u, page ratio %.2f, actual used size %"PRId64", size ratio %.2f\n",
                 cxfspgd,
                 CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd),
                 page_desc,
                 CXFSPGD_PAGE_MAX_NUM(cxfspgd),
                 CXFSPGD_PAGE_USED_NUM(cxfspgd),
                 ratio_page,
                 CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd),
                 ratio_size
                 );

    sys_log(log, "cxfspgd_print: cxfspgd %p, assign bitmap %s \n",
                 cxfspgd,
                 c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd))
                 );

    if(0)
    {
        for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
        {
            if(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd) & (1 << page_model))
            {
                sys_log(log, "cxfspgd_print: cxfspgd %p, model %u has page to assign\n", cxfspgd, page_model);
            }
            else
            {
                sys_log(log, "cxfspgd_print: cxfspgd %p, model %u no  page to assign\n", cxfspgd, page_model);
            }
        }
    }

    if(0)
    {
        uint16_t  block_no;
        for(block_no = 0; block_no < CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd); block_no ++)
        {
            sys_log(log, "cxfspgd_print: block %u is\n", block_no);
            cxfspgb_print(log, CXFSPGD_BLOCK_NODE(cxfspgd, block_no));
        }
    }

    return;
}

/* ---- debug ---- */
EC_BOOL cxfspgd_debug_cmp(const CXFSPGD *cxfspgd_1st, const CXFSPGD *cxfspgd_2nd)
{
    uint16_t page_model;
    uint16_t block_no;

    /*cxfspgrb pool*/
    if(EC_FALSE == cxfspgrb_debug_cmp(CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd_1st), CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd_2nd)))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_debug_cmp: inconsistent cxfspgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd_1st, page_model);
        root_pos_2nd = CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*assign bitmap*/
    if(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd_1st) != CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd_1st))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_debug_cmp: inconsistent CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd_1st), CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd_2nd));
        return (EC_FALSE);
    }

    /*block max num*/
    if(CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd_1st) != CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd_1st))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_debug_cmp: inconsistent CXFSPGD_PAGE_BLOCK_MAX_NUM: %u != %u\n",
                            CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd_1st), CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CXFSPGD_PAGE_MAX_NUM(cxfspgd_1st) != CXFSPGD_PAGE_MAX_NUM(cxfspgd_1st))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_debug_cmp: inconsistent CXFSPGD_PAGE_MAX_NUM: %u != %u\n",
                            CXFSPGD_PAGE_MAX_NUM(cxfspgd_1st), CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CXFSPGD_PAGE_USED_NUM(cxfspgd_1st) != CXFSPGD_PAGE_USED_NUM(cxfspgd_1st))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_debug_cmp: inconsistent CXFSPGD_PAGE_USED_NUM: %u != %u\n",
                            CXFSPGD_PAGE_USED_NUM(cxfspgd_1st), CXFSPGD_PAGE_USED_NUM(cxfspgd_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd_1st) != CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd_1st))
    {
        dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDERR, "error:cxfspgd_debug_cmp: inconsistent CXFSPGD_PAGE_ACTUAL_USED_SIZE: %"PRId64" != %"PRId64"\n",
                            CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd_1st), CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd_2nd));
        return (EC_FALSE);
    }

    /*block cxfspgb*/
    for(block_no = 0; block_no < CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd_1st); block_no ++)
    {
        if(EC_FALSE == cxfspgb_debug_cmp(CXFSPGD_BLOCK_NODE(cxfspgd_1st, block_no), CXFSPGD_BLOCK_NODE(cxfspgd_2nd, block_no)))
        {
            dbg_log(SEC_0202_CXFSPGD, 0)(LOGSTDOUT, "error:cxfspgd_debug_cmp: inconsistent CXFSPGD_BLOCK_NODE at block_no %u\n", block_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

