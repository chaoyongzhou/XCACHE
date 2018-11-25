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

#include "cmisc.h"
#include "real.h"

#include "cmcpgrb.h"
#include "cmcpgb.h"
#include "cmcpgd.h"

#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMCPGD_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMCPGD_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

static CMCPGD_CFG g_cmcpgd_cfg_tbl[] = {
    {(const char *)"32M"  , (const char *)"CMCPGD_032MB_BLOCK_NUM", CMCPGD_032MB_BLOCK_NUM, 0, 0 },
    {(const char *)"64M"  , (const char *)"CMCPGD_064MB_BLOCK_NUM", CMCPGD_064MB_BLOCK_NUM, 0, 0 },
    {(const char *)"128M" , (const char *)"CMCPGD_128MB_BLOCK_NUM", CMCPGD_128MB_BLOCK_NUM, 0, 0 },
    {(const char *)"256M" , (const char *)"CMCPGD_256MB_BLOCK_NUM", CMCPGD_256MB_BLOCK_NUM, 0, 0 },
    {(const char *)"512M" , (const char *)"CMCPGD_512MB_BLOCK_NUM", CMCPGD_512MB_BLOCK_NUM, 0, 0 },
    {(const char *)"1G"   , (const char *)"CMCPGD_001GB_BLOCK_NUM", CMCPGD_001GB_BLOCK_NUM, 0, 0 },
    {(const char *)"2G"   , (const char *)"CMCPGD_002GB_BLOCK_NUM", CMCPGD_002GB_BLOCK_NUM, 0, 0 },
    {(const char *)"4G"   , (const char *)"CMCPGD_004GB_BLOCK_NUM", CMCPGD_004GB_BLOCK_NUM, 0, 0 },
    {(const char *)"8G"   , (const char *)"CMCPGD_008GB_BLOCK_NUM", CMCPGD_008GB_BLOCK_NUM, 0, 0 },
    {(const char *)"16G"  , (const char *)"CMCPGD_016GB_BLOCK_NUM", CMCPGD_016GB_BLOCK_NUM, 0, 0 },
    {(const char *)"32G"  , (const char *)"CMCPGD_032GB_BLOCK_NUM", CMCPGD_032GB_BLOCK_NUM, 0, 0 },
    {(const char *)"64G"  , (const char *)"CMCPGD_064GB_BLOCK_NUM", CMCPGD_064GB_BLOCK_NUM, 0, 0 },
    {(const char *)"128G" , (const char *)"CMCPGD_128GB_BLOCK_NUM", CMCPGD_128GB_BLOCK_NUM, 0, 0 },
    {(const char *)"256G" , (const char *)"CMCPGD_256GB_BLOCK_NUM", CMCPGD_256GB_BLOCK_NUM, 0, 0 },
    {(const char *)"512G" , (const char *)"CMCPGD_512GB_BLOCK_NUM", CMCPGD_512GB_BLOCK_NUM, 0, 0 },
};

static uint8_t g_cmcpgd_cfg_tbl_len = (uint8_t)(sizeof(g_cmcpgd_cfg_tbl)/sizeof(g_cmcpgd_cfg_tbl[0]));

const char *cmcpgd_model_str(const uint16_t pgd_block_num)
{
    uint8_t cmcpgd_model;

    for(cmcpgd_model = 0; cmcpgd_model < g_cmcpgd_cfg_tbl_len; cmcpgd_model ++)
    {
        CMCPGD_CFG *cmcpgd_cfg;

        cmcpgd_cfg = &(g_cmcpgd_cfg_tbl[ cmcpgd_model ]);
        if(pgd_block_num == CMCPGD_CFG_BLOCK_NUM(cmcpgd_cfg))
        {
            return CMCPGD_CFG_MODEL_STR(cmcpgd_cfg);
        }
    }

    return (const char *)"unkown";
}

uint16_t cmcpgd_model_get(const char *model_str)
{
    uint8_t cmcpgd_model;

    for(cmcpgd_model = 0; cmcpgd_model < g_cmcpgd_cfg_tbl_len; cmcpgd_model ++)
    {
        CMCPGD_CFG *cmcpgd_cfg;
        cmcpgd_cfg = &(g_cmcpgd_cfg_tbl[ cmcpgd_model ]);

        if(0 == strcasecmp(CMCPGD_CFG_MODEL_STR(cmcpgd_cfg), model_str))
        {
            return CMCPGD_CFG_BLOCK_NUM(cmcpgd_cfg);
        }
    }
    return (CMCPGD_ERROR_BLOCK_NUM);
}

STATIC_CAST static uint16_t __cmcpgd_page_model_first_block(const CMCPGD *cmcpgd, const uint16_t page_model)
{
    uint16_t node_pos;
    const CMCPGRB_NODE *node;

    node_pos = cmcpgrb_tree_first_node(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd), CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model));
    if(CMCPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:__cmcpgd_page_model_first_block: no free page in page model %u\n", page_model);
        return (CMCPGRB_ERR_POS);
    }

    node = CMCPGRB_POOL_NODE(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd), node_pos);
    return (CMCPGRB_NODE_DATA(node));
}

STATIC_CAST static uint16_t __cmcpgd_page_model_get(const CMCPGD *cmcpgd, const uint16_t assign_bitmap)
{
    uint16_t page_model;
    uint16_t e;

    for(page_model = 0, e = 1; CMCPGB_MODEL_NUM > page_model && 0 == (assign_bitmap & e); page_model ++, e <<= 1)
    {
      /*do nothing*/
    }
    return (page_model);
}

STATIC_CAST static CMCPGB *__cmcpgd_block(CMCPGD *cmcpgd, const uint16_t  block_no)
{
    return (CMCPGB *)(((void *)CMCPGD_HEADER(cmcpgd)) + CMCPGD_HDR_SIZE + block_no * CMCPGB_SIZE);
}

CMCPGD_HDR *cmcpgd_hdr_new(CMCPGD *cmcpgd, const uint16_t block_num)
{
    CMCPGD_HDR *cmcpgd_hdr;
    uint16_t    page_model;

    cmcpgd_hdr = safe_malloc(CMCPGD_SIZE(cmcpgd), LOC_CMCPGD_0001);
    if(NULL_PTR == cmcpgd_hdr)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_hdr_new: malloc %u bytes failed\n",
                           CMCPGD_SIZE(cmcpgd));
        return (NULL_PTR);
    }

    if(EC_FALSE == cmcpgrb_pool_init(CMCPGD_HDR_CMCPGRB_POOL(cmcpgd_hdr), block_num))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_hdr_new: init cmcpgrb pool failed where block_num = %u\n", block_num);
        safe_free(cmcpgd_hdr, LOC_CMCPGD_0002);
        return (NULL_PTR);
    }

    for(page_model = 0; CMCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CMCPGD_HDR_BLOCK_CMCPGRB_ROOT_POS(cmcpgd_hdr, page_model) = CMCPGRB_ERR_POS;
    }

    CMCPGD_HDR_ASSIGN_BITMAP(cmcpgd_hdr) = 0;

    CMCPGD_HDR_PAGE_BLOCK_MAX_NUM(cmcpgd_hdr) = block_num;

    /*statistics*/
    CMCPGD_HDR_PAGE_MAX_NUM(cmcpgd_hdr)          = block_num * CMCPGD_BLOCK_PAGE_NUM;
    CMCPGD_HDR_PAGE_USED_NUM(cmcpgd_hdr)         = 0;
    CMCPGD_HDR_PAGE_ACTUAL_USED_SIZE(cmcpgd_hdr) = 0;

    return (cmcpgd_hdr);
}

EC_BOOL cmcpgd_hdr_free(CMCPGD *cmcpgd)
{
    if(NULL_PTR != CMCPGD_HEADER(cmcpgd))
    {
        safe_free(CMCPGD_HEADER(cmcpgd), LOC_CMCPGD_0003);
        CMCPGD_HEADER(cmcpgd) = NULL_PTR;
    }

    /*cpgv_hdr cannot be accessed again*/
    return (EC_TRUE);
}

CMCPGD *cmcpgd_new(const uint16_t block_num)
{
    CMCPGD      *cmcpgd;
    uint16_t     block_no;

    if(CMCPGD_MAX_BLOCK_NUM < block_num)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_new: block_num %u overflow\n", block_num);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CMCPGD, &cmcpgd, LOC_CMCPGD_0004);
    if(NULL_PTR == cmcpgd)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_new:malloc cmcpgd failed\n");
        return (NULL_PTR);
    }

    cmcpgd_init(cmcpgd);

    dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new: CMCPGD_HDR_SIZE %ld, block_num %u, CMCPGB_SIZE %ld, sizeof(off_t) = %ld\n",
                        CMCPGD_HDR_SIZE, block_num, CMCPGB_SIZE, sizeof(off_t));

    CMCPGD_SIZE(cmcpgd) = CMCPGD_HDR_SIZE + block_num * CMCPGB_SIZE;

    CMCPGD_HEADER(cmcpgd) = cmcpgd_hdr_new(cmcpgd, block_num);
    if(NULL_PTR == CMCPGD_HEADER(cmcpgd))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_new: new cmcpgd header failed\n");
        cmcpgd_free(cmcpgd);
        return (NULL_PTR);
    }

    /*init blocks*/
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no) = __cmcpgd_block(cmcpgd, block_no);
        cmcpgb_init(CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no), CMCPGD_BLOCK_PAGE_MODEL);
        cmcpgd_add_block(cmcpgd, block_no, CMCPGD_BLOCK_PAGE_MODEL);

        if(0 == ((block_no + 1) % 1000))
        {
            dbg_log(SEC_0102_CMCPGD, 3)(LOGSTDOUT, "info:cmcpgd_new: init block %u - %u done\n", block_no - 999, block_no);
        }
    }
    dbg_log(SEC_0102_CMCPGD, 3)(LOGSTDOUT, "info:cmcpgd_new: init %u blocks done\n", block_num);

    return (cmcpgd);
}

EC_BOOL cmcpgd_free(CMCPGD *cmcpgd)
{
    if(NULL_PTR != cmcpgd)
    {
        UINT32 block_num;
        UINT32 block_no;

        /*clean blocks*/
        block_num = CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd);
        for(block_no = 0; block_no < block_num; block_no ++)
        {
            CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no) = NULL_PTR;
        }

        cmcpgd_hdr_free(cmcpgd);

        free_static_mem(MM_CMCPGD, cmcpgd, LOC_CMCPGD_0005);
    }

    return (EC_TRUE);
}

/* one page cache disk = 32GB */
EC_BOOL cmcpgd_init(CMCPGD *cmcpgd)
{
    uint16_t block_no;

    CMCPGD_SIZE(cmcpgd)  = 0;
    CMCPGD_HEADER(cmcpgd)= NULL_PTR;

    for(block_no = 0; block_no < CMCPGD_MAX_BLOCK_NUM; block_no ++)
    {
        CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no) = NULL_PTR;
    }
    return (EC_TRUE);
}

/*note: cmcpgd_clean is for not applying mmap*/
void cmcpgd_clean(CMCPGD *cmcpgd)
{
    uint16_t page_model;
    uint16_t block_no;

    if(NULL_PTR == CMCPGD_HEADER(cmcpgd))
    {
        return;
    }

    cmcpgrb_pool_clean(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd));

    for(page_model = 0; CMCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model) = CMCPGRB_ERR_POS;
    }

    for(block_no = 0; block_no < CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd); block_no ++)
    {
        if(NULL_PTR != CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no))
        {
            safe_free(CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no), LOC_CMCPGD_0006);
            CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no) = NULL_PTR;
        }
    }
    CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd)           = 0;

    CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)     = 0;
    CMCPGD_PAGE_MAX_NUM(cmcpgd)                 = 0;
    CMCPGD_PAGE_USED_NUM(cmcpgd)                = 0;
    CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd)        = 0;

    safe_free(CMCPGD_HEADER(cmcpgd), LOC_CMCPGD_0007);
    CMCPGD_HEADER(cmcpgd) = NULL_PTR;

    return;
}

/*add one free block into pool*/
EC_BOOL cmcpgd_add_block(CMCPGD *cmcpgd, const uint16_t block_no, const uint16_t page_model)
{
    if(CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd) <= block_no)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_add_block: block_no %u overflow where block max num is %u\n", block_no, CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd));
        return (EC_FALSE);
    }

    /*insert block_no to rbtree*/
    if(CMCPGRB_ERR_POS == cmcpgrb_tree_insert_data(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd), &(CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model)), block_no))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_add_block: add block_no %u to rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd) |= (uint16_t)(~((1 << page_model) - 1)) & CMCPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free block from pool*/
EC_BOOL cmcpgd_del_block(CMCPGD *cmcpgd, const uint16_t block_no, const uint16_t page_model)
{
    /*del block_no from rbtree*/
    if(CMCPGRB_ERR_POS == cmcpgrb_tree_delete_data(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd), &(CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model)), block_no))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_del_block: del block_no %u from rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CMCPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cmcpgrb_tree_is_empty(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd), CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model_t))/*this page-model is empty*/
        )
        {
            CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cmcpgd_assign_block(CMCPGD *cmcpgd, uint16_t *page_model, uint16_t *block_no)
{
    uint16_t block_no_t;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd) & mask))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:__cmcpgd_assign_block: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd), mask);
        return (EC_FALSE);
    }

    while(CMCPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cmcpgrb_tree_is_empty(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd), CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CMCPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:__cmcpgd_assign_block: no free block available from page model %u\n", *page_model);
        return (EC_FALSE);
    }

    block_no_t = __cmcpgd_page_model_first_block(cmcpgd, page_model_t);
    if(CMCPGRB_ERR_POS == block_no_t)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:__cmcpgd_assign_block: no free block in page model %u\n", page_model_t);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;
    (*block_no)   = block_no_t;

    return (EC_TRUE);
}

EC_BOOL cmcpgd_new_space(CMCPGD *cmcpgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no)
{
    CMCPGB    *cmcpgb;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t e;
    uint16_t t;
    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t block_no_t;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CMCPGD_ASSERT(0 < size);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CMCPGB_PAGE_BYTE_SIZE - 1) >> CMCPGB_PAGE_BIT_SIZE);
    //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDNULL, "[DEBUG] cmcpgd_new_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CMCPGD_ASSERT(CMCPGB_032MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CMCPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDNULL, "[DEBUG] cmcpgd_new_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CMCPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDNULL, "[DEBUG] cmcpgd_new_space: page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   page_num_need, page_model, (uint16_t)(1 << (CMCPGB_MODEL_NUM - 1 - page_model)));

    for(;;)/*Oops! fix inconsistency between cmcpgd and cmcpgb*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;

        if(EC_FALSE == __cmcpgd_assign_block(cmcpgd, &page_model_t, &block_no_t))
        {
            dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_new_space: assign one block from page model %u failed\n", page_model_t);
            return (EC_FALSE);
        }

        cmcpgb = CMCPGD_BLOCK_NODE(cmcpgd, block_no_t);
        pgb_assign_bitmap_old = CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb);

        if(EC_TRUE == cmcpgb_new_space(cmcpgb, size, &page_no_t))
        {
            page_model = page_model_t; /*re-init page_model*/
            break;
        }

        /*find inconsistent, fix it!*/
        cmcpgd_del_block(cmcpgd, block_no_t, page_model_t);

        while(CMCPGB_MODEL_NUM > page_model_t
           && 0 == (pgb_assign_bitmap_old & (uint16_t)(1 << page_model_t))
           )
        {
             page_model_t ++;
        }
        CMCPGD_ASSERT(CMCPGB_MODEL_NUM > page_model_t);
        cmcpgd_add_block(cmcpgd, block_no_t, page_model_t);

        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "warn:cmcpgd_new_space: block %u relocation to page model %u\n", block_no_t, page_model_t);
    }

    pgb_assign_bitmap_new = CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb);

    //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new_space: block_no_t %u: pgb bitmap %x => %x\n", block_no_t, pgb_assign_bitmap_old, pgb_assign_bitmap_new);

    /*pgb_assign_bitmap changes may make pgd_assign_bitmap changes*/
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new_space: before delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb)),
        //                    c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)));

        cmcpgd_del_block(cmcpgd, block_no_t, page_model);

        //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new_space: after  delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb)),
        //                    c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)));

        if(EC_FALSE == cmcpgb_is_full(cmcpgb))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CMCPGB_MODEL_NUM > page_model_t
               && 0 == (pgb_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }
            CMCPGD_ASSERT(CMCPGB_MODEL_NUM > page_model_t);
            //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            cmcpgd_add_block(cmcpgd, block_no_t, page_model_t);
            //dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new_space: block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
            //                    block_no_t,
            //                    c_uint16_t_to_bin_str(CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb)),
            //                    c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CMCPGD_PAGE_USED_NUM(cmcpgd)         += page_num_need;
    CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd) += size;

    CMCPGD_ASSERT(EC_TRUE == cmcpgd_check(cmcpgd));

    dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new_space: pgd_page_used_num %u due to increment %u\n",
                        CMCPGD_PAGE_USED_NUM(cmcpgd), page_num_need);
    dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_new_space: pgd_actual_used_size %"PRId64" due to increment %u\n",
                        CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd), size);

    return (EC_TRUE);
}

EC_BOOL cmcpgd_free_space(CMCPGD *cmcpgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    CMCPGB    *cmcpgb;

    uint16_t page_num_used;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CMCPGD_ASSERT(0 < size);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    cmcpgb = CMCPGD_BLOCK_NODE(cmcpgd, block_no);
    pgb_assign_bitmap_old = CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb);

    if(EC_FALSE == cmcpgb_free_space(cmcpgb, page_no, size))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_free_space: block_no %u free space of page_no %u, size %u failed\n",
                           block_no, page_no, size);
        return (EC_FALSE);
    }

    pgb_assign_bitmap_new = CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb);
#if 0
    dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_free_space: cmcpgd %p, block %u, asssign bitmap %s -> %s\n",
                       cmcpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_old),
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_new));
#endif
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        uint16_t page_model_old;
        uint16_t page_model_new;

        page_model_old = __cmcpgd_page_model_get(cmcpgd, pgb_assign_bitmap_old);
        page_model_new = __cmcpgd_page_model_get(cmcpgd, pgb_assign_bitmap_new);
#if 0
        dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_free_space: cmcpgd %p, block %u, old asssign bitmap %s = page model %u\n",
                       cmcpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_old), page_model_old);

        dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_free_space: cmcpgd %p, block %u, new asssign bitmap %s = page model %u\n",
                       cmcpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_new), page_model_new);
#endif
        if(CMCPGB_MODEL_NUM > page_model_old)
        {
            cmcpgd_del_block(cmcpgd, block_no, page_model_old);
        }

        if(EC_FALSE == cmcpgd_add_block(cmcpgd, block_no, page_model_new))
        {
            dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_free_space: add block %d, page_model_new %u failed, fix it!\n",
                                block_no, page_model_new);
            abort();
        }
    }

    page_num_used = (uint16_t)((size + CMCPGB_PAGE_BYTE_SIZE - 1) >> CMCPGB_PAGE_BIT_SIZE);

    CMCPGD_PAGE_USED_NUM(cmcpgd)         -= page_num_used;
    CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd) -= size;

    dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_free_space: pgd_page_used_num %u due to decrement %u\n",
                        CMCPGD_PAGE_USED_NUM(cmcpgd), page_num_used);
    dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_free_space: pgd_actual_used_size %"PRId64" due to decrement %u\n",
                        CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd), size);

    return (EC_TRUE);
}

EC_BOOL cmcpgd_is_full(const CMCPGD *cmcpgd)
{
    if(CMCPGD_PAGE_USED_NUM(cmcpgd) == CMCPGD_PAGE_MAX_NUM(cmcpgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcpgd_is_empty(const CMCPGD *cmcpgd)
{
    if(0 == CMCPGD_PAGE_USED_NUM(cmcpgd) && 0 < CMCPGD_PAGE_MAX_NUM(cmcpgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*compute cmcpgd current page model support up to*/
uint16_t cmcpgd_page_model(const CMCPGD *cmcpgd)
{
    uint16_t page_model;
    uint16_t pgd_assign_bitmap;
    uint16_t e;

    pgd_assign_bitmap = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);
    for(page_model = 0, e = 1; CMCPGB_MODEL_NUM > page_model && 0 == (pgd_assign_bitmap & e); e <<= 1, page_model ++)
    {
        /*do nothing*/
    }

    dbg_log(SEC_0102_CMCPGD, 9)(LOGSTDOUT, "[DEBUG] cmcpgd_page_model: cmcpgd %p: assign bitmap %s ==> page_model %u\n",
                       cmcpgd, c_uint16_t_to_bin_str(pgd_assign_bitmap), page_model);

    return (page_model);
}


EC_BOOL cmcpgd_check(const CMCPGD *cmcpgd)
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

    pgd_assign_bitmap    = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);
    pgd_actual_used_size = CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd);
    pgd_page_max_num     = CMCPGD_PAGE_MAX_NUM(cmcpgd);
    pgd_page_used_num    = CMCPGD_PAGE_USED_NUM(cmcpgd);
    block_num = CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd);

    pgb_assign_bitmap    = 0;
    pgb_actual_used_size = 0;
    pgb_page_max_num     = 0;
    pgb_page_used_num    = 0;

    for(block_no = 0; block_no < block_num; block_no ++)
    {
        pgb_assign_bitmap    |= CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(CMCPGD_BLOCK_NODE(cmcpgd, block_no));
        pgb_actual_used_size += CMCPGB_PAGE_ACTUAL_USED_SIZE(CMCPGD_BLOCK_NODE(cmcpgd, block_no));
        pgb_page_max_num     += CMCPGB_PAGE_MAX_NUM(CMCPGD_BLOCK_NODE(cmcpgd, block_no));
        pgb_page_used_num    += CMCPGB_PAGE_USED_NUM(CMCPGD_BLOCK_NODE(cmcpgd, block_no));
    }

    if(pgd_assign_bitmap != pgb_assign_bitmap)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_check: inconsistent bitmap: pgd_assign_bitmap = %s, pgb_assign_bitmap = %s\n",
                           c_uint16_t_to_bin_str(pgd_assign_bitmap), c_uint16_t_to_bin_str(pgb_assign_bitmap));
        return (EC_FALSE);
    }

    if(pgd_actual_used_size != pgb_actual_used_size)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_check: inconsistent actual used size: pgd_actual_used_size = %"PRId64", pgb_actual_used_size = %"PRId64"\n",
                            pgd_actual_used_size, pgb_actual_used_size);
        return (EC_FALSE);
    }

    if(pgd_page_max_num != pgb_page_max_num)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_check: inconsistent page max num: pgd_page_max_num = %u, pgb_page_max_num = %u\n",
                            pgd_page_max_num, pgb_page_max_num);
        return (EC_FALSE);
    }

    if(pgd_page_used_num != pgb_page_used_num)
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_check: inconsistent page used num: pgd_page_used_num = %u, pgb_page_used_num = %u\n",
                            pgd_page_used_num, pgb_page_used_num);
        return (EC_FALSE);
    }

    /*check block table*/
    for(block_no = 0; block_no < CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd); block_no ++)
    {
        if(EC_FALSE == cmcpgb_check(CMCPGD_BLOCK_NODE(cmcpgd, block_no)))
        {
            dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_check: check CMCPGD_BLOCK_NODE of block_no %u failed\n", block_no);
            return (EC_FALSE);
        }
    }
    dbg_log(SEC_0102_CMCPGD, 5)(LOGSTDOUT, "cmcpgd_check: cmcpgd %p check passed\n", cmcpgd);
    return (EC_TRUE);
}

void cmcpgd_print(LOG *log, const CMCPGD *cmcpgd)
{
    uint16_t  page_model;
    char     *page_desc;
    REAL      used_size;
    REAL      occupied_size;
    REAL      ratio_size;
    REAL      ratio_page;

    CMCPGD_ASSERT(NULL_PTR != cmcpgd);

    //cmcpgrb_pool_print(log, CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd));

    if(0)
    {
        for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
        {
            sys_log(log, "cmcpgd_print: page_model %u, block root_pos %u\n",
                         page_model,
                         CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model));
            cmcpgrb_tree_print(log, CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd), CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model));
            sys_log(log, "----------------------------------------------------------\n");
        }
    }
    used_size     = (0.0 + CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd));
    occupied_size = (0.0 + (((uint64_t)CMCPGD_PAGE_USED_NUM(cmcpgd)) << CMCPGB_PAGE_BIT_SIZE));
    ratio_size    = (EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size));

    ratio_page    = ((0.0 + CMCPGD_PAGE_USED_NUM(cmcpgd)) / (0.0 + CMCPGD_PAGE_MAX_NUM(cmcpgd)));

    page_desc = "UNKNOWN-page";

    if(CMCPGB_PAGE_BIT_SIZE == CMCPGB_PAGE_2K_BIT_SIZE)
    {
        page_desc = "2K-page";
    }

    if(CMCPGB_PAGE_BIT_SIZE == CMCPGB_PAGE_4K_BIT_SIZE)
    {
        page_desc = "4K-page";
    }

    if(CMCPGB_PAGE_BIT_SIZE == CMCPGB_PAGE_8K_BIT_SIZE)
    {
        page_desc = "8K-page";
    }

    if(CMCPGB_PAGE_BIT_SIZE == CMCPGB_PAGE_16M_BIT_SIZE)
    {
        page_desc = "16M-page";
    }

    if(CMCPGB_PAGE_BIT_SIZE == CMCPGB_PAGE_32M_BIT_SIZE)
    {
        page_desc = "32M-page";
    }
/*
    sys_log(log, "cmcpgd_print: cmcpgd %p, ratio %.2f\n",
                 cmcpgd,
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );
*/
    sys_log(log, "cmcpgd_print: cmcpgd %p, block num %u, %s, page max num %u, page used num %u, page ratio %.2f, actual used size %"PRId64", size ratio %.2f\n",
                 cmcpgd,
                 CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd),
                 page_desc,
                 CMCPGD_PAGE_MAX_NUM(cmcpgd),
                 CMCPGD_PAGE_USED_NUM(cmcpgd),
                 ratio_page,
                 CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd),
                 ratio_size
                 );

    sys_log(log, "cmcpgd_print: cmcpgd %p, assign bitmap %s \n",
                 cmcpgd,
                 c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd))
                 );

    if(0)
    {
        for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
        {
            if(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd) & (1 << page_model))
            {
                sys_log(log, "cmcpgd_print: cmcpgd %p, model %u has page to assign\n", cmcpgd, page_model);
            }
            else
            {
                sys_log(log, "cmcpgd_print: cmcpgd %p, model %u no  page to assign\n", cmcpgd, page_model);
            }
        }
    }

    if(0)
    {
        uint16_t  block_no;
        for(block_no = 0; block_no < CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd); block_no ++)
        {
            sys_log(log, "cmcpgd_print: block %u is\n", block_no);
            cmcpgb_print(log, CMCPGD_BLOCK_NODE(cmcpgd, block_no));
        }
    }

    return;
}

/* ---- debug ---- */
EC_BOOL cmcpgd_debug_cmp(const CMCPGD *cmcpgd_1st, const CMCPGD *cmcpgd_2nd)
{
    uint16_t page_model;
    uint16_t block_no;

    /*cmcpgrb pool*/
    if(EC_FALSE == cmcpgrb_debug_cmp(CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd_1st), CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd_2nd)))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent cmcpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd_1st, page_model);
        root_pos_2nd = CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*assign bitmap*/
    if(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd_1st) != CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd_1st))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent CMCPGD_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd_1st), CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd_2nd));
        return (EC_FALSE);
    }

    /*block max num*/
    if(CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd_1st) != CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd_1st))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent CMCPGD_PAGE_BLOCK_MAX_NUM: %u != %u\n",
                            CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd_1st), CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CMCPGD_PAGE_MAX_NUM(cmcpgd_1st) != CMCPGD_PAGE_MAX_NUM(cmcpgd_1st))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent CMCPGD_PAGE_MAX_NUM: %u != %u\n",
                            CMCPGD_PAGE_MAX_NUM(cmcpgd_1st), CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CMCPGD_PAGE_USED_NUM(cmcpgd_1st) != CMCPGD_PAGE_USED_NUM(cmcpgd_1st))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent CMCPGD_PAGE_USED_NUM: %u != %u\n",
                            CMCPGD_PAGE_USED_NUM(cmcpgd_1st), CMCPGD_PAGE_USED_NUM(cmcpgd_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd_1st) != CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd_1st))
    {
        dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent CMCPGD_PAGE_ACTUAL_USED_SIZE: %"PRId64" != %"PRId64"\n",
                            CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd_1st), CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd_2nd));
        return (EC_FALSE);
    }

    /*block cmcpgb*/
    for(block_no = 0; block_no < CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd_1st); block_no ++)
    {
        if(EC_FALSE == cmcpgb_debug_cmp(CMCPGD_BLOCK_NODE(cmcpgd_1st, block_no), CMCPGD_BLOCK_NODE(cmcpgd_2nd, block_no)))
        {
            dbg_log(SEC_0102_CMCPGD, 0)(LOGSTDOUT, "error:cmcpgd_debug_cmp: inconsistent CMCPGD_BLOCK_NODE at block_no %u\n", block_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

