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

#include "cdcpgrb.h"
#include "cdcpgb.h"
#include "cdcpgd.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCPGD_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCPGD_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

static CDCPGD_CFG g_cdcpgd_cfg_tbl[] = {
    {(const char *)"32M"  , (const char *)"CDCPGD_032MB_BLOCK_NUM", CDCPGD_032MB_BLOCK_NUM, 0, 0 },
    {(const char *)"64M"  , (const char *)"CDCPGD_064MB_BLOCK_NUM", CDCPGD_064MB_BLOCK_NUM, 0, 0 },
    {(const char *)"128M" , (const char *)"CDCPGD_128MB_BLOCK_NUM", CDCPGD_128MB_BLOCK_NUM, 0, 0 },
    {(const char *)"256M" , (const char *)"CDCPGD_256MB_BLOCK_NUM", CDCPGD_256MB_BLOCK_NUM, 0, 0 },
    {(const char *)"512M" , (const char *)"CDCPGD_512MB_BLOCK_NUM", CDCPGD_512MB_BLOCK_NUM, 0, 0 },
    {(const char *)"1G"   , (const char *)"CDCPGD_001GB_BLOCK_NUM", CDCPGD_001GB_BLOCK_NUM, 0, 0 },
    {(const char *)"2G"   , (const char *)"CDCPGD_002GB_BLOCK_NUM", CDCPGD_002GB_BLOCK_NUM, 0, 0 },
    {(const char *)"4G"   , (const char *)"CDCPGD_004GB_BLOCK_NUM", CDCPGD_004GB_BLOCK_NUM, 0, 0 },
    {(const char *)"8G"   , (const char *)"CDCPGD_008GB_BLOCK_NUM", CDCPGD_008GB_BLOCK_NUM, 0, 0 },
    {(const char *)"16G"  , (const char *)"CDCPGD_016GB_BLOCK_NUM", CDCPGD_016GB_BLOCK_NUM, 0, 0 },
    {(const char *)"32G"  , (const char *)"CDCPGD_032GB_BLOCK_NUM", CDCPGD_032GB_BLOCK_NUM, 0, 0 },
    {(const char *)"64G"  , (const char *)"CDCPGD_064GB_BLOCK_NUM", CDCPGD_064GB_BLOCK_NUM, 0, 0 },
    {(const char *)"128G" , (const char *)"CDCPGD_128GB_BLOCK_NUM", CDCPGD_128GB_BLOCK_NUM, 0, 0 },
    {(const char *)"256G" , (const char *)"CDCPGD_256GB_BLOCK_NUM", CDCPGD_256GB_BLOCK_NUM, 0, 0 },
    {(const char *)"512G" , (const char *)"CDCPGD_512GB_BLOCK_NUM", CDCPGD_512GB_BLOCK_NUM, 0, 0 },
};

static uint8_t g_cdcpgd_cfg_tbl_len = (uint8_t)(sizeof(g_cdcpgd_cfg_tbl)/sizeof(g_cdcpgd_cfg_tbl[0]));

const char *cdcpgd_model_str(const uint16_t pgd_block_num)
{
    uint8_t cdcpgd_model;

    for(cdcpgd_model = 0; cdcpgd_model < g_cdcpgd_cfg_tbl_len; cdcpgd_model ++)
    {
        CDCPGD_CFG *cdcpgd_cfg;

        cdcpgd_cfg = &(g_cdcpgd_cfg_tbl[ cdcpgd_model ]);
        if(pgd_block_num == CDCPGD_CFG_BLOCK_NUM(cdcpgd_cfg))
        {
            return CDCPGD_CFG_MODEL_STR(cdcpgd_cfg);
        }
    }

    return (const char *)"unkown";
}

uint16_t cdcpgd_model_get(const char *model_str)
{
    uint8_t cdcpgd_model;

    for(cdcpgd_model = 0; cdcpgd_model < g_cdcpgd_cfg_tbl_len; cdcpgd_model ++)
    {
        CDCPGD_CFG *cdcpgd_cfg;
        cdcpgd_cfg = &(g_cdcpgd_cfg_tbl[ cdcpgd_model ]);

        if(0 == strcasecmp(CDCPGD_CFG_MODEL_STR(cdcpgd_cfg), model_str))
        {
            return CDCPGD_CFG_BLOCK_NUM(cdcpgd_cfg);
        }
    }
    return (CDCPGD_ERROR_BLOCK_NUM);
}

EC_BOOL cdcpgd_model_search(const UINT32 vdisk_size /*in byte*/, UINT32 *vdisk_num)
{
    UINT32      block_num;

    /*how many blocks for vdisk total space*/
    block_num    = ((vdisk_size + (UINT32)CDCPGB_SIZE_NBYTES - 1) >> (UINT32)CDCPGB_SIZE_NBITS);

    /*how many vdisks for the blocks*/
    (*vdisk_num) = ((block_num + CDCPGD_MAX_BLOCK_NUM - 1) / CDCPGD_MAX_BLOCK_NUM);

    dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "[DEBUG] cdcpgd_model_search: "
                                           "vdisk size %ld bytes => %ld vdisks, "
                                           "where block size %u Bytes\n",
                                           vdisk_size, (*vdisk_num),
                                           (uint32_t)CDCPGB_SIZE_NBYTES);

    return (EC_TRUE);
}

STATIC_CAST static uint16_t __cdcpgd_page_model_first_block(const CDCPGD *cdcpgd, const uint16_t page_model)
{
    uint16_t node_pos;
    const CDCPGRB_NODE *node;

    node_pos = cdcpgrb_tree_first_node(CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd), CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model));
    if(CDCPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:__cdcpgd_page_model_first_block: no free page in page model %u\n", page_model);
        return (CDCPGRB_ERR_POS);
    }

    node = CDCPGRB_POOL_NODE(CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd), node_pos);
    return (CDCPGRB_NODE_DATA(node));
}

STATIC_CAST static uint16_t __cdcpgd_page_model_get(const CDCPGD *cdcpgd, const uint16_t assign_bitmap)
{
    uint16_t page_model;
    uint16_t e;

    for(page_model = 0, e = 1; CDCPGB_MODEL_NUM > page_model && 0 == (assign_bitmap & e); page_model ++, e <<= 1)
    {
      /*do nothing*/
    }
    return (page_model);
}

STATIC_CAST static CDCPGB *__cdcpgd_block(CDCPGD *cdcpgd, const uint16_t  block_no)
{
    return (CDCPGB *)(((void *)CDCPGD_HEADER(cdcpgd)) + CDCPGD_HDR_SIZE + block_no * CDCPGB_SIZE);
}

EC_BOOL cdcpgd_hdr_max_size(UINT32 *size)
{
    (*size) += CDCPGD_HDR_SIZE;
    return (EC_TRUE);
}

EC_BOOL cdcpgd_hdr_init(CDCPGD_HDR *cdcpgd_hdr, const uint16_t disk_no, const uint16_t block_num)
{
    uint16_t    page_model;

    if(EC_FALSE == cdcpgrb_pool_init(CDCPGD_HDR_CDCPGRB_POOL(cdcpgd_hdr), block_num))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_hdr_init: "
                                               "init cdcpgrb pool failed "
                                               "where block_num = %u\n",
                                               block_num);
        return (EC_FALSE);
    }

    for(page_model = 0; CDCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CDCPGD_HDR_BLOCK_CDCPGRB_ROOT_POS(cdcpgd_hdr, page_model) = CDCPGRB_ERR_POS;
    }

    CDCPGD_HDR_DISK_NO(cdcpgd_hdr)               = disk_no;
    CDCPGD_HDR_ASSIGN_BITMAP(cdcpgd_hdr)         = 0;
    CDCPGD_HDR_PAGE_BLOCK_MAX_NUM(cdcpgd_hdr)    = block_num;

    /*statistics*/
    CDCPGD_HDR_PAGE_MAX_NUM(cdcpgd_hdr)          = block_num * CDCPGD_BLOCK_PAGE_NUM;
    CDCPGD_HDR_PAGE_USED_NUM(cdcpgd_hdr)         = 0;
    CDCPGD_HDR_PAGE_ACTUAL_USED_SIZE(cdcpgd_hdr) = 0;

    return (EC_TRUE);
}

CDCPGD *cdcpgd_new()
{
    CDCPGD *cdcpgd;

    alloc_static_mem(MM_CDCPGD, &cdcpgd, LOC_CDCPGD_0001);
    if(NULL_PTR == cdcpgd)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_new: "
                                               "malloc cdcpgd failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdcpgd_init(cdcpgd))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_new: "
                                               "init cdcpgd failed\n");
        free_static_mem(MM_CDCPGD, cdcpgd, LOC_CDCPGD_0002);
        return (NULL_PTR);
    }

    return (cdcpgd);
}

/* one page cache disk = 32GB */
EC_BOOL cdcpgd_init(CDCPGD *cdcpgd)
{
    uint16_t block_no;

    CDCPGD_SIZE(cdcpgd)  = 0;
    CDCPGD_HEADER(cdcpgd)= NULL_PTR;

    for(block_no = 0; block_no < CDCPGD_MAX_BLOCK_NUM; block_no ++)
    {
        CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cdcpgd_clean(CDCPGD *cdcpgd)
{
    if(NULL_PTR != cdcpgd)
    {
        UINT32 block_num;
        UINT32 block_no;

        /*clean blocks*/
        if(NULL_PTR != CDCPGD_HEADER(cdcpgd))
        {
            block_num = DMIN(CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd), CDCPGD_MAX_BLOCK_NUM);
        }
        else
        {
            block_num = CDCPGD_MAX_BLOCK_NUM;
        }

        for(block_no = 0; block_no < block_num; block_no ++)
        {
            CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no) = NULL_PTR;
        }

        CDCPGD_HEADER(cdcpgd) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cdcpgd_clear(CDCPGD *cdcpgd)
{
    if(NULL_PTR != cdcpgd)
    {
        UINT32 block_no;

        /*clean blocks*/
        for(block_no = 0; block_no < CDCPGD_MAX_BLOCK_NUM; block_no ++)
        {
            CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no) = NULL_PTR;
        }

        CDCPGD_HEADER(cdcpgd) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cdcpgd_free(CDCPGD *cdcpgd)
{
    if(NULL_PTR != cdcpgd)
    {
        cdcpgd_clean(cdcpgd);
        free_static_mem(MM_CDCPGD, cdcpgd, LOC_CDCPGD_0003);
    }

    return (EC_TRUE);
}

CDCPGD *cdcpgd_make(const uint16_t disk_no, const uint16_t block_num, UINT8 *base, UINT32 *pos)
{
    CDCPGD      *cdcpgd;
    CDCPGD_HDR  *cdcpgd_hdr;
    uint16_t     block_no;

    if(CDCPGD_MAX_BLOCK_NUM < block_num)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_make: "
                                               "block_num %u overflow\n",
                                               block_num);
        return (NULL_PTR);
    }

    cdcpgd = cdcpgd_new();
    if(NULL_PTR == cdcpgd)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_make: "
                                               "new cdcpgd failed\n");
        return (NULL_PTR);
    }

    rlog(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_make: "
                    "CDCPGD_HDR_SIZE %ld, block_num %u, CDCPGB_SIZE %ld, sizeof(off_t) = %ld\n",
                    CDCPGD_HDR_SIZE, block_num, CDCPGB_SIZE, sizeof(off_t));

    CDCPGD_SIZE(cdcpgd) = CDCPGD_HDR_SIZE + block_num * CDCPGB_SIZE;

    cdcpgd_hdr = (CDCPGD_HDR *)(base + (*pos));

    dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_make: "
                                           "cdcpgd_hdr: %p, at base %p, offset %ld\n",
                                           cdcpgd_hdr, base, (*pos));

    //(*pos) += CDCPGD_HDR_SIZE;
    (*pos) += CDCPGD_SIZE(cdcpgd); /*next disk*/

    if(EC_FALSE == cdcpgd_hdr_init(cdcpgd_hdr, disk_no, block_num))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_make: "
                                               "init disk header failed\n");

        cdcpgd_free(cdcpgd);
        return (NULL_PTR);
    }

    CDCPGD_HEADER(cdcpgd) = cdcpgd_hdr;

    /*init blocks*/
    for(block_no = 0; block_no < block_num; block_no ++)
    {
        CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no) = __cdcpgd_block(cdcpgd, block_no);
        cdcpgb_init(CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no), CDCPGD_BLOCK_PAGE_MODEL);
        cdcpgd_add_block(cdcpgd, block_no, CDCPGD_BLOCK_PAGE_MODEL);

        if(0 == ((block_no + 1) % 1000))
        {
            dbg_log(SEC_0184_CDCPGD, 3)(LOGSTDOUT, "info:cdcpgd_make: init block %u - %u done\n", block_no - 999, block_no);
        }
    }
    dbg_log(SEC_0184_CDCPGD, 3)(LOGSTDOUT, "info:cdcpgd_make: init %u blocks done\n", block_num);

    return (cdcpgd);
}

/*add one free block into pool*/
EC_BOOL cdcpgd_add_block(CDCPGD *cdcpgd, const uint16_t block_no, const uint16_t page_model)
{
    if(CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd) <= block_no)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_add_block: block_no %u overflow where block max num is %u\n", block_no, CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd));
        return (EC_FALSE);
    }

    /*insert block_no to rbtree*/
    if(CDCPGRB_ERR_POS == cdcpgrb_tree_insert_data(CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd), &(CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model)), block_no))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_add_block: add block_no %u to rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd) |= (uint16_t)(~((1 << page_model) - 1)) & CDCPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free block from pool*/
EC_BOOL cdcpgd_del_block(CDCPGD *cdcpgd, const uint16_t block_no, const uint16_t page_model)
{
    /*del block_no from rbtree*/
    if(EC_FALSE == cdcpgrb_tree_delete_data(CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd), &(CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model)), block_no))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_del_block: del block_no %u from rbtree of page model %u failed\n", block_no, page_model);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CDCPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cdcpgrb_tree_is_empty(CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd), CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model_t))/*this page-model is empty*/
        )
        {
            CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cdcpgd_assign_block(CDCPGD *cdcpgd, uint16_t *page_model, uint16_t *block_no)
{
    uint16_t block_no_t;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd) & mask))
    {
        dbg_log(SEC_0184_CDCPGD, 7)(LOGSTDOUT, "error:__cdcpgd_assign_block: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd), mask);
        return (EC_FALSE);
    }

    while(CDCPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cdcpgrb_tree_is_empty(CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd), CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CDCPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:__cdcpgd_assign_block: no free block available from page model %u\n", *page_model);
        return (EC_FALSE);
    }

    block_no_t = __cdcpgd_page_model_first_block(cdcpgd, page_model_t);
    if(CDCPGRB_ERR_POS == block_no_t)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:__cdcpgd_assign_block: no free block in page model %u\n", page_model_t);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;
    (*block_no)   = block_no_t;

    return (EC_TRUE);
}

EC_BOOL cdcpgd_new_space(CDCPGD *cdcpgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no)
{
    CDCPGB    *cdcpgb;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t e;
    uint16_t t;
    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t block_no_t;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CDCPGD_ASSERT(0 < size);

    if(CDCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    page_num_need = (uint16_t)((size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);
    //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDNULL, "[DEBUG] cdcpgd_new_space: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CDCPGD_ASSERT(CDCPGB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CDCPGB_PAGE_HI_BITS_MASK;
    for(t = page_num_need, page_model = 0; 0 == (t & e); t <<= 1, page_model ++)
    {
        /*do nothing*/
    }
    //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDNULL, "[DEBUG] cdcpgd_new_space: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n", t, page_model, e, (t << 1));

    if(CDCPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model --;/*upgrade page_model one level*/
    }

    //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDNULL, "[DEBUG] cdcpgd_new_space: page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   page_num_need, page_model, (uint16_t)(1 << (CDCPGB_MODEL_NUM - 1 - page_model)));

    for(;;)/*Oops! fix inconsistency between cdcpgd and cdcpgb*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;

        if(EC_FALSE == __cdcpgd_assign_block(cdcpgd, &page_model_t, &block_no_t))
        {
            dbg_log(SEC_0184_CDCPGD, 7)(LOGSTDOUT, "error:cdcpgd_new_space: assign one block from page model %u failed\n", page_model);
            return (EC_FALSE);
        }

        //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: page model %u => assign block %u, page model %u\n", page_model, page_model_t, block_no_t);

        cdcpgb = CDCPGD_BLOCK_NODE(cdcpgd, block_no_t);
        pgb_assign_bitmap_old = CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb);

        //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: block %u, bitmap %s\n",
        //                                       block_no_t, c_uint16_t_to_bin_str(pgb_assign_bitmap_old));


        if(EC_TRUE == cdcpgb_new_space(cdcpgb, size, &page_no_t))
        {
            page_model = page_model_t; /*re-init page_model*/
            break;
        }

        /*find inconsistent, fix it!*/
        cdcpgd_del_block(cdcpgd, block_no_t, page_model_t);

        while(CDCPGB_MODEL_NUM > page_model_t
           && 0 == (pgb_assign_bitmap_old & (uint16_t)(1 << page_model_t))
           )
        {
             page_model_t ++;
        }
        CDCPGD_ASSERT(CDCPGB_MODEL_NUM > page_model_t);
        cdcpgd_add_block(cdcpgd, block_no_t, page_model_t);

        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "warn:cdcpgd_new_space: block %u relocation to page model %u\n", block_no_t, page_model_t);
    }

    pgb_assign_bitmap_new = CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb);

    //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: block_no_t %u: pgb bitmap %x => %x\n", block_no_t, pgb_assign_bitmap_old, pgb_assign_bitmap_new);

    /*pgb_assign_bitmap changes may make pgd_assign_bitmap changes*/
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: before delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb)),
        //                    c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)));

        cdcpgd_del_block(cdcpgd, block_no_t, page_model);

        //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: after  delete block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
        //                    block_no_t,
        //                    c_uint16_t_to_bin_str(CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb)),
        //                    c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)));

        if(EC_FALSE == cdcpgb_is_full(cdcpgb))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CDCPGB_MODEL_NUM > page_model_t
               && 0 == (pgb_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }
            CDCPGD_ASSERT(CDCPGB_MODEL_NUM > page_model_t);
            //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            cdcpgd_add_block(cdcpgd, block_no_t, page_model_t);
            //dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: block_no_t %u: pgb bitmap %s, pgd assign bitmap %s\n",
            //                    block_no_t,
            //                    c_uint16_t_to_bin_str(CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb)),
            //                    c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CDCPGD_PAGE_USED_NUM(cdcpgd)         += page_num_need;
    CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd) += size;

    CDCPGD_ASSERT(EC_TRUE == cdcpgd_check(cdcpgd));

    dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: pgd_page_used_num %u due to increment %u\n",
                        CDCPGD_PAGE_USED_NUM(cdcpgd), page_num_need);
    dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_new_space: pgd_actual_used_size %"PRId64" due to increment %u\n",
                        CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd), size);

    return (EC_TRUE);
}

EC_BOOL cdcpgd_free_space(CDCPGD *cdcpgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    CDCPGB    *cdcpgb;

    uint16_t page_num_used;

    uint16_t pgb_assign_bitmap_old;
    uint16_t pgb_assign_bitmap_new;

    CDCPGD_ASSERT(0 < size);

    if(CDCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    cdcpgb = CDCPGD_BLOCK_NODE(cdcpgd, block_no);
    pgb_assign_bitmap_old = CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb);

    if(EC_FALSE == cdcpgb_free_space(cdcpgb, page_no, size))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_free_space: block_no %u free space of page_no %u, size %u failed\n",
                           block_no, page_no, size);
        return (EC_FALSE);
    }

    pgb_assign_bitmap_new = CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb);
#if 0
    dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_free_space: cdcpgd %p, block %u, asssign bitmap %s -> %s\n",
                       cdcpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_old),
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_new));
#endif
    if(pgb_assign_bitmap_new != pgb_assign_bitmap_old)
    {
        uint16_t page_model_old;
        uint16_t page_model_new;

        page_model_old = __cdcpgd_page_model_get(cdcpgd, pgb_assign_bitmap_old);
        page_model_new = __cdcpgd_page_model_get(cdcpgd, pgb_assign_bitmap_new);
#if 0
        dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_free_space: cdcpgd %p, block %u, old asssign bitmap %s = page model %u\n",
                       cdcpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_old), page_model_old);

        dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_free_space: cdcpgd %p, block %u, new asssign bitmap %s = page model %u\n",
                       cdcpgd, block_no,
                       c_uint16_t_to_bin_str(pgb_assign_bitmap_new), page_model_new);
#endif
        if(CDCPGB_MODEL_NUM > page_model_old)
        {
            cdcpgd_del_block(cdcpgd, block_no, page_model_old);
        }

        if(EC_FALSE == cdcpgd_add_block(cdcpgd, block_no, page_model_new))
        {
            dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_free_space: add block %d, page_model_new %u failed, fix it!\n",
                                block_no, page_model_new);
            abort();
        }
    }

    page_num_used = (uint16_t)((size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    CDCPGD_PAGE_USED_NUM(cdcpgd)         -= page_num_used;
    CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd) -= size;

    dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_free_space: pgd_page_used_num %u due to decrement %u\n",
                        CDCPGD_PAGE_USED_NUM(cdcpgd), page_num_used);
    dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_free_space: pgd_actual_used_size %"PRId64" due to decrement %u\n",
                        CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd), size);

    return (EC_TRUE);
}

EC_BOOL cdcpgd_is_full(const CDCPGD *cdcpgd)
{
    if(CDCPGD_PAGE_USED_NUM(cdcpgd) == CDCPGD_PAGE_MAX_NUM(cdcpgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcpgd_is_empty(const CDCPGD *cdcpgd)
{
    if(0 == CDCPGD_PAGE_USED_NUM(cdcpgd) && 0 < CDCPGD_PAGE_MAX_NUM(cdcpgd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*compute cdcpgd current page model support up to*/
uint16_t cdcpgd_page_model(const CDCPGD *cdcpgd)
{
    uint16_t page_model;
    uint16_t pgd_assign_bitmap;
    uint16_t e;

    pgd_assign_bitmap = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);
    for(page_model = 0, e = 1; CDCPGB_MODEL_NUM > page_model && 0 == (pgd_assign_bitmap & e); e <<= 1, page_model ++)
    {
        /*do nothing*/
    }

    dbg_log(SEC_0184_CDCPGD, 9)(LOGSTDOUT, "[DEBUG] cdcpgd_page_model: cdcpgd %p: assign bitmap %s ==> page_model %u\n",
                       cdcpgd, c_uint16_t_to_bin_str(pgd_assign_bitmap), page_model);

    return (page_model);
}

EC_BOOL cdcpgd_max_size(UINT32 *size)
{
    UINT32   block_size;
    //uint16_t block_no;

    cdcpgd_hdr_max_size(size);

    block_size = 0;
    cdcpgb_max_size(&block_size);

    (*size) += block_size * CDCPGD_MAX_BLOCK_NUM;

#if 0
    for(block_no = 0; block_no < CDCPGD_MAX_BLOCK_NUM; block_no ++)
    {
        cdcpgb_max_size(size);
    }
#endif
    return (EC_TRUE);
}

EC_BOOL cdcpgd_load(CDCPGD *cdcpgd, UINT8 *base, UINT32 *pos)
{
    uint16_t block_no;

    CDCPGD_ASSERT(NULL_PTR != CDCPGD_HEADER(cdcpgd));

    /*load block table*/
    for(block_no = 0; block_no < CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd); block_no ++)
    {
        CDCPGB      *cdcpgb;

        cdcpgb = (CDCPGB *)(base + (*pos));
        (*pos) += CDCPGB_SIZE;

        CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no) = cdcpgb;
    }

    return (EC_TRUE);
}

EC_BOOL cdcpgd_check(const CDCPGD *cdcpgd)
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

    pgd_assign_bitmap    = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);
    pgd_actual_used_size = CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd);
    pgd_page_max_num     = CDCPGD_PAGE_MAX_NUM(cdcpgd);
    pgd_page_used_num    = CDCPGD_PAGE_USED_NUM(cdcpgd);
    block_num = CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd);

    pgb_assign_bitmap    = 0;
    pgb_actual_used_size = 0;
    pgb_page_max_num     = 0;
    pgb_page_used_num    = 0;

    for(block_no = 0; block_no < block_num; block_no ++)
    {
        pgb_assign_bitmap    |= CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(CDCPGD_BLOCK_NODE(cdcpgd, block_no));
        pgb_actual_used_size += CDCPGB_PAGE_ACTUAL_USED_SIZE(CDCPGD_BLOCK_NODE(cdcpgd, block_no));
        pgb_page_max_num     += CDCPGB_PAGE_MAX_NUM(CDCPGD_BLOCK_NODE(cdcpgd, block_no));
        pgb_page_used_num    += CDCPGB_PAGE_USED_NUM(CDCPGD_BLOCK_NODE(cdcpgd, block_no));
    }

    if(pgd_assign_bitmap != pgb_assign_bitmap)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_check: inconsistent bitmap: pgd_assign_bitmap = %s, pgb_assign_bitmap = %s\n",
                           c_uint16_t_to_bin_str(pgd_assign_bitmap), c_uint16_t_to_bin_str(pgb_assign_bitmap));
        return (EC_FALSE);
    }

    if(pgd_actual_used_size != pgb_actual_used_size)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_check: inconsistent actual used size: pgd_actual_used_size = %"PRId64", pgb_actual_used_size = %"PRId64"\n",
                            pgd_actual_used_size, pgb_actual_used_size);
        return (EC_FALSE);
    }

    if(pgd_page_max_num != pgb_page_max_num)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_check: inconsistent page max num: pgd_page_max_num = %u, pgb_page_max_num = %u\n",
                            pgd_page_max_num, pgb_page_max_num);
        return (EC_FALSE);
    }

    if(pgd_page_used_num != pgb_page_used_num)
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_check: inconsistent page used num: pgd_page_used_num = %u, pgb_page_used_num = %u\n",
                            pgd_page_used_num, pgb_page_used_num);
        return (EC_FALSE);
    }

    /*check block table*/
    for(block_no = 0; block_no < CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd); block_no ++)
    {
        if(EC_FALSE == cdcpgb_check(CDCPGD_BLOCK_NODE(cdcpgd, block_no)))
        {
            dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_check: check CDCPGD_BLOCK_NODE of block_no %u failed\n", block_no);
            return (EC_FALSE);
        }
    }
    dbg_log(SEC_0184_CDCPGD, 5)(LOGSTDOUT, "cdcpgd_check: cdcpgd %p check passed\n", cdcpgd);
    return (EC_TRUE);
}

void cdcpgd_print(LOG *log, const CDCPGD *cdcpgd)
{
    uint16_t  page_model;
    char     *page_desc;
    REAL      used_size;
    REAL      occupied_size;
    REAL      ratio_size;
    REAL      ratio_page;

    CDCPGD_ASSERT(NULL_PTR != cdcpgd);

    //cdcpgrb_pool_print(log, CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd));

    if(0)
    {
        for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
        {
            sys_log(log, "cdcpgd_print: page_model %u, block root_pos %u\n",
                         page_model,
                         CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model));
            cdcpgrb_tree_print(log, CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd), CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model));
            sys_log(log, "----------------------------------------------------------\n");
        }
    }
    used_size     = (0.0 + CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd));
    occupied_size = (0.0 + (((uint64_t)CDCPGD_PAGE_USED_NUM(cdcpgd)) << CDCPGB_PAGE_SIZE_NBITS));
    ratio_size    = (EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size));

    ratio_page    = ((0.0 + CDCPGD_PAGE_USED_NUM(cdcpgd)) / (0.0 + CDCPGD_PAGE_MAX_NUM(cdcpgd)));

    page_desc = CDCPGB_PAGE_DESC;

/*
    sys_log(log, "cdcpgd_print: cdcpgd %p, ratio %.2f\n",
                 cdcpgd,
                 EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size)
                 );
*/
    sys_log(log, "cdcpgd_print: cdcpgd %p, block num %u, %s, page max num %u, page used num %u, page ratio %.2f, actual used size %"PRId64", size ratio %.2f\n",
                 cdcpgd,
                 CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd),
                 page_desc,
                 CDCPGD_PAGE_MAX_NUM(cdcpgd),
                 CDCPGD_PAGE_USED_NUM(cdcpgd),
                 ratio_page,
                 CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd),
                 ratio_size
                 );

    sys_log(log, "cdcpgd_print: cdcpgd %p, assign bitmap %s \n",
                 cdcpgd,
                 c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd))
                 );

    if(0)
    {
        for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
        {
            if(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd) & (1 << page_model))
            {
                sys_log(log, "cdcpgd_print: cdcpgd %p, model %u has page to assign\n", cdcpgd, page_model);
            }
            else
            {
                sys_log(log, "cdcpgd_print: cdcpgd %p, model %u no  page to assign\n", cdcpgd, page_model);
            }
        }
    }

    if(0)
    {
        uint16_t  block_no;
        for(block_no = 0; block_no < CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd); block_no ++)
        {
            sys_log(log, "cdcpgd_print: block %u is\n", block_no);
            cdcpgb_print(log, CDCPGD_BLOCK_NODE(cdcpgd, block_no));
        }
    }

    return;
}

/* ---- debug ---- */
EC_BOOL cdcpgd_debug_cmp(const CDCPGD *cdcpgd_1st, const CDCPGD *cdcpgd_2nd)
{
    uint16_t page_model;
    uint16_t block_no;

    /*cdcpgrb pool*/
    if(EC_FALSE == cdcpgrb_debug_cmp(CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd_1st), CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd_2nd)))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent cdcpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd_1st, page_model);
        root_pos_2nd = CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*assign bitmap*/
    if(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd_1st) != CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd_1st))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent CDCPGD_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd_1st), CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd_2nd));
        return (EC_FALSE);
    }

    /*block max num*/
    if(CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd_1st) != CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd_1st))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent CDCPGD_PAGE_BLOCK_MAX_NUM: %u != %u\n",
                            CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd_1st), CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CDCPGD_PAGE_MAX_NUM(cdcpgd_1st) != CDCPGD_PAGE_MAX_NUM(cdcpgd_1st))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent CDCPGD_PAGE_MAX_NUM: %u != %u\n",
                            CDCPGD_PAGE_MAX_NUM(cdcpgd_1st), CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CDCPGD_PAGE_USED_NUM(cdcpgd_1st) != CDCPGD_PAGE_USED_NUM(cdcpgd_1st))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent CDCPGD_PAGE_USED_NUM: %u != %u\n",
                            CDCPGD_PAGE_USED_NUM(cdcpgd_1st), CDCPGD_PAGE_USED_NUM(cdcpgd_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd_1st) != CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd_1st))
    {
        dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent CDCPGD_PAGE_ACTUAL_USED_SIZE: %"PRId64" != %"PRId64"\n",
                            CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd_1st), CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd_2nd));
        return (EC_FALSE);
    }

    /*block cdcpgb*/
    for(block_no = 0; block_no < CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd_1st); block_no ++)
    {
        if(EC_FALSE == cdcpgb_debug_cmp(CDCPGD_BLOCK_NODE(cdcpgd_1st, block_no), CDCPGD_BLOCK_NODE(cdcpgd_2nd, block_no)))
        {
            dbg_log(SEC_0184_CDCPGD, 0)(LOGSTDOUT, "error:cdcpgd_debug_cmp: inconsistent CDCPGD_BLOCK_NODE at block_no %u\n", block_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

