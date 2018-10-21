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
#include "cmcpgd.h"
#include "cmcpgv.h"

#if (SWITCH_ON == CMC_ASSERT_SWITCH)
#define CMCPGV_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CMC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CMC_ASSERT_SWITCH)
#define CMCPGV_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CMC_ASSERT_SWITCH)*/

STATIC_CAST static uint16_t __cmcpgv_page_model_first_disk(const CMCPGV *cmcpgv, const uint16_t page_model)
{
    uint16_t node_pos;
    const CMCPGRB_NODE *node;

    node_pos = cmcpgrb_tree_first_node(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv), CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model));
    if(CMCPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_page_model_first_disk: no free page in page model %u\n", page_model);
        return (CMCPGRB_ERR_POS);
    }

    node = CMCPGRB_POOL_NODE(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv), node_pos);
    return (CMCPGRB_NODE_DATA(node));
}

STATIC_CAST static uint16_t __cmcpgv_page_model_get(const CMCPGV *cmcpgv, const uint16_t assign_bitmap)
{
    uint16_t page_model;
    uint16_t e;

    for(page_model = 0, e = 1; CMCPGB_MODEL_NUM > page_model && 0 == (assign_bitmap & e); page_model ++, e <<= 1)
    {
      /*do nothing*/
    }
    return (page_model);
}

EC_BOOL cmcpgv_hdr_free(CMCPGV *cmcpgv)
{
    if(NULL_PTR != CMCPGV_HEADER(cmcpgv))
    {
        safe_free(CMCPGV_HEADER(cmcpgv), LOC_CMCPGV_0001);
        CMCPGV_HEADER(cmcpgv) = NULL_PTR;
    }

    /*cmcpgv_hdr cannot be accessed again*/
    return (EC_TRUE);
}

CMCPGV_HDR *cmcpgv_hdr_new(CMCPGV *cmcpgv)
{
    CMCPGV_HDR *cmcpgv_hdr;

    cmcpgv_hdr = (CMCPGV_HDR *)safe_malloc(CMCPGV_SIZE(cmcpgv), LOC_CMCPGV_0002);
    if(NULL_PTR == cmcpgv_hdr)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_hdr_new: new header with %u bytes failed\n", 
                                               CMCPGV_SIZE(cmcpgv));
        return (NULL_PTR);
    }

    CMCPGV_HEADER(cmcpgv) = cmcpgv_hdr;

    if(EC_FALSE == cmcpgv_hdr_init(cmcpgv))
    {
        CMCPGV_HEADER(cmcpgv) = NULL_PTR;

        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_hdr_new: init cmcpgv failed\n");
        safe_free(cmcpgv_hdr, LOC_CMCPGV_0003);

        return (NULL_PTR);
    }


    return (cmcpgv_hdr);
}

EC_BOOL cmcpgv_hdr_init(CMCPGV *cmcpgv)
{
    CMCPGV_HDR *cmcpgv_hdr;
    uint16_t  page_model;

    cmcpgv_hdr = CMCPGV_HEADER(cmcpgv);
    if(EC_FALSE == cmcpgrb_pool_init(CMCPGV_HDR_CMCPGRB_POOL(cmcpgv_hdr), CMCPGV_MAX_DISK_NUM))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_hdr_init: init cpgrb pool failed where disk_num = %u\n", CMCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    for(page_model = 0; CMCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CMCPGV_HDR_DISK_CMCPGRB_ROOT_POS(cmcpgv_hdr, page_model) = CMCPGRB_ERR_POS;
    }

    CMCPGV_HDR_ASSIGN_BITMAP(cmcpgv_hdr) = 0;

    CMCPGV_HDR_PAGE_DISK_NUM(cmcpgv_hdr) = 0;

    /*statistics*/
    CMCPGV_HDR_PAGE_MAX_NUM(cmcpgv_hdr)          = 0;
    CMCPGV_HDR_PAGE_USED_NUM(cmcpgv_hdr)         = 0;
    CMCPGV_HDR_PAGE_ACTUAL_USED_SIZE(cmcpgv_hdr) = 0;

    return (EC_TRUE);
}

CMCPGV *cmcpgv_new()
{
    CMCPGV      *cmcpgv;

    alloc_static_mem(MM_CMCPGV, &cmcpgv, LOC_CMCPGV_0004);
    if(NULL_PTR == cmcpgv)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_new: malloc cmcpgv failed\n");
        return (NULL_PTR);
    }

    cmcpgv_init(cmcpgv);

    CMCPGV_SIZE(cmcpgv) = CMCPGV_HDR_SIZE;
    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] CMCPGV_HDR_SIZE = %ld\n", CMCPGV_HDR_SIZE);

    CMCPGV_HEADER(cmcpgv) = cmcpgv_hdr_new(cmcpgv);
    if(NULL_PTR == CMCPGV_HEADER(cmcpgv))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_new: new cmcpgv header failed\n");
        cmcpgv_free(cmcpgv);
        return (NULL_PTR);
    }

    //dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new: cmcpgv %p is\n", cmcpgv);
    //cmcpgv_print(LOGSTDOUT, cmcpgv);

    return (cmcpgv);
}

EC_BOOL cmcpgv_free(CMCPGV *cmcpgv)
{
    if(NULL_PTR != cmcpgv)
    {
        uint16_t disk_no;

        /*clean disks*/
        for(disk_no = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CMCPGV_DISK_CMCPGD(cmcpgv, disk_no))
            {
                cmcpgd_free(CMCPGV_DISK_CMCPGD(cmcpgv, disk_no));
                CMCPGV_DISK_CMCPGD(cmcpgv, disk_no) = NULL_PTR;
            }
        }

        cmcpgv_hdr_free(cmcpgv);

        free_static_mem(MM_CMCPGV, cmcpgv, LOC_CMCPGV_0005);
    }

    return (EC_TRUE);
}

/* one page cache disk = 32GB */
EC_BOOL cmcpgv_init(CMCPGV *cmcpgv)
{
    uint16_t disk_no;

    CMCPGV_SIZE(cmcpgv)  = 0;
    CMCPGV_HEADER(cmcpgv)= NULL_PTR;

    for(disk_no = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
    {
        CMCPGV_DISK_CMCPGD(cmcpgv, disk_no) = NULL_PTR;
    }
    return (EC_TRUE);
}

/*note: cmcpgv_clean is for not applying mmap*/
void cmcpgv_clean(CMCPGV *cmcpgv)
{
    uint16_t page_model;
    uint16_t disk_no;

    if(NULL_PTR == CMCPGV_HEADER(cmcpgv))
    {
        return;
    }

    cmcpgrb_pool_clean(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv));

    for(page_model = 0; CMCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model) = CMCPGRB_ERR_POS;
    }

    for(disk_no = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CMCPGV_DISK_CMCPGD(cmcpgv, disk_no))
        {
            safe_free(CMCPGV_DISK_CMCPGD(cmcpgv, disk_no), LOC_CMCPGV_0006);
            CMCPGV_DISK_CMCPGD(cmcpgv, disk_no) = NULL_PTR;
        }
    }
    CMCPGV_PAGE_DISK_NUM(cmcpgv)                = 0;

    CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)     = 0;
    CMCPGV_PAGE_MAX_NUM(cmcpgv)                 = 0;
    CMCPGV_PAGE_USED_NUM(cmcpgv)                = 0;
    CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv)        = 0;

    safe_free(CMCPGV_HEADER(cmcpgv), LOC_CMCPGV_0007);
    CMCPGV_HEADER(cmcpgv) = NULL_PTR;

    return;
}

/*add one free disk into pool*/
STATIC_CAST static EC_BOOL __cmcpgv_add_disk(CMCPGV *cmcpgv, const uint16_t disk_no, const uint16_t page_model)
{
    if(CMCPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_add_disk: disk_no %u overflow where disk max num is %u\n", disk_no, CMCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    /*insert disk_no to rbtree*/
    if(CMCPGRB_ERR_POS == cmcpgrb_tree_insert_data(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv), &(CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model)), disk_no))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_add_disk: add disk_no %u to rbtree of page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv) |= (uint16_t)(~((1 << page_model) - 1)) & CMCPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free disk from pool*/
STATIC_CAST static EC_BOOL __cmcpgv_del_disk(CMCPGV *cmcpgv, const uint16_t disk_no, const uint16_t page_model)
{
    /*del disk_no from rbtree*/
    if(CMCPGRB_ERR_POS == cmcpgrb_tree_delete_data(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv), &(CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model)), disk_no))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_del_disk: del disk_no %u from rbtree of page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CMCPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cmcpgrb_tree_is_empty(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv), CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model_t))/*this page-model is empty*/
        )
        {
            CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cmcpgv_assign_disk(CMCPGV *cmcpgv, uint16_t *page_model, uint16_t *disk_no)
{
    uint16_t disk_no_t;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv) & mask))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_assign_disk: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv), mask);
        return (EC_FALSE);
    }

    while(CMCPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cmcpgrb_tree_is_empty(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv), CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CMCPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_assign_disk: no free disk available from page model %u\n", *page_model);
        return (EC_FALSE);
    }

    disk_no_t = __cmcpgv_page_model_first_disk(cmcpgv, page_model_t);
    if(CMCPGRB_ERR_POS == disk_no_t)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:__cmcpgv_assign_disk: no free disk in page model %u\n", page_model_t);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;
    (*disk_no)    = disk_no_t;

    return (EC_TRUE);
}

EC_BOOL cmcpgv_add_disk(CMCPGV *cmcpgv, const uint16_t disk_no)
{
    CMCPGD  *cmcpgd;

    if(CMCPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_add_disk: disk %u overflow the max disk num %u\n", disk_no, CMCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    if(NULL_PTR != CMCPGV_DISK_CMCPGD(cmcpgv, disk_no))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_add_disk: disk %u already exist\n", disk_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0105_CMCPGV, 3)(LOGSTDOUT, "info:cmcpgv_add_disk: try to create disk %u ...\n", disk_no);

    cmcpgd = cmcpgd_new(CMCPGD_MAX_BLOCK_NUM);
    if(NULL_PTR == cmcpgd)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_add_disk: create disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0105_CMCPGV, 3)(LOGSTDOUT, "info:cmcpgv_add_disk: create disk %u done\n", disk_no);

    /*add disk to volume*/
    CMCPGV_DISK_CMCPGD(cmcpgv, disk_no) = cmcpgd;
    CMCPGV_PAGE_DISK_NUM(cmcpgv) ++;

    /*statistics*/
    CMCPGV_PAGE_MAX_NUM(cmcpgv)          += ((uint64_t)1) * CMCPGD_MAX_BLOCK_NUM * CMCPGD_BLOCK_PAGE_NUM;
    CMCPGV_PAGE_USED_NUM(cmcpgv)         += 0;
    CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv) += 0;

    /*add one free disk into pool*/
    return __cmcpgv_add_disk(cmcpgv, disk_no, CMCPGD_BLOCK_PAGE_MODEL);
}

EC_BOOL cmcpgv_del_disk(CMCPGV *cmcpgv, const uint16_t disk_no)
{
    CMCPGD    *cmcpgd;
    uint16_t page_model;

    if(CMCPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_del_disk: disk %u overflow the max disk num %u\n", disk_no, CMCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    cmcpgd = CMCPGV_DISK_CMCPGD(cmcpgv, disk_no);
    if(NULL_PTR == cmcpgd)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_del_disk: disk %u not exist\n", disk_no);
        return (EC_FALSE);
    }

    page_model = cmcpgd_page_model(cmcpgd);

    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_del_disk: disk %u, page_model %u\n", disk_no, page_model);

    /*delete the disk from pool*/
    if(EC_FALSE == __cmcpgv_del_disk(cmcpgv, disk_no, page_model))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_del_disk: del disk %u, page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*adjust cmcpgv statistics*/
    CMCPGV_PAGE_DISK_NUM(cmcpgv) --;
    CMCPGV_DISK_CMCPGD(cmcpgv, disk_no) = NULL_PTR;

    /*statistics*/
    CMCPGV_PAGE_MAX_NUM(cmcpgv)          -= ((uint64_t)1) * CMCPGD_MAX_BLOCK_NUM * CMCPGD_BLOCK_PAGE_NUM;;
    CMCPGV_PAGE_USED_NUM(cmcpgv)         -= CMCPGD_PAGE_USED_NUM(cmcpgd);
    CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv) -= CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd);

    cmcpgd_free(cmcpgd);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cmcpgv_size_to_page_model(const uint32_t size, uint16_t *page_num, uint16_t *page_model)
{
    uint16_t page_num_need;
    uint16_t page_model_t;
    uint16_t e;
    uint16_t t;

    page_num_need = (uint16_t)((size + CMCPGB_PAGE_BYTE_SIZE - 1) >> CMCPGB_PAGE_BIT_SIZE);
    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDNULL, "[DEBUG] __cmcpgv_size_to_page_model: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CMCPGV_ASSERT(CMCPGB_032MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CMCPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model_t = 0/*CMCPGB_064MB_MODEL*/; 0 == (t & e); t <<= 1, page_model_t ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDNULL, "[DEBUG] __cmcpgv_size_to_page_model: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n",
                        t, page_model_t, e, (t << 1));

    if(CMCPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model_t --;/*upgrade page_model one level*/
    }

    (*page_num)   = page_num_need;
    (*page_model) = page_model_t;

    return (EC_TRUE);
}

EC_BOOL cmcpgv_new_space_from_disk(CMCPGV *cmcpgv, const uint32_t size, const uint16_t disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CMCPGD    *cmcpgd;

    uint16_t page_num_need;
    uint16_t page_model;
    uint16_t page_model_t;

    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t disk_no_t;
    uint16_t block_no_t;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CMCPGV_ASSERT(0 < size);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_new_space_from_disk: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    __cmcpgv_size_to_page_model(size, &page_num_need, &page_model);

    //dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: size = %u ==> page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   size, page_num_need, page_model, (uint16_t)(1 << (CMCPGB_MODEL_NUM - 1 - page_model)));

    disk_no_t = disk_no;

    cmcpgd = CMCPGV_DISK_NODE(cmcpgv, disk_no_t);
    pgd_assign_bitmap_old = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);

    if(EC_FALSE == cmcpgd_new_space(cmcpgd, size, &block_no_t, &page_no_t))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_new_space_from_disk: assign size %u from disk %u failed\n", size, disk_no);
        return (EC_FALSE);
    }

    pgd_assign_bitmap_new = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);

    //dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: disk_no_t %u: pgd bitmap %x => %x\n", disk_no_t, pgd_assign_bitmap_old, pgd_assign_bitmap_new);

    /*pgd_assign_bitmap changes may make pgv_assign_bitmap changes*/
    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: before delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)),
                            c_uint16_t_to_bin_str(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)));

        for(page_model_t = page_model, page_model = 0;  page_model < page_model_t; page_model ++)
        {
            if(0 != (pgd_assign_bitmap_old & (uint16_t)(1 << page_model)))
            {
                break;
            }
        }

        /*delete the disk from pool*/
        __cmcpgv_del_disk(cmcpgv, disk_no_t, page_model);

        dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: after  delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)),
                            c_uint16_t_to_bin_str(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)));

        dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: disk_no_t %u: max pages %u, used pages %u\n",
                            disk_no_t, CMCPGD_PAGE_MAX_NUM(cmcpgd), CMCPGD_PAGE_USED_NUM(cmcpgd));

        if(EC_FALSE == cmcpgd_is_full(cmcpgd))
        {
            //uint16_t page_model_t;

            page_model_t = page_model;
            while(CMCPGB_MODEL_NUM > page_model_t
               && 0 == (pgd_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CMCPGV_ASSERT(CMCPGB_MODEL_NUM > page_model_t);

            dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: page_model %u, page_model_t %u\n", page_model, page_model_t);
            /*add the disk into pool*/
            __cmcpgv_add_disk(cmcpgv, disk_no_t, page_model_t);
            dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                                disk_no_t,
                                c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)),
                                c_uint16_t_to_bin_str(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CMCPGV_PAGE_USED_NUM(cmcpgv)         += page_num_need;
    CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv) += size;

    CMCPGV_ASSERT(EC_TRUE == cmcpgv_check(cmcpgv));

    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: pgv_page_used_num %"PRId64" due to increment %u\n",
                        CMCPGV_PAGE_USED_NUM(cmcpgv), page_num_need);
    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space_from_disk: pgv_actual_used_size %"PRId64" due to increment %u\n",
                        CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv), size);

    return (EC_TRUE);
}

EC_BOOL cmcpgv_new_space(CMCPGV *cmcpgv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CMCPGD    *cmcpgd;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t disk_no_t;
    uint16_t block_no_t;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CMCPGV_ASSERT(0 < size);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    __cmcpgv_size_to_page_model(size, &page_num_need, &page_model);

    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: size = %u ==> page_num_need = %u ==> page_model = %u (has %u pages )\n",
                       size, page_num_need, page_model, (uint16_t)(1 << (CMCPGB_MODEL_NUM - 1 - page_model)));

    for(;;)/*Oops! fix inconsistency between cmcpgv and cmcpgd*/
    {
        uint16_t page_model_t;

        page_model_t = page_model; /*re-arm*/

        if(EC_FALSE == __cmcpgv_assign_disk(cmcpgv, &page_model_t, &disk_no_t))
        {
            dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_new_space: assign one disk from page model %u failed\n", page_model_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: size %u ==> page_model_t %u and disk_no_t %u\n", size, page_model_t, disk_no_t);

        cmcpgd = CMCPGV_DISK_NODE(cmcpgv, disk_no_t);
        pgd_assign_bitmap_old = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);

        if(EC_TRUE == cmcpgd_new_space(cmcpgd, size, &block_no_t, &page_no_t))
        {
            page_model = page_model_t;
            break;
        }

        /*find inconsistent, fix it!*/

        /*delete the disk from pool*/
        __cmcpgv_del_disk(cmcpgv, disk_no_t, page_model_t);

        while(CMCPGB_MODEL_NUM > page_model_t
           && 0 == (pgd_assign_bitmap_old & (uint16_t)(1 << page_model_t))
           )
        {
             page_model_t ++;
        }

        CMCPGV_ASSERT(CMCPGB_MODEL_NUM > page_model_t);

        /*add the disk into pool*/
        __cmcpgv_add_disk(cmcpgv, disk_no_t, page_model_t);

        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "warn:cmcpgv_new_space: disk %u model %u relocation to page model %u\n", disk_no_t, page_model_t, page_model_t);
    }

    pgd_assign_bitmap_new = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);

    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: disk_no_t %u: pgd bitmap %x => %x\n", disk_no_t, pgd_assign_bitmap_old, pgd_assign_bitmap_new);

    /*pgd_assign_bitmap changes may make pgv_assign_bitmap changes*/
    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: before delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)),
                            c_uint16_t_to_bin_str(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)));

        /*delete the disk from pool*/
        __cmcpgv_del_disk(cmcpgv, disk_no_t, page_model);

        dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: after  delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)),
                            c_uint16_t_to_bin_str(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)));

        dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: disk_no_t %u: max pages %u, used pages %u\n",
                            disk_no_t, CMCPGD_PAGE_MAX_NUM(cmcpgd), CMCPGD_PAGE_USED_NUM(cmcpgd));

        if(EC_FALSE == cmcpgd_is_full(cmcpgd))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CMCPGB_MODEL_NUM > page_model_t
               && 0 == (pgd_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CMCPGV_ASSERT(CMCPGB_MODEL_NUM > page_model_t);

            dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            /*add the disk into pool*/
            __cmcpgv_add_disk(cmcpgv, disk_no_t, page_model_t);
            dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                                disk_no_t,
                                c_uint16_t_to_bin_str(CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)),
                                c_uint16_t_to_bin_str(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*disk_no)  = disk_no_t;
    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CMCPGV_PAGE_USED_NUM(cmcpgv)         += page_num_need;
    CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv) += size;

    CMCPGV_ASSERT(EC_TRUE == cmcpgv_check(cmcpgv));

    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: pgv_page_used_num %"PRId64" due to increment %u\n",
                        CMCPGV_PAGE_USED_NUM(cmcpgv), page_num_need);
    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_new_space: pgv_actual_used_size %"PRId64" due to increment %u\n",
                        CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv), size);

    return (EC_TRUE);
}

EC_BOOL cmcpgv_free_space(CMCPGV *cmcpgv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    CMCPGD    *cmcpgd;

    uint16_t page_num_used;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CMCPGV_ASSERT(0 < size);

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    cmcpgd = CMCPGV_DISK_NODE(cmcpgv, disk_no);
    pgd_assign_bitmap_old = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);

    if(EC_FALSE == cmcpgd_free_space(cmcpgd, block_no, page_no, size))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_free_space: disk_no %u free space of block_no %u, page_no %u, size %u failed\n",
                           disk_no, block_no, page_no, size);
        return (EC_FALSE);
    }

    pgd_assign_bitmap_new = CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd);

    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        uint16_t page_model_old;
        uint16_t page_model_new;

        page_model_old = __cmcpgv_page_model_get(cmcpgv, pgd_assign_bitmap_old);
        page_model_new = __cmcpgv_page_model_get(cmcpgv, pgd_assign_bitmap_new);

        if(CMCPGB_MODEL_NUM > page_model_old)
        {
            __cmcpgv_del_disk(cmcpgv, disk_no, page_model_old);
        }
        __cmcpgv_add_disk(cmcpgv, disk_no, page_model_new);
    }

    page_num_used = (uint16_t)((size + CMCPGB_PAGE_BYTE_SIZE - 1) >> CMCPGB_PAGE_BIT_SIZE);

    CMCPGV_PAGE_USED_NUM(cmcpgv)         -= page_num_used;
    CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv) -= size;

    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_free_space: pgv_page_used_num %"PRId64" due to decrement %u\n",
                        CMCPGV_PAGE_USED_NUM(cmcpgv), page_num_used);
    dbg_log(SEC_0105_CMCPGV, 9)(LOGSTDOUT, "[DEBUG] cmcpgv_free_space: pgv_actual_used_size %"PRId64" due to decrement %u\n",
                        CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv), size);

    return (EC_TRUE);
}

EC_BOOL cmcpgv_is_full(const CMCPGV *cmcpgv)
{
    if(CMCPGV_PAGE_USED_NUM(cmcpgv) == CMCPGV_PAGE_MAX_NUM(cmcpgv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcpgv_is_empty(const CMCPGV *cmcpgv)
{
    if(0 == CMCPGV_PAGE_USED_NUM(cmcpgv) && 0 < CMCPGV_PAGE_MAX_NUM(cmcpgv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cmcpgv_check(const CMCPGV *cmcpgv)
{
    uint16_t  pgv_assign_bitmap;
    uint16_t  pgd_assign_bitmap;/*all pgd's bitmap*/
    uint16_t  disk_no;
    uint16_t  disk_num;

    uint64_t  pgv_actual_used_size;
    uint64_t  pgd_actual_used_size;/*all pgd's used size*/

    uint64_t  pgv_page_max_num;
    uint64_t  pgd_page_max_num;/*all pgd's page max num*/

    uint64_t  pgv_page_used_num;
    uint64_t  pgd_page_used_num;/*all pgd's page used num*/

    pgv_assign_bitmap    = CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv);
    pgv_actual_used_size = CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv);
    pgv_page_max_num     = CMCPGV_PAGE_MAX_NUM(cmcpgv);
    pgv_page_used_num    = CMCPGV_PAGE_USED_NUM(cmcpgv);

    pgd_assign_bitmap    = 0;
    pgd_actual_used_size = 0;
    pgd_page_max_num     = 0;
    pgd_page_used_num    = 0;

    for(disk_no = 0, disk_num = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CMCPGV_DISK_NODE(cmcpgv, disk_no))
        {
            disk_num ++;
        }
    }

    if(disk_num != CMCPGV_PAGE_DISK_NUM(cmcpgv))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_check: inconsistent disk_num: counted disk num = %u, CMCPGV_PAGE_DISK_NUM = %u\n",
                           disk_num, CMCPGV_PAGE_DISK_NUM(cmcpgv));
        return (EC_FALSE);
    }

    for(disk_no = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CMCPGV_DISK_NODE(cmcpgv, disk_no))
        {
            pgd_assign_bitmap    |= CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(CMCPGV_DISK_NODE(cmcpgv, disk_no));
            pgd_actual_used_size += CMCPGD_PAGE_ACTUAL_USED_SIZE(CMCPGV_DISK_NODE(cmcpgv, disk_no));
            pgd_page_max_num     += CMCPGD_PAGE_MAX_NUM(CMCPGV_DISK_NODE(cmcpgv, disk_no));
            pgd_page_used_num    += CMCPGD_PAGE_USED_NUM(CMCPGV_DISK_NODE(cmcpgv, disk_no));
        }
    }

    if(pgv_assign_bitmap != pgd_assign_bitmap)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_check: inconsistent bitmap: pgv_assign_bitmap = %s, pgd_assign_bitmap = %s\n",
                           c_uint16_t_to_bin_str(pgv_assign_bitmap), c_uint16_t_to_bin_str(pgd_assign_bitmap));
        return (EC_FALSE);
    }

    if(pgv_actual_used_size != pgd_actual_used_size)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_check: inconsistent actual used size: pgv_actual_used_size = %"PRId64", pgd_actual_used_size = %"PRId64"\n",
                            pgv_actual_used_size, pgd_actual_used_size);
        return (EC_FALSE);
    }

    if(pgv_page_max_num != pgd_page_max_num)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_check: inconsistent page max num: pgv_page_max_num = %"PRId64", pgd_page_max_num = %"PRId64"\n",
                            pgv_page_max_num, pgd_page_max_num);
        return (EC_FALSE);
    }

    if(pgv_page_used_num != pgd_page_used_num)
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_check: inconsistent page used num: pgv_page_used_num = %"PRId64", pgd_page_used_num = %"PRId64"\n",
                            pgv_page_used_num, pgd_page_used_num);
        return (EC_FALSE);
    }

    /*check block table*/
    for(disk_no = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CMCPGV_DISK_NODE(cmcpgv, disk_no))
        {
            if(EC_FALSE == cmcpgd_check(CMCPGV_DISK_NODE(cmcpgv, disk_no)))
            {
                dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_check: check CMCPGV_DISK_NODE of disk_no %u failed\n", disk_no);
                return (EC_FALSE);
            }
        }
    }
    dbg_log(SEC_0105_CMCPGV, 5)(LOGSTDOUT, "cmcpgv_check: cmcpgv %p check passed\n", cmcpgv);
    return (EC_TRUE);
}

void cmcpgv_print(LOG *log, const CMCPGV *cmcpgv)
{
    uint16_t  page_model;
    char     *page_desc;
    REAL      used_size;
    REAL      occupied_size;
    REAL      ratio_size;

    REAL      ratio_page;

    CMCPGV_ASSERT(NULL_PTR != cmcpgv);

    //cmcpgrb_pool_print(log, CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv));
    if(0)
    {
        for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
        {
            sys_log(log, "cmcpgv_print: page_model %u, block root_pos %u\n",
                          page_model,
                          CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model));
            cmcpgrb_tree_print(log, CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv), CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv, page_model));
            sys_log(log, "----------------------------------------------------------\n");
        }
    }

    used_size     = (0.0 + CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv));
    occupied_size = (0.0 + (((uint64_t)CMCPGV_PAGE_USED_NUM(cmcpgv)) << CMCPGB_PAGE_BIT_SIZE));
    ratio_size    = (EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size));

    ratio_page    = ((0.0 + CMCPGV_PAGE_USED_NUM(cmcpgv)) / (0.0 + CMCPGV_PAGE_MAX_NUM(cmcpgv)));

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

    sys_log(log, "cmcpgv_print: cmcpgv %p, disk num %u, %s, page max num %"PRId64", page used num %"PRId64", page ratio %.2f, used size %"PRId64", size ratio %.2f\n",
                 cmcpgv,
                 CMCPGV_PAGE_DISK_NUM(cmcpgv),
                 page_desc,
                 CMCPGV_PAGE_MAX_NUM(cmcpgv),
                 CMCPGV_PAGE_USED_NUM(cmcpgv),
                 ratio_page,
                 CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv),
                 ratio_size
                 );

    sys_log(log, "cmcpgv_print: cmcpgv %p, assign bitmap %s \n",
                 cmcpgv,
                 c_uint16_t_to_bin_str(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv))
                 );

    if(0)
    {
        for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++)
        {
            if(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv) & (1 << page_model))
            {
                sys_log(log, "cmcpgv_print: cmcpgv %p, model %u has page to assign\n", cmcpgv, page_model);
            }
            else
            {
                sys_log(log, "cmcpgv_print: cmcpgv %p, model %u no  page to assign\n", cmcpgv, page_model);
            }
        }
    }

    if(1)
    {
        uint16_t  disk_no;
        for(disk_no = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CMCPGV_DISK_NODE(cmcpgv, disk_no))
            {
                sys_log(log, "cmcpgv_print: disk %u is\n", disk_no);
                cmcpgd_print(log, CMCPGV_DISK_NODE(cmcpgv, disk_no));
            }
        }
    }

    return;
}

/* ---- debug ---- */
EC_BOOL cmcpgv_debug_cmp(const CMCPGV *cmcpgv_1st, const CMCPGV *cmcpgv_2nd)
{
    uint16_t page_model;
    uint16_t disk_no;

    /*cpgrb pool*/
    if(EC_FALSE == cmcpgrb_debug_cmp(CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv_1st), CMCPGV_PAGE_DISK_CMCPGRB_POOL(cmcpgv_2nd)))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent cpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CMCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv_1st, page_model);
        root_pos_2nd = CMCPGV_PAGE_MODEL_DISK_CMCPGRB_ROOT_POS(cmcpgv_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*assign bitmap*/
    if(CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv_1st) != CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv_1st))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv_1st), CMCPGV_PAGE_MODEL_ASSIGN_BITMAP(cmcpgv_2nd));
        return (EC_FALSE);
    }

    /*dis num*/
    if(CMCPGV_PAGE_DISK_NUM(cmcpgv_1st) != CMCPGV_PAGE_DISK_NUM(cmcpgv_1st))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_PAGE_DISK_NUM: %u != %u\n",
                            CMCPGV_PAGE_DISK_NUM(cmcpgv_1st), CMCPGV_PAGE_DISK_NUM(cmcpgv_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CMCPGV_PAGE_MAX_NUM(cmcpgv_1st) != CMCPGV_PAGE_MAX_NUM(cmcpgv_1st))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_PAGE_MAX_NUM: %"PRId64" != %"PRId64"\n",
                            CMCPGV_PAGE_MAX_NUM(cmcpgv_1st), CMCPGV_PAGE_MAX_NUM(cmcpgv_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CMCPGV_PAGE_USED_NUM(cmcpgv_1st) != CMCPGV_PAGE_USED_NUM(cmcpgv_1st))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_PAGE_USED_NUM: %"PRId64" != %"PRId64"\n",
                            CMCPGV_PAGE_USED_NUM(cmcpgv_1st), CMCPGV_PAGE_USED_NUM(cmcpgv_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv_1st) != CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv_1st))
    {
        dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_PAGE_ACTUAL_USED_SIZE: %"PRId64" != %"PRId64"\n",
                            CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv_1st), CMCPGV_PAGE_ACTUAL_USED_SIZE(cmcpgv_2nd));
        return (EC_FALSE);
    }

    /*cmcpgd*/
    for(disk_no = 0; disk_no < CMCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR == CMCPGV_DISK_NODE(cmcpgv_1st, disk_no) && NULL_PTR != CMCPGV_DISK_NODE(cmcpgv_2nd, disk_no))
        {
            dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_DISK_NODE at disk_no %u: 1st is null but 2nd is not null\n", disk_no);
            return (EC_FALSE);
        }

        if(NULL_PTR != CMCPGV_DISK_NODE(cmcpgv_1st, disk_no) && NULL_PTR == CMCPGV_DISK_NODE(cmcpgv_2nd, disk_no))
        {
            dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_DISK_NODE at disk_no %u: 1st is not null but 2nd is null\n", disk_no);
            return (EC_FALSE);
        }

        if(NULL_PTR == CMCPGV_DISK_NODE(cmcpgv_1st, disk_no) && NULL_PTR == CMCPGV_DISK_NODE(cmcpgv_2nd, disk_no))
        {
            continue;
        }

        if(EC_FALSE == cmcpgd_debug_cmp(CMCPGV_DISK_NODE(cmcpgv_1st, disk_no), CMCPGV_DISK_NODE(cmcpgv_2nd, disk_no)))
        {
            dbg_log(SEC_0105_CMCPGV, 0)(LOGSTDOUT, "error:cmcpgv_debug_cmp: inconsistent CMCPGV_DISK_NODE at disk_no %u\n", disk_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

