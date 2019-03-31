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

#include "db_internal.h"

#include "cxfscfg.h"
#include "cxfspgrb.h"
#include "cxfspgd.h"
#include "cxfspgv.h"

/*page-cache disk:1TB = 2^14 page-cache block*/

/************************************************************************************************
  comment:
  ========
   1. if one block can assign max pages with page model, then put the block into page model
      RB tree of disk
   2. one block was in at most one RB tree
************************************************************************************************/

#if (SWITCH_ON == CXFS_ASSERT_SWITCH)
#define CXFSPGV_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CXFS_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CXFS_ASSERT_SWITCH)
#define CXFSPGV_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CXFS_ASSERT_SWITCH)*/

STATIC_CAST static uint16_t __cxfspgv_page_model_first_disk(const CXFSPGV *cxfspgv, const uint16_t page_model)
{
    uint16_t node_pos;
    const CXFSPGRB_NODE *node;

    node_pos = cxfspgrb_tree_first_node(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model));
    if(CXFSPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_page_model_first_disk: no free page in page model %u\n", page_model);
        return (CXFSPGRB_ERR_POS);
    }

    node = CXFSPGRB_POOL_NODE(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), node_pos);
    return (CXFSPGRB_NODE_DATA(node));
}

STATIC_CAST static uint16_t __cxfspgv_page_model_get(const CXFSPGV *cxfspgv, const uint16_t assign_bitmap)
{
    uint16_t page_model;
    uint16_t e;

    for(page_model = 0, e = 1; CXFSPGB_MODEL_NUM > page_model && 0 == (assign_bitmap & e); page_model ++, e <<= 1)
    {
      /*do nothing*/
    }
    return (page_model);
}

CXFSPGV_HDR *cxfspgv_hdr_create(CXFSPGV *cxfspgv)
{
    CXFSPGV_HDR *cxfspgv_hdr;

    cxfspgv_hdr = (CXFSPGV_HDR *)CXFSPGV_CACHE(cxfspgv);

    CXFSPGV_HEADER(cxfspgv) = cxfspgv_hdr;

    if(EC_FALSE == cxfspgv_hdr_init(cxfspgv))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_hdr_create: init cxfspgv failed\n");
        CXFSPGV_HEADER(cxfspgv) = NULL_PTR;
        return (NULL_PTR);
    }

    //CXFSPGV_HDR_DISK_NUM(cxfspgv_hdr)      = 0;
    CXFSPGV_HDR_DISK_MAX_NUM(cxfspgv_hdr)  = 0;

    return (cxfspgv_hdr);
}

EC_BOOL cxfspgv_hdr_init(CXFSPGV *cxfspgv)
{
    CXFSPGV_HDR *cxfspgv_hdr;
    uint16_t  page_model;

    cxfspgv_hdr = CXFSPGV_HEADER(cxfspgv);
    if(EC_FALSE == cxfspgrb_pool_init(CXFSPGV_HDR_CXFSPGRB_POOL(cxfspgv_hdr), CXFSPGV_MAX_DISK_NUM))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_hdr_init: init cxfspgrb pool failed where disk_num = %u\n", CXFSPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    for(page_model = 0; CXFSPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CXFSPGV_HDR_DISK_CXFSPGRB_ROOT_POS(cxfspgv_hdr, page_model) = CXFSPGRB_ERR_POS;
    }

    CXFSPGV_HDR_ASSIGN_BITMAP(cxfspgv_hdr) = 0;

    CXFSPGV_HDR_DISK_NUM(cxfspgv_hdr)      = 0;
    /*CXFSPGV_HDR_DISK_MAX_NUM(cxfspgv_hdr)  = 0;*/

    /*statistics*/
    CXFSPGV_HDR_PAGE_MAX_NUM(cxfspgv_hdr)          = 0;
    CXFSPGV_HDR_PAGE_USED_NUM(cxfspgv_hdr)         = 0;
    CXFSPGV_HDR_PAGE_ACTUAL_USED_SIZE(cxfspgv_hdr) = 0;

    return (EC_TRUE);
}

CXFSPGV_HDR *cxfspgv_hdr_open(CXFSPGV *cxfspgv, UINT8 *base, const UINT32 offset, const UINT32 size)
{
    CXFSPGV_CACHE(cxfspgv)  = base;
    CXFSPGV_OFFSET(cxfspgv) = offset;
    CXFSPGV_FSIZE(cxfspgv)  = size;

    return ((CXFSPGV_HDR *)CXFSPGV_CACHE(cxfspgv));
}

void cxfspgv_hdr_print(LOG *log, const CXFSPGV_HDR *cxfspgv_hdr)
{
    if(NULL_PTR != cxfspgv_hdr)
    {
        sys_log(log, "[DEBUG] cxfspgv_hdr_print: "
                     "cxfspgv_hdr %p, assign bitmap %u, disk num %u, disk max num %u\n",
                     cxfspgv_hdr,
                     CXFSPGV_HDR_ASSIGN_BITMAP(cxfspgv_hdr),
                     CXFSPGV_HDR_DISK_NUM(cxfspgv_hdr),
                     CXFSPGV_HDR_DISK_MAX_NUM(cxfspgv_hdr));

        sys_log(log, "[DEBUG] cxfspgv_hdr_print: "
                     "cxfspgv_hdr %p, page max num %lu, page used num %lu, actual used size %lu\n",
                     cxfspgv_hdr,
                     CXFSPGV_HDR_PAGE_MAX_NUM(cxfspgv_hdr),
                     CXFSPGV_HDR_PAGE_USED_NUM(cxfspgv_hdr),
                     CXFSPGV_HDR_PAGE_ACTUAL_USED_SIZE(cxfspgv_hdr));
    }

    return;
}

CXFSPGV *cxfspgv_new(UINT8 *base, const UINT32 size, const uint16_t disk_max_num)
{
    CXFSPGV      *cxfspgv;
    CXFSPGV_HDR  *cxfspgv_hdr;

    alloc_static_mem(MM_CXFSPGV, &cxfspgv, LOC_CXFSPGV_0001);
    if(NULL_PTR == cxfspgv)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_new: malloc cxfspgv failed\n");
        return (NULL_PTR);
    }

    cxfspgv_init(cxfspgv);

    CXFSPGV_CACHE(cxfspgv)        = base;
    CXFSPGV_FSIZE(cxfspgv)        = size;

    cxfspgv_hdr = cxfspgv_hdr_create(cxfspgv);
    if(NULL_PTR == cxfspgv_hdr)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_new: new cxfspgv header failed\n");
        cxfspgv_free(cxfspgv);
        return (NULL_PTR);
    }
    CXFSPGV_HDR_DISK_MAX_NUM(cxfspgv_hdr) = disk_max_num;

    CXFSPGV_HEADER(cxfspgv) = cxfspgv_hdr;

    return (cxfspgv);
}

EC_BOOL cxfspgv_free(CXFSPGV *cxfspgv)
{
    if(NULL_PTR != cxfspgv)
    {
        uint16_t disk_no;

        /*clean disks*/
        for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no))
            {
                cxfspgd_free(CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no));
                CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = NULL_PTR;
            }
        }

        CXFSPGV_HEADER(cxfspgv) = NULL_PTR;

        free_static_mem(MM_CXFSPGV, cxfspgv, LOC_CXFSPGV_0002);
    }

    return (EC_TRUE);
}

CXFSPGV *cxfspgv_open(UINT8 *base, const CXFSZONE *cxfszone)
{
    CXFSPGV             *cxfspgv;

    uint16_t             disk_no;
    uint16_t             disk_num;

    alloc_static_mem(MM_CXFSPGV, &cxfspgv, LOC_CXFSPGV_0003);
    if(NULL_PTR == cxfspgv)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_open:"
                                                "malloc cxfspgv failed\n");
        return (NULL_PTR);
    }

    cxfspgv_init(cxfspgv);

    CXFSPGV_CACHE(cxfspgv)  = base;
    CXFSPGV_OFFSET(cxfspgv) = CXFSZONE_S_OFFSET(cxfszone);
    CXFSPGV_FSIZE(cxfspgv)  = CXFSZONE_E_OFFSET(cxfszone) - CXFSZONE_S_OFFSET(cxfszone);
    CXFSPGV_HEADER(cxfspgv) = ((CXFSPGV_HDR *)CXFSPGV_CACHE(cxfspgv));

    if(do_log(SEC_0203_CXFSPGV, 0))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "[DEBUG] cxfspgv_open: cxfspgv header is\n");
        cxfspgv_hdr_print(LOGSTDOUT, CXFSPGV_HEADER(cxfspgv));
    }

    disk_num = CXFSPGV_DISK_NUM(cxfspgv);

    dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "[DEBUG] cxfspgv_open: [1] "
                                            "disk num %u, disk max num %u\n",
                                            CXFSPGV_DISK_NUM(cxfspgv),
                                            CXFSPGV_DISK_MAX_NUM(cxfspgv));

    if(CXFSPGV_MAX_DISK_NUM <= CXFSPGV_DISK_MAX_NUM(cxfspgv))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_open: "
                                                "disk max num %u >= %u => overflow\n",
                                                CXFSPGV_DISK_MAX_NUM(cxfspgv),
                                                CXFSPGV_MAX_DISK_NUM);
        cxfspgv_close(cxfspgv);
        return (NULL_PTR);
    }

    if(CXFSPGV_DISK_NUM(cxfspgv) > CXFSPGV_DISK_MAX_NUM(cxfspgv))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_open: "
                                                "disk num %u > disk max num %u => invalid\n",
                                                CXFSPGV_DISK_NUM(cxfspgv),
                                                CXFSPGV_DISK_MAX_NUM(cxfspgv));
        cxfspgv_close(cxfspgv);
        return (NULL_PTR);
    }

    /*cleanup everything but not disk max num*/
    if(EC_FALSE == cxfspgv_hdr_init(cxfspgv))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_open: "
                                                "init cxfspgv header failed\n");
        cxfspgv_close(cxfspgv);
        return (NULL_PTR);
    }

    dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "[DEBUG] cxfspgv_open: [2] "
                                            "disk num %u, disk max num %u\n",
                                            CXFSPGV_DISK_NUM(cxfspgv),
                                            CXFSPGV_DISK_MAX_NUM(cxfspgv));

    /*mount disks*/
    for(disk_no = 0; disk_no < disk_num; disk_no ++)
    {
        /*try to mount the disk. ignore any failure*/
        cxfspgv_mount_disk(cxfspgv, disk_no);
    }

    return (cxfspgv);
}

EC_BOOL cxfspgv_close(CXFSPGV *cxfspgv)
{
    if(NULL_PTR != cxfspgv)
    {
        uint16_t disk_no;

        /*clean disks*/
        for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no))
            {
                cxfspgd_close(CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no));
                CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = NULL_PTR;
            }
        }

        CXFSPGV_CACHE(cxfspgv)  = NULL_PTR;
        CXFSPGV_HEADER(cxfspgv) = NULL_PTR;
        CXFSPGV_FSIZE(cxfspgv)  = 0;
        CXFSPGV_OFFSET(cxfspgv) = 0;

        free_static_mem(MM_CXFSPGV, cxfspgv, LOC_CXFSPGV_0004);
    }
    return (EC_TRUE);
}

EC_BOOL cxfspgv_init(CXFSPGV *cxfspgv)
{
    uint16_t disk_no;

    CXFSPGV_OFFSET(cxfspgv)= 0;
    CXFSPGV_FSIZE(cxfspgv) = 0;
    CXFSPGV_CACHE(cxfspgv) = NULL_PTR;
    CXFSPGV_HEADER(cxfspgv)= NULL_PTR;

    for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
    {
        CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cxfspgv_clean(CXFSPGV *cxfspgv)
{
    uint16_t disk_no;

    CXFSPGV_OFFSET(cxfspgv)= 0;
    CXFSPGV_FSIZE(cxfspgv) = 0;
    CXFSPGV_CACHE(cxfspgv) = NULL_PTR;
    CXFSPGV_HEADER(cxfspgv)= NULL_PTR;

    for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
    {
        CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = NULL_PTR;
    }
    return (EC_TRUE);
}

/*add one free disk into pool*/
STATIC_CAST static EC_BOOL __cxfspgv_add_disk(CXFSPGV *cxfspgv, const uint16_t disk_no, const uint16_t page_model)
{
    if(CXFSPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:__cxfspgv_add_disk: disk_no %u overflow where disk max num is %u\n", disk_no, CXFSPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    /*insert disk_no to rbtree*/
    if(CXFSPGRB_ERR_POS == cxfspgrb_tree_insert_data(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), &(CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model)), disk_no))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_add_disk: add disk_no %u to rbtree of page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv) |= (uint16_t)(~((1 << page_model) - 1)) & CXFSPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free disk from pool*/
STATIC_CAST static EC_BOOL __cxfspgv_del_disk(CXFSPGV *cxfspgv, const uint16_t disk_no, const uint16_t page_model)
{
    /*del disk_no from rbtree*/
    if(EC_FALSE == cxfspgrb_tree_delete_data(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), &(CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model)), disk_no))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_del_disk: del disk_no %u from rbtree of page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CXFSPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model_t))/*this page-model is empty*/
        )
        {
            CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cxfspgv_assign_disk(CXFSPGV *cxfspgv, uint16_t *page_model, uint16_t *disk_no)
{
    uint16_t disk_no_t;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv) & mask))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_assign_disk: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv), mask);
        return (EC_FALSE);
    }

    while(CXFSPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CXFSPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_assign_disk: no free disk available from page model %u\n", *page_model);
        return (EC_FALSE);
    }

    disk_no_t = __cxfspgv_page_model_first_disk(cxfspgv, page_model_t);
    if(CXFSPGRB_ERR_POS == disk_no_t)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_assign_disk: no free disk in page model %u\n", page_model_t);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;
    (*disk_no)    = disk_no_t;

    return (EC_TRUE);
}

EC_BOOL cxfspgv_add_disk(CXFSPGV *cxfspgv, const uint16_t disk_no)
{
    CXFSPGD *cxfspgd;
    UINT8   *base;
    UINT32   offset;

    if(CXFSPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_add_disk: "
                                                "disk %u overflow the max disk num %u\n",
                                                disk_no, CXFSPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    if(CXFSPGV_DISK_MAX_NUM(cxfspgv) <= disk_no)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_add_disk: "
                                                "disk %u >= supported max disk num %u\n",
                                                disk_no, CXFSPGV_DISK_MAX_NUM(cxfspgv));
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_add_disk: "
                                                "disk %u already exist\n",
                                                disk_no);
        return (EC_FALSE);
    }

    offset = ((UINT32)CXFSPGV_HDR_SIZE) + cxfspgd_size(CXFSPGD_MAX_BLOCK_NUM) * ((UINT32)disk_no);
    base   = CXFSPGV_CACHE(cxfspgv) + offset;

    dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "[DEBUG] cxfspgv_add_disk: "
                                            "disk %u, offset %ld\n",
                                            disk_no, offset);

    cxfspgd = cxfspgd_new(base, CXFSPGD_MAX_BLOCK_NUM);
    if(NULL_PTR == cxfspgd)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_add_disk: "
                                                "create disk %u failed\n",
                                                disk_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0203_CXFSPGV, 3)(LOGSTDOUT, "info:cxfspgv_add_disk: "
                                            "create disk %u done\n",
                                            disk_no);

    /*add disk to volume*/
    CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = cxfspgd;
    CXFSPGV_DISK_NUM(cxfspgv) ++;

    /*statistics*/
    CXFSPGV_PAGE_MAX_NUM(cxfspgv)          += ((uint64_t)1) * CXFSPGD_MAX_BLOCK_NUM * CXFSPGD_BLOCK_PAGE_NUM;
    CXFSPGV_PAGE_USED_NUM(cxfspgv)         += 0;
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) += 0;

    /*add one free disk into pool*/
    return __cxfspgv_add_disk(cxfspgv, disk_no, CXFSPGD_BLOCK_PAGE_MODEL);
}

EC_BOOL cxfspgv_del_disk(CXFSPGV *cxfspgv, const uint16_t disk_no)
{
    CXFSPGD    *cxfspgd;
    uint16_t page_model;

    if(CXFSPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_del_disk: "
                                                "disk %u overflow the max disk num %u\n",
                                                disk_no, CXFSPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    cxfspgd = CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no);
    if(NULL_PTR == cxfspgd)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_del_disk: "
                                                "disk %u not exist\n",
                                                disk_no);
        return (EC_FALSE);
    }

    page_model = cxfspgd_page_model(cxfspgd);

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_del_disk: "
                                            "disk %u, page_model %u\n",
                                            disk_no, page_model);

    /*delete the disk from pool*/
    if(EC_FALSE == __cxfspgv_del_disk(cxfspgv, disk_no, page_model))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_del_disk: "
                                                "del disk %u, page model %u failed\n",
                                                disk_no, page_model);
        return (EC_FALSE);
    }

    /*adjust cxfspgv statistics*/
    CXFSPGV_DISK_NUM(cxfspgv) --;
    CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = NULL_PTR;

    /*statistics*/
    CXFSPGV_PAGE_MAX_NUM(cxfspgv)          -= ((uint64_t)1) * CXFSPGD_MAX_BLOCK_NUM * CXFSPGD_BLOCK_PAGE_NUM;;
    CXFSPGV_PAGE_USED_NUM(cxfspgv)         -= CXFSPGD_PAGE_USED_NUM(cxfspgd);
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) -= CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd);

    cxfspgd_close(cxfspgd);

    return (EC_TRUE);
}

EC_BOOL cxfspgv_mount_disk(CXFSPGV *cxfspgv, const uint16_t disk_no)
{
    CXFSPGD    *cxfspgd;
    UINT8      *base;
    UINT32      offset;
    uint16_t    page_model;

    if(CXFSPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_mount_disk: "
                                                "disk %u overflow the max disk num %u\n",
                                                disk_no, CXFSPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    if(CXFSPGV_DISK_MAX_NUM(cxfspgv) <= disk_no)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_mount_disk: "
                                                "disk %u >= supported max disk num %u\n",
                                                disk_no, CXFSPGV_DISK_MAX_NUM(cxfspgv));
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_mount_disk: "
                                                "disk %u already exist\n",
                                                disk_no);
        return (EC_FALSE);
    }

    offset = ((UINT32)CXFSPGV_HDR_SIZE) + cxfspgd_size(CXFSPGD_MAX_BLOCK_NUM) * ((UINT32)disk_no);
    base   = CXFSPGV_CACHE(cxfspgv) + offset;

    dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "[DEBUG] cxfspgv_mount_disk: "
                                            "disk %u, offset %ld\n",
                                            disk_no, offset);

    cxfspgd = cxfspgd_open(base, CXFSPGD_HDR_SIZE);
    if(NULL_PTR == cxfspgd)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_mount_disk: "
                                                "open disk %u failed\n",
                                                disk_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0203_CXFSPGV, 3)(LOGSTDOUT, "[DEBUG] cxfspgv_mount_disk: "
                                            "open disk %u done\n",
                                            disk_no);

    /*add disk to volume*/
    CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = cxfspgd;
    CXFSPGV_DISK_NUM(cxfspgv) ++;

    /*statistics*/
    CXFSPGV_PAGE_MAX_NUM(cxfspgv)          += CXFSPGD_PAGE_MAX_NUM(cxfspgd);
    CXFSPGV_PAGE_USED_NUM(cxfspgv)         += CXFSPGD_PAGE_USED_NUM(cxfspgd);
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) += CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd);

    page_model = cxfspgd_page_model(cxfspgd);

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_mount_disk: "
                                            "disk %u, page_model %u\n",
                                             disk_no, page_model);

    /*add one free disk into pool*/
    return __cxfspgv_add_disk(cxfspgv, disk_no, page_model);
}

EC_BOOL cxfspgv_umount_disk(CXFSPGV *cxfspgv, const uint16_t disk_no)
{
    CXFSPGD    *cxfspgd;
    uint16_t page_model;

    if(CXFSPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_umount_disk: "
                                                "disk %u overflow the max disk num %u\n",
                                                disk_no, CXFSPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    cxfspgd = CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no);
    if(NULL_PTR == cxfspgd)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_umount_disk: "
                                                "disk %u not exist\n",
                                                disk_no);
        return (EC_FALSE);
    }

    page_model = cxfspgd_page_model(cxfspgd);

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_umount_disk: "
                                            "disk %u, page_model %u\n",
                                            disk_no, page_model);

    /*delete the disk from pool*/
    if(EC_FALSE == __cxfspgv_del_disk(cxfspgv, disk_no, page_model))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_umount_disk: "
                                                "del disk %u, page model %u failed\n",
                                                disk_no, page_model);
        return (EC_FALSE);
    }

    /*adjust cxfspgv statistics*/
    CXFSPGV_DISK_NUM(cxfspgv) --;
    CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no) = NULL_PTR;

    /*statistics*/
    CXFSPGV_PAGE_MAX_NUM(cxfspgv)          -= CXFSPGD_PAGE_MAX_NUM(cxfspgd);
    CXFSPGV_PAGE_USED_NUM(cxfspgv)         -= CXFSPGD_PAGE_USED_NUM(cxfspgd);
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) -= CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd);

    cxfspgd_close(cxfspgd);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfspgv_size_to_page_model(const uint32_t size, uint16_t *page_num, uint16_t *page_model)
{
    uint16_t page_num_need;
    uint16_t page_model_t;
    uint16_t e;
    uint16_t t;

    page_num_need = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);
    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDNULL, "[DEBUG] __cxfspgv_size_to_page_model: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CXFSPGV_ASSERT(CXFSPGB_064MB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CXFSPGB_PAGE_HI_BIT_MASK;
    for(t = page_num_need, page_model_t = 0/*CXFSPGB_064MB_MODEL*/; 0 == (t & e); t <<= 1, page_model_t ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDNULL, "[DEBUG] __cxfspgv_size_to_page_model: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n",
                        t, page_model_t, e, (t << 1));

    if(CXFSPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model_t --;/*upgrade page_model one level*/
    }

    (*page_num)   = page_num_need;
    (*page_model) = page_model_t;

    return (EC_TRUE);
}

EC_BOOL cxfspgv_new_space_from_disk(CXFSPGV *cxfspgv, const uint32_t size, const uint16_t disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CXFSPGD    *cxfspgd;

    uint16_t page_num_need;
    uint16_t page_model;
    uint16_t page_model_t;

    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t disk_no_t;
    uint16_t block_no_t;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CXFSPGV_ASSERT(0 < size);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_new_space_from_disk: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    __cxfspgv_size_to_page_model(size, &page_num_need, &page_model);

    //dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: size = %u ==> page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   size, page_num_need, page_model, (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model)));

    disk_no_t = disk_no;

    cxfspgd = CXFSPGV_DISK_NODE(cxfspgv, disk_no_t);
    pgd_assign_bitmap_old = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

    if(EC_FALSE == cxfspgd_new_space(cxfspgd, size, &block_no_t, &page_no_t))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_new_space_from_disk: assign size %u from disk %u failed\n", size, disk_no);
        return (EC_FALSE);
    }

    pgd_assign_bitmap_new = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

    //dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: disk_no_t %u: pgd bitmap %x => %x\n", disk_no_t, pgd_assign_bitmap_old, pgd_assign_bitmap_new);

    /*pgd_assign_bitmap changes may make pgv_assign_bitmap changes*/
    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: before delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                            c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));

        for(page_model_t = page_model, page_model = 0;  page_model < page_model_t; page_model ++)
        {
            if(0 != (pgd_assign_bitmap_old & (uint16_t)(1 << page_model)))
            {
                break;
            }
        }

        /*delete the disk from pool*/
        __cxfspgv_del_disk(cxfspgv, disk_no_t, page_model);

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: after  delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                            c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: disk_no_t %u: max pages %u, used pages %u\n",
                            disk_no_t, CXFSPGD_PAGE_MAX_NUM(cxfspgd), CXFSPGD_PAGE_USED_NUM(cxfspgd));

        if(EC_FALSE == cxfspgd_is_full(cxfspgd))
        {
            //uint16_t page_model_t;

            page_model_t = page_model;
            while(CXFSPGB_MODEL_NUM > page_model_t
               && 0 == (pgd_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CXFSPGV_ASSERT(CXFSPGB_MODEL_NUM > page_model_t);

            dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: page_model %u, page_model_t %u\n", page_model, page_model_t);
            /*add the disk into pool*/
            __cxfspgv_add_disk(cxfspgv, disk_no_t, page_model_t);
            dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                                disk_no_t,
                                c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                                c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CXFSPGV_PAGE_USED_NUM(cxfspgv)         += page_num_need;
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) += size;

    CXFSPGV_ASSERT(EC_TRUE == cxfspgv_check(cxfspgv));

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: pgv_page_used_num %"PRId64" due to increment %u\n",
                        CXFSPGV_PAGE_USED_NUM(cxfspgv), page_num_need);
    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space_from_disk: pgv_actual_used_size %"PRId64" due to increment %u\n",
                        CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv), size);

    return (EC_TRUE);
}

EC_BOOL cxfspgv_new_space(CXFSPGV *cxfspgv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CXFSPGD    *cxfspgd;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t disk_no_t;
    uint16_t block_no_t;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CXFSPGV_ASSERT(0 < size);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    __cxfspgv_size_to_page_model(size, &page_num_need, &page_model);

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: size = %u ==> page_num_need = %u ==> page_model = %u (has %u pages )\n",
                       size, page_num_need, page_model, (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model)));

    for(;;)/*Oops! fix inconsistency between cxfspgv and cxfspgd*/
    {
        uint16_t page_model_t;

        page_model_t = page_model; /*re-arm*/

        if(EC_FALSE == __cxfspgv_assign_disk(cxfspgv, &page_model_t, &disk_no_t))
        {
            dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_new_space: assign one disk from page model %u failed\n", page_model_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: size %u ==> page_model_t %u and disk_no_t %u\n", size, page_model_t, disk_no_t);

        cxfspgd = CXFSPGV_DISK_NODE(cxfspgv, disk_no_t);
        pgd_assign_bitmap_old = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

        if(EC_TRUE == cxfspgd_new_space(cxfspgd, size, &block_no_t, &page_no_t))
        {
            page_model = page_model_t;
            break;
        }

        /*find inconsistent, fix it!*/

        /*delete the disk from pool*/
        __cxfspgv_del_disk(cxfspgv, disk_no_t, page_model_t);

        while(CXFSPGB_MODEL_NUM > page_model_t
           && 0 == (pgd_assign_bitmap_old & (uint16_t)(1 << page_model_t))
           )
        {
             page_model_t ++;
        }

        CXFSPGV_ASSERT(CXFSPGB_MODEL_NUM > page_model_t);

        /*add the disk into pool*/
        __cxfspgv_add_disk(cxfspgv, disk_no_t, page_model_t);

        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "warn:cxfspgv_new_space: disk %u model %u relocation to page model %u\n", disk_no_t, page_model_t, page_model_t);
    }

    pgd_assign_bitmap_new = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: disk_no_t %u: pgd bitmap %x => %x\n", disk_no_t, pgd_assign_bitmap_old, pgd_assign_bitmap_new);

    /*pgd_assign_bitmap changes may make pgv_assign_bitmap changes*/
    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: before delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                            c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));

        /*delete the disk from pool*/
        __cxfspgv_del_disk(cxfspgv, disk_no_t, page_model);

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: after  delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                            c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: disk_no_t %u: max pages %u, used pages %u\n",
                            disk_no_t, CXFSPGD_PAGE_MAX_NUM(cxfspgd), CXFSPGD_PAGE_USED_NUM(cxfspgd));

        if(EC_FALSE == cxfspgd_is_full(cxfspgd))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CXFSPGB_MODEL_NUM > page_model_t
               && 0 == (pgd_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CXFSPGV_ASSERT(CXFSPGB_MODEL_NUM > page_model_t);

            dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            /*add the disk into pool*/
            __cxfspgv_add_disk(cxfspgv, disk_no_t, page_model_t);
            dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                                disk_no_t,
                                c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                                c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*disk_no)  = disk_no_t;
    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CXFSPGV_PAGE_USED_NUM(cxfspgv)         += page_num_need;
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) += size;

    CXFSPGV_ASSERT(EC_TRUE == cxfspgv_check(cxfspgv));

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: pgv_page_used_num %"PRId64" due to increment %u\n",
                        CXFSPGV_PAGE_USED_NUM(cxfspgv), page_num_need);
    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_new_space: pgv_actual_used_size %"PRId64" due to increment %u\n",
                        CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv), size);

    return (EC_TRUE);
}

EC_BOOL cxfspgv_free_space(CXFSPGV *cxfspgv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    CXFSPGD    *cxfspgd;

    uint16_t page_num_used;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CXFSPGV_ASSERT(0 < size);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    cxfspgd = CXFSPGV_DISK_NODE(cxfspgv, disk_no);
    pgd_assign_bitmap_old = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

    if(EC_FALSE == cxfspgd_free_space(cxfspgd, block_no, page_no, size))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_free_space: disk_no %u free space of block_no %u, page_no %u, size %u failed\n",
                           disk_no, block_no, page_no, size);
        return (EC_FALSE);
    }

    pgd_assign_bitmap_new = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        uint16_t page_model_old;
        uint16_t page_model_new;

        page_model_old = __cxfspgv_page_model_get(cxfspgv, pgd_assign_bitmap_old);
        page_model_new = __cxfspgv_page_model_get(cxfspgv, pgd_assign_bitmap_new);

        if(CXFSPGB_MODEL_NUM > page_model_old)
        {
            __cxfspgv_del_disk(cxfspgv, disk_no, page_model_old);
        }
        __cxfspgv_add_disk(cxfspgv, disk_no, page_model_new);
    }

    page_num_used = (uint16_t)((size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE);

    CXFSPGV_PAGE_USED_NUM(cxfspgv)         -= page_num_used;
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) -= size;

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_free_space: pgv_page_used_num %"PRId64" due to decrement %u\n",
                        CXFSPGV_PAGE_USED_NUM(cxfspgv), page_num_used);
    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_free_space: pgv_actual_used_size %"PRId64" due to decrement %u\n",
                        CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv), size);

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cxfspgv_extract_disk(CXFSPGV *cxfspgv, uint16_t *page_model, const uint16_t disk_no)
{
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv) & mask))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_extract_disk: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv), mask);
        return (EC_FALSE);
    }

    while(CXFSPGB_MODEL_NUM > page_model_t
       && (EC_TRUE == cxfspgrb_tree_is_empty(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model_t))
       || CXFSPGRB_ERR_POS == cxfspgrb_tree_search_data(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model_t), disk_no))
       )
    {
        page_model_t --;
    }

    if(CXFSPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:__cxfspgv_extract_disk: no free disk %u\n", disk_no);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;

    return (EC_TRUE);
}

EC_BOOL cxfspgv_reserve_space(CXFSPGV *cxfspgv, const uint32_t size, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no)
{
    CXFSPGD    *cxfspgd;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CXFSPGV_ASSERT(0 < size);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < size)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_reserve_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    __cxfspgv_size_to_page_model(size, &page_num_need, &page_model);

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: size = %u ==> page_num_need = %u ==> page_model = %u (has %u pages )\n",
                       size, page_num_need, page_model, (uint16_t)(1 << (CXFSPGB_MODEL_NUM - 1 - page_model)));

    if(1)
    {
        uint16_t page_model_t;

        page_model_t = page_model; /*re-arm*/

        if(EC_FALSE == __cxfspgv_extract_disk(cxfspgv, &page_model_t, disk_no))
        {
            dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_reserve_space: extract disk %u from page model %u failed\n", disk_no, page_model_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: size %u ==> page_model_t %u and disk_no_t %u\n", size, page_model_t, disk_no);

        cxfspgd = CXFSPGV_DISK_NODE(cxfspgv, disk_no);
        pgd_assign_bitmap_old = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

        if(EC_FALSE == cxfspgd_reserve_space(cxfspgd, size, block_no, page_no))
        {
            dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_reserve_space: reserve size %u, block %u, page %u from disk %u failed\n", size, block_no, page_no, disk_no);
            return (EC_FALSE);
        }

        page_model = page_model_t;
    }

    pgd_assign_bitmap_new = CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd);

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: disk_no_t %u: pgd bitmap %x => %x\n", disk_no, pgd_assign_bitmap_old, pgd_assign_bitmap_new);

    /*pgd_assign_bitmap changes may make pgv_assign_bitmap changes*/
    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: before delete disk_no %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no,
                            c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                            c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));

        /*delete the disk from pool*/
        __cxfspgv_del_disk(cxfspgv, disk_no, page_model);

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: after  delete disk_no %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no,
                            c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                            c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));

        dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: disk_no %u: max pages %u, used pages %u\n",
                            disk_no, CXFSPGD_PAGE_MAX_NUM(cxfspgd), CXFSPGD_PAGE_USED_NUM(cxfspgd));

        if(EC_FALSE == cxfspgd_is_full(cxfspgd))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CXFSPGB_MODEL_NUM > page_model_t
               && 0 == (pgd_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CXFSPGV_ASSERT(CXFSPGB_MODEL_NUM > page_model_t);

            dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            /*add the disk into pool*/
            __cxfspgv_add_disk(cxfspgv, disk_no, page_model_t);
            dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: disk_no %u: pgb bitmap %s, pgv assign bitmap %s\n",
                                disk_no,
                                c_uint16_t_to_bin_str(CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)),
                                c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)));
        }
        else
        {
            /*do nothing*/
        }
    }

    CXFSPGV_PAGE_USED_NUM(cxfspgv)         += page_num_need;
    CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv) += size;

    CXFSPGV_ASSERT(EC_TRUE == cxfspgv_check(cxfspgv));

    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: pgv_page_used_num %"PRId64" due to increment %u\n",
                        CXFSPGV_PAGE_USED_NUM(cxfspgv), page_num_need);
    dbg_log(SEC_0203_CXFSPGV, 9)(LOGSTDOUT, "[DEBUG] cxfspgv_reserve_space: pgv_actual_used_size %"PRId64" due to increment %u\n",
                        CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv), size);

    return (EC_TRUE);
}

EC_BOOL cxfspgv_release_space(CXFSPGV *cxfspgv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    return cxfspgv_free_space(cxfspgv, disk_no, block_no, page_no, size);
}

EC_BOOL cxfspgv_is_full(const CXFSPGV *cxfspgv)
{
    if(CXFSPGV_PAGE_USED_NUM(cxfspgv) == CXFSPGV_PAGE_MAX_NUM(cxfspgv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cxfspgv_is_empty(const CXFSPGV *cxfspgv)
{
    if(0 == CXFSPGV_PAGE_USED_NUM(cxfspgv) && 0 < CXFSPGV_PAGE_MAX_NUM(cxfspgv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/*vol meta data size*/
UINT32 cxfspgv_size(const uint16_t disk_num)
{
    UINT32      disk_size;
    UINT32      vol_size;

    /*disk meta data size*/
    disk_size = cxfspgd_size(CXFSPGD_MAX_BLOCK_NUM);

    /*vol meta data size*/
    vol_size  = (((UINT32)CXFSPGV_HDR_SIZE) + ((UINT32)disk_num) * (disk_size));

    return (vol_size);
}


EC_BOOL cxfspgv_check(const CXFSPGV *cxfspgv)
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

    pgv_assign_bitmap    = CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv);
    pgv_actual_used_size = CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv);
    pgv_page_max_num     = CXFSPGV_PAGE_MAX_NUM(cxfspgv);
    pgv_page_used_num    = CXFSPGV_PAGE_USED_NUM(cxfspgv);

    pgd_assign_bitmap    = 0;
    pgd_actual_used_size = 0;
    pgd_page_max_num     = 0;
    pgd_page_used_num    = 0;

    for(disk_no = 0, disk_num = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CXFSPGV_DISK_NODE(cxfspgv, disk_no))
        {
            disk_num ++;
        }
    }

    if(disk_num != CXFSPGV_DISK_NUM(cxfspgv))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_check: inconsistent disk_num: counted disk num = %u, CXFSPGV_DISK_NUM = %u\n",
                           disk_num, CXFSPGV_DISK_NUM(cxfspgv));
        return (EC_FALSE);
    }

    for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CXFSPGV_DISK_NODE(cxfspgv, disk_no))
        {
            pgd_assign_bitmap    |= CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(CXFSPGV_DISK_NODE(cxfspgv, disk_no));
            pgd_actual_used_size += CXFSPGD_PAGE_ACTUAL_USED_SIZE(CXFSPGV_DISK_NODE(cxfspgv, disk_no));
            pgd_page_max_num     += CXFSPGD_PAGE_MAX_NUM(CXFSPGV_DISK_NODE(cxfspgv, disk_no));
            pgd_page_used_num    += CXFSPGD_PAGE_USED_NUM(CXFSPGV_DISK_NODE(cxfspgv, disk_no));
        }
    }

    if(pgv_assign_bitmap != pgd_assign_bitmap)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_check: inconsistent bitmap: pgv_assign_bitmap = %s, pgd_assign_bitmap = %s\n",
                           c_uint16_t_to_bin_str(pgv_assign_bitmap), c_uint16_t_to_bin_str(pgd_assign_bitmap));
        return (EC_FALSE);
    }

    if(pgv_actual_used_size != pgd_actual_used_size)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_check: inconsistent actual used size: pgv_actual_used_size = %"PRId64", pgd_actual_used_size = %"PRId64"\n",
                            pgv_actual_used_size, pgd_actual_used_size);
        return (EC_FALSE);
    }

    if(pgv_page_max_num != pgd_page_max_num)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_check: inconsistent page max num: pgv_page_max_num = %"PRId64", pgd_page_max_num = %"PRId64"\n",
                            pgv_page_max_num, pgd_page_max_num);
        return (EC_FALSE);
    }

    if(pgv_page_used_num != pgd_page_used_num)
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_check: inconsistent page used num: pgv_page_used_num = %"PRId64", pgd_page_used_num = %"PRId64"\n",
                            pgv_page_used_num, pgd_page_used_num);
        return (EC_FALSE);
    }

    /*check block table*/
    for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CXFSPGV_DISK_NODE(cxfspgv, disk_no))
        {
            if(EC_FALSE == cxfspgd_check(CXFSPGV_DISK_NODE(cxfspgv, disk_no)))
            {
                dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_check: check CXFSPGV_DISK_NODE of disk_no %u failed\n", disk_no);
                return (EC_FALSE);
            }
        }
    }
    dbg_log(SEC_0203_CXFSPGV, 5)(LOGSTDOUT, "cxfspgv_check: cxfspgv %p check passed\n", cxfspgv);
    return (EC_TRUE);
}

void cxfspgv_print(LOG *log, const CXFSPGV *cxfspgv)
{
    uint16_t  page_model;
    char     *page_desc;
    REAL      used_size;
    REAL      occupied_size;
    REAL      ratio_size;

    REAL      ratio_page;

    CXFSPGV_ASSERT(NULL_PTR != cxfspgv);

    //cxfspgrb_pool_print(log, CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv));
    if(0)
    {
        for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
        {
            sys_log(log, "cxfspgv_print: page_model %u, block root_pos %u\n",
                          page_model,
                          CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model));
            cxfspgrb_tree_print(log, CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv), CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model));
            sys_log(log, "----------------------------------------------------------\n");
        }
    }

    used_size     = (0.0 + CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv));
    occupied_size = (0.0 + (((uint64_t)CXFSPGV_PAGE_USED_NUM(cxfspgv)) << CXFSPGB_PAGE_BIT_SIZE));
    ratio_size    = (EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size));

    ratio_page    = ((0.0 + CXFSPGV_PAGE_USED_NUM(cxfspgv)) / (0.0 + CXFSPGV_PAGE_MAX_NUM(cxfspgv)));

    page_desc     = CXFSPCB_PAGE_DESC;

    sys_log(log, "cxfspgv_print: cxfspgv %p, disk num %u, disk max num %u, %s, page max num %"PRId64", page used num %"PRId64", page ratio %.2f, used size %"PRId64", size ratio %.2f\n",
                 cxfspgv,
                 CXFSPGV_DISK_NUM(cxfspgv),
                 CXFSPGV_DISK_MAX_NUM(cxfspgv),
                 page_desc,
                 CXFSPGV_PAGE_MAX_NUM(cxfspgv),
                 CXFSPGV_PAGE_USED_NUM(cxfspgv),
                 ratio_page,
                 CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv),
                 ratio_size
                 );

    sys_log(log, "cxfspgv_print: cxfspgv %p, assign bitmap %s \n",
                 cxfspgv,
                 c_uint16_t_to_bin_str(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv))
                 );

    if(0)
    {
        for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++)
        {
            if(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv) & (1 << page_model))
            {
                sys_log(log, "cxfspgv_print: cxfspgv %p, model %u has page to assign\n", cxfspgv, page_model);
            }
            else
            {
                sys_log(log, "cxfspgv_print: cxfspgv %p, model %u no  page to assign\n", cxfspgv, page_model);
            }
        }
    }

    if(1)
    {
        uint16_t  disk_no;
        for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CXFSPGV_DISK_NODE(cxfspgv, disk_no))
            {
                sys_log(log, "cxfspgv_print: disk %u is\n", disk_no);
                cxfspgd_print(log, CXFSPGV_DISK_NODE(cxfspgv, disk_no));
            }
        }
    }

    return;
}

/* ---- debug ---- */
EC_BOOL cxfspgv_debug_cmp(const CXFSPGV *cxfspgv_1st, const CXFSPGV *cxfspgv_2nd)
{
    uint16_t page_model;
    uint16_t disk_no;

    /*cxfspgrb pool*/
    if(EC_FALSE == cxfspgrb_debug_cmp(CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv_1st), CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv_2nd)))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_debug_cmp: inconsistent cxfspgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CXFSPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv_1st, page_model);
        root_pos_2nd = CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*assign bitmap*/
    if(CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv_1st) != CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv_1st))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv_1st), CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv_2nd));
        return (EC_FALSE);
    }

    /*dis num*/
    if(CXFSPGV_DISK_NUM(cxfspgv_1st) != CXFSPGV_DISK_NUM(cxfspgv_1st))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_DISK_NUM: %u != %u\n",
                            CXFSPGV_DISK_NUM(cxfspgv_1st), CXFSPGV_DISK_NUM(cxfspgv_2nd));
        return (EC_FALSE);
    }

    /*dis max num*/
    if(CXFSPGV_DISK_MAX_NUM(cxfspgv_1st) != CXFSPGV_DISK_MAX_NUM(cxfspgv_1st))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_DISK_MAX_NUM: %u != %u\n",
                            CXFSPGV_DISK_MAX_NUM(cxfspgv_1st), CXFSPGV_DISK_MAX_NUM(cxfspgv_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CXFSPGV_PAGE_MAX_NUM(cxfspgv_1st) != CXFSPGV_PAGE_MAX_NUM(cxfspgv_1st))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_PAGE_MAX_NUM: %"PRId64" != %"PRId64"\n",
                            CXFSPGV_PAGE_MAX_NUM(cxfspgv_1st), CXFSPGV_PAGE_MAX_NUM(cxfspgv_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CXFSPGV_PAGE_USED_NUM(cxfspgv_1st) != CXFSPGV_PAGE_USED_NUM(cxfspgv_1st))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_PAGE_USED_NUM: %"PRId64" != %"PRId64"\n",
                            CXFSPGV_PAGE_USED_NUM(cxfspgv_1st), CXFSPGV_PAGE_USED_NUM(cxfspgv_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv_1st) != CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv_1st))
    {
        dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDERR, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_PAGE_ACTUAL_USED_SIZE: %"PRId64" != %"PRId64"\n",
                            CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv_1st), CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv_2nd));
        return (EC_FALSE);
    }

    /*cxfspgd*/
    for(disk_no = 0; disk_no < CXFSPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR == CXFSPGV_DISK_NODE(cxfspgv_1st, disk_no) && NULL_PTR != CXFSPGV_DISK_NODE(cxfspgv_2nd, disk_no))
        {
            dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_DISK_NODE at disk_no %u: 1st is null but 2nd is not null\n", disk_no);
            return (EC_FALSE);
        }

        if(NULL_PTR != CXFSPGV_DISK_NODE(cxfspgv_1st, disk_no) && NULL_PTR == CXFSPGV_DISK_NODE(cxfspgv_2nd, disk_no))
        {
            dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_DISK_NODE at disk_no %u: 1st is not null but 2nd is null\n", disk_no);
            return (EC_FALSE);
        }

        if(NULL_PTR == CXFSPGV_DISK_NODE(cxfspgv_1st, disk_no) && NULL_PTR == CXFSPGV_DISK_NODE(cxfspgv_2nd, disk_no))
        {
            continue;
        }

        if(EC_FALSE == cxfspgd_debug_cmp(CXFSPGV_DISK_NODE(cxfspgv_1st, disk_no), CXFSPGV_DISK_NODE(cxfspgv_2nd, disk_no)))
        {
            dbg_log(SEC_0203_CXFSPGV, 0)(LOGSTDOUT, "error:cxfspgv_debug_cmp: inconsistent CXFSPGV_DISK_NODE at disk_no %u\n", disk_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

