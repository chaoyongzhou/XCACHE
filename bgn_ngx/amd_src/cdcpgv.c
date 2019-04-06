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
#include "cdcpgd.h"
#include "cdcpgv.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCPGV_ASSERT(cond)   ASSERT(cond)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCPGV_ASSERT(cond)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

STATIC_CAST static uint16_t __cdcpgv_page_model_first_disk(const CDCPGV *cdcpgv, const uint16_t page_model)
{
    uint16_t node_pos;
    const CDCPGRB_NODE *node;

    node_pos = cdcpgrb_tree_first_node(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv), CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model));
    if(CDCPGRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:__cdcpgv_page_model_first_disk: no free page in page model %u\n", page_model);
        return (CDCPGRB_ERR_POS);
    }

    node = CDCPGRB_POOL_NODE(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv), node_pos);
    return (CDCPGRB_NODE_DATA(node));
}

STATIC_CAST static uint16_t __cdcpgv_page_model_get(const CDCPGV *cdcpgv, const uint16_t assign_bitmap)
{
    uint16_t page_model;
    uint16_t e;

    for(page_model = 0, e = 1; CDCPGB_MODEL_NUM > page_model && 0 == (assign_bitmap & e); page_model ++, e <<= 1)
    {
      /*do nothing*/
    }
    return (page_model);
}

UINT8 *cdcpgv_mcache_new(const UINT32 size)
{
    void            *base;
    UINT32           align;

    /*align = CDCDN_NODE_SIZE_NBYTES;*/ /*align to node size*/
    align = CDCPGB_SIZE_NBYTES;         /*align to block size*/

    base = c_memalign_new(size, CDCPGB_SIZE_NBYTES);
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_mcache_new: "
                                               "alloc %ld bytes with alignment %ld failed\n",
                                               size, align);
        return (NULL_PTR);
    }

    CDCPGV_ASSERT(NULL_PTR != base);
    return (base);
}

void cdcpgv_mcache_free(UINT8 *base)
{
    if(NULL_PTR != base)
    {
        c_memalign_free(base);
    }

    return;
}

EC_BOOL cdcpgv_hdr_free(CDCPGV *cdcpgv)
{
    if(NULL_PTR != CDCPGV_HEADER(cdcpgv))
    {
        cdcpgv_mcache_free((UINT8 *)CDCPGV_HEADER(cdcpgv));
        CDCPGV_HEADER(cdcpgv) = NULL_PTR;
    }

    /*cdcpgv_hdr cannot be accessed again*/
    return (EC_TRUE);
}

EC_BOOL cdcpgv_hdr_new(CDCPGV *cdcpgv)
{
    CDCPGV_HDR      *cdcpgv_hdr;

    cdcpgv_hdr = (CDCPGV_HDR *)cdcpgv_mcache_new(CDCPGV_SIZE(cdcpgv));
    if(NULL_PTR == cdcpgv_hdr)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_hdr_new: "
                                               "new mcache for cdcpgv_hdr with size %u failed\n",
                                               CDCPGV_SIZE(cdcpgv));
        return (EC_FALSE);
    }

    CDCPGV_HEADER(cdcpgv) = cdcpgv_hdr;

    if(EC_FALSE == cdcpgv_hdr_init(cdcpgv))
    {
        CDCPGV_HEADER(cdcpgv) = NULL_PTR;

        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:__cdcpgv_hdr_new: init cdcpgv failed\n");
        cdcpgv_mcache_free((UINT8 *)cdcpgv_hdr);

        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcpgv_hdr_init(CDCPGV *cdcpgv)
{
    CDCPGV_HDR *cdcpgv_hdr;
    uint16_t    page_model;

    cdcpgv_hdr = CDCPGV_HEADER(cdcpgv);
    if(EC_FALSE == cdcpgrb_pool_init(CDCPGV_HDR_CDCPGRB_POOL(cdcpgv_hdr), CDCPGV_MAX_DISK_NUM))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_hdr_init: init cpgrb pool failed where disk_num = %u\n", CDCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    for(page_model = 0; CDCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CDCPGV_HDR_DISK_CDCPGRB_ROOT_POS(cdcpgv_hdr, page_model) = CDCPGRB_ERR_POS;
    }

    CDCPGV_HDR_ASSIGN_BITMAP(cdcpgv_hdr) = 0;

    CDCPGV_HDR_PAGE_DISK_NUM(cdcpgv_hdr) = 0;

    CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)              = 0;
    CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr)         = CDCPGV_ERR_OFFSET;
    CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr)         = CDCPGV_ERR_OFFSET;
    CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr)         = CDCPGV_ERR_OFFSET;
    CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr)         = CDCPGV_ERR_OFFSET;

    /*statistics*/
    CDCPGV_HDR_PAGE_MAX_NUM(cdcpgv_hdr)          = 0;
    CDCPGV_HDR_PAGE_USED_NUM(cdcpgv_hdr)         = 0;
    CDCPGV_HDR_PAGE_ACTUAL_USED_SIZE(cdcpgv_hdr) = 0;

    return (EC_TRUE);
}

EC_BOOL cdcpgv_hdr_close(CDCPGV *cdcpgv)
{
    if(NULL_PTR != CDCPGV_HEADER(cdcpgv))
    {
        CDCPGV_HEADER(cdcpgv) = NULL_PTR;
    }

    /*cdcpgv_hdr cannot be accessed again*/
    return (EC_TRUE);
}


REAL cdcpgv_hdr_used_ratio(const CDCPGV *cdcpgv)
{
    if(NULL_PTR != CDCPGV_HEADER(cdcpgv))
    {
        CDCPGV_HDR *cdcpgv_hdr;

        cdcpgv_hdr = CDCPGV_HEADER(cdcpgv);

        if(0 < CDCPGV_HDR_PAGE_USED_NUM(cdcpgv_hdr))
        {
            REAL    page_used_num;
            REAL    page_max_num;

            page_used_num = (CDCPGV_HDR_PAGE_USED_NUM(cdcpgv_hdr) + 0.0);
            page_max_num  = (CDCPGV_HDR_PAGE_MAX_NUM(cdcpgv_hdr)  + 0.0);

            return (page_used_num / page_max_num);
        }
    }

    return (0.0);
}

EC_BOOL cdcpgv_hdr_max_size(UINT32 *size)
{
    (*size) += CDCPGV_HDR_SIZE;
    return (EC_TRUE);
}

CDCPGV *cdcpgv_new()
{
    CDCPGV      *cdcpgv;

    alloc_static_mem(MM_CDCPGV, &cdcpgv, LOC_CDCPGV_0001);
    if(NULL_PTR == cdcpgv)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_new: malloc cdcpgv failed\n");
        return (NULL_PTR);
    }

    cdcpgv_init(cdcpgv);

    CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;
    rlog(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new: CDCPGV_HDR_SIZE = %ld\n",
                                           CDCPGV_HDR_SIZE);

#if 0
    CDCPGV_HEADER(cdcpgv) = cdcpgv_hdr_new(cdcpgv);
    if(NULL_PTR == CDCPGV_HEADER(cdcpgv))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_new: new cdcpgv header failed\n");
        cdcpgv_free(cdcpgv);
        return (NULL_PTR);
    }
#endif
    //dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new: cdcpgv %p is\n", cdcpgv);
    //cdcpgv_print(LOGSTDOUT, cdcpgv);

    return (cdcpgv);
}

EC_BOOL cdcpgv_clear(CDCPGV *cdcpgv)
{
    if(NULL_PTR != cdcpgv)
    {
        uint16_t disk_no;

        /*clean disks*/
        for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CDCPGV_DISK_CDCPGD(cdcpgv, disk_no))
            {
                cdcpgd_clear(CDCPGV_DISK_CDCPGD(cdcpgv, disk_no));
                cdcpgd_free(CDCPGV_DISK_CDCPGD(cdcpgv, disk_no));
                CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = NULL_PTR;
            }
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdcpgv_free(CDCPGV *cdcpgv)
{
    if(NULL_PTR != cdcpgv)
    {
        uint16_t disk_no;

        /*clean disks*/
        for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CDCPGV_DISK_CDCPGD(cdcpgv, disk_no))
            {
                cdcpgd_free(CDCPGV_DISK_CDCPGD(cdcpgv, disk_no));
                CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = NULL_PTR;
            }
        }

        cdcpgv_hdr_free(cdcpgv);

        free_static_mem(MM_CDCPGV, cdcpgv, LOC_CDCPGV_0002);
    }

    return (EC_TRUE);
}

/* one page cache disk = 32GB */
EC_BOOL cdcpgv_init(CDCPGV *cdcpgv)
{
    uint16_t disk_no;

    CDCPGV_SIZE(cdcpgv)  = 0;
    CDCPGV_HEADER(cdcpgv)= NULL_PTR;

    for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = NULL_PTR;
    }
    return (EC_TRUE);
}

/*note: cdcpgv_clean is for not applying mmap*/
void cdcpgv_clean(CDCPGV *cdcpgv)
{
    uint16_t page_model;
    uint16_t disk_no;

    if(NULL_PTR == CDCPGV_HEADER(cdcpgv))
    {
        return;
    }

    cdcpgrb_pool_clean(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv));

    for(page_model = 0; CDCPGB_MODEL_MAX_NUM > page_model; page_model ++)
    {
        CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model) = CDCPGRB_ERR_POS;
    }

    for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CDCPGV_DISK_CDCPGD(cdcpgv, disk_no))
        {
            safe_free(CDCPGV_DISK_CDCPGD(cdcpgv, disk_no), LOC_CDCPGV_0003);
            CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = NULL_PTR;
        }
    }
    CDCPGV_PAGE_DISK_NUM(cdcpgv)                = 0;

    CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)     = 0;
    CDCPGV_PAGE_MAX_NUM(cdcpgv)                 = 0;
    CDCPGV_PAGE_USED_NUM(cdcpgv)                = 0;
    CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv)        = 0;

    safe_free(CDCPGV_HEADER(cdcpgv), LOC_CDCPGV_0004);
    CDCPGV_HEADER(cdcpgv) = NULL_PTR;

    return;
}

CDCPGV *cdcpgv_open()
{
    CDCPGV      *cdcpgv;

    alloc_static_mem(MM_CDCPGV, &cdcpgv, LOC_CDCPGV_0005);
    if(NULL_PTR == cdcpgv)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_open: malloc cdcpgv failed\n");
        return (NULL_PTR);
    }

    cdcpgv_init(cdcpgv);

    CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;

    return (cdcpgv);
}

EC_BOOL cdcpgv_close(CDCPGV *cdcpgv)
{
    if(NULL_PTR != cdcpgv)
    {
        cdcpgv_hdr_close(cdcpgv);
        cdcpgv_clear(cdcpgv);
        cdcpgv_free(cdcpgv);
    }

    return (EC_TRUE);
}

/*add one free disk into pool*/
STATIC_CAST static EC_BOOL __cdcpgv_add_disk(CDCPGV *cdcpgv, const uint16_t disk_no, const uint16_t page_model)
{
    if(CDCPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:__cdcpgv_add_disk: disk_no %u overflow where disk max num is %u\n", disk_no, CDCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    /*insert disk_no to rbtree*/
    if(CDCPGRB_ERR_POS == cdcpgrb_tree_insert_data(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv), &(CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model)), disk_no))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:__cdcpgv_add_disk: add disk_no %u to rbtree of page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*set assignment bitmap*/
    /*set bits of page_model, page_model + 1, ... page_4k_model, the highest bit is for 2k-page which is not supported,clear it!*/
    CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv) |= (uint16_t)(~((1 << page_model) - 1)) & CDCPGB_MODEL_MASK_ALL;

    return (EC_TRUE);
}

/*del one free disk from pool*/
STATIC_CAST static EC_BOOL __cdcpgv_del_disk(CDCPGV *cdcpgv, const uint16_t disk_no, const uint16_t page_model)
{
    /*del disk_no from rbtree*/
    if(EC_FALSE == cdcpgrb_tree_delete_data(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv), &(CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model)), disk_no))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:__cdcpgv_del_disk: del disk_no %u from rbtree of page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*clear assignment bitmap if necessary*/
    if(0 == (CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv) & (uint16_t)((1 << page_model) - 1)))/*upper page-model has no page*/
    {
        uint16_t page_model_t;

        page_model_t = page_model;
        while(CDCPGB_MODEL_NUM > page_model_t
           && EC_TRUE == cdcpgrb_tree_is_empty(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv), CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model_t))/*this page-model is empty*/
        )
        {
            CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv) &= (uint16_t)~(1 << page_model_t);/*clear bit*/
            page_model_t ++;
        }
    }

    return (EC_TRUE);
}

/*page_model is IN & OUT parameter*/
STATIC_CAST static EC_BOOL __cdcpgv_assign_disk(CDCPGV *cdcpgv, uint16_t *page_model, uint16_t *disk_no)
{
    uint16_t disk_no_t;
    uint16_t page_model_t;
    uint16_t mask;

    page_model_t = *page_model;

    mask = (uint16_t)((1 << (page_model_t + 1)) - 1);
    if(0 == (CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv) & mask))
    {
        dbg_log(SEC_0186_CDCPGV, 7)(LOGSTDOUT, "error:__cdcpgv_assign_disk: page_model = %u where 0 == bitmap %x & mask %x indicates page is not available\n",
                           page_model_t, CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv), mask);
        return (EC_FALSE);
    }

    while(CDCPGB_MODEL_NUM > page_model_t
       && EC_TRUE == cdcpgrb_tree_is_empty(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv), CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model_t))
       )
    {
        page_model_t --;
    }

    if(CDCPGB_MODEL_NUM <= page_model_t)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:__cdcpgv_assign_disk: no free disk available from page model %u\n", *page_model);
        return (EC_FALSE);
    }

    disk_no_t = __cdcpgv_page_model_first_disk(cdcpgv, page_model_t);
    if(CDCPGRB_ERR_POS == disk_no_t)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:__cdcpgv_assign_disk: no free disk in page model %u\n", page_model_t);
        return (EC_FALSE);
    }

    (*page_model) = page_model_t;
    (*disk_no)    = disk_no_t;

    return (EC_TRUE);
}

EC_BOOL cdcpgv_add_disk(CDCPGV *cdcpgv, const uint16_t disk_no, UINT8 *base, UINT32 *pos)
{
    CDCPGD          *cdcpgd;

    if(CDCPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_add_disk: "
                                               "disk %u overflow the max disk num %u\n",
                                               disk_no, CDCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    if(NULL_PTR != CDCPGV_DISK_CDCPGD(cdcpgv, disk_no))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_add_disk: "
                                               "disk %u already exist\n",
                                               disk_no);
        return (EC_FALSE);
    }

    cdcpgd = cdcpgd_make(disk_no, CDCPGD_MAX_BLOCK_NUM, base, pos);
    if(NULL_PTR == cdcpgd)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_add_disk: "
                                               "make disk %u failed\n",
                                               disk_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0186_CDCPGV, 3)(LOGSTDOUT, "[DEBUG] cdcpgv_add_disk: "
                                           "make disk %u done\n",
                                           disk_no);

    /*add disk to volume*/
    CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = cdcpgd;
    CDCPGV_PAGE_DISK_NUM(cdcpgv) ++;

    /*statistics*/
    CDCPGV_PAGE_MAX_NUM(cdcpgv)          += ((uint64_t)1) * CDCPGD_MAX_BLOCK_NUM * CDCPGD_BLOCK_PAGE_NUM;
    CDCPGV_PAGE_USED_NUM(cdcpgv)         += 0;
    CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv) += 0;

    /*add one free disk into pool*/
    return __cdcpgv_add_disk(cdcpgv, disk_no, CDCPGD_BLOCK_PAGE_MODEL);
}

EC_BOOL cdcpgv_del_disk(CDCPGV *cdcpgv, const uint16_t disk_no)
{
    CDCPGD    *cdcpgd;
    uint16_t page_model;

    if(CDCPGV_MAX_DISK_NUM <= disk_no)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_del_disk: disk %u overflow the max disk num %u\n", disk_no, CDCPGV_MAX_DISK_NUM);
        return (EC_FALSE);
    }

    cdcpgd = CDCPGV_DISK_CDCPGD(cdcpgv, disk_no);
    if(NULL_PTR == cdcpgd)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_del_disk: disk %u not exist\n", disk_no);
        return (EC_FALSE);
    }

    page_model = cdcpgd_page_model(cdcpgd);

    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_del_disk: disk %u, page_model %u\n", disk_no, page_model);

    /*delete the disk from pool*/
    if(EC_FALSE == __cdcpgv_del_disk(cdcpgv, disk_no, page_model))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_del_disk: del disk %u, page model %u failed\n", disk_no, page_model);
        return (EC_FALSE);
    }

    /*adjust cdcpgv statistics*/
    CDCPGV_PAGE_DISK_NUM(cdcpgv) --;
    CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = NULL_PTR;

    /*statistics*/
    CDCPGV_PAGE_MAX_NUM(cdcpgv)          -= ((uint64_t)1) * CDCPGD_MAX_BLOCK_NUM * CDCPGD_BLOCK_PAGE_NUM;;
    CDCPGV_PAGE_USED_NUM(cdcpgv)         -= CDCPGD_PAGE_USED_NUM(cdcpgd);
    CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv) -= CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd);

    cdcpgd_free(cdcpgd);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdcpgv_size_to_page_model(const uint32_t size, uint16_t *page_num, uint16_t *page_model)
{
    uint16_t page_num_need;
    uint16_t page_model_t;
    uint16_t e;
    uint16_t t;

    page_num_need = (uint16_t)((size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDNULL, "[DEBUG] __cdcpgv_size_to_page_model: size = %u ==> page_num_need = %u\n", size, page_num_need);

    /*find a page model which can accept the page_num_need pages */
    /*and then split the left space into page model with smaller size  */

    CDCPGV_ASSERT(CDCPGB_PAGE_NUM >= page_num_need);

    /*check bits of page_num_need and determine the page_model*/
    e = CDCPGB_PAGE_HI_BITS_MASK;
    for(t = page_num_need, page_model_t = 0/*CDCPGB_064MB_MODEL*/; 0 == (t & e); t <<= 1, page_model_t ++)
    {
        /*do nothing*/
    }
    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDNULL, "[DEBUG] __cdcpgv_size_to_page_model: t = 0x%x, page_model = %u, e = 0x%x, t << 1 is 0x%x\n",
                        t, page_model_t, e, (t << 1));

    if(CDCPGB_PAGE_LO_BITS_MASK & t)
    {
        page_model_t --;/*upgrade page_model one level*/
    }

    (*page_num)   = page_num_need;
    (*page_model) = page_model_t;

    return (EC_TRUE);
}

EC_BOOL cdcpgv_new_space_from_disk(CDCPGV *cdcpgv, const uint32_t size, const uint16_t disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CDCPGD    *cdcpgd;

    uint16_t page_num_need;
    uint16_t page_model;
    uint16_t page_model_t;

    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t disk_no_t;
    uint16_t block_no_t;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CDCPGV_ASSERT(0 < size);

    if(CDCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_new_space_from_disk: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    __cdcpgv_size_to_page_model(size, &page_num_need, &page_model);

    //dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: size = %u ==> page_num_need = %u ==> page_model = %u (has %u pages )\n",
    //                   size, page_num_need, page_model, (uint16_t)(1 << (CDCPGB_MODEL_NUM - 1 - page_model)));

    disk_no_t = disk_no;

    cdcpgd = CDCPGV_DISK_NODE(cdcpgv, disk_no_t);
    pgd_assign_bitmap_old = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);

    if(EC_FALSE == cdcpgd_new_space(cdcpgd, size, &block_no_t, &page_no_t))
    {
        dbg_log(SEC_0186_CDCPGV, 7)(LOGSTDOUT, "error:cdcpgv_new_space_from_disk: assign size %u from disk %u failed\n", size, disk_no);
        return (EC_FALSE);
    }

    pgd_assign_bitmap_new = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);

    //dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: disk_no_t %u: pgd bitmap %x => %x\n", disk_no_t, pgd_assign_bitmap_old, pgd_assign_bitmap_new);

    /*pgd_assign_bitmap changes may make pgv_assign_bitmap changes*/
    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: before delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)),
                            c_uint16_t_to_bin_str(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)));

        for(page_model_t = page_model, page_model = 0;  page_model < page_model_t; page_model ++)
        {
            if(0 != (pgd_assign_bitmap_old & (uint16_t)(1 << page_model)))
            {
                break;
            }
        }

        /*delete the disk from pool*/
        __cdcpgv_del_disk(cdcpgv, disk_no_t, page_model);

        dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: after  delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)),
                            c_uint16_t_to_bin_str(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)));

        dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: disk_no_t %u: max pages %u, used pages %u\n",
                            disk_no_t, CDCPGD_PAGE_MAX_NUM(cdcpgd), CDCPGD_PAGE_USED_NUM(cdcpgd));

        if(EC_FALSE == cdcpgd_is_full(cdcpgd))
        {
            //uint16_t page_model_t;

            page_model_t = page_model;
            while(CDCPGB_MODEL_NUM > page_model_t
               && 0 == (pgd_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CDCPGV_ASSERT(CDCPGB_MODEL_NUM > page_model_t);

            dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: page_model %u, page_model_t %u\n", page_model, page_model_t);
            /*add the disk into pool*/
            __cdcpgv_add_disk(cdcpgv, disk_no_t, page_model_t);
            dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                                disk_no_t,
                                c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)),
                                c_uint16_t_to_bin_str(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CDCPGV_PAGE_USED_NUM(cdcpgv)         += page_num_need;
    CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv) += size;

    CDCPGV_ASSERT(EC_TRUE == cdcpgv_check(cdcpgv));

    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: pgv_page_used_num %"PRId64" due to increment %u\n",
                        CDCPGV_PAGE_USED_NUM(cdcpgv), page_num_need);
    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space_from_disk: pgv_actual_used_size %"PRId64" due to increment %u\n",
                        CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv), size);

    return (EC_TRUE);
}

EC_BOOL cdcpgv_new_space(CDCPGV *cdcpgv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    CDCPGD    *cdcpgd;

    uint16_t page_num_need;
    uint16_t page_model;

    uint16_t page_no_t;/*the page No. in certain page model*/

    uint16_t disk_no_t;
    uint16_t block_no_t;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CDCPGV_ASSERT(0 < size);

    if(CDCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_new_space: the expected size %u overflow\n", size);
        return (EC_FALSE);
    }

    __cdcpgv_size_to_page_model(size, &page_num_need, &page_model);

    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: size = %u ==> page_num_need = %u ==> page_model = %u (has %u pages )\n",
                       size, page_num_need, page_model, (uint16_t)(1 << (CDCPGB_MODEL_NUM - 1 - page_model)));

    for(;;)/*Oops! fix inconsistency between cdcpgv and cdcpgd*/
    {
        uint16_t page_model_t;

        page_model_t = page_model; /*re-arm*/

        if(EC_FALSE == __cdcpgv_assign_disk(cdcpgv, &page_model_t, &disk_no_t))
        {
            dbg_log(SEC_0186_CDCPGV, 7)(LOGSTDOUT, "error:cdcpgv_new_space: assign one disk from page model %u failed\n", page_model_t);
            return (EC_FALSE);
        }

        dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: size %u ==> page_model_t %u and disk_no_t %u\n", size, page_model_t, disk_no_t);

        cdcpgd = CDCPGV_DISK_NODE(cdcpgv, disk_no_t);
        pgd_assign_bitmap_old = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);

        if(EC_TRUE == cdcpgd_new_space(cdcpgd, size, &block_no_t, &page_no_t))
        {
            page_model = page_model_t;
            break;
        }

        /*find inconsistent, fix it!*/

        /*delete the disk from pool*/
        __cdcpgv_del_disk(cdcpgv, disk_no_t, page_model_t);

        while(CDCPGB_MODEL_NUM > page_model_t
           && 0 == (pgd_assign_bitmap_old & (uint16_t)(1 << page_model_t))
           )
        {
             page_model_t ++;
        }

        CDCPGV_ASSERT(CDCPGB_MODEL_NUM > page_model_t);

        /*add the disk into pool*/
        __cdcpgv_add_disk(cdcpgv, disk_no_t, page_model_t);

        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "warn:cdcpgv_new_space: disk %u model %u relocation to page model %u\n", disk_no_t, page_model_t, page_model_t);
    }

    pgd_assign_bitmap_new = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);

    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: disk_no_t %u: pgd bitmap %x => %x\n", disk_no_t, pgd_assign_bitmap_old, pgd_assign_bitmap_new);

    /*pgd_assign_bitmap changes may make pgv_assign_bitmap changes*/
    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: before delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)),
                            c_uint16_t_to_bin_str(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)));

        /*delete the disk from pool*/
        __cdcpgv_del_disk(cdcpgv, disk_no_t, page_model);

        dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: after  delete disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                            disk_no_t,
                            c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)),
                            c_uint16_t_to_bin_str(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)));

        dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: disk_no_t %u: max pages %u, used pages %u\n",
                            disk_no_t, CDCPGD_PAGE_MAX_NUM(cdcpgd), CDCPGD_PAGE_USED_NUM(cdcpgd));

        if(EC_FALSE == cdcpgd_is_full(cdcpgd))
        {
            uint16_t page_model_t;

            page_model_t = page_model;
            while(CDCPGB_MODEL_NUM > page_model_t
               && 0 == (pgd_assign_bitmap_new & (uint16_t)(1 << page_model_t))
               )
            {
                 page_model_t ++;
            }

            CDCPGV_ASSERT(CDCPGB_MODEL_NUM > page_model_t);

            dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: page_model %u, page_model_t %u\n", page_model, page_model_t);
            /*add the disk into pool*/
            __cdcpgv_add_disk(cdcpgv, disk_no_t, page_model_t);
            dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: disk_no_t %u: pgb bitmap %s, pgv assign bitmap %s\n",
                                disk_no_t,
                                c_uint16_t_to_bin_str(CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)),
                                c_uint16_t_to_bin_str(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv)));
        }
        else
        {
            /*do nothing*/
        }
    }

    (*disk_no)  = disk_no_t;
    (*block_no) = block_no_t;
    (*page_no)  = page_no_t;

    CDCPGV_PAGE_USED_NUM(cdcpgv)         += page_num_need;
    CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv) += size;

    CDCPGV_ASSERT(EC_TRUE == cdcpgv_check(cdcpgv));

    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: pgv_page_used_num %"PRId64" due to increment %u\n",
                        CDCPGV_PAGE_USED_NUM(cdcpgv), page_num_need);
    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_new_space: pgv_actual_used_size %"PRId64" due to increment %u\n",
                        CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv), size);

    return (EC_TRUE);
}

EC_BOOL cdcpgv_free_space(CDCPGV *cdcpgv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size)
{
    CDCPGD    *cdcpgd;

    uint16_t page_num_used;

    uint16_t pgd_assign_bitmap_old;
    uint16_t pgd_assign_bitmap_new;

    CDCPGV_ASSERT(0 < size);

    if(CDCPGB_SIZE_NBYTES < size)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_free_space: invalid size %u due to overflow\n", size);
        return (EC_FALSE);
    }

    cdcpgd = CDCPGV_DISK_NODE(cdcpgv, disk_no);
    pgd_assign_bitmap_old = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);

    if(EC_FALSE == cdcpgd_free_space(cdcpgd, block_no, page_no, size))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_free_space: disk_no %u free space of block_no %u, page_no %u, size %u failed\n",
                           disk_no, block_no, page_no, size);
        return (EC_FALSE);
    }

    pgd_assign_bitmap_new = CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd);

    if(pgd_assign_bitmap_new != pgd_assign_bitmap_old)
    {
        uint16_t page_model_old;
        uint16_t page_model_new;

        page_model_old = __cdcpgv_page_model_get(cdcpgv, pgd_assign_bitmap_old);
        page_model_new = __cdcpgv_page_model_get(cdcpgv, pgd_assign_bitmap_new);

        if(CDCPGB_MODEL_NUM > page_model_old)
        {
            __cdcpgv_del_disk(cdcpgv, disk_no, page_model_old);
        }
        __cdcpgv_add_disk(cdcpgv, disk_no, page_model_new);
    }

    page_num_used = (uint16_t)((size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    CDCPGV_PAGE_USED_NUM(cdcpgv)         -= page_num_used;
    CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv) -= size;

    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_free_space: pgv_page_used_num %"PRId64" due to decrement %u\n",
                        CDCPGV_PAGE_USED_NUM(cdcpgv), page_num_used);
    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_free_space: pgv_actual_used_size %"PRId64" due to decrement %u\n",
                        CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv), size);

    return (EC_TRUE);
}

EC_BOOL cdcpgv_is_full(const CDCPGV *cdcpgv)
{
    if(CDCPGV_PAGE_USED_NUM(cdcpgv) == CDCPGV_PAGE_MAX_NUM(cdcpgv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcpgv_is_empty(const CDCPGV *cdcpgv)
{
    if(0 == CDCPGV_PAGE_USED_NUM(cdcpgv) && 0 < CDCPGV_PAGE_MAX_NUM(cdcpgv))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdcpgv_aligned_size(UINT32 *size, const UINT32 mask)
{
    UINT32      max_size;

    max_size = 0;

    cdcpgv_max_size(&max_size);

    /*align to one block*/
    (*size) = VAL_ALIGN_NEXT(max_size, mask);

    dbg_log(SEC_0186_CDCPGV, 9)(LOGSTDOUT, "[DEBUG] cdcpgv_aligned_size: "
                                           "max size %ld, aligned to %ld\n",
                                           max_size, (*size));

    return (EC_TRUE);
}

EC_BOOL cdcpgv_max_size(UINT32 *size)
{
    uint16_t disk_no;

    cdcpgv_hdr_max_size(size);

    for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        cdcpgd_max_size(size);
    }
    return (EC_TRUE);
}

EC_BOOL cdcpgv_load(CDCPGV *cdcpgv, UINT8 *base, UINT32 *pos)
{
    uint16_t    disk_num;
    uint16_t    disk_idx;
    uint16_t    disk_no;

    CDCPGV_ASSERT(NULL_PTR != CDCPGV_HEADER(cdcpgv));

    disk_num = CDCPGV_PAGE_DISK_NUM(cdcpgv);
    if(CDCPGV_MAX_DISK_NUM <= disk_num)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_load: loaded disk_num %u overflow!\n", disk_num);
        return (EC_FALSE);
    }

    for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = NULL_PTR;
    }

    /*load CDCPGV_DISK_NODE table*/
    for(disk_idx = 0; disk_idx < disk_num; disk_idx ++)
    {
        CDCPGD_HDR  *cdcpgd_hdr;
        CDCPGD      *cdcpgd;

        cdcpgd_hdr = (CDCPGD_HDR *)(base + (*pos));

        disk_no = CDCPGD_HDR_DISK_NO(cdcpgd_hdr);
        if(CDCPGV_MAX_DISK_NUM <= disk_no)
        {
            dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_load: loaded disk_no %u overflow!\n",
                                                   disk_no);
            return (EC_FALSE);
        }

        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "[DEBUG] cdcpgv_load: loaded disk_no %u from pos %ld\n",
                                               disk_no, (*pos));

        cdcpgd = cdcpgd_new();
        if(NULL_PTR == cdcpgd)
        {
            dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_load: malloc disk %u failed\n",
                                                   disk_no);
            return (EC_FALSE);
        }

        CDCPGD_HEADER(cdcpgd) = cdcpgd_hdr;
        (*pos) += CDCPGD_HDR_SIZE;

        if(EC_FALSE == cdcpgd_load(cdcpgd, base, pos))
        {
            dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_load: load disk %u failed\n",
                                                   disk_no);
            cdcpgd_free(cdcpgd);
            return (EC_FALSE);
        }

        CDCPGD_SIZE(cdcpgd) = CDCPGD_HDR_SIZE + CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd) * CDCPGB_SIZE;

        CDCPGV_DISK_CDCPGD(cdcpgv, disk_no) = cdcpgd;
    }

    return (EC_TRUE);
}

EC_BOOL cdcpgv_check(const CDCPGV *cdcpgv)
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

    pgv_assign_bitmap    = CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv);
    pgv_actual_used_size = CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv);
    pgv_page_max_num     = CDCPGV_PAGE_MAX_NUM(cdcpgv);
    pgv_page_used_num    = CDCPGV_PAGE_USED_NUM(cdcpgv);

    pgd_assign_bitmap    = 0;
    pgd_actual_used_size = 0;
    pgd_page_max_num     = 0;
    pgd_page_used_num    = 0;

    for(disk_no = 0, disk_num = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CDCPGV_DISK_NODE(cdcpgv, disk_no))
        {
            disk_num ++;
        }
    }

    if(disk_num != CDCPGV_PAGE_DISK_NUM(cdcpgv))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_check: inconsistent disk_num: counted disk num = %u, CDCPGV_PAGE_DISK_NUM = %u\n",
                           disk_num, CDCPGV_PAGE_DISK_NUM(cdcpgv));
        return (EC_FALSE);
    }

    for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CDCPGV_DISK_NODE(cdcpgv, disk_no))
        {
            pgd_assign_bitmap    |= CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(CDCPGV_DISK_NODE(cdcpgv, disk_no));
            pgd_actual_used_size += CDCPGD_PAGE_ACTUAL_USED_SIZE(CDCPGV_DISK_NODE(cdcpgv, disk_no));
            pgd_page_max_num     += CDCPGD_PAGE_MAX_NUM(CDCPGV_DISK_NODE(cdcpgv, disk_no));
            pgd_page_used_num    += CDCPGD_PAGE_USED_NUM(CDCPGV_DISK_NODE(cdcpgv, disk_no));
        }
    }

    if(pgv_assign_bitmap != pgd_assign_bitmap)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_check: inconsistent bitmap: pgv_assign_bitmap = %s, pgd_assign_bitmap = %s\n",
                           c_uint16_t_to_bin_str(pgv_assign_bitmap), c_uint16_t_to_bin_str(pgd_assign_bitmap));
        return (EC_FALSE);
    }

    if(pgv_actual_used_size != pgd_actual_used_size)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_check: inconsistent actual used size: pgv_actual_used_size = %"PRId64", pgd_actual_used_size = %"PRId64"\n",
                            pgv_actual_used_size, pgd_actual_used_size);
        return (EC_FALSE);
    }

    if(pgv_page_max_num != pgd_page_max_num)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_check: inconsistent page max num: pgv_page_max_num = %"PRId64", pgd_page_max_num = %"PRId64"\n",
                            pgv_page_max_num, pgd_page_max_num);
        return (EC_FALSE);
    }

    if(pgv_page_used_num != pgd_page_used_num)
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_check: inconsistent page used num: pgv_page_used_num = %"PRId64", pgd_page_used_num = %"PRId64"\n",
                            pgv_page_used_num, pgd_page_used_num);
        return (EC_FALSE);
    }

    /*check block table*/
    for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR != CDCPGV_DISK_NODE(cdcpgv, disk_no))
        {
            if(EC_FALSE == cdcpgd_check(CDCPGV_DISK_NODE(cdcpgv, disk_no)))
            {
                dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_check: check CDCPGV_DISK_NODE of disk_no %u failed\n", disk_no);
                return (EC_FALSE);
            }
        }
    }
    dbg_log(SEC_0186_CDCPGV, 5)(LOGSTDOUT, "cdcpgv_check: cdcpgv %p check passed\n", cdcpgv);
    return (EC_TRUE);
}

REAL cdcpgv_used_ratio(const CDCPGV *cdcpgv)
{
    return cdcpgv_hdr_used_ratio(cdcpgv);
}

void cdcpgv_print(LOG *log, const CDCPGV *cdcpgv)
{
    uint16_t  page_model;
    char     *page_desc;
    REAL      used_size;
    REAL      occupied_size;
    REAL      ratio_size;

    REAL      ratio_page;

    CDCPGV_ASSERT(NULL_PTR != cdcpgv);

    //cdcpgrb_pool_print(log, CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv));
    if(0)
    {
        for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
        {
            sys_log(log, "cdcpgv_print: page_model %u, block root_pos %u\n",
                          page_model,
                          CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model));
            cdcpgrb_tree_print(log, CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv), CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv, page_model));
            sys_log(log, "----------------------------------------------------------\n");
        }
    }

    used_size     = (0.0 + CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv));
    occupied_size = (0.0 + (((uint64_t)CDCPGV_PAGE_USED_NUM(cdcpgv)) << CDCPGB_PAGE_SIZE_NBITS));
    ratio_size    = (EC_TRUE == REAL_ISZERO(CMPI_ERROR_MODI, occupied_size) ? 0.0 : (used_size / occupied_size));

    ratio_page    = ((0.0 + CDCPGV_PAGE_USED_NUM(cdcpgv)) / (0.0 + CDCPGV_PAGE_MAX_NUM(cdcpgv)));

    page_desc     = (char *)CDCPGB_PAGE_DESC;

    sys_log(log, "cdcpgv_print: cdcpgv %p, disk num %u, %s, page max num %"PRId64", page used num %"PRId64", page ratio %.2f, used size %"PRId64", size ratio %.2f\n",
                 cdcpgv,
                 CDCPGV_PAGE_DISK_NUM(cdcpgv),
                 page_desc,
                 CDCPGV_PAGE_MAX_NUM(cdcpgv),
                 CDCPGV_PAGE_USED_NUM(cdcpgv),
                 ratio_page,
                 CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv),
                 ratio_size
                 );

    sys_log(log, "cdcpgv_print: cdcpgv %p, assign bitmap %s \n",
                 cdcpgv,
                 c_uint16_t_to_bin_str(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv))
                 );

    if(0)
    {
        for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++)
        {
            if(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv) & (1 << page_model))
            {
                sys_log(log, "cdcpgv_print: cdcpgv %p, model %u has page to assign\n", cdcpgv, page_model);
            }
            else
            {
                sys_log(log, "cdcpgv_print: cdcpgv %p, model %u no  page to assign\n", cdcpgv, page_model);
            }
        }
    }

    if(1)
    {
        uint16_t  disk_no;
        for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
        {
            if(NULL_PTR != CDCPGV_DISK_NODE(cdcpgv, disk_no))
            {
                sys_log(log, "cdcpgv_print: disk %u is\n", disk_no);
                cdcpgd_print(log, CDCPGV_DISK_NODE(cdcpgv, disk_no));
            }
        }
    }

    return;
}

/* ---- debug ---- */
EC_BOOL cdcpgv_debug_cmp(const CDCPGV *cdcpgv_1st, const CDCPGV *cdcpgv_2nd)
{
    uint16_t page_model;
    uint16_t disk_no;

    /*cpgrb pool*/
    if(EC_FALSE == cdcpgrb_debug_cmp(CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv_1st), CDCPGV_PAGE_DISK_CDCPGRB_POOL(cdcpgv_2nd)))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent cpgrb pool\n");
        return (EC_FALSE);
    }

    /*root pos*/
    for(page_model = 0; CDCPGB_MODEL_NUM > page_model; page_model ++ )
    {
        uint16_t root_pos_1st;
        uint16_t root_pos_2nd;

        root_pos_1st = CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv_1st, page_model);
        root_pos_2nd = CDCPGV_PAGE_MODEL_DISK_CDCPGRB_ROOT_POS(cdcpgv_2nd, page_model);

        if(root_pos_1st != root_pos_2nd)
        {
            dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent root_pos: %u != %u at page_model %u\n",
                                root_pos_1st, root_pos_2nd, page_model);
            return (EC_FALSE);
        }
    }

    /*assign bitmap*/
    if(CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv_1st) != CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv_1st))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_PAGE_MODEL_ASSIGN_BITMAP: %u != %u\n",
                            CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv_1st), CDCPGV_PAGE_MODEL_ASSIGN_BITMAP(cdcpgv_2nd));
        return (EC_FALSE);
    }

    /*dis num*/
    if(CDCPGV_PAGE_DISK_NUM(cdcpgv_1st) != CDCPGV_PAGE_DISK_NUM(cdcpgv_1st))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_PAGE_DISK_NUM: %u != %u\n",
                            CDCPGV_PAGE_DISK_NUM(cdcpgv_1st), CDCPGV_PAGE_DISK_NUM(cdcpgv_2nd));
        return (EC_FALSE);
    }

    /*page max num*/
    if(CDCPGV_PAGE_MAX_NUM(cdcpgv_1st) != CDCPGV_PAGE_MAX_NUM(cdcpgv_1st))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_PAGE_MAX_NUM: %"PRId64" != %"PRId64"\n",
                            CDCPGV_PAGE_MAX_NUM(cdcpgv_1st), CDCPGV_PAGE_MAX_NUM(cdcpgv_2nd));
        return (EC_FALSE);
    }

    /*page used num*/
    if(CDCPGV_PAGE_USED_NUM(cdcpgv_1st) != CDCPGV_PAGE_USED_NUM(cdcpgv_1st))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_PAGE_USED_NUM: %"PRId64" != %"PRId64"\n",
                            CDCPGV_PAGE_USED_NUM(cdcpgv_1st), CDCPGV_PAGE_USED_NUM(cdcpgv_2nd));
        return (EC_FALSE);
    }

    /*page actual used bytes num*/
    if(CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv_1st) != CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv_1st))
    {
        dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_PAGE_ACTUAL_USED_SIZE: %"PRId64" != %"PRId64"\n",
                            CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv_1st), CDCPGV_PAGE_ACTUAL_USED_SIZE(cdcpgv_2nd));
        return (EC_FALSE);
    }

    /*cdcpgd*/
    for(disk_no = 0; disk_no < CDCPGV_MAX_DISK_NUM; disk_no ++)
    {
        if(NULL_PTR == CDCPGV_DISK_NODE(cdcpgv_1st, disk_no) && NULL_PTR != CDCPGV_DISK_NODE(cdcpgv_2nd, disk_no))
        {
            dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_DISK_NODE at disk_no %u: 1st is null but 2nd is not null\n", disk_no);
            return (EC_FALSE);
        }

        if(NULL_PTR != CDCPGV_DISK_NODE(cdcpgv_1st, disk_no) && NULL_PTR == CDCPGV_DISK_NODE(cdcpgv_2nd, disk_no))
        {
            dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_DISK_NODE at disk_no %u: 1st is not null but 2nd is null\n", disk_no);
            return (EC_FALSE);
        }

        if(NULL_PTR == CDCPGV_DISK_NODE(cdcpgv_1st, disk_no) && NULL_PTR == CDCPGV_DISK_NODE(cdcpgv_2nd, disk_no))
        {
            continue;
        }

        if(EC_FALSE == cdcpgd_debug_cmp(CDCPGV_DISK_NODE(cdcpgv_1st, disk_no), CDCPGV_DISK_NODE(cdcpgv_2nd, disk_no)))
        {
            dbg_log(SEC_0186_CDCPGV, 0)(LOGSTDOUT, "error:cdcpgv_debug_cmp: inconsistent CDCPGV_DISK_NODE at disk_no %u\n", disk_no);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

