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

#ifndef    _CXFSPGV_H
#define    _CXFSPGV_H

/*page disk volume, one page = 4KB, one page disk = 2^14 page block = 2^14 * 64MB = 1TB, one page volume = 2^6 * page disk = 64TB*/

#include "type.h"

#include "cxfscfg.h"
#include "cxfspgrb.h"
#include "cxfspgd.h"

#if (CXFSPGD_004G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 << 10))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 << 11))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 << 12))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 << 13))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 << 14))
#endif/*(CXFSPGD_004G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_008G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 << 10))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 << 11))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 << 12))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 << 13))
#endif/*(CXFSPGD_008G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_016G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 << 10))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 << 11))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 << 12))
#endif/*(CXFSPGD_016G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_032G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 << 10))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 << 11))
#endif/*(CXFSPGD_032G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_064G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 << 10))
#endif/*(CXFSPGD_064G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_128G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  3))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 <<  9))
#endif/*(CXFSPGD_128G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_256G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  2))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  3))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 <<  8))
#endif/*(CXFSPGD_256G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_512G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  1))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  2))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  3))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 <<  7))
#endif/*(CXFSPGD_512G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_001T_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGV_001TB_DISK_NUM  ((uint16_t)(1 <<  0))
#define CXFSPGV_002TB_DISK_NUM  ((uint16_t)(1 <<  1))
#define CXFSPGV_004TB_DISK_NUM  ((uint16_t)(1 <<  2))
#define CXFSPGV_008TB_DISK_NUM  ((uint16_t)(1 <<  3))
#define CXFSPGV_016TB_DISK_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGV_032TB_DISK_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGV_064TB_DISK_NUM  ((uint16_t)(1 <<  6))
#endif/*(CXFSPGD_001T_DISK == CXFSPGD_DEBUG_CHOICE)*/

#define CXFSPGV_MAX_DISK_NUM               (CXFSPGV_064TB_DISK_NUM)

typedef struct
{
    uint16_t        pgv_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/
    uint16_t        pgv_disk_num;      /*current disk number*/
    uint16_t        pgv_disk_max_num;  /*max disk number support up to*/
    uint16_t        rsvd1;

    uint64_t        pgv_page_max_num; /*max pages number */
    uint64_t        pgv_page_used_num;/*used pages number*/
    uint64_t        pgv_actual_used_size;/*actual used bytes*/

    uint16_t        pgv_disk_rb_root_pos[ CPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t        rsvd2;

    CXFSPGRB_POOL   pgv_disk_rb_pool;
}CXFSPGV_HDR;

#define CXFSPGV_HDR_CXFSPGRB_POOL(cxfspgv_hdr)                            (&((cxfspgv_hdr)->pgv_disk_rb_pool))
#define CXFSPGV_HDR_DISK_CXFSPGRB_ROOT_POS_TBL(cxfspgv_hdr)               ((cxfspgv_hdr)->pgv_disk_rb_root_pos)
#define CXFSPGV_HDR_DISK_CXFSPGRB_ROOT_POS(cxfspgv_hdr, page_model)       ((cxfspgv_hdr)->pgv_disk_rb_root_pos[ (page_model) ])
#define CXFSPGV_HDR_ASSIGN_BITMAP(cxfspgv_hdr)                            ((cxfspgv_hdr)->pgv_assign_bitmap)
#define CXFSPGV_HDR_DISK_NUM(cxfspgv_hdr)                                 ((cxfspgv_hdr)->pgv_disk_num)
#define CXFSPGV_HDR_DISK_MAX_NUM(cxfspgv_hdr)                             ((cxfspgv_hdr)->pgv_disk_max_num)
#define CXFSPGV_HDR_PAGE_MAX_NUM(cxfspgv_hdr)                             ((cxfspgv_hdr)->pgv_page_max_num)
#define CXFSPGV_HDR_PAGE_USED_NUM(cxfspgv_hdr)                            ((cxfspgv_hdr)->pgv_page_used_num)
#define CXFSPGV_HDR_PAGE_ACTUAL_USED_SIZE(cxfspgv_hdr)                    ((cxfspgv_hdr)->pgv_actual_used_size)

#define CXFSPGV_HDR_SIZE     (sizeof(CXFSPGV_HDR) + sizeof(CXFSPGRB_NODE) * CXFSPGV_MAX_DISK_NUM)

typedef struct
{
    UINT32           pgv_offset;
    UINT32           pgv_fsize;
    UINT8           *pgv_cache; /*vol cache in memory*/
    CXFSPGV_HDR     *pgv_hdr;
    CXFSPGD         *pgv_disk_tbl[CXFSPGV_MAX_DISK_NUM];
}CXFSPGV;

#define CXFSPGV_OFFSET(cxfspgv)                                            ((cxfspgv)->pgv_offset)
#define CXFSPGV_FSIZE(cxfspgv)                                             ((cxfspgv)->pgv_fsize)
#define CXFSPGV_CACHE(cxfspgv)                                             ((cxfspgv)->pgv_cache)
#define CXFSPGV_HEADER(cxfspgv)                                            ((cxfspgv)->pgv_hdr)
#define CXFSPGV_PAGE_DISK_CXFSPGRB_POOL(cxfspgv)                           (CXFSPGV_HDR_CXFSPGRB_POOL(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS_TBL(cxfspgv)             (CXFSPGV_HDR_DISK_CXFSPGRB_ROOT_POS_TBL(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_PAGE_MODEL_DISK_CXFSPGRB_ROOT_POS(cxfspgv, page_model)     (CXFSPGV_HDR_DISK_CXFSPGRB_ROOT_POS(CXFSPGV_HEADER(cxfspgv), page_model))
#define CXFSPGV_PAGE_MODEL_ASSIGN_BITMAP(cxfspgv)                          (CXFSPGV_HDR_ASSIGN_BITMAP(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_DISK_NUM(cxfspgv)                                          (CXFSPGV_HDR_DISK_NUM(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_DISK_MAX_NUM(cxfspgv)                                      (CXFSPGV_HDR_DISK_MAX_NUM(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_PAGE_MAX_NUM(cxfspgv)                                      (CXFSPGV_HDR_PAGE_MAX_NUM(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_PAGE_USED_NUM(cxfspgv)                                     (CXFSPGV_HDR_PAGE_USED_NUM(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_PAGE_ACTUAL_USED_SIZE(cxfspgv)                             (CXFSPGV_HDR_PAGE_ACTUAL_USED_SIZE(CXFSPGV_HEADER(cxfspgv)))
#define CXFSPGV_DISK_TBL(cxfspgv)                                          ((cxfspgv)->pgv_disk_tbl)
#define CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no)                             ((cxfspgv)->pgv_disk_tbl[ disk_no ])
#define CXFSPGV_DISK_NODE(cxfspgv, disk_no)                                ((CXFSPGV_MAX_DISK_NUM <= (disk_no)) ? NULL_PTR : CXFSPGV_DISK_CXFSPGD(cxfspgv, disk_no))


EC_BOOL cxfspgv_hdr_init(CXFSPGV *cxfspgv);

CXFSPGV_HDR *cxfspgv_hdr_create(CXFSPGV *cxfspgv);

EC_BOOL cxfspgv_free(CXFSPGV *cxfspgv);

CXFSPGV *cxfspgv_open(UINT8 *base, const CXFSCFG *cxfscfg);

EC_BOOL cxfspgv_close(CXFSPGV *cxfspgv);

EC_BOOL cxfspgv_init(CXFSPGV *cxfspgv);

EC_BOOL cxfspgv_add_disk(CXFSPGV *cxfspgv, const uint16_t disk_no);

EC_BOOL cxfspgv_del_disk(CXFSPGV *cxfspgv, const uint16_t disk_no);

EC_BOOL cxfspgv_mount_disk(CXFSPGV *cxfspgv, const uint16_t disk_no);

EC_BOOL cxfspgv_umount_disk(CXFSPGV *cxfspgv, const uint16_t disk_no);

EC_BOOL cxfspgv_new_space_from_disk(CXFSPGV *cxfspgv, const uint32_t size, const uint16_t disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cxfspgv_new_space(CXFSPGV *cxfspgv, const uint32_t size, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cxfspgv_free_space(CXFSPGV *cxfspgv, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cxfspgv_is_full(const CXFSPGV *cxfspgv);

EC_BOOL cxfspgv_is_empty(const CXFSPGV *cxfspgv);

UINT32 cxfspgv_size(const uint16_t disk_num);

EC_BOOL cxfspgv_check(const CXFSPGV *cxfspgv);

void cxfspgv_print(LOG *log, const CXFSPGV *cxfspgv);

CXFSPGV *cxfspgv_new(UINT8 *base, const UINT32 size, const uint16_t disk_max_num);


/* ---- debug ---- */
EC_BOOL cxfspgv_debug_cmp(const CXFSPGV *cxfspgv_1st, const CXFSPGV *cxfspgv_2nd);


#endif    /* _CXFSPGV_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
