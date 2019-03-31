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

#ifndef    _CXFSPGD_H
#define    _CXFSPGD_H

/*page disk cache, one page = 4KB, one page disk = 2^14 page block = 2^14 * 64MB = 1TB*/

#include "type.h"
#include "cxfspgrb.h"
#include "cxfspgb.h"

#define CXFSPGD_064MB_SIZE_NBITS ((uint32_t) 26)
#define CXFSPGD_128MB_SIZE_NBITS ((uint32_t) 27)
#define CXFSPGD_256MB_SIZE_NBITS ((uint32_t) 28)
#define CXFSPGD_512MB_SIZE_NBITS ((uint32_t) 29)
#define CXFSPGD_001GB_SIZE_NBITS ((uint32_t) 30)
#define CXFSPGD_002GB_SIZE_NBITS ((uint32_t) 31)
#define CXFSPGD_004GB_SIZE_NBITS ((uint32_t) 32)
#define CXFSPGD_008GB_SIZE_NBITS ((uint32_t) 33)
#define CXFSPGD_016GB_SIZE_NBITS ((uint32_t) 34)
#define CXFSPGD_032GB_SIZE_NBITS ((uint32_t) 35)
#define CXFSPGD_064GB_SIZE_NBITS ((uint32_t) 36)
#define CXFSPGD_128GB_SIZE_NBITS ((uint32_t) 37)
#define CXFSPGD_256GB_SIZE_NBITS ((uint32_t) 38)
#define CXFSPGD_512GB_SIZE_NBITS ((uint32_t) 39)
#define CXFSPGD_001TB_SIZE_NBITS ((uint32_t) 40)

#define CXFSPGD_064MB_BLOCK_NUM  ((uint16_t)(1 <<  0))
#define CXFSPGD_128MB_BLOCK_NUM  ((uint16_t)(1 <<  1))
#define CXFSPGD_256MB_BLOCK_NUM  ((uint16_t)(1 <<  2))
#define CXFSPGD_512MB_BLOCK_NUM  ((uint16_t)(1 <<  3))
#define CXFSPGD_001GB_BLOCK_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGD_002GB_BLOCK_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGD_004GB_BLOCK_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGD_008GB_BLOCK_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGD_016GB_BLOCK_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGD_032GB_BLOCK_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGD_064GB_BLOCK_NUM  ((uint16_t)(1 << 10))
#define CXFSPGD_128GB_BLOCK_NUM  ((uint16_t)(1 << 11))
#define CXFSPGD_256GB_BLOCK_NUM  ((uint16_t)(1 << 12))
#define CXFSPGD_512GB_BLOCK_NUM  ((uint16_t)(1 << 13))
#define CXFSPGD_001TB_BLOCK_NUM  ((uint16_t)(1 << 14))

#define CXFSPGD_ERROR_BLOCK_NUM  ((uint16_t)        0)

/*************************************************************
*    CXFSPGD_MAX_BLOCK_NUM   : how many blocks per disk
*    CXFSPGD_BLOCK_PAGE_MODEL: how many MB per block
*    CXFSPGD_BLOCK_PAGE_NUM  : how many pages per block
*************************************************************/

#define CXFSPGD_004G_DISK     (1)
#define CXFSPGD_008G_DISK     (2)
#define CXFSPGD_016G_DISK     (3)
#define CXFSPGD_032G_DISK     (4)
#define CXFSPGD_064G_DISK     (5)
#define CXFSPGD_128G_DISK     (6)
#define CXFSPGD_256G_DISK     (7)
#define CXFSPGD_512G_DISK     (8)
#define CXFSPGD_001T_DISK     (9)

#define CXFSPGD_DEBUG_CHOICE CXFSPGD_032G_DISK
//#define CXFSPGD_DEBUG_CHOICE CXFSPGD_004G_DISK


#if (CXFSPGD_004G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_004GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_004GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_004G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_008G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_008GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_008GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_008G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_016G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_016GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_016GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_016G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_032G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_032GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_032GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_032G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_064G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_064GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_064GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_064G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_128G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_128GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_128GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_128G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_256G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_256GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_256GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_256G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_512G_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_512GB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_512GB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_032G_DISK == CXFSPGD_DEBUG_CHOICE)*/

#if (CXFSPGD_001T_DISK == CXFSPGD_DEBUG_CHOICE)
#define CXFSPGD_SIZE_NBITS                  (CXFSPGD_001TB_SIZE_NBITS)
#define CXFSPGD_MAX_BLOCK_NUM               (CXFSPGD_001TB_BLOCK_NUM)
#define CXFSPGD_BLOCK_PAGE_MODEL            (CXFSPGB_064MB_MODEL)
#define CXFSPGD_BLOCK_PAGE_NUM              (CXFSPGB_064MB_PAGE_NUM)
#endif/*(CXFSPGD_001T_DISK == CXFSPGD_DEBUG_CHOICE)*/


#define CXFSPGD_PAGE_BLOCK_IS_FREE          ((uint8_t) 1)
#define CXFSPGD_PAGE_BLOCK_IS_NOT_FREE      ((uint8_t) 0)

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    uint16_t       block_num;
    uint16_t       rsvd01;
    uint32_t       rsvd02;
}CXFSPGD_CFG;

#define CXFSPGD_CFG_MODEL_STR(cxfspgd_cfg)     ((cxfspgd_cfg)->model_str)
#define CXFSPGD_CFG_ALIAS_STR(cxfspgd_cfg)     ((cxfspgd_cfg)->alias_str)
#define CXFSPGD_CFG_BLOCK_NUM(cxfspgd_cfg)     ((cxfspgd_cfg)->block_num)


typedef struct
{
    uint16_t        pgd_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/
    uint16_t        pgd_block_max_num; /*max block number */
    uint32_t        rsvd1;

    uint32_t        pgd_page_max_num; /*max pages number */
    uint32_t        pgd_page_used_num;/*used pages number*/
    uint64_t        pgd_actual_used_size;/*actual used bytes*/

    uint16_t        pgd_block_rb_root_pos[ CXFSPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t        rsvd2;

    CXFSPGRB_POOL   pgd_block_rb_pool;
}CXFSPGD_HDR;

#define CXFSPGD_HDR_CXFSPGRB_POOL(cxfspgd_hdr)                              (&((cxfspgd_hdr)->pgd_block_rb_pool))
#define CXFSPGD_HDR_BLOCK_CXFSPGRB_ROOT_POS_TBL(cxfspgd_hdr)                ((cxfspgd_hdr)->pgd_block_rb_root_pos)
#define CXFSPGD_HDR_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd_hdr, page_model)        ((cxfspgd_hdr)->pgd_block_rb_root_pos[ (page_model) ])
#define CXFSPGD_HDR_ASSIGN_BITMAP(cxfspgd_hdr)                              ((cxfspgd_hdr)->pgd_assign_bitmap)
#define CXFSPGD_HDR_PAGE_BLOCK_MAX_NUM(cxfspgd_hdr)                         ((cxfspgd_hdr)->pgd_block_max_num)
#define CXFSPGD_HDR_PAGE_MAX_NUM(cxfspgd_hdr)                               ((cxfspgd_hdr)->pgd_page_max_num)
#define CXFSPGD_HDR_PAGE_USED_NUM(cxfspgd_hdr)                              ((cxfspgd_hdr)->pgd_page_used_num)
#define CXFSPGD_HDR_PAGE_ACTUAL_USED_SIZE(cxfspgd_hdr)                      ((cxfspgd_hdr)->pgd_actual_used_size)

#define CXFSPGD_HDR_SIZE       (sizeof(CXFSPGD_HDR) + sizeof(CXFSPGRB_NODE) * CXFSPGD_MAX_BLOCK_NUM)

typedef struct
{
    UINT32          pgd_fsize;
    CXFSPGD_HDR    *pgd_hdr;
    CXFSPGB        *pgd_block_tbl[CXFSPGD_MAX_BLOCK_NUM];
}CXFSPGD;

#define CXFSPGD_FSIZE(cxfspgd)                                              ((cxfspgd)->pgd_fsize)
#define CXFSPGD_HEADER(cxfspgd)                                             ((cxfspgd)->pgd_hdr)

#define CXFSPGD_PAGE_BLOCK_CXFSPGRB_POOL(cxfspgd)                           (CXFSPGD_HDR_CXFSPGRB_POOL(CXFSPGD_HEADER(cxfspgd)))
#define CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS_TBL(cxfspgd)             (CXFSPGD_HDR_BLOCK_CXFSPGRB_ROOT_POS_TBL(CXFSPGD_HEADER(cxfspgd)))
#define CXFSPGD_PAGE_MODEL_BLOCK_CXFSPGRB_ROOT_POS(cxfspgd, page_model)     (CXFSPGD_HDR_BLOCK_CXFSPGRB_ROOT_POS(CXFSPGD_HEADER(cxfspgd), page_model))
#define CXFSPGD_PAGE_MODEL_ASSIGN_BITMAP(cxfspgd)                           (CXFSPGD_HDR_ASSIGN_BITMAP(CXFSPGD_HEADER(cxfspgd)))
#define CXFSPGD_PAGE_BLOCK_MAX_NUM(cxfspgd)                                 (CXFSPGD_HDR_PAGE_BLOCK_MAX_NUM(CXFSPGD_HEADER(cxfspgd)))
#define CXFSPGD_PAGE_MAX_NUM(cxfspgd)                                       (CXFSPGD_HDR_PAGE_MAX_NUM(CXFSPGD_HEADER(cxfspgd)))
#define CXFSPGD_PAGE_USED_NUM(cxfspgd)                                      (CXFSPGD_HDR_PAGE_USED_NUM(CXFSPGD_HEADER(cxfspgd)))
#define CXFSPGD_PAGE_ACTUAL_USED_SIZE(cxfspgd)                              (CXFSPGD_HDR_PAGE_ACTUAL_USED_SIZE(CXFSPGD_HEADER(cxfspgd)))
#define CXFSPGD_BLOCK_TBL(cxfspgd)                                          ((cxfspgd)->pgd_block_tbl)
#define CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no)                            ((cxfspgd)->pgd_block_tbl[ block_no ])
#define CXFSPGD_BLOCK_NODE(cxfspgd, block_no)                               ((CXFSPGD_MAX_BLOCK_NUM <= (block_no)) ? NULL_PTR : CXFSPGD_BLOCK_CXFSPGB(cxfspgd, block_no))

const char *cxfspgd_model_str(const uint16_t pgd_block_num);

uint16_t cxfspgd_model_get(const char *model_str);

CXFSPGD_HDR *cxfspgd_hdr_new(uint8_t *base, const uint16_t block_num);

CXFSPGD *cxfspgd_new(uint8_t *base, const uint16_t block_num);

EC_BOOL cxfspgd_free(CXFSPGD *cxfspgd);

CXFSPGD *cxfspgd_open(UINT8 *base, const UINT32 size);

EC_BOOL cxfspgd_close(CXFSPGD *cxfspgd);


/* one disk = 1TB */
EC_BOOL cxfspgd_init(CXFSPGD *cxfspgd);

void cxfspgd_clean(CXFSPGD *cxfspgd);

/*add one free block into pool*/
EC_BOOL cxfspgd_add_block(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_model);

/*del one free block from pool*/
EC_BOOL cxfspgd_del_block(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_model);

EC_BOOL cxfspgd_new_space(CXFSPGD *cxfspgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cxfspgd_free_space(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cxfspgd_reserve_space(CXFSPGD *cxfspgd, const uint32_t size, const uint16_t block_no, const uint16_t page_no);

EC_BOOL cxfspgd_release_space(CXFSPGD *cxfspgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cxfspgd_is_full(const CXFSPGD *cxfspgd);

EC_BOOL cxfspgd_is_empty(const CXFSPGD *cxfspgd);

uint16_t cxfspgd_page_model(const CXFSPGD *cxfspgd);

UINT32 cxfspgd_size(const uint16_t block_num);

EC_BOOL cxfspgd_check(const CXFSPGD *cxfspgd);

void cxfspgd_print(LOG *log, const CXFSPGD *cxfspgd);


/* ---- debug ---- */
EC_BOOL cxfspgd_debug_cmp(const CXFSPGD *cxfspgd_1st, const CXFSPGD *cxfspgd_2nd);


#endif    /* _CXFSPGD_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
