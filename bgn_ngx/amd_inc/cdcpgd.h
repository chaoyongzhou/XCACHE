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

#ifndef    _CDCPGD_H
#define    _CDCPGD_H

#include "type.h"
#include "cdcpgrb.h"
#include "cdcpgb.h"

#define CDCPGD_032MB_SIZE_NBITS ((uint32_t) 25)
#define CDCPGD_064MB_SIZE_NBITS ((uint32_t) 26)
#define CDCPGD_128MB_SIZE_NBITS ((uint32_t) 27)
#define CDCPGD_256MB_SIZE_NBITS ((uint32_t) 28)
#define CDCPGD_512MB_SIZE_NBITS ((uint32_t) 29)
#define CDCPGD_001GB_SIZE_NBITS ((uint32_t) 30)
#define CDCPGD_002GB_SIZE_NBITS ((uint32_t) 31)
#define CDCPGD_004GB_SIZE_NBITS ((uint32_t) 32)
#define CDCPGD_008GB_SIZE_NBITS ((uint32_t) 33)
#define CDCPGD_016GB_SIZE_NBITS ((uint32_t) 34)
#define CDCPGD_032GB_SIZE_NBITS ((uint32_t) 35)
#define CDCPGD_064GB_SIZE_NBITS ((uint32_t) 36)
#define CDCPGD_128GB_SIZE_NBITS ((uint32_t) 37)
#define CDCPGD_256GB_SIZE_NBITS ((uint32_t) 38)
#define CDCPGD_512GB_SIZE_NBITS ((uint32_t) 39)

#define CDCPGD_032MB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_032MB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_064MB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_064MB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_128MB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_128MB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_256MB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_256MB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_512MB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_512MB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_001GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_001GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_002GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_002GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_004GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_004GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_008GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_008GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_016GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_016GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_032GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_032GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_064GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_064GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_128GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_128GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_256GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_256GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))
#define CDCPGD_512GB_BLOCK_NUM  ((uint16_t)(1 <<  (CDCPGD_512GB_SIZE_NBITS - CDCPGB_SIZE_NBITS)))

#define CDCPGD_ERROR_BLOCK_NUM  ((uint16_t)        0)

/*************************************************************
*    CDCPGD_MAX_BLOCK_NUM   : how many blocks per disk
*    CDCPGD_BLOCK_PAGE_MODEL: how many MB per block
*    CDCPGD_BLOCK_PAGE_NUM  : how many pages per block
*************************************************************/

#define CDCPGD_032M_DISK     ( 1)
#define CDCPGD_064M_DISK     ( 2)
#define CDCPGD_128M_DISK     ( 3)
#define CDCPGD_256M_DISK     ( 4)
#define CDCPGD_512M_DISK     ( 5)
#define CDCPGD_001G_DISK     ( 6)
#define CDCPGD_002G_DISK     ( 7)
#define CDCPGD_004G_DISK     ( 8)
#define CDCPGD_008G_DISK     ( 9)
#define CDCPGD_016G_DISK     (10)
#define CDCPGD_032G_DISK     (11)
#define CDCPGD_064G_DISK     (12)
#define CDCPGD_128G_DISK     (12)
#define CDCPGD_256G_DISK     (14)
#define CDCPGD_512G_DISK     (15)

//#define CDCPGD_DISK_CHOICE CDCPGD_256G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_512G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_128G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_064G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_032G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_016G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_008G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_004G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_002G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_001G_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_512M_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_256M_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_128M_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_064M_DISK
//#define CDCPGD_DISK_CHOICE CDCPGD_032M_DISK

#if (CDCPGD_032M_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_032MB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_032MB_BLOCK_NUM)
#endif/*(CDCPGD_032M_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_064M_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_064MB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_064MB_BLOCK_NUM)
#endif/*(CDCPGD_064M_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_128M_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_128MB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_128MB_BLOCK_NUM)
#endif/*(CDCPGD_128M_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_256M_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_256MB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_256MB_BLOCK_NUM)
#endif/*(CDCPGD_256M_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_512M_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_512MB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_512MB_BLOCK_NUM)
#endif/*(CDCPGD_512M_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_001G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_001GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_001GB_BLOCK_NUM)
#endif/*(CDCPGD_001G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_002G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_002GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_002GB_BLOCK_NUM)
#endif/*(CDCPGD_002G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_004G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_004GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_004GB_BLOCK_NUM)
#endif/*(CDCPGD_004G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_008G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_008GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_008GB_BLOCK_NUM)
#endif/*(CDCPGD_008G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_016G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_016GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_016GB_BLOCK_NUM)
#endif/*(CDCPGD_016G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_032G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_032GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_032GB_BLOCK_NUM)
#endif/*(CDCPGD_032G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_064G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_064GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_064GB_BLOCK_NUM)
#endif/*(CDCPGD_064G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_128G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_128GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_128GB_BLOCK_NUM)
#endif/*(CDCPGD_128G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_256G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_256GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_256GB_BLOCK_NUM)
#endif/*(CDCPGD_256G_DISK == CDCPGD_DISK_CHOICE)*/

#if (CDCPGD_512G_DISK == CDCPGD_DISK_CHOICE)
#define CDCPGD_SIZE_NBITS                  (CDCPGD_512GB_SIZE_NBITS)
#define CDCPGD_MAX_BLOCK_NUM               (CDCPGD_512GB_BLOCK_NUM)
#endif/*(CDCPGD_032G_DISK == CDCPGD_DISK_CHOICE)*/

#define CDCPGD_BLOCK_PAGE_MODEL            (CDCPGB_PAGE_MODEL)
#define CDCPGD_BLOCK_PAGE_NUM              (CDCPGB_PAGE_NUM)

#define CDCPGD_PAGE_BLOCK_IS_FREE          ((uint8_t) 1)
#define CDCPGD_PAGE_BLOCK_IS_NOT_FREE      ((uint8_t) 0)

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    uint16_t       block_num;
    uint16_t       rsvd01;
    uint32_t       rsvd02;
}CDCPGD_CFG;

#define CDCPGD_CFG_MODEL_STR(cdcpgd_cfg)     ((cdcpgd_cfg)->model_str)
#define CDCPGD_CFG_ALIAS_STR(cdcpgd_cfg)     ((cdcpgd_cfg)->alias_str)
#define CDCPGD_CFG_BLOCK_NUM(cdcpgd_cfg)     ((cdcpgd_cfg)->block_num)


typedef struct
{
    uint16_t        pgd_no;
    uint16_t        pgd_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/
    uint16_t        pgd_block_max_num; /*max block number */
    uint16_t        rsvd1;

    uint32_t        pgd_page_max_num; /*max pages number */
    uint32_t        pgd_page_used_num;/*used pages number*/
    uint64_t        pgd_actual_used_size;/*actual used bytes*/

    uint16_t        pgd_block_rb_root_pos[ CDCPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t        rsvd2;

    CDCPGRB_POOL    pgd_block_rb_pool;
}CDCPGD_HDR;

#define CDCPGD_HDR_CDCPGRB_POOL(cdcpgd_hdr)                         (&((cdcpgd_hdr)->pgd_block_rb_pool))
#define CDCPGD_HDR_BLOCK_CDCPGRB_ROOT_POS_TBL(cdcpgd_hdr)           ((cdcpgd_hdr)->pgd_block_rb_root_pos)
#define CDCPGD_HDR_BLOCK_CDCPGRB_ROOT_POS(cdcpgd_hdr, page_model)   ((cdcpgd_hdr)->pgd_block_rb_root_pos[ (page_model) ])
#define CDCPGD_HDR_ASSIGN_BITMAP(cdcpgd_hdr)                        ((cdcpgd_hdr)->pgd_assign_bitmap)
#define CDCPGD_HDR_PAGE_BLOCK_MAX_NUM(cdcpgd_hdr)                   ((cdcpgd_hdr)->pgd_block_max_num)
#define CDCPGD_HDR_PAGE_MAX_NUM(cdcpgd_hdr)                         ((cdcpgd_hdr)->pgd_page_max_num)
#define CDCPGD_HDR_PAGE_USED_NUM(cdcpgd_hdr)                        ((cdcpgd_hdr)->pgd_page_used_num)
#define CDCPGD_HDR_PAGE_ACTUAL_USED_SIZE(cdcpgd_hdr)                ((cdcpgd_hdr)->pgd_actual_used_size)
#define CDCPGD_HDR_DISK_NO(cdcpgd_hdr)                              ((cdcpgd_hdr)->pgd_no)

#define CDCPGD_HDR_SIZE       (sizeof(CDCPGD_HDR) + sizeof(CDCPGRB_NODE) * CDCPGD_MAX_BLOCK_NUM)

typedef struct
{
    uint32_t       pgd_size;
    uint32_t       rsvd;
    CDCPGD_HDR    *pgd_hdr; /*mount only*/
    CDCPGB        *pgd_block_tbl[CDCPGD_MAX_BLOCK_NUM];
}CDCPGD;

#define CDCPGD_SIZE(cdcpgd)                                          ((cdcpgd)->pgd_size)
#define CDCPGD_HEADER(cdcpgd)                                        ((cdcpgd)->pgd_hdr)
#define CDCPGD_PAGE_BLOCK_CDCPGRB_POOL(cdcpgd)                       (CDCPGD_HDR_CDCPGRB_POOL(CDCPGD_HEADER(cdcpgd)))
#define CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS_TBL(cdcpgd)         (CDCPGD_HDR_BLOCK_CDCPGRB_ROOT_POS_TBL(CDCPGD_HEADER(cdcpgd)))
#define CDCPGD_PAGE_MODEL_BLOCK_CDCPGRB_ROOT_POS(cdcpgd, page_model) (CDCPGD_HDR_BLOCK_CDCPGRB_ROOT_POS(CDCPGD_HEADER(cdcpgd), page_model))
#define CDCPGD_PAGE_MODEL_ASSIGN_BITMAP(cdcpgd)                      (CDCPGD_HDR_ASSIGN_BITMAP(CDCPGD_HEADER(cdcpgd)))
#define CDCPGD_PAGE_BLOCK_MAX_NUM(cdcpgd)                            (CDCPGD_HDR_PAGE_BLOCK_MAX_NUM(CDCPGD_HEADER(cdcpgd)))
#define CDCPGD_PAGE_MAX_NUM(cdcpgd)                                  (CDCPGD_HDR_PAGE_MAX_NUM(CDCPGD_HEADER(cdcpgd)))
#define CDCPGD_PAGE_USED_NUM(cdcpgd)                                 (CDCPGD_HDR_PAGE_USED_NUM(CDCPGD_HEADER(cdcpgd)))
#define CDCPGD_PAGE_ACTUAL_USED_SIZE(cdcpgd)                         (CDCPGD_HDR_PAGE_ACTUAL_USED_SIZE(CDCPGD_HEADER(cdcpgd)))
#define CDCPGD_BLOCK_TBL(cdcpgd)                                     ((cdcpgd)->pgd_block_tbl)
#define CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no)                        ((cdcpgd)->pgd_block_tbl[ block_no ])
#define CDCPGD_BLOCK_NODE(cdcpgd, block_no)                          ((CDCPGD_MAX_BLOCK_NUM <= (block_no)) ? NULL_PTR : CDCPGD_BLOCK_CDCPGB(cdcpgd, block_no))

const char *cdcpgd_model_str(const uint16_t pgd_block_num);

uint16_t cdcpgd_model_get(const char *model_str);

EC_BOOL cdcpgd_model_search(const UINT32 vdisk_size /*in byte*/, UINT32 *vdisk_num);

EC_BOOL cdcpgd_hdr_max_size(UINT32 *size);

EC_BOOL cdcpgd_hdr_init(CDCPGD_HDR *cdcpgd_hdr, const uint16_t disk_no, const uint16_t block_num);

CDCPGD *cdcpgd_new();

EC_BOOL cdcpgd_init(CDCPGD *cdcpgd);

EC_BOOL cdcpgd_clean(CDCPGD *cdcpgd);

EC_BOOL cdcpgd_free(CDCPGD *cdcpgd);

CDCPGD *cdcpgd_make(const uint16_t disk_no, const uint16_t block_num, UINT8 *base, UINT32 *pos);

/*add one free block into pool*/
EC_BOOL cdcpgd_add_block(CDCPGD *cdcpgd, const uint16_t block_no, const uint16_t page_model);

/*del one free block from pool*/
EC_BOOL cdcpgd_del_block(CDCPGD *cdcpgd, const uint16_t block_no, const uint16_t page_model);

EC_BOOL cdcpgd_new_space(CDCPGD *cdcpgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cdcpgd_free_space(CDCPGD *cdcpgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cdcpgd_is_full(const CDCPGD *cdcpgd);

EC_BOOL cdcpgd_is_empty(const CDCPGD *cdcpgd);

uint16_t cdcpgd_page_model(const CDCPGD *cdcpgd);

EC_BOOL cdcpgd_check(const CDCPGD *cdcpgd);

EC_BOOL cdcpgd_max_size(UINT32 *size);

EC_BOOL cdcpgd_load(CDCPGD *cdcpgd, UINT8 *base, UINT32 *pos);

void cdcpgd_print(LOG *log, const CDCPGD *cdcpgd);


/* ---- debug ---- */
EC_BOOL cdcpgd_debug_cmp(const CDCPGD *cdcpgd_1st, const CDCPGD *cdcpgd_2nd);


/*-------------------------------------------- DISK in memory --------------------------------------------*/
CDCPGD *cdcpgd_mem_new(const uint16_t block_num);

EC_BOOL cdcpgd_mem_free(CDCPGD *cdcpgd);


#endif    /* _CDCPGD_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
