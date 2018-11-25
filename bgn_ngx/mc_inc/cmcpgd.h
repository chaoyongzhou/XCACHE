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

#ifndef    _CMCPGD_H
#define    _CMCPGD_H

#include "type.h"
#include "cmcpgrb.h"
#include "cmcpgb.h"

#define CMCPGD_032MB_BLOCK_NUM  ((uint16_t)(1 <<  0))
#define CMCPGD_064MB_BLOCK_NUM  ((uint16_t)(1 <<  1))
#define CMCPGD_128MB_BLOCK_NUM  ((uint16_t)(1 <<  2))
#define CMCPGD_256MB_BLOCK_NUM  ((uint16_t)(1 <<  3))
#define CMCPGD_512MB_BLOCK_NUM  ((uint16_t)(1 <<  4))
#define CMCPGD_001GB_BLOCK_NUM  ((uint16_t)(1 <<  5))
#define CMCPGD_002GB_BLOCK_NUM  ((uint16_t)(1 <<  6))
#define CMCPGD_004GB_BLOCK_NUM  ((uint16_t)(1 <<  7))
#define CMCPGD_008GB_BLOCK_NUM  ((uint16_t)(1 <<  8))
#define CMCPGD_016GB_BLOCK_NUM  ((uint16_t)(1 <<  9))
#define CMCPGD_032GB_BLOCK_NUM  ((uint16_t)(1 << 10))
#define CMCPGD_064GB_BLOCK_NUM  ((uint16_t)(1 << 11))
#define CMCPGD_128GB_BLOCK_NUM  ((uint16_t)(1 << 12))
#define CMCPGD_256GB_BLOCK_NUM  ((uint16_t)(1 << 13))
#define CMCPGD_512GB_BLOCK_NUM  ((uint16_t)(1 << 14))

#define CMCPGD_ERROR_BLOCK_NUM  ((uint16_t)        0)

/*************************************************************
*    CMCPGD_MAX_BLOCK_NUM   : how many blocks per disk
*    CMCPGD_BLOCK_PAGE_MODEL: how many MB per block
*    CMCPGD_BLOCK_PAGE_NUM  : how many pages per block
*************************************************************/

#define CMCPGD_TEST_SCENARIO_032M_DISK     ( 1)
#define CMCPGD_TEST_SCENARIO_064M_DISK     ( 2)
#define CMCPGD_TEST_SCENARIO_128M_DISK     ( 3)
#define CMCPGD_TEST_SCENARIO_256M_DISK     ( 4)
#define CMCPGD_TEST_SCENARIO_512M_DISK     ( 5)
#define CMCPGD_TEST_SCENARIO_001G_DISK     ( 6)
#define CMCPGD_TEST_SCENARIO_002G_DISK     ( 7)
#define CMCPGD_TEST_SCENARIO_004G_DISK     ( 8)
#define CMCPGD_TEST_SCENARIO_008G_DISK     ( 9)
#define CMCPGD_TEST_SCENARIO_016G_DISK     (10)
#define CMCPGD_TEST_SCENARIO_032G_DISK     (11)
#define CMCPGD_TEST_SCENARIO_064G_DISK     (12)
#define CMCPGD_TEST_SCENARIO_128G_DISK     (12)
#define CMCPGD_TEST_SCENARIO_256G_DISK     (14)
#define CMCPGD_TEST_SCENARIO_512G_DISK     (15)

//#define CMCPGD_DEBUG_CHOICE CMCPGD_TEST_SCENARIO_032G_DISK
#define CMCPGD_DEBUG_CHOICE CMCPGD_TEST_SCENARIO_128M_DISK

#if (CMCPGD_TEST_SCENARIO_032M_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_032MB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_032M_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_064M_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_064MB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_064M_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_128M_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_128MB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_128M_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_256M_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_256MB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_256M_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_512M_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_512MB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_512M_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_001G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_001GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_001G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_002G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_002GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_002G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_004G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_004GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_004G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_008G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_008GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_008G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_016G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_016GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_016G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_032G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_032GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_032G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_064G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_064GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_064G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_128G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_128GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_128G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_256G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_256GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_256G_DISK == CMCPGD_DEBUG_CHOICE)*/

#if (CMCPGD_TEST_SCENARIO_512G_DISK == CMCPGD_DEBUG_CHOICE)
#define CMCPGD_MAX_BLOCK_NUM               (CMCPGD_512GB_BLOCK_NUM)
#define CMCPGD_BLOCK_PAGE_MODEL            (CMCPGB_032MB_MODEL)
#define CMCPGD_BLOCK_PAGE_NUM              (CMCPGB_032MB_PAGE_NUM)
#endif/*(CMCPGD_TEST_SCENARIO_032G_DISK == CMCPGD_DEBUG_CHOICE)*/


#define CMCPGD_PAGE_BLOCK_IS_FREE          ((uint8_t) 1)
#define CMCPGD_PAGE_BLOCK_IS_NOT_FREE      ((uint8_t) 0)

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    uint16_t       block_num;
    uint16_t       rsvd01;
    uint32_t       rsvd02;
}CMCPGD_CFG;

#define CMCPGD_CFG_MODEL_STR(cmcpgd_cfg)     ((cmcpgd_cfg)->model_str)
#define CMCPGD_CFG_ALIAS_STR(cmcpgd_cfg)     ((cmcpgd_cfg)->alias_str)
#define CMCPGD_CFG_BLOCK_NUM(cmcpgd_cfg)     ((cmcpgd_cfg)->block_num)


typedef struct
{
    uint16_t     pgd_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/
    uint16_t     pgd_block_max_num; /*max block number */
    uint32_t     rsvd1;

    uint32_t     pgd_page_max_num; /*max pages number */
    uint32_t     pgd_page_used_num;/*used pages number*/
    uint64_t     pgd_actual_used_size;/*actual used bytes*/

    uint16_t     pgd_block_rb_root_pos[ CMCPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t     rsvd2;    

    CMCPGRB_POOL   pgd_block_rb_pool;
}CMCPGD_HDR;

#define CMCPGD_HDR_CMCPGRB_POOL(cmcpgd_hdr)                         (&((cmcpgd_hdr)->pgd_block_rb_pool))
#define CMCPGD_HDR_BLOCK_CMCPGRB_ROOT_POS_TBL(cmcpgd_hdr)           ((cmcpgd_hdr)->pgd_block_rb_root_pos)
#define CMCPGD_HDR_BLOCK_CMCPGRB_ROOT_POS(cmcpgd_hdr, page_model)   ((cmcpgd_hdr)->pgd_block_rb_root_pos[ (page_model) ])
#define CMCPGD_HDR_ASSIGN_BITMAP(cmcpgd_hdr)                        ((cmcpgd_hdr)->pgd_assign_bitmap)
#define CMCPGD_HDR_PAGE_BLOCK_MAX_NUM(cmcpgd_hdr)                   ((cmcpgd_hdr)->pgd_block_max_num)
#define CMCPGD_HDR_PAGE_MAX_NUM(cmcpgd_hdr)                         ((cmcpgd_hdr)->pgd_page_max_num)
#define CMCPGD_HDR_PAGE_USED_NUM(cmcpgd_hdr)                        ((cmcpgd_hdr)->pgd_page_used_num)
#define CMCPGD_HDR_PAGE_ACTUAL_USED_SIZE(cmcpgd_hdr)                ((cmcpgd_hdr)->pgd_actual_used_size)

#define CMCPGD_HDR_SIZE       (sizeof(CMCPGD_HDR) + sizeof(CMCPGRB_NODE) * CMCPGD_MAX_BLOCK_NUM)

typedef struct
{
    uint32_t       pgd_size;
    uint32_t       rsvd2;
    CMCPGD_HDR    *pgd_hdr;
    CMCPGB        *pgd_block_tbl[CMCPGD_MAX_BLOCK_NUM];
}CMCPGD;

#define CMCPGD_SIZE(cmcpgd)                                          ((cmcpgd)->pgd_size)
#define CMCPGD_HEADER(cmcpgd)                                        ((cmcpgd)->pgd_hdr)
#define CMCPGD_PAGE_BLOCK_CMCPGRB_POOL(cmcpgd)                       (CMCPGD_HDR_CMCPGRB_POOL(CMCPGD_HEADER(cmcpgd)))
#define CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS_TBL(cmcpgd)         (CMCPGD_HDR_BLOCK_CMCPGRB_ROOT_POS_TBL(CMCPGD_HEADER(cmcpgd)))
#define CMCPGD_PAGE_MODEL_BLOCK_CMCPGRB_ROOT_POS(cmcpgd, page_model) (CMCPGD_HDR_BLOCK_CMCPGRB_ROOT_POS(CMCPGD_HEADER(cmcpgd), page_model))
#define CMCPGD_PAGE_MODEL_ASSIGN_BITMAP(cmcpgd)                      (CMCPGD_HDR_ASSIGN_BITMAP(CMCPGD_HEADER(cmcpgd)))
#define CMCPGD_PAGE_BLOCK_MAX_NUM(cmcpgd)                            (CMCPGD_HDR_PAGE_BLOCK_MAX_NUM(CMCPGD_HEADER(cmcpgd)))
#define CMCPGD_PAGE_MAX_NUM(cmcpgd)                                  (CMCPGD_HDR_PAGE_MAX_NUM(CMCPGD_HEADER(cmcpgd)))
#define CMCPGD_PAGE_USED_NUM(cmcpgd)                                 (CMCPGD_HDR_PAGE_USED_NUM(CMCPGD_HEADER(cmcpgd)))
#define CMCPGD_PAGE_ACTUAL_USED_SIZE(cmcpgd)                         (CMCPGD_HDR_PAGE_ACTUAL_USED_SIZE(CMCPGD_HEADER(cmcpgd)))
#define CMCPGD_BLOCK_TBL(cmcpgd)                                     ((cmcpgd)->pgd_block_tbl)
#define CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no)                        ((cmcpgd)->pgd_block_tbl[ block_no ])
#define CMCPGD_BLOCK_NODE(cmcpgd, block_no)                          ((CMCPGD_MAX_BLOCK_NUM <= (block_no)) ? NULL_PTR : CMCPGD_BLOCK_CMCPGB(cmcpgd, block_no))

const char *cmcpgd_model_str(const uint16_t pgd_block_num);
uint16_t cmcpgd_model_get(const char *model_str);

CMCPGD_HDR *cmcpgd_hdr_new(CMCPGD *cmcpgd, const uint16_t block_num);

EC_BOOL cmcpgd_hdr_free(CMCPGD *cmcpgd);

CMCPGD *cmcpgd_new(const uint16_t block_num);

EC_BOOL cmcpgd_free(CMCPGD *cmcpgd);

/* one disk = 1TB */
EC_BOOL cmcpgd_init(CMCPGD *cmcpgd);

void cmcpgd_clean(CMCPGD *cmcpgd);

/*add one free block into pool*/
EC_BOOL cmcpgd_add_block(CMCPGD *cmcpgd, const uint16_t block_no, const uint16_t page_model);

/*del one free block from pool*/
EC_BOOL cmcpgd_del_block(CMCPGD *cmcpgd, const uint16_t block_no, const uint16_t page_model);

EC_BOOL cmcpgd_new_space(CMCPGD *cmcpgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cmcpgd_free_space(CMCPGD *cmcpgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cmcpgd_is_full(const CMCPGD *cmcpgd);

EC_BOOL cmcpgd_is_empty(const CMCPGD *cmcpgd);

uint16_t cmcpgd_page_model(const CMCPGD *cmcpgd);

EC_BOOL cmcpgd_check(const CMCPGD *cmcpgd);

void cmcpgd_print(LOG *log, const CMCPGD *cmcpgd);


/* ---- debug ---- */
EC_BOOL cmcpgd_debug_cmp(const CMCPGD *cmcpgd_1st, const CMCPGD *cmcpgd_2nd);


/*-------------------------------------------- DISK in memory --------------------------------------------*/
CMCPGD *cmcpgd_mem_new(const uint16_t block_num);

EC_BOOL cmcpgd_mem_free(CMCPGD *cmcpgd);


#endif    /* _CMCPGD_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
