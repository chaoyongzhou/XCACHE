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

#ifndef    _CPGD_H
#define    _CPGD_H

/*page disk cache, one page = 4KB, one page disk = 2^14 page block = 2^14 * 64MB = 1TB*/

#include "type.h"
#include "cpgrb.h"
#include "cpgb.h"

#define CPGD_064MB_BLOCK_NUM  ((uint16_t)(1 <<  0))
#define CPGD_128MB_BLOCK_NUM  ((uint16_t)(1 <<  1))
#define CPGD_256MB_BLOCK_NUM  ((uint16_t)(1 <<  2))
#define CPGD_512MB_BLOCK_NUM  ((uint16_t)(1 <<  3))
#define CPGD_001GB_BLOCK_NUM  ((uint16_t)(1 <<  4))
#define CPGD_002GB_BLOCK_NUM  ((uint16_t)(1 <<  5))
#define CPGD_004GB_BLOCK_NUM  ((uint16_t)(1 <<  6))
#define CPGD_008GB_BLOCK_NUM  ((uint16_t)(1 <<  7))
#define CPGD_016GB_BLOCK_NUM  ((uint16_t)(1 <<  8))
#define CPGD_032GB_BLOCK_NUM  ((uint16_t)(1 <<  9))
#define CPGD_064GB_BLOCK_NUM  ((uint16_t)(1 << 10))
#define CPGD_128GB_BLOCK_NUM  ((uint16_t)(1 << 11))
#define CPGD_256GB_BLOCK_NUM  ((uint16_t)(1 << 12))
#define CPGD_512GB_BLOCK_NUM  ((uint16_t)(1 << 13))
#define CPGD_001TB_BLOCK_NUM  ((uint16_t)(1 << 14))

#define CPGD_ERROR_BLOCK_NUM  ((uint16_t)        0)

/*************************************************************
*    CPGD_MAX_BLOCK_NUM   : how many blocks per disk
*    CPGD_BLOCK_PAGE_MODEL: how many MB per block
*    CPGD_BLOCK_PAGE_NUM  : how many pages per block
*************************************************************/

#define CPGD_TEST_SCENARIO_256M_DISK     (1)
#define CPGD_TEST_SCENARIO_512M_DISK     (2)
#define CPGD_TEST_SCENARIO_032G_DISK     (3)
#define CPGD_TEST_SCENARIO_512G_DISK     (4)
#define CPGD_TEST_SCENARIO_001T_DISK     (5)

#if (32 == WORDSIZE)
#define CPGD_DEBUG_CHOICE CPGD_TEST_SCENARIO_512M_DISK
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
#define CPGD_DEBUG_CHOICE CPGD_TEST_SCENARIO_032G_DISK
//#define CPGD_DEBUG_CHOICE CPGD_TEST_SCENARIO_512G_DISK
//#define CPGD_DEBUG_CHOICE CPGD_TEST_SCENARIO_001T_DISK
#endif/*(64 == WORDSIZE)*/

#if (CPGD_TEST_SCENARIO_001T_DISK == CPGD_DEBUG_CHOICE)
#define CPGD_MAX_BLOCK_NUM               (CPGD_001TB_BLOCK_NUM)
#define CPGD_BLOCK_PAGE_MODEL            (CPGB_064MB_MODEL)
#define CPGD_BLOCK_PAGE_NUM              (CPGB_064MB_PAGE_NUM)
#endif/*(CPGD_TEST_SCENARIO_001T_DISK == CPGD_DEBUG_CHOICE)*/

#if (CPGD_TEST_SCENARIO_512G_DISK == CPGD_DEBUG_CHOICE)
#define CPGD_MAX_BLOCK_NUM               (CPGD_512GB_BLOCK_NUM)
#define CPGD_BLOCK_PAGE_MODEL            (CPGB_064MB_MODEL)
#define CPGD_BLOCK_PAGE_NUM              (CPGB_064MB_PAGE_NUM)
#endif/*(CPGD_TEST_SCENARIO_032G_DISK == CPGD_DEBUG_CHOICE)*/

#if (CPGD_TEST_SCENARIO_256M_DISK == CPGD_DEBUG_CHOICE)
#define CPGD_MAX_BLOCK_NUM               (CPGD_256MB_BLOCK_NUM)
#define CPGD_BLOCK_PAGE_MODEL            (CPGB_064MB_MODEL)
#define CPGD_BLOCK_PAGE_NUM              (CPGB_064MB_PAGE_NUM)
#endif/*(CPGD_TEST_SCENARIO_256M_DISK == CPGD_DEBUG_CHOICE)*/

#if (CPGD_TEST_SCENARIO_512M_DISK == CPGD_DEBUG_CHOICE)
#define CPGD_MAX_BLOCK_NUM               (CPGD_512MB_BLOCK_NUM)
#define CPGD_BLOCK_PAGE_MODEL            (CPGB_064MB_MODEL)
#define CPGD_BLOCK_PAGE_NUM              (CPGB_064MB_PAGE_NUM)
#endif/*(CPGD_TEST_SCENARIO_512M_DISK == CPGD_DEBUG_CHOICE)*/

#if (CPGD_TEST_SCENARIO_032G_DISK == CPGD_DEBUG_CHOICE)
#define CPGD_MAX_BLOCK_NUM               (CPGD_032GB_BLOCK_NUM)
#define CPGD_BLOCK_PAGE_MODEL            (CPGB_064MB_MODEL)
#define CPGD_BLOCK_PAGE_NUM              (CPGB_064MB_PAGE_NUM)
#endif/*(CPGD_TEST_SCENARIO_032G_DISK == CPGD_DEBUG_CHOICE)*/

#define CPGD_PAGE_BLOCK_IS_FREE          ((uint8_t) 1)
#define CPGD_PAGE_BLOCK_IS_NOT_FREE      ((uint8_t) 0)

#define CPGD_HDR_PAD_SIZE                (4040)

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    uint16_t       block_num;
    uint16_t       rsvd01;
    uint32_t       rsvd02;
}CPGD_CFG;

#define CPGD_CFG_MODEL_STR(cpgd_cfg)     ((cpgd_cfg)->model_str)
#define CPGD_CFG_ALIAS_STR(cpgd_cfg)     ((cpgd_cfg)->alias_str)
#define CPGD_CFG_BLOCK_NUM(cpgd_cfg)     ((cpgd_cfg)->block_num)


typedef struct
{
    CPGRB_POOL   pgd_block_rb_pool;

    uint16_t     pgd_block_rb_root_pos[ CPGB_MODEL_NUM ];/*root pos of rbtree*/
    uint16_t     rsvd1;

    uint16_t     pgd_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/
    uint16_t     pgd_block_max_num; /*max block number */
    uint32_t     rsvd2;

    uint32_t     pgd_page_max_num; /*max pages number */
    uint32_t     pgd_page_used_num;/*used pages number*/
    uint64_t     pgd_actual_used_size;/*actual used bytes*/

    uint8_t      rsvd3[CPGD_HDR_PAD_SIZE];
}CPGD_HDR;/*4k-alignment*/

#define CPGD_HDR_CPGRB_POOL(cpgd_hdr)                           (&((cpgd_hdr)->pgd_block_rb_pool))
#define CPGD_HDR_BLOCK_CPGRB_ROOT_POS_TBL(cpgd_hdr)             ((cpgd_hdr)->pgd_block_rb_root_pos)
#define CPGD_HDR_BLOCK_CPGRB_ROOT_POS(cpgd_hdr, page_model)     ((cpgd_hdr)->pgd_block_rb_root_pos[ (page_model) ])
#define CPGD_HDR_ASSIGN_BITMAP(cpgd_hdr)                        ((cpgd_hdr)->pgd_assign_bitmap)
#define CPGD_HDR_PAGE_BLOCK_MAX_NUM(cpgd_hdr)                   ((cpgd_hdr)->pgd_block_max_num)
#define CPGD_HDR_PAGE_MAX_NUM(cpgd_hdr)                         ((cpgd_hdr)->pgd_page_max_num)
#define CPGD_HDR_PAGE_USED_NUM(cpgd_hdr)                        ((cpgd_hdr)->pgd_page_used_num)
#define CPGD_HDR_PAGE_ACTUAL_USED_SIZE(cpgd_hdr)                ((cpgd_hdr)->pgd_actual_used_size)


typedef struct
{
    int          pgd_fd;
    int          rsvd1;
    uint8_t     *pgd_fname;
    uint32_t     pgd_fsize;
    uint32_t     rsvd2;
    CPGD_HDR    *pgd_hdr;
    CPGB        *pgd_block_tbl[CPGD_MAX_BLOCK_NUM];
}CPGD;

#define CPGD_FD(cpgd)                                            ((cpgd)->pgd_fd)
#define CPGD_FNAME(cpgd)                                         ((cpgd)->pgd_fname)
#define CPGD_FSIZE(cpgd)                                         ((cpgd)->pgd_fsize)
#define CPGD_HEADER(cpgd)                                        ((cpgd)->pgd_hdr)
#define CPGD_PAGE_BLOCK_CPGRB_POOL(cpgd)                         (CPGD_HDR_CPGRB_POOL(CPGD_HEADER(cpgd)))
#define CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS_TBL(cpgd)           (CPGD_HDR_BLOCK_CPGRB_ROOT_POS_TBL(CPGD_HEADER(cpgd)))
#define CPGD_PAGE_MODEL_BLOCK_CPGRB_ROOT_POS(cpgd, page_model)   (CPGD_HDR_BLOCK_CPGRB_ROOT_POS(CPGD_HEADER(cpgd), page_model))
#define CPGD_PAGE_MODEL_ASSIGN_BITMAP(cpgd)                      (CPGD_HDR_ASSIGN_BITMAP(CPGD_HEADER(cpgd)))
#define CPGD_PAGE_BLOCK_MAX_NUM(cpgd)                            (CPGD_HDR_PAGE_BLOCK_MAX_NUM(CPGD_HEADER(cpgd)))
#define CPGD_PAGE_MAX_NUM(cpgd)                                  (CPGD_HDR_PAGE_MAX_NUM(CPGD_HEADER(cpgd)))
#define CPGD_PAGE_USED_NUM(cpgd)                                 (CPGD_HDR_PAGE_USED_NUM(CPGD_HEADER(cpgd)))
#define CPGD_PAGE_ACTUAL_USED_SIZE(cpgd)                         (CPGD_HDR_PAGE_ACTUAL_USED_SIZE(CPGD_HEADER(cpgd)))
#define CPGD_BLOCK_TBL(cpgd)                                     ((cpgd)->pgd_block_tbl)
#define CPGD_BLOCK_CPGB(cpgd, block_no)                          ((cpgd)->pgd_block_tbl[ block_no ])
#define CPGD_BLOCK_NODE(cpgd, block_no)                          ((CPGD_MAX_BLOCK_NUM <= (block_no)) ? NULL_PTR : CPGD_BLOCK_CPGB(cpgd, block_no))

const char *cpgd_model_str(const uint16_t pgd_block_num);
uint16_t cpgd_model_get(const char *model_str);

CPGD_HDR *cpgd_hdr_mem_new(CPGD *cpgd, const uint16_t block_num);

EC_BOOL cpgd_hdr_mem_free(CPGD *cpgd);

CPGD_HDR *cpgd_hdr_new(CPGD *cpgd, const uint16_t block_num);

EC_BOOL cpgd_hdr_free(CPGD *cpgd);

CPGD_HDR *cpgd_hdr_open(CPGD *cpgd);

EC_BOOL cpgd_hdr_close(CPGD *cpgd);

EC_BOOL cpgd_hdr_sync(CPGD *cpgd);

CPGD *cpgd_new(const uint8_t *cpgd_fname, const uint16_t block_num);

EC_BOOL cpgd_free(CPGD *cpgd);

EC_BOOL cpgd_exist(const uint8_t *cpgd_fname);

EC_BOOL cpgd_rmv(const uint8_t *cpgd_fname);

CPGD *cpgd_open(const uint8_t *cpgd_fname);

EC_BOOL cpgd_close(CPGD *cpgd);

EC_BOOL cpgd_sync(CPGD *cpgd);

/* one disk = 1TB */
EC_BOOL cpgd_init(CPGD *cpgd);

void cpgd_clean(CPGD *cpgd);

/*add one free block into pool*/
EC_BOOL cpgd_add_block(CPGD *cpgd, const uint16_t block_no, const uint16_t page_model);

/*del one free block from pool*/
EC_BOOL cpgd_del_block(CPGD *cpgd, const uint16_t block_no, const uint16_t page_model);

EC_BOOL cpgd_new_space(CPGD *cpgd, const uint32_t size, uint16_t *block_no, uint16_t *page_no);

EC_BOOL cpgd_free_space(CPGD *cpgd, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

EC_BOOL cpgd_is_full(const CPGD *cpgd);

EC_BOOL cpgd_is_empty(const CPGD *cpgd);

uint16_t cpgd_page_model(const CPGD *cpgd);

EC_BOOL cpgd_flush_size(const CPGD *cpgd, UINT32 *size);

EC_BOOL cpgd_flush(const CPGD *cpgd, int fd, UINT32 *offset);

EC_BOOL cpgd_load(CPGD *cpgd, int fd, UINT32 *offset);

EC_BOOL cpgd_check(const CPGD *cpgd);

void cpgd_print(LOG *log, const CPGD *cpgd);

CPGD *cpgd_new(const uint8_t *cpgd_dat_file, const uint16_t block_num);

EC_BOOL cpgd_free(CPGD *cpgd);

EC_BOOL cpgd_close(CPGD *cpgd);


/* ---- debug ---- */
EC_BOOL cpgd_debug_cmp(const CPGD *cpgd_1st, const CPGD *cpgd_2nd);


/*-------------------------------------------- DISK in memory --------------------------------------------*/
CPGD *cpgd_mem_new(const uint16_t block_num);

EC_BOOL cpgd_mem_free(CPGD *cpgd);


#endif    /* _CPGD_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
