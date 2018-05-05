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

#ifndef    _CPGB_H
#define    _CPGB_H

/*page cache, one page = 4KB, one page cache = 64MB*/

#include "type.h"
#include "cpgrb.h"

/*page model*/
#define CPGB_064MB_MODEL    ((uint16_t) 0)
#define CPGB_032MB_MODEL    ((uint16_t) 1)
#define CPGB_016MB_MODEL    ((uint16_t) 2)
#define CPGB_008MB_MODEL    ((uint16_t) 3)
#define CPGB_004MB_MODEL    ((uint16_t) 4)
#define CPGB_002MB_MODEL    ((uint16_t) 5)
#define CPGB_001MB_MODEL    ((uint16_t) 6)
#define CPGB_512KB_MODEL    ((uint16_t) 7)
#define CPGB_256KB_MODEL    ((uint16_t) 8)
#define CPGB_128KB_MODEL    ((uint16_t) 9)
#define CPGB_064KB_MODEL    ((uint16_t)10)
#define CPGB_032KB_MODEL    ((uint16_t)11)
#define CPGB_016KB_MODEL    ((uint16_t)12)
#define CPGB_008KB_MODEL    ((uint16_t)13)
#define CPGB_004KB_MODEL    ((uint16_t)14)
#define CPGB_MODEL_NUM      ((uint16_t)15)
#define CPGB_MODEL_MASK_ALL ((uint16_t)0x7FFF)

/*num of bytes represent the bitmap*/
#define CPGB_064MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CPGB_032MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CPGB_016MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CPGB_008MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CPGB_004MB_BITMAP_SIZE  ((uint16_t)(1 <<  1))
#define CPGB_002MB_BITMAP_SIZE  ((uint16_t)(1 <<  2))
#define CPGB_001MB_BITMAP_SIZE  ((uint16_t)(1 <<  3))
#define CPGB_512KB_BITMAP_SIZE  ((uint16_t)(1 <<  4))
#define CPGB_256KB_BITMAP_SIZE  ((uint16_t)(1 <<  5))
#define CPGB_128KB_BITMAP_SIZE  ((uint16_t)(1 <<  6))
#define CPGB_064KB_BITMAP_SIZE  ((uint16_t)(1 <<  7))
#define CPGB_032KB_BITMAP_SIZE  ((uint16_t)(1 <<  8))
#define CPGB_016KB_BITMAP_SIZE  ((uint16_t)(1 <<  9))
#define CPGB_008KB_BITMAP_SIZE  ((uint16_t)(1 << 10))
#define CPGB_004KB_BITMAP_SIZE  ((uint16_t)(1 << 11))

/*------------------4k-page beg ------------------------*/
#define CPGB_064MB_PAGE_4K_NUM  ((uint16_t)(1 << 14))
#define CPGB_032MB_PAGE_4K_NUM  ((uint16_t)(1 << 13))
#define CPGB_016MB_PAGE_4K_NUM  ((uint16_t)(1 << 12))
#define CPGB_008MB_PAGE_4K_NUM  ((uint16_t)(1 << 11))
#define CPGB_004MB_PAGE_4K_NUM  ((uint16_t)(1 << 10))
#define CPGB_002MB_PAGE_4K_NUM  ((uint16_t)(1 <<  9))
#define CPGB_001MB_PAGE_4K_NUM  ((uint16_t)(1 <<  8))
#define CPGB_512KB_PAGE_4K_NUM  ((uint16_t)(1 <<  7))
#define CPGB_256KB_PAGE_4K_NUM  ((uint16_t)(1 <<  6))
#define CPGB_128KB_PAGE_4K_NUM  ((uint16_t)(1 <<  5))
#define CPGB_064KB_PAGE_4K_NUM  ((uint16_t)(1 <<  4))
#define CPGB_032KB_PAGE_4K_NUM  ((uint16_t)(1 <<  3))
#define CPGB_016KB_PAGE_4K_NUM  ((uint16_t)(1 <<  2))
#define CPGB_008KB_PAGE_4K_NUM  ((uint16_t)(1 <<  1))
#define CPGB_004KB_PAGE_4K_NUM  ((uint16_t)(1 <<  0))

#define CPGB_PAGE_4K_BIT_SIZE         ((uint32_t)12)
#define CPGB_PAGE_4K_BYTE_SIZE        ((uint32_t)(1 << CPGB_PAGE_4K_BIT_SIZE))

#define CPGB_PAGE_4K_HI_BIT_MASK      ((uint16_t)0x4000)     /*for 2k-page, is 0x8000*/
#define CPGB_PAGE_4K_LO_BITS_MASK     ((uint16_t)0x3FFF)     /*for 2k-page, is 0x7FFF*/
/*------------------4k-page end ------------------------*/

/*------------------8k-page beg ------------------------*/
#define CPGB_064MB_PAGE_8K_NUM  ((uint16_t)(1 << 13))
#define CPGB_032MB_PAGE_8K_NUM  ((uint16_t)(1 << 12))
#define CPGB_016MB_PAGE_8K_NUM  ((uint16_t)(1 << 11))
#define CPGB_008MB_PAGE_8K_NUM  ((uint16_t)(1 << 10))
#define CPGB_004MB_PAGE_8K_NUM  ((uint16_t)(1 <<  9))
#define CPGB_002MB_PAGE_8K_NUM  ((uint16_t)(1 <<  8))
#define CPGB_001MB_PAGE_8K_NUM  ((uint16_t)(1 <<  7))
#define CPGB_512KB_PAGE_8K_NUM  ((uint16_t)(1 <<  6))
#define CPGB_256KB_PAGE_8K_NUM  ((uint16_t)(1 <<  5))
#define CPGB_128KB_PAGE_8K_NUM  ((uint16_t)(1 <<  4))
#define CPGB_068KB_PAGE_8K_NUM  ((uint16_t)(1 <<  3))
#define CPGB_032KB_PAGE_8K_NUM  ((uint16_t)(1 <<  2))
#define CPGB_016KB_PAGE_8K_NUM  ((uint16_t)(1 <<  2))
#define CPGB_008KB_PAGE_8K_NUM  ((uint16_t)(1 <<  0))
#define CPGB_004KB_PAGE_8K_NUM  ((uint16_t)(0)) /*xxx*/

#define CPGB_PAGE_8K_BIT_SIZE         ((uint32_t)13)
#define CPGB_PAGE_8K_BYTE_SIZE        ((uint32_t)(1 << CPGB_PAGE_8K_BIT_SIZE))

#define CPGB_PAGE_8K_HI_BIT_MASK      ((uint16_t)0x2000)
#define CPGB_PAGE_8K_LO_BITS_MASK     ((uint16_t)0x1FFF)
/*------------------8k-page end ------------------------*/

#define CPGB_RB_BITMAP_OFFSET_OF_064MB_MODEL ((uint16_t)0)
#define CPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_064MB_MODEL + CPGB_064MB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL + CPGB_032MB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL + CPGB_016MB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL + CPGB_008MB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL + CPGB_004MB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL + CPGB_002MB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL + CPGB_001MB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL + CPGB_512KB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL + CPGB_256KB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL + CPGB_128KB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL + CPGB_064KB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL + CPGB_032KB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL + CPGB_016KB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL (CPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL + CPGB_008KB_BITMAP_SIZE)
#define CPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL (CPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL + CPGB_004KB_BITMAP_SIZE)

#define CPGB_RB_BITMAP_SIZE                  (CPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL)/*=4098*/
#define CPGB_RB_BITMAP_PAD_SIZE              (8 - (CPGB_RB_BITMAP_SIZE & 7))/*=4098*/

#define CPGB_CACHE_BIT_SIZE           ((uint32_t)26) /*64MB*/
#define CPGB_CACHE_MAX_BYTE_SIZE      ((uint32_t)(1 << CPGB_CACHE_BIT_SIZE)) /*64MB*/

/*--------------------------------------------------------------------------------------------*/
#if 1 /*for 4k-page*/
#define CPGB_064MB_PAGE_NUM           (CPGB_064MB_PAGE_4K_NUM)
#define CPGB_032MB_PAGE_NUM           (CPGB_032MB_PAGE_4K_NUM)
#define CPGB_016MB_PAGE_NUM           (CPGB_016MB_PAGE_4K_NUM)
#define CPGB_008MB_PAGE_NUM           (CPGB_008MB_PAGE_4K_NUM)
#define CPGB_004MB_PAGE_NUM           (CPGB_004MB_PAGE_4K_NUM)
#define CPGB_002MB_PAGE_NUM           (CPGB_002MB_PAGE_4K_NUM)
#define CPGB_001MB_PAGE_NUM           (CPGB_001MB_PAGE_4K_NUM)
#define CPGB_512KB_PAGE_NUM           (CPGB_512KB_PAGE_4K_NUM)
#define CPGB_256KB_PAGE_NUM           (CPGB_256KB_PAGE_4K_NUM)
#define CPGB_128KB_PAGE_NUM           (CPGB_128KB_PAGE_4K_NUM)
#define CPGB_064KB_PAGE_NUM           (CPGB_064KB_PAGE_4K_NUM)
#define CPGB_032KB_PAGE_NUM           (CPGB_032KB_PAGE_4K_NUM)
#define CPGB_016KB_PAGE_NUM           (CPGB_016KB_PAGE_4K_NUM)
#define CPGB_008KB_PAGE_NUM           (CPGB_008KB_PAGE_4K_NUM)
#define CPGB_004KB_PAGE_NUM           (CPGB_004KB_PAGE_4K_NUM)

#define CPGB_PAGE_BIT_SIZE            (CPGB_PAGE_4K_BIT_SIZE)
#define CPGB_PAGE_BYTE_SIZE           (CPGB_PAGE_4K_BYTE_SIZE)

#define CPGB_PAGE_HI_BIT_MASK         (CPGB_PAGE_4K_HI_BIT_MASK)
#define CPGB_PAGE_LO_BITS_MASK        (CPGB_PAGE_4K_LO_BITS_MASK)
#endif

#if 0 /*for 8k-page*/
#define CPGB_064MB_PAGE_NUM           (CPGB_064MB_PAGE_8K_NUM)
#define CPGB_032MB_PAGE_NUM           (CPGB_032MB_PAGE_8K_NUM)
#define CPGB_016MB_PAGE_NUM           (CPGB_016MB_PAGE_8K_NUM)
#define CPGB_008MB_PAGE_NUM           (CPGB_008MB_PAGE_8K_NUM)
#define CPGB_004MB_PAGE_NUM           (CPGB_004MB_PAGE_8K_NUM)
#define CPGB_002MB_PAGE_NUM           (CPGB_002MB_PAGE_8K_NUM)
#define CPGB_001MB_PAGE_NUM           (CPGB_001MB_PAGE_8K_NUM)
#define CPGB_512KB_PAGE_NUM           (CPGB_512KB_PAGE_8K_NUM)
#define CPGB_256KB_PAGE_NUM           (CPGB_256KB_PAGE_8K_NUM)
#define CPGB_128KB_PAGE_NUM           (CPGB_128KB_PAGE_8K_NUM)
#define CPGB_064KB_PAGE_NUM           (CPGB_068KB_PAGE_8K_NUM)
#define CPGB_032KB_PAGE_NUM           (CPGB_032KB_PAGE_8K_NUM)
#define CPGB_016KB_PAGE_NUM           (CPGB_016KB_PAGE_8K_NUM)
#define CPGB_008KB_PAGE_NUM           (CPGB_008KB_PAGE_8K_NUM)
#define CPGB_004KB_PAGE_NUM           (CPGB_008KB_PAGE_8K_NUM)

#define CPGB_PAGE_BIT_SIZE            (CPGB_PAGE_8K_BIT_SIZE)
#define CPGB_PAGE_BYTE_SIZE           (CPGB_PAGE_8K_BYTE_SIZE)

#define CPGB_PAGE_HI_BIT_MASK         (CPGB_PAGE_8K_HI_BIT_MASK)
#define CPGB_PAGE_LO_BITS_MASK        (CPGB_PAGE_8K_LO_BITS_MASK)
#endif

/*--------------------------------------------------------------------------------------------*/


#define CPGB_PAGE_IS_FREE             ((uint8_t) 1)
#define CPGB_PAGE_IS_NOT_FREE         ((uint8_t) 0)

#define CPGB_PAD_SIZE                 (4040)

typedef struct
{
    CPGRB_POOL   pgb_rb_pool;

    uint8_t      pgb_rb_bitmap_buff[ CPGB_RB_BITMAP_SIZE ];
    uint8_t      rsvd1[CPGB_RB_BITMAP_PAD_SIZE];

    uint16_t     pgb_rb_root_pos[ CPGB_MODEL_NUM ];/*root pos of rbtree*/
    uint16_t     pgb_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/

    uint16_t     pgb_page_max_num; /*max page number*/
    uint16_t     pgb_page_used_num;/*used page number*/
    uint32_t     pgb_actual_used_size;/*actual used bytes*/

    uint8_t      rsvd[CPGB_PAD_SIZE];
}CPGB;/*4k-alignment*/

#define CPGB_CPGRB_POOL(cpgb)                              (&((cpgb)->pgb_rb_pool))
#define CPGB_PAGE_MODEL_CPGRB_ROOT_POS_TBL(cpgb)           ((cpgb)->pgb_rb_root_pos)
#define CPGB_PAGE_MODEL_CPGRB_ROOT_POS(cpgb, page_model)   ((cpgb)->pgb_rb_root_pos[ (page_model) ])
#define CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF(cpgb)            ((cpgb)->pgb_rb_bitmap_buff)
#define CPGB_PAGE_MODEL_CPGRB_BITMAP(cpgb, page_model)     ((uint8_t *)CPGB_PAGE_MODEL_CPGRB_BITMAP_BUFF(cpgb) + g_pgb_bitmap_offset[ (page_model)])
#define CPGB_PAGE_MODEL_ASSIGN_BITMAP(cpgb)                ((cpgb)->pgb_assign_bitmap)
#define CPGB_PAGE_MAX_NUM(cpgb)                            ((cpgb)->pgb_page_max_num)
#define CPGB_PAGE_USED_NUM(cpgb)                           ((cpgb)->pgb_page_used_num)
#define CPGB_PAGE_ACTUAL_USED_SIZE(cpgb)                   ((cpgb)->pgb_actual_used_size)

typedef struct
{
    const char *name;
    uint16_t    page_model;
    uint16_t    cpgrb_bitmap_size;
    uint16_t    page_num;
    uint16_t    rsvd;
}CPGB_CONF;

#define CPGB_CONF_NAME(cpgb_conf)               ((cpgb_conf)->name)
#define CPGB_CONF_PAGE_MODEL(cpgb_conf)         ((cpgb_conf)->page_model)
#define CPGB_CONF_CPGRB_BITMAP_SIZE(cpgb_conf)  ((cpgb_conf)->cpgrb_bitmap_size)
#define CPGB_CONF_PAGE_NUM(cpgb_conf)           ((cpgb_conf)->page_num)


CPGB *cpgb_new(const uint16_t page_model_target);

/* one page cache = 64MB */
EC_BOOL cpgb_init(CPGB *cpgb, const uint16_t page_model_target);

void cpgb_clean(CPGB *cpgb);

EC_BOOL cpgb_free(CPGB *cpgb);

/*add one free page into pool and set page model bitmap*/
EC_BOOL cpgb_add_page(CPGB *cpgb, const uint16_t page_model, const uint16_t page_no);

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cpgb_del_page(CPGB *cpgb, const uint16_t page_model, const uint16_t page_no);

uint16_t cpgb_assign_page(CPGB *cpgb, const uint16_t page_model);

EC_BOOL cpgb_recycle_page(CPGB *cpgb, const uint16_t page_model, const uint16_t page_no);

EC_BOOL cpgb_new_space(CPGB *cpgb, const uint32_t size, uint16_t *page_no);

EC_BOOL cpgb_free_space(CPGB *cpgb, const uint16_t page_start_no, const uint32_t size);

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cpgb_is_full(const CPGB *cpgb);

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cpgb_is_empty(const CPGB *cpgb);

EC_BOOL cpgb_check(const CPGB *cpgb);

void cpgb_print(LOG *log, const CPGB *cpgb);

EC_BOOL cpgb_flush_size(const CPGB *cpgb, UINT32 *size);

EC_BOOL cpgb_flush(const CPGB *cpgb, int fd, UINT32 *offset);

EC_BOOL cpgb_load(CPGB *cpgb, int fd, UINT32 *offset);

EC_BOOL cpgb_debug_cmp(const CPGB *cpgb_1st, const CPGB *cpgb_2nd);

#endif    /* _CPGB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
