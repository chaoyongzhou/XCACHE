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

#ifndef    _CSFSB_H
#define    _CSFSB_H

#include "type.h"

#define CSFSB_ERR_POS        ((uint16_t)0x7FFF)/*15 bits*/

/*------------------4k-page beg ------------------------*/
#define CSFSB_064MB_PAGE_4K_NUM  ((uint16_t)(1 << 14))
#define CSFSB_032MB_PAGE_4K_NUM  ((uint16_t)(1 << 13))
#define CSFSB_016MB_PAGE_4K_NUM  ((uint16_t)(1 << 12))
#define CSFSB_008MB_PAGE_4K_NUM  ((uint16_t)(1 << 11))
#define CSFSB_004MB_PAGE_4K_NUM  ((uint16_t)(1 << 10))
#define CSFSB_002MB_PAGE_4K_NUM  ((uint16_t)(1 <<  9))
#define CSFSB_001MB_PAGE_4K_NUM  ((uint16_t)(1 <<  8))
#define CSFSB_512KB_PAGE_4K_NUM  ((uint16_t)(1 <<  7))
#define CSFSB_256KB_PAGE_4K_NUM  ((uint16_t)(1 <<  6))
#define CSFSB_128KB_PAGE_4K_NUM  ((uint16_t)(1 <<  5))
#define CSFSB_064KB_PAGE_4K_NUM  ((uint16_t)(1 <<  4))
#define CSFSB_032KB_PAGE_4K_NUM  ((uint16_t)(1 <<  3))
#define CSFSB_016KB_PAGE_4K_NUM  ((uint16_t)(1 <<  2))
#define CSFSB_008KB_PAGE_4K_NUM  ((uint16_t)(1 <<  1))
#define CSFSB_004KB_PAGE_4K_NUM  ((uint16_t)(1 <<  0))

#define CSFSB_PAGE_4K_BIT_SIZE         ((uint32_t)12)
#define CSFSB_PAGE_4K_BYTE_SIZE        ((uint32_t)(1 << CSFSB_PAGE_4K_BIT_SIZE))

#define CSFSB_PAGE_4K_HI_BIT_MASK      ((uint16_t)0x4000)     /*for 2k-page, is 0x8000*/
#define CSFSB_PAGE_4K_LO_BITS_MASK     ((uint16_t)0x3FFF)     /*for 2k-page, is 0x7FFF*/
/*------------------4k-page end ------------------------*/

/*------------------8k-page beg ------------------------*/
#define CSFSB_064MB_PAGE_8K_NUM  ((uint16_t)(1 << 13))
#define CSFSB_032MB_PAGE_8K_NUM  ((uint16_t)(1 << 12))
#define CSFSB_016MB_PAGE_8K_NUM  ((uint16_t)(1 << 11))
#define CSFSB_008MB_PAGE_8K_NUM  ((uint16_t)(1 << 10))
#define CSFSB_004MB_PAGE_8K_NUM  ((uint16_t)(1 <<  9))
#define CSFSB_002MB_PAGE_8K_NUM  ((uint16_t)(1 <<  8))
#define CSFSB_001MB_PAGE_8K_NUM  ((uint16_t)(1 <<  7))
#define CSFSB_512KB_PAGE_8K_NUM  ((uint16_t)(1 <<  6))
#define CSFSB_256KB_PAGE_8K_NUM  ((uint16_t)(1 <<  5))
#define CSFSB_128KB_PAGE_8K_NUM  ((uint16_t)(1 <<  4))
#define CSFSB_068KB_PAGE_8K_NUM  ((uint16_t)(1 <<  3))
#define CSFSB_032KB_PAGE_8K_NUM  ((uint16_t)(1 <<  2))
#define CSFSB_016KB_PAGE_8K_NUM  ((uint16_t)(1 <<  2))
#define CSFSB_008KB_PAGE_8K_NUM  ((uint16_t)(1 <<  0))
#define CSFSB_004KB_PAGE_8K_NUM  ((uint16_t)(0)) /*xxx*/

#define CSFSB_PAGE_8K_BIT_SIZE         ((uint32_t)13)
#define CSFSB_PAGE_8K_BYTE_SIZE        ((uint32_t)(1 << CSFSB_PAGE_8K_BIT_SIZE))

#define CSFSB_PAGE_8K_HI_BIT_MASK      ((uint16_t)0x2000)
#define CSFSB_PAGE_8K_LO_BITS_MASK     ((uint16_t)0x1FFF)
/*------------------8k-page end ------------------------*/

#define CSFSB_CACHE_BIT_SIZE           ((uint32_t)26) /*64MB*/
#define CSFSB_CACHE_MAX_BYTE_SIZE      ((uint32_t)(1 << CSFSB_CACHE_BIT_SIZE)) /*64MB*/

/*--------------------------------------------------------------------------------------------*/
#if 1 /*for 4k-page*/
#define CSFSB_064MB_PAGE_NUM           (CSFSB_064MB_PAGE_4K_NUM)
#define CSFSB_032MB_PAGE_NUM           (CSFSB_032MB_PAGE_4K_NUM)
#define CSFSB_016MB_PAGE_NUM           (CSFSB_016MB_PAGE_4K_NUM)
#define CSFSB_008MB_PAGE_NUM           (CSFSB_008MB_PAGE_4K_NUM)
#define CSFSB_004MB_PAGE_NUM           (CSFSB_004MB_PAGE_4K_NUM)
#define CSFSB_002MB_PAGE_NUM           (CSFSB_002MB_PAGE_4K_NUM)
#define CSFSB_001MB_PAGE_NUM           (CSFSB_001MB_PAGE_4K_NUM)
#define CSFSB_512KB_PAGE_NUM           (CSFSB_512KB_PAGE_4K_NUM)
#define CSFSB_256KB_PAGE_NUM           (CSFSB_256KB_PAGE_4K_NUM)
#define CSFSB_128KB_PAGE_NUM           (CSFSB_128KB_PAGE_4K_NUM)
#define CSFSB_064KB_PAGE_NUM           (CSFSB_064KB_PAGE_4K_NUM)
#define CSFSB_032KB_PAGE_NUM           (CSFSB_032KB_PAGE_4K_NUM)
#define CSFSB_016KB_PAGE_NUM           (CSFSB_016KB_PAGE_4K_NUM)
#define CSFSB_008KB_PAGE_NUM           (CSFSB_008KB_PAGE_4K_NUM)
#define CSFSB_004KB_PAGE_NUM           (CSFSB_004KB_PAGE_4K_NUM)

#define CSFSB_PAGE_BIT_SIZE            (CSFSB_PAGE_4K_BIT_SIZE)
#define CSFSB_PAGE_BYTE_SIZE           (CSFSB_PAGE_4K_BYTE_SIZE)

#define CSFSB_PAGE_HI_BIT_MASK         (CSFSB_PAGE_4K_HI_BIT_MASK)
#define CSFSB_PAGE_LO_BITS_MASK        (CSFSB_PAGE_4K_LO_BITS_MASK)

#endif


#if 0 /*for 8k-page*/
#define CSFSB_064MB_PAGE_NUM           (CSFSB_064MB_PAGE_8K_NUM)
#define CSFSB_032MB_PAGE_NUM           (CSFSB_032MB_PAGE_8K_NUM)
#define CSFSB_016MB_PAGE_NUM           (CSFSB_016MB_PAGE_8K_NUM)
#define CSFSB_008MB_PAGE_NUM           (CSFSB_008MB_PAGE_8K_NUM)
#define CSFSB_004MB_PAGE_NUM           (CSFSB_004MB_PAGE_8K_NUM)
#define CSFSB_002MB_PAGE_NUM           (CSFSB_002MB_PAGE_8K_NUM)
#define CSFSB_001MB_PAGE_NUM           (CSFSB_001MB_PAGE_8K_NUM)
#define CSFSB_512KB_PAGE_NUM           (CSFSB_512KB_PAGE_8K_NUM)
#define CSFSB_256KB_PAGE_NUM           (CSFSB_256KB_PAGE_8K_NUM)
#define CSFSB_128KB_PAGE_NUM           (CSFSB_128KB_PAGE_8K_NUM)
#define CSFSB_064KB_PAGE_NUM           (CSFSB_068KB_PAGE_8K_NUM)
#define CSFSB_032KB_PAGE_NUM           (CSFSB_032KB_PAGE_8K_NUM)
#define CSFSB_016KB_PAGE_NUM           (CSFSB_016KB_PAGE_8K_NUM)
#define CSFSB_008KB_PAGE_NUM           (CSFSB_008KB_PAGE_8K_NUM)
#define CSFSB_004KB_PAGE_NUM           (CSFSB_008KB_PAGE_8K_NUM)

#define CSFSB_PAGE_BIT_SIZE            (CSFSB_PAGE_8K_BIT_SIZE)
#define CSFSB_PAGE_BYTE_SIZE           (CSFSB_PAGE_8K_BYTE_SIZE)

#define CSFSB_PAGE_HI_BIT_MASK         (CSFSB_PAGE_8K_HI_BIT_MASK)
#define CSFSB_PAGE_LO_BITS_MASK        (CSFSB_PAGE_8K_LO_BITS_MASK)
#endif

/*--------------------------------------------------------------------------------------------*/

/*note: let block = 64MB. otherwise, CSFSD_XXX_BLOCK_NUM must be adjusted*/
#define CSFSB_PAGE_NUM                 (CSFSB_064MB_PAGE_NUM)

#define CSFSB_PAD_SIZE                 (2046)


#define CSFSB_PAGE_NP_NODE_POS_CHECK(np_id, np_node_pos)   ASSERT(0 == ((np_id) & (~0x3)) && 0 == ((np_node_pos) & (0xC0000000)))

#define CSFSB_PAGE_NP_NODE_POS_MAKE(np_id, np_node_pos)    (((np_id) << 30) | ((np_node_pos) & 0x3FFFFFFF))

#define CSFSB_PAGE_NP_NODE_POS_TO_NP_ID(__np_node_pos)     ((__np_node_pos) >> 30)

#define CSFSB_PAGE_NP_NODE_POS_TO_POS(__np_node_pos)       ((__np_node_pos) & 0x3FFFFFFF)

typedef struct
{
    /*2KB*/
    uint16_t     sfsb_page_max_num; /*max page number*/
    uint8_t      rsvd01[ CSFSB_PAD_SIZE ];

    /*2KB*/
    uint32_t     sfsb_page_used_bitmap[ CSFSB_PAGE_NUM >> 5 ]; /*one bit for one page.*/
                                                               /*note: only the first page of the stored file should set to used, i.e. 1*/
                                                               /*note: bit 0 means the page is not used, or is used and part of a stored file*/
    /*64KB*/
    uint32_t     sfsb_page_np_node_pos[ CSFSB_PAGE_NUM ];      /*32 bits for one page*/
                                                               /*note: only the first page of the stored file would carray on the np node_pos info*/
                                                               /*note: generally one should query used bitmap and then finger out node_pos from here*/
}CSFSB;/*4k-alignment*/

#define CSFSB_PAGE_MAX_NUM(csfsb)                            ((csfsb)->sfsb_page_max_num)
#define CSFSB_PAGE_USED_BITMAP_TBL(csfsb)                    ((csfsb)->sfsb_page_used_bitmap)
#define CSFSB_PAGE_NP_NODE_POS_TBL(csfsb)                    ((csfsb)->sfsb_page_np_node_pos)

typedef EC_BOOL (*CSFSNP_RECYCLE)(void *, const uint32_t);

typedef struct
{
    const char *name;
    uint16_t    page_num;
    uint16_t    rsvd01;
    uint16_t    rsvd02;
    uint16_t    rsvd03;
}CSFSB_CONF;

#define CSFSB_CONF_NAME(csfsb_conf)               ((csfsb_conf)->name)
#define CSFSB_CONF_PAGE_NUM(csfsb_conf)           ((csfsb_conf)->page_num)

CSFSB  *csfsb_new(const uint32_t np_node_err_pos);

EC_BOOL csfsb_init(CSFSB *csfsb, const uint32_t np_node_err_pos);

void    csfsb_clean(CSFSB *csfsb, const uint32_t np_node_err_pos);

EC_BOOL csfsb_free(CSFSB *csfsb, const uint32_t np_node_err_pos);

EC_BOOL csfsb_new_space(CSFSB *csfsb, const uint16_t page_num, const uint16_t page_no, const uint32_t np_node_err_pos, CSFSNP_RECYCLE recycle, void *npp);

EC_BOOL csfsb_bind(CSFSB *csfsb, const uint16_t page_no, const uint32_t np_id, const uint32_t np_node_pos);

EC_BOOL csfsb_flush_size(const CSFSB *csfsb, UINT32 *size);

EC_BOOL csfsb_flush(const CSFSB *csfsb, int fd, UINT32 *offset);

EC_BOOL csfsb_load(CSFSB *csfsb, int fd, UINT32 *offset);

void    csfsb_print(LOG *log, const CSFSB *csfsb);

#endif    /* _CSFSB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
