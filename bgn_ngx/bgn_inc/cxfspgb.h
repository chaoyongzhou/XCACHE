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

#ifndef    _CXFSPGB_H
#define    _CXFSPGB_H

/*page cache, one page = 4KB, one page cache = 64MB*/

#include "type.h"
#include "cxfspgrb.h"

/*page model*/
#define CXFSPGB_064MB_MODEL    ((uint16_t) 0)
#define CXFSPGB_032MB_MODEL    ((uint16_t) 1)
#define CXFSPGB_016MB_MODEL    ((uint16_t) 2)
#define CXFSPGB_008MB_MODEL    ((uint16_t) 3)
#define CXFSPGB_004MB_MODEL    ((uint16_t) 4)
#define CXFSPGB_002MB_MODEL    ((uint16_t) 5)
#define CXFSPGB_001MB_MODEL    ((uint16_t) 6)
#define CXFSPGB_512KB_MODEL    ((uint16_t) 7)
#define CXFSPGB_256KB_MODEL    ((uint16_t) 8)
#define CXFSPGB_128KB_MODEL    ((uint16_t) 9)
#define CXFSPGB_064KB_MODEL    ((uint16_t)10)
#define CXFSPGB_032KB_MODEL    ((uint16_t)11)
#define CXFSPGB_016KB_MODEL    ((uint16_t)12)
#define CXFSPGB_008KB_MODEL    ((uint16_t)13)
#define CXFSPGB_004KB_MODEL    ((uint16_t)14)
#define CXFSPGB_MODEL_MAX_NUM  ((uint16_t)15)

/*---------------------------------------------------------------------------------\
 reference table (64M-block, 4K-page)
 ================================================================================================
    model | size of page model | num of page model | bitmap of num in bits | bitmap of num in bytes
    0       64M                  2^0                 2^0                     2^0
    1       32M                  2^1                 2^1                     2^0
    2       16M                  2^2                 2^2                     2^0
    3       8M                   2^3                 2^3                     2^0
    4       4M                   2^4                 2^4                     2^1
    5       2M                   2^5                 2^5                     2^2
    6       1M                   2^6                 2^6                     2^3
    7       512K                 2^7                 2^7                     2^4
    8       256K                 2^8                 2^8                     2^5
    9       128K                 2^9                 2^9                     2^6
    10      64K                  2^10                2^10                    2^7
    11      32K                  2^11                2^11                    2^8
    12      16K                  2^12                2^12                    2^9
    13      8K                   2^13                2^13                    2^10
    14      4K                   2^14                2^14                    2^11
 ================================================================================================

   64M-block = (model size of page model) * (num of page model)

\---------------------------------------------------------------------------------*/

/*num of bytes represent the bitmap*/
#define CXFSPGB_064MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CXFSPGB_032MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CXFSPGB_016MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CXFSPGB_008MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CXFSPGB_004MB_BITMAP_SIZE  ((uint16_t)(1 <<  1))
#define CXFSPGB_002MB_BITMAP_SIZE  ((uint16_t)(1 <<  2))
#define CXFSPGB_001MB_BITMAP_SIZE  ((uint16_t)(1 <<  3))
#define CXFSPGB_512KB_BITMAP_SIZE  ((uint16_t)(1 <<  4))
#define CXFSPGB_256KB_BITMAP_SIZE  ((uint16_t)(1 <<  5))
#define CXFSPGB_128KB_BITMAP_SIZE  ((uint16_t)(1 <<  6))
#define CXFSPGB_064KB_BITMAP_SIZE  ((uint16_t)(1 <<  7))
#define CXFSPGB_032KB_BITMAP_SIZE  ((uint16_t)(1 <<  8))
#define CXFSPGB_016KB_BITMAP_SIZE  ((uint16_t)(1 <<  9))
#define CXFSPGB_008KB_BITMAP_SIZE  ((uint16_t)(1 << 10))
#define CXFSPGB_004KB_BITMAP_SIZE  ((uint16_t)(1 << 11))

#define CXFSPGB_RB_BITMAP_OFFSET_OF_064MB_MODEL ((uint16_t)0)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_064MB_MODEL + CXFSPGB_064MB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL + CXFSPGB_032MB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL + CXFSPGB_016MB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL + CXFSPGB_008MB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL + CXFSPGB_004MB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL + CXFSPGB_002MB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL + CXFSPGB_001MB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL + CXFSPGB_512KB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL + CXFSPGB_256KB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL + CXFSPGB_128KB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL + CXFSPGB_064KB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL + CXFSPGB_032KB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL + CXFSPGB_016KB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL + CXFSPGB_008KB_BITMAP_SIZE)
#define CXFSPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL (CXFSPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL + CXFSPGB_004KB_BITMAP_SIZE)

#define CXFSPGB_RB_BITMAP_SIZE                  (CXFSPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL)/*=4098*/
#define CXFSPGB_RB_BITMAP_PAD_SIZE              (8 - (CXFSPGB_RB_BITMAP_SIZE & 7))/*=4098*/

#define CXFSPGB_CACHE_BIT_SIZE                  ((uint32_t)26) /*64MB*/
#define CXFSPGB_CACHE_MAX_BYTE_SIZE             ((uint32_t)(1 << CXFSPGB_CACHE_BIT_SIZE)) /*64MB*/

/*---------------------------------------------------------------------------------\
 reference table
 ==================================================================================
    PAGE       PAGE_BIT_SIZE  HI_BIT_MASK  CXFSPGB_MODEL_MASK_ALL   MASK N-BITS
    4K         12             0x4000       0x7FFF                15
    8K         13             0x2000       0x3FFF                14
    16K        14             0x1000       0x1FFF                13
    32K        15             0x0800       0x0FFF                12
    64K        16             0x0400       0x07FF                11
    128K       17             0x0200       0x03FF                10
    256K       18             0x0100       0x01FF                9
    512K       19             0x0080       0x00FF                8
    1M         20             0x0040       0x007F                7
    2M         21             0x0020       0x003F                6
    4M         22             0x0010       0x001F                5
    8M         23             0x0008       0x000F                4
    16M        24             0x0004       0x0007                3
    32M        25             0x0002       0x0003                2
    64M        26             0x0001       0x0001                1
 ==================================================================================
 note: (LO_BIT_MASK = HI_BIT_MASK - 1)
\---------------------------------------------------------------------------------*/

/*------------------4K-page beg ------------------------*/
#define CXFSPGB_064MB_PAGE_4K_NUM  ((uint16_t)(1 << 14))
#define CXFSPGB_032MB_PAGE_4K_NUM  ((uint16_t)(1 << 13))
#define CXFSPGB_016MB_PAGE_4K_NUM  ((uint16_t)(1 << 12))
#define CXFSPGB_008MB_PAGE_4K_NUM  ((uint16_t)(1 << 11))
#define CXFSPGB_004MB_PAGE_4K_NUM  ((uint16_t)(1 << 10))
#define CXFSPGB_002MB_PAGE_4K_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGB_001MB_PAGE_4K_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGB_512KB_PAGE_4K_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGB_256KB_PAGE_4K_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGB_128KB_PAGE_4K_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGB_064KB_PAGE_4K_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGB_032KB_PAGE_4K_NUM  ((uint16_t)(1 <<  3))
#define CXFSPGB_016KB_PAGE_4K_NUM  ((uint16_t)(1 <<  2))
#define CXFSPGB_008KB_PAGE_4K_NUM  ((uint16_t)(1 <<  1))
#define CXFSPGB_004KB_PAGE_4K_NUM  ((uint16_t)(1 <<  0))

#define CXFSPGB_PAGE_4K_MODEL_MASK       ((uint16_t)0x7FFF)

#define CXFSPGB_PAGE_4K_BIT_SIZE         ((uint32_t)12)
#define CXFSPGB_PAGE_4K_BYTE_SIZE        ((uint32_t)(1 << CXFSPGB_PAGE_4K_BIT_SIZE))

#define CXFSPGB_PAGE_4K_HI_BIT_MASK      ((uint16_t)0x4000)     /*for 2k-page, is 0x8000*/
#define CXFSPGB_PAGE_4K_LO_BITS_MASK     ((uint16_t)0x3FFF)     /*for 2k-page, is 0x7FFF*/
/*------------------4K-page end ------------------------*/

/*------------------8K-page beg ------------------------*/
#define CXFSPGB_064MB_PAGE_8K_NUM  ((uint16_t)(1 << 13))
#define CXFSPGB_032MB_PAGE_8K_NUM  ((uint16_t)(1 << 12))
#define CXFSPGB_016MB_PAGE_8K_NUM  ((uint16_t)(1 << 11))
#define CXFSPGB_008MB_PAGE_8K_NUM  ((uint16_t)(1 << 10))
#define CXFSPGB_004MB_PAGE_8K_NUM  ((uint16_t)(1 <<  9))
#define CXFSPGB_002MB_PAGE_8K_NUM  ((uint16_t)(1 <<  8))
#define CXFSPGB_001MB_PAGE_8K_NUM  ((uint16_t)(1 <<  7))
#define CXFSPGB_512KB_PAGE_8K_NUM  ((uint16_t)(1 <<  6))
#define CXFSPGB_256KB_PAGE_8K_NUM  ((uint16_t)(1 <<  5))
#define CXFSPGB_128KB_PAGE_8K_NUM  ((uint16_t)(1 <<  4))
#define CXFSPGB_064KB_PAGE_8K_NUM  ((uint16_t)(1 <<  3))
#define CXFSPGB_032KB_PAGE_8K_NUM  ((uint16_t)(1 <<  2))
#define CXFSPGB_016KB_PAGE_8K_NUM  ((uint16_t)(1 <<  1))
#define CXFSPGB_008KB_PAGE_8K_NUM  ((uint16_t)(1 <<  0))
#define CXFSPGB_004KB_PAGE_8K_NUM  ((uint16_t)(0))

#define CXFSPGB_PAGE_8K_MODEL_MASK       ((uint16_t)0x3FFF)

#define CXFSPGB_PAGE_8K_BIT_SIZE         ((uint32_t)13)
#define CXFSPGB_PAGE_8K_BYTE_SIZE        ((uint32_t)(1 << CXFSPGB_PAGE_8K_BIT_SIZE))

#define CXFSPGB_PAGE_8K_HI_BIT_MASK      ((uint16_t)0x2000)
#define CXFSPGB_PAGE_8K_LO_BITS_MASK     ((uint16_t)0x1FFF)
/*------------------8K-page end ------------------------*/

/*for debug*/
/*------------------16M-page beg ------------------------*/
#define CXFSPGB_064MB_PAGE_16M_NUM  ((uint16_t)(1 << 2))
#define CXFSPGB_032MB_PAGE_16M_NUM  ((uint16_t)(1 << 1))
#define CXFSPGB_016MB_PAGE_16M_NUM  ((uint16_t)(1 << 0))
#define CXFSPGB_008MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_004MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_002MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_001MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_512KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_256KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_128KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_064KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_032KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_016KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_008KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CXFSPGB_004KB_PAGE_16M_NUM  ((uint16_t)(0))

#define CXFSPGB_PAGE_16M_MODEL_MASK       ((uint16_t)0x0007)

#define CXFSPGB_PAGE_16M_BIT_SIZE         ((uint32_t)24)
#define CXFSPGB_PAGE_16M_BYTE_SIZE        ((uint32_t)(1 << CXFSPGB_PAGE_16M_BIT_SIZE))

#define CXFSPGB_PAGE_16M_HI_BIT_MASK      ((uint16_t)0x0004)
#define CXFSPGB_PAGE_16M_LO_BITS_MASK     ((uint16_t)0x0003)
/*------------------16M-page end ------------------------*/

/*------------------32M-page beg ------------------------*/
#define CXFSPGB_064MB_PAGE_32M_NUM  ((uint16_t)(1 << 1))
#define CXFSPGB_032MB_PAGE_32M_NUM  ((uint16_t)(1 << 0))
#define CXFSPGB_016MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_008MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_004MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_002MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_001MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_512KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_256KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_128KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_064KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_032KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_016KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_008KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CXFSPGB_004KB_PAGE_32M_NUM  ((uint16_t)(0))

#define CXFSPGB_PAGE_32M_MODEL_MASK       ((uint16_t)0x0003)

#define CXFSPGB_PAGE_32M_BIT_SIZE         ((uint32_t)25)
#define CXFSPGB_PAGE_32M_BYTE_SIZE        ((uint32_t)(1 << CXFSPGB_PAGE_32M_BIT_SIZE))

#define CXFSPGB_PAGE_32M_HI_BIT_MASK      ((uint16_t)0x0002)
#define CXFSPGB_PAGE_32M_LO_BITS_MASK     ((uint16_t)0x0001)
/*------------------32M-page end ------------------------*/

#define CXFSPGB_004K_PAGE_CHOICE         (1)
#define CXFSPGB_008K_PAGE_CHOICE         (2)
#define CXFSPGB_016M_PAGE_CHOICE         (3)
#define CXFSPGB_032M_PAGE_CHOICE         (4)

//#define CXFSPGB_PAGE_CHOICE              (CXFSPGB_004K_PAGE_CHOICE)
#define CXFSPGB_PAGE_CHOICE              (CXFSPGB_008K_PAGE_CHOICE)
//#define CXFSPGB_PAGE_CHOICE              (CXFSPGB_016M_PAGE_CHOICE)
//#define CXFSPGB_PAGE_CHOICE              (CXFSPGB_032M_PAGE_CHOICE)

/*--------------------------------------------------------------------------------------------*/
#if (CXFSPGB_004K_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)
#define CXFSPGB_064MB_PAGE_NUM           (CXFSPGB_064MB_PAGE_4K_NUM)
#define CXFSPGB_032MB_PAGE_NUM           (CXFSPGB_032MB_PAGE_4K_NUM)
#define CXFSPGB_016MB_PAGE_NUM           (CXFSPGB_016MB_PAGE_4K_NUM)
#define CXFSPGB_008MB_PAGE_NUM           (CXFSPGB_008MB_PAGE_4K_NUM)
#define CXFSPGB_004MB_PAGE_NUM           (CXFSPGB_004MB_PAGE_4K_NUM)
#define CXFSPGB_002MB_PAGE_NUM           (CXFSPGB_002MB_PAGE_4K_NUM)
#define CXFSPGB_001MB_PAGE_NUM           (CXFSPGB_001MB_PAGE_4K_NUM)
#define CXFSPGB_512KB_PAGE_NUM           (CXFSPGB_512KB_PAGE_4K_NUM)
#define CXFSPGB_256KB_PAGE_NUM           (CXFSPGB_256KB_PAGE_4K_NUM)
#define CXFSPGB_128KB_PAGE_NUM           (CXFSPGB_128KB_PAGE_4K_NUM)
#define CXFSPGB_064KB_PAGE_NUM           (CXFSPGB_064KB_PAGE_4K_NUM)
#define CXFSPGB_032KB_PAGE_NUM           (CXFSPGB_032KB_PAGE_4K_NUM)
#define CXFSPGB_016KB_PAGE_NUM           (CXFSPGB_016KB_PAGE_4K_NUM)
#define CXFSPGB_008KB_PAGE_NUM           (CXFSPGB_008KB_PAGE_4K_NUM)
#define CXFSPGB_004KB_PAGE_NUM           (CXFSPGB_004KB_PAGE_4K_NUM)

#define CXFSPGB_PAGE_BIT_SIZE            (CXFSPGB_PAGE_4K_BIT_SIZE)
#define CXFSPGB_PAGE_BYTE_SIZE           (CXFSPGB_PAGE_4K_BYTE_SIZE)

#define CXFSPGB_PAGE_HI_BIT_MASK         (CXFSPGB_PAGE_4K_HI_BIT_MASK)
#define CXFSPGB_PAGE_LO_BITS_MASK        (CXFSPGB_PAGE_4K_LO_BITS_MASK)

/*actual used cxfspgb model num*/
#define CXFSPGB_MODEL_NUM                (CXFSPGB_004KB_MODEL + 1)/*15*/
#define CXFSPGB_MODEL_MASK_ALL           (CXFSPGB_PAGE_4K_MODEL_MASK)
#endif/*(CXFSPGB_004K_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)*/

#if (CXFSPGB_008K_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)
#define CXFSPGB_064MB_PAGE_NUM           (CXFSPGB_064MB_PAGE_8K_NUM)
#define CXFSPGB_032MB_PAGE_NUM           (CXFSPGB_032MB_PAGE_8K_NUM)
#define CXFSPGB_016MB_PAGE_NUM           (CXFSPGB_016MB_PAGE_8K_NUM)
#define CXFSPGB_008MB_PAGE_NUM           (CXFSPGB_008MB_PAGE_8K_NUM)
#define CXFSPGB_004MB_PAGE_NUM           (CXFSPGB_004MB_PAGE_8K_NUM)
#define CXFSPGB_002MB_PAGE_NUM           (CXFSPGB_002MB_PAGE_8K_NUM)
#define CXFSPGB_001MB_PAGE_NUM           (CXFSPGB_001MB_PAGE_8K_NUM)
#define CXFSPGB_512KB_PAGE_NUM           (CXFSPGB_512KB_PAGE_8K_NUM)
#define CXFSPGB_256KB_PAGE_NUM           (CXFSPGB_256KB_PAGE_8K_NUM)
#define CXFSPGB_128KB_PAGE_NUM           (CXFSPGB_128KB_PAGE_8K_NUM)
#define CXFSPGB_064KB_PAGE_NUM           (CXFSPGB_064KB_PAGE_8K_NUM)
#define CXFSPGB_032KB_PAGE_NUM           (CXFSPGB_032KB_PAGE_8K_NUM)
#define CXFSPGB_016KB_PAGE_NUM           (CXFSPGB_016KB_PAGE_8K_NUM)
#define CXFSPGB_008KB_PAGE_NUM           (CXFSPGB_008KB_PAGE_8K_NUM)
#define CXFSPGB_004KB_PAGE_NUM           (CXFSPGB_004KB_PAGE_8K_NUM)

#define CXFSPGB_PAGE_BIT_SIZE            (CXFSPGB_PAGE_8K_BIT_SIZE)
#define CXFSPGB_PAGE_BYTE_SIZE           (CXFSPGB_PAGE_8K_BYTE_SIZE)

#define CXFSPGB_PAGE_HI_BIT_MASK         (CXFSPGB_PAGE_8K_HI_BIT_MASK)
#define CXFSPGB_PAGE_LO_BITS_MASK        (CXFSPGB_PAGE_8K_LO_BITS_MASK)

/*actual used cxfspgb model num*/
#define CXFSPGB_MODEL_NUM                (CXFSPGB_008KB_MODEL + 1)/*14*/
#define CXFSPGB_MODEL_MASK_ALL           (CXFSPGB_PAGE_8K_MODEL_MASK)
#endif/*(CXFSPGB_008K_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)*/


#if (CXFSPGB_016M_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)
#define CXFSPGB_064MB_PAGE_NUM           (CXFSPGB_064MB_PAGE_16M_NUM)
#define CXFSPGB_032MB_PAGE_NUM           (CXFSPGB_032MB_PAGE_16M_NUM)
#define CXFSPGB_016MB_PAGE_NUM           (CXFSPGB_016MB_PAGE_16M_NUM)
#define CXFSPGB_008MB_PAGE_NUM           (CXFSPGB_008MB_PAGE_16M_NUM)
#define CXFSPGB_004MB_PAGE_NUM           (CXFSPGB_004MB_PAGE_16M_NUM)
#define CXFSPGB_002MB_PAGE_NUM           (CXFSPGB_002MB_PAGE_16M_NUM)
#define CXFSPGB_001MB_PAGE_NUM           (CXFSPGB_001MB_PAGE_16M_NUM)
#define CXFSPGB_512KB_PAGE_NUM           (CXFSPGB_512KB_PAGE_16M_NUM)
#define CXFSPGB_256KB_PAGE_NUM           (CXFSPGB_256KB_PAGE_16M_NUM)
#define CXFSPGB_128KB_PAGE_NUM           (CXFSPGB_128KB_PAGE_16M_NUM)
#define CXFSPGB_064KB_PAGE_NUM           (CXFSPGB_064KB_PAGE_16M_NUM)
#define CXFSPGB_032KB_PAGE_NUM           (CXFSPGB_032KB_PAGE_16M_NUM)
#define CXFSPGB_016KB_PAGE_NUM           (CXFSPGB_016KB_PAGE_16M_NUM)
#define CXFSPGB_008KB_PAGE_NUM           (CXFSPGB_008KB_PAGE_16M_NUM)
#define CXFSPGB_004KB_PAGE_NUM           (CXFSPGB_004KB_PAGE_16M_NUM)

#define CXFSPGB_PAGE_BIT_SIZE            (CXFSPGB_PAGE_16M_BIT_SIZE)
#define CXFSPGB_PAGE_BYTE_SIZE           (CXFSPGB_PAGE_16M_BYTE_SIZE)

#define CXFSPGB_PAGE_HI_BIT_MASK         (CXFSPGB_PAGE_16M_HI_BIT_MASK)
#define CXFSPGB_PAGE_LO_BITS_MASK        (CXFSPGB_PAGE_16M_LO_BITS_MASK)

/*actual used cxfspgb model num*/
#define CXFSPGB_MODEL_NUM                (CXFSPGB_016MB_MODEL + 1)/*3*/
#define CXFSPGB_MODEL_MASK_ALL           (CXFSPGB_PAGE_16M_MODEL_MASK)
#endif/*(CXFSPGB_016M_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)*/

#if (CXFSPGB_032M_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)
#define CXFSPGB_064MB_PAGE_NUM           (CXFSPGB_064MB_PAGE_32M_NUM)
#define CXFSPGB_032MB_PAGE_NUM           (CXFSPGB_032MB_PAGE_32M_NUM)
#define CXFSPGB_016MB_PAGE_NUM           (CXFSPGB_016MB_PAGE_32M_NUM)
#define CXFSPGB_008MB_PAGE_NUM           (CXFSPGB_008MB_PAGE_32M_NUM)
#define CXFSPGB_004MB_PAGE_NUM           (CXFSPGB_004MB_PAGE_32M_NUM)
#define CXFSPGB_002MB_PAGE_NUM           (CXFSPGB_002MB_PAGE_32M_NUM)
#define CXFSPGB_001MB_PAGE_NUM           (CXFSPGB_001MB_PAGE_32M_NUM)
#define CXFSPGB_512KB_PAGE_NUM           (CXFSPGB_512KB_PAGE_32M_NUM)
#define CXFSPGB_256KB_PAGE_NUM           (CXFSPGB_256KB_PAGE_32M_NUM)
#define CXFSPGB_128KB_PAGE_NUM           (CXFSPGB_128KB_PAGE_32M_NUM)
#define CXFSPGB_064KB_PAGE_NUM           (CXFSPGB_064KB_PAGE_32M_NUM)
#define CXFSPGB_032KB_PAGE_NUM           (CXFSPGB_032KB_PAGE_32M_NUM)
#define CXFSPGB_016KB_PAGE_NUM           (CXFSPGB_016KB_PAGE_32M_NUM)
#define CXFSPGB_008KB_PAGE_NUM           (CXFSPGB_008KB_PAGE_32M_NUM)
#define CXFSPGB_004KB_PAGE_NUM           (CXFSPGB_004KB_PAGE_32M_NUM)

#define CXFSPGB_PAGE_BIT_SIZE            (CXFSPGB_PAGE_32M_BIT_SIZE)
#define CXFSPGB_PAGE_BYTE_SIZE           (CXFSPGB_PAGE_32M_BYTE_SIZE)

#define CXFSPGB_PAGE_HI_BIT_MASK         (CXFSPGB_PAGE_32M_HI_BIT_MASK)
#define CXFSPGB_PAGE_LO_BITS_MASK        (CXFSPGB_PAGE_32M_LO_BITS_MASK)

/*actual used cxfspgb model num*/
#define CXFSPGB_MODEL_NUM                (CXFSPGB_032MB_MODEL + 1)/*2*/
#define CXFSPGB_MODEL_MASK_ALL           (CXFSPGB_PAGE_32M_MODEL_MASK)
#endif/*(CXFSPGB_032M_PAGE_CHOICE == CXFSPGB_PAGE_CHOICE)*/


/*--------------------------------------------------------------------------------------------*/

#define CXFSPGB_PAGE_IS_FREE             ((uint8_t) 1)
#define CXFSPGB_PAGE_IS_NOT_FREE         ((uint8_t) 0)

typedef struct
{
    uint8_t      pgb_rb_bitmap_buff[ CXFSPGB_RB_BITMAP_SIZE ];
    uint8_t      rsvd1[CXFSPGB_RB_BITMAP_PAD_SIZE];

    uint16_t     pgb_rb_root_pos[ CXFSPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t     pgb_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/

    uint16_t     pgb_page_max_num; /*max page number*/
    uint16_t     pgb_page_used_num;/*used page number*/
    uint32_t     pgb_actual_used_size;/*actual used bytes*/

    CXFSPGRB_POOL   pgb_rb_pool;
}CXFSPGB;/*4k-alignment*/

#define CXFSPGB_CXFSPGRB_POOL(cxfspgb)                              (&((cxfspgb)->pgb_rb_pool))
#define CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS_TBL(cxfspgb)           ((cxfspgb)->pgb_rb_root_pos)
#define CXFSPGB_PAGE_MODEL_CXFSPGRB_ROOT_POS(cxfspgb, page_model)   ((cxfspgb)->pgb_rb_root_pos[ (page_model) ])
#define CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP_BUFF(cxfspgb)            ((cxfspgb)->pgb_rb_bitmap_buff)
#define CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP(cxfspgb, page_model)     ((uint8_t *)CXFSPGB_PAGE_MODEL_CXFSPGRB_BITMAP_BUFF(cxfspgb) + g_pgb_bitmap_offset[ (page_model)])
#define CXFSPGB_PAGE_MODEL_ASSIGN_BITMAP(cxfspgb)                ((cxfspgb)->pgb_assign_bitmap)
#define CXFSPGB_PAGE_MAX_NUM(cxfspgb)                            ((cxfspgb)->pgb_page_max_num)
#define CXFSPGB_PAGE_USED_NUM(cxfspgb)                           ((cxfspgb)->pgb_page_used_num)
#define CXFSPGB_PAGE_ACTUAL_USED_SIZE(cxfspgb)                   ((cxfspgb)->pgb_actual_used_size)

/*rb_node num = half of page num (enough!)*/
#define CXFSPGB_SIZE        (sizeof(CXFSPGB) + sizeof(CXFSPGRB_NODE) * ((CXFSPGB_064MB_PAGE_NUM + 1) >> 1))

typedef struct
{
    const char *name;
    uint16_t    page_model;
    uint16_t    cxfspgrb_bitmap_size;
    uint16_t    page_num;
    uint16_t    rsvd;
}CXFSPGB_CONF;

#define CXFSPGB_CONF_NAME(cxfspgb_conf)                     ((cxfspgb_conf)->name)
#define CXFSPGB_CONF_PAGE_MODEL(cxfspgb_conf)               ((cxfspgb_conf)->page_model)
#define CXFSPGB_CONF_CXFSPGRB_BITMAP_SIZE(cxfspgb_conf)     ((cxfspgb_conf)->cxfspgrb_bitmap_size)
#define CXFSPGB_CONF_PAGE_NUM(cxfspgb_conf)                 ((cxfspgb_conf)->page_num)


CXFSPGB *cxfspgb_new(const uint16_t page_model_target);

/* one page cache = 64MB */
EC_BOOL cxfspgb_init(CXFSPGB *cxfspgb, const uint16_t page_model_target);

void cxfspgb_clean(CXFSPGB *cxfspgb);

EC_BOOL cxfspgb_free(CXFSPGB *cxfspgb);

/*add one free page into pool and set page model bitmap*/
EC_BOOL cxfspgb_add_page(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t page_no);

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cxfspgb_del_page(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t page_no);

uint16_t cxfspgb_assign_page(CXFSPGB *cxfspgb, const uint16_t page_model);

EC_BOOL cxfspgb_recycle_page(CXFSPGB *cxfspgb, const uint16_t page_model, const uint16_t page_no);

EC_BOOL cxfspgb_new_space(CXFSPGB *cxfspgb, const uint32_t size, uint16_t *page_no);

EC_BOOL cxfspgb_free_space(CXFSPGB *cxfspgb, const uint16_t page_start_no, const uint32_t size);

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cxfspgb_is_full(const CXFSPGB *cxfspgb);

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cxfspgb_is_empty(const CXFSPGB *cxfspgb);

EC_BOOL cxfspgb_check(const CXFSPGB *cxfspgb);

void cxfspgb_print(LOG *log, const CXFSPGB *cxfspgb);

EC_BOOL cxfspgb_debug_cmp(const CXFSPGB *cxfspgb_1st, const CXFSPGB *cxfspgb_2nd);

#endif    /* _CXFSPGB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
