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
#define CPGB_MODEL_MAX_NUM  ((uint16_t)15)

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

#define CPGB_CACHE_BIT_SIZE                  ((uint32_t)26) /*64MB*/
#define CPGB_CACHE_MAX_BYTE_SIZE             ((uint32_t)(1 << CPGB_CACHE_BIT_SIZE)) /*64MB*/

/*---------------------------------------------------------------------------------\
 reference table
 ==================================================================================
    PAGE       PAGE_BIT_SIZE  HI_BIT_MASK  CPGB_MODEL_MASK_ALL   MASK N-BITS  
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

#define CPGB_PAGE_4K_MODEL_MASK       ((uint16_t)0x7FFF)

#define CPGB_PAGE_4K_BIT_SIZE         ((uint32_t)12)
#define CPGB_PAGE_4K_BYTE_SIZE        ((uint32_t)(1 << CPGB_PAGE_4K_BIT_SIZE))

#define CPGB_PAGE_4K_HI_BIT_MASK      ((uint16_t)0x4000)     /*for 2k-page, is 0x8000*/
#define CPGB_PAGE_4K_LO_BITS_MASK     ((uint16_t)0x3FFF)     /*for 2k-page, is 0x7FFF*/
/*------------------4K-page end ------------------------*/

/*------------------8K-page beg ------------------------*/
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
#define CPGB_064KB_PAGE_8K_NUM  ((uint16_t)(1 <<  3))
#define CPGB_032KB_PAGE_8K_NUM  ((uint16_t)(1 <<  2))
#define CPGB_016KB_PAGE_8K_NUM  ((uint16_t)(1 <<  1))
#define CPGB_008KB_PAGE_8K_NUM  ((uint16_t)(1 <<  0))
#define CPGB_004KB_PAGE_8K_NUM  ((uint16_t)(0))

#define CPGB_PAGE_8K_MODEL_MASK       ((uint16_t)0x3FFF)

#define CPGB_PAGE_8K_BIT_SIZE         ((uint32_t)13)
#define CPGB_PAGE_8K_BYTE_SIZE        ((uint32_t)(1 << CPGB_PAGE_8K_BIT_SIZE))

#define CPGB_PAGE_8K_HI_BIT_MASK      ((uint16_t)0x2000)
#define CPGB_PAGE_8K_LO_BITS_MASK     ((uint16_t)0x1FFF)
/*------------------8K-page end ------------------------*/

/*for debug*/
/*------------------16M-page beg ------------------------*/
#define CPGB_064MB_PAGE_16M_NUM  ((uint16_t)(1 << 2))
#define CPGB_032MB_PAGE_16M_NUM  ((uint16_t)(1 << 1))
#define CPGB_016MB_PAGE_16M_NUM  ((uint16_t)(1 << 0))
#define CPGB_008MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_004MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_002MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_001MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_512KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_256KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_128KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_064KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_032KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_016KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_008KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CPGB_004KB_PAGE_16M_NUM  ((uint16_t)(0))

#define CPGB_PAGE_16M_MODEL_MASK       ((uint16_t)0x0007)

#define CPGB_PAGE_16M_BIT_SIZE         ((uint32_t)24)
#define CPGB_PAGE_16M_BYTE_SIZE        ((uint32_t)(1 << CPGB_PAGE_16M_BIT_SIZE))

#define CPGB_PAGE_16M_HI_BIT_MASK      ((uint16_t)0x0004)
#define CPGB_PAGE_16M_LO_BITS_MASK     ((uint16_t)0x0003)
/*------------------16M-page end ------------------------*/

/*------------------32M-page beg ------------------------*/
#define CPGB_064MB_PAGE_32M_NUM  ((uint16_t)(1 << 1))
#define CPGB_032MB_PAGE_32M_NUM  ((uint16_t)(1 << 0))
#define CPGB_016MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_008MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_004MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_002MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_001MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_512KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_256KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_128KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_064KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_032KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_016KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_008KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CPGB_004KB_PAGE_32M_NUM  ((uint16_t)(0))

#define CPGB_PAGE_32M_MODEL_MASK       ((uint16_t)0x0003)

#define CPGB_PAGE_32M_BIT_SIZE         ((uint32_t)25)
#define CPGB_PAGE_32M_BYTE_SIZE        ((uint32_t)(1 << CPGB_PAGE_32M_BIT_SIZE))

#define CPGB_PAGE_32M_HI_BIT_MASK      ((uint16_t)0x0002)
#define CPGB_PAGE_32M_LO_BITS_MASK     ((uint16_t)0x0001)
/*------------------32M-page end ------------------------*/

#define CPGB_004K_PAGE_CHOICE         (1)
#define CPGB_008K_PAGE_CHOICE         (2)
#define CPGB_016M_PAGE_CHOICE         (3)
#define CPGB_032M_PAGE_CHOICE         (4)

//#define CPGB_PAGE_CHOICE              (CPGB_004K_PAGE_CHOICE)
#define CPGB_PAGE_CHOICE              (CPGB_008K_PAGE_CHOICE)
//#define CPGB_PAGE_CHOICE              (CPGB_016M_PAGE_CHOICE)
//#define CPGB_PAGE_CHOICE              (CPGB_032M_PAGE_CHOICE)

/*--------------------------------------------------------------------------------------------*/
#if (CPGB_004K_PAGE_CHOICE == CPGB_PAGE_CHOICE)
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

/*actual used cpgb model num*/
#define CPGB_MODEL_NUM                (CPGB_004KB_MODEL + 1)/*15*/
#define CPGB_MODEL_MASK_ALL           (CPGB_PAGE_4K_MODEL_MASK)
#endif/*(CPGB_004K_PAGE_CHOICE == CPGB_PAGE_CHOICE)*/

#if (CPGB_008K_PAGE_CHOICE == CPGB_PAGE_CHOICE)
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
#define CPGB_064KB_PAGE_NUM           (CPGB_064KB_PAGE_8K_NUM)
#define CPGB_032KB_PAGE_NUM           (CPGB_032KB_PAGE_8K_NUM)
#define CPGB_016KB_PAGE_NUM           (CPGB_016KB_PAGE_8K_NUM)
#define CPGB_008KB_PAGE_NUM           (CPGB_008KB_PAGE_8K_NUM)
#define CPGB_004KB_PAGE_NUM           (CPGB_004KB_PAGE_8K_NUM)

#define CPGB_PAGE_BIT_SIZE            (CPGB_PAGE_8K_BIT_SIZE)
#define CPGB_PAGE_BYTE_SIZE           (CPGB_PAGE_8K_BYTE_SIZE)

#define CPGB_PAGE_HI_BIT_MASK         (CPGB_PAGE_8K_HI_BIT_MASK)
#define CPGB_PAGE_LO_BITS_MASK        (CPGB_PAGE_8K_LO_BITS_MASK)

/*actual used cpgb model num*/
#define CPGB_MODEL_NUM                (CPGB_008KB_MODEL + 1)/*14*/
#define CPGB_MODEL_MASK_ALL           (CPGB_PAGE_8K_MODEL_MASK)
#endif/*(CPGB_008K_PAGE_CHOICE == CPGB_PAGE_CHOICE)*/


#if (CPGB_016M_PAGE_CHOICE == CPGB_PAGE_CHOICE)
#define CPGB_064MB_PAGE_NUM           (CPGB_064MB_PAGE_16M_NUM)
#define CPGB_032MB_PAGE_NUM           (CPGB_032MB_PAGE_16M_NUM)
#define CPGB_016MB_PAGE_NUM           (CPGB_016MB_PAGE_16M_NUM)
#define CPGB_008MB_PAGE_NUM           (CPGB_008MB_PAGE_16M_NUM)
#define CPGB_004MB_PAGE_NUM           (CPGB_004MB_PAGE_16M_NUM)
#define CPGB_002MB_PAGE_NUM           (CPGB_002MB_PAGE_16M_NUM)
#define CPGB_001MB_PAGE_NUM           (CPGB_001MB_PAGE_16M_NUM)
#define CPGB_512KB_PAGE_NUM           (CPGB_512KB_PAGE_16M_NUM)
#define CPGB_256KB_PAGE_NUM           (CPGB_256KB_PAGE_16M_NUM)
#define CPGB_128KB_PAGE_NUM           (CPGB_128KB_PAGE_16M_NUM)
#define CPGB_064KB_PAGE_NUM           (CPGB_064KB_PAGE_16M_NUM)
#define CPGB_032KB_PAGE_NUM           (CPGB_032KB_PAGE_16M_NUM)
#define CPGB_016KB_PAGE_NUM           (CPGB_016KB_PAGE_16M_NUM)
#define CPGB_008KB_PAGE_NUM           (CPGB_008KB_PAGE_16M_NUM)
#define CPGB_004KB_PAGE_NUM           (CPGB_004KB_PAGE_16M_NUM)

#define CPGB_PAGE_BIT_SIZE            (CPGB_PAGE_16M_BIT_SIZE)
#define CPGB_PAGE_BYTE_SIZE           (CPGB_PAGE_16M_BYTE_SIZE)

#define CPGB_PAGE_HI_BIT_MASK         (CPGB_PAGE_16M_HI_BIT_MASK)
#define CPGB_PAGE_LO_BITS_MASK        (CPGB_PAGE_16M_LO_BITS_MASK)

/*actual used cpgb model num*/
#define CPGB_MODEL_NUM                (CPGB_016MB_MODEL + 1)/*3*/
#define CPGB_MODEL_MASK_ALL           (CPGB_PAGE_16M_MODEL_MASK)
#endif/*(CPGB_016M_PAGE_CHOICE == CPGB_PAGE_CHOICE)*/

#if (CPGB_032M_PAGE_CHOICE == CPGB_PAGE_CHOICE)
#define CPGB_064MB_PAGE_NUM           (CPGB_064MB_PAGE_32M_NUM)
#define CPGB_032MB_PAGE_NUM           (CPGB_032MB_PAGE_32M_NUM)
#define CPGB_016MB_PAGE_NUM           (CPGB_016MB_PAGE_32M_NUM)
#define CPGB_008MB_PAGE_NUM           (CPGB_008MB_PAGE_32M_NUM)
#define CPGB_004MB_PAGE_NUM           (CPGB_004MB_PAGE_32M_NUM)
#define CPGB_002MB_PAGE_NUM           (CPGB_002MB_PAGE_32M_NUM)
#define CPGB_001MB_PAGE_NUM           (CPGB_001MB_PAGE_32M_NUM)
#define CPGB_512KB_PAGE_NUM           (CPGB_512KB_PAGE_32M_NUM)
#define CPGB_256KB_PAGE_NUM           (CPGB_256KB_PAGE_32M_NUM)
#define CPGB_128KB_PAGE_NUM           (CPGB_128KB_PAGE_32M_NUM)
#define CPGB_064KB_PAGE_NUM           (CPGB_064KB_PAGE_32M_NUM)
#define CPGB_032KB_PAGE_NUM           (CPGB_032KB_PAGE_32M_NUM)
#define CPGB_016KB_PAGE_NUM           (CPGB_016KB_PAGE_32M_NUM)
#define CPGB_008KB_PAGE_NUM           (CPGB_008KB_PAGE_32M_NUM)
#define CPGB_004KB_PAGE_NUM           (CPGB_004KB_PAGE_32M_NUM)

#define CPGB_PAGE_BIT_SIZE            (CPGB_PAGE_32M_BIT_SIZE)
#define CPGB_PAGE_BYTE_SIZE           (CPGB_PAGE_32M_BYTE_SIZE)

#define CPGB_PAGE_HI_BIT_MASK         (CPGB_PAGE_32M_HI_BIT_MASK)
#define CPGB_PAGE_LO_BITS_MASK        (CPGB_PAGE_32M_LO_BITS_MASK)

/*actual used cpgb model num*/
#define CPGB_MODEL_NUM                (CPGB_032MB_MODEL + 1)/*2*/
#define CPGB_MODEL_MASK_ALL           (CPGB_PAGE_32M_MODEL_MASK)
#endif/*(CPGB_032M_PAGE_CHOICE == CPGB_PAGE_CHOICE)*/


/*--------------------------------------------------------------------------------------------*/

#define CPGB_PAGE_IS_FREE             ((uint8_t) 1)
#define CPGB_PAGE_IS_NOT_FREE         ((uint8_t) 0)

typedef struct
{
    uint8_t      pgb_rb_bitmap_buff[ CPGB_RB_BITMAP_SIZE ];
    uint8_t      rsvd1[CPGB_RB_BITMAP_PAD_SIZE];

    uint16_t     pgb_rb_root_pos[ CPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t     pgb_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/

    uint16_t     pgb_page_max_num; /*max page number*/
    uint16_t     pgb_page_used_num;/*used page number*/
    uint32_t     pgb_actual_used_size;/*actual used bytes*/

    CPGRB_POOL   pgb_rb_pool;
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

/*rb_node num = half of page num (enough!)*/
#define CPGB_SIZE        (sizeof(CPGB) + sizeof(CPGRB_NODE) * ((CPGB_064MB_PAGE_NUM + 1) >> 1))

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
