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

#ifndef    _CMCPGB_H
#define    _CMCPGB_H

#include "type.h"
#include "cmcpgrb.h"

/*page model*/
#define CMCPGB_032MB_MODEL    ((uint16_t) 0)
#define CMCPGB_016MB_MODEL    ((uint16_t) 1)
#define CMCPGB_008MB_MODEL    ((uint16_t) 2)
#define CMCPGB_004MB_MODEL    ((uint16_t) 3)
#define CMCPGB_002MB_MODEL    ((uint16_t) 4)
#define CMCPGB_001MB_MODEL    ((uint16_t) 5)
#define CMCPGB_512KB_MODEL    ((uint16_t) 6)
#define CMCPGB_256KB_MODEL    ((uint16_t) 7)
#define CMCPGB_128KB_MODEL    ((uint16_t) 8)
#define CMCPGB_064KB_MODEL    ((uint16_t) 9)
#define CMCPGB_032KB_MODEL    ((uint16_t)10)
#define CMCPGB_016KB_MODEL    ((uint16_t)11)
#define CMCPGB_008KB_MODEL    ((uint16_t)12)
#define CMCPGB_004KB_MODEL    ((uint16_t)13)
#define CMCPGB_002KB_MODEL    ((uint16_t)14)
#define CMCPGB_MODEL_MAX_NUM  ((uint16_t)15)

/*---------------------------------------------------------------------------------\
 reference table (32M-block, 2K-page)
 ================================================================================================
    model | size of page model | num of page model | bitmap of num in bits | bitmap of num in bytes
    0       32M                  2^0                 2^0                     2^0
    1       16M                  2^1                 2^1                     2^0
    2       8M                   2^2                 2^2                     2^0    
    3       4M                   2^3                 2^3                     2^0
    4       2M                   2^4                 2^4                     2^1
    5       1M                   2^5                 2^5                     2^2
    6       512K                 2^6                 2^6                     2^3
    7       256K                 2^7                 2^7                     2^4
    8       128K                 2^8                 2^8                     2^5
    9       64K                  2^9                 2^9                     2^6
    10      32K                  2^10                2^10                    2^7
    11      16K                  2^11                2^11                    2^8
    12      8K                   2^12                2^12                    2^9
    13      4K                   2^13                2^13                    2^10
    14      2K                   2^14                2^14                    2^11
 ================================================================================================

   32M-block = (model size of page model) * (num of page model)
 
\---------------------------------------------------------------------------------*/

/*num of bytes represent the bitmap*/
#define CMCPGB_032MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CMCPGB_016MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CMCPGB_008MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CMCPGB_004MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CMCPGB_002MB_BITMAP_SIZE  ((uint16_t)(1 <<  1))
#define CMCPGB_001MB_BITMAP_SIZE  ((uint16_t)(1 <<  2))
#define CMCPGB_512KB_BITMAP_SIZE  ((uint16_t)(1 <<  3))
#define CMCPGB_256KB_BITMAP_SIZE  ((uint16_t)(1 <<  4))
#define CMCPGB_128KB_BITMAP_SIZE  ((uint16_t)(1 <<  5))
#define CMCPGB_064KB_BITMAP_SIZE  ((uint16_t)(1 <<  6))
#define CMCPGB_032KB_BITMAP_SIZE  ((uint16_t)(1 <<  7))
#define CMCPGB_016KB_BITMAP_SIZE  ((uint16_t)(1 <<  8))
#define CMCPGB_008KB_BITMAP_SIZE  ((uint16_t)(1 <<  9))
#define CMCPGB_004KB_BITMAP_SIZE  ((uint16_t)(1 << 10))
#define CMCPGB_002KB_BITMAP_SIZE  ((uint16_t)(1 << 11))

#define CMCPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL ((uint16_t)0)
#define CMCPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL + CMCPGB_032MB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL + CMCPGB_016MB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL + CMCPGB_008MB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL + CMCPGB_004MB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL + CMCPGB_002MB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL + CMCPGB_001MB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL + CMCPGB_512KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL + CMCPGB_256KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL + CMCPGB_128KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL + CMCPGB_064KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL + CMCPGB_032KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL + CMCPGB_016KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL + CMCPGB_008KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_002KB_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL + CMCPGB_004KB_BITMAP_SIZE)
#define CMCPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL (CMCPGB_RB_BITMAP_OFFSET_OF_002KB_MODEL + CMCPGB_002KB_BITMAP_SIZE)

#define CMCPGB_RB_BITMAP_SIZE                  (CMCPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL)/*=4098*/
#define CMCPGB_RB_BITMAP_PAD_SIZE              (8 - (CMCPGB_RB_BITMAP_SIZE & 7))/*=4098*/

#define CMCPGB_CACHE_BIT_SIZE                  ((uint32_t)25) /*32MB*/
#define CMCPGB_CACHE_MAX_BYTE_SIZE             ((uint32_t)(1 << CMCPGB_CACHE_BIT_SIZE)) /*32MB*/

/*---------------------------------------------------------------------------------\
 reference table
 ==================================================================================
    PAGE       PAGE_BIT_SIZE  HI_BIT_MASK  CMCPGB_MODEL_MASK_ALL   MASK N-BITS 
    2K         11             0x4000       0x7FFF                  15
    4K         12             0x2000       0x3FFF                  14
    8K         13             0x1000       0x1FFF                  13 
    16K        14             0x0800       0x0FFF                  12
    32K        15             0x0400       0x07FF                  11
    64K        16             0x0200       0x03FF                  10
    128K       17             0x0100       0x01FF                  9
    256K       18             0x0080       0x00FF                  8
    512K       19             0x0040       0x007F                  7
    1M         20             0x0020       0x003F                  6
    2M         21             0x0010       0x001F                  5
    4M         22             0x0008       0x000F                  4
    8M         23             0x0004       0x0007                  3
    16M        24             0x0002       0x0003                  2
    32M        25             0x0001       0x0001                  1
 ==================================================================================
 note: (LO_BIT_MASK = HI_BIT_MASK - 1)
\---------------------------------------------------------------------------------*/

/*------------------2K-page beg ------------------------*/
#define CMCPGB_032MB_PAGE_2K_NUM  ((uint16_t)(1 << 14))
#define CMCPGB_016MB_PAGE_2K_NUM  ((uint16_t)(1 << 13))
#define CMCPGB_008MB_PAGE_2K_NUM  ((uint16_t)(1 << 12))
#define CMCPGB_004MB_PAGE_2K_NUM  ((uint16_t)(1 << 11))
#define CMCPGB_002MB_PAGE_2K_NUM  ((uint16_t)(1 << 10))
#define CMCPGB_001MB_PAGE_2K_NUM  ((uint16_t)(1 <<  9))
#define CMCPGB_512KB_PAGE_2K_NUM  ((uint16_t)(1 <<  8))
#define CMCPGB_256KB_PAGE_2K_NUM  ((uint16_t)(1 <<  7))
#define CMCPGB_128KB_PAGE_2K_NUM  ((uint16_t)(1 <<  6))
#define CMCPGB_064KB_PAGE_2K_NUM  ((uint16_t)(1 <<  5))
#define CMCPGB_032KB_PAGE_2K_NUM  ((uint16_t)(1 <<  4))
#define CMCPGB_016KB_PAGE_2K_NUM  ((uint16_t)(1 <<  3))
#define CMCPGB_008KB_PAGE_2K_NUM  ((uint16_t)(1 <<  2))
#define CMCPGB_004KB_PAGE_2K_NUM  ((uint16_t)(1 <<  1))
#define CMCPGB_002KB_PAGE_2K_NUM  ((uint16_t)(1 <<  0))

#define CMCPGB_PAGE_2K_MODEL_MASK       ((uint16_t)0x7FFF)

#define CMCPGB_PAGE_2K_BIT_SIZE         ((uint32_t)11)
#define CMCPGB_PAGE_2K_BYTE_SIZE        ((uint32_t)(1 << CMCPGB_PAGE_2K_BIT_SIZE))

#define CMCPGB_PAGE_2K_HI_BIT_MASK      ((uint16_t)0x4000)
#define CMCPGB_PAGE_2K_LO_BITS_MASK     ((uint16_t)0x3FFF)
/*------------------2K-page end ------------------------*/

/*------------------4K-page beg ------------------------*/
#define CMCPGB_032MB_PAGE_4K_NUM  ((uint16_t)(1 << 13))
#define CMCPGB_016MB_PAGE_4K_NUM  ((uint16_t)(1 << 12))
#define CMCPGB_008MB_PAGE_4K_NUM  ((uint16_t)(1 << 11))
#define CMCPGB_004MB_PAGE_4K_NUM  ((uint16_t)(1 << 10))
#define CMCPGB_002MB_PAGE_4K_NUM  ((uint16_t)(1 <<  9))
#define CMCPGB_001MB_PAGE_4K_NUM  ((uint16_t)(1 <<  8))
#define CMCPGB_512KB_PAGE_4K_NUM  ((uint16_t)(1 <<  7))
#define CMCPGB_256KB_PAGE_4K_NUM  ((uint16_t)(1 <<  6))
#define CMCPGB_128KB_PAGE_4K_NUM  ((uint16_t)(1 <<  5))
#define CMCPGB_064KB_PAGE_4K_NUM  ((uint16_t)(1 <<  4))
#define CMCPGB_032KB_PAGE_4K_NUM  ((uint16_t)(1 <<  3))
#define CMCPGB_016KB_PAGE_4K_NUM  ((uint16_t)(1 <<  2))
#define CMCPGB_008KB_PAGE_4K_NUM  ((uint16_t)(1 <<  1))
#define CMCPGB_004KB_PAGE_4K_NUM  ((uint16_t)(1 <<  0))
#define CMCPGB_002KB_PAGE_4K_NUM  ((uint16_t)(0))

#define CMCPGB_PAGE_4K_MODEL_MASK       ((uint16_t)0x3FFF)

#define CMCPGB_PAGE_4K_BIT_SIZE         ((uint32_t)12)
#define CMCPGB_PAGE_4K_BYTE_SIZE        ((uint32_t)(1 << CMCPGB_PAGE_4K_BIT_SIZE))

#define CMCPGB_PAGE_4K_HI_BIT_MASK      ((uint16_t)0x2000)
#define CMCPGB_PAGE_4K_LO_BITS_MASK     ((uint16_t)0x1FFF)
/*------------------4K-page end ------------------------*/

/*------------------8K-page beg ------------------------*/
#define CMCPGB_032MB_PAGE_8K_NUM  ((uint16_t)(1 << 12))
#define CMCPGB_016MB_PAGE_8K_NUM  ((uint16_t)(1 << 11))
#define CMCPGB_008MB_PAGE_8K_NUM  ((uint16_t)(1 << 10))
#define CMCPGB_004MB_PAGE_8K_NUM  ((uint16_t)(1 <<  9))
#define CMCPGB_002MB_PAGE_8K_NUM  ((uint16_t)(1 <<  8))
#define CMCPGB_001MB_PAGE_8K_NUM  ((uint16_t)(1 <<  7))
#define CMCPGB_512KB_PAGE_8K_NUM  ((uint16_t)(1 <<  6))
#define CMCPGB_256KB_PAGE_8K_NUM  ((uint16_t)(1 <<  5))
#define CMCPGB_128KB_PAGE_8K_NUM  ((uint16_t)(1 <<  4))
#define CMCPGB_064KB_PAGE_8K_NUM  ((uint16_t)(1 <<  3))
#define CMCPGB_032KB_PAGE_8K_NUM  ((uint16_t)(1 <<  2))
#define CMCPGB_016KB_PAGE_8K_NUM  ((uint16_t)(1 <<  1))
#define CMCPGB_008KB_PAGE_8K_NUM  ((uint16_t)(1 <<  0))
#define CMCPGB_004KB_PAGE_8K_NUM  ((uint16_t)(0))
#define CMCPGB_002KB_PAGE_8K_NUM  ((uint16_t)(0))

#define CMCPGB_PAGE_8K_MODEL_MASK       ((uint16_t)0x1FFF)

#define CMCPGB_PAGE_8K_BIT_SIZE         ((uint32_t)13)
#define CMCPGB_PAGE_8K_BYTE_SIZE        ((uint32_t)(1 << CMCPGB_PAGE_8K_BIT_SIZE))

#define CMCPGB_PAGE_8K_HI_BIT_MASK      ((uint16_t)0x1000)
#define CMCPGB_PAGE_8K_LO_BITS_MASK     ((uint16_t)0x0FFF)
/*------------------8K-page end ------------------------*/

/*for debug*/
/*------------------16M-page beg ------------------------*/
#define CMCPGB_032MB_PAGE_16M_NUM  ((uint16_t)(1 << 1))
#define CMCPGB_016MB_PAGE_16M_NUM  ((uint16_t)(1 << 0))
#define CMCPGB_008MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_004MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_002MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_001MB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_512KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_256KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_128KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_064KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_032KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_016KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_008KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_004KB_PAGE_16M_NUM  ((uint16_t)(0))
#define CMCPGB_002KB_PAGE_16M_NUM  ((uint16_t)(0))

#define CMCPGB_PAGE_16M_MODEL_MASK       ((uint16_t)0x0003)

#define CMCPGB_PAGE_16M_BIT_SIZE         ((uint32_t)24)
#define CMCPGB_PAGE_16M_BYTE_SIZE        ((uint32_t)(1 << CMCPGB_PAGE_16M_BIT_SIZE))

#define CMCPGB_PAGE_16M_HI_BIT_MASK      ((uint16_t)0x0002)
#define CMCPGB_PAGE_16M_LO_BITS_MASK     ((uint16_t)0x0001)
/*------------------16M-page end ------------------------*/

/*------------------32M-page beg ------------------------*/
#define CMCPGB_032MB_PAGE_32M_NUM  ((uint16_t)(1 << 0))
#define CMCPGB_016MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_008MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_004MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_002MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_001MB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_512KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_256KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_128KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_064KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_032KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_016KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_008KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_004KB_PAGE_32M_NUM  ((uint16_t)(0))
#define CMCPGB_002KB_PAGE_32M_NUM  ((uint16_t)(0))

#define CMCPGB_PAGE_32M_MODEL_MASK       ((uint16_t)0x0001)

#define CMCPGB_PAGE_32M_BIT_SIZE         ((uint32_t)25)
#define CMCPGB_PAGE_32M_BYTE_SIZE        ((uint32_t)(1 << CMCPGB_PAGE_32M_BIT_SIZE))

#define CMCPGB_PAGE_32M_HI_BIT_MASK      ((uint16_t)0x0001)
#define CMCPGB_PAGE_32M_LO_BITS_MASK     ((uint16_t)0x0000)
/*------------------32M-page end ------------------------*/

#define CMCPGB_002K_PAGE_CHOICE         (1)
#define CMCPGB_004K_PAGE_CHOICE         (2)
#define CMCPGB_008K_PAGE_CHOICE         (3)
#define CMCPGB_016M_PAGE_CHOICE         (4)
#define CMCPGB_032M_PAGE_CHOICE         (5)

#define CMCPGB_PAGE_CHOICE              (CMCPGB_002K_PAGE_CHOICE)
//#define CMCPGB_PAGE_CHOICE              (CMCPGB_004K_PAGE_CHOICE)
//#define CMCPGB_PAGE_CHOICE              (CMCPGB_008K_PAGE_CHOICE)
//#define CMCPGB_PAGE_CHOICE              (CMCPGB_016M_PAGE_CHOICE)
//#define CMCPGB_PAGE_CHOICE              (CMCPGB_032M_PAGE_CHOICE)

/*--------------------------------------------------------------------------------------------*/
#if (CMCPGB_002K_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)
#define CMCPGB_032MB_PAGE_NUM           (CMCPGB_032MB_PAGE_2K_NUM)
#define CMCPGB_016MB_PAGE_NUM           (CMCPGB_016MB_PAGE_2K_NUM)
#define CMCPGB_008MB_PAGE_NUM           (CMCPGB_008MB_PAGE_2K_NUM)
#define CMCPGB_004MB_PAGE_NUM           (CMCPGB_004MB_PAGE_2K_NUM)
#define CMCPGB_002MB_PAGE_NUM           (CMCPGB_002MB_PAGE_2K_NUM)
#define CMCPGB_001MB_PAGE_NUM           (CMCPGB_001MB_PAGE_2K_NUM)
#define CMCPGB_512KB_PAGE_NUM           (CMCPGB_512KB_PAGE_2K_NUM)
#define CMCPGB_256KB_PAGE_NUM           (CMCPGB_256KB_PAGE_2K_NUM)
#define CMCPGB_128KB_PAGE_NUM           (CMCPGB_128KB_PAGE_2K_NUM)
#define CMCPGB_064KB_PAGE_NUM           (CMCPGB_064KB_PAGE_2K_NUM)
#define CMCPGB_032KB_PAGE_NUM           (CMCPGB_032KB_PAGE_2K_NUM)
#define CMCPGB_016KB_PAGE_NUM           (CMCPGB_016KB_PAGE_2K_NUM)
#define CMCPGB_008KB_PAGE_NUM           (CMCPGB_008KB_PAGE_2K_NUM)
#define CMCPGB_004KB_PAGE_NUM           (CMCPGB_004KB_PAGE_2K_NUM)
#define CMCPGB_002KB_PAGE_NUM           (CMCPGB_002KB_PAGE_2K_NUM)

#define CMCPGB_PAGE_BIT_SIZE            (CMCPGB_PAGE_2K_BIT_SIZE)
#define CMCPGB_PAGE_BYTE_SIZE           (CMCPGB_PAGE_2K_BYTE_SIZE)

#define CMCPGB_PAGE_HI_BIT_MASK         (CMCPGB_PAGE_2K_HI_BIT_MASK)
#define CMCPGB_PAGE_LO_BITS_MASK        (CMCPGB_PAGE_2K_LO_BITS_MASK)

/*actual used cmcpgb model num*/
#define CMCPGB_MODEL_NUM                (CMCPGB_002KB_MODEL + 1)/*15*/
#define CMCPGB_MODEL_MASK_ALL           (CMCPGB_PAGE_2K_MODEL_MASK)
#endif/*(CMCPGB_002K_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)*/

#if (CMCPGB_004K_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)
#define CMCPGB_032MB_PAGE_NUM           (CMCPGB_032MB_PAGE_4K_NUM)
#define CMCPGB_016MB_PAGE_NUM           (CMCPGB_016MB_PAGE_4K_NUM)
#define CMCPGB_008MB_PAGE_NUM           (CMCPGB_008MB_PAGE_4K_NUM)
#define CMCPGB_004MB_PAGE_NUM           (CMCPGB_004MB_PAGE_4K_NUM)
#define CMCPGB_002MB_PAGE_NUM           (CMCPGB_002MB_PAGE_4K_NUM)
#define CMCPGB_001MB_PAGE_NUM           (CMCPGB_001MB_PAGE_4K_NUM)
#define CMCPGB_512KB_PAGE_NUM           (CMCPGB_512KB_PAGE_4K_NUM)
#define CMCPGB_256KB_PAGE_NUM           (CMCPGB_256KB_PAGE_4K_NUM)
#define CMCPGB_128KB_PAGE_NUM           (CMCPGB_128KB_PAGE_4K_NUM)
#define CMCPGB_064KB_PAGE_NUM           (CMCPGB_064KB_PAGE_4K_NUM)
#define CMCPGB_032KB_PAGE_NUM           (CMCPGB_032KB_PAGE_4K_NUM)
#define CMCPGB_016KB_PAGE_NUM           (CMCPGB_016KB_PAGE_4K_NUM)
#define CMCPGB_008KB_PAGE_NUM           (CMCPGB_008KB_PAGE_4K_NUM)
#define CMCPGB_004KB_PAGE_NUM           (CMCPGB_004KB_PAGE_4K_NUM)
#define CMCPGB_002KB_PAGE_NUM           (CMCPGB_002KB_PAGE_4K_NUM)

#define CMCPGB_PAGE_BIT_SIZE            (CMCPGB_PAGE_4K_BIT_SIZE)
#define CMCPGB_PAGE_BYTE_SIZE           (CMCPGB_PAGE_4K_BYTE_SIZE)

#define CMCPGB_PAGE_HI_BIT_MASK         (CMCPGB_PAGE_4K_HI_BIT_MASK)
#define CMCPGB_PAGE_LO_BITS_MASK        (CMCPGB_PAGE_4K_LO_BITS_MASK)

/*actual used cmcpgb model num*/
#define CMCPGB_MODEL_NUM                (CMCPGB_004KB_MODEL + 1)/*14*/
#define CMCPGB_MODEL_MASK_ALL           (CMCPGB_PAGE_4K_MODEL_MASK)
#endif/*(CMCPGB_004K_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)*/

#if (CMCPGB_008K_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)
#define CMCPGB_032MB_PAGE_NUM           (CMCPGB_032MB_PAGE_8K_NUM)
#define CMCPGB_016MB_PAGE_NUM           (CMCPGB_016MB_PAGE_8K_NUM)
#define CMCPGB_008MB_PAGE_NUM           (CMCPGB_008MB_PAGE_8K_NUM)
#define CMCPGB_004MB_PAGE_NUM           (CMCPGB_004MB_PAGE_8K_NUM)
#define CMCPGB_002MB_PAGE_NUM           (CMCPGB_002MB_PAGE_8K_NUM)
#define CMCPGB_001MB_PAGE_NUM           (CMCPGB_001MB_PAGE_8K_NUM)
#define CMCPGB_512KB_PAGE_NUM           (CMCPGB_512KB_PAGE_8K_NUM)
#define CMCPGB_256KB_PAGE_NUM           (CMCPGB_256KB_PAGE_8K_NUM)
#define CMCPGB_128KB_PAGE_NUM           (CMCPGB_128KB_PAGE_8K_NUM)
#define CMCPGB_064KB_PAGE_NUM           (CMCPGB_064KB_PAGE_8K_NUM)
#define CMCPGB_032KB_PAGE_NUM           (CMCPGB_032KB_PAGE_8K_NUM)
#define CMCPGB_016KB_PAGE_NUM           (CMCPGB_016KB_PAGE_8K_NUM)
#define CMCPGB_008KB_PAGE_NUM           (CMCPGB_008KB_PAGE_8K_NUM)
#define CMCPGB_004KB_PAGE_NUM           (CMCPGB_004KB_PAGE_8K_NUM)
#define CMCPGB_002KB_PAGE_NUM           (CMCPGB_004KB_PAGE_2K_NUM)

#define CMCPGB_PAGE_BIT_SIZE            (CMCPGB_PAGE_8K_BIT_SIZE)
#define CMCPGB_PAGE_BYTE_SIZE           (CMCPGB_PAGE_8K_BYTE_SIZE)

#define CMCPGB_PAGE_HI_BIT_MASK         (CMCPGB_PAGE_8K_HI_BIT_MASK)
#define CMCPGB_PAGE_LO_BITS_MASK        (CMCPGB_PAGE_8K_LO_BITS_MASK)

/*actual used cmcpgb model num*/
#define CMCPGB_MODEL_NUM                (CMCPGB_008KB_MODEL + 1)/*13*/
#define CMCPGB_MODEL_MASK_ALL           (CMCPGB_PAGE_8K_MODEL_MASK)
#endif/*(CMCPGB_008K_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)*/


#if (CMCPGB_016M_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)
#define CMCPGB_032MB_PAGE_NUM           (CMCPGB_032MB_PAGE_16M_NUM)
#define CMCPGB_016MB_PAGE_NUM           (CMCPGB_016MB_PAGE_16M_NUM)
#define CMCPGB_008MB_PAGE_NUM           (CMCPGB_008MB_PAGE_16M_NUM)
#define CMCPGB_004MB_PAGE_NUM           (CMCPGB_004MB_PAGE_16M_NUM)
#define CMCPGB_002MB_PAGE_NUM           (CMCPGB_002MB_PAGE_16M_NUM)
#define CMCPGB_001MB_PAGE_NUM           (CMCPGB_001MB_PAGE_16M_NUM)
#define CMCPGB_512KB_PAGE_NUM           (CMCPGB_512KB_PAGE_16M_NUM)
#define CMCPGB_256KB_PAGE_NUM           (CMCPGB_256KB_PAGE_16M_NUM)
#define CMCPGB_128KB_PAGE_NUM           (CMCPGB_128KB_PAGE_16M_NUM)
#define CMCPGB_064KB_PAGE_NUM           (CMCPGB_064KB_PAGE_16M_NUM)
#define CMCPGB_032KB_PAGE_NUM           (CMCPGB_032KB_PAGE_16M_NUM)
#define CMCPGB_016KB_PAGE_NUM           (CMCPGB_016KB_PAGE_16M_NUM)
#define CMCPGB_008KB_PAGE_NUM           (CMCPGB_008KB_PAGE_16M_NUM)
#define CMCPGB_004KB_PAGE_NUM           (CMCPGB_004KB_PAGE_16M_NUM)
#define CMCPGB_002KB_PAGE_NUM           (CMCPGB_002KB_PAGE_16M_NUM)

#define CMCPGB_PAGE_BIT_SIZE            (CMCPGB_PAGE_16M_BIT_SIZE)
#define CMCPGB_PAGE_BYTE_SIZE           (CMCPGB_PAGE_16M_BYTE_SIZE)

#define CMCPGB_PAGE_HI_BIT_MASK         (CMCPGB_PAGE_16M_HI_BIT_MASK)
#define CMCPGB_PAGE_LO_BITS_MASK        (CMCPGB_PAGE_16M_LO_BITS_MASK)

/*actual used cmcpgb model num*/
#define CMCPGB_MODEL_NUM                (CMCPGB_016MB_MODEL + 1)/*2*/
#define CMCPGB_MODEL_MASK_ALL           (CMCPGB_PAGE_16M_MODEL_MASK)
#endif/*(CMCPGB_016M_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)*/

#if (CMCPGB_032M_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)
#define CMCPGB_032MB_PAGE_NUM           (CMCPGB_032MB_PAGE_32M_NUM)
#define CMCPGB_016MB_PAGE_NUM           (CMCPGB_016MB_PAGE_32M_NUM)
#define CMCPGB_008MB_PAGE_NUM           (CMCPGB_008MB_PAGE_32M_NUM)
#define CMCPGB_004MB_PAGE_NUM           (CMCPGB_004MB_PAGE_32M_NUM)
#define CMCPGB_002MB_PAGE_NUM           (CMCPGB_002MB_PAGE_32M_NUM)
#define CMCPGB_001MB_PAGE_NUM           (CMCPGB_001MB_PAGE_32M_NUM)
#define CMCPGB_512KB_PAGE_NUM           (CMCPGB_512KB_PAGE_32M_NUM)
#define CMCPGB_256KB_PAGE_NUM           (CMCPGB_256KB_PAGE_32M_NUM)
#define CMCPGB_128KB_PAGE_NUM           (CMCPGB_128KB_PAGE_32M_NUM)
#define CMCPGB_064KB_PAGE_NUM           (CMCPGB_064KB_PAGE_32M_NUM)
#define CMCPGB_032KB_PAGE_NUM           (CMCPGB_032KB_PAGE_32M_NUM)
#define CMCPGB_016KB_PAGE_NUM           (CMCPGB_016KB_PAGE_32M_NUM)
#define CMCPGB_008KB_PAGE_NUM           (CMCPGB_008KB_PAGE_32M_NUM)
#define CMCPGB_004KB_PAGE_NUM           (CMCPGB_004KB_PAGE_32M_NUM)
#define CMCPGB_002KB_PAGE_NUM           (CMCPGB_002KB_PAGE_32M_NUM)

#define CMCPGB_PAGE_BIT_SIZE            (CMCPGB_PAGE_32M_BIT_SIZE)
#define CMCPGB_PAGE_BYTE_SIZE           (CMCPGB_PAGE_32M_BYTE_SIZE)

#define CMCPGB_PAGE_HI_BIT_MASK         (CMCPGB_PAGE_32M_HI_BIT_MASK)
#define CMCPGB_PAGE_LO_BITS_MASK        (CMCPGB_PAGE_32M_LO_BITS_MASK)

/*actual used cmcpgb model num*/
#define CMCPGB_MODEL_NUM                (CMCPGB_032MB_MODEL + 1)/*1*/
#define CMCPGB_MODEL_MASK_ALL           (CMCPGB_PAGE_32M_MODEL_MASK)
#endif/*(CMCPGB_032M_PAGE_CHOICE == CMCPGB_PAGE_CHOICE)*/


/*--------------------------------------------------------------------------------------------*/

#define CMCPGB_PAGE_IS_FREE             ((uint8_t) 1)
#define CMCPGB_PAGE_IS_NOT_FREE         ((uint8_t) 0)

typedef struct
{
    uint8_t         pgb_rb_bitmap_buff[ CMCPGB_RB_BITMAP_SIZE ];
    uint8_t         rsvd1[CMCPGB_RB_BITMAP_PAD_SIZE];

    uint16_t        pgb_rb_root_pos[ CMCPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t        pgb_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/

    uint16_t        pgb_page_max_num; /*max page number*/
    uint16_t        pgb_page_used_num;/*used page number*/
    uint32_t        pgb_actual_used_size;/*actual used bytes*/

    CMCPGRB_POOL    pgb_rb_pool;
}CMCPGB;/*4k-alignment*/

#define CMCPGB_CMCPGRB_POOL(cmcpgb)                              (&((cmcpgb)->pgb_rb_pool))
#define CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS_TBL(cmcpgb)           ((cmcpgb)->pgb_rb_root_pos)
#define CMCPGB_PAGE_MODEL_CMCPGRB_ROOT_POS(cmcpgb, page_model)   ((cmcpgb)->pgb_rb_root_pos[ (page_model) ])
#define CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP_BUFF(cmcpgb)            ((cmcpgb)->pgb_rb_bitmap_buff)
#define CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP(cmcpgb, page_model)     ((uint8_t *)CMCPGB_PAGE_MODEL_CMCPGRB_BITMAP_BUFF(cmcpgb) + g_cmcpgb_bitmap_offset[ (page_model)])
#define CMCPGB_PAGE_MODEL_ASSIGN_BITMAP(cmcpgb)                  ((cmcpgb)->pgb_assign_bitmap)
#define CMCPGB_PAGE_MAX_NUM(cmcpgb)                              ((cmcpgb)->pgb_page_max_num)
#define CMCPGB_PAGE_USED_NUM(cmcpgb)                             ((cmcpgb)->pgb_page_used_num)
#define CMCPGB_PAGE_ACTUAL_USED_SIZE(cmcpgb)                     ((cmcpgb)->pgb_actual_used_size)

/*rb_node num = half of page num (enough!)*/
#define CMCPGB_SIZE        (sizeof(CMCPGB) + sizeof(CMCPGRB_NODE) * ((CMCPGB_032MB_PAGE_NUM + 1) >> 1))

typedef struct
{
    const char *name;
    uint16_t    page_model;
    uint16_t    cpgrb_bitmap_size;
    uint16_t    page_num;
    uint16_t    rsvd;
}CMCPGB_CONF;

#define CMCPGB_CONF_NAME(cmcpgb_conf)                 ((cmcpgb_conf)->name)
#define CMCPGB_CONF_PAGE_MODEL(cmcpgb_conf)           ((cmcpgb_conf)->page_model)
#define CMCPGB_CONF_CMCPGRB_BITMAP_SIZE(cmcpgb_conf)  ((cmcpgb_conf)->cpgrb_bitmap_size)
#define CMCPGB_CONF_PAGE_NUM(cmcpgb_conf)             ((cmcpgb_conf)->page_num)

const char *cmcpgb_model_str(const uint16_t pgb_page_num);

/* one page cache = 32MB */
EC_BOOL cmcpgb_init(CMCPGB *cmcpgb, const uint16_t page_model_target);

void cmcpgb_clean(CMCPGB *cmcpgb);

/*add one free page into pool and set page model bitmap*/
EC_BOOL cmcpgb_add_page(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t page_no);

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cmcpgb_del_page(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t page_no);

uint16_t cmcpgb_assign_page(CMCPGB *cmcpgb, const uint16_t page_model);

EC_BOOL cmcpgb_recycle_page(CMCPGB *cmcpgb, const uint16_t page_model, const uint16_t page_no);

EC_BOOL cmcpgb_new_space(CMCPGB *cmcpgb, const uint32_t size, uint16_t *page_no);

EC_BOOL cmcpgb_free_space(CMCPGB *cmcpgb, const uint16_t page_start_no, const uint32_t size);

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cmcpgb_is_full(const CMCPGB *cmcpgb);

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cmcpgb_is_empty(const CMCPGB *cmcpgb);

EC_BOOL cmcpgb_check(const CMCPGB *cmcpgb);

void cmcpgb_print(LOG *log, const CMCPGB *cmcpgb);

EC_BOOL cmcpgb_debug_cmp(const CMCPGB *cmcpgb_1st, const CMCPGB *cmcpgb_2nd);

#endif    /* _CMCPGB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
