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

#ifndef    _CDCPGB_H
#define    _CDCPGB_H

#include "type.h"
#include "cdcpgrb.h"

/*page model*/
#define CDCPGB_032MB_MODEL    ((uint16_t) 0)
#define CDCPGB_016MB_MODEL    ((uint16_t) 1)
#define CDCPGB_008MB_MODEL    ((uint16_t) 2)
#define CDCPGB_004MB_MODEL    ((uint16_t) 3)
#define CDCPGB_002MB_MODEL    ((uint16_t) 4)
#define CDCPGB_001MB_MODEL    ((uint16_t) 5)
#define CDCPGB_512KB_MODEL    ((uint16_t) 6)
#define CDCPGB_256KB_MODEL    ((uint16_t) 7)
#define CDCPGB_128KB_MODEL    ((uint16_t) 8)
#define CDCPGB_064KB_MODEL    ((uint16_t) 9)
#define CDCPGB_032KB_MODEL    ((uint16_t)10)
#define CDCPGB_016KB_MODEL    ((uint16_t)11)
#define CDCPGB_008KB_MODEL    ((uint16_t)12)
#define CDCPGB_004KB_MODEL    ((uint16_t)13)
#define CDCPGB_002KB_MODEL    ((uint16_t)14)
#define CDCPGB_MODEL_MAX_NUM  ((uint16_t)15)

/*32M-block*/
#define CDCPGB_SIZE_NBITS     ((uint32_t)25) /*32MB block*/
#define CDCPGB_SIZE_NBYTES    ((uint32_t)(1 << CDCPGB_SIZE_NBITS)) /*32MB*/
#define CDCPGB_SIZE_MASK      ((uint32_t)(CDCPGB_SIZE_NBYTES - 1))
#define CDCPGB_PAGE_MODEL     (CDCPGB_032MB_MODEL)

#define CDCPGB_002K_PAGE      ( 1)
#define CDCPGB_004K_PAGE      ( 2)
#define CDCPGB_008K_PAGE      ( 3)
#define CDCPGB_016K_PAGE      ( 4)
#define CDCPGB_032K_PAGE      ( 5)
#define CDCPGB_064K_PAGE      ( 6)
#define CDCPGB_128K_PAGE      ( 7)
#define CDCPGB_256K_PAGE      ( 8)
#define CDCPGB_512K_PAGE      ( 9)
#define CDCPGB_001M_PAGE      (10)
#define CDCPGB_002M_PAGE      (11)
#define CDCPGB_004M_PAGE      (12)
#define CDCPGB_008M_PAGE      (13)
#define CDCPGB_016M_PAGE      (14)
#define CDCPGB_032M_PAGE      (15)

//#define CDCPGB_PAGE_CHOICE              (CDCPGB_002K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_004K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_008K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_016K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_032K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_064K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_128K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_256K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_512K_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_001M_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_002M_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_004M_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_008M_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_016M_PAGE)
//#define CDCPGB_PAGE_CHOICE              (CDCPGB_032M_PAGE)

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
    ---------------------------------------------------------------------------------
    sum(bitmap of num in bytes) = 4098
 ================================================================================================

   32M-block = (size of page model) * (num of page model)

\---------------------------------------------------------------------------------*/

/*num of bytes represent the bitmap*/
#define CDCPGB_032MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CDCPGB_016MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CDCPGB_008MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CDCPGB_004MB_BITMAP_SIZE  ((uint16_t)(1 <<  0))
#define CDCPGB_002MB_BITMAP_SIZE  ((uint16_t)(1 <<  1))
#define CDCPGB_001MB_BITMAP_SIZE  ((uint16_t)(1 <<  2))
#define CDCPGB_512KB_BITMAP_SIZE  ((uint16_t)(1 <<  3))
#define CDCPGB_256KB_BITMAP_SIZE  ((uint16_t)(1 <<  4))
#define CDCPGB_128KB_BITMAP_SIZE  ((uint16_t)(1 <<  5))
#define CDCPGB_064KB_BITMAP_SIZE  ((uint16_t)(1 <<  6))
#define CDCPGB_032KB_BITMAP_SIZE  ((uint16_t)(1 <<  7))
#define CDCPGB_016KB_BITMAP_SIZE  ((uint16_t)(1 <<  8))
#define CDCPGB_008KB_BITMAP_SIZE  ((uint16_t)(1 <<  9))
#define CDCPGB_004KB_BITMAP_SIZE  ((uint16_t)(1 << 10))
#define CDCPGB_002KB_BITMAP_SIZE  ((uint16_t)(1 << 11))

#define CDCPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL ((uint16_t)0)
#define CDCPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_032MB_MODEL + CDCPGB_032MB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL + CDCPGB_016MB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL + CDCPGB_008MB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL + CDCPGB_004MB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL + CDCPGB_002MB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL + CDCPGB_001MB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL + CDCPGB_512KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL + CDCPGB_256KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL + CDCPGB_128KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL + CDCPGB_064KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL + CDCPGB_032KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL + CDCPGB_016KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL + CDCPGB_008KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_002KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL + CDCPGB_004KB_BITMAP_SIZE)
#define CDCPGB_RB_BITMAP_OFFSET_OF_001KB_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_002KB_MODEL + CDCPGB_002KB_BITMAP_SIZE)

#define CDCPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL (CDCPGB_RB_BITMAP_OFFSET_OF_001KB_MODEL)

//#define CDCPGB_RB_BITMAP_SIZE                  (CDCPGB_RB_BITMAP_OFFSET_OF_ENDOF_MODEL)/*=4098*/
//#define CDCPGB_RB_BITMAP_PAD_SIZE              (8 - (CDCPGB_RB_BITMAP_SIZE & 7))/*=6*/

/*---------------------------------------------------------------------------------\
 reference table
 ==================================================================================
    PAGE       PAGE_SIZE_NBITS  HI_BITS_MASK CDCPGB_MODEL_MASK_ALL   MASK N-BITS
    2K         11               0x4000       0x7FFF                  15
    4K         12               0x2000       0x3FFF                  14
    8K         13               0x1000       0x1FFF                  13
    16K        14               0x0800       0x0FFF                  12
    32K        15               0x0400       0x07FF                  11
    64K        16               0x0200       0x03FF                  10
    128K       17               0x0100       0x01FF                  9
    256K       18               0x0080       0x00FF                  8
    512K       19               0x0040       0x007F                  7
    1M         20               0x0020       0x003F                  6
    2M         21               0x0010       0x001F                  5
    4M         22               0x0008       0x000F                  4
    8M         23               0x0004       0x0007                  3
    16M        24               0x0002       0x0003                  2
    32M        25               0x0001       0x0001                  1
 ==================================================================================
 note: (LO_BITS_MASK = HI_BITS_MASK- 1)
\---------------------------------------------------------------------------------*/

/*------------------2K-page beg ------------------------*/
#define CDCPGB_PAGE_2K_MODEL_MASK       ((uint16_t)0x7FFF)

#define CDCPGB_PAGE_2K_SIZE_NBITS       ((uint32_t)11)
#define CDCPGB_PAGE_2K_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_2K_SIZE_NBITS))

#define CDCPGB_PAGE_2K_HI_BITS_MASK     ((uint16_t)0x4000)
#define CDCPGB_PAGE_2K_LO_BITS_MASK     ((uint16_t)0x3FFF)
/*------------------2K-page end ------------------------*/

/*------------------4K-page beg ------------------------*/
#define CDCPGB_PAGE_4K_MODEL_MASK       ((uint16_t)0x3FFF)

#define CDCPGB_PAGE_4K_SIZE_NBITS       ((uint32_t)12)
#define CDCPGB_PAGE_4K_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_4K_SIZE_NBITS))

#define CDCPGB_PAGE_4K_HI_BITS_MASK     ((uint16_t)0x2000)
#define CDCPGB_PAGE_4K_LO_BITS_MASK     ((uint16_t)0x1FFF)
/*------------------4K-page end ------------------------*/

/*------------------8K-page beg ------------------------*/
#define CDCPGB_PAGE_8K_MODEL_MASK       ((uint16_t)0x1FFF)

#define CDCPGB_PAGE_8K_SIZE_NBITS       ((uint32_t)13)
#define CDCPGB_PAGE_8K_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_8K_SIZE_NBITS))

#define CDCPGB_PAGE_8K_HI_BITS_MASK     ((uint16_t)0x1000)
#define CDCPGB_PAGE_8K_LO_BITS_MASK     ((uint16_t)0x0FFF)
/*------------------8K-page end ------------------------*/

/*------------------16K-page beg ------------------------*/
#define CDCPGB_PAGE_16K_MODEL_MASK       ((uint16_t)0x0FFF)

#define CDCPGB_PAGE_16K_SIZE_NBITS       ((uint32_t)14)
#define CDCPGB_PAGE_16K_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_16K_SIZE_NBITS))

#define CDCPGB_PAGE_16K_HI_BITS_MASK     ((uint16_t)0x0800)
#define CDCPGB_PAGE_16K_LO_BITS_MASK     ((uint16_t)0x07FF)
/*------------------16K-page end ------------------------*/

/*------------------32K-page beg ------------------------*/
#define CDCPGB_PAGE_32K_MODEL_MASK       ((uint16_t)0x07FF)

#define CDCPGB_PAGE_32K_SIZE_NBITS       ((uint32_t)15)
#define CDCPGB_PAGE_32K_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_32K_SIZE_NBITS))

#define CDCPGB_PAGE_32K_HI_BITS_MASK     ((uint16_t)0x0400)
#define CDCPGB_PAGE_32K_LO_BITS_MASK     ((uint16_t)0x03FF)
/*------------------32K-page end ------------------------*/

/*------------------64K-page beg ------------------------*/
#define CDCPGB_PAGE_64K_MODEL_MASK       ((uint16_t)0x03FF)

#define CDCPGB_PAGE_64K_SIZE_NBITS       ((uint32_t)16)
#define CDCPGB_PAGE_64K_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_64K_SIZE_NBITS))

#define CDCPGB_PAGE_64K_HI_BITS_MASK     ((uint16_t)0x0200)
#define CDCPGB_PAGE_64K_LO_BITS_MASK     ((uint16_t)0x01FF)
/*------------------64K-page end ------------------------*/

/*------------------128K-page beg ------------------------*/
#define CDCPGB_PAGE_128K_MODEL_MASK      ((uint16_t)0x01FF)

#define CDCPGB_PAGE_128K_SIZE_NBITS      ((uint32_t)17)
#define CDCPGB_PAGE_128K_SIZE_NBYTES     ((uint32_t)(1 << CDCPGB_PAGE_128K_SIZE_NBITS))

#define CDCPGB_PAGE_128K_HI_BITS_MASK    ((uint16_t)0x0100)
#define CDCPGB_PAGE_128K_LO_BITS_MASK    ((uint16_t)0x00FF)
/*------------------128K-page end ------------------------*/

/*------------------256K-page beg ------------------------*/
#define CDCPGB_PAGE_256K_MODEL_MASK      ((uint16_t)0x00FF)

#define CDCPGB_PAGE_256K_SIZE_NBITS      ((uint32_t)18)
#define CDCPGB_PAGE_256K_SIZE_NBYTES     ((uint32_t)(1 << CDCPGB_PAGE_256K_SIZE_NBITS))

#define CDCPGB_PAGE_256K_HI_BITS_MASK    ((uint16_t)0x0080)
#define CDCPGB_PAGE_256K_LO_BITS_MASK    ((uint16_t)0x007F)
/*------------------256K-page end ------------------------*/

/*------------------512K-page beg ------------------------*/
#define CDCPGB_PAGE_512K_MODEL_MASK      ((uint16_t)0x007F)

#define CDCPGB_PAGE_512K_SIZE_NBITS      ((uint32_t)19)
#define CDCPGB_PAGE_512K_SIZE_NBYTES     ((uint32_t)(1 << CDCPGB_PAGE_512K_SIZE_NBITS))

#define CDCPGB_PAGE_512K_HI_BITS_MASK    ((uint16_t)0x0040)
#define CDCPGB_PAGE_512K_LO_BITS_MASK    ((uint16_t)0x003F)
/*------------------512K-page end ------------------------*/

/*------------------1M-page beg ------------------------*/
#define CDCPGB_PAGE_1M_MODEL_MASK        ((uint16_t)0x003F)

#define CDCPGB_PAGE_1M_SIZE_NBITS        ((uint32_t)20)
#define CDCPGB_PAGE_1M_SIZE_NBYTES       ((uint32_t)(1 << CDCPGB_PAGE_1M_SIZE_NBITS))

#define CDCPGB_PAGE_1M_HI_BITS_MASK      ((uint16_t)0x0020)
#define CDCPGB_PAGE_1M_LO_BITS_MASK      ((uint16_t)0x001F)
/*------------------1M-page end ------------------------*/

/*------------------2M-page beg ------------------------*/
#define CDCPGB_PAGE_2M_MODEL_MASK        ((uint16_t)0x001F)

#define CDCPGB_PAGE_2M_SIZE_NBITS        ((uint32_t)21)
#define CDCPGB_PAGE_2M_SIZE_NBYTES       ((uint32_t)(1 << CDCPGB_PAGE_2M_SIZE_NBITS))

#define CDCPGB_PAGE_2M_HI_BITS_MASK      ((uint16_t)0x0010)
#define CDCPGB_PAGE_2M_LO_BITS_MASK      ((uint16_t)0x000F)
/*------------------2M-page end ------------------------*/

/*------------------4M-page beg ------------------------*/
#define CDCPGB_PAGE_4M_MODEL_MASK        ((uint16_t)0x000F)

#define CDCPGB_PAGE_4M_SIZE_NBITS        ((uint32_t)22)
#define CDCPGB_PAGE_4M_SIZE_NBYTES       ((uint32_t)(1 << CDCPGB_PAGE_4M_SIZE_NBITS))

#define CDCPGB_PAGE_4M_HI_BITS_MASK      ((uint16_t)0x0008)
#define CDCPGB_PAGE_4M_LO_BITS_MASK      ((uint16_t)0x0007)
/*------------------4M-page end ------------------------*/

/*------------------8M-page beg ------------------------*/
#define CDCPGB_PAGE_8M_MODEL_MASK        ((uint16_t)0x0007)

#define CDCPGB_PAGE_8M_SIZE_NBITS        ((uint32_t)23)
#define CDCPGB_PAGE_8M_SIZE_NBYTES       ((uint32_t)(1 << CDCPGB_PAGE_8M_SIZE_NBITS))

#define CDCPGB_PAGE_8M_HI_BITS_MASK      ((uint16_t)0x0004)
#define CDCPGB_PAGE_8M_LO_BITS_MASK      ((uint16_t)0x0003)
/*------------------8M-page end ------------------------*/

/*for debug*/
/*------------------16M-page beg ------------------------*/
#define CDCPGB_PAGE_16M_MODEL_MASK       ((uint16_t)0x0003)

#define CDCPGB_PAGE_16M_SIZE_NBITS       ((uint32_t)24)
#define CDCPGB_PAGE_16M_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_16M_SIZE_NBITS))

#define CDCPGB_PAGE_16M_HI_BITS_MASK     ((uint16_t)0x0002)
#define CDCPGB_PAGE_16M_LO_BITS_MASK     ((uint16_t)0x0001)
/*------------------16M-page end ------------------------*/

/*------------------32M-page beg ------------------------*/
#define CDCPGB_PAGE_32M_MODEL_MASK       ((uint16_t)0x0001)

#define CDCPGB_PAGE_32M_SIZE_NBITS       ((uint32_t)25)
#define CDCPGB_PAGE_32M_SIZE_NBYTES      ((uint32_t)(1 << CDCPGB_PAGE_32M_SIZE_NBITS))

#define CDCPGB_PAGE_32M_HI_BITS_MASK     ((uint16_t)0x0001)
#define CDCPGB_PAGE_32M_LO_BITS_MASK     ((uint16_t)0x0000)
/*------------------32M-page end ------------------------*/

/*--------------------------------------------------------------------------------------------*/
#if (CDCPGB_002K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_2K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_2K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("2K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_2K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_2K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_002KB_MODEL + 1)/*15*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_2K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_001KB_MODEL)/*=4098*/
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)/*=6*/
#endif/*(CDCPGB_002K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_004K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_4K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_4K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("4K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_4K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_4K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_004KB_MODEL + 1)/*14*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_4K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_002KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_004K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_008K_PAGE == CDCPGB_PAGE_CHOICE)

#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_8K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_8K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("8K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_8K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_8K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_008KB_MODEL + 1)/*13*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_8K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_004KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_008K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_016K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_16K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_16K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("16K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_16K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_16K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_016KB_MODEL + 1)/*12*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_16K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_008KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_016K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_032K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_32K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_32K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("32K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_32K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_32K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_032KB_MODEL + 1)/*11*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_32K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_016KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_032K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_064K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_64K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_64K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("64K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_64K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_64K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_064KB_MODEL + 1)/*10*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_64K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_032KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_064K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_128K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_128K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_128K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("128K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_128K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_128K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_128KB_MODEL + 1)/*9*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_128K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_064KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_128K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_256K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_256K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_256K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("256K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_256K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_256K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_256KB_MODEL + 1)/*8*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_256K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_128KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_256K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_512K_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_512K_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_512K_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("512K-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_512K_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_512K_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_512KB_MODEL + 1)/*7*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_512K_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_256KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_512K_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_001M_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_1M_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_1M_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("1M-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_1M_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_1M_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_001MB_MODEL + 1)/*6*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_1M_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_512KB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_001M_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_002M_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_2M_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_2M_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("2M-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_2M_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_2M_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_002MB_MODEL + 1)/*5*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_2M_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_001MB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_002M_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_004M_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_4M_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_4M_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("4M-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_4M_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_4M_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_004MB_MODEL + 1)/*4*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_4M_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_002MB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_004M_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_008M_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_8M_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_8M_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("8M-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_8M_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_8M_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_008MB_MODEL + 1)/*3*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_8M_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_004MB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_008M_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_016M_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_16M_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_16M_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("16M-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_16M_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_16M_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_016MB_MODEL + 1)/*2*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_16M_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_008MB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_016M_PAGE == CDCPGB_PAGE_CHOICE)*/

#if (CDCPGB_032M_PAGE == CDCPGB_PAGE_CHOICE)
#define CDCPGB_PAGE_SIZE_NBITS           (CDCPGB_PAGE_32M_SIZE_NBITS)
#define CDCPGB_PAGE_SIZE_NBYTES          (CDCPGB_PAGE_32M_SIZE_NBYTES)
#define CDCPGB_PAGE_DESC                 ("32M-page")

#define CDCPGB_PAGE_HI_BITS_MASK         (CDCPGB_PAGE_32M_HI_BITS_MASK)
#define CDCPGB_PAGE_LO_BITS_MASK         (CDCPGB_PAGE_32M_LO_BITS_MASK)

/*actual used cdcpgb model num*/
#define CDCPGB_MODEL_NUM                 (CDCPGB_032MB_MODEL + 1)/*1*/
#define CDCPGB_MODEL_MASK_ALL            (CDCPGB_PAGE_32M_MODEL_MASK)

#define CDCPGB_RB_BITMAP_SIZE            (CDCPGB_RB_BITMAP_OFFSET_OF_016MB_MODEL)
#define CDCPGB_RB_BITMAP_PAD_SIZE        (((~CDCPGB_RB_BITMAP_SIZE) + 1) & 7)
#endif/*(CDCPGB_032M_PAGE == CDCPGB_PAGE_CHOICE)*/

#define CDCPGB_PAGE_SIZE_MASK            (CDCPGB_PAGE_SIZE_NBYTES - 1)
#define CDCPGB_PAGE_NUM                  ((uint16_t)(1 << (CDCPGB_SIZE_NBITS - CDCPGB_PAGE_SIZE_NBITS)))

/*--------------------------------------------------------------------------------------------*/

#define CDCPGB_PAGE_IS_FREE              ((uint8_t) 1)
#define CDCPGB_PAGE_IS_NOT_FREE          ((uint8_t) 0)

typedef struct
{
    uint8_t         pgb_rb_bitmap_buff[ CDCPGB_RB_BITMAP_SIZE ];
    uint8_t         rsvd1[CDCPGB_RB_BITMAP_PAD_SIZE];

    uint16_t        pgb_rb_root_pos[ CDCPGB_MODEL_MAX_NUM ];/*root pos of rbtree*/
    uint16_t        pgb_assign_bitmap; /*when some page model can provide pages or can borrow from upper, set bit to 1*/

    uint16_t        pgb_page_max_num; /*max page number*/
    uint16_t        pgb_page_used_num;/*used page number*/
    uint32_t        pgb_actual_used_size;/*actual used bytes*/

    CDCPGRB_POOL    pgb_rb_pool;
}CDCPGB;/*4k-alignment*/

#define CDCPGB_CDCPGRB_POOL(cdcpgb)                              (&((cdcpgb)->pgb_rb_pool))
#define CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS_TBL(cdcpgb)           ((cdcpgb)->pgb_rb_root_pos)
#define CDCPGB_PAGE_MODEL_CDCPGRB_ROOT_POS(cdcpgb, page_model)   ((cdcpgb)->pgb_rb_root_pos[ (page_model) ])
#define CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP_BUFF(cdcpgb)            ((cdcpgb)->pgb_rb_bitmap_buff)
#define CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP(cdcpgb, page_model)     ((uint8_t *)CDCPGB_PAGE_MODEL_CDCPGRB_BITMAP_BUFF(cdcpgb) + g_cdcpgb_bitmap_offset[ (page_model)])
#define CDCPGB_PAGE_MODEL_ASSIGN_BITMAP(cdcpgb)                  ((cdcpgb)->pgb_assign_bitmap)
#define CDCPGB_PAGE_MAX_NUM(cdcpgb)                              ((cdcpgb)->pgb_page_max_num)
#define CDCPGB_PAGE_USED_NUM(cdcpgb)                             ((cdcpgb)->pgb_page_used_num)
#define CDCPGB_PAGE_ACTUAL_USED_SIZE(cdcpgb)                     ((cdcpgb)->pgb_actual_used_size)

/*rb_node num = half of page num (enough!)*/
#define CDCPGB_SIZE        (sizeof(CDCPGB) + sizeof(CDCPGRB_NODE) * ((uint32_t)((CDCPGB_PAGE_NUM + 1) >> 1)))

typedef struct
{
    const char *name;
    uint16_t    page_model;
    uint16_t    cpgrb_bitmap_size;
    uint32_t    rsvd;
}CDCPGB_CONF;

#define CDCPGB_CONF_NAME(cdcpgb_conf)                 ((cdcpgb_conf)->name)
#define CDCPGB_CONF_PAGE_MODEL(cdcpgb_conf)           ((cdcpgb_conf)->page_model)
#define CDCPGB_CONF_CDCPGRB_BITMAP_SIZE(cdcpgb_conf)  ((cdcpgb_conf)->cpgrb_bitmap_size)

/* one page cache = 32MB */
EC_BOOL cdcpgb_init(CDCPGB *cdcpgb, const uint16_t page_model_target);

void cdcpgb_clean(CDCPGB *cdcpgb);

/*add one free page into pool and set page model bitmap*/
EC_BOOL cdcpgb_add_page(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t page_no);

/*del one free page from pool and clear page model bitmap, i.e., del one page from pool and used it later*/
EC_BOOL cdcpgb_del_page(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t page_no);

uint16_t cdcpgb_assign_page(CDCPGB *cdcpgb, const uint16_t page_model);

EC_BOOL cdcpgb_recycle_page(CDCPGB *cdcpgb, const uint16_t page_model, const uint16_t page_no);

EC_BOOL cdcpgb_new_space(CDCPGB *cdcpgb, const uint32_t size, uint16_t *page_no);

EC_BOOL cdcpgb_free_space(CDCPGB *cdcpgb, const uint16_t page_start_no, const uint32_t size);

/*return true if all pages in block are used, otherwise return false*/
EC_BOOL cdcpgb_is_full(const CDCPGB *cdcpgb);

/*return true if no page in block is used and block is given, otherwise return false*/
EC_BOOL cdcpgb_is_empty(const CDCPGB *cdcpgb);

EC_BOOL cdcpgb_check(const CDCPGB *cdcpgb);

EC_BOOL cdcpgb_max_size(UINT32 *size);

void cdcpgb_print(LOG *log, const CDCPGB *cdcpgb);

EC_BOOL cdcpgb_debug_cmp(const CDCPGB *cdcpgb_1st, const CDCPGB *cdcpgb_2nd);

#endif    /* _CDCPGB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
