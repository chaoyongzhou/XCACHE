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

#ifndef _CTDNSNP_INC
#define _CTDNSNP_INC

#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cstring.h"

#include "chashalgo.h"
#include "cmd5.h"

#include "ctdnsnprb.h"

#define CTDNSNP_512K_MODEL   ((uint8_t) 0)
#define CTDNSNP_001M_MODEL   ((uint8_t) 1)
#define CTDNSNP_002M_MODEL   ((uint8_t) 2)
#define CTDNSNP_004M_MODEL   ((uint8_t) 3)
#define CTDNSNP_008M_MODEL   ((uint8_t) 4)
#define CTDNSNP_016M_MODEL   ((uint8_t) 5)
#define CTDNSNP_032M_MODEL   ((uint8_t) 6)
#define CTDNSNP_064M_MODEL   ((uint8_t) 7)
#define CTDNSNP_128M_MODEL   ((uint8_t) 8)
#define CTDNSNP_256M_MODEL   ((uint8_t) 9)
#define CTDNSNP_512M_MODEL   ((uint8_t)10)
#define CTDNSNP_001G_MODEL   ((uint8_t)11)
#define CTDNSNP_002G_MODEL   ((uint8_t)12)
#define CTDNSNP_004G_MODEL   ((uint8_t)13)


typedef struct
{   
    /*16B*/
    CTDNSNPRB_NODE   rb_node;
    
    /*64 bits (8B)*/
    UINT32           tcid;     /*primary key of rb tree*/
#if (32 == WORDSIZE)
    uint32_t         rsvd1;
#endif/*(32 == WORDSIZE)*/ 

    UINT32           ipaddr;   /*real ip*/
#if (32 == WORDSIZE)
    uint32_t         rsvd2;
#endif/*(32 == WORDSIZE)*/

} CTDNSNP_ITEM;/*32B*/

#define CTDNSNP_ITEM_RB_NODE(ctdnsnp_item)          (&((ctdnsnp_item)->rb_node))
#define CTDNSNP_ITEM_TCID(ctdnsnp_item)             ((ctdnsnp_item)->tcid)
#define CTDNSNP_ITEM_IPADDR(ctdnsnp_item)           ((ctdnsnp_item)->ipaddr)
#define CTDNSNP_ITEM_PORT(ctdnsnp_item)             (CTDNSNPRB_NODE_DATA(CTDNSNP_ITEM_RB_NODE(ctdnsnp_item)))

/*get CTDNSNP_ITEM from CTDNSNPRB_NODE*/
#define CTDNSNP_RB_NODE_ITEM(ctdnsnprb_node)        ((NULL_PTR == (ctdnsnprb_node)) ? NULL_PTR : \
    ((CTDNSNP_ITEM *)((char *)(ctdnsnprb_node)-(unsigned long)(&((CTDNSNP_ITEM *)0)->rb_node))))

/*item max num = file size / sizeof(CTDNSNP_ITEM) - delta where sizeof(CTDNSNP_ITEM) = 512 = 2^9*/
/*where delta = 4096, i.e., 4096 * 512B = 2MB, less than 1MB is bitmap of deleted items, left is other members or reserved bytes*/
#define CTDNSNP_ITEM_BIT_SIZE             (5)
#define CTDNSNP_ITEM_SIZEOF               (1 << CTDNSNP_ITEM_BIT_SIZE) /*it must be 32B*/

#define CTDNSNP_512K_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 19))
#define CTDNSNP_512K_CFG_ITEM_MAX_NUM     ((CTDNSNP_512K_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_001M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 20))
#define CTDNSNP_001M_CFG_ITEM_MAX_NUM     ((CTDNSNP_001M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_002M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 21))
#define CTDNSNP_002M_CFG_ITEM_MAX_NUM     ((CTDNSNP_002M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_004M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 22))
#define CTDNSNP_004M_CFG_ITEM_MAX_NUM     ((CTDNSNP_004M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CTDNSNP_008M_CFG_ITEM_MAX_NUM     ((CTDNSNP_008M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CTDNSNP_016M_CFG_ITEM_MAX_NUM     ((CTDNSNP_016M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CTDNSNP_032M_CFG_ITEM_MAX_NUM     ((CTDNSNP_032M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CTDNSNP_064M_CFG_ITEM_MAX_NUM     ((CTDNSNP_064M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CTDNSNP_128M_CFG_ITEM_MAX_NUM     ((CTDNSNP_128M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CTDNSNP_256M_CFG_ITEM_MAX_NUM     ((CTDNSNP_256M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CTDNSNP_512M_CFG_ITEM_MAX_NUM     ((CTDNSNP_512M_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CTDNSNP_001G_CFG_ITEM_MAX_NUM     ((CTDNSNP_001G_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CTDNSNP_002G_CFG_ITEM_MAX_NUM     ((CTDNSNP_002G_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

#if (64 == WORDSIZE)
#define CTDNSNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CTDNSNP_004G_CFG_ITEM_MAX_NUM     ((CTDNSNP_004G_CFG_FILE_SIZE >> CTDNSNP_ITEM_BIT_SIZE) - (2048*4))

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    UINT32         file_size; /*np file size*/
    uint32_t       item_max_num;
    uint32_t       rsvd;
}CTDNSNP_CFG;

#define CTDNSNP_CFG_MODEL_STR(ctdnsnp_cfg)              ((ctdnsnp_cfg)->model_str)
#define CTDNSNP_CFG_ALIAS_STR(ctdnsnp_cfg)              ((ctdnsnp_cfg)->alias_str)
#define CTDNSNP_CFG_FILE_SIZE(ctdnsnp_cfg)              ((ctdnsnp_cfg)->file_size)
#define CTDNSNP_CFG_ITEM_MAX_NUM(ctdnsnp_cfg)           ((ctdnsnp_cfg)->item_max_num)

#define CTDNSNP_ERR_MODEL                               ((uint32_t)0xF)  /*4 bits*/

#define CTDNSNP_ERR_ID                                  ((uint32_t)0xFFFFFFFF)

#define CTDNSNP_U32_BIT_POS_TO_U32_OFFSET(bit_pos)      ((bit_pos) >>  5)
#define CTDNSNP_U32_BIT_POS_TO_BIT_OFFSET(bit_pos)      ((bit_pos)  & 31)

#define CTDNSNP_HEADER_PAD_U8_SIZE                      (8 * 1024) /*8K*/

/*each np own one header*/
typedef struct
{    
    uint32_t         np_id;               /*ctdnsnp id              */    
    uint8_t          np_model;            /*ctdnsnp model           */    
    uint8_t          rsvd1;                    
    uint8_t          rsvd2;
    uint8_t          rsvd3;      

    uint8_t          pad[ CTDNSNP_HEADER_PAD_U8_SIZE - 8 - 24]; /*pad the first part to 8KB*/ 
    
    CTDNSNPRB_POOL   pool;                /*pool of CTDNSNP_ITEM, CTDNSNP_ITEM head must be CTDNSNPRB_NODE*/
} CTDNSNP_HEADER;

#define CTDNSNP_HEADER_NP_ID(ctdnsnp_header)              ((ctdnsnp_header)->np_id)
#define CTDNSNP_HEADER_NP_MODEL(ctdnsnp_header)           ((ctdnsnp_header)->np_model)

#define CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header)         (&((ctdnsnp_header)->pool))
#define CTDNSNP_HEADER_ITEMS_MAX_NUM(ctdnsnp_header)      (CTDNSNPRB_POOL_NODE_MAX_NUM(CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header)))
#define CTDNSNP_HEADER_ITEMS_USED_NUM(ctdnsnp_header)     (CTDNSNPRB_POOL_NODE_USED_NUM(CTDNSNP_HEADER_ITEMS_POOL(ctdnsnp_header)))

typedef struct
{   
    int                fd;         /* tdns fd  */
    uint32_t           rsvd; 
    UINT32             fsize;
    uint8_t           *fname;
    CTDNSNP_HEADER    *header;     /* header */    

} CTDNSNP;

#define CTDNSNP_FD(ctdnsnp)                     ((ctdnsnp)->fd)
#define CTDNSNP_FSIZE(ctdnsnp)                  ((ctdnsnp)->fsize)
#define CTDNSNP_FNAME(ctdnsnp)                  ((ctdnsnp)->fname)
#define CTDNSNP_HDR(ctdnsnp)                    ((ctdnsnp)->header)

#define CTDNSNP_ID(ctdnsnp)                     (CTDNSNP_HEADER_NP_ID(CTDNSNP_HDR(ctdnsnp)))
#define CTDNSNP_MODEL(ctdnsnp)                  (CTDNSNP_HEADER_NP_MODEL(CTDNSNP_HDR(ctdnsnp)))

#define CTDNSNP_ITEMS_POOL(ctdnsnp)             (CTDNSNP_HEADER_ITEMS_POOL(CTDNSNP_HDR(ctdnsnp)))
#define CTDNSNP_ITEMS_MAX_NUM(ctdnsnp)          (CTDNSNPRB_POOL_NODE_MAX_NUM(CTDNSNP_ITEMS_POOL(ctdnsnp)))
#define CTDNSNP_ITEMS_USED_NUM(ctdnsnp)         (CTDNSNPRB_POOL_NODE_USED_NUM(CTDNSNP_ITEMS_POOL(ctdnsnp)))

#endif/* _CTDNSNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

