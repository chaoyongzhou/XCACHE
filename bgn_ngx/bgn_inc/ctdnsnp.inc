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

#define CTDNSNP_008M_MODEL   ((uint8_t) 0)
#define CTDNSNP_016M_MODEL   ((uint8_t) 1)
#define CTDNSNP_032M_MODEL   ((uint8_t) 2)
#define CTDNSNP_064M_MODEL   ((uint8_t) 3)
#define CTDNSNP_128M_MODEL   ((uint8_t) 4)
#define CTDNSNP_256M_MODEL   ((uint8_t) 5)
#define CTDNSNP_512M_MODEL   ((uint8_t) 6)
#define CTDNSNP_001G_MODEL   ((uint8_t) 7)
#define CTDNSNP_002G_MODEL   ((uint8_t) 8)
#define CTDNSNP_004G_MODEL   ((uint8_t) 9)


#define CTDNSNP_ITEM_IS_NOT_USED         ((uint32_t) 0x0001)  /*2 bits*/
#define CTDNSNP_ITEM_IS_USED             ((uint32_t) 0x0002)

#define CTDNSNP_KEY_MAX_SIZE             ( 16 )  /*max len of service name*/

typedef struct
{   
    /*16B*/
    CTDNSNPRB_NODE   rb_node;
    
    /*32 bits (4B)*/
    uint32_t      used_flag:4;  /* item status: not used, used */
    uint32_t      key_len  :8;  /* key lenght, range [0..CTDNSNP_KEY_MAX_SIZE] */
    uint32_t      rsvd1    :20;

    /*32 bits (4B)*/
    uint32_t      prev_pos;/*prev node pos with the samke key*/

    /*32 bits (4B)*/
    uint32_t      next_pos;/*next node pos with the samke key*/

    /*32 bits (4B)*/
    uint32_t      key_hash; /*hash of key*/
    
    /*64 bits (8B)*/
    UINT32        tcid;    /*primary key*/
#if (32 == WORDSIZE)   
    UINT32        rsvd2;
#endif/*(32 == WORDSIZE)*/

    /*64 bits (8B)*/
    UINT32        ipaddr;  /*real ip*/
#if (32 == WORDSIZE)   
    UINT32        rsvd3;
#endif/*(32 == WORDSIZE)*/

    /*16B*/
    uint8_t       key[ CTDNSNP_KEY_MAX_SIZE ];
} CTDNSNP_ITEM;/*64B*/

#define CTDNSNP_ITEM_RB_NODE(ctdnsnp_item)          (&((ctdnsnp_item)->rb_node))
#define CTDNSNP_ITEM_USED_FLAG(ctdnsnp_item)        ((ctdnsnp_item)->used_flag)
#define CTDNSNP_ITEM_KLEN(ctdnsnp_item)             ((ctdnsnp_item)->key_len)
#define CTDNSNP_ITEM_KEY(ctdnsnp_item)              ((ctdnsnp_item)->key)
#define CTDNSNP_ITEM_KEY_HASH(ctdnsnp_item)         ((ctdnsnp_item)->key_hash)
#define CTDNSNP_ITEM_PREV_POS(ctdnsnp_item)         ((ctdnsnp_item)->prev_pos)
#define CTDNSNP_ITEM_NEXT_POS(ctdnsnp_item)         ((ctdnsnp_item)->next_pos)
#define CTDNSNP_ITEM_TCID(ctdnsnp_item)             ((ctdnsnp_item)->tcid)
#define CTDNSNP_ITEM_IPADDR(ctdnsnp_item)           ((ctdnsnp_item)->ipaddr)

/*get CTDNSNP_ITEM from CTDNSNPRB_NODE*/
#define CTDNSNP_RB_NODE_ITEM(ctdnsnprb_node)        ((NULL_PTR == (ctdnsnprb_node)) ? NULL_PTR : \
    ((CTDNSNP_ITEM *)((char *)(ctdnsnprb_node)-(unsigned long)(&((CTDNSNP_ITEM *)0)->rb_node))))


/*item max num = file size / sizeof(CTDNSNP_ITEM) - delta where sizeof(CTDNSNP_ITEM) = 512 = 2^9*/
/*where delta = 4096, i.e., 4096 * 512B = 2MB, less than 1MB is bitmap of deleted items, left is other members or reserved bytes*/
#define CTDNSNP_ITEM_BIT_SIZE             (6)
#define CTDNSNP_ITEM_SIZEOF               (1 << CTDNSNP_ITEM_BIT_SIZE) /*it must be 64B*/

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

#define CTDNSNP_ERR_MODEL             ((uint32_t)0xF)  /*4 bits*/


/*bitmap*/
#define CTDNSNP_STATE_NOT_DIRTY       ((uint8_t)0x00)
#define CTDNSNP_STATE_DIRTY           ((uint8_t)0x01)

#define CTDNSNP_PATH_LAYOUT_DIR0_NBITS    ( 8)
#define CTDNSNP_PATH_LAYOUT_DIR1_NBITS    ( 8)
#define CTDNSNP_PATH_LAYOUT_DIR2_NBITS    ( 8)
#define CTDNSNP_PATH_LAYOUT_DIR3_NBITS    ( 8)

#define CTDNSNP_PATH_LAYOUT_DIR0_ABITS    (24) /*bit alignment*/
#define CTDNSNP_PATH_LAYOUT_DIR1_ABITS    (16) /*bit alignment*/
#define CTDNSNP_PATH_LAYOUT_DIR2_ABITS    ( 8) /*bit alignment*/
#define CTDNSNP_PATH_LAYOUT_DIR3_ABITS    ( 0) /*bit alignment*/

#define CTDNSNP_PATH_LAYOUT_DIR0_MASK     (((UINT32)(UINT32_ONE << CTDNSNP_PATH_LAYOUT_DIR0_NBITS)) - 1)
#define CTDNSNP_PATH_LAYOUT_DIR1_MASK     (((UINT32)(UINT32_ONE << CTDNSNP_PATH_LAYOUT_DIR1_NBITS)) - 1)
#define CTDNSNP_PATH_LAYOUT_DIR2_MASK     (((UINT32)(UINT32_ONE << CTDNSNP_PATH_LAYOUT_DIR2_NBITS)) - 1)
#define CTDNSNP_PATH_LAYOUT_DIR3_MASK     (((UINT32)(UINT32_ONE << CTDNSNP_PATH_LAYOUT_DIR3_NBITS)) - 1)

#define CTDNSNP_PATH_LAYOUT_DIR0_NO(path_id)     (((path_id) >> CTDNSNP_PATH_LAYOUT_DIR0_ABITS) & CTDNSNP_PATH_LAYOUT_DIR0_MASK)
#define CTDNSNP_PATH_LAYOUT_DIR1_NO(path_id)     (((path_id) >> CTDNSNP_PATH_LAYOUT_DIR1_ABITS) & CTDNSNP_PATH_LAYOUT_DIR1_MASK)
#define CTDNSNP_PATH_LAYOUT_DIR2_NO(path_id)     (((path_id) >> CTDNSNP_PATH_LAYOUT_DIR2_ABITS) & CTDNSNP_PATH_LAYOUT_DIR2_MASK)
#define CTDNSNP_PATH_LAYOUT_DIR3_NO(path_id)     (((path_id) >> CTDNSNP_PATH_LAYOUT_DIR3_ABITS) & CTDNSNP_PATH_LAYOUT_DIR3_MASK)

#define CTDNSNP_ERR_ID                     ((uint32_t)0xFFFFFFFF)

#define CTDNSNP_U32_BIT_POS_TO_U32_OFFSET(bit_pos)      ((bit_pos) >>  5)
#define CTDNSNP_U32_BIT_POS_TO_BIT_OFFSET(bit_pos)      ((bit_pos)  & 31)

/*support up to 1024 services*/
#define CTDNSNP_SERVICE_ERR_POS                       ((uint32_t)~0)
#define CTDNSNP_SERVICE_MAX_NUM                       (1024)
#define CTDNSNP_SERVICE_BITMAP_U8_TAB_SIZE            (CTDNSNP_SERVICE_MAX_NUM >> 3)
#define CTDNSNP_SERVICE_BITMAP_U32_TAB_SIZE           (CTDNSNP_SERVICE_BITMAP_U8_TAB_SIZE >> 2)
#define CTDNSNP_SERVICE_PAD_U8_SIZE                   (8192 - (CTDNSNP_SERVICE_MAX_NUM << 2) - (CTDNSNP_SERVICE_BITMAP_U32_TAB_SIZE << 2) - 4 - 4)

#define CTDNSNP_SERVICE_BIT_NOT_SET                   ((uint8_t) 0)
#define CTDNSNP_SERVICE_BIT_WAS_SET                   ((uint8_t) 1)

/*each np own one header*/
typedef struct
{    
    uint32_t       id;                  /*ctdnsnp id              */    
    uint8_t        model;               /*ctdnsnp model           */    
    uint8_t        rsvd1;                    
    uint8_t        rsvd2 ;
    uint8_t        chash_algo_2nd_id;   /*second hash algo func id: used to compute ctdnsnprb_node hash data*/   

    uint32_t       service_max_num;
    uint32_t       service_cur_num;
    uint32_t       service_bitmap[ CTDNSNP_SERVICE_BITMAP_U32_TAB_SIZE ];  /*128B*/
    uint32_t       service_nodes[ CTDNSNP_SERVICE_MAX_NUM ];           /*4KB*/

    uint8_t        pad_a[ CTDNSNP_SERVICE_PAD_U8_SIZE - 8 - 24]; /*pad the first part to 8KB*/ 
    
    CTDNSNPRB_POOL   pool;                /*pool of CTDNSNP_ITEM, CTDNSNP_ITEM head must be CTDNSNPRB_NODE*/
} CTDNSNP_HEADER;

#define CTDNSNP_HEADER_ID(ctdnsnp_header)                 ((ctdnsnp_header)->id)
#define CTDNSNP_HEADER_MODEL(ctdnsnp_header)              ((ctdnsnp_header)->model)

#define CTDNSNP_HEADER_2ND_CHASH_ALGO_ID(ctdnsnp_header)  ((ctdnsnp_header)->chash_algo_2nd_id)

#define CTDNSNP_HEADER_SERVICE_MAX_NUM(ctdnsnp_header)    ((ctdnsnp_header)->service_max_num)
#define CTDNSNP_HEADER_SERVICE_CUR_NUM(ctdnsnp_header)    ((ctdnsnp_header)->service_cur_num)
#define CTDNSNP_HEADER_SERVICE_BITMAP(ctdnsnp_header)     ((ctdnsnp_header)->service_bitmap)
#define CTDNSNP_HEADER_SERVICE_NODES(ctdnsnp_header)      ((ctdnsnp_header)->service_nodes)

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

    CHASH_ALGO         chash_algo_2nd;       /* used to compute key hash */   

} CTDNSNP;

#define CTDNSNP_FD(ctdnsnp)                     ((ctdnsnp)->fd)
#define CTDNSNP_FSIZE(ctdnsnp)                  ((ctdnsnp)->fsize)
#define CTDNSNP_FNAME(ctdnsnp)                  ((ctdnsnp)->fname)
#define CTDNSNP_HDR(ctdnsnp)                    ((ctdnsnp)->header)

#define CTDNSNP_2ND_CHASH_ALGO(ctdnsnp)         ((ctdnsnp)->chash_algo_2nd)


#define CTDNSNP_ID(ctdnsnp)                     (CTDNSNP_HEADER_ID(CTDNSNP_HDR(ctdnsnp)))
#define CTDNSNP_MODEL(ctdnsnp)                  (CTDNSNP_HEADER_MODEL(CTDNSNP_HDR(ctdnsnp)))
#define CTDNSNP_SECOND_CHASH_ALGO_ID(ctdnsnp)   (CTDNSNP_HEADER_2ND_CHASH_ALGO_ID(CTDNSNP_HDR(ctdnsnp)))

#define CTDNSNP_ITEMS_POOL(ctdnsnp)             (CTDNSNP_HEADER_ITEMS_POOL(CTDNSNP_HDR(ctdnsnp)))
#define CTDNSNP_ITEMS_MAX_NUM(ctdnsnp)          (CTDNSNPRB_POOL_NODE_MAX_NUM(CTDNSNP_ITEMS_POOL(ctdnsnp)))
#define CTDNSNP_ITEMS_USED_NUM(ctdnsnp)         (CTDNSNPRB_POOL_NODE_USED_NUM(CTDNSNP_ITEMS_POOL(ctdnsnp)))

#define CTDNSNP_2ND_CHASH_ALGO_COMPUTE(ctdnsnp, klen, key)  (CTDNSNP_2ND_CHASH_ALGO(ctdnsnp)(klen, key))

#endif/* _CTDNSNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

