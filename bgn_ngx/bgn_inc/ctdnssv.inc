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

#ifndef _CTDNSSV_INC
#define _CTDNSSV_INC

#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cstring.h"

#include "chashalgo.h"
#include "cmd5.h"

#include "ctdnssvrb.h"

#define CTDNSSV_008M_MODEL   ((uint8_t) 0)
#define CTDNSSV_016M_MODEL   ((uint8_t) 1)
#define CTDNSSV_032M_MODEL   ((uint8_t) 2)
#define CTDNSSV_064M_MODEL   ((uint8_t) 3)
#define CTDNSSV_128M_MODEL   ((uint8_t) 4)
#define CTDNSSV_256M_MODEL   ((uint8_t) 5)
#define CTDNSSV_512M_MODEL   ((uint8_t) 6)
#define CTDNSSV_001G_MODEL   ((uint8_t) 7)
#define CTDNSSV_002G_MODEL   ((uint8_t) 8)
#define CTDNSSV_004G_MODEL   ((uint8_t) 9)


typedef struct
{   
    /*16B*/
    CTDNSSVRB_NODE   rb_node;
    
    /*64 bits (8B)*/
    UINT32           tcid;     /*primary key of rb tree*/
#if (32 == WORDSIZE)
    uint32_t         rsvd1;
#endif/*(32 == WORDSIZE)*/ 

    UINT32           ipaddr;   /*real ip*/
#if (32 == WORDSIZE)
    uint32_t         rsvd2;
#endif/*(32 == WORDSIZE)*/

} CTDNSSV_ITEM;/*32B*/

#define CTDNSSV_ITEM_RB_NODE(ctdnssv_item)          (&((ctdnssv_item)->rb_node))
#define CTDNSSV_ITEM_TCID(ctdnssv_item)             ((ctdnssv_item)->tcid)
#define CTDNSSV_ITEM_IPADDR(ctdnssv_item)           ((ctdnssv_item)->ipaddr)
#define CTDNSSV_ITEM_PORT(ctdnssv_item)             (CTDNSSVRB_NODE_DATA(CTDNSSV_ITEM_RB_NODE(ctdnssv_item)))

/*get CTDNSSV_ITEM from CTDNSSVRB_NODE*/
#define CTDNSSV_RB_NODE_ITEM(ctdnssvrb_node)        ((NULL_PTR == (ctdnssvrb_node)) ? NULL_PTR : \
    ((CTDNSSV_ITEM *)((char *)(ctdnssvrb_node)-(unsigned long)(&((CTDNSSV_ITEM *)0)->rb_node))))

/*item max num = file size / sizeof(CTDNSSV_ITEM) - delta where sizeof(CTDNSSV_ITEM) = 512 = 2^9*/
/*where delta = 4096, i.e., 4096 * 512B = 2MB, less than 1MB is bitmap of deleted items, left is other members or reserved bytes*/
#define CTDNSSV_ITEM_BIT_SIZE             (5)
#define CTDNSSV_ITEM_SIZEOF               (1 << CTDNSSV_ITEM_BIT_SIZE) /*it must be 32B*/

#define CTDNSSV_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CTDNSSV_008M_CFG_ITEM_MAX_NUM     ((CTDNSSV_008M_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CTDNSSV_016M_CFG_ITEM_MAX_NUM     ((CTDNSSV_016M_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CTDNSSV_032M_CFG_ITEM_MAX_NUM     ((CTDNSSV_032M_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CTDNSSV_064M_CFG_ITEM_MAX_NUM     ((CTDNSSV_064M_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CTDNSSV_128M_CFG_ITEM_MAX_NUM     ((CTDNSSV_128M_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CTDNSSV_256M_CFG_ITEM_MAX_NUM     ((CTDNSSV_256M_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CTDNSSV_512M_CFG_ITEM_MAX_NUM     ((CTDNSSV_512M_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CTDNSSV_001G_CFG_ITEM_MAX_NUM     ((CTDNSSV_001G_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#define CTDNSSV_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CTDNSSV_002G_CFG_ITEM_MAX_NUM     ((CTDNSSV_002G_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

#if (64 == WORDSIZE)
#define CTDNSSV_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CTDNSSV_004G_CFG_ITEM_MAX_NUM     ((CTDNSSV_004G_CFG_FILE_SIZE >> CTDNSSV_ITEM_BIT_SIZE) - (2048*4))

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#define CTDNSSV_SERVICE_NAME_MAX_LEN        (128)
#define CTDNSSV_SERVICE_PAD_U8_SIZE         (8 * 1024) /*8K*/

#define CTDNSSV_POSTFIX                     (".service.dat")

typedef struct
{   
    uint32_t            sname_len;
    uint32_t            rsvd02;
    uint8_t             sname[ CTDNSSV_SERVICE_NAME_MAX_LEN ];
    
    uint8_t             pad[ CTDNSSV_SERVICE_PAD_U8_SIZE - 8 - CTDNSSV_SERVICE_NAME_MAX_LEN - 24 ]; 

    CTDNSSVRB_POOL      nodes_pool;     /*item is CTDNSSV_ITEM*/ 
}CTDNSSV_HEADER;

#define CTDNSSV_HEADER_SNAME_LEN(ctdnssv_service_header)      ((ctdnssv_service_header)->sname_len)
#define CTDNSSV_HEADER_SNAME(ctdnssv_service_header)          ((ctdnssv_service_header)->sname)
#define CTDNSSV_HEADER_NODES_POOL(ctdnssv_service_header)     (&((ctdnssv_service_header)->nodes_pool))

typedef struct
{   
    uint8_t                         *fname;          /*file name*/
    int                              fd;             /* tdns fd  */
    uint32_t                         rsvd01;
    UINT32                           fsize;

    CTDNSSV_HEADER                  *header;
}CTDNSSV;

#define CTDNSSV_FNAME(ctdnssv)              ((ctdnssv)->fname)
#define CTDNSSV_FD(ctdnssv)                 ((ctdnssv)->fd)
#define CTDNSSV_FSIZE(ctdnssv)              ((ctdnssv)->fsize)
#define CTDNSSV_HDR(ctdnssv)                ((ctdnssv)->header)

#define CTDNSSV_SNAME_LEN(ctdnssv)          (CTDNSSV_HEADER_SNAME_LEN(CTDNSSV_HDR(ctdnssv)))
#define CTDNSSV_SNAME(ctdnssv)              (CTDNSSV_HEADER_SNAME(CTDNSSV_HDR(ctdnssv)))
#define CTDNSSV_NODES_POOL(ctdnssv)         (CTDNSSV_HEADER_NODES_POOL(CTDNSSV_HDR(ctdnssv)))
#define CTDNSSV_NODES_MAX_NUM(ctdnssv)      (CTDNSSVRB_POOL_NODE_MAX_NUM(CTDNSSV_NODES_POOL(ctdnssv)))
#define CTDNSSV_NODES_USED_NUM(ctdnssv)     (CTDNSSVRB_POOL_NODE_USED_NUM(CTDNSSV_NODES_POOL(ctdnssv)))


typedef struct
{
    UINT32          tcid;
    UINT32          ipaddr;
    UINT32          port;
}CTDNSSV_NODE;

#define CTDNSSV_NODE_TCID(ctdnssv_node)      ((ctdnssv_node)->tcid)
#define CTDNSSV_NODE_IPADDR(ctdnssv_node)    ((ctdnssv_node)->ipaddr)
#define CTDNSSV_NODE_PORT(ctdnssv_node)      ((ctdnssv_node)->port)

typedef struct
{
    CLIST           nodes; /*item is CTDNSSV_NODE*/
}CTDNSSV_NODE_MGR;

#define CTDNSSV_NODE_MGR_NODES(ctdnssv_node_mgr)        (&((ctdnssv_node_mgr)->nodes))

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    UINT32         file_size; /*np file size*/
    uint32_t       item_max_num;
    uint32_t       rsvd;
}CTDNSSV_CFG;

#define CTDNSSV_CFG_MODEL_STR(ctdnssv_cfg)              ((ctdnssv_cfg)->model_str)
#define CTDNSSV_CFG_ALIAS_STR(ctdnssv_cfg)              ((ctdnssv_cfg)->alias_str)
#define CTDNSSV_CFG_FILE_SIZE(ctdnssv_cfg)              ((ctdnssv_cfg)->file_size)
#define CTDNSSV_CFG_ITEM_MAX_NUM(ctdnssv_cfg)           ((ctdnssv_cfg)->item_max_num)

#define CTDNSSV_ERR_MODEL                               ((uint32_t)0xF)  /*4 bits*/

#define CTDNSSV_ERR_ID                                  ((uint32_t)0xFFFFFFFF)

#define CTDNSSV_U32_BIT_POS_TO_U32_OFFSET(bit_pos)      ((bit_pos) >>  5)
#define CTDNSSV_U32_BIT_POS_TO_BIT_OFFSET(bit_pos)      ((bit_pos)  & 31)


#endif/* _CTDNSSV_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

