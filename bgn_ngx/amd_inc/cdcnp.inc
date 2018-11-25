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

#ifndef _CDCNP_INC
#define _CDCNP_INC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "type.h"
#include "log.h"

#include "cdcnprb.h"
#include "cdcnplru.inc"
#include "cdcnpdel.inc"

#include "caio.h"

#define CDCNP_KEY_SIZE_255B            ( 255)/*max len of file or dir seg name*/
#define CDCNP_KEY_SIZE_063B            (  63)/*max len of file or dir seg name*/

#define CDCNP_KEY_MAX_SIZE             (CDCNP_KEY_SIZE_063B)
#define CDCNP_PATH_MAX_LEN             (1024)  /*max len of file or dir path name*/

#define CDCNP_HEADER_SIZE_NBYTES       ((UINT32)(UINT32_ONE << 20))  /*1MB = 2^20*/
#define CDCNP_HEADER_SIZE_MASK         (CDCNP_HEADER_SIZE_NBYTES - 1)

#define CDCNP_OFFSET_ERR               ((UINT32)~0)

#define CDCNP_AIO_TIMEOUT_NSEC         (60) /*seconds*/

#define CDCNP_008M_MODEL   ((uint8_t) 0)
#define CDCNP_016M_MODEL   ((uint8_t) 1)
#define CDCNP_032M_MODEL   ((uint8_t) 2)
#define CDCNP_064M_MODEL   ((uint8_t) 3)
#define CDCNP_128M_MODEL   ((uint8_t) 4)
#define CDCNP_256M_MODEL   ((uint8_t) 5)
#define CDCNP_512M_MODEL   ((uint8_t) 6)
#define CDCNP_001G_MODEL   ((uint8_t) 7)
#define CDCNP_002G_MODEL   ((uint8_t) 8)
#define CDCNP_004G_MODEL   ((uint8_t) 9)

#define CDCNP_FILE_REPLICA_MAX_NUM     ((uint32_t) 1)  /*max num of supported replicas up to*/

#define CDCNP_ITEM_FILE_IS_DIR         ((uint32_t) 0x0001)  /*directory   */
#define CDCNP_ITEM_FILE_IS_REG         ((uint32_t) 0x0002)  /*regular file*/
//#define CDCNP_ITEM_FILE_IS_ANY         ((uint32_t) 0x0004)  /*any file    */
#define CDCNP_ITEM_FILE_IS_ERR         ((uint32_t) 0x0000)  /*4 bits      */

#define CDCNP_ITEM_IS_NOT_USED         ((uint32_t) 0x0000)  /*2 bits*/
#define CDCNP_ITEM_IS_USED             ((uint32_t) 0x0001)

typedef struct
{
    uint16_t    rsvd;
    uint16_t    disk_no;        /*local disk_no*/
    uint16_t    block_no;       /*block_no in above disk*/
    uint16_t    page_no;        /*page_no in above block*/
}CDCNP_INODE;

#define CDCNP_INODE_DISK_NO(cdcnp_inode)           ((cdcnp_inode)->disk_no)
#define CDCNP_INODE_BLOCK_NO(cdcnp_inode)          ((cdcnp_inode)->block_no)
#define CDCNP_INODE_PAGE_NO(cdcnp_inode)           ((cdcnp_inode)->page_no)

#define CDCNP_FNODE_NO_MEM_CACHE_FLAG               ((uint32_t) 0)
#define CDCNP_FNODE_HAS_MEM_CACHE_FLAG              ((uint32_t) 1)

typedef struct
{
    /*8B*/
    uint32_t      file_size:28;    /*data/value length <= 64M = 2^26B*/
    uint32_t      file_replica_num:4;
    uint32_t      file_path_hash;  /*hash for disk choice*/

    /*8B*/
    CDCNP_INODE  inodes[ CDCNP_FILE_REPLICA_MAX_NUM ];
}CDCNP_FNODE;/*16B*/

#define CDCNP_FNODE_FILESZ(cdcnp_fnode)        ((cdcnp_fnode)->file_size)
#define CDCNP_FNODE_REPNUM(cdcnp_fnode)        ((cdcnp_fnode)->file_replica_num)
#define CDCNP_FNODE_HASH(cdcnp_fnode)          ((cdcnp_fnode)->file_path_hash)
#define CDCNP_FNODE_INODES(cdcnp_fnode)        ((cdcnp_fnode)->inodes)
#define CDCNP_FNODE_INODE(cdcnp_fnode, idx)    (&((cdcnp_fnode)->inodes[ (idx) ]))

#define CDCNP_FNODE_INODE_DISK_NO(cdcnp_fnode, idx)    CDCNP_INODE_DISK_NO(CDCNP_FNODE_INODE(cdcnp_fnode, idx))
#define CDCNP_FNODE_INODE_BLOCK_NO(cdcnp_fnode, idx)   CDCNP_INODE_BLOCK_NO(CDCNP_FNODE_INODE(cdcnp_fnode, idx))
#define CDCNP_FNODE_INODE_PAGE_NO(cdcnp_fnode, idx)    CDCNP_INODE_PAGE_NO(CDCNP_FNODE_INODE(cdcnp_fnode, idx))

#define CDCNP_DNODE_PAD_SIZE                        (8)

typedef struct
{
    /*8B*/
    uint32_t       file_num;   /*number of files under this directory*/
    uint32_t       root_pos;   /*dir root pos*/

    /*8B*/
    uint8_t        pad[ CDCNP_DNODE_PAD_SIZE ];
}CDCNP_DNODE;/*16B*/

#define CDCNP_DNODE_FILE_NUM(cdcnp_dnode)      ((cdcnp_dnode)->file_num)
#define CDCNP_DNODE_ROOT_POS(cdcnp_dnode)      ((cdcnp_dnode)->root_pos)

#define CDCNP_KEY_S_PAGE_ERR                   ((uint32_t)~0)
#define CDCNP_KEY_E_PAGE_ERR                   ((uint32_t)~0)

/*
*
*   range: [page_start * page_size, page_end *page_size)
*   where page_size is 2K or 4K etc which depends on cdc data node
*
*/
typedef struct
{
    uint32_t        page_start;
    uint32_t        page_end;
}CDCNP_KEY;/*8B*/

#define CDCNP_KEY_S_PAGE(cdcnp_key)          ((cdcnp_key)->page_start)
#define CDCNP_KEY_E_PAGE(cdcnp_key)          ((cdcnp_key)->page_end)

typedef struct
{
    /*16B*/
    CDCNPRB_NODE    rb_node;

    /*4B*/
    uint32_t        used_flag   :3;  /* item status: not used, used */
    uint32_t        dir_flag    :2;  /* directory or regular file */
    uint32_t        rsvd01      :27;

    /*4B*/
    uint32_t        parent_pos;/*parent directory*/

    /*8B*/
    CDCNPLRU_NODE   lru_node;

    /*8B*/
    CDCNPDEL_NODE   del_node;

    /*8B*/
    CDCNP_KEY       key;

    union
    {
        CDCNP_FNODE fnode;/*16B*/
        CDCNP_DNODE dnode;/*16B*/
    }u;/*16B*/
} CDCNP_ITEM;/*64B*/

#define CDCNP_ITEM_RB_NODE(cdcnp_item)          (&((cdcnp_item)->rb_node))
#define CDCNP_ITEM_DIR_FLAG(cdcnp_item)         ((cdcnp_item)->dir_flag)
#define CDCNP_ITEM_USED_FLAG(cdcnp_item)        ((cdcnp_item)->used_flag)

#define CDCNP_ITEM_PARENT_POS(cdcnp_item)       ((cdcnp_item)->parent_pos)
#define CDCNP_ITEM_FNODE(cdcnp_item)            (&((cdcnp_item)->u.fnode))
#define CDCNP_ITEM_DNODE(cdcnp_item)            (&((cdcnp_item)->u.dnode))
#define CDCNP_ITEM_LRU_NODE(cdcnp_item)         (&((cdcnp_item)->lru_node))
#define CDCNP_ITEM_DEL_NODE(cdcnp_item)         (&((cdcnp_item)->del_node))

#define CDCNP_ITEM_KEY(cdcnp_item)              (&((cdcnp_item)->key))

#define CDCNP_ITEM_S_PAGE(cdcnp_item)           (CDCNP_KEY_S_PAGE(CDCNP_ITEM_KEY(cdcnp_item)))
#define CDCNP_ITEM_E_PAGE(cdcnp_item)           (CDCNP_KEY_E_PAGE(CDCNP_ITEM_KEY(cdcnp_item)))

/*get CDCNP_ITEM from CDCNPRB_NODE*/
#define CDCNP_RB_NODE_ITEM(cdcnprb_node)        ((NULL_PTR == (cdcnprb_node)) ? NULL_PTR : \
    ((CDCNP_ITEM *)((char *)(cdcnprb_node)-(unsigned long)(&((CDCNP_ITEM *)0)->rb_node))))

/*get CDCNP_ITEM from CDCNPLRU_NODE*/
#define CDCNP_LRU_NODE_ITEM(cdcnplru_node)        ((NULL_PTR == (cdcnplru_node)) ? NULL_PTR : \
    ((CDCNP_ITEM *)((char *)(cdcnplru_node)-(unsigned long)(&((CDCNP_ITEM *)0)->lru_node))))

/*get CDCNP_ITEM from CDCNPDEL_NODE*/
#define CDCNP_DEL_NODE_ITEM(cdcnpdel_node)        ((NULL_PTR == (cdcnpdel_node)) ? NULL_PTR : \
    ((CDCNP_ITEM *)((char *)(cdcnpdel_node)-(unsigned long)(&((CDCNP_ITEM *)0)->del_node))))

#define CDCNP_ITEM_IS_REG(cdcnp_item)            (CDCNP_ITEM_FILE_IS_REG == (CDCNP_ITEM_FILE_IS_REG & CDCNP_ITEM_DIR_FLAG(cdcnp_item)))
#define CDCNP_ITEM_IS_DIR(cdcnp_item)            (CDCNP_ITEM_FILE_IS_DIR == (CDCNP_ITEM_FILE_IS_DIR & CDCNP_ITEM_DIR_FLAG(cdcnp_item)))

#define CDCNP_ITEM_IS_NOT_REG(cdcnp_item)        (CDCNP_ITEM_FILE_IS_REG != (CDCNP_ITEM_FILE_IS_REG & CDCNP_ITEM_DIR_FLAG(cdcnp_item)))
#define CDCNP_ITEM_IS_NOT_DIR(cdcnp_item)        (CDCNP_ITEM_FILE_IS_DIR != (CDCNP_ITEM_FILE_IS_DIR & CDCNP_ITEM_DIR_FLAG(cdcnp_item)))

#define CDCNP_ITEM_IS_INVALID(cdcnp_item)        ((CDCNP_ITEM_FILE_IS_REG | CDCNP_ITEM_FILE_IS_DIR) & CDCNP_ITEM_DIR_FLAG(cdcnp_item))
#define CDCNP_ITEM_IS_NOT_INVALID(cdcnp_item)    (0 == ((CDCNP_ITEM_FILE_IS_REG | CDCNP_ITEM_FILE_IS_DIR) & CDCNP_ITEM_DIR_FLAG(cdcnp_item)) )

#if (CDCNP_KEY_SIZE_255B == CDCNP_KEY_MAX_SIZE)
/*item max num = [(file size - item header size) / 1280] * 4*/
/*item table start from offset 1MB. */
/*file name table start from offset 1MB + 64 * item max num which is aligned to 256 ( mod 256 = 0)*/
/*1280 = 320 * 4 = 256 * 5, where 320 = 64 (sizeof item) + 256 (sizeof key)*/

#define CDCNP_ITEM_SIZE_NBITS           (6)
#define CDCNP_ITEM_SIZEOF               (1 << CDCNP_ITEM_SIZE_NBITS) /*it must be 64B*/

#define CDCNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CDCNP_008M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CDCNP_016M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CDCNP_032M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CDCNP_064M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CDCNP_128M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CDCNP_256M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CDCNP_512M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CDCNP_001G_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#define CDCNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CDCNP_002G_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

#if (64 == WORDSIZE)
#define CDCNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CDCNP_004G_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE - CDCNP_HEADER_SIZE_NBYTES) / 1280) << 2)

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#endif/*(CDCNP_KEY_SIZE_255B == CDCNP_KEY_MAX_SIZE)*/

#if (CDCNP_KEY_SIZE_063B == CDCNP_KEY_MAX_SIZE)
/**/
/*item max num = [file size / 128] - [item header size / 64]*/
/*item table start from offset 256B. */
/*128 = 64 (sizeof item) + 64 (sizeof key)*/

#define CDCNP_ITEM_SIZE_NBITS           (6)
#define CDCNP_ITEM_SIZEOF               (1 << CDCNP_ITEM_SIZE_NBITS) /*it must be 64B*/

#define CDCNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CDCNP_008M_CFG_ITEM_MAX_NUM     (((CDCNP_008M_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CDCNP_016M_CFG_ITEM_MAX_NUM     (((CDCNP_016M_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CDCNP_032M_CFG_ITEM_MAX_NUM     (((CDCNP_032M_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CDCNP_064M_CFG_ITEM_MAX_NUM     (((CDCNP_064M_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CDCNP_128M_CFG_ITEM_MAX_NUM     (((CDCNP_128M_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CDCNP_256M_CFG_ITEM_MAX_NUM     (((CDCNP_256M_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CDCNP_512M_CFG_ITEM_MAX_NUM     (((CDCNP_512M_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CDCNP_001G_CFG_ITEM_MAX_NUM     (((CDCNP_001G_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#define CDCNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CDCNP_002G_CFG_ITEM_MAX_NUM     (((CDCNP_002G_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

#if (64 == WORDSIZE)
#define CDCNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CDCNP_004G_CFG_ITEM_MAX_NUM     (((CDCNP_004G_CFG_FILE_SIZE >> CDCNP_ITEM_SIZE_NBITS) >> 1) - (CDCNP_HEADER_SIZE_NBYTES >> CDCNP_ITEM_SIZE_NBITS))

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#endif/*(CDCNP_KEY_SIZE_063B == CDCNP_KEY_MAX_SIZE)*/


typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    UINT32         file_size; /*np file size*/
    uint32_t       item_max_num;
    uint32_t       rsvd;
}CDCNP_CFG;

#define CDCNP_CFG_MODEL_STR(cdcnp_cfg)              ((cdcnp_cfg)->model_str)
#define CDCNP_CFG_ALIAS_STR(cdcnp_cfg)              ((cdcnp_cfg)->alias_str)
#define CDCNP_CFG_FILE_SIZE(cdcnp_cfg)              ((cdcnp_cfg)->file_size)
#define CDCNP_CFG_ITEM_MAX_NUM(cdcnp_cfg)           ((cdcnp_cfg)->item_max_num)

#define CDCNP_ERR_MODEL             ((uint32_t)0xF)  /*4 bits*/

#define CDCNP_ERR_ID                ((uint32_t)0xFFFFFFFF)

typedef struct
{
    uint32_t    size;
    uint32_t    rsvd;
    UINT8       data[ 0 ]; /*item is start page no*/
}CDCNP_BITMAP;

#define CDCNP_BITMAP_SIZE(cdcnp_bitmap)               ((cdcnp_bitmap)->size)
#define CDCNP_BITMAP_DATA(cdcnp_bitmap)               ((cdcnp_bitmap)->data)

/********************************************************************************************************************************
*
* np_id | model | rsvd | pad (bitmap size | bitmap data)  | node_max_num | node_used_num | node_sizeof | free_head | item x n    |
* |<---------------------------------1 MB--------------------------------------------------------------------------------------->|
*
*********************************************************************************************************************************/

#define CDCNP_BITMAP_SIZE_NBYTES        (CDCNP_HEADER_SIZE_NBYTES - 8 - 16)
#define CDCNP_PAGE_MAX_NUM              (CDCNP_BITMAP_SIZE_NBYTES << 3) /*nbytes * 8*/

/*each np own one header*/
typedef struct
{
    /*8B*/
    uint32_t            np_id;               /*cdcnp id              */
    uint8_t             model;               /*cdcnp model           */
    uint8_t             rsvd1;
    uint8_t             rsvd2;
    uint8_t             rsvd3;

    uint8_t             pad[ CDCNP_BITMAP_SIZE_NBYTES ]; /*pad the first part to 1 MB*/

    CDCNPRB_POOL        pool;                /*pool of CDCNP_ITEM, CDCNP_ITEM head must be CDCNPRB_NODE*/
} CDCNP_HEADER;

#define CDCNP_HEADER_NP_ID(cdcnp_header)              ((cdcnp_header)->np_id)
#define CDCNP_HEADER_MODEL(cdcnp_header)              ((cdcnp_header)->model)

#define CDCNP_HEADER_ITEMS_POOL(cdcnp_header)         (&((cdcnp_header)->pool))
#define CDCNP_HEADER_ITEMS_MAX_NUM(cdcnp_header)      (CDCNPRB_POOL_NODE_MAX_NUM(CDCNP_HEADER_ITEMS_POOL(cdcnp_header)))
#define CDCNP_HEADER_ITEMS_USED_NUM(cdcnp_header)     (CDCNPRB_POOL_NODE_USED_NUM(CDCNP_HEADER_ITEMS_POOL(cdcnp_header)))

#define CDCNP_HEADER_BITMAP(cdcnp_header)             ((CDCNP_BITMAP *)((cdcnp_header)->pad))

typedef struct
{
    int              fd;           /* memcache namespace fd */
    uint32_t         rsvd;

    UINT32           s_offset;     /* start offset of name node */
    UINT32           e_offset;     /* end offset of name node   */

    uint8_t         *fname;
    CAIO_MD         *caio_md;      /* mount point. inherit from cdc module */

    uint64_t         del_size;     /* deleted but not recycled bytes */
    uint64_t         recycle_size; /* recycled bytes */

    CDCNP_BITMAP    *bitmap;
    CDCNP_HEADER    *header;       /* namespace header */

    /*shortcut of lru list which point to root rb node */
    CDCNPLRU_NODE   *lru_list;     /* the lastest access node is at head covering fnode only */

    /*shortcut of del list which point to root rb node */
    CDCNPDEL_NODE   *del_list;     /* the lastest access node is at head covering fnode only */
} CDCNP;

#define CDCNP_FD(cdcnp)                     ((cdcnp)->fd)
#define CDCNP_S_OFFSET(cdcnp)               ((cdcnp)->s_offset)
#define CDCNP_E_OFFSET(cdcnp)               ((cdcnp)->e_offset)

#define CDCNP_FNAME(cdcnp)                  ((cdcnp)->fname)
#define CDCNP_CAIO_MD(cdcnp)                ((cdcnp)->caio_md)

#define CDCNP_DEL_SIZE(cdcnp)               ((cdcnp)->del_size)
#define CDCNP_RECYCLE_SIZE(cdcnp)           ((cdcnp)->recycle_size)
#define CDCNP_BITMAP(cdcnp)                 ((cdcnp)->bitmap)
#define CDCNP_HDR(cdcnp)                    ((cdcnp)->header)

#define CDCNP_LRU_LIST(cdcnp)               ((cdcnp)->lru_list)
#define CDCNP_DEL_LIST(cdcnp)               ((cdcnp)->del_list)

#define CDCNP_ID(cdcnp)                     (CDCNP_HEADER_NP_ID(CDCNP_HDR(cdcnp)))
#define CDCNP_MODEL(cdcnp)                  (CDCNP_HEADER_MODEL(CDCNP_HDR(cdcnp)))

#define CDCNP_ITEMS_POOL(cdcnp)             (CDCNP_HEADER_ITEMS_POOL(CDCNP_HDR(cdcnp)))
#define CDCNP_ITEMS_MAX_NUM(cdcnp)          (CDCNPRB_POOL_NODE_MAX_NUM(CDCNP_ITEMS_POOL(cdcnp)))
#define CDCNP_ITEMS_USED_NUM(cdcnp)         (CDCNPRB_POOL_NODE_USED_NUM(CDCNP_ITEMS_POOL(cdcnp)))


typedef struct
{
    CDCNP             *cdcnp;

    uint32_t           np_id;
    uint8_t            np_model;
    uint8_t            rsvd01;
    uint16_t           rsvd02;

    UINT32             np_size;

    int                fd;
    int                rsvd03;

    UINT32             f_s_offset;
    UINT32             f_e_offset;

    UINT32            *s_offset;           /*mounted input start offset pointer*/

    UINT32             aio_s_offset;       /*start offset of reading or writing*/
    UINT32             aio_e_offset;       /*expected end offset of reading or writing*/
    UINT32             aio_c_offset;       /*current/reached offset of reading or writing*/

    UINT8              aio_m_data[ 8 ];

    UINT8             *aio_m_buff;

    CAIO_CB            caio_cb;
}CDCNP_AIO;

#define CDCNP_AIO_CDCNP(cdcnp_aio)                       ((cdcnp_aio)->cdcnp)
#define CDCNP_AIO_NP_ID(cdcnp_aio)                       ((cdcnp_aio)->np_id)
#define CDCNP_AIO_NP_MODEL(cdcnp_aio)                    ((cdcnp_aio)->np_model)
#define CDCNP_AIO_NP_SIZE(cdcnp_aio)                     ((cdcnp_aio)->np_size)
#define CDCNP_AIO_FD(cdcnp_aio)                          ((cdcnp_aio)->fd)
#define CDCNP_AIO_I_S_OFFSET(cdcnp_aio)                  ((cdcnp_aio)->s_offset)
#define CDCNP_AIO_F_S_OFFSET(cdcnp_aio)                  ((cdcnp_aio)->f_s_offset)
#define CDCNP_AIO_F_E_OFFSET(cdcnp_aio)                  ((cdcnp_aio)->f_e_offset)
#define CDCNP_AIO_S_OFFSET(cdcnp_aio)                    ((cdcnp_aio)->aio_s_offset)
#define CDCNP_AIO_E_OFFSET(cdcnp_aio)                    ((cdcnp_aio)->aio_e_offset)
#define CDCNP_AIO_C_OFFSET(cdcnp_aio)                    ((cdcnp_aio)->aio_c_offset)
#define CDCNP_AIO_M_DATA(cdcnp_aio)                      ((cdcnp_aio)->aio_m_data)
#define CDCNP_AIO_M_BUFF(cdcnp_aio)                      ((cdcnp_aio)->aio_m_buff)
#define CDCNP_AIO_CAIO_CB(cdcnp_aio)                     (&((cdcnp_aio)->caio_cb))

typedef EC_BOOL (*CDCNP_RECYCLE_DN_FUNC)(void *, const CDCNP_FNODE *);

typedef struct
{
    void * arg1;

    CDCNP_RECYCLE_DN_FUNC recycle_dn;
}CDCNP_RECYCLE_DN;

#define CDCNP_RECYCLE_DN_ARG1(cdcnp_recycle_dn)      ((cdcnp_recycle_dn)->arg1)
#define CDCNP_RECYCLE_DN_FUNC(cdcnp_recycle_dn)      ((cdcnp_recycle_dn)->recycle_dn)

typedef EC_BOOL (*CDCNP_RECYCLE_NP_FUNC)(const UINT32, const uint32_t);
typedef struct
{
    UINT32 arg1;

    CDCNP_RECYCLE_NP_FUNC recycle_np;
}CDCNP_RECYCLE_NP;

#define CDCNP_RECYCLE_NP_ARG1(cdcnp_recycle_np)      ((cdcnp_recycle_np)->arg1)
#define CDCNP_RECYCLE_NP_FUNC(cdcnp_recycle_np)      ((cdcnp_recycle_np)->recycle_np)

#endif/* _CDCNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/


