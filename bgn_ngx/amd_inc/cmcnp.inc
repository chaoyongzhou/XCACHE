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

#ifndef _CMCNP_INC
#define _CMCNP_INC

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

#include "cmcnprb.h"
#include "cmcnplru.inc"
#include "cmcnpdel.inc"

#define CMCNP_KEY_SIZE_255B            ( 255)/*max len of file or dir seg name*/
#define CMCNP_KEY_SIZE_063B            (  63)/*max len of file or dir seg name*/

#define CMCNP_KEY_MAX_SIZE             (CMCNP_KEY_SIZE_063B)
#define CMCNP_PATH_MAX_LEN             (1024)  /*max len of file or dir path name*/

#define CMCNP_008M_MODEL   ((uint8_t) 0)
#define CMCNP_016M_MODEL   ((uint8_t) 1)
#define CMCNP_032M_MODEL   ((uint8_t) 2)
#define CMCNP_064M_MODEL   ((uint8_t) 3)
#define CMCNP_128M_MODEL   ((uint8_t) 4)
#define CMCNP_256M_MODEL   ((uint8_t) 5)
#define CMCNP_512M_MODEL   ((uint8_t) 6)
#define CMCNP_001G_MODEL   ((uint8_t) 7)
#define CMCNP_002G_MODEL   ((uint8_t) 8)
#define CMCNP_004G_MODEL   ((uint8_t) 9)

#define CMCNP_FILE_REPLICA_MAX_NUM     ((uint32_t) 1)  /*max num of supported replicas up to*/

#define CMCNP_ITEM_FILE_IS_DIR         ((uint32_t) 0x0001)  /*directory   */
#define CMCNP_ITEM_FILE_IS_REG         ((uint32_t) 0x0002)  /*regular file*/
//#define CMCNP_ITEM_FILE_IS_ANY         ((uint32_t) 0x0004)  /*any file    */
#define CMCNP_ITEM_FILE_IS_ERR         ((uint32_t) 0x0000)  /*4 bits      */

#define CMCNP_ITEM_IS_NOT_USED         ((uint32_t) 0x0000)  /*2 bits*/
#define CMCNP_ITEM_IS_USED             ((uint32_t) 0x0001)

typedef struct
{
    uint16_t    rsvd;
    uint16_t    disk_no;        /*local disk_no*/
    uint16_t    block_no;       /*block_no in above disk*/
    uint16_t    page_no;        /*page_no in above block*/
}CMCNP_INODE;

#define CMCNP_INODE_DISK_NO(cmcnp_inode)           ((cmcnp_inode)->disk_no)
#define CMCNP_INODE_BLOCK_NO(cmcnp_inode)          ((cmcnp_inode)->block_no)
#define CMCNP_INODE_PAGE_NO(cmcnp_inode)           ((cmcnp_inode)->page_no)

#define CMCNP_FNODE_NO_MEM_CACHE_FLAG               ((uint32_t) 0)
#define CMCNP_FNODE_HAS_MEM_CACHE_FLAG              ((uint32_t) 1)

typedef struct
{
    /*8B*/
    uint32_t      file_size:28;    /*data/value length <= 64M = 2^26B*/
    uint32_t      file_replica_num:3;
    uint32_t      file_flush_flag :1;  /* file is dirty => flush to ssd*/
                                       /* file is loaded from sata => flush to ssd*/
                                       /* file is loaded from ssd and dirty => flush to ssd*/
                                       /* otherwise, do not flush to ssd*/
    uint32_t      file_path_hash;  /*hash for disk choice*/

    /*8B*/
    CMCNP_INODE  inodes[ CMCNP_FILE_REPLICA_MAX_NUM ];
}CMCNP_FNODE;/*16B*/

#define CMCNP_FNODE_FILESZ(cmcnp_fnode)        ((cmcnp_fnode)->file_size)
#define CMCNP_FNODE_REPNUM(cmcnp_fnode)        ((cmcnp_fnode)->file_replica_num)
#define CMCNP_FNODE_FLUSH_FLAG(cmcnp_fnode)    ((cmcnp_fnode)->file_flush_flag)
#define CMCNP_FNODE_HASH(cmcnp_fnode)          ((cmcnp_fnode)->file_path_hash)
#define CMCNP_FNODE_INODES(cmcnp_fnode)        ((cmcnp_fnode)->inodes)
#define CMCNP_FNODE_INODE(cmcnp_fnode, idx)    (&((cmcnp_fnode)->inodes[ (idx) ]))

#define CMCNP_FNODE_INODE_DISK_NO(cmcnp_fnode, idx)    CMCNP_INODE_DISK_NO(CMCNP_FNODE_INODE(cmcnp_fnode, idx))
#define CMCNP_FNODE_INODE_BLOCK_NO(cmcnp_fnode, idx)   CMCNP_INODE_BLOCK_NO(CMCNP_FNODE_INODE(cmcnp_fnode, idx))
#define CMCNP_FNODE_INODE_PAGE_NO(cmcnp_fnode, idx)    CMCNP_INODE_PAGE_NO(CMCNP_FNODE_INODE(cmcnp_fnode, idx))

#define CMCNP_DNODE_PAD_SIZE                        (8)

typedef struct
{
    /*8B*/
    uint32_t       file_num;   /*number of files under this directory*/
    uint32_t       root_pos;   /*dir root pos*/

    /*8B*/
    uint8_t        pad[ CMCNP_DNODE_PAD_SIZE ];
}CMCNP_DNODE;/*16B*/

#define CMCNP_DNODE_FILE_NUM(cmcnp_dnode)      ((cmcnp_dnode)->file_num)
#define CMCNP_DNODE_ROOT_POS(cmcnp_dnode)      ((cmcnp_dnode)->root_pos)

#define CMCNP_KEY_S_PAGE_ERR                   ((uint32_t)~0)
#define CMCNP_KEY_E_PAGE_ERR                   ((uint32_t)~0)

/*
*
*   range: [page_start * page_size, page_end *page_size)
*   where page_size is 2K or 4K etc which depends on cmc data node
*
*/
typedef struct
{
    uint32_t        page_start;
    uint32_t        page_end;
}CMCNP_KEY;/*8B*/

#define CMCNP_KEY_S_PAGE(cmcnp_key)          ((cmcnp_key)->page_start)
#define CMCNP_KEY_E_PAGE(cmcnp_key)          ((cmcnp_key)->page_end)

typedef struct
{
    /*16B*/
    CMCNPRB_NODE    rb_node;

    /*4B*/
    uint32_t        used_flag   :3;  /* item status: not used, used */
    uint32_t        dir_flag    :2;  /* directory or regular file */
    uint32_t        rsvd01      :27;

    /*4B*/
    uint32_t        parent_pos;/*parent directory*/

    /*8B*/
    CMCNPLRU_NODE   lru_node;

    /*8B*/
    CMCNPDEL_NODE   del_node;

    /*8B*/
    CMCNP_KEY       key;

    union
    {
        CMCNP_FNODE fnode;/*16B*/
        CMCNP_DNODE dnode;/*16B*/
    }u;/*16B*/
} CMCNP_ITEM;/*64B*/

#define CMCNP_ITEM_RB_NODE(cmcnp_item)          (&((cmcnp_item)->rb_node))
#define CMCNP_ITEM_DIR_FLAG(cmcnp_item)         ((cmcnp_item)->dir_flag)
#define CMCNP_ITEM_USED_FLAG(cmcnp_item)        ((cmcnp_item)->used_flag)

#define CMCNP_ITEM_PARENT_POS(cmcnp_item)       ((cmcnp_item)->parent_pos)
#define CMCNP_ITEM_FNODE(cmcnp_item)            (&((cmcnp_item)->u.fnode))
#define CMCNP_ITEM_DNODE(cmcnp_item)            (&((cmcnp_item)->u.dnode))
#define CMCNP_ITEM_LRU_NODE(cmcnp_item)         (&((cmcnp_item)->lru_node))
#define CMCNP_ITEM_DEL_NODE(cmcnp_item)         (&((cmcnp_item)->del_node))

#define CMCNP_ITEM_KEY(cmcnp_item)              (&((cmcnp_item)->key))

#define CMCNP_ITEM_S_PAGE(cmcnp_item)           (CMCNP_KEY_S_PAGE(CMCNP_ITEM_KEY(cmcnp_item)))
#define CMCNP_ITEM_E_PAGE(cmcnp_item)           (CMCNP_KEY_E_PAGE(CMCNP_ITEM_KEY(cmcnp_item)))

/*get CMCNP_ITEM from CMCNPRB_NODE*/
#define CMCNP_RB_NODE_ITEM(cmcnprb_node)        ((NULL_PTR == (cmcnprb_node)) ? NULL_PTR : \
    ((CMCNP_ITEM *)((char *)(cmcnprb_node)-(unsigned long)(&((CMCNP_ITEM *)0)->rb_node))))

/*get CMCNP_ITEM from CMCNPLRU_NODE*/
#define CMCNP_LRU_NODE_ITEM(cmcnplru_node)        ((NULL_PTR == (cmcnplru_node)) ? NULL_PTR : \
    ((CMCNP_ITEM *)((char *)(cmcnplru_node)-(unsigned long)(&((CMCNP_ITEM *)0)->lru_node))))

/*get CMCNP_ITEM from CMCNPDEL_NODE*/
#define CMCNP_DEL_NODE_ITEM(cmcnpdel_node)        ((NULL_PTR == (cmcnpdel_node)) ? NULL_PTR : \
    ((CMCNP_ITEM *)((char *)(cmcnpdel_node)-(unsigned long)(&((CMCNP_ITEM *)0)->del_node))))

#define CMCNP_ITEM_IS_REG(cmcnp_item)            (CMCNP_ITEM_FILE_IS_REG == (CMCNP_ITEM_FILE_IS_REG & CMCNP_ITEM_DIR_FLAG(cmcnp_item)))
#define CMCNP_ITEM_IS_DIR(cmcnp_item)            (CMCNP_ITEM_FILE_IS_DIR == (CMCNP_ITEM_FILE_IS_DIR & CMCNP_ITEM_DIR_FLAG(cmcnp_item)))

#define CMCNP_ITEM_IS_NOT_REG(cmcnp_item)        (CMCNP_ITEM_FILE_IS_REG != (CMCNP_ITEM_FILE_IS_REG & CMCNP_ITEM_DIR_FLAG(cmcnp_item)))
#define CMCNP_ITEM_IS_NOT_DIR(cmcnp_item)        (CMCNP_ITEM_FILE_IS_DIR != (CMCNP_ITEM_FILE_IS_DIR & CMCNP_ITEM_DIR_FLAG(cmcnp_item)))

#define CMCNP_ITEM_IS_INVALID(cmcnp_item)        ((CMCNP_ITEM_FILE_IS_REG | CMCNP_ITEM_FILE_IS_DIR) & CMCNP_ITEM_DIR_FLAG(cmcnp_item))
#define CMCNP_ITEM_IS_NOT_INVALID(cmcnp_item)    (0 == ((CMCNP_ITEM_FILE_IS_REG | CMCNP_ITEM_FILE_IS_DIR) & CMCNP_ITEM_DIR_FLAG(cmcnp_item)) )

#if (CMCNP_KEY_SIZE_255B == CMCNP_KEY_MAX_SIZE)
/*item max num = [file size / 1280] * 4*/
/*item table start from offset 256B. */
/*file name table start from offset 256 + 64 * item max num which is aligned to 256 ( mod 256 = 0)*/
/*1280 = 320 * 4 = 256 * 5, where 320 = 64 (sizeof item) + 256 (sizeof key)*/

#define CMCNP_ITEM_SIZE_NBITS           (6)
#define CMCNP_ITEM_SIZEOF               (1 << CMCNP_ITEM_SIZE_NBITS) /*it must be 64B*/

#define CMCNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CMCNP_008M_CFG_ITEM_MAX_NUM     ((CMCNP_008M_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CMCNP_016M_CFG_ITEM_MAX_NUM     ((CMCNP_016M_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CMCNP_032M_CFG_ITEM_MAX_NUM     ((CMCNP_032M_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CMCNP_064M_CFG_ITEM_MAX_NUM     ((CMCNP_064M_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CMCNP_128M_CFG_ITEM_MAX_NUM     ((CMCNP_128M_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CMCNP_256M_CFG_ITEM_MAX_NUM     ((CMCNP_256M_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CMCNP_512M_CFG_ITEM_MAX_NUM     ((CMCNP_512M_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CMCNP_001G_CFG_ITEM_MAX_NUM     ((CMCNP_001G_CFG_FILE_SIZE / 1280) << 2)

#define CMCNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CMCNP_002G_CFG_ITEM_MAX_NUM     ((CMCNP_002G_CFG_FILE_SIZE / 1280) << 2)

#if (64 == WORDSIZE)
#define CMCNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CMCNP_004G_CFG_ITEM_MAX_NUM     ((CMCNP_004G_CFG_FILE_SIZE / 1280) << 2)

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#endif/*(CMCNP_KEY_SIZE_255B == CMCNP_KEY_MAX_SIZE)*/

#if (CMCNP_KEY_SIZE_063B == CMCNP_KEY_MAX_SIZE)
/*item max num = [file size / 128] - 2*/
/*item table start from offset 256B. */
/*128 = 64 (sizeof item) + 64 (sizeof key)*/

#define CMCNP_ITEM_SIZE_NBITS           (6)
#define CMCNP_ITEM_SIZEOF               (1 << CMCNP_ITEM_SIZE_NBITS) /*it must be 64B*/

#define CMCNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CMCNP_008M_CFG_ITEM_MAX_NUM     (((CMCNP_008M_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CMCNP_016M_CFG_ITEM_MAX_NUM     (((CMCNP_016M_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CMCNP_032M_CFG_ITEM_MAX_NUM     (((CMCNP_032M_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CMCNP_064M_CFG_ITEM_MAX_NUM     (((CMCNP_064M_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CMCNP_128M_CFG_ITEM_MAX_NUM     (((CMCNP_128M_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CMCNP_256M_CFG_ITEM_MAX_NUM     (((CMCNP_256M_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CMCNP_512M_CFG_ITEM_MAX_NUM     (((CMCNP_512M_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CMCNP_001G_CFG_ITEM_MAX_NUM     (((CMCNP_001G_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#define CMCNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CMCNP_002G_CFG_ITEM_MAX_NUM     (((CMCNP_002G_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

#if (64 == WORDSIZE)
#define CMCNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CMCNP_004G_CFG_ITEM_MAX_NUM     (((CMCNP_004G_CFG_FILE_SIZE >> CMCNP_ITEM_SIZE_NBITS) >> 1) - 2)

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#endif/*(CMCNP_KEY_SIZE_063B == CMCNP_KEY_MAX_SIZE)*/


typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    UINT32         file_size; /*np file size*/
    uint32_t       item_max_num;
    uint32_t       rsvd;
}CMCNP_CFG;

#define CMCNP_CFG_MODEL_STR(cmcnp_cfg)              ((cmcnp_cfg)->model_str)
#define CMCNP_CFG_ALIAS_STR(cmcnp_cfg)              ((cmcnp_cfg)->alias_str)
#define CMCNP_CFG_FILE_SIZE(cmcnp_cfg)              ((cmcnp_cfg)->file_size)
#define CMCNP_CFG_ITEM_MAX_NUM(cmcnp_cfg)           ((cmcnp_cfg)->item_max_num)

#define CMCNP_ERR_MODEL             ((uint32_t)0xF)  /*4 bits*/

#define CMCNP_ERR_ID                ((uint32_t)0xFFFFFFFF)

typedef struct
{
    UINT32      size;
    UINT8      *data; /*item is start page no*/
}CMCNP_BITMAP;

#define CMCNP_BITMAP_SIZE(cmcnp_bitmap)               ((cmcnp_bitmap)->size)
#define CMCNP_BITMAP_DATA(cmcnp_bitmap)               ((cmcnp_bitmap)->data)

/**********************************************************************************************************************
*
* np_id | model | rsvd1 | rsvd2 | rsvd3 | pad | node_max_num | node_used_num | node_sizeof | free_head | item x n    |
* |<---------------------------------256 B-------------------------------------------------------------------------->|
*
***********************************************************************************************************************/
/*each np own one header*/
typedef struct
{
    /*8B*/
    uint32_t            np_id;               /*cmcnp id              */
    uint8_t             model;               /*cmcnp model           */
    uint8_t             rsvd1;
    uint8_t             rsvd2;
    uint8_t             rsvd3;

    uint8_t             pad[ 256 - 8 - 16 ]; /*pad the first part to 256 bytes*/

    CMCNPRB_POOL        pool;                /*pool of CMCNP_ITEM, CMCNP_ITEM head must be CMCNPRB_NODE*/
} CMCNP_HEADER;

#define CMCNP_HEADER_NP_ID(cmcnp_header)              ((cmcnp_header)->np_id)
#define CMCNP_HEADER_MODEL(cmcnp_header)              ((cmcnp_header)->model)

#define CMCNP_HEADER_ITEMS_POOL(cmcnp_header)         (&((cmcnp_header)->pool))
#define CMCNP_HEADER_ITEMS_MAX_NUM(cmcnp_header)      (CMCNPRB_POOL_NODE_MAX_NUM(CMCNP_HEADER_ITEMS_POOL(cmcnp_header)))
#define CMCNP_HEADER_ITEMS_USED_NUM(cmcnp_header)     (CMCNPRB_POOL_NODE_USED_NUM(CMCNP_HEADER_ITEMS_POOL(cmcnp_header)))


typedef EC_BOOL (*CMCNP_RETIRE_CALLBACK)(void *, const CMCNP_KEY *, const uint16_t, const uint16_t, const uint16_t);

typedef struct
{
    CMCNP_RETIRE_CALLBACK       func;
    void                       *arg;
}CMCNP_RETIRE_CB;

#define CMCNP_RETIRE_CB_FUNC(cmcnp_retire_cb)         ((cmcnp_retire_cb)->func)
#define CMCNP_RETIRE_CB_ARG(cmcnp_retire_cb)          ((cmcnp_retire_cb)->arg)

typedef struct
{
    int              fd;         /* memcache namespace fd  */
    uint32_t         rsvd;

    UINT32           fsize;

    uint8_t         *fname;

    uint64_t         del_size;     /* deleted but not recycled bytes*/
    uint64_t         recycle_size; /* recycled bytes*/

    CMCNP_BITMAP    *bitmap;
    CMCNP_HEADER    *header;       /* namespace header */

    /*shortcut of lru list which point to root rb node */
    CMCNPLRU_NODE   *lru_list; /*the lastest access node is at head covering fnode only*/

    /*shortcut of del list which point to root rb node */
    CMCNPDEL_NODE   *del_list; /*the lastest access node is at head covering fnode only*/

    /*for retire callback*/
    CMCNP_RETIRE_CB  retire_cb;
} CMCNP;

#define CMCNP_FD(cmcnp)                     ((cmcnp)->fd)
#define CMCNP_FSIZE(cmcnp)                  ((cmcnp)->fsize)
#define CMCNP_FNAME(cmcnp)                  ((cmcnp)->fname)
#define CMCNP_DEL_SIZE(cmcnp)               ((cmcnp)->del_size)
#define CMCNP_RECYCLE_SIZE(cmcnp)           ((cmcnp)->recycle_size)
#define CMCNP_BITMAP(cmcnp)                 ((cmcnp)->bitmap)
#define CMCNP_HDR(cmcnp)                    ((cmcnp)->header)

#define CMCNP_LRU_LIST(cmcnp)               ((cmcnp)->lru_list)
#define CMCNP_DEL_LIST(cmcnp)               ((cmcnp)->del_list)
#define CMCNP_RETIRE_CB(cmcnp)              (&((cmcnp)->retire_cb))

#define CMCNP_ID(cmcnp)                     (CMCNP_HEADER_NP_ID(CMCNP_HDR(cmcnp)))
#define CMCNP_MODEL(cmcnp)                  (CMCNP_HEADER_MODEL(CMCNP_HDR(cmcnp)))

#define CMCNP_ITEMS_POOL(cmcnp)             (CMCNP_HEADER_ITEMS_POOL(CMCNP_HDR(cmcnp)))
#define CMCNP_ITEMS_MAX_NUM(cmcnp)          (CMCNPRB_POOL_NODE_MAX_NUM(CMCNP_ITEMS_POOL(cmcnp)))
#define CMCNP_ITEMS_USED_NUM(cmcnp)         (CMCNPRB_POOL_NODE_USED_NUM(CMCNP_ITEMS_POOL(cmcnp)))

typedef EC_BOOL (*CMCNP_RECYCLE_DN_FUNC)(void *, const CMCNP_FNODE *);

typedef struct
{
    void * arg1;

    CMCNP_RECYCLE_DN_FUNC recycle_dn;
}CMCNP_RECYCLE_DN;

#define CMCNP_RECYCLE_DN_ARG1(cmcnp_recycle_dn)      ((cmcnp_recycle_dn)->arg1)
#define CMCNP_RECYCLE_DN_FUNC(cmcnp_recycle_dn)      ((cmcnp_recycle_dn)->recycle_dn)

typedef EC_BOOL (*CMCNP_RECYCLE_NP_FUNC)(const UINT32, const uint32_t);
typedef struct
{
    UINT32 arg1;

    CMCNP_RECYCLE_NP_FUNC recycle_np;
}CMCNP_RECYCLE_NP;

#define CMCNP_RECYCLE_NP_ARG1(cmcnp_recycle_np)      ((cmcnp_recycle_np)->arg1)
#define CMCNP_RECYCLE_NP_FUNC(cmcnp_recycle_np)      ((cmcnp_recycle_np)->recycle_np)

#endif/* _CMCNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/


