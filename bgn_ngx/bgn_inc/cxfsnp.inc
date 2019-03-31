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

#ifndef _CXFSNP_INC
#define _CXFSNP_INC

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

#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"

#include "cbloom.h"
#include "chashalgo.h"
#include "cmd5.h"
#include "cstack.h"

#include "cxfsnprb.h"
#include "cxfsnplru.inc"
#include "cxfsnpdel.inc"

#define CXFSNP_KEY_SIZE_255B            ( 255)/*max len of file or dir seg name*/
#define CXFSNP_KEY_SIZE_063B            (  63)/*max len of file or dir seg name*/

#define CXFSNP_KEY_MAX_SIZE             (CXFSNP_KEY_SIZE_063B)
#define CXFSNP_PATH_MAX_LEN             (1024)  /*max len of file or dir path name*/

#define CXFSNP_008M_MODEL   ((uint8_t) 0)
#define CXFSNP_016M_MODEL   ((uint8_t) 1)
#define CXFSNP_032M_MODEL   ((uint8_t) 2)
#define CXFSNP_064M_MODEL   ((uint8_t) 3)
#define CXFSNP_128M_MODEL   ((uint8_t) 4)
#define CXFSNP_256M_MODEL   ((uint8_t) 5)
#define CXFSNP_512M_MODEL   ((uint8_t) 6)
#define CXFSNP_001G_MODEL   ((uint8_t) 7)
#define CXFSNP_002G_MODEL   ((uint8_t) 8)
#define CXFSNP_004G_MODEL   ((uint8_t) 9)

#define CXFSNP_FILE_REPLICA_MAX_NUM     ((uint32_t) 1)  /*max num of supported replicas up to*/

#define CXFSNP_ITEM_FILE_IS_DIR         ((uint32_t) 0x0001)  /*directory   */
#define CXFSNP_ITEM_FILE_IS_REG         ((uint32_t) 0x0002)  /*regular file*/
#define CXFSNP_ITEM_FILE_IS_ANY         ((uint32_t) 0x0004)  /*any file    */
#define CXFSNP_ITEM_FILE_IS_ERR         ((uint32_t) 0x0000)  /*4 bits      */

#define CXFSNP_ITEM_IS_NOT_USED         ((uint32_t) 0x0000)  /*2 bits*/
#define CXFSNP_ITEM_IS_USED             ((uint32_t) 0x0001)

typedef struct
{
    uint16_t    rsvd;     /*data is cached or not*/
    uint16_t    disk_no;        /*local disk_no*/
    uint16_t    block_no;       /*block_no in above disk*/
    uint16_t    page_no;        /*page_no in above block*/
}CXFSNP_INODE;/*8B*/

#define CXFSNP_INODE_DISK_NO(cxfsnp_inode)           ((cxfsnp_inode)->disk_no)
#define CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)          ((cxfsnp_inode)->block_no)
#define CXFSNP_INODE_PAGE_NO(cxfsnp_inode)           ((cxfsnp_inode)->page_no)

typedef struct
{
    /*8B*/
    uint32_t      file_size:28;    /*data/value length <= 64M = 2^26B*/
    uint32_t      file_replica_num:4;
    uint32_t      rsvd;

    /*8B*/
    CXFSNP_INODE  inodes[ CXFSNP_FILE_REPLICA_MAX_NUM ];
}CXFSNP_FNODE;/*16B*/

#define CXFSNP_FNODE_FILESZ(cxfsnp_fnode)        ((cxfsnp_fnode)->file_size)
#define CXFSNP_FNODE_REPNUM(cxfsnp_fnode)        ((cxfsnp_fnode)->file_replica_num)
#define CXFSNP_FNODE_INODES(cxfsnp_fnode)        ((cxfsnp_fnode)->inodes)
#define CXFSNP_FNODE_INODE(cxfsnp_fnode, idx)    (&((cxfsnp_fnode)->inodes[ (idx) ]))

#define CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, idx)    CXFSNP_INODE_DISK_NO(CXFSNP_FNODE_INODE(cxfsnp_fnode, idx))
#define CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, idx)   CXFSNP_INODE_BLOCK_NO(CXFSNP_FNODE_INODE(cxfsnp_fnode, idx))
#define CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, idx)    CXFSNP_INODE_PAGE_NO(CXFSNP_FNODE_INODE(cxfsnp_fnode, idx))

#define CXFSNP_DNODE_PAD_SIZE                        (8)

typedef struct
{
    /*8B*/
    uint32_t       file_num;   /*number of files under this directory*/
    uint32_t       root_pos;   /*dir root pos*/

    /*8B*/
    uint8_t        pad[ CXFSNP_DNODE_PAD_SIZE ];
}CXFSNP_DNODE;/*16B*/

#define CXFSNP_DNODE_FILE_NUM(cxfsnp_dnode)      ((cxfsnp_dnode)->file_num)
#define CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode)      ((cxfsnp_dnode)->root_pos)

typedef struct
{
    uint8_t       len; /*[0..CXFSNP_KEY_MAX_SIZE]*/
    uint8_t       name[ CXFSNP_KEY_MAX_SIZE ];  /* dir name or file name */
}CXFSNP_KEY;

#define CXFSNP_KEY_LEN(cxfsnp_key)               ((cxfsnp_key)->len)
#define CXFSNP_KEY_NAME(cxfsnp_key)              ((cxfsnp_key)->name)

typedef struct
{
    /*16B*/
    CXFSNPRB_NODE   rb_node;

    /*4B*/
    uint32_t        used_flag   :3;  /* item status: not used, used */
    uint32_t        dir_flag    :2;  /* directory or regular file */
    uint32_t        create_time :27; /* num of bits is enough */

    /*4B*/
    uint32_t        key_offset; /*key address = item address + key_offset*/

    /*8B*/
    uint32_t        parent_pos;/*parent directory*/
    uint32_t        second_hash;

    /*8B*/
    CXFSNPLRU_NODE  lru_node;

    /*8B*/
    CXFSNPDEL_NODE  del_node;

    union
    {
        CXFSNP_FNODE fnode;/*16B*/
        CXFSNP_DNODE dnode;/*16B*/
    }u;/*16B*/
} CXFSNP_ITEM;/*64B*/

#define CXFSNP_ITEM_RB_NODE(cxfsnp_item)          (&((cxfsnp_item)->rb_node))
#define CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)         ((cxfsnp_item)->dir_flag)
#define CXFSNP_ITEM_USED_FLAG(cxfsnp_item)        ((cxfsnp_item)->used_flag)
#define CXFSNP_ITEM_KEY_OFFSET(cxfsnp_item)       ((cxfsnp_item)->key_offset)

#define CXFSNP_ITEM_PARENT_POS(cxfsnp_item)       ((cxfsnp_item)->parent_pos)
#define CXFSNP_ITEM_FNODE(cxfsnp_item)            (&((cxfsnp_item)->u.fnode))
#define CXFSNP_ITEM_DNODE(cxfsnp_item)            (&((cxfsnp_item)->u.dnode))
#define CXFSNP_ITEM_CREATE_TIME(cxfsnp_item)      ((cxfsnp_item)->create_time)
#define CXFSNP_ITEM_SECOND_HASH(cxfsnp_item)      ((cxfsnp_item)->second_hash)
#define CXFSNP_ITEM_LRU_NODE(cxfsnp_item)         (&((cxfsnp_item)->lru_node))
#define CXFSNP_ITEM_DEL_NODE(cxfsnp_item)         (&((cxfsnp_item)->del_node))

#define CXFSNP_ITEM_KEY(cxfsnp_item)              \
    ((CXFSNP_KEY *)(((void *)(cxfsnp_item)) + CXFSNP_ITEM_KEY_OFFSET(cxfsnp_item)))

#define CXFSNP_ITEM_KLEN(cxfsnp_item)             (CXFSNP_KEY_LEN(CXFSNP_ITEM_KEY(cxfsnp_item)))
#define CXFSNP_ITEM_KNAME(cxfsnp_item)            (CXFSNP_KEY_NAME(CXFSNP_ITEM_KEY(cxfsnp_item)))


/*get CXFSNP_ITEM from CXFSNPRB_NODE*/
#define CXFSNP_RB_NODE_ITEM(cxfsnprb_node)        ((NULL_PTR == (cxfsnprb_node)) ? NULL_PTR : \
    ((CXFSNP_ITEM *)((char *)(cxfsnprb_node)-(unsigned long)(&((CXFSNP_ITEM *)0)->rb_node))))

/*get CXFSNP_ITEM from CXFSNPLRU_NODE*/
#define CXFSNP_LRU_NODE_ITEM(cxfsnplru_node)        ((NULL_PTR == (cxfsnplru_node)) ? NULL_PTR : \
    ((CXFSNP_ITEM *)((char *)(cxfsnplru_node)-(unsigned long)(&((CXFSNP_ITEM *)0)->lru_node))))

/*get CXFSNP_ITEM from CXFSNPDEL_NODE*/
#define CXFSNP_DEL_NODE_ITEM(cxfsnpdel_node)        ((NULL_PTR == (cxfsnpdel_node)) ? NULL_PTR : \
    ((CXFSNP_ITEM *)((char *)(cxfsnpdel_node)-(unsigned long)(&((CXFSNP_ITEM *)0)->del_node))))

#define CXFSNP_ITEM_IS_REG(cxfsnp_item)            (CXFSNP_ITEM_FILE_IS_REG == (CXFSNP_ITEM_FILE_IS_REG & CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)))
#define CXFSNP_ITEM_IS_DIR(cxfsnp_item)            (CXFSNP_ITEM_FILE_IS_DIR == (CXFSNP_ITEM_FILE_IS_DIR & CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)))

#define CXFSNP_ITEM_IS_NOT_REG(cxfsnp_item)        (CXFSNP_ITEM_FILE_IS_REG != (CXFSNP_ITEM_FILE_IS_REG & CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)))
#define CXFSNP_ITEM_IS_NOT_DIR(cxfsnp_item)        (CXFSNP_ITEM_FILE_IS_DIR != (CXFSNP_ITEM_FILE_IS_DIR & CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)))

#define CXFSNP_ITEM_IS_INVALID(cxfsnp_item)        ((CXFSNP_ITEM_FILE_IS_REG | CXFSNP_ITEM_FILE_IS_DIR) & CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
#define CXFSNP_ITEM_IS_NOT_INVALID(cxfsnp_item)    (0 == ((CXFSNP_ITEM_FILE_IS_REG | CXFSNP_ITEM_FILE_IS_DIR) & CXFSNP_ITEM_DIR_FLAG(cxfsnp_item)) )

#if (CXFSNP_KEY_SIZE_255B == CXFSNP_KEY_MAX_SIZE)
/*item max num = [file size / 1280] * 4*/
/*item table start from offset 256B. */
/*file name table start from offset 256 + 64 * item max num which is aligned to 256 ( mod 256 = 0)*/
/*1280 = 320 * 4 = 256 * 5, where 320 = 64 (sizeof item) + 256 (sizeof key)*/

#define CXFSNP_ITEM_BIT_SIZE             (6)
#define CXFSNP_ITEM_SIZEOF               (1 << CXFSNP_ITEM_BIT_SIZE) /*it must be 64B*/

#define CXFSNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CXFSNP_008M_CFG_ITEM_MAX_NUM     ((CXFSNP_008M_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CXFSNP_016M_CFG_ITEM_MAX_NUM     ((CXFSNP_016M_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CXFSNP_032M_CFG_ITEM_MAX_NUM     ((CXFSNP_032M_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CXFSNP_064M_CFG_ITEM_MAX_NUM     ((CXFSNP_064M_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CXFSNP_128M_CFG_ITEM_MAX_NUM     ((CXFSNP_128M_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CXFSNP_256M_CFG_ITEM_MAX_NUM     ((CXFSNP_256M_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CXFSNP_512M_CFG_ITEM_MAX_NUM     ((CXFSNP_512M_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CXFSNP_001G_CFG_ITEM_MAX_NUM     ((CXFSNP_001G_CFG_FILE_SIZE / 1280) << 2)

#define CXFSNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CXFSNP_002G_CFG_ITEM_MAX_NUM     ((CXFSNP_002G_CFG_FILE_SIZE / 1280) << 2)

#if (64 == WORDSIZE)
#define CXFSNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CXFSNP_004G_CFG_ITEM_MAX_NUM     ((CXFSNP_004G_CFG_FILE_SIZE / 1280) << 2)

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#endif/*(CXFSNP_KEY_SIZE_255B == CXFSNP_KEY_MAX_SIZE)*/

#if (CXFSNP_KEY_SIZE_063B == CXFSNP_KEY_MAX_SIZE)
/*item max num = [file size / 128] - 2*/
/*item table start from offset 256B. */
/*128 = 64 (sizeof item) + 64 (sizeof key)*/

#define CXFSNP_ITEM_BIT_SIZE             (6)
#define CXFSNP_ITEM_SIZEOF               (1 << CXFSNP_ITEM_BIT_SIZE) /*it must be 64B*/

#define CXFSNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CXFSNP_008M_CFG_ITEM_MAX_NUM     (((CXFSNP_008M_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CXFSNP_016M_CFG_ITEM_MAX_NUM     (((CXFSNP_016M_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CXFSNP_032M_CFG_ITEM_MAX_NUM     (((CXFSNP_032M_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CXFSNP_064M_CFG_ITEM_MAX_NUM     (((CXFSNP_064M_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CXFSNP_128M_CFG_ITEM_MAX_NUM     (((CXFSNP_128M_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CXFSNP_256M_CFG_ITEM_MAX_NUM     (((CXFSNP_256M_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CXFSNP_512M_CFG_ITEM_MAX_NUM     (((CXFSNP_512M_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CXFSNP_001G_CFG_ITEM_MAX_NUM     (((CXFSNP_001G_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#define CXFSNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CXFSNP_002G_CFG_ITEM_MAX_NUM     (((CXFSNP_002G_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

#if (64 == WORDSIZE)
#define CXFSNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CXFSNP_004G_CFG_ITEM_MAX_NUM     (((CXFSNP_004G_CFG_FILE_SIZE >> CXFSNP_ITEM_BIT_SIZE) >> 1) - 2)

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#endif/*(CXFSNP_KEY_SIZE_063B == CXFSNP_KEY_MAX_SIZE)*/


typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    UINT32         file_size; /*np file size*/
    uint32_t       item_max_num;
    uint32_t       rsvd;
}CXFSNP_CFG;

#define CXFSNP_CFG_MODEL_STR(cxfsnp_cfg)              ((cxfsnp_cfg)->model_str)
#define CXFSNP_CFG_ALIAS_STR(cxfsnp_cfg)              ((cxfsnp_cfg)->alias_str)
#define CXFSNP_CFG_FILE_SIZE(cxfsnp_cfg)              ((cxfsnp_cfg)->file_size)
#define CXFSNP_CFG_ITEM_MAX_NUM(cxfsnp_cfg)           ((cxfsnp_cfg)->item_max_num)

#define CXFSNP_ERR_MODEL             ((uint32_t)0xF)  /*4 bits*/

#define CXFSNP_O_RDONLY              ((uint32_t)O_RDONLY)
#define CXFSNP_O_WRONLY              ((uint32_t)O_WRONLY)
#define CXFSNP_O_RDWR                ((uint32_t)O_RDWR  )
#define CXFSNP_O_CREATE              ((uint32_t)O_CREAT )

#define CXFSNP_PATH_LAYOUT_DIR0_NBITS    ( 8)
#define CXFSNP_PATH_LAYOUT_DIR1_NBITS    ( 8)
#define CXFSNP_PATH_LAYOUT_DIR2_NBITS    ( 8)
#define CXFSNP_PATH_LAYOUT_DIR3_NBITS    ( 8)

#define CXFSNP_PATH_LAYOUT_DIR0_ABITS    (24) /*bit alignment*/
#define CXFSNP_PATH_LAYOUT_DIR1_ABITS    (16) /*bit alignment*/
#define CXFSNP_PATH_LAYOUT_DIR2_ABITS    ( 8) /*bit alignment*/
#define CXFSNP_PATH_LAYOUT_DIR3_ABITS    ( 0) /*bit alignment*/

#define CXFSNP_PATH_LAYOUT_DIR0_MASK     (((UINT32)(UINT32_ONE << CXFSNP_PATH_LAYOUT_DIR0_NBITS)) - 1)
#define CXFSNP_PATH_LAYOUT_DIR1_MASK     (((UINT32)(UINT32_ONE << CXFSNP_PATH_LAYOUT_DIR1_NBITS)) - 1)
#define CXFSNP_PATH_LAYOUT_DIR2_MASK     (((UINT32)(UINT32_ONE << CXFSNP_PATH_LAYOUT_DIR2_NBITS)) - 1)
#define CXFSNP_PATH_LAYOUT_DIR3_MASK     (((UINT32)(UINT32_ONE << CXFSNP_PATH_LAYOUT_DIR3_NBITS)) - 1)

#define CXFSNP_PATH_LAYOUT_DIR0_NO(path_id)     (((path_id) >> CXFSNP_PATH_LAYOUT_DIR0_ABITS) & CXFSNP_PATH_LAYOUT_DIR0_MASK)
#define CXFSNP_PATH_LAYOUT_DIR1_NO(path_id)     (((path_id) >> CXFSNP_PATH_LAYOUT_DIR1_ABITS) & CXFSNP_PATH_LAYOUT_DIR1_MASK)
#define CXFSNP_PATH_LAYOUT_DIR2_NO(path_id)     (((path_id) >> CXFSNP_PATH_LAYOUT_DIR2_ABITS) & CXFSNP_PATH_LAYOUT_DIR2_MASK)
#define CXFSNP_PATH_LAYOUT_DIR3_NO(path_id)     (((path_id) >> CXFSNP_PATH_LAYOUT_DIR3_ABITS) & CXFSNP_PATH_LAYOUT_DIR3_MASK)

#define CXFSNP_ERR_ID                     ((uint32_t)0xFFFFFFFF)


/**********************************************************************************************************************************************************************
*
* np_id | model | rsvd1 | rsvd2 | algo_1st | algo_2nd | pad | node_max_num | node_used_num | node_sizeof | free_head | item x n | key x n |
* |<---------------------------------256 B-------------------------------------------------------------------------->|
*
***********************************************************************************************************************************************************************/
/*each np own one header*/
typedef struct
{
    /*8B*/
    uint32_t            np_id;               /*cxfsnp id              */
    uint8_t             model;               /*cxfsnp model           */
    uint8_t             rsvd1;
    uint8_t             rsvd2;
    uint8_t             chash_algo_2nd_id;   /*second hash algo func id: used to compute cxfsnprb_node hash data*/

    uint8_t             pad[ 256 - 8 - 16 ]; /*pad the first part to 256B*/

    CXFSNPRB_POOL       pool;                /*pool of CXFSNP_ITEM, CXFSNP_ITEM head must be CXFSNPRB_NODE*/
} CXFSNP_HEADER;

#define CXFSNP_HEADER_NP_ID(cxfsnp_header)                      ((cxfsnp_header)->np_id)
#define CXFSNP_HEADER_MODEL(cxfsnp_header)                      ((cxfsnp_header)->model)

#define CXFSNP_HEADER_2ND_CHASH_ALGO_ID(cxfsnp_header)          ((cxfsnp_header)->chash_algo_2nd_id)

#define CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header)         (&((cxfsnp_header)->pool))
#define CXFSNP_HEADER_ITEMS_MAX_NUM(cxfsnp_header)      (CXFSNPRB_POOL_NODE_MAX_NUM(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header)))
#define CXFSNP_HEADER_ITEMS_USED_NUM(cxfsnp_header)     (CXFSNPRB_POOL_NODE_USED_NUM(CXFSNP_HEADER_ITEMS_POOL(cxfsnp_header)))

typedef struct
{
    uint32_t                read_only_flag:1;
    uint32_t                rsvd01        :31;
    uint32_t                rsvd02;

    UINT32                  fsize;

    uint64_t                del_size;     /* deleted but not recycled bytes*/
    uint64_t                recycle_size; /* recycled bytes*/

    CXFSNP_HEADER          *header;       /* hashdb header */

    /*shortcut of lru list which point to root rb node */
    CXFSNPLRU_NODE         *lru_list; /*the lastest access node is at head covering fnode only*/

    /*shortcut of del list which point to root rb node */
    CXFSNPDEL_NODE         *del_list;      /*the deleted but not recycled nodes are in covering fnode and dnode*/

    CHASH_ALGO              chash_algo_2nd;/* hash algo for rbtree in the hash bucket: used to compute cxfsnprb_node hash data*/
} CXFSNP;

#define CXFSNP_READ_ONLY_FLAG(cxfsnp)         ((cxfsnp)->read_only_flag)
#define CXFSNP_FSIZE(cxfsnp)                  ((cxfsnp)->fsize)
#define CXFSNP_DEL_SIZE(cxfsnp)               ((cxfsnp)->del_size)
#define CXFSNP_RECYCLE_SIZE(cxfsnp)           ((cxfsnp)->recycle_size)
#define CXFSNP_HDR(cxfsnp)                    ((cxfsnp)->header)

#define CXFSNP_LRU_LIST(cxfsnp)               ((cxfsnp)->lru_list)
#define CXFSNP_DEL_LIST(cxfsnp)               ((cxfsnp)->del_list)

#define CXFSNP_2ND_CHASH_ALGO(cxfsnp)         ((cxfsnp)->chash_algo_2nd)

#define CXFSNP_ID(cxfsnp)                     (CXFSNP_HEADER_NP_ID(CXFSNP_HDR(cxfsnp)))
#define CXFSNP_MODEL(cxfsnp)                  (CXFSNP_HEADER_MODEL(CXFSNP_HDR(cxfsnp)))
#define CXFSNP_SECOND_CHASH_ALGO_ID(cxfsnp)   (CXFSNP_HEADER_2ND_CHASH_ALGO_ID(CXFSNP_HDR(cxfsnp)))

#define CXFSNP_ITEMS_POOL(cxfsnp)             (CXFSNP_HEADER_ITEMS_POOL(CXFSNP_HDR(cxfsnp)))
#define CXFSNP_ITEMS_MAX_NUM(cxfsnp)          (CXFSNPRB_POOL_NODE_MAX_NUM(CXFSNP_ITEMS_POOL(cxfsnp)))
#define CXFSNP_ITEMS_USED_NUM(cxfsnp)         (CXFSNPRB_POOL_NODE_USED_NUM(CXFSNP_ITEMS_POOL(cxfsnp)))

#define CXFSNP_2ND_CHASH_ALGO_COMPUTE(cxfsnp, klen, key)  (CXFSNP_2ND_CHASH_ALGO(cxfsnp)(klen, key))

typedef EC_BOOL (*CXFSNP_RECYCLE_DN_FUNC)(const UINT32, const CXFSNP_FNODE *);

typedef struct
{
    UINT32 arg1;

    CXFSNP_RECYCLE_DN_FUNC recycle_dn;
}CXFSNP_RECYCLE_DN;

#define CXFSNP_RECYCLE_DN_ARG1(cxfsnp_recycle_dn)      ((cxfsnp_recycle_dn)->arg1)
#define CXFSNP_RECYCLE_DN_FUNC(cxfsnp_recycle_dn)      ((cxfsnp_recycle_dn)->recycle_dn)

typedef EC_BOOL (*CXFSNP_RECYCLE_NP_FUNC)(const UINT32, const uint32_t);
typedef struct
{
    UINT32 arg1;

    CXFSNP_RECYCLE_NP_FUNC recycle_np;
}CXFSNP_RECYCLE_NP;

#define CXFSNP_RECYCLE_NP_ARG1(cxfsnp_recycle_np)      ((cxfsnp_recycle_np)->arg1)
#define CXFSNP_RECYCLE_NP_FUNC(cxfsnp_recycle_np)      ((cxfsnp_recycle_np)->recycle_np)

/*np iterator when walkthrough directory*/
#define CXFSNP_DIT_ARGS_MAX_NUM  ((UINT32)4)
typedef struct _CXFSNP_DIT_NODE
{
    EC_BOOL (*handler)(struct _CXFSNP_DIT_NODE *, CXFSNP *, CXFSNP_ITEM *, const uint32_t);
    CSTACK  cxfsnp_item_stack;
    void *args[ CXFSNP_DIT_ARGS_MAX_NUM ];
}CXFSNP_DIT_NODE;

#define CXFSNP_DIT_NODE_HANDLER(cxfsnp_dit_node)        ((cxfsnp_dit_node)->handler)
#define CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node)          (&((cxfsnp_dit_node)->cxfsnp_item_stack))
#define CXFSNP_DIT_NODE_ARGS(cxfsnp_dit_node)           ((cxfsnp_dit_node)->args)
#define CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, idx)       ((cxfsnp_dit_node)->args[ (idx) ])

#endif/* _CXFSNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

