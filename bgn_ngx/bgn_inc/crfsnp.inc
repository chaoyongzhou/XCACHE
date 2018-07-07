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

#ifndef _CRFSNP_INC
#define _CRFSNP_INC

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

#include "crfsnprb.h"
#include "crfsnplru.inc"
#include "crfsnpdel.inc"

#define CRFSNP_KEY_MAX_SIZE             ( 255)  /*max len of file or dir seg name*/
#define CRFSNP_PATH_MAX_LEN             (1024)  /*max len of file or dir path name*/

#define CRFSNP_008M_MODEL   ((uint8_t) 0)
#define CRFSNP_016M_MODEL   ((uint8_t) 1)
#define CRFSNP_032M_MODEL   ((uint8_t) 2)
#define CRFSNP_064M_MODEL   ((uint8_t) 3)
#define CRFSNP_128M_MODEL   ((uint8_t) 4)
#define CRFSNP_256M_MODEL   ((uint8_t) 5)
#define CRFSNP_512M_MODEL   ((uint8_t) 6)
#define CRFSNP_001G_MODEL   ((uint8_t) 7)
#define CRFSNP_002G_MODEL   ((uint8_t) 8)
#define CRFSNP_004G_MODEL   ((uint8_t) 9)

#define CRFSNP_FILE_REPLICA_MAX_NUM     ((uint32_t) 1)  /*max num of supported replicas up to*/

#define CRFSNP_ITEM_REF_MAX_NUM         ((UINT32) 0xF)  /*4 bits*/

#define CRFSNP_ITEM_FILE_IS_PIP         ((uint32_t) 0x0001)  /*pipe file   */
#define CRFSNP_ITEM_FILE_IS_DIR         ((uint32_t) 0x0002)  /*directory   */
#define CRFSNP_ITEM_FILE_IS_LNK         ((uint32_t) 0x0004)  /*link file   */
#define CRFSNP_ITEM_FILE_IS_REG         ((uint32_t) 0x0008)  /*regular file*/
#define CRFSNP_ITEM_FILE_IS_SCK         ((uint32_t) 0x0010)  /*socket file */
#define CRFSNP_ITEM_FILE_IS_CHR         ((uint32_t) 0x0020)  /*char device */
#define CRFSNP_ITEM_FILE_IS_BLK         ((uint32_t) 0x0040)  /*block device*/
#define CRFSNP_ITEM_FILE_IS_ANY         ((uint32_t) 0x0080)  /*any file    */
#define CRFSNP_ITEM_FILE_IS_ERR         ((uint32_t) 0x0000)  /*4 bits      */

#define CRFSNP_ITEM_IS_NOT_USED         ((uint32_t) 0x0001)  /*2 bits*/
#define CRFSNP_ITEM_IS_USED             ((uint32_t) 0x0002)
//#define CRFSNP_ITEM_ANY_USED            ((uint32_t) 0x3)

#define CRFSNP_ITEM_CAN_ACCESS          ((uint32_t) 0x0001)  /*2 bits*/
#define CRFSNP_ITEM_NOT_ACCESS          ((uint32_t) 0x0002)
#define CRFSNP_ITEM_ANY_ACCESS          ((uint32_t) 0x0003)

/**********************************************************************************
*   bit# 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
*        t  t  t  t  u   g  s  r  w  x  r  w  x  r  w  x
*        ----------  -   -  -  -------  -------  -------
*           |        |   |  |     |        |        |_ other permission
*           |        |   |  |     |        |
*           |        |   |  |     |        |_ group permission
*           |        |   |  |     |
*           |        |   |  |     |_ owner/user permission
*           |        |   |  |
*           |        |   |  |_ sticky bit
*           |        |   |
*           |        |   |_ set_gid bit
*           |        |
*           |        |_ set_uid bit
*           |
*           |_ file type
*
**********************************************************************************/

#define CRFSNP_PERMISSION_UID_BIT_MASK  ((uint32_t) 04000)
#define CRFSNP_PERMISSION_GID_BIT_MASK  ((uint32_t) 02000)
#define CRFSNP_PERMISSION_STK_BIT_MASK  ((uint32_t) 01000)
#define CRFSNP_PERMISSION_USR_BIT_MASK  ((uint32_t) 00700)
#define CRFSNP_PERMISSION_GRP_BIT_MASK  ((uint32_t) 00070)
#define CRFSNP_PERMISSION_OTH_BIT_MASK  ((uint32_t) 00007)

#define CRFSNP_PERMISSION_UID_NBITS     ((uint32_t)  1)    /*num of bits*/
#define CRFSNP_PERMISSION_GID_NBITS     ((uint32_t)  1)    /*num of bits*/
#define CRFSNP_PERMISSION_STK_NBITS     ((uint32_t)  1)    /*num of bits*/
#define CRFSNP_PERMISSION_USR_NBITS     ((uint32_t)  3)    /*num of bits*/
#define CRFSNP_PERMISSION_GRP_NBITS     ((uint32_t)  3)    /*num of bits*/
#define CRFSNP_PERMISSION_OTH_NBITS     ((uint32_t)  3)    /*num of bits*/

#define CRFSNP_PERMISSION_UID_ABITS     ((uint32_t) 11)    /*bit alignment*/
#define CRFSNP_PERMISSION_GID_ABITS     ((uint32_t) 10)    /*bit alignment*/
#define CRFSNP_PERMISSION_STK_ABITS     ((uint32_t)  9)    /*bit alignment*/
#define CRFSNP_PERMISSION_USR_ABITS     ((uint32_t)  6)    /*bit alignment*/
#define CRFSNP_PERMISSION_GRP_ABITS     ((uint32_t)  3)    /*bit alignment*/
#define CRFSNP_PERMISSION_OTH_ABITS     ((uint32_t)  0)    /*bit alignment*/


#define CRFSDN_DATA_NOT_IN_CACHE        ((uint16_t)0x0000)
#define CRFSDN_DATA_IS_IN_CACHE         ((uint16_t)0x0001)

typedef struct
{
    uint16_t    cache_flag;     /*data is cached or not*/
    uint16_t    disk_no;        /*local disk_no*/
    uint16_t    block_no;       /*block_no in above disk*/
    uint16_t    page_no;        /*page_no in above block*/
}CRFSNP_INODE;

//#define CRFSNP_INODE_TCID(crfsnp_inode)              ((crfsnp_inode)->tcid)
#define CRFSNP_INODE_CACHE_FLAG(crfsnp_inode)        ((crfsnp_inode)->cache_flag)
#define CRFSNP_INODE_DISK_NO(crfsnp_inode)           ((crfsnp_inode)->disk_no)
#define CRFSNP_INODE_BLOCK_NO(crfsnp_inode)          ((crfsnp_inode)->block_no)
#define CRFSNP_INODE_PAGE_NO(crfsnp_inode)           ((crfsnp_inode)->page_no)

#define CRFSNP_FNODE_NO_MEM_CACHE_FLAG               ((uint32_t) 0)
#define CRFSNP_FNODE_HAS_MEM_CACHE_FLAG              ((uint32_t) 1)
#define CRFSNP_FNODE_PAD_SIZE                        (160)

typedef struct
{
    /*16B*/
    uint32_t      file_size;    /*data/value length <= 64M = 2^26B*/
    uint32_t      file_replica_num;
    uint32_t      file_path_hash;
    uint32_t      rsvd;

    /*8B*/  
    CRFSNP_INODE  inodes[ CRFSNP_FILE_REPLICA_MAX_NUM ]; 

    /*16B*/
    uint8_t       md5sum[ CMD5_DIGEST_LEN ];

    /*160B*/
    uint8_t       pad[ CRFSNP_FNODE_PAD_SIZE ];
}CRFSNP_FNODE;/*200B*/

#define CRFSNP_FNODE_FILESZ(crfsnp_fnode)        ((crfsnp_fnode)->file_size)
#define CRFSNP_FNODE_REPNUM(crfsnp_fnode)        ((crfsnp_fnode)->file_replica_num)
#define CRFSNP_FNODE_HASH(crfsnp_fnode)          ((crfsnp_fnode)->file_path_hash)
#define CRFSNP_FNODE_INODES(crfsnp_fnode)        ((crfsnp_fnode)->inodes)
#define CRFSNP_FNODE_INODE(crfsnp_fnode, idx)    (&((crfsnp_fnode)->inodes[ (idx) ]))
#define CRFSNP_FNODE_MD5SUM(crfsnp_fnode)        ((crfsnp_fnode)->md5sum)

#define CRFSNP_FNODE_CACHE_FLAG(crfsnp_fnode, idx)       CRFSNP_INODE_CACHE_FLAG(CRFSNP_FNODE_INODE(crfsnp_fnode, idx))
#define CRFSNP_FNODE_INODE_DISK_NO(crfsnp_fnode, idx)    CRFSNP_INODE_DISK_NO(CRFSNP_FNODE_INODE(crfsnp_fnode, idx))
#define CRFSNP_FNODE_INODE_BLOCK_NO(crfsnp_fnode, idx)   CRFSNP_INODE_BLOCK_NO(CRFSNP_FNODE_INODE(crfsnp_fnode, idx))
#define CRFSNP_FNODE_INODE_PAGE_NO(crfsnp_fnode, idx)    CRFSNP_INODE_PAGE_NO(CRFSNP_FNODE_INODE(crfsnp_fnode, idx))

#define CRFSNP_DNODE_PAD_SIZE                        (192)

typedef struct
{
    uint32_t       file_num;   /*number of files under this directory*/
    uint32_t       root_pos;   /*dir root pos*/
    uint8_t        pad[ CRFSNP_DNODE_PAD_SIZE ];/*192B*/
}CRFSNP_DNODE;/*200B*/

#define CRFSNP_DNODE_FILE_NUM(crfsnp_dnode)      ((crfsnp_dnode)->file_num)
#define CRFSNP_DNODE_ROOT_POS(crfsnp_dnode)      ((crfsnp_dnode)->root_pos)

typedef struct
{
    /*16B*/
    CRFSNPRB_NODE   rb_node;

    /*4B*/
    uint32_t      used_flag:4;  /* item status: not used, used */
    uint32_t      key_len  :8;  /* key lenght, range [0..CRFSNP_KEY_MAX_SIZE] */
    uint32_t      dir_flag :8;  /* directory or regular file */
    uint32_t      set_uid  :1;  /* set uid bit*/
    uint32_t      set_gid  :1;  /* set gid bit*/
    uint32_t      sticky   :1;  /* sticky bit*/
    uint32_t      owner_per:3;  /* owner permission*/
    uint32_t      group_per:3;  /* group permission*/
    uint32_t      other_per:3;  /* other permission*/

    /*4B*/
    uint16_t      gid;
    uint16_t      uid;

    /*8B*/
    ctime_t       create_time; /*file created or modified time. 32 bits for 32bit OS, 64 bits for 64bit OS*/
#if (32 == WORDSIZE)
    uint32_t      rsvd1;
#endif/*(32 == WORDSIZE)*/

    /*8B*/
    uint32_t      parent_pos;/*parent directory*/
    uint32_t      second_hash;

    /*8B*/
    CRFSNPLRU_NODE lru_node;

    /*8B*/
    CRFSNPDEL_NODE del_node;

    /*256B*/
    uint8_t       rsvd3;
    uint8_t       key[ CRFSNP_KEY_MAX_SIZE ];  /* dir name or file name */

    union
    {
        CRFSNP_FNODE fnode;/*200B*/
        CRFSNP_DNODE dnode;/*200B*/
    }u;/*200B*/
} CRFSNP_ITEM;/*512B*/

#define CRFSNP_ITEM_RB_NODE(crfsnp_item)          (&((crfsnp_item)->rb_node))
#define CRFSNP_ITEM_DIR_FLAG(crfsnp_item)         ((crfsnp_item)->dir_flag)
#define CRFSNP_ITEM_USED_FLAG(crfsnp_item)        ((crfsnp_item)->used_flag)
//#define CRFSNP_ITEM_ACC_FLAG(crfsnp_item)         ((crfsnp_item)->acc_flag)
#define CRFSNP_ITEM_KLEN(crfsnp_item)             ((crfsnp_item)->key_len)
#define CRFSNP_ITEM_KEY(crfsnp_item)              ((crfsnp_item)->key)
#define CRFSNP_ITEM_PARENT_POS(crfsnp_item)       ((crfsnp_item)->parent_pos)
#define CRFSNP_ITEM_FNODE(crfsnp_item)            (&((crfsnp_item)->u.fnode))
#define CRFSNP_ITEM_DNODE(crfsnp_item)            (&((crfsnp_item)->u.dnode))
#define CRFSNP_ITEM_CREATE_TIME(crfsnp_item)      ((crfsnp_item)->create_time)
#define CRFSNP_ITEM_SECOND_HASH(crfsnp_item)      ((crfsnp_item)->second_hash)
#define CRFSNP_ITEM_LRU_NODE(crfsnp_item)         (&((crfsnp_item)->lru_node))
#define CRFSNP_ITEM_DEL_NODE(crfsnp_item)         (&((crfsnp_item)->del_node))

/*get CRFSNP_ITEM from CRFSNPRB_NODE*/
#define CRFSNP_RB_NODE_ITEM(crfsnprb_node)        ((NULL_PTR == (crfsnprb_node)) ? NULL_PTR : \
    ((CRFSNP_ITEM *)((char *)(crfsnprb_node)-(unsigned long)(&((CRFSNP_ITEM *)0)->rb_node))))

/*get CRFSNP_ITEM from CRFSNPLRU_NODE*/
#define CRFSNP_LRU_NODE_ITEM(crfsnplru_node)        ((NULL_PTR == (crfsnplru_node)) ? NULL_PTR : \
    ((CRFSNP_ITEM *)((char *)(crfsnplru_node)-(unsigned long)(&((CRFSNP_ITEM *)0)->lru_node))))

/*get CRFSNP_ITEM from CRFSNPDEL_NODE*/
#define CRFSNP_DEL_NODE_ITEM(crfsnpdel_node)        ((NULL_PTR == (crfsnpdel_node)) ? NULL_PTR : \
    ((CRFSNP_ITEM *)((char *)(crfsnpdel_node)-(unsigned long)(&((CRFSNP_ITEM *)0)->del_node))))
    
#define CRFSNP_ITEM_IS_REG(crfsnp_item)            (CRFSNP_ITEM_FILE_IS_REG == (CRFSNP_ITEM_FILE_IS_REG & CRFSNP_ITEM_DIR_FLAG(crfsnp_item)))
#define CRFSNP_ITEM_IS_DIR(crfsnp_item)            (CRFSNP_ITEM_FILE_IS_DIR == (CRFSNP_ITEM_FILE_IS_DIR & CRFSNP_ITEM_DIR_FLAG(crfsnp_item)))

#define CRFSNP_ITEM_IS_NOT_REG(crfsnp_item)        (CRFSNP_ITEM_FILE_IS_REG != (CRFSNP_ITEM_FILE_IS_REG & CRFSNP_ITEM_DIR_FLAG(crfsnp_item)))
#define CRFSNP_ITEM_IS_NOT_DIR(crfsnp_item)        (CRFSNP_ITEM_FILE_IS_DIR != (CRFSNP_ITEM_FILE_IS_DIR & CRFSNP_ITEM_DIR_FLAG(crfsnp_item)))

#define CRFSNP_ITEM_IS_INVALID(crfsnp_item)        ((CRFSNP_ITEM_FILE_IS_REG | CRFSNP_ITEM_FILE_IS_DIR) & CRFSNP_ITEM_DIR_FLAG(crfsnp_item))
#define CRFSNP_ITEM_IS_NOT_INVALID(crfsnp_item)    (0 == ((CRFSNP_ITEM_FILE_IS_REG | CRFSNP_ITEM_FILE_IS_DIR) & CRFSNP_ITEM_DIR_FLAG(crfsnp_item)) )

/*item max num = file size / sizeof(CRFSNP_ITEM) - delta where sizeof(CRFSNP_ITEM) = 512 = 2^9*/
/*where delta = 4096, i.e., 4096 * 512B = 2MB, less than 1MB is bitmap of deleted items, left is other members or reserved bytes*/
#define CRFSNP_ITEM_BIT_SIZE             (9)
#define CRFSNP_ITEM_SIZEOF               (1 << CRFSNP_ITEM_BIT_SIZE) /*it must be 512B*/

#define CRFSNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CRFSNP_008M_CFG_ITEM_MAX_NUM     ((CRFSNP_008M_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CRFSNP_016M_CFG_ITEM_MAX_NUM     ((CRFSNP_016M_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CRFSNP_032M_CFG_ITEM_MAX_NUM     ((CRFSNP_032M_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CRFSNP_064M_CFG_ITEM_MAX_NUM     ((CRFSNP_064M_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CRFSNP_128M_CFG_ITEM_MAX_NUM     ((CRFSNP_128M_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CRFSNP_256M_CFG_ITEM_MAX_NUM     ((CRFSNP_256M_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CRFSNP_512M_CFG_ITEM_MAX_NUM     ((CRFSNP_512M_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CRFSNP_001G_CFG_ITEM_MAX_NUM     ((CRFSNP_001G_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#define CRFSNP_002G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CRFSNP_002G_CFG_ITEM_MAX_NUM     ((CRFSNP_002G_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

#if (64 == WORDSIZE)
#define CRFSNP_004G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CRFSNP_004G_CFG_ITEM_MAX_NUM     ((CRFSNP_004G_CFG_FILE_SIZE >> CRFSNP_ITEM_BIT_SIZE) - (2048*4))

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

typedef struct
{
    const char    *model_str;
    const char    *alias_str;
    UINT32         file_size; /*np file size*/
    uint32_t       item_max_num;
    uint32_t       rsvd;
}CRFSNP_CFG;

#define CRFSNP_CFG_MODEL_STR(crfsnp_cfg)              ((crfsnp_cfg)->model_str)
#define CRFSNP_CFG_ALIAS_STR(crfsnp_cfg)              ((crfsnp_cfg)->alias_str)
#define CRFSNP_CFG_FILE_SIZE(crfsnp_cfg)              ((crfsnp_cfg)->file_size)
#define CRFSNP_CFG_ITEM_MAX_NUM(crfsnp_cfg)           ((crfsnp_cfg)->item_max_num)

#define CRFSNP_ERR_MODEL             ((uint32_t)0xF)  /*4 bits*/

#define CRFSNP_O_RDONLY              ((uint32_t)O_RDONLY)
#define CRFSNP_O_WRONLY              ((uint32_t)O_WRONLY)
#define CRFSNP_O_RDWR                ((uint32_t)O_RDWR  )
#define CRFSNP_O_CREATE              ((uint32_t)O_CREAT )

/*bitmap*/
#define CRFSNP_STATE_NOT_DIRTY       ((uint8_t)0x00)
#define CRFSNP_STATE_DIRTY           ((uint8_t)0x01)

#define CRFSNP_PATH_LAYOUT_DIR0_NBITS    ( 8)
#define CRFSNP_PATH_LAYOUT_DIR1_NBITS    ( 8)
#define CRFSNP_PATH_LAYOUT_DIR2_NBITS    ( 8)
#define CRFSNP_PATH_LAYOUT_DIR3_NBITS    ( 8)

#define CRFSNP_PATH_LAYOUT_DIR0_ABITS    (24) /*bit alignment*/
#define CRFSNP_PATH_LAYOUT_DIR1_ABITS    (16) /*bit alignment*/
#define CRFSNP_PATH_LAYOUT_DIR2_ABITS    ( 8) /*bit alignment*/
#define CRFSNP_PATH_LAYOUT_DIR3_ABITS    ( 0) /*bit alignment*/

#define CRFSNP_PATH_LAYOUT_DIR0_MASK     (((UINT32)(UINT32_ONE << CRFSNP_PATH_LAYOUT_DIR0_NBITS)) - 1)
#define CRFSNP_PATH_LAYOUT_DIR1_MASK     (((UINT32)(UINT32_ONE << CRFSNP_PATH_LAYOUT_DIR1_NBITS)) - 1)
#define CRFSNP_PATH_LAYOUT_DIR2_MASK     (((UINT32)(UINT32_ONE << CRFSNP_PATH_LAYOUT_DIR2_NBITS)) - 1)
#define CRFSNP_PATH_LAYOUT_DIR3_MASK     (((UINT32)(UINT32_ONE << CRFSNP_PATH_LAYOUT_DIR3_NBITS)) - 1)

#define CRFSNP_PATH_LAYOUT_DIR0_NO(path_id)     (((path_id) >> CRFSNP_PATH_LAYOUT_DIR0_ABITS) & CRFSNP_PATH_LAYOUT_DIR0_MASK)
#define CRFSNP_PATH_LAYOUT_DIR1_NO(path_id)     (((path_id) >> CRFSNP_PATH_LAYOUT_DIR1_ABITS) & CRFSNP_PATH_LAYOUT_DIR1_MASK)
#define CRFSNP_PATH_LAYOUT_DIR2_NO(path_id)     (((path_id) >> CRFSNP_PATH_LAYOUT_DIR2_ABITS) & CRFSNP_PATH_LAYOUT_DIR2_MASK)
#define CRFSNP_PATH_LAYOUT_DIR3_NO(path_id)     (((path_id) >> CRFSNP_PATH_LAYOUT_DIR3_ABITS) & CRFSNP_PATH_LAYOUT_DIR3_MASK)

#define CRFSNP_ERR_ID                     ((uint32_t)0xFFFFFFFF)


/**********************************************************************************************************************************************************************
*
* np_id | model | rsvd1 | algo_1st | algo_2nd | del max_num | del cur_num | del bitmap | pad_a | pad_b | node_max_num | node_used_num | node_sizeof | free_head | items
* |<----------------- 16 B <----------------------------------------------|
* |<---------------------------------1 MB ---------------------------------------------------->|
*                                                                                              |<-------------------------------1 MB -------------------------->|
***********************************************************************************************************************************************************************/
/*each np own one header*/
typedef struct
{
    /*8B*/
    uint32_t            np_id;               /*crfsnp id              */
    uint8_t             model;               /*crfsnp model           */
    uint8_t             rsvd1;
    uint8_t             rsvd2 ;
    uint8_t             chash_algo_2nd_id;   /*second hash algo func id: used to compute crfsnprb_node hash data*/

    uint8_t             pad_a[ (1 << CRFSNP_ITEM_BIT_SIZE) - 8 - 16 ]; /*pad the first part to 1 MB*/

    CRFSNPRB_POOL       pool;                /*pool of CRFSNP_ITEM, CRFSNP_ITEM head must be CRFSNPRB_NODE*/
} CRFSNP_HEADER;

#define CRFSNP_HEADER_NP_ID(crfsnp_header)                      ((crfsnp_header)->np_id)
#define CRFSNP_HEADER_MODEL(crfsnp_header)                      ((crfsnp_header)->model)

#define CRFSNP_HEADER_2ND_CHASH_ALGO_ID(crfsnp_header)          ((crfsnp_header)->chash_algo_2nd_id)

#define CRFSNP_HEADER_ITEMS_POOL(crfsnp_header)         (&((crfsnp_header)->pool))
#define CRFSNP_HEADER_ITEMS_MAX_NUM(crfsnp_header)      (CRFSNPRB_POOL_NODE_MAX_NUM(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header)))
#define CRFSNP_HEADER_ITEMS_USED_NUM(crfsnp_header)     (CRFSNPRB_POOL_NODE_USED_NUM(CRFSNP_HEADER_ITEMS_POOL(crfsnp_header)))

typedef struct
{
    int              fd;         /* rfs namespace fd  */
    uint32_t         rsvd;

    UINT32           fsize;

    uint8_t         *fname;

    uint64_t         del_size;     /* deleted but not recycled bytes*/
    uint64_t         recycle_size; /* recycled bytes*/

    CRFSNP_HEADER   *header;       /* hashdb header */

    /*shortcut of lru list which point to root rb node */
    CRFSNPLRU_NODE  *lru_list; /*the lastest access node is at head covering fnode only*/

    /*shortcut of del list which point to root rb node */
    CRFSNPDEL_NODE  *del_list; /*the deleted but not recycled nodes are in covering fnode and dnode*/

    CHASH_ALGO       chash_algo_2nd;       /* hash algo for rbtree in the hash bucket: used to compute crfsnprb_node hash data*/

} CRFSNP;

#define CRFSNP_FD(crfsnp)                     ((crfsnp)->fd)
#define CRFSNP_FSIZE(crfsnp)                  ((crfsnp)->fsize)
#define CRFSNP_FNAME(crfsnp)                  ((crfsnp)->fname)
#define CRFSNP_DEL_SIZE(crfsnp)               ((crfsnp)->del_size)
#define CRFSNP_RECYCLE_SIZE(crfsnp)           ((crfsnp)->recycle_size)
#define CRFSNP_HDR(crfsnp)                    ((crfsnp)->header)

#define CRFSNP_LRU_LIST(crfsnp)               ((crfsnp)->lru_list)
#define CRFSNP_DEL_LIST(crfsnp)               ((crfsnp)->del_list)

#define CRFSNP_2ND_CHASH_ALGO(crfsnp)         ((crfsnp)->chash_algo_2nd)

#define CRFSNP_ID(crfsnp)                     (CRFSNP_HEADER_NP_ID(CRFSNP_HDR(crfsnp)))
#define CRFSNP_MODEL(crfsnp)                  (CRFSNP_HEADER_MODEL(CRFSNP_HDR(crfsnp)))
#define CRFSNP_SECOND_CHASH_ALGO_ID(crfsnp)   (CRFSNP_HEADER_2ND_CHASH_ALGO_ID(CRFSNP_HDR(crfsnp)))

#define CRFSNP_ITEMS_POOL(crfsnp)             (CRFSNP_HEADER_ITEMS_POOL(CRFSNP_HDR(crfsnp)))
#define CRFSNP_ITEMS_MAX_NUM(crfsnp)          (CRFSNPRB_POOL_NODE_MAX_NUM(CRFSNP_ITEMS_POOL(crfsnp)))
#define CRFSNP_ITEMS_USED_NUM(crfsnp)         (CRFSNPRB_POOL_NODE_USED_NUM(CRFSNP_ITEMS_POOL(crfsnp)))

#define CRFSNP_2ND_CHASH_ALGO_COMPUTE(crfsnp, klen, key)  (CRFSNP_2ND_CHASH_ALGO(crfsnp)(klen, key))

typedef EC_BOOL (*CRFSNP_RECYCLE_DN_FUNC)(const UINT32, const CRFSNP_FNODE *);

typedef struct
{
    UINT32 arg1;

    CRFSNP_RECYCLE_DN_FUNC recycle_dn;
}CRFSNP_RECYCLE_DN;

#define CRFSNP_RECYCLE_DN_ARG1(crfsnp_recycle_dn)      ((crfsnp_recycle_dn)->arg1)
#define CRFSNP_RECYCLE_DN_FUNC(crfsnp_recycle_dn)      ((crfsnp_recycle_dn)->recycle_dn)

typedef EC_BOOL (*CRFSNP_RECYCLE_NP_FUNC)(const UINT32, const uint32_t);
typedef struct
{
    UINT32 arg1;

    CRFSNP_RECYCLE_NP_FUNC recycle_np;
}CRFSNP_RECYCLE_NP;

#define CRFSNP_RECYCLE_NP_ARG1(crfsnp_recycle_np)      ((crfsnp_recycle_np)->arg1)
#define CRFSNP_RECYCLE_NP_FUNC(crfsnp_recycle_np)      ((crfsnp_recycle_np)->recycle_np)

/*np iterator when walkthrough directory*/
#define CRFSNP_DIT_ARGS_MAX_NUM  ((UINT32)4)
typedef struct _CRFSNP_DIT_NODE
{
    EC_BOOL (*handler)(struct _CRFSNP_DIT_NODE *, CRFSNP *, CRFSNP_ITEM *, const uint32_t);
    CSTACK  crfsnp_item_stack;
    void *args[ CRFSNP_DIT_ARGS_MAX_NUM ];
}CRFSNP_DIT_NODE;

#define CRFSNP_DIT_NODE_HANDLER(crfsnp_dit_node)        ((crfsnp_dit_node)->handler)
#define CRFSNP_DIT_NODE_STACK(crfsnp_dit_node)          (&((crfsnp_dit_node)->crfsnp_item_stack))
#define CRFSNP_DIT_NODE_ARGS(crfsnp_dit_node)           ((crfsnp_dit_node)->args)
#define CRFSNP_DIT_NODE_ARG(crfsnp_dit_node, idx)       ((crfsnp_dit_node)->args[ (idx) ])

#endif/* _CRFSNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

