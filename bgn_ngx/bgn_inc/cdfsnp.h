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

#ifndef _CDFSNP_H
#define _CDFSNP_H

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

#define CDFSNP_KEY_MAX_SIZE             (  40)  /*max len of file or dir seg name*/

#define CDFSNP_DIR_FILE_MAX_NUM         ((UINT32)1024)  /*each directory support up to 1024 directories and regular files*/

#define CDFSNP_NAME_MAX_SIZE            ( 256)  /*max len of /$(cdfsnp_db_root_dir)/$(dir0)/$(dir1)/$(dir2)/$(dir3)*/

#define CDFSNP_CMUTEX_MAX_NUM           ( 256)  /*max cmutex num*/

#if (32 == WORDSIZE)
#define CDFSNP_FILE_REPLICA_MAX_NUM     (   4)  /*max num of supported replicas up to*/
#define CDFSNP_DIR_BUCKET_MAX_NUM       (  12)  /*CDFSNP_DIR_BUCKET_MAX_NUM = 3 * CDFSNP_FILE_REPLICA_MAX_NUM    */
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
#define CDFSNP_FILE_REPLICA_MAX_NUM     (   3)  /*max num of supported replicas up to*/
#define CDFSNP_DIR_BUCKET_MAX_NUM       (  12)  /*CDFSNP_DIR_BUCKET_MAX_NUM = 3 * CDFSNP_FILE_REPLICA_MAX_NUM    */
#endif/*(64 == WORDSIZE)*/

#define CDFSNP_ITEM_REF_MAX_NUM         ((UINT32) 0xF)/*4 bits*/

#define CDFSNP_WRITE_ONCE_MAX_BYTES     ((UINT32)0x7FFFF000)/*2GB - 4KB*/
#define CDFSNP_READ_ONCE_MAX_BYTES      ((UINT32)0x7FFFF000)/*2GB - 4KB*/

#define CDFSNP_32BIT_MASK               ((UINT32)0xFFFFFFFF)

#define CDFSNP_ERR_PATH                 ((UINT32)0xFFFFFFFF)/*error path layout*/
#define CDFSNP_ERR_FOFF                 ((UINT32)0xFFFFFFFF)/*error file offset*/

#define CDFSNP_ITEM_ERR_OFFSET          ((UINT32)0xFFFFFFFF)/*error item offset*/

#define CDFSNP_ITEM_FILE_IS_PIP         ((UINT32) 0x1)  /*pipe file   */
#define CDFSNP_ITEM_FILE_IS_DIR         ((UINT32) 0x2)  /*directory   */
#define CDFSNP_ITEM_FILE_IS_LNK         ((UINT32) 0x3)  /*link file   */
#define CDFSNP_ITEM_FILE_IS_REG         ((UINT32) 0x4)  /*regular file*/
#define CDFSNP_ITEM_FILE_IS_SCK         ((UINT32) 0x5)  /*socket file */
#define CDFSNP_ITEM_FILE_IS_CHR         ((UINT32) 0x6)  /*char device */
#define CDFSNP_ITEM_FILE_IS_BLK         ((UINT32) 0x7)  /*block device*/
#define CDFSNP_ITEM_FILE_IS_ANY         ((UINT32) 0x8)  /*any file    */
#define CDFSNP_ITEM_FILE_IS_ERR         ((UINT32) 0x0)  /*4 bits      */

#define CDFSNP_ITEM_STAT_IS_NOT_USED    ((UINT32) 0x1)
#define CDFSNP_ITEM_STAT_IS_FLUSHED     ((UINT32) 0x2)
#define CDFSNP_ITEM_STAT_IS_CACHED      ((UINT32) 0x4)
#define CDFSNP_ITEM_STAT_IS_ERR         ((UINT32) 0x0) /*4 bits*/

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

#define CDFSNP_PERMISSION_UID_BIT_MASK  ((UINT32) 04000)
#define CDFSNP_PERMISSION_GID_BIT_MASK  ((UINT32) 02000)
#define CDFSNP_PERMISSION_STK_BIT_MASK  ((UINT32) 01000)
#define CDFSNP_PERMISSION_USR_BIT_MASK  ((UINT32) 00700)
#define CDFSNP_PERMISSION_GRP_BIT_MASK  ((UINT32) 00070)
#define CDFSNP_PERMISSION_OTH_BIT_MASK  ((UINT32) 00007)

#define CDFSNP_PERMISSION_UID_NBITS     ((UINT32)  1)    /*num of bits*/
#define CDFSNP_PERMISSION_GID_NBITS     ((UINT32)  1)    /*num of bits*/
#define CDFSNP_PERMISSION_STK_NBITS     ((UINT32)  1)    /*num of bits*/
#define CDFSNP_PERMISSION_USR_NBITS     ((UINT32)  3)    /*num of bits*/
#define CDFSNP_PERMISSION_GRP_NBITS     ((UINT32)  3)    /*num of bits*/
#define CDFSNP_PERMISSION_OTH_NBITS     ((UINT32)  3)    /*num of bits*/

#define CDFSNP_PERMISSION_UID_ABITS     ((UINT32) 11)    /*bit alignment*/
#define CDFSNP_PERMISSION_GID_ABITS     ((UINT32) 10)    /*bit alignment*/
#define CDFSNP_PERMISSION_STK_ABITS     ((UINT32)  9)    /*bit alignment*/
#define CDFSNP_PERMISSION_USR_ABITS     ((UINT32)  6)    /*bit alignment*/
#define CDFSNP_PERMISSION_GRP_ABITS     ((UINT32)  3)    /*bit alignment*/
#define CDFSNP_PERMISSION_OTH_ABITS     ((UINT32)  0)    /*bit alignment*/

typedef struct
{
    UINT32      datanode_tcid;       /*remote datanode*/
    UINT32      path_layout:32;      /*remote full path layout. bitmap: 2bits - disk layout, 10bits - level 1 dir, 10bits - leve 2 dir, 10bits - level 3 dir*/
    UINT32      file_offset:32;      /*file offset in the full path. note full path point to a regular data file but not directory*/
}CDFSNP_INODE;

#define CDFSNP_INODE_TCID(cdfsnp_inode)           ((cdfsnp_inode)->datanode_tcid)
#define CDFSNP_INODE_PATH(cdfsnp_inode)           ((cdfsnp_inode)->path_layout)
#define CDFSNP_INODE_FOFF(cdfsnp_inode)           ((cdfsnp_inode)->file_offset)

#define CDFSNP_FNODE_IS_NOT_TRUNCATED             ((UINT32) 0)
#define CDFSNP_FNODE_IS_TRUNCATED                 ((UINT32) 1)

typedef struct
{
    UINT32        next_offset     :32;/*see CDFSNP_RNODE*/
    UINT32        file_size       :26;/*data/value length < 64M = 2^26B*/
    UINT32        rsvd1           :3;
    UINT32        file_replica_num:3;

    UINT32        trunc_flag      :1; /*when file is truncated, the first word in file must be the real file size*/
    UINT32        rsvd2           :5;
    UINT32        actual_fsize    :26;/*when trunc_flag is set, here is the actual file size*/
    UINT32        rsvd3           :32;

    CDFSNP_INODE  inodes[ CDFSNP_FILE_REPLICA_MAX_NUM ];
}CDFSNP_FNODE;

#define CDFSNP_FNODE_ROFF(cdfsnp_fnode)          ((cdfsnp_fnode)->next_offset)
#define CDFSNP_FNODE_FILESZ(cdfsnp_fnode)        ((cdfsnp_fnode)->file_size)
#define CDFSNP_FNODE_REPNUM(cdfsnp_fnode)        ((cdfsnp_fnode)->file_replica_num)
#define CDFSNP_FNODE_TRUNCF(cdfsnp_fnode)        ((cdfsnp_fnode)->trunc_flag)
#define CDFSNP_FNODE_ACTFSZ(cdfsnp_fnode)        ((cdfsnp_fnode)->actual_fsize)
#define CDFSNP_FNODE_INODES(cdfsnp_fnode)        ((cdfsnp_fnode)->inodes)
#define CDFSNP_FNODE_INODE(cdfsnp_fnode, idx)    (&((cdfsnp_fnode)->inodes[ (idx) ]))

#define CDFSNP_FNODE_INODE_TCID(cdfsnp_fnode, idx)  CDFSNP_INODE_TCID(CDFSNP_FNODE_INODE(cdfsnp_fnode, idx))
#define CDFSNP_FNODE_INODE_PATH(cdfsnp_fnode, idx)  CDFSNP_INODE_PATH(CDFSNP_FNODE_INODE(cdfsnp_fnode, idx))
#define CDFSNP_FNODE_INODE_FOFF(cdfsnp_fnode, idx)  CDFSNP_INODE_FOFF(CDFSNP_FNODE_INODE(cdfsnp_fnode, idx))

#if (32 == WORDSIZE)
typedef UINT32    CDFSNP_BUCKET;
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
typedef UINT32FIXED    CDFSNP_BUCKET;
#endif/*(64 == WORDSIZE)*/

typedef struct
{
    UINT32               next_offset:32;/*see CDFSNP_RNODE*/
    UINT32               file_num:32; /*number of files under this directory*/
    CDFSNP_BUCKET        dir_buckets[ CDFSNP_DIR_BUCKET_MAX_NUM ];
}CDFSNP_DNODE;

#define CDFSNP_DNODE_ROFF(cdfsnp_dnode)             ((cdfsnp_dnode)->next_offset)
#define CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode)         ((cdfsnp_dnode)->file_num)
#define CDFSNP_DNODE_DIR_BUCKETS(cdfsnp_dnode)      ((cdfsnp_dnode)->dir_buckets)
#define CDFSNP_DNODE_DIR_BUCKET(cdfsnp_dnode, idx)  ((cdfsnp_dnode)->dir_buckets[ (idx) ])

#define CDFSNP_BUCKET_POS(second_hash)                      ((second_hash) % CDFSNP_DIR_BUCKET_MAX_NUM)
#define CDFSNP_BUCKET_FETCH(cdfsnp_buckets, second_hash)    (((CDFSNP_BUCKET *)cdfsnp_buckets) + CDFSNP_BUCKET_POS(second_hash))

#define CDFSNP_DNODE_IS_FULL(cdfsnp_dnode)                  (CDFSNP_DIR_FILE_MAX_NUM <= CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode))

/**/
typedef struct
{
    UINT32               next_offset:32;/*next unused cdfsnp_item offset*/
    UINT32               rsvd:32;
}CDFSNP_RNODE;

#define CDFSNP_RNODE_NEXT_OFFSET(cdfsnp_rnode)      ((cdfsnp_rnode)->next_offset)

typedef struct
{
    UINT32      item_stat:4;  /* item status: not used, flushed, or cached */
    UINT32      ref_num  :4;  /* num of reference to this item, range [0..CDFSNP_ITEM_REF_MAX_NUM]*/
    UINT32      key_len  :8;  /* key lenght, range [0..CDFSNP_KEY_MAX_SIZE] */
    UINT32      dir_flag :4;  /* directory or regular file */
    UINT32      set_uid  :1;  /* set uid bit*/
    UINT32      set_gid  :1;  /* set gid bit*/
    UINT32      sticky   :1;  /* sticky bit*/
    UINT32      owner_per:3;  /* owner permission*/
    UINT32      group_per:3;  /* group permission*/
    UINT32      other_per:3;  /* other permission*/

    UINT32      gid:16;
    UINT32      uid:16;

    CTIMET      time; /*file created or modified time. 32 bits for 32bit OS, 64 bits for 64bit OS*/
    UINT8       key[ CDFSNP_KEY_MAX_SIZE ];  /* dir name or file name */

    UINT32      parent_offset    :32;   /*point to parent directory*/
    UINT32      shash_next_offset:32;   /*point to next file or directory in the same bucket.*/

    union
    {
          CDFSNP_FNODE fnode;
          CDFSNP_DNODE dnode;
          CDFSNP_RNODE rnode;
    }u;
} CDFSNP_ITEM;


#define CDFSNP_ITEM_DFLG(cdfsnp_item)             ((cdfsnp_item)->dir_flag)
#define CDFSNP_ITEM_STAT(cdfsnp_item)             ((cdfsnp_item)->item_stat)
#define CDFSNP_ITEM_KLEN(cdfsnp_item)             ((cdfsnp_item)->key_len)
#define CDFSNP_ITEM_KEY(cdfsnp_item)              ((cdfsnp_item)->key)
#define CDFSNP_ITEM_PARENT(cdfsnp_item)           ((cdfsnp_item)->parent_offset)
#define CDFSNP_ITEM_SHASH_NEXT(cdfsnp_item)       ((cdfsnp_item)->shash_next_offset)
#define CDFSNP_ITEM_FNODE(cdfsnp_item)            (&((cdfsnp_item)->u.fnode))
#define CDFSNP_ITEM_DNODE(cdfsnp_item)            (&((cdfsnp_item)->u.dnode))
#define CDFSNP_ITEM_RNODE(cdfsnp_item)            (&((cdfsnp_item)->u.rnode))

#define CDFSNP_ITEM_ROFF(cdfsnp_item)             (CDFSNP_RNODE_NEXT_OFFSET(CDFSNP_ITEM_RNODE(cdfsnp_item)))

/*item max num = file size / sizeof(CDFSNP_ITEM) where sizeof(CDFSNP_ITEM) = 128B = 2^7*/
#define CDFSNP_4K_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 12))
#define CDFSNP_4K_CFG_ITEM_MAX_NUM     ((UINT32)(UINT32_ONE <<  5))
#define CDFSNP_4K_CFG_BLOOM_ROW_NUM    ((UINT32)(UINT32_ONE <<  4))
#define CDFSNP_4K_CFG_BLOOM_COL_NUM    ((UINT32)(UINT32_ONE <<  4))

#define CDFSNP_64K_CFG_FILE_SIZE       ((UINT32)(UINT32_ONE << 16))
#define CDFSNP_64K_CFG_ITEM_MAX_NUM    ((UINT32)(UINT32_ONE <<  9))
#define CDFSNP_64K_CFG_BLOOM_ROW_NUM   ((UINT32)(UINT32_ONE <<  5))
#define CDFSNP_64K_CFG_BLOOM_COL_NUM   ((UINT32)(UINT32_ONE <<  4))

#define CDFSNP_1M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 20))
#define CDFSNP_1M_CFG_ITEM_MAX_NUM     ((UINT32)(UINT32_ONE << 13))
#define CDFSNP_1M_CFG_BLOOM_ROW_NUM    ((UINT32)(UINT32_ONE <<  7))
#define CDFSNP_1M_CFG_BLOOM_COL_NUM    ((UINT32)(UINT32_ONE <<  6))

#define CDFSNP_2M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 21))
#define CDFSNP_2M_CFG_ITEM_MAX_NUM     ((UINT32)(UINT32_ONE << 14))
#define CDFSNP_2M_CFG_BLOOM_ROW_NUM    ((UINT32)(UINT32_ONE <<  7))
#define CDFSNP_2M_CFG_BLOOM_COL_NUM    ((UINT32)(UINT32_ONE <<  7))

#define CDFSNP_128M_CFG_FILE_SIZE      ((UINT32)(UINT32_ONE << 27))
#define CDFSNP_128M_CFG_ITEM_MAX_NUM   ((UINT32)(UINT32_ONE << 20))
#define CDFSNP_128M_CFG_BLOOM_ROW_NUM  ((UINT32)(UINT32_ONE << 10))
#define CDFSNP_128M_CFG_BLOOM_COL_NUM  ((UINT32)(UINT32_ONE << 10))

#define CDFSNP_256M_CFG_FILE_SIZE      ((UINT32)(UINT32_ONE << 28))
#define CDFSNP_256M_CFG_ITEM_MAX_NUM   ((UINT32)(UINT32_ONE << 21))
#define CDFSNP_256M_CFG_BLOOM_ROW_NUM  ((UINT32)(UINT32_ONE << 11))
#define CDFSNP_256M_CFG_BLOOM_COL_NUM  ((UINT32)(UINT32_ONE << 11))

#define CDFSNP_512M_CFG_FILE_SIZE      ((UINT32)(UINT32_ONE << 29))
#define CDFSNP_512M_CFG_ITEM_MAX_NUM   ((UINT32)(UINT32_ONE << 22))
#define CDFSNP_512M_CFG_BLOOM_ROW_NUM  ((UINT32)(UINT32_ONE << 11))
#define CDFSNP_512M_CFG_BLOOM_COL_NUM  ((UINT32)(UINT32_ONE << 11))

#define CDFSNP_1G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CDFSNP_1G_CFG_ITEM_MAX_NUM     ((UINT32)(UINT32_ONE << 23))
#define CDFSNP_1G_CFG_BLOOM_ROW_NUM    ((UINT32)(UINT32_ONE << 12))
#define CDFSNP_1G_CFG_BLOOM_COL_NUM    ((UINT32)(UINT32_ONE << 11))

#define CDFSNP_2G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 31))
#define CDFSNP_2G_CFG_ITEM_MAX_NUM     ((UINT32)(UINT32_ONE << 24))
#define CDFSNP_2G_CFG_BLOOM_ROW_NUM    ((UINT32)(UINT32_ONE << 12))
#define CDFSNP_2G_CFG_BLOOM_COL_NUM    ((UINT32)(UINT32_ONE << 12))

#if (64 == WORDSIZE)
#define CDFSNP_4G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 32))
#define CDFSNP_4G_CFG_ITEM_MAX_NUM     ((UINT32)(UINT32_ONE << 25))
#define CDFSNP_4G_CFG_BLOOM_ROW_NUM    ((UINT32)(UINT32_ONE << 13))
#define CDFSNP_4G_CFG_BLOOM_COL_NUM    ((UINT32)(UINT32_ONE << 13))

/*due to offset is defined as 32bit integer, here cannot support more than 4G file*/
#endif/*(64 == WORDSIZE)*/

#define CDFSNP_4K_MODE               ((UINT32) 0)   /*item max num = 2^12/2^7=2^5 =        32*/
#define CDFSNP_64K_MODE              ((UINT32) 1)   /*item max num = 2^16/2^7=2^9 =       512*/
#define CDFSNP_1M_MODE               ((UINT32) 2)   /*item max num = 2^20/2^7=2^13=     8 192*/
#define CDFSNP_2M_MODE               ((UINT32) 3)   /*item max num = 2^21/2^7=2^14=    16 384*/
#define CDFSNP_128M_MODE             ((UINT32) 4)   /*item max num = 2^27/2^7=2^20= 1 048 576*/
#define CDFSNP_256M_MODE             ((UINT32) 5)   /*item max num = 2^28/2^7=2^21= 2 097 152*/
#define CDFSNP_512M_MODE             ((UINT32) 6)   /*item max num = 2^29/2^7=2^22= 4 194 304*/
#define CDFSNP_1G_MODE               ((UINT32) 7)   /*item max num = 2^30/2^7=2^23= 8 388 608*/
#define CDFSNP_2G_MODE               ((UINT32) 8)   /*item max num = 2^31/2^7=2^24=16 777 216*/

#if (64 == WORDSIZE)
#define CDFSNP_4G_MODE               ((UINT32) 9)   /*item max num = 2^32/2^7=2^25=33 554 432*/
#endif/*(64 == WORDSIZE)*/

#define CDFSNP_ERR_MODE              ((UINT32)0xF)  /*4 bits*/

#define CDFSNP_O_RDONLY              ((UINT32)O_RDONLY)
#define CDFSNP_O_WRONLY              ((UINT32)O_WRONLY)
#define CDFSNP_O_RDWR                ((UINT32)O_RDWR  )
#define CDFSNP_O_CREATE              ((UINT32)O_CREAT )

/*bitmap*/
#define CDFSNP_STATE_RDONLY          ((UINT32)0x01)
#define CDFSNP_STATE_RDWR            ((UINT32)0x02)
#define CDFSNP_STATE_UPDATED         ((UINT32)0x04)
#define CDFSNP_STATE_CACHED          ((UINT32)0x08)
#define CDFSNP_STATE_LOADING         ((UINT32)0x10)
#define CDFSNP_STATE_MASK            ((UINT32)0xFF)/*8 bits*/
#define CDFSNP_STATE_ERR             ((UINT32)0x00)/*8 bits*/

#define CDFSNP_PATH_LAYOUT_DIR0_NBITS    ( 8)
#define CDFSNP_PATH_LAYOUT_DIR1_NBITS    ( 8)
#define CDFSNP_PATH_LAYOUT_DIR2_NBITS    ( 8)
#define CDFSNP_PATH_LAYOUT_DIR3_NBITS    ( 8)

#define CDFSNP_PATH_LAYOUT_DIR0_ABITS    (24) /*bit alignment*/
#define CDFSNP_PATH_LAYOUT_DIR1_ABITS    (16) /*bit alignment*/
#define CDFSNP_PATH_LAYOUT_DIR2_ABITS    ( 8) /*bit alignment*/
#define CDFSNP_PATH_LAYOUT_DIR3_ABITS    ( 0) /*bit alignment*/

#define CDFSNP_PATH_LAYOUT_DIR0_MASK     (((UINT32)(UINT32_ONE << CDFSNP_PATH_LAYOUT_DIR0_NBITS)) - 1)
#define CDFSNP_PATH_LAYOUT_DIR1_MASK     (((UINT32)(UINT32_ONE << CDFSNP_PATH_LAYOUT_DIR1_NBITS)) - 1)
#define CDFSNP_PATH_LAYOUT_DIR2_MASK     (((UINT32)(UINT32_ONE << CDFSNP_PATH_LAYOUT_DIR2_NBITS)) - 1)
#define CDFSNP_PATH_LAYOUT_DIR3_MASK     (((UINT32)(UINT32_ONE << CDFSNP_PATH_LAYOUT_DIR3_NBITS)) - 1)

#define CDFSNP_PATH_LAYOUT_DIR0_NO(path_id)     (((path_id) >> CDFSNP_PATH_LAYOUT_DIR0_ABITS) & CDFSNP_PATH_LAYOUT_DIR0_MASK)
#define CDFSNP_PATH_LAYOUT_DIR1_NO(path_id)     (((path_id) >> CDFSNP_PATH_LAYOUT_DIR1_ABITS) & CDFSNP_PATH_LAYOUT_DIR1_MASK)
#define CDFSNP_PATH_LAYOUT_DIR2_NO(path_id)     (((path_id) >> CDFSNP_PATH_LAYOUT_DIR2_ABITS) & CDFSNP_PATH_LAYOUT_DIR2_MASK)
#define CDFSNP_PATH_LAYOUT_DIR3_NO(path_id)     (((path_id) >> CDFSNP_PATH_LAYOUT_DIR3_ABITS) & CDFSNP_PATH_LAYOUT_DIR3_MASK)

typedef struct
{
    char * mode_str;
    UINT32 file_size;
    UINT32 item_max_num;
    UINT32 bloom_row_num;
    UINT32 bloom_col_num;
}CDFSNP_CFG;

#define CDFSNP_CFG_MOD_STR(cdfsnp_cfg)                ((cdfsnp_cfg)->mode_str)
#define CDFSNP_CFG_FILE_SIZE(cdfsnp_cfg)              ((cdfsnp_cfg)->file_size)
#define CDFSNP_CFG_ITEM_MAX_NUM(cdfsnp_cfg)           ((cdfsnp_cfg)->item_max_num)
#define CDFSNP_CFG_BLOOM_ROW_NUM(cdfsnp_cfg)          ((cdfsnp_cfg)->bloom_row_num)
#define CDFSNP_CFG_BLOOM_COL_NUM(cdfsnp_cfg)          ((cdfsnp_cfg)->bloom_col_num)


/*each np own one header*/
typedef struct
{
    UINT32      state;        /*cdfsnp state              */
    UINT32      file_size;    /*total file size           */
    UINT32      item_max_num:32; /*max supported num of items*/
    UINT32      item_cur_num:32; /*current num of items      */

    UINT32      bloom_row_num:16;/*row num of bloom          */
    UINT32      bloom_col_num:16;/*col num of bloom          */

    UINT32      free_offset         :32; /*the first free cdfsnp_item offset */
    UINT32      disk_max_num        :16; /*config max disk num, should same as that of CDFSNP_MGR_CFG*/
    UINT32      chash_algo_first_id :8;  /*first hash algo func id*/
    UINT32      chash_algo_second_id:8;  /*first hash algo func id*/
} CDFSNP_HEADER;

#define CDFSNP_HEADER_STATE(cdfsnp_header)         ((cdfsnp_header)->state)
#define CDFSNP_HEADER_FSIZE(cdfsnp_header)         ((cdfsnp_header)->file_size)
#define CDFSNP_HEADER_IMNUM(cdfsnp_header)         ((cdfsnp_header)->item_max_num)
#define CDFSNP_HEADER_ICNUM(cdfsnp_header)         ((cdfsnp_header)->item_cur_num)
#define CDFSNP_HEADER_BMROW(cdfsnp_header)         ((cdfsnp_header)->bloom_row_num)
#define CDFSNP_HEADER_BMCOL(cdfsnp_header)         ((cdfsnp_header)->bloom_col_num)
#define CDFSNP_HEADER_ROFF(cdfsnp_header)          ((cdfsnp_header)->free_offset)

#define CDFSNP_HEADER_IS_FULL(cdfsnp_header)       (CDFSNP_HEADER_IMNUM(cdfsnp_header) <= CDFSNP_HEADER_ICNUM(cdfsnp_header))
#define CDFSNP_HEADER_IS_EMPTY(cdfsnp_header)      (0 == CDFSNP_HEADER_ICNUM(cdfsnp_header))

#define CDFSNP_HEADER_DISK_MAX_NUM(cdfsnp_header)  ((cdfsnp_header)->disk_max_num)

#define CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(cdfsnp_header)  ((cdfsnp_header)->chash_algo_first_id)
#define CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(cdfsnp_header) ((cdfsnp_header)->chash_algo_second_id)

typedef struct
{
    UINT32           path_layout;

    UINT32           reader_num:32; /* current reader num*/
    int              fd:32;         /* dfs namespace fd  */

    CDFSNP_HEADER   *header;        /* hashdb header */
    CBLOOM          *cbloom;        /* bloom filter  */
    CDFSNP_ITEM     *items;
    CMUTEX           cmutex;        /* bucket cmutexs*/

    CHASH_ALGO       chash_algo_first;        /* hash algo for hash bucket              */
    CHASH_ALGO       chash_algo_second;       /* hash algo for btree in the hash bucket */

    UINT32           base_buff_len;
    UINT8 *          base_buff;
} CDFSNP;

#define CDFSNP_PATH_LAYOUT(cdfsnp)            ((cdfsnp)->path_layout)
#define CDFSNP_READER_NUM(cdfsnp)             ((cdfsnp)->reader_num)
#define CDFSNP_FD(cdfsnp)                     ((cdfsnp)->fd)
#define CDFSNP_HDR(cdfsnp)                    ((cdfsnp)->header)
#define CDFSNP_CBLOOM(cdfsnp)                 ((cdfsnp)->cbloom)
#define CDFSNP_ITEM_VEC(cdfsnp)               ((cdfsnp)->items)
#define CDFSNP_CMUTEX(cdfsnp)                 (&((cdfsnp)->cmutex))
#define CDFSNP_FIRST_CHASH_ALGO(cdfsnp)       ((cdfsnp)->chash_algo_first)
#define CDFSNP_SECOND_CHASH_ALGO(cdfsnp)      ((cdfsnp)->chash_algo_second)
#define CDFSNP_BASE_BUFF(cdfsnp)              ((cdfsnp)->base_buff)
#define CDFSNP_BASE_BUFF_LEN(cdfsnp)          ((cdfsnp)->base_buff_len)

#define CDFSNP_INIT_LOCK(cdfsnp, location)    (cmutex_init(CDFSNP_CMUTEX(cdfsnp), CMUTEX_PROCESS_PRIVATE, location))
#define CDFSNP_CLEAN_LOCK(cdfsnp, location)   (cmutex_clean(CDFSNP_CMUTEX(cdfsnp), location))
#define CDFSNP_LOCK(cdfsnp, location)         (cmutex_lock(CDFSNP_CMUTEX(cdfsnp), location))
#define CDFSNP_UNLOCK(cdfsnp, location)       (cmutex_unlock(CDFSNP_CMUTEX(cdfsnp), location))

#define CDFSNP_STATE(cdfsnp)                  (CDFSNP_HEADER_STATE(CDFSNP_HDR(cdfsnp)))
#define CDFSNP_FSIZE(cdfsnp)                  (CDFSNP_HEADER_FSIZE(CDFSNP_HDR(cdfsnp)))
#define CDFSNP_IMNUM(cdfsnp)                  (CDFSNP_HEADER_IMNUM(CDFSNP_HDR(cdfsnp)))
#define CDFSNP_ICNUM(cdfsnp)                  (CDFSNP_HEADER_ICNUM(CDFSNP_HDR(cdfsnp)))
#define CDFSNP_BMROW(cdfsnp)                  (CDFSNP_HEADER_BMROW(CDFSNP_HDR(cdfsnp)))
#define CDFSNP_BMCOL(cdfsnp)                  (CDFSNP_HEADER_BMCOL(CDFSNP_HDR(cdfsnp)))
#define CDFSNP_ROFF(cdfsnp)                   (CDFSNP_HEADER_ROFF(CDFSNP_HDR(cdfsnp)) )

#define CDFSNP_NEXT_OFF(cdfsnp, offset)       (CDFSNP_ITEM_ROFF((CDFSNP_ITEM *)(CDFSNP_BASE_BUFF(cdfsnp) + offset)))

#define CDFSNP_GET_ITEM_OFFSET(cdfsnp, item)  (((UINT8 *)(item)) - CDFSNP_BASE_BUFF(cdfsnp))

#define CDFSNP_DISK_MAX_NUM(cdfsnp)           (CDFSNP_HEADER_DISK_MAX_NUM(CDFSNP_HDR(cdfsnp)))
#define CDFSNP_FIRST_CHASH_ALGO_ID(cdfsnp)    (CDFSNP_HEADER_FIRST_CHASH_ALGO_ID(CDFSNP_HDR(cdfsnp)) )
#define CDFSNP_SECOND_CHASH_ALGO_ID(cdfsnp)   (CDFSNP_HEADER_SECOND_CHASH_ALGO_ID(CDFSNP_HDR(cdfsnp)))

#define CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, klen, key)   (CDFSNP_FIRST_CHASH_ALGO(cdfsnp)(klen, key))
#define CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, klen, key)  (CDFSNP_SECOND_CHASH_ALGO(cdfsnp)(klen, key))

#define CDFSNP_IS_FULL(cdfsnp)                CDFSNP_HEADER_IS_FULL(CDFSNP_HDR(cdfsnp))

#define CDFSNP_BLOOM_ROW_IDX(cdfsnp, first_hash)          ((first_hash) % CDFSNP_BMROW(cdfsnp))
#define CDFSNP_BLOOM_COL_IDX(cdfsnp, second_hash)         ((second_hash) % CDFSNP_BMCOL(cdfsnp))

#define CDFSNP_IS_RDONLY(cdfsnp)         (CDFSNP_STATE(cdfsnp) & CDFSNP_STATE_RDONLY)
#define CDFSNP_IS_RDWR(cdfsnp)           (CDFSNP_STATE(cdfsnp) & CDFSNP_STATE_RDWR)
#define CDFSNP_IS_UPDATED(cdfsnp)        (CDFSNP_STATE(cdfsnp) & CDFSNP_STATE_UPDATED)
#define CDFSNP_IS_CACHED(cdfsnp)         (CDFSNP_STATE(cdfsnp) & CDFSNP_STATE_CACHED)
#define CDFSNP_IS_LOADING(cdfsnp)        (CDFSNP_STATE(cdfsnp) & CDFSNP_STATE_LOADING)
#define CDFSNP_HAS_READER(cdfsnp)        (0 < CDFSNP_READER_NUM(cdfsnp))

#define CDFSNP_IS_NOT_RDONLY(cdfsnp)     (0 == CDFSNP_IS_RDONLY(cdfsnp))
#define CDFSNP_IS_NOT_RDWR(cdfsnp)       (0 == CDFSNP_IS_RDWR(cdfsnp))
#define CDFSNP_IS_NOT_UPDATED(cdfsnp)    (0 == CDFSNP_IS_UPDATED(cdfsnp))
#define CDFSNP_IS_NOT_CACHED(cdfsnp)     (0 == CDFSNP_IS_CACHED(cdfsnp))
#define CDFSNP_NO_READER(cdfsnp)         (0 == CDFSNP_READER_NUM(cdfsnp))

#define CDFSNP_SET_RDONLY(cdfsnp)        (CDFSNP_STATE(cdfsnp) |= CDFSNP_STATE_RDONLY)
#define CDFSNP_SET_RDWR(cdfsnp)          (CDFSNP_STATE(cdfsnp) |= CDFSNP_STATE_RDWR)
#define CDFSNP_SET_UPDATED(cdfsnp)       (CDFSNP_STATE(cdfsnp) |= CDFSNP_STATE_UPDATED)
#define CDFSNP_SET_CACHED(cdfsnp)        (CDFSNP_STATE(cdfsnp) |= CDFSNP_STATE_CACHED)
#define CDFSNP_SET_LOADING(cdfsnp)       (CDFSNP_STATE(cdfsnp) |= CDFSNP_STATE_LOADING)

#define CDFSNP_SET_NOT_RDONLY(cdfsnp)    (CDFSNP_STATE(cdfsnp) &= ((~CDFSNP_STATE_RDONLY ) & CDFSNP_STATE_MASK))
#define CDFSNP_SET_NOT_RDWR(cdfsnp)      (CDFSNP_STATE(cdfsnp) &= ((~CDFSNP_STATE_RDWR   ) & CDFSNP_STATE_MASK))
#define CDFSNP_SET_NOT_UPDATED(cdfsnp)   (CDFSNP_STATE(cdfsnp) &= ((~CDFSNP_STATE_UPDATED) & CDFSNP_STATE_MASK))
#define CDFSNP_SET_NOT_CACHED(cdfsnp)    (CDFSNP_STATE(cdfsnp) &= ((~CDFSNP_STATE_CACHED ) & CDFSNP_STATE_MASK))
#define CDFSNP_SET_NOT_LOADING(cdfsnp)   (CDFSNP_STATE(cdfsnp) &= ((~CDFSNP_STATE_LOADING ) & CDFSNP_STATE_MASK))
#define CDFSNP_SET_NO_READER(cdfsnp)     (CDFSNP_READER_NUM(cdfsnp) = 0)

#define CDFSNP_INC_READER(cdfsnp)        (CDFSNP_READER_NUM(cdfsnp) = (CDFSNP_READER_NUM(cdfsnp) + 1) & CDFSNP_32BIT_MASK)
#define CDFSNP_DEC_READER(cdfsnp)        (CDFSNP_READER_NUM(cdfsnp) = (CDFSNP_READER_NUM(cdfsnp) - 1) & CDFSNP_32BIT_MASK)

#define CDFSNP_INC_READER_WITHOUT_LOCK(cdfsnp, location) do{\
        CDFSNP_READER_NUM(cdfsnp) ++;\
        CDFSNP_READER_NUM(cdfsnp) &= CDFSNP_32BIT_MASK;\
}while(0)

#define CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, location) do{\
        CDFSNP_READER_NUM(cdfsnp) --;\
        CDFSNP_READER_NUM(cdfsnp) &= CDFSNP_32BIT_MASK;\
}while(0)

#define CDFSNP_INC_READER_WITH_LOCK(cdfsnp, location) do{\
        CDFSNP_LOCK(cdfsnp, location);\
        CDFSNP_READER_NUM(cdfsnp) ++;\
        CDFSNP_READER_NUM(cdfsnp) &= CDFSNP_32BIT_MASK;\
        CDFSNP_UNLOCK(cdfsnp, location); \
}while(0)

#define CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, location) do{\
        CDFSNP_LOCK(cdfsnp, location);\
        CDFSNP_READER_NUM(cdfsnp) --;\
        CDFSNP_READER_NUM(cdfsnp) &= CDFSNP_32BIT_MASK;\
        CDFSNP_UNLOCK(cdfsnp, location); \
}while(0)

EC_BOOL cdfsnp_mode_str(const UINT32 cdfsnp_mode, char **mod_str);

UINT32 cdfsnp_mode_get(const char *mod_str);

EC_BOOL cdfsnp_mode_file_size(const UINT32 cdfsnp_mode, UINT32 *file_size);

EC_BOOL cdfsnp_mode_item_max_num(const UINT32 cdfsnp_mode, UINT32 *item_max_num);

EC_BOOL cdfsnp_mode_bloom_row_num(const UINT32 cdfsnp_mode, UINT32 *bloom_row_num);

EC_BOOL cdfsnp_mode_bloom_col_num(const UINT32 cdfsnp_mode, UINT32 *bloom_col_num);

EC_BOOL cdfsnp_inode_init(CDFSNP_INODE *cdfsnp_inode);

EC_BOOL cdfsnp_inode_clean(CDFSNP_INODE *cdfsnp_inode);

EC_BOOL cdfsnp_inode_clone(const CDFSNP_INODE *cdfsnp_inode_src, CDFSNP_INODE *cdfsnp_inode_des);

void    cdfsnp_inode_print(LOG *log, const CDFSNP_INODE *cdfsnp_inode);

void    cdfsnp_inode_log_no_lock(LOG *log, const CDFSNP_INODE *cdfsnp_inode);

CDFSNP_FNODE *cdfsnp_fnode_new();

CDFSNP_FNODE *cdfsnp_fnode_make(const CDFSNP_FNODE *cdfsnp_fnode_src);

EC_BOOL cdfsnp_fnode_init(CDFSNP_FNODE *cdfsnp_fnode);

EC_BOOL cdfsnp_fnode_clean(CDFSNP_FNODE *cdfsnp_fnode);

EC_BOOL cdfsnp_fnode_free(CDFSNP_FNODE *cdfsnp_fnode);

EC_BOOL cdfsnp_fnode_clone(const CDFSNP_FNODE *cdfsnp_fnode_src, CDFSNP_FNODE *cdfsnp_fnode_des);

EC_BOOL cdfsnp_fnode_check_inode_exist(const CDFSNP_INODE *inode, const CDFSNP_FNODE *cdfsnp_fnode);

EC_BOOL cdfsnp_fnode_cmp(const CDFSNP_FNODE *cdfsnp_fnode_1st, const CDFSNP_FNODE *cdfsnp_fnode_2nd);

EC_BOOL cdfsnp_fnode_import(const CDFSNP_FNODE *cdfsnp_fnode_src, CDFSNP_FNODE *cdfsnp_fnode_des);

UINT32  cdfsnp_fnode_count_replica(const CDFSNP_FNODE *cdfsnp_fnode);

void    cdfsnp_fnode_print(LOG *log, const CDFSNP_FNODE *cdfsnp_fnode);

void    cdfsnp_fnode_log_no_lock(LOG *log, const CDFSNP_FNODE *cdfsnp_fnode);

CDFSNP_DNODE *cdfsnp_dnode_new();

EC_BOOL cdfsnp_dnode_init(CDFSNP_DNODE *cdfsnp_dnode);

EC_BOOL cdfsnp_dnode_clean(CDFSNP_DNODE *cdfsnp_dnode);

EC_BOOL cdfsnp_dnode_free(CDFSNP_DNODE *cdfsnp_dnode);

EC_BOOL cdfsnp_dnode_clone(const CDFSNP_DNODE *cdfsnp_dnode_src, CDFSNP_DNODE *cdfsnp_dnode_des);

CDFSNP_ITEM *cdfsnp_item_new();

EC_BOOL cdfsnp_item_init(CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_item_clean(CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_item_clone(const CDFSNP_ITEM *cdfsnp_item_src, CDFSNP_ITEM *cdfsnp_item_des);

EC_BOOL cdfsnp_item_free(CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_item_set_key(CDFSNP_ITEM *cdfsnp_item, const UINT32 klen, const UINT8 *key);

void    cdfsnp_item_print(LOG *log, const CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_item_load(CDFSNP *cdfsnp, const UINT32 offset, CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_item_flush(CDFSNP *cdfsnp, const UINT32 offset, const CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_item_check(const CDFSNP_ITEM *cdfsnp_item, const UINT32 klen, const UINT8 *key);

/**
*   return -1 when (klen, key, second hash); <  cdfsnp item
*   return  1 when (klen, key, second hash); >  cdfsnp item
*   return  0 when (klen, key, second hash); == cdfsnp item
**/
int     cdfsnp_item_cmp(const CDFSNP_ITEM *cdfsnp_item, const UINT32 klen, const UINT8 *key);

void    cdfsnp_bucket_print(LOG *log, const UINT32 *cdfsnp_buckets);

EC_BOOL cdfsnp_bucket_load(CDFSNP *cdfsnp, const UINT32 offset, UINT32 *cdfsnp_buckets);

EC_BOOL cdfsnp_bucket_flush(const CDFSNP *cdfsnp, const UINT32 offset, const UINT32 *cdfsnp_buckets);

EC_BOOL cdfsnp_header_init(CDFSNP_HEADER *cdfsnp_header, const UINT32 disk_max_num, const UINT32 item_max_num, const UINT32 item_cur_num, const UINT32 bloom_row_num, const UINT32 bloom_col_num, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id);

EC_BOOL cdfsnp_header_clone(const CDFSNP_HEADER *cdfsnp_header_src, CDFSNP_HEADER *cdfsnp_header_des);

EC_BOOL cdfsnp_header_clean(CDFSNP_HEADER *cdfsnp_header);

EC_BOOL cdfsnp_header_is_valid(const CDFSNP_HEADER *cdfsnp_header, const UINT32 item_min_num);

EC_BOOL cdfsnp_header_create(CDFSNP_HEADER *cdfsnp_header, const UINT32 cdfsnp_mode, const UINT32 disk_max_num, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id);

EC_BOOL cdfsnp_cbloom_is_set(const CDFSNP *cdfsnp, const UINT32 first_hash, const UINT32 second_hash);

EC_BOOL cdfsnp_cbloom_set(CDFSNP *cdfsnp, const UINT32 first_hash, const UINT32 second_hash);

CDFSNP *cdfsnp_new(const UINT32 cdfsnp_path_layout, const CDFSNP_HEADER *cdfsnp_header, const CBLOOM *cdfsnp_cbloom);

EC_BOOL cdfsnp_init(CDFSNP *cdfsnp, const UINT32 cdfsnp_path_layout, const CDFSNP_HEADER *cdfsnp_header, const CBLOOM *cdfsnp_cbloom);

EC_BOOL cdfsnp_clean(CDFSNP *cdfsnp);

EC_BOOL cdfsnp_swapout(CDFSNP *cdfsnp);

EC_BOOL cdfsnp_free(CDFSNP *cdfsnp);

EC_BOOL cdfsnp_is_full(const CDFSNP *cdfsnp);

void    cdfsnp_print_header(LOG *log, const CDFSNP *cdfsnp);

void    cdfsnp_print_cbloom(LOG *log, const CDFSNP *cdfsnp);

void    cdfsnp_print(LOG *log, const CDFSNP *cdfsnp);

EC_BOOL cdfsnp_buff_flush(const CDFSNP *cdfsnp, const UINT32 offset, const RWSIZE wsize, const UINT8 *buff);

EC_BOOL cdfsnp_buff_load(const CDFSNP *cdfsnp, const UINT32 offset, const RWSIZE rsize, UINT8 *buff);

EC_BOOL cdfsnp_link(CDFSNP *cdfsnp, const UINT32 base_buff_len, const UINT8 *base_buff);

CDFSNP_ITEM *cdfsnp_dnode_find(const CDFSNP *cdfsnp, const CDFSNP_DNODE *cdfsnp_dnode, const UINT32 second_hash, const UINT32 klen, const UINT8 *key);

UINT32 cdfsnp_dnode_search(const CDFSNP *cdfsnp, const CDFSNP_DNODE *cdfsnp_dnode, const UINT32 second_hash, const UINT32 klen, const UINT8 *key);

UINT32 cdfsnp_dnode_insert(CDFSNP *cdfsnp, const UINT32 parent_offset, const UINT32 path_seg_len, const UINT8 *path_seg, const UINT32 path_seg_second_hash, const UINT32 dir_flag, const UINT32 path_len, const UINT8 *path);

CDFSNP_ITEM * cdfsnp_dnode_umount_son(const CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, const UINT32 second_hash, const UINT32 klen, const UINT8 * key);

EC_BOOL cdfsnp_dnode_delete_one_bucket(const CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, const UINT32 bucket_pos, CVECTOR *cdfsnp_fnode_vec);

EC_BOOL cdfsnp_dnode_delete_dir_son(const CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, CVECTOR *cdfsnp_fnode_vec);

CDFSNP_ITEM *cdfsnp_item_parent(const CDFSNP *cdfsnp, const CDFSNP_ITEM *cdfsnp_item);

EC_BOOL cdfsnp_check_cbloom(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path);

UINT32 cdfsnp_search_with_hash_no_lock(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag, const UINT32 first_hash, const UINT32 second_hash);

UINT32 cdfsnp_search_no_lock(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag);

UINT32 cdfsnp_search(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag);

UINT32 cdfsnp_insert(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag);

CDFSNP_ITEM *cdfsnp_fetch(const CDFSNP *cdfsnp, const UINT32 offset);

CDFSNP_ITEM *cdfsnp_reserve_item(CDFSNP *cdfsnp);
CDFSNP_ITEM *cdfsnp_reserve_item_no_lock(CDFSNP *cdfsnp);

EC_BOOL      cdfsnp_release_item(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item);
EC_BOOL      cdfsnp_release_item_no_lock(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item);

CDFSNP_ITEM *cdfsnp_set(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag);

CDFSNP_ITEM *cdfsnp_get(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag);

EC_BOOL cdfsnp_del(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec);

EC_BOOL cdfsnp_del_item(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item, CVECTOR *cdfsnp_fnode_vec);

EC_BOOL cdfsnp_path_name(const CDFSNP *cdfsnp, const UINT32 offset, const UINT32 path_max_len, UINT32 *path_len, UINT8 *path);

EC_BOOL cdfsnp_path_name_cstr(const CDFSNP *cdfsnp, const UINT32 offset, CSTRING *path_cstr);

EC_BOOL cdfsnp_seg_name(const CDFSNP *cdfsnp, const UINT32 offset, const UINT32 seg_name_max_len, UINT32 *seg_name_len, UINT8 *seg_name);

EC_BOOL cdfsnp_seg_name_cstr(const CDFSNP *cdfsnp, const UINT32 offset, CSTRING *seg_cstr);

EC_BOOL cdfsnp_list_path_vec(const CDFSNP *cdfsnp, const UINT32 offset, CVECTOR *path_cstr_vec);

EC_BOOL cdfsnp_list_seg_vec(const CDFSNP *cdfsnp, const UINT32 offset, CVECTOR *seg_cstr_vec);

EC_BOOL cdfsnp_file_num(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, UINT32 *file_num);

EC_BOOL cdfsnp_file_size(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path, UINT32 *file_size);

EC_BOOL cdfsnp_mkdirs(CDFSNP *cdfsnp, const UINT32 path_len, const UINT8 *path);

EC_BOOL cdfsnp_flush(const CDFSNP *cdfsnp);

EC_BOOL cdfsnp_load(CDFSNP *cdfsnp);

EC_BOOL cdfsnp_unlink(const char *dbname);

EC_BOOL cdfsnp_open(CDFSNP *cdfsnp, const char *cdfsnp_db_root_dir, UINT32 *create_flag);

EC_BOOL cdfsnp_close(CDFSNP *cdfsnp);

EC_BOOL cdfsnp_close_with_flush(CDFSNP *cdfsnp);

EC_BOOL cdfsnp_create(CDFSNP *cdfsnp, const char *cdfsnp_db_root_dir);

EC_BOOL cdfsnp_figure_out_block(const CDFSNP *cdfsnp, const UINT32 tcid, const UINT32 path_layout, LOG *log);

EC_BOOL cdfsnp_show(LOG *log, const char *dbname);

EC_BOOL cdfsnp_show_depth(LOG *log, const char *dbname);

EC_BOOL cdfsnp_show_item_depth(LOG *log, const CDFSNP *cdfsnp, const UINT32 offset);

EC_BOOL cdfsnp_inode_update(CDFSNP *cdfsnp, CDFSNP_INODE *cdfsnp_inode, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout);

EC_BOOL cdfsnp_fnode_update(CDFSNP *cdfsnp, CDFSNP_FNODE *cdfsnp_fnode, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout);

EC_BOOL cdfsnp_bucket_update(CDFSNP *cdfsnp, const CDFSNP_BUCKET bucket, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout);

EC_BOOL cdfsnp_dnode_update(CDFSNP *cdfsnp, CDFSNP_DNODE *cdfsnp_dnode, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout);

EC_BOOL cdfsnp_item_update(CDFSNP *cdfsnp, CDFSNP_ITEM *cdfsnp_item, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout);

EC_BOOL cdfsnp_update_no_lock(CDFSNP *cdfsnp, const UINT32 src_dn_tcid, const UINT32 src_path_layout, const UINT32 des_tcid, const UINT32 des_path_layout);


#endif/* _CDFSNP_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

