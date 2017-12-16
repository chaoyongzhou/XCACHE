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

#ifndef _CDFSDN_H
#define _CDFSDN_H

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
#include "clist.h"
#include "cmutex.h"

#if (32 == WORDSIZE)
#define CDFSDN_BLOCK_CONFIG_GROUP 4
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
#define CDFSDN_BLOCK_CONFIG_GROUP 4
#endif/*(64 == WORDSIZE)*/

/*each partition was 512 bytes*/
#define CDFSDN_BLOCK_PER_PART_SIZE      ((UINT32)(UINT32_ONE <<  9)) /*512B*/

#if (1 == CDFSDN_BLOCK_CONFIG_GROUP)/*8G memory, per node: 1 x np or 1 x dn*/
#define CDFSDN_BLOCK_DATA_MAX_SIZE      ((UINT32)(UINT32_ONE << 26))   /*64MB*/
#define CDFSDN_BLOCK_PART_MAX_NUM       (CDFSDN_BLOCK_DATA_MAX_SIZE / CDFSDN_BLOCK_PER_PART_SIZE)
#define CDFSDN_BLOCK_PART_MAX_SIZE      (CDFSDN_BLOCK_PART_MAX_NUM << 2)/*each index represented by a 32-bit number*/
#define CDFSDN_BLOCK_MAX_SIZE           (CDFSDN_BLOCK_DATA_MAX_SIZE + CDFSDN_BLOCK_PART_MAX_SIZE)

#define CDFSDN_BLOCK_MIN_SIZE           (CDFSDN_BLOCK_PART_MAX_SIZE)
#define CDFSDN_MAX_BLOCKS_PER_GB        (16)   /* 16 = 1GB/64MB */
#define CDFSDN_LOAD_BLOCK_MAX_NUM       (32)   /* 32 = 2G/64MB,max num of blocks which can be loaded into memory*/
#define CDFSDN_SHRINK_BLOCK_MAX_NUM     ( 4)   /*max num of blocks which can be once swapout from memory*/
#define CDFSDN_CMUTEX_MAX_NUM           (256)
#endif/*(1 == CDFSDN_BLOCK_CONFIG_GROUP)*/

#if (4 == CDFSDN_BLOCK_CONFIG_GROUP)/*1G memory, node A: 1 x np + 3 x dn*/
#define CDFSDN_BLOCK_DATA_MAX_SIZE      ((UINT32)(UINT32_ONE << 20))   /*1MB*/
#define CDFSDN_BLOCK_PART_MAX_NUM       (CDFSDN_BLOCK_DATA_MAX_SIZE / CDFSDN_BLOCK_PER_PART_SIZE)
#define CDFSDN_BLOCK_PART_MAX_SIZE      (CDFSDN_BLOCK_PART_MAX_NUM << 2)/*each index represented by a 32-bit number*/
#define CDFSDN_BLOCK_MAX_SIZE           (CDFSDN_BLOCK_DATA_MAX_SIZE + CDFSDN_BLOCK_PART_MAX_SIZE)

#define CDFSDN_BLOCK_MIN_SIZE           (CDFSDN_BLOCK_PART_MAX_SIZE)
#define CDFSDN_MAX_BLOCKS_PER_GB        (1024)  /* 1024 = 1GB/1MB */
#define CDFSDN_LOAD_BLOCK_MAX_NUM       ( 32)   /*  4 = 256M/64MB,max num of blocks which can be loaded into memory*/
#define CDFSDN_SHRINK_BLOCK_MAX_NUM     (  4)   /*max num of blocks which can be once swapout from memory*/
#define CDFSDN_CMUTEX_MAX_NUM           (256)
#endif/*(4 == CDFSDN_BLOCK_CONFIG_GROUP)*/


#define CDFSDN_ROOT_DIR_MAX_SIZE        ( 64)   /*root of record file and data files of data node  */
#define CDFSDN_BLOOM_NAME_MAX_SIZE      (128)   /*max len of record file name of data node         */
#define CDFSDN_BLOCK_NAME_MAX_SIZE      (256)   /*max len of /$(root_dir)/dsk$no/$dir1/$dir2/$dir3 */

#define CDFSDN_LOST_REPLICA_LOG_NAME_MAX_SIZE (256)   /*max len of /$(cdfsdn_root_dir)/rank_{tcid}_lost_replica.log*/

#define CDFSDN_BLOCK_O_RDONLY           ((UINT32)O_RDONLY)
#define CDFSDN_BLOCK_O_WRONLY           ((UINT32)O_WRONLY)
#define CDFSDN_BLOCK_O_RDWR             ((UINT32)O_RDWR  )
#define CDFSDN_BLOCK_O_CREATE           ((UINT32)O_CREAT )

#define CDFSDN_STAT_IS_NOT_FULL         ((UINT32) 1)
#define CDFSDN_STAT_IS_FULL             ((UINT32) 2)

#define CDFSDN_WRITE_ONCE_MAX_BYTES     ((UINT32)0x7FFFF000)/*2GB - 4KB*/
#define CDFSDN_READ_ONCE_MAX_BYTES      ((UINT32)0x7FFFF000)/*2GB - 4KB*/

#define CDFSDN_32BIT_MASK               ((UINT32)0xFFFFFFFF)

#define CDFSDN_ERR_POS                  ((UINT32)0xFFFFFFFF)
#define CDFSDN_ERR_LAYOUT               ((UINT32)0xFFFFFFFF)

#define CDFSDN_ERR_PART_IDX             ((UINT32)0xFFFFFFFF)

#define CDFSDN_ERR_PATH                 ((UINT32)0xFFFFFFFF)
#define CDFSDN_ERR_OFFSET               ((UINT32)0xFFFFFFFF)

#if 1
#define CDFSDN_PATH_LAYOUT_DIR0_NBITS    ( 8)
#define CDFSDN_PATH_LAYOUT_DIR1_NBITS    ( 8)
#define CDFSDN_PATH_LAYOUT_DIR2_NBITS    ( 8)
#define CDFSDN_PATH_LAYOUT_DIR3_NBITS    ( 8)

#define CDFSDN_PATH_LAYOUT_DIR0_ABITS    (24) /*bit alignment*/
#define CDFSDN_PATH_LAYOUT_DIR1_ABITS    (16) /*bit alignment*/
#define CDFSDN_PATH_LAYOUT_DIR2_ABITS    ( 8) /*bit alignment*/
#define CDFSDN_PATH_LAYOUT_DIR3_ABITS    ( 0) /*bit alignment*/
#endif

#if 0
#define CDFSDN_PATH_LAYOUT_DIR0_NBITS    (23)
#define CDFSDN_PATH_LAYOUT_DIR1_NBITS    ( 4)
#define CDFSDN_PATH_LAYOUT_DIR2_NBITS    ( 3)
#define CDFSDN_PATH_LAYOUT_DIR3_NBITS    ( 2)

#define CDFSDN_PATH_LAYOUT_DIR0_ABITS    ( 9) /*bit alignment*/
#define CDFSDN_PATH_LAYOUT_DIR1_ABITS    ( 5) /*bit alignment*/
#define CDFSDN_PATH_LAYOUT_DIR2_ABITS    ( 2) /*bit alignment*/
#define CDFSDN_PATH_LAYOUT_DIR3_ABITS    ( 0) /*bit alignment*/
#endif

#define CDFSDN_PATH_LAYOUT_DIR0_MASK     (((UINT32)(UINT32_ONE << CDFSDN_PATH_LAYOUT_DIR0_NBITS)) - 1)
#define CDFSDN_PATH_LAYOUT_DIR1_MASK     (((UINT32)(UINT32_ONE << CDFSDN_PATH_LAYOUT_DIR1_NBITS)) - 1)
#define CDFSDN_PATH_LAYOUT_DIR2_MASK     (((UINT32)(UINT32_ONE << CDFSDN_PATH_LAYOUT_DIR2_NBITS)) - 1)
#define CDFSDN_PATH_LAYOUT_DIR3_MASK     (((UINT32)(UINT32_ONE << CDFSDN_PATH_LAYOUT_DIR3_NBITS)) - 1)

#define CDFSDN_PATH_LAYOUT_DIR0_NO(path_id)     (((path_id) >> CDFSDN_PATH_LAYOUT_DIR0_ABITS) & CDFSDN_PATH_LAYOUT_DIR0_MASK)
#define CDFSDN_PATH_LAYOUT_DIR1_NO(path_id)     (((path_id) >> CDFSDN_PATH_LAYOUT_DIR1_ABITS) & CDFSDN_PATH_LAYOUT_DIR1_MASK)
#define CDFSDN_PATH_LAYOUT_DIR2_NO(path_id)     (((path_id) >> CDFSDN_PATH_LAYOUT_DIR2_ABITS) & CDFSDN_PATH_LAYOUT_DIR2_MASK)
#define CDFSDN_PATH_LAYOUT_DIR3_NO(path_id)     (((path_id) >> CDFSDN_PATH_LAYOUT_DIR3_ABITS) & CDFSDN_PATH_LAYOUT_DIR3_MASK)

#define CDFSDN_BUFF_LEN(cdfsdn_buff)        ((cdfsdn_buff)->len)
#define CDFSDN_BUFF_VAL(cdfsdn_buff)        ((cdfsdn_buff)->val)

typedef struct
{
    UINT32  cdfsdn_tcid;
    UINT32  cdfsdn_full;
}CDFSDN_STAT;

#define CDFSDN_STAT_TCID(cdfsdn_stat)       ((cdfsdn_stat)->cdfsdn_tcid)
#define CDFSDN_STAT_FULL(cdfsdn_stat)       ((cdfsdn_stat)->cdfsdn_full)

typedef struct
{
    UINT8           data[CDFSDN_BLOCK_DATA_MAX_SIZE];

    /*next linked(used or unused) partition index: */
    UINT32FIXED     next_partition_idx[CDFSDN_BLOCK_PART_MAX_NUM];
}CDFSDN_CACHE;

#define CDFSDN_CACHE_DATA(cdfsdn_cache)                        ((cdfsdn_cache)->data)
#define CDFSDN_CACHE_PART(cdfsdn_cache)                        ((cdfsdn_cache)->next_partition_idx)
#define CDFSDN_CACHE_PART_DATA(cdfsdn_cache, part_idx)         ((cdfsdn_cache)->data + (part_idx) * CDFSDN_BLOCK_PER_PART_SIZE)
#define CDFSDN_CACHE_PART_NEXT_IDX(cdfsdn_cache, part_idx)     ((cdfsdn_cache)->next_partition_idx[(part_idx)])

typedef struct
{
    UINT8       block_root_dir[ CDFSDN_ROOT_DIR_MAX_SIZE ];
    UINT32      block_path_layout;

    int         block_fd;            /* block fd */
    int         rsvd;

    CDFSDN_CACHE *block_cache;
}CDFSDN_BLOCK;

#define CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block)                 ((cdfsdn_block)->block_root_dir)
#define CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)              ((cdfsdn_block)->block_path_layout)
#define CDFSDN_BLOCK_PATH_LAYOUT_DISK_NO(cdfsdn_block)      (CDFSDN_PATH_LAYOUT_DIR0_NO(CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)))
#define CDFSDN_BLOCK_PATH_LAYOUT_DIR1_NO(cdfsdn_block)      (CDFSDN_PATH_LAYOUT_DIR1_NO(CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)))
#define CDFSDN_BLOCK_PATH_LAYOUT_DIR2_NO(cdfsdn_block)      (CDFSDN_PATH_LAYOUT_DIR2_NO(CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)))
#define CDFSDN_BLOCK_PATH_LAYOUT_DIR3_NO(cdfsdn_block)      (CDFSDN_PATH_LAYOUT_DIR3_NO(CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)))
#define CDFSDN_BLOCK_FD(cdfsdn_block)                       ((cdfsdn_block)->block_fd)
#define CDFSDN_BLOCK_CACHE(cdfsdn_block)                    ((cdfsdn_block)->block_cache)
#define CDFSDN_BLOCK_PART_DATA(cdfsdn_block, part_idx)      (CDFSDN_CACHE_PART_DATA(CDFSDN_BLOCK_CACHE(cdfsdn_block), part_idx))
#define CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, part_idx)  (CDFSDN_CACHE_PART_NEXT_IDX(CDFSDN_BLOCK_CACHE(cdfsdn_block), part_idx))

#define CDFSDN_BLOCK_CACHE_DATA(cdfsdn_block)               (CDFSDN_CACHE_DATA(CDFSDN_BLOCK_CACHE(cdfsdn_block)))
#define CDFSDN_BLOCK_CACHE_PART(cdfsdn_block)               (CDFSDN_CACHE_PART(CDFSDN_BLOCK_CACHE(cdfsdn_block)))

#define CDFSDN_RECORD_FLAG_CACHED_BIT          ((UINT32) 0x1)
#define CDFSDN_RECORD_FLAG_UPDATED_BIT         ((UINT32) 0x2)
#define CDFSDN_RECORD_FLAG_WRITE_BIT           ((UINT32) 0x4)
#define CDFSDN_RECORD_FLAG_SWAPOUT_BIT         ((UINT32) 0x8)
#define CDFSDN_RECORD_FLAG_MASK                ((UINT32) 0xF)/*4 bits*/

#define CDFSDN_RECORD_FLAG_READ_BIT            ((UINT32)0x10)/*trick!*/

typedef struct
{
    UINT32      flag          :4;
    UINT32      size          :28;/*size <= CDFSDN_BLOCK_MAX_SIZE. note: here must be greater than 26 due to block max size is 64M(2^26) in general*/
    UINT32      first_part_idx:32;
    UINT32      record_next   :32;/*next free record*/
    UINT32      reader_num    :32;/*reader num of the block*/
}CDFSDN_RECORD;

#define CDFSDN_RECORD_FLAG(cdfsdn_record)                ((cdfsdn_record)->flag)
#define CDFSDN_RECORD_SET_FLAG(cdfsdn_record, bflags)    (CDFSDN_RECORD_FLAG(cdfsdn_record) = ((bflags) & CDFSDN_RECORD_FLAG_MASK))
#define CDFSDN_RECORD_CACHED_FLAG(cdfsdn_record)         (CDFSDN_RECORD_FLAG_CACHED_BIT  & CDFSDN_RECORD_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_UPDATED_FLAG(cdfsdn_record)        (CDFSDN_RECORD_FLAG_UPDATED_BIT & CDFSDN_RECORD_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_WRITE_FLAG(cdfsdn_record)          (CDFSDN_RECORD_FLAG_WRITE_BIT   & CDFSDN_RECORD_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_SWAPOUT_FLAG(cdfsdn_record)        (CDFSDN_RECORD_FLAG_SWAPOUT_BIT & CDFSDN_RECORD_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_READER_NUM(cdfsdn_record)          ((cdfsdn_record)->reader_num)
#define CDFSDN_RECORD_SIZE(cdfsdn_record)                ((cdfsdn_record)->size)
#define CDFSDN_RECORD_ROOM(cdfsdn_record)                (CDFSDN_BLOCK_DATA_MAX_SIZE - (CDFSDN_RECORD_SIZE(cdfsdn_record) & CDFSDN_32BIT_MASK))
#define CDFSDN_RECORD_NEXT(cdfsdn_record)                ((cdfsdn_record)->record_next)
#define CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record)      ((cdfsdn_record)->first_part_idx)

#define CDFSDN_RECORD_IS_CACHED(cdfsdn_record)           (0 < CDFSDN_RECORD_CACHED_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_UPDATED(cdfsdn_record)          (0 < CDFSDN_RECORD_UPDATED_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_WRITE(cdfsdn_record)            (0 < CDFSDN_RECORD_WRITE_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_SWAPOUT(cdfsdn_record)          (0 < CDFSDN_RECORD_SWAPOUT_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_READ(cdfsdn_record)             (0 < CDFSDN_RECORD_READER_NUM(cdfsdn_record))
#define CDFSDN_RECORD_IS_FULL(cdfsdn_record)             (CDFSDN_BLOCK_PART_MAX_NUM <= CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record) )

#define CDFSDN_RECORD_IS_NOT_CACHED(cdfsdn_record)       (0 == CDFSDN_RECORD_CACHED_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_NOT_UPDATED(cdfsdn_record)      (0 == CDFSDN_RECORD_UPDATED_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_NOT_WRITE(cdfsdn_record)        (0 == CDFSDN_RECORD_WRITE_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_NOT_SWAPOUT(cdfsdn_record)      (0 == CDFSDN_RECORD_SWAPOUT_FLAG(cdfsdn_record))
#define CDFSDN_RECORD_IS_NOT_READ(cdfsdn_record)         (0 == CDFSDN_RECORD_READER_NUM(cdfsdn_record))
#define CDFSDN_RECORD_IS_NOT_FULL(cdfsdn_record)         (CDFSDN_BLOCK_PART_MAX_NUM > CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record) )

#define CDFSDN_RECORD_SET_CACHED(cdfsdn_record)          (CDFSDN_RECORD_FLAG(cdfsdn_record) |= CDFSDN_RECORD_FLAG_CACHED_BIT)
#define CDFSDN_RECORD_SET_UPDATED(cdfsdn_record)         (CDFSDN_RECORD_FLAG(cdfsdn_record) |= CDFSDN_RECORD_FLAG_UPDATED_BIT)
#define CDFSDN_RECORD_SET_WRITE(cdfsdn_record)           (CDFSDN_RECORD_FLAG(cdfsdn_record) |= CDFSDN_RECORD_FLAG_WRITE_BIT)
#define CDFSDN_RECORD_SET_SWAPOUT(cdfsdn_record)         (CDFSDN_RECORD_FLAG(cdfsdn_record) |= CDFSDN_RECORD_FLAG_SWAPOUT_BIT)
#define CDFSDN_RECORD_INC_READER(cdfsdn_record)          (CDFSDN_RECORD_READER_NUM(cdfsdn_record) ++)

#define CDFSDN_RECORD_SET_NOT_CACHED(cdfsdn_record)      (CDFSDN_RECORD_FLAG(cdfsdn_record) &= ((~CDFSDN_RECORD_FLAG_CACHED_BIT ) & CDFSDN_RECORD_FLAG_MASK))
#define CDFSDN_RECORD_SET_NOT_UPDATED(cdfsdn_record)     (CDFSDN_RECORD_FLAG(cdfsdn_record) &= ((~CDFSDN_RECORD_FLAG_UPDATED_BIT) & CDFSDN_RECORD_FLAG_MASK))
#define CDFSDN_RECORD_SET_NOT_WRITE(cdfsdn_record)       (CDFSDN_RECORD_FLAG(cdfsdn_record) &= ((~CDFSDN_RECORD_FLAG_WRITE_BIT  ) & CDFSDN_RECORD_FLAG_MASK))
#define CDFSDN_RECORD_SET_NOT_SWAPOUT(cdfsdn_record)     (CDFSDN_RECORD_FLAG(cdfsdn_record) &= ((~CDFSDN_RECORD_FLAG_SWAPOUT_BIT) & CDFSDN_RECORD_FLAG_MASK))
#define CDFSDN_RECORD_DEC_READER(cdfsdn_record)          (CDFSDN_RECORD_READER_NUM(cdfsdn_record) --)
#define CDFSDN_RECORD_SET_NO_READER(cdfsdn_record)       (CDFSDN_RECORD_READER_NUM(cdfsdn_record) = 0)


typedef struct
{
    CROUTINE_MUTEX    cmutex;
    UINT32            disk_num;
    UINT32            record_num:32;
    UINT32            record_beg:32;  /*unfull block record link head*/
    CDFSDN_RECORD    *record_tbl;  /*block record table*/
}CDFSDN_RECORD_MGR;

#define CDFSDN_RECORD_MGR_CMUTEX(cdfsdn_record_mgr)                         (&((cdfsdn_record_mgr)->cmutex))
#define CDFSDN_RECORD_MGR_DISK_NUM(cdfsdn_record_mgr)                       ((cdfsdn_record_mgr)->disk_num)
#define CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr)                       ((cdfsdn_record_mgr)->record_num)
#define CDFSDN_RECORD_MGR_NODE_BEG(cdfsdn_record_mgr)                       ((cdfsdn_record_mgr)->record_beg)
#define CDFSDN_RECORD_MGR_NODE_TBL(cdfsdn_record_mgr)                       ((cdfsdn_record_mgr)->record_tbl)
#define CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)              ((cdfsdn_record_mgr)->record_tbl + (path_layout))

#define CDFSDN_RECORD_MGR_NODE_NEXT(cdfsdn_record_mgr, path_layout)         (CDFSDN_RECORD_NEXT(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_PART_IDX(cdfsdn_record_mgr, path_layout)     (CDFSDN_RECORD_FIRST_PART_IDX(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))

#define CDFSDN_RECORD_MGR_NODE_CACHED_FLAG(cdfsdn_record_mgr, path_layout)   (CDFSDN_RECORD_CACHED_FLAG(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_UPDATED_FLAG(cdfsdn_record_mgr, path_layout)  (CDFSDN_RECORD_UPDATED_FLAG(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_WRITE_FLAG(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_WRITE_FLAG(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SWAPOUT_FLAG(cdfsdn_record_mgr, path_layout)  (CDFSDN_RECORD_SWAPOUT_FLAG(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_READER_NUM(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_READER_NUM(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SIZE(cdfsdn_record_mgr, path_layout)          (CDFSDN_RECORD_SIZE(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_ROOM(cdfsdn_record_mgr, path_layout)          (CDFSDN_RECORD_ROOM(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_CACHED(cdfsdn_record_mgr, path_layout)     (CDFSDN_RECORD_IS_CACHED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_UPDATED(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_IS_UPDATED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_WRITE(cdfsdn_record_mgr, path_layout)      (CDFSDN_RECORD_IS_WRITE(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_READ(cdfsdn_record_mgr, path_layout)       (CDFSDN_RECORD_IS_READ(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_SWAPOUT(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_IS_SWAPOUT(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_FULL(cdfsdn_record_mgr, path_layout)       (CDFSDN_RECORD_IS_FULL(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))

#define CDFSDN_RECORD_MGR_NODE_IS_NOT_CACHED(cdfsdn_record_mgr, path_layout)     (CDFSDN_RECORD_IS_NOT_CACHED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_NOT_UPDATED(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_IS_NOT_UPDATED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_NOT_WRITE(cdfsdn_record_mgr, path_layout)      (CDFSDN_RECORD_IS_NOT_WRITE(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_NOT_READ(cdfsdn_record_mgr, path_layout)       (CDFSDN_RECORD_IS_NOT_READ(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_NOT_SWAPOUT(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_IS_NOT_SWAPOUT(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_IS_NOT_FULL(cdfsdn_record_mgr, path_layout)       (CDFSDN_RECORD_IS_NOT_FULL(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))

#define CDFSDN_RECORD_MGR_NODE_FLAG(cdfsdn_record_mgr, path_layout)              (CDFSDN_RECORD_FLAG(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_FLAG(cdfsdn_record_mgr, path_layout, bflags)  (CDFSDN_RECORD_SET_FLAG(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout), bflags))
#define CDFSDN_RECORD_MGR_NODE_SET_CACHED(cdfsdn_record_mgr, path_layout)        (CDFSDN_RECORD_SET_CACHED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_UPDATED(cdfsdn_record_mgr, path_layout)       (CDFSDN_RECORD_SET_UPDATED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_WRITE(cdfsdn_record_mgr, path_layout)         (CDFSDN_RECORD_SET_WRITE(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_SWAPOUT(cdfsdn_record_mgr, path_layout)       (CDFSDN_RECORD_SET_SWAPOUT(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_INC_READER(cdfsdn_record_mgr, path_layout)        (CDFSDN_RECORD_INC_READER(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))

#define CDFSDN_RECORD_MGR_NODE_SET_NOT_CACHED(cdfsdn_record_mgr, path_layout)     (CDFSDN_RECORD_SET_NOT_CACHED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_NOT_UPDATED(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_SET_NOT_UPDATED(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_NOT_WRITE(cdfsdn_record_mgr, path_layout)      (CDFSDN_RECORD_SET_NOT_WRITE(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_NOT_SWAPOUT(cdfsdn_record_mgr, path_layout)    (CDFSDN_RECORD_SET_NOT_SWAPOUT(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_DEC_READER(cdfsdn_record_mgr, path_layout)         (CDFSDN_RECORD_DEC_READER(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))
#define CDFSDN_RECORD_MGR_NODE_SET_NO_READER(cdfsdn_record_mgr, path_layout)      (CDFSDN_RECORD_SET_NO_READER(CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, path_layout)))

#define CDFSDN_RECORD_MGR_INIT_CMUTEX_LOCK(cdfsdn_record_mgr, location)    (croutine_mutex_init(CDFSDN_RECORD_MGR_CMUTEX(cdfsdn_record_mgr), CMUTEX_PROCESS_PRIVATE, location))
#define CDFSDN_RECORD_MGR_CLEAN_CMUTEX_LOCK(cdfsdn_record_mgr, location)   (croutine_mutex_clean(CDFSDN_RECORD_MGR_CMUTEX(cdfsdn_record_mgr), location))
#define CDFSDN_RECORD_MGR_CMUTEX_LOCK(cdfsdn_record_mgr, location)         (croutine_mutex_lock(CDFSDN_RECORD_MGR_CMUTEX(cdfsdn_record_mgr), location))
#define CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(cdfsdn_record_mgr, location)       (croutine_mutex_unlock(CDFSDN_RECORD_MGR_CMUTEX(cdfsdn_record_mgr), location))


typedef struct
{
    CROUTINE_MUTEX         cmutex[CDFSDN_CMUTEX_MAX_NUM];
    CLIST          block_tbl;

    UINT8          root_dir[ CDFSDN_ROOT_DIR_MAX_SIZE ];
    UINT8          record_name[ CDFSDN_BLOOM_NAME_MAX_SIZE ];

    int            record_fd;      /* record fd */
    int            rsvd;

    CDFSDN_RECORD_MGR *record_mgr;
}CDFSDN;

#define CDFSDN_CMUTEX(cdfsdn, path_layout)                  (&((cdfsdn)->cmutex[ (path_layout) % (CDFSDN_CMUTEX_MAX_NUM) ]))
#define CDFSDN_BLOCK_TBL(cdfsdn)                            (&((cdfsdn)->block_tbl))
#define CDFSDN_ROOT_DIR(cdfsdn)                             ((cdfsdn)->root_dir)
#define CDFSDN_RECORD_NAME(cdfsdn)                          ((cdfsdn)->record_name)
#define CDFSDN_RECORD_FD(cdfsdn)                            ((cdfsdn)->record_fd)
#define CDFSDN_RECORD_MGR(cdfsdn)                           ((cdfsdn)->record_mgr)

#define CDFSDN_NODE_INIT_LOCK(cdfsdn, path_layout, location)  (croutine_mutex_init(CDFSDN_CMUTEX(cdfsdn, path_layout), CMUTEX_PROCESS_PRIVATE, location))
#define CDFSDN_NODE_CLEAN_LOCK(cdfsdn, path_layout, location) (croutine_mutex_clean(CDFSDN_CMUTEX(cdfsdn, path_layout), location))

#if 1
#define CDFSDN_NODE_LOCK(cdfsdn, path_layout, location)       (croutine_mutex_lock(CDFSDN_CMUTEX(cdfsdn, path_layout), location))
#define CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, location)     (croutine_mutex_unlock(CDFSDN_CMUTEX(cdfsdn, path_layout), location))
#endif
#if 0
#define CDFSDN_NODE_LOCK(cdfsdn, path_layout, location)       do{\
sys_log(LOGSTDOUT, "LOCATION %ld: try to lock path layout %ld or cmutex %ld owner %d#\n", location, path_layout, ((path_layout) % (CDFSDN_CMUTEX_MAX_NUM)), CMUTEX_OWNER(CDFSDN_CMUTEX(cdfsdn, path_layout)));\
croutine_mutex_lock(CDFSDN_CMUTEX(cdfsdn, path_layout), location);\
}while(0)

#define CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, location)     do{\
sys_log(LOGSTDOUT, "LOCATION %ld: try to unlock path layout %ld or cmutex %ld owner %d#\n", location, path_layout, ((path_layout) % (CDFSDN_CMUTEX_MAX_NUM)), CMUTEX_OWNER(CDFSDN_CMUTEX(cdfsdn, path_layout)));\
croutine_mutex_unlock(CDFSDN_CMUTEX(cdfsdn, path_layout), location);\
}while(0)
#endif

#define CDFSDN_DISK_NUM(cdfsdn)                             (CDFSDN_RECORD_MGR_DISK_NUM(CDFSDN_RECORD_MGR(cdfsdn)))
#define CDFSDN_NODE_NUM(cdfsdn)                             (CDFSDN_RECORD_MGR_NODE_NUM(CDFSDN_RECORD_MGR(cdfsdn)))
#define CDFSDN_NODE_BEG(cdfsdn)                             (CDFSDN_RECORD_MGR_NODE_BEG(CDFSDN_RECORD_MGR(cdfsdn)))
#define CDFSDN_NODE_TBL(cdfsdn)                             (CDFSDN_RECORD_MGR_NODE_TBL(CDFSDN_RECORD_MGR(cdfsdn)))

#define CDFSDN_NODE_NEXT(cdfsdn, path_layout)               (CDFSDN_RECORD_MGR_NODE_NEXT(CDFSDN_RECORD_MGR(cdfsdn), path_layout))
#define CDFSDN_NODE_PART_IDX(cdfsdn, path_layout)           (CDFSDN_RECORD_MGR_NODE_PART_IDX(CDFSDN_RECORD_MGR(cdfsdn), path_layout))

#define CDFSDN_NODE_CACHED_FLAG(cdfsdn, record_pos)         (CDFSDN_RECORD_MGR_NODE_CACHED_FLAG(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_UPDATED_FLAG(cdfsdn, record_pos)        (CDFSDN_RECORD_MGR_NODE_UPDATED_FLAG(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_WRITE_FLAG(cdfsdn, record_pos)          (CDFSDN_RECORD_MGR_NODE_WRITE_FLAG(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SWAPOUT_FLAG(cdfsdn, record_pos)        (CDFSDN_RECORD_MGR_NODE_SWAPOUT_FLAG(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_READER_NUM(cdfsdn, record_pos)          (CDFSDN_RECORD_MGR_NODE_READER_NUM(CDFSDN_RECORD_MGR(cdfsdn), record_pos))

#define CDFSDN_NODE_SIZE(cdfsdn, record_pos)                (CDFSDN_RECORD_MGR_NODE_SIZE(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_ROOM(cdfsdn, record_pos)                (CDFSDN_RECORD_MGR_NODE_ROOM(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_CACHED(cdfsdn, record_pos)           (CDFSDN_RECORD_MGR_NODE_IS_CACHED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_UPDATED(cdfsdn, record_pos)          (CDFSDN_RECORD_MGR_NODE_IS_UPDATED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_WRITE(cdfsdn, record_pos)            (CDFSDN_RECORD_MGR_NODE_IS_WRITE(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_READ(cdfsdn, record_pos)             (CDFSDN_RECORD_MGR_NODE_IS_READ(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_SWAPOUT(cdfsdn, record_pos)          (CDFSDN_RECORD_MGR_NODE_IS_SWAPOUT(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_FULL(cdfsdn, record_pos)             (CDFSDN_NODE_BEG(cdfsdn) >= CDFSDN_NODE_NUM(cdfsdn))

#define CDFSDN_NODE_IS_NOT_CACHED(cdfsdn, record_pos)       (CDFSDN_RECORD_MGR_NODE_IS_NOT_CACHED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_NOT_UPDATED(cdfsdn, record_pos)      (CDFSDN_RECORD_MGR_NODE_IS_NOT_UPDATED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_NOT_WRITE(cdfsdn, record_pos)        (CDFSDN_RECORD_MGR_NODE_IS_NOT_WRITE(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_NOT_READ(cdfsdn, record_pos)         (CDFSDN_RECORD_MGR_NODE_IS_NOT_READ(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_NOT_SWAPOUT(cdfsdn, record_pos)      (CDFSDN_RECORD_MGR_NODE_IS_NOT_SWAPOUT(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_IS_NOT_FULL(cdfsdn, record_pos)         (CDFSDN_RECORD_MGR_NODE_IS_NOT_FULL(CDFSDN_RECORD_MGR(cdfsdn), record_pos))

#define CDFSDN_NODE_FLAG(cdfsdn, record_pos)                (CDFSDN_RECORD_MGR_NODE_FLAG(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_FLAG(cdfsdn, record_pos, bflags)    (CDFSDN_RECORD_MGR_NODE_SET_FLAG(CDFSDN_RECORD_MGR(cdfsdn), record_pos, bflags))
#define CDFSDN_NODE_SET_CACHED(cdfsdn, record_pos)          (CDFSDN_RECORD_MGR_NODE_SET_CACHED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_UPDATED(cdfsdn, record_pos)         (CDFSDN_RECORD_MGR_NODE_SET_UPDATED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_WRITE(cdfsdn, record_pos)           (CDFSDN_RECORD_MGR_NODE_SET_WRITE(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_SWAPOUT(cdfsdn, record_pos)         (CDFSDN_RECORD_MGR_NODE_SET_SWAPOUT(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_INC_READER(cdfsdn, record_pos)          (CDFSDN_RECORD_MGR_NODE_INC_READER(CDFSDN_RECORD_MGR(cdfsdn), record_pos))

#define CDFSDN_NODE_SET_NOT_CACHED(cdfsdn, record_pos)      (CDFSDN_RECORD_MGR_NODE_SET_NOT_CACHED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_NOT_UPDATED(cdfsdn, record_pos)     (CDFSDN_RECORD_MGR_NODE_SET_NOT_UPDATED(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, record_pos)       (CDFSDN_RECORD_MGR_NODE_SET_NOT_WRITE(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_NOT_SWAPOUT(cdfsdn, record_pos)     (CDFSDN_RECORD_MGR_NODE_SET_NOT_SWAPOUT(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_DEC_READER(cdfsdn, record_pos)          (CDFSDN_RECORD_MGR_NODE_DEC_READER(CDFSDN_RECORD_MGR(cdfsdn), record_pos))
#define CDFSDN_NODE_SET_NO_READER(cdfsdn, record_pos)       (CDFSDN_RECORD_MGR_NODE_SET_NO_READER(CDFSDN_RECORD_MGR(cdfsdn), record_pos))

CDFSDN_CACHE *cdfsdn_cache_new();

EC_BOOL cdfsdn_cache_init(CDFSDN_CACHE *cdfsdn_cache);

EC_BOOL cdfsdn_cache_clean(CDFSDN_CACHE *cdfsdn_cache);

EC_BOOL cdfsdn_cache_free(CDFSDN_CACHE *cdfsdn_cache);

EC_BOOL cdfsdn_cache_clone(const CDFSDN_CACHE *cdfsdn_cache_src, CDFSDN_CACHE *cdfsdn_cache_des);

void cdfsdn_cache_print(LOG *log, const CDFSDN_CACHE *cdfsdn_cache);

CDFSDN_STAT *cdfsdn_stat_new();

EC_BOOL cdfsdn_stat_init(CDFSDN_STAT *cdfsdn_stat);

EC_BOOL cdfsdn_stat_clean(CDFSDN_STAT *cdfsdn_stat);

EC_BOOL cdfsdn_stat_free(CDFSDN_STAT *cdfsdn_stat);

EC_BOOL cdfsdn_record_init(CDFSDN_RECORD *cdfsdn_record);

EC_BOOL cdfsdn_record_clean(CDFSDN_RECORD *cdfsdn_record);

EC_BOOL cdfsdn_record_free(CDFSDN_RECORD *cdfsdn_record);

CDFSDN_RECORD_MGR *cdfsdn_record_mgr_new(const UINT32 disk_num, const UINT32 record_num, const UINT32 record_beg);

EC_BOOL cdfsdn_record_mgr_init(CDFSDN_RECORD_MGR *cdfsdn_record_mgr, const UINT32 disk_num, const UINT32 record_num, const UINT32 record_beg);

EC_BOOL cdfsdn_record_mgr_link(CDFSDN_RECORD_MGR *cdfsdn_record_mgr);

EC_BOOL cdfsdn_record_mgr_clear_flags(CDFSDN_RECORD_MGR *cdfsdn_record_mgr);

EC_BOOL cdfsdn_record_mgr_free(CDFSDN_RECORD_MGR *cdfsdn_record_mgr);

void cdfsdn_record_mgr_print(LOG *log, const CDFSDN_RECORD_MGR *cdfsdn_record_mgr);

EC_BOOL cdfsdn_record_mgr_load(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_record_mgr_flush(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_record_mgr_set(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 cache_size);

EC_BOOL cdfsdn_record_mgr_get(const CDFSDN *cdfsdn, const UINT32 path_layout, UINT32 *cache_size);

EC_BOOL cdfsdn_record_is_full(const CDFSDN *cdfsdn, const UINT32 path_layout);

EC_BOOL cdfsdn_record_rmv(const CDFSDN * cdfsdn);

CDFSDN_BLOCK *cdfsdn_block_new(const char *block_root_dir);

EC_BOOL cdfsdn_block_init(CDFSDN_BLOCK *cdfsdn_block, const char *block_root_dir);

EC_BOOL cdfsdn_block_init_0(CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_clean(CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_free(CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_cache_flush(const CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_cache_load(CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_cache_flush_to(int fd, const CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_cache_load_from(int fd, CDFSDN_BLOCK *cdfsdn_block);

void cdfsdn_block_print(LOG *log, const CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_create(CDFSDN_BLOCK *cdfsdn_block, const UINT32 disk_num, const UINT32 block_path_layout);

EC_BOOL cdfsdn_block_open(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 block_path_layout, const UINT32 open_flags);

EC_BOOL cdfsdn_block_flush(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_load(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_unlink(const CDFSDN_BLOCK *cdfsdn_block, const UINT32 disk_num, const UINT32 block_path_layout);

EC_BOOL cdfsdn_block_clear_flags(CDFSDN *cdfsdn, const CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_burn(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_len);

EC_BOOL cdfsdn_block_return(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_block_truncate(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_max_len, const CVECTOR *part_idx_vec);

EC_BOOL cdfsdn_block_update(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_max_len, const UINT8 *data_buff, const UINT32 partition_beg);

EC_BOOL cdfsdn_block_write(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_max_len, const UINT8 *data_buff, const CVECTOR *part_idx_vec);

EC_BOOL cdfsdn_block_read(const CDFSDN_BLOCK *cdfsdn_block, const UINT32 first_partition_idx, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

EC_BOOL cdfsdn_block_reserve_partition(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 room, UINT32 *partition_beg, CVECTOR *partition_idx_vec);

EC_BOOL cdfsdn_block_release_partition(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, CVECTOR *partition_idx_vec);

EC_BOOL cdfsdn_block_recycle_partition(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 first_partition_idx);

CDFSDN *cdfsdn_new(const char *root_dir);

EC_BOOL cdfsdn_init(CDFSDN *cdfsdn, const char *root_dir);

EC_BOOL cdfsdn_clean(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_free(CDFSDN *cdfsdn);

void    cdfsdn_print(LOG *log, const CDFSDN *cdfsdn);

EC_BOOL cdfsdn_is_full(CDFSDN *cdfsdn);

UINT32  cdfsdn_stat_fetch(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_flush(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_load(CDFSDN *cdfsdn);

CDFSDN *cdfsdn_open(const char *root_dir);

EC_BOOL cdfsdn_close(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_close_with_flush(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_create(const char *root_dir, const UINT32 disk_num, const UINT32 max_gb_num_of_disk_space);

CDFSDN_BLOCK *cdfsdn_search_block_to_swapout(CDFSDN *cdfsdn, const UINT32 except_cdfsdn_node_lock);

EC_BOOL cdfsdn_reserve_block_to_swapin(CDFSDN *cdfsdn, const UINT32 room, UINT32 *path_layout_reserved);

CDFSDN_BLOCK *cdfsdn_lookup_block(CDFSDN *cdfsdn, const UINT32 path_layout);

CDFSDN_BLOCK *cdfsdn_lookup_block_no_lock(CDFSDN *cdfsdn, const UINT32 path_layout);

CDFSDN_BLOCK *cdfsdn_reserve_block_to_write(CDFSDN *cdfsdn, const UINT32 room, UINT32 *partition_beg, CVECTOR *partition_idx_vec);

EC_BOOL cdfsdn_fexist_block(const CDFSDN *cdfsdn, const UINT32 path_layout);

EC_BOOL cdfsdn_swapout(CDFSDN *cdfsdn, CDFSDN_BLOCK  *cdfsdn_block);

CDFSDN_BLOCK * cdfsdn_swapin(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 open_flags, const UINT32 bit_flags);

CDFSDN_BLOCK * cdfsdn_swapin_no_lock(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 open_flags, const UINT32 bit_flags);

EC_BOOL cdfsdn_shrink(CDFSDN *cdfsdn, const UINT32 except_cdfsdn_node_lock);

EC_BOOL cdfsdn_shrink_no_lock(CDFSDN *cdfsdn, const UINT32 except_cdfsdn_node_lock);

EC_BOOL cdfsdn_shrink_opt(CDFSDN *cdfsdn, const UINT32 except_cdfsdn_node_lock, const UINT32 swapout_block_max_num);

EC_BOOL cdfsdn_read(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

EC_BOOL cdfsdn_write(CDFSDN *cdfsdn, const UINT32 data_len, const UINT8 *data_buff, UINT32 *path_layout, UINT32 *offset);

EC_BOOL cdfsdn_update(CDFSDN *cdfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const UINT32 path_layout, const UINT32 partition_beg);

EC_BOOL cdfsdn_truncate(CDFSDN *cdfsdn, const UINT32 data_max_len, UINT32 *path_layout, UINT32 *partition_idx);

EC_BOOL cdfsdn_remove(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 partition_idx);

CDFSDN_BLOCK * cdfsdn_get(CDFSDN *cdfsdn, const UINT32 path_layout);

EC_BOOL cdfsdn_set(CDFSDN *cdfsdn, const UINT32 block_path_layout, const CDFSDN_BLOCK *cdfsdn_block);

EC_BOOL cdfsdn_transfer_in_do(CDFSDN *cdfsdn, const UINT32 size, const UINT32 first_part_idx, const CDFSDN_BLOCK *cdfsdn_block, UINT32 *des_block_path_layout);

CDFSDN_BLOCK * cdfsdn_transfer_out_start(CDFSDN *cdfsdn);

EC_BOOL cdfsdn_transfer_out_end(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block);

/*for debug only*/
void cdfsdn_block_fname_print(LOG *log, const UINT32 disk_num, const UINT32 block_path_layout);

EC_BOOL cdfsdn_show(LOG *log, const char *root_dir);


#endif/* _CDFSDN_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

