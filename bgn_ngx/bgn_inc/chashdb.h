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

#ifndef _CHASHDB_H
#define _CHASHDB_H

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
#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"

#include "cbloom.h"
#include "chashalgo.h"

#define CHASHDB_KEY_MAX_SIZE	         (48)
#define CHASHDB_DATA_REPLICA_MAX_NUM     (4)
#define CHASHDB_BUCKET_CMUTEX_MAX_NUM    (1024)

#define CHASHDB_ERR_PATH                 ((UINT32)  -1)
#define CHASHDB_ERR_OFFSET               ((UINT32)  -1)

#define CHASHDB_ITEM_FILE_IS_REG         ((UINT32)   1)
#define CHASHDB_ITEM_FILE_IS_DIR         ((UINT32)   2)
#define CHASHDB_ITEM_FILE_IS_ERR         ((UINT32)0xFF)/*8 bits*/

#define CHASHDB_ITEM_STAT_IS_NOT_USED    ((UINT32)   3)
#define CHASHDB_ITEM_STAT_IS_FLUSHED     ((UINT32)   4)
#define CHASHDB_ITEM_STAT_IS_CACHED      ((UINT32)   5)
#define CHASHDB_ITEM_STAT_IS_ERR         ((UINT32)0xFF)/*8 bits*/

typedef struct
{
    UINT32      datanode_tcid;       /*remote datanode*/
    UINT32      path_layout;         /*remote full path layout. bitmap: 2bits - disk layout, 10bits - level 1 dir, 10bits - leve 2 dir, 10bits - level 3 dir*/
    UINT32      file_offset;         /*file offset in the full path. note full path point to a regular data file but not directory*/
}CHASHDB_INODE;

#define CHASHDB_INODE_TCID(chashdb_inode)           ((chashdb_inode)->datanode_tcid)
#define CHASHDB_INODE_PATH(chashdb_inode)           ((chashdb_inode)->path_layout)
#define CHASHDB_INODE_FOFF(chashdb_inode)           ((chashdb_inode)->file_offset)

typedef struct
{
    UINT32      file_flag:8;  /* regular file or directory */
    UINT32      item_stat:8;  /* item status: not used, flushed, or cached */
    UINT32      rsvd1    :8;  /* reserved bits */
    UINT32      key_len  :8;  /* key lenght, range from [0..CHASHDB_KEY_MAX_SIZE] */

	UINT8       key[ CHASHDB_KEY_MAX_SIZE ];  /* key of <key, value> */
	UINT32      second_hash;                  /* hash fingerprint of key generated by the second hash algorithm */
	UINT32      second_hash_next_item_offset; /* offset of next item which has the same second hash */

	UINT32      brother_next_item_offset;     /* offset of next brother item which under the same parent directory*/
	UINT32      son_first_item_offset;        /* offset of first son item which under the current directory*/
	                                          /* note: this offset works only when file_flag is DIR */

    UINT32        data_len        :27;                       /* data/value length < 128M = 2^27B*/
    UINT32        rsvd2           :2;
    UINT32        data_replica_num:3;                        /* data_replica_num <= CHASHDB_DATA_REPLICA_MAX_NUM*/
	CHASHDB_INODE data_nodes[ CHASHDB_DATA_REPLICA_MAX_NUM ];/* data replicas*/
} CHASHDB_ITEM;

#define CHASHDB_ITEM_FLAG(chashdb_item)             ((chashdb_item)->file_flag)
#define CHASHDB_ITEM_STAT(chashdb_item)             ((chashdb_item)->item_stat)
#define CHASHDB_ITEM_KLEN(chashdb_item)             ((chashdb_item)->key_len)
#define CHASHDB_ITEM_KEY(chashdb_item)              ((chashdb_item)->key)
#define CHASHDB_ITEM_SHASH(chashdb_item)            ((chashdb_item)->second_hash)
#define CHASHDB_ITEM_SHASH_NEXT(chashdb_item)       ((chashdb_item)->second_hash_next_item_offset)
#define CHASHDB_ITEM_BROTHER_NEXT(chashdb_item)     ((chashdb_item)->brother_next_item_offset)
#define CHASHDB_ITEM_SON_NEXT(chashdb_item)         ((chashdb_item)->son_first_item_offset)
#define CHASHDB_ITEM_DLEN(chashdb_item)             ((chashdb_item)->data_len)
#define CHASHDB_ITEM_DREPLICA_NUM(chashdb_item)     ((chashdb_item)->data_replica_num)
#define CHASHDB_ITEM_DNODES(chashdb_item)           ((chashdb_item)->data_nodes)
#define CHASHDB_ITEM_DATA_NODE(chashdb_item, idx)   (&((chashdb_item)->data_nodes[ (idx) ]))


typedef struct
{
	UINT32 offset;		/* offset of the first entry in the bucket */
} CHASHDB_BUCKET;

#define CHASHDB_BUCKET_BOFFSET(chashdb_bucket)        ((chashdb_bucket)->offset)

#define CHASHDB_4K_CFG_FILE_SIZE        ((UINT32)(1 << 12))
#define CHASHDB_4K_CFG_ITEM_MAX_NUM     ((UINT32)(1 <<  5))
#define CHASHDB_4K_CFG_BUCKET_NUM       ((UINT32)(1 <<  5))
#define CHASHDB_4K_CFG_BLOOW_ROW_NUM    ((UINT32)(1 <<  4))
#define CHASHDB_4K_CFG_BLOOW_COL_NUM    ((UINT32)(1 <<  4))

#define CHASHDB_1M_CFG_FILE_SIZE        ((UINT32)(1 << 20))
#define CHASHDB_1M_CFG_ITEM_MAX_NUM     ((UINT32)(1 << 13))
#define CHASHDB_1M_CFG_BUCKET_NUM       ((UINT32)(1 << 13))
#define CHASHDB_1M_CFG_BLOOW_ROW_NUM    ((UINT32)(1 <<  7))
#define CHASHDB_1M_CFG_BLOOW_COL_NUM    ((UINT32)(1 <<  6))

#define CHASHDB_2M_CFG_FILE_SIZE        ((UINT32)(1 << 21))
#define CHASHDB_2M_CFG_ITEM_MAX_NUM     ((UINT32)(1 << 14))
#define CHASHDB_2M_CFG_BUCKET_NUM       ((UINT32)(1 << 14))
#define CHASHDB_2M_CFG_BLOOW_ROW_NUM    ((UINT32)(1 <<  7))
#define CHASHDB_2M_CFG_BLOOW_COL_NUM    ((UINT32)(1 <<  7))

#define CHASHDB_500M_CFG_FILE_SIZE      ((UINT32)(1 << 29))
#define CHASHDB_500M_CFG_ITEM_MAX_NUM   ((UINT32)(1 << 22))
#define CHASHDB_500M_CFG_BUCKET_NUM     ((UINT32)(1 << 22))
#define CHASHDB_500M_CFG_BLOOW_ROW_NUM  ((UINT32)(1 << 11))
#define CHASHDB_500M_CFG_BLOOW_COL_NUM  ((UINT32)(1 << 11))

#define CHASHDB_1G_CFG_FILE_SIZE        ((UINT32)(1 << 30))
#define CHASHDB_1G_CFG_ITEM_MAX_NUM     ((UINT32)(1 << 23))
#define CHASHDB_1G_CFG_BUCKET_NUM       ((UINT32)(1 << 23))
#define CHASHDB_1G_CFG_BLOOW_ROW_NUM    ((UINT32)(1 << 12))
#define CHASHDB_1G_CFG_BLOOW_COL_NUM    ((UINT32)(1 << 11))

#define CHASHDB_2G_CFG_FILE_SIZE        ((UINT32)(1 << 31))
#define CHASHDB_2G_CFG_ITEM_MAX_NUM     ((UINT32)(1 << 24))
#define CHASHDB_2G_CFG_BUCKET_NUM       ((UINT32)(1 << 24))
#define CHASHDB_2G_CFG_BLOOW_ROW_NUM    ((UINT32)(1 << 12))
#define CHASHDB_2G_CFG_BLOOW_COL_NUM    ((UINT32)(1 << 12))

#define CHASHDB_4K_MODE               ((UINT32) 1)
#define CHASHDB_1M_MODE               ((UINT32) 2)
#define CHASHDB_2M_MODE               ((UINT32) 3)
#define CHASHDB_500M_MODE             ((UINT32) 4)
#define CHASHDB_1G_MODE               ((UINT32) 5)
#define CHASHDB_2G_MODE               ((UINT32) 6)

typedef struct
{
    UINT32      file_size;    /*total file size           */
    UINT32      item_max_num; /*max supported num of items*/
    UINT32      item_cur_num; /*current num of items      */
    UINT32      bucket_num;   /*num of buckets            */

    UINT32      bloom_row_num;/*row num of bloom          */
    UINT32      bloom_col_num;/*col num of bloom          */

    UINT32      bloom_offset; /*bloom filter offset       */
    UINT32      bucket_offset;/*bucket vec offset         */
    UINT32      item_offset;  /*item table offset         */
    UINT32      end_offset;   /*end offset                */

	UINT32      chash_algo_first_id; /*first hash algo func id*/
	UINT32      chash_algo_second_id;/*first hash algo func id*/
} CHASHDB_HEADER;

#define CHASHDB_HEADER_FSIZE(chashdb_header)         ((chashdb_header)->file_size)
#define CHASHDB_HEADER_IMNUM(chashdb_header)         ((chashdb_header)->item_max_num)
#define CHASHDB_HEADER_ICNUM(chashdb_header)         ((chashdb_header)->item_cur_num)
#define CHASHDB_HEADER_BKNUM(chashdb_header)         ((chashdb_header)->bucket_num)
#define CHASHDB_HEADER_BMROW(chashdb_header)         ((chashdb_header)->bloom_row_num)
#define CHASHDB_HEADER_BMCOL(chashdb_header)         ((chashdb_header)->bloom_col_num)
#define CHASHDB_HEADER_BMOFF(chashdb_header)         ((chashdb_header)->bloom_offset)
#define CHASHDB_HEADER_BKOFF(chashdb_header)         ((chashdb_header)->bucket_offset)
#define CHASHDB_HEADER_IOFF(chashdb_header)          ((chashdb_header)->item_offset)
#define CHASHDB_HEADER_EOFF(chashdb_header)          ((chashdb_header)->end_offset)

#define CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header)  ((chashdb_header)->chash_algo_first_id)
#define CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header) ((chashdb_header)->chash_algo_second_id)

typedef struct hashdb
{
    CSTRING *dbname;

	int fd;			/* hashdb fd */
	int rsv;
	CHASHDB_HEADER  *header;	    /* hashdb header */
	CBLOOM          *cbloom;	    /* bloom filter  */
	CHASHDB_BUCKET  *buckets;  	    /* hash buckets  */
	CHASHDB_ITEM    *items;
	CMUTEX           cmutexs[CHASHDB_BUCKET_CMUTEX_MAX_NUM];       /* bucket cmutexs*/

	CHASH_ALGO   chash_algo_first;	    /* hash algo for hash bucket */
	CHASH_ALGO   chash_algo_second;	    /* hash algo for btree in the hash bucket */

    UINT32 base_buff_len;
	UINT8 *base_buff;
} CHASHDB;

#define CHASHDB_DBNAME(chashdb)                 ((chashdb)->dbname)
#define CHASHDB_DBNAME_STR(chashdb)             (cstring_get_str(CHASHDB_DBNAME(chashdb)))
#define CHASHDB_FD(chashdb)                     ((chashdb)->fd)
#define CHASHDB_HDR(chashdb)                    ((chashdb)->header)
#define CHASHDB_CBLOOM(chashdb)                 ((chashdb)->cbloom)
#define CHASHDB_BUCKET_VEC(chashdb)             ((chashdb)->buckets)
#define CHASHDB_ITEM_VEC(chashdb)               ((chashdb)->items)
#define CHASHDB_BUCKET_CMUTEX_VEC(chashdb)      ((chashdb)->cmutexs)
#define CHASHDB_BUCKET_CMUTEX(chashdb, idx)     (&((chashdb)->cmutexs[ (idx) ]))
#define CHASHDB_FIRST_CHASH_ALGO(chashdb)       ((chashdb)->chash_algo_first)
#define CHASHDB_SECOND_CHASH_ALGO(chashdb)      ((chashdb)->chash_algo_second)

#define CHASHDB_FSIZE(chashdb)                  (CHASHDB_HEADER_FSIZE(CHASHDB_HDR(chashdb)))
#define CHASHDB_IMNUM(chashdb)                  (CHASHDB_HEADER_IMNUM(CHASHDB_HDR(chashdb)))
#define CHASHDB_ICNUM(chashdb)                  (CHASHDB_HEADER_ICNUM(CHASHDB_HDR(chashdb)))
#define CHASHDB_BKNUM(chashdb)                  (CHASHDB_HEADER_BKNUM(CHASHDB_HDR(chashdb)))
#define CHASHDB_BMROW(chashdb)                  (CHASHDB_HEADER_BMROW(CHASHDB_HDR(chashdb)))
#define CHASHDB_BMCOL(chashdb)                  (CHASHDB_HEADER_BMCOL(CHASHDB_HDR(chashdb)))
#define CHASHDB_BMOFF(chashdb)                  (CHASHDB_HEADER_BMOFF(CHASHDB_HDR(chashdb)))
#define CHASHDB_BKOFF(chashdb)                  (CHASHDB_HEADER_BKOFF(CHASHDB_HDR(chashdb)))
#define CHASHDB_IOFF(chashdb)                   (CHASHDB_HEADER_IOFF(CHASHDB_HDR(chashdb)) )
#define CHASHDB_EOFF(chashdb)                   (CHASHDB_HEADER_EOFF(CHASHDB_HDR(chashdb)) )
#define CHASHDB_FIRST_CHASH_ALGO_ID(chashdb)    (CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(CHASHDB_HDR(chashdb)) )
#define CHASHDB_SECOND_CHASH_ALGO_ID(chashdb)   (CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(CHASHDB_HDR(chashdb)))
#define CHASHDB_BASE_BUFF(chashdb)              ((chashdb)->base_buff)
#define CHASHDB_BASE_BUFF_LEN(chashdb)          ((chashdb)->base_buff_len)

#define CHASHDB_FIRST_CHASH_ALGO_COMPUTE(chashdb, klen, key)   (CHASHDB_FIRST_CHASH_ALGO(chashdb)(klen, key))
#define CHASHDB_SECOND_CHASH_ALGO_COMPUTE(chashdb, klen, key)  (CHASHDB_SECOND_CHASH_ALGO(chashdb)(klen, key))

#define CHASHDB_BLOOM_ROW_IDX(chashdb, first_hash)          ((first_hash) % CHASHDB_BMROW(chashdb))
#define CHASHDB_BLOOM_COL_IDX(chashdb, second_hash)         ((second_hash) % CHASHDB_BMCOL(chashdb))


EC_BOOL chashdb_inode_init(CHASHDB_INODE *chashdb_inode);

EC_BOOL chashdb_inode_clean(CHASHDB_INODE *chashdb_inode);

EC_BOOL chashdb_inode_clone(const CHASHDB_INODE *chashdb_inode_src, CHASHDB_INODE *chashdb_inode_des);

void chashdb_inode_print(LOG *log, const CHASHDB_INODE *chashdb_inode);

CHASHDB_ITEM *chashdb_item_new();

EC_BOOL chashdb_item_init(CHASHDB_ITEM *chashdb_item);

EC_BOOL chashdb_item_clean(CHASHDB_ITEM *chashdb_item);

EC_BOOL chashdb_item_clone(const CHASHDB_ITEM *chashdb_item_src, CHASHDB_ITEM *chashdb_item_des);

EC_BOOL chashdb_item_free(CHASHDB_ITEM *chashdb_item);

EC_BOOL chashdb_item_set_key(CHASHDB_ITEM *chashdb_item, const UINT32 klen, const UINT8 *key);

void chashdb_item_print(LOG *log, const CHASHDB_ITEM *chashdb_item);

EC_BOOL chashdb_item_load(CHASHDB *chashdb, const UINT32 offset, CHASHDB_ITEM *chashdb_item);

EC_BOOL chashdb_item_flush(CHASHDB *chashdb, const UINT32 offset, const CHASHDB_ITEM *chashdb_item);

EC_BOOL chashdb_item_check(const CHASHDB_ITEM *chashdb_item, const UINT32 klen, const UINT8 *key, const UINT32 second_hash);

/**
*   return -1 when (klen, key, second hash); <  chashdb item
*   return  1 when (klen, key, second hash); >  chashdb item
*   return  0 when (klen, key, second hash); == chashdb item
**/
int chashdb_item_cmp(const CHASHDB_ITEM *chashdb_item, const UINT32 klen, const UINT8 *key, const UINT32 second_hash);

CHASHDB_BUCKET *chashdb_bucket_new();

EC_BOOL chashdb_bucket_init(CHASHDB_BUCKET *chashdb_bucket);

EC_BOOL chashdb_bucket_clean(CHASHDB_BUCKET *chashdb_bucket);

EC_BOOL chashdb_bucket_free(CHASHDB_BUCKET *chashdb_bucket);

void chashdb_bucket_print(LOG *log, const CHASHDB_BUCKET *chashdb_bucket);

EC_BOOL chashdb_bucket_load(CHASHDB *chashdb, const UINT32 offset, CHASHDB_BUCKET *chashdb_bucket);

EC_BOOL chashdb_bucket_flush(const CHASHDB *chashdb, const UINT32 offset, const CHASHDB_BUCKET *chashdb_bucket);

CHASHDB_BUCKET *chashdb_bucket_fetch(const CHASHDB *chashdb, const UINT32 first_hash);

EC_BOOL chashdb_header_init(CHASHDB_HEADER *chashdb_header, const UINT32 item_max_num, const UINT32 item_cur_num, const UINT32 bucket_num, const UINT32 bloom_row_num, const UINT32 bloom_col_num, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id);

EC_BOOL chashdb_header_clone(const CHASHDB_HEADER *chashdb_header_src, CHASHDB_HEADER *chashdb_header_des);

EC_BOOL chashdb_header_clean(CHASHDB_HEADER *chashdb_header);

EC_BOOL chashdb_header_is_valid(const CHASHDB_HEADER *chashdb_header);

void chashdb_header_print(LOG *log, const CHASHDB_HEADER *chashdb_header);

EC_BOOL chashdb_header_create(CHASHDB_HEADER *chashdb_header, const UINT32 chashdb_mode, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id);

EC_BOOL chashdb_header_load(CHASHDB *chashdb, const UINT32 offset, CHASHDB_HEADER *chashdb_header);

EC_BOOL chashdb_header_flush(CHASHDB *chashdb, const UINT32 offset, const CHASHDB_HEADER *chashdb_header);

EC_BOOL chashdb_cbloom_load(CHASHDB *chashdb, const UINT32 offset, const RWSIZE rsize, CBLOOM *chashdb_cbloom);

EC_BOOL chashdb_cbloom_flush(CHASHDB *chashdb, const UINT32 offset, const RWSIZE wsize, const CBLOOM *chashdb_cbloom);

EC_BOOL chashdb_cbloom_word_flush(CHASHDB *chashdb, const UINT32 offset, const UINT32 word_offset, const CBLOOM *chashdb_cbloom);

EC_BOOL chashdb_cbloom_is_set(const CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash);

EC_BOOL chashdb_cbloom_set(CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash);

EC_BOOL chashdb_cbloom_set_and_flush(CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash);

EC_BOOL chashdb_cmutexs_init(CHASHDB *chashdb);

EC_BOOL chashdb_cmutexs_clean(CHASHDB *chashdb);

CHASHDB *chashdb_new(const char *dbname);

EC_BOOL chashdb_init(CHASHDB *chashdb, const char *dbname);

EC_BOOL chashdb_clean(CHASHDB *chashdb);

EC_BOOL chashdb_free(CHASHDB *chashdb);

EC_BOOL chashdb_is_full(const CHASHDB *chashdb);

void chashdb_print_buckets(LOG *log, const UINT32 bucket_num, const CHASHDB_BUCKET *chashdb_bucket_vec);

void chashdb_print(LOG *log, const CHASHDB *chashdb);

EC_BOOL chashdb_buff_flush(const CHASHDB *chashdb, const UINT32 offset, const RWSIZE wsize, const UINT8 *buff);

EC_BOOL chashdb_buff_load(const CHASHDB *chashdb, const UINT32 offset, const RWSIZE rsize, UINT8 *buff);

EC_BOOL chashdb_link(CHASHDB *chashdb, const CHASHDB_HEADER *chashdb_header, const UINT32 base_buff_len, const UINT8 *base_buff);

EC_BOOL chashdb_ahead_create(CHASHDB *chashdb, const CHASHDB_HEADER *chashdb_header, const UINT32 base_buff_len, const UINT8 *base_buff);

EC_BOOL chashdb_ahead_flush(const CHASHDB *chashdb);

EC_BOOL chashdb_ahead_load(CHASHDB *chashdb);

CHASHDB_ITEM * chasdb_find_item_by_key(const CHASHDB *chashdb, const UINT32 klen, const UINT8 *key, const UINT32 first_hash, const UINT32 second_hash);

EC_BOOL chashdb_insert_item_by_key(CHASHDB *chashdb, const UINT32 klen, const UINT8 *key, const UINT32 first_hash, const UINT32 second_hash, const CHASHDB_ITEM *chashdb_item_insert);

EC_BOOL chashdb_set(CHASHDB *chashdb, const UINT32 klen, const UINT8 *key, const UINT32 vlen, const UINT8 *value, const UINT32 replica_num);

EC_BOOL chashdb_get(const CHASHDB *chashdb, const UINT32 klen, const UINT8 *key,  UINT32 *vlen, UINT8 **value);

EC_BOOL chashdb_flush(const CHASHDB *chashdb);

EC_BOOL chashdb_load(CHASHDB *chashdb);

EC_BOOL chashdb_unlink(const char *dbname);

CHASHDB *chashdb_open(const char *dbname);

EC_BOOL chashdb_close(CHASHDB *chashdb);

EC_BOOL chashdb_close_with_flush(CHASHDB *chashdb);

EC_BOOL chashdb_create(const char *dbname, const UINT32 chashdb_mode, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id);

EC_BOOL chashdb_show(LOG *log, const char *dbname);

void chashdb_set_test(const char *dbname);

void chashdb_get_test(const char *dbname);

void chashdb_test();

#endif/* _CHASHDB_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/
