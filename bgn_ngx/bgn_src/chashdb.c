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
#include "mm.h"
#include "log.h"
#include "cmpic.inc"
#include "cmutex.h"
#include "cstring.h"
#include "cmisc.h"

#include "cbloom.h"
#include "chashdb.h"
#include "chashalgo.h"

void chashdb_init_buff(UINT8 *buff, const UINT32 len)
{
    UINT32 pos;

    for(pos = 0; pos < len; pos ++)
    {
        buff[ pos ] = '\0';
    }
    return;
}

void chashdb_clean_buff(UINT8 *buff, const UINT32 len)
{
    UINT32 pos;

    for(pos = 0; pos < len; pos ++)
    {
        buff[ pos ] = '\0';
    }
    return;
}

void chashdb_copy_buff(const UINT8 *src_buff, const UINT32 src_len, UINT8 *des_buff, const UINT32 max_len, UINT32 *len)
{
    UINT32 pos;

    for(pos = 0; pos < src_len && pos < max_len; pos ++)
    {
        des_buff[ pos ] = src_buff[ pos ];
    }
    (*len) = pos;
    return;
}

void chashdb_print_buff_0(LOG *log, const UINT8 *buff, const UINT32 len)
{
    UINT32 pos;

    for(pos = 0; pos < len; pos ++)
    {
        sys_print(log, "%02x,", buff[ pos ]);
    }
    return;
}

void chashdb_print_buff(LOG *log, const UINT8 *buff, const UINT32 len)
{
    sys_print(log, "%.*s", len, (char *)buff);
    return;
}
#if 0
CHASHDB_INODE *chashdb_inode_new()
{
    CHASHDB_INODE *chashdb_inode;

    alloc_static_mem(MM_CHASHDB_INODE, &chashdb_inode, LOC_CHASHDB_0001);
    chashdb_inode_init(chashdb_inode);
    return (chashdb_inode);
}
#endif
EC_BOOL chashdb_inode_init(CHASHDB_INODE *chashdb_inode)
{
    CHASHDB_INODE_TCID(chashdb_inode) = CMPI_ERROR_TCID;
    CHASHDB_INODE_PATH(chashdb_inode) = CHASHDB_ERR_PATH;
    CHASHDB_INODE_FOFF(chashdb_inode) = CHASHDB_ERR_OFFSET;
    return (EC_TRUE);
}

EC_BOOL chashdb_inode_clean(CHASHDB_INODE *chashdb_inode)
{
    CHASHDB_INODE_TCID(chashdb_inode) = CMPI_ERROR_TCID;
    CHASHDB_INODE_PATH(chashdb_inode) = CHASHDB_ERR_PATH;
    CHASHDB_INODE_FOFF(chashdb_inode) = CHASHDB_ERR_OFFSET;
    return (EC_TRUE);
}
#if 0
EC_BOOL chashdb_inode_free(CHASHDB_INODE *chashdb_inode)
{
    if(NULL_PTR != chashdb_inode)
    {
        chashdb_inode_clean(chashdb_inode);
        free_static_mem(MM_CHASHDB_INODE, chashdb_inode, LOC_CHASHDB_0002);
    }
    return (EC_TRUE);
}
#endif
EC_BOOL chashdb_inode_clone(const CHASHDB_INODE *chashdb_inode_src, CHASHDB_INODE *chashdb_inode_des)
{
    CHASHDB_INODE_TCID(chashdb_inode_des) = CHASHDB_INODE_TCID(chashdb_inode_src);
    CHASHDB_INODE_PATH(chashdb_inode_des) = CHASHDB_INODE_PATH(chashdb_inode_src);
    CHASHDB_INODE_FOFF(chashdb_inode_des) = CHASHDB_INODE_FOFF(chashdb_inode_src);
    return (EC_TRUE);
}

void chashdb_inode_print(LOG *log, const CHASHDB_INODE *chashdb_inode)
{
    sys_print(log, "(tcid %s, path %lx, offset %ld) ",
                 c_word_to_ipv4(CHASHDB_INODE_TCID(chashdb_inode)),
                 CHASHDB_INODE_PATH(chashdb_inode),
                 CHASHDB_INODE_FOFF(chashdb_inode)
             );
    return;
}

CHASHDB_ITEM *chashdb_item_new()
{
    CHASHDB_ITEM *chashdb_item;

    alloc_static_mem(MM_CHASHDB_ITEM, &chashdb_item, LOC_CHASHDB_0003);
    chashdb_item_init(chashdb_item);
    return (chashdb_item);
}

EC_BOOL chashdb_item_init(CHASHDB_ITEM *chashdb_item)
{
    UINT32 pos;
    UINT8 *key;

    CHASHDB_ITEM_FLAG(chashdb_item)             = CHASHDB_ITEM_FILE_IS_ERR;
    CHASHDB_ITEM_STAT(chashdb_item)             = CHASHDB_ITEM_STAT_IS_ERR;
    CHASHDB_ITEM_KLEN(chashdb_item)             = 0;
    CHASHDB_ITEM_SHASH(chashdb_item)            = 0;
    CHASHDB_ITEM_SHASH_NEXT(chashdb_item)       = 0;
    CHASHDB_ITEM_BROTHER_NEXT(chashdb_item)     = 0;
    CHASHDB_ITEM_SON_NEXT(chashdb_item)         = 0;
    CHASHDB_ITEM_DLEN(chashdb_item)             = 0;
    CHASHDB_ITEM_DREPLICA_NUM(chashdb_item)     = 0;

    key = CHASHDB_ITEM_KEY(chashdb_item);
    for(pos = 0; pos < CHASHDB_KEY_MAX_SIZE; pos ++)
    {
        key[ pos ] = '\0';
    }

    for(pos = 0; pos < CHASHDB_DATA_REPLICA_MAX_NUM; pos ++)
    {
        chashdb_inode_init(CHASHDB_ITEM_DATA_NODE(chashdb_item, pos));
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_item_clean(CHASHDB_ITEM *chashdb_item)
{
    UINT32 pos;
    UINT8 *key;

    CHASHDB_ITEM_FLAG(chashdb_item)             = CHASHDB_ITEM_FILE_IS_ERR;
    CHASHDB_ITEM_STAT(chashdb_item)             = CHASHDB_ITEM_STAT_IS_ERR;
    CHASHDB_ITEM_KLEN(chashdb_item)             = 0;
    CHASHDB_ITEM_SHASH(chashdb_item)            = 0;
    CHASHDB_ITEM_SHASH_NEXT(chashdb_item)       = 0;
    CHASHDB_ITEM_BROTHER_NEXT(chashdb_item)     = 0;
    CHASHDB_ITEM_SON_NEXT(chashdb_item)         = 0;
    CHASHDB_ITEM_DLEN(chashdb_item)             = 0;
    CHASHDB_ITEM_DREPLICA_NUM(chashdb_item)     = 0;

    key = CHASHDB_ITEM_KEY(chashdb_item);
    for(pos = 0; pos < CHASHDB_KEY_MAX_SIZE; pos ++)
    {
        key[ pos ] = '\0';
    }

    for(pos = 0; pos < CHASHDB_DATA_REPLICA_MAX_NUM; pos ++)
    {
        chashdb_inode_init(CHASHDB_ITEM_DATA_NODE(chashdb_item, pos));
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_item_clone(const CHASHDB_ITEM *chashdb_item_src, CHASHDB_ITEM *chashdb_item_des)
{
    UINT32 pos;

    CHASHDB_ITEM_FLAG(chashdb_item_des)             =   CHASHDB_ITEM_FLAG(chashdb_item_src)        ;
    CHASHDB_ITEM_STAT(chashdb_item_des)             =   CHASHDB_ITEM_STAT(chashdb_item_src)        ;
    CHASHDB_ITEM_KLEN(chashdb_item_des)             =   CHASHDB_ITEM_KLEN(chashdb_item_src)        ;
    CHASHDB_ITEM_SHASH(chashdb_item_des)            =   CHASHDB_ITEM_SHASH(chashdb_item_src)       ;
    CHASHDB_ITEM_SHASH_NEXT(chashdb_item_des)       =   CHASHDB_ITEM_SHASH_NEXT(chashdb_item_src)  ;
    CHASHDB_ITEM_BROTHER_NEXT(chashdb_item_des)     =   CHASHDB_ITEM_BROTHER_NEXT(chashdb_item_src);
    CHASHDB_ITEM_SON_NEXT(chashdb_item_des)         =   CHASHDB_ITEM_SON_NEXT(chashdb_item_src)    ;
    CHASHDB_ITEM_DLEN(chashdb_item_des)             =   CHASHDB_ITEM_DLEN(chashdb_item_src)        ;
    CHASHDB_ITEM_DREPLICA_NUM(chashdb_item_des)     =   CHASHDB_ITEM_DREPLICA_NUM(chashdb_item_src);

    for(pos = 0; pos < CHASHDB_ITEM_KLEN(chashdb_item_src); pos ++)
    {
        CHASHDB_ITEM_KEY(chashdb_item_des)[ pos ] = CHASHDB_ITEM_KEY(chashdb_item_src)[ pos ];
    }

    for(pos = 0; pos < CHASHDB_ITEM_DREPLICA_NUM(chashdb_item_src); pos ++)
    {
        chashdb_inode_clone(CHASHDB_ITEM_DATA_NODE(chashdb_item_src, pos), CHASHDB_ITEM_DATA_NODE(chashdb_item_des, pos));
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_item_free(CHASHDB_ITEM *chashdb_item)
{
    if(NULL_PTR != chashdb_item)
    {
        chashdb_item_clean(chashdb_item);
        free_static_mem(MM_CHASHDB_ITEM, chashdb_item, LOC_CHASHDB_0004);
    }
    return (EC_TRUE);
}

EC_BOOL chashdb_item_set_key(CHASHDB_ITEM *chashdb_item, const UINT32 klen, const UINT8 *key)
{
    UINT32 pos;

    for(pos = 0; pos < klen && pos < CHASHDB_KEY_MAX_SIZE; pos ++)
    {
        CHASHDB_ITEM_KEY(chashdb_item)[ pos ] = key[ pos ];
    }
    CHASHDB_ITEM_KLEN(chashdb_item) = pos;

    return (EC_TRUE);
}

void chashdb_item_print(LOG *log, const CHASHDB_ITEM *chashdb_item)
{
    UINT32 pos;
#if 1
    sys_print(log, "chashdb_item %lx: flag %ld, stat %ld, klen %ld, shash %ld, shash next %ld, brother next %ld, son next %ld, data len %ld, data replicas %ld\n",
                    chashdb_item,
                    CHASHDB_ITEM_FLAG(chashdb_item),
                    CHASHDB_ITEM_STAT(chashdb_item),
                    CHASHDB_ITEM_KLEN(chashdb_item),
                    CHASHDB_ITEM_SHASH(chashdb_item),
                    CHASHDB_ITEM_SHASH_NEXT(chashdb_item),
                    CHASHDB_ITEM_BROTHER_NEXT(chashdb_item),
                    CHASHDB_ITEM_SON_NEXT(chashdb_item),
                    CHASHDB_ITEM_DLEN(chashdb_item),
                    CHASHDB_ITEM_DREPLICA_NUM(chashdb_item)
                    );

    sys_log(log, "key: ");
    for(pos = 0; pos < CHASHDB_ITEM_KLEN(chashdb_item); pos ++)
    {
        sys_print(log, "%c", (char)(CHASHDB_ITEM_KEY(chashdb_item)[ pos ]));
    }
    sys_print(log, "\n");
#if 0
    sys_log(log, "replicas: ");
    for(pos = 0; pos < CHASHDB_ITEM_DREPLICA_NUM(chashdb_item); pos ++)
    {
        chashdb_inode_print(log, CHASHDB_ITEM_DATA_NODE(chashdb_item, pos));
    }
    sys_print(log, "\n");
#endif
#endif

#if 0
    sys_print(log, "chashdb_item %lx: klen %ld, vlen %ld, tlen %ld, shash %ld, soff %u, loff %u, roff %u\n",
                    chashdb_item,
                    CHASHDB_ITEM_KLEN(chashdb_item),
                    CHASHDB_ITEM_VLEN(chashdb_item),
                    CHASHDB_ITEM_TLEN(chashdb_item),
                    CHASHDB_ITEM_SHASH(chashdb_item),
                    CHASHDB_ITEM_SOFFSET(chashdb_item),
                    CHASHDB_ITEM_LOFFSET(chashdb_item),
                    CHASHDB_ITEM_ROFFSET(chashdb_item)
                    );

    sys_log(log, "chashdb_item %lx: key = ", chashdb_item);
    chashdb_print_buff(log, CHASHDB_ITEM_KEY(chashdb_item), CHASHDB_ITEM_KLEN(chashdb_item));
    sys_print(log, "\n");

    sys_log(log, "chashdb_item %lx: value = ", chashdb_item);
    chashdb_print_buff(log, CHASHDB_ITEM_VALUE(chashdb_item), CHASHDB_ITEM_VLEN(chashdb_item));
    sys_print(log, "\n");
#endif
    return;
}

EC_BOOL chashdb_item_load(CHASHDB *chashdb, const UINT32 offset, CHASHDB_ITEM *chashdb_item)
{
    RWSIZE rsize;

    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_item_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    rsize = sizeof(CHASHDB_ITEM);
    if(rsize != read(CHASHDB_FD(chashdb), chashdb_item, rsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_item_load: load item from offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_item_flush(CHASHDB *chashdb, const UINT32 offset, const CHASHDB_ITEM *chashdb_item)
{
    RWSIZE wsize;

    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_item_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    wsize = sizeof(CHASHDB_ITEM);
    if(wsize != write(CHASHDB_FD(chashdb), chashdb_item, wsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_item_flush: flush item to offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_item_check(const CHASHDB_ITEM *chashdb_item, const UINT32 klen, const UINT8 *key, const UINT32 second_hash)
{
    if(second_hash != CHASHDB_ITEM_SHASH(chashdb_item))
    {
        return (EC_FALSE);
    }

    if(klen !=  CHASHDB_ITEM_KLEN(chashdb_item))
    {
        return (EC_FALSE);
    }

    if(0 != BCMP(key, CHASHDB_ITEM_KEY(chashdb_item), klen))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*   return -1 when (klen, key, second hash) <  chashdb item
*   return  1 when (klen, key, second hash) >  chashdb item
*   return  0 when (klen, key, second hash) == chashdb item
**/
int chashdb_item_cmp(const CHASHDB_ITEM *chashdb_item, const UINT32 klen, const UINT8 *key, const UINT32 second_hash)
{
    UINT32 pos;
    UINT32 min_len;
    UINT8 *item_key;

    if(second_hash < CHASHDB_ITEM_SHASH(chashdb_item))
    {
        return ((int)-1);
    }

    if(second_hash > CHASHDB_ITEM_SHASH(chashdb_item))
    {
        return ((int) 1);
    }

    min_len  = ((klen < CHASHDB_ITEM_KLEN(chashdb_item)) ? klen : CHASHDB_ITEM_KLEN(chashdb_item));
    item_key = (UINT8 *)CHASHDB_ITEM_KEY(chashdb_item);
    for(pos = 0; pos < min_len; pos ++)
    {
        if(key[ pos ] < item_key[ pos ])
        {
            return ((int)-1);
        }

        if(key[ pos ] > item_key[ pos ])
        {
            return ((int) 1);
        }
    }

    if(klen < CHASHDB_ITEM_KLEN(chashdb_item))
    {
        return ((int)-1);
    }

    if(klen > CHASHDB_ITEM_KLEN(chashdb_item))
    {
        return ((int) 1);
    }

    return (0);
}


CHASHDB_BUCKET *chashdb_bucket_new()
{
    CHASHDB_BUCKET *chashdb_bucket;

    alloc_static_mem(MM_CHASHDB_BUCKET, &chashdb_bucket, LOC_CHASHDB_0005);
    chashdb_bucket_init(chashdb_bucket);
    return (chashdb_bucket);
}

EC_BOOL chashdb_bucket_init(CHASHDB_BUCKET *chashdb_bucket)
{
    CHASHDB_BUCKET_BOFFSET(chashdb_bucket) = 0;
    return (EC_TRUE);
}

EC_BOOL chashdb_bucket_clean(CHASHDB_BUCKET *chashdb_bucket)
{
    CHASHDB_BUCKET_BOFFSET(chashdb_bucket) = 0;
    return (EC_TRUE);
}

EC_BOOL chashdb_bucket_free(CHASHDB_BUCKET *chashdb_bucket)
{
    chashdb_bucket_clean(chashdb_bucket);
    free_static_mem(MM_CHASHDB_BUCKET, chashdb_bucket, LOC_CHASHDB_0006);
    return (EC_TRUE);
}

void chashdb_bucket_print(LOG *log, const CHASHDB_BUCKET *chashdb_bucket)
{
    sys_print(log, "offset: %u\n", CHASHDB_BUCKET_BOFFSET(chashdb_bucket));
    return;
}

EC_BOOL chashdb_bucket_load(CHASHDB *chashdb, const UINT32 offset, CHASHDB_BUCKET *chashdb_bucket)
{
    RWSIZE rsize;

    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_bucket_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    rsize = sizeof(CHASHDB_BUCKET);
    if(rsize != read(CHASHDB_FD(chashdb), chashdb_bucket, rsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_bucket_load: load bucket from offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_bucket_flush(const CHASHDB *chashdb, const UINT32 offset, const CHASHDB_BUCKET *chashdb_bucket)
{
    RWSIZE wsize;

    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_bucket_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    wsize = sizeof(CHASHDB_BUCKET);
    if(wsize != write(CHASHDB_FD(chashdb), chashdb_bucket, wsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_bucket_flush: flush bucket to offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CHASHDB_BUCKET *chashdb_bucket_fetch(const CHASHDB *chashdb, const UINT32 first_hash)
{
    return (CHASHDB_BUCKET_VEC(chashdb) + (first_hash % (CHASHDB_BKNUM(chashdb))));
}

EC_BOOL chashdb_header_init(CHASHDB_HEADER *chashdb_header, const UINT32 item_max_num, const UINT32 item_cur_num, const UINT32 bucket_num, const UINT32 bloom_row_num, const UINT32 bloom_col_num, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id)
{
    CHASHDB_HEADER_IMNUM(chashdb_header)         = item_max_num;
    CHASHDB_HEADER_ICNUM(chashdb_header)         = item_cur_num;
    CHASHDB_HEADER_BKNUM(chashdb_header)         = bucket_num;
    CHASHDB_HEADER_BMROW(chashdb_header)         = bloom_row_num;
    CHASHDB_HEADER_BMCOL(chashdb_header)         = bloom_col_num;
    CHASHDB_HEADER_BMOFF(chashdb_header)         = sizeof(CHASHDB_HEADER);
    CHASHDB_HEADER_BKOFF(chashdb_header)         = CHASHDB_HEADER_BMOFF(chashdb_header)
                                                 + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(bloom_row_num * bloom_col_num));
    CHASHDB_HEADER_IOFF(chashdb_header)          = CHASHDB_HEADER_BKOFF(chashdb_header)
                                                 + bucket_num * sizeof(CHASHDB_BUCKET);
    CHASHDB_HEADER_EOFF(chashdb_header)          = CHASHDB_HEADER_IOFF(chashdb_header)
                                                 + item_cur_num * sizeof(CHASHDB_ITEM);
    CHASHDB_HEADER_FSIZE(chashdb_header)         = CHASHDB_HEADER_IOFF(chashdb_header)
                                                 + item_max_num * sizeof(CHASHDB_ITEM);

    CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header)   = first_chash_algo_id;
    CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header)  = second_chash_algo_id;

    return (EC_TRUE);
}

EC_BOOL chashdb_header_clone(const CHASHDB_HEADER *chashdb_header_src, CHASHDB_HEADER *chashdb_header_des)
{
    CHASHDB_HEADER_FSIZE(chashdb_header_des)        = CHASHDB_HEADER_FSIZE(chashdb_header_src);
    CHASHDB_HEADER_IMNUM(chashdb_header_des)        = CHASHDB_HEADER_IMNUM(chashdb_header_src);
    CHASHDB_HEADER_ICNUM(chashdb_header_des)        = CHASHDB_HEADER_ICNUM(chashdb_header_src);
    CHASHDB_HEADER_BKNUM(chashdb_header_des)        = CHASHDB_HEADER_BKNUM(chashdb_header_src);
    CHASHDB_HEADER_BMROW(chashdb_header_des)        = CHASHDB_HEADER_BMROW(chashdb_header_src);
    CHASHDB_HEADER_BMCOL(chashdb_header_des)        = CHASHDB_HEADER_BMCOL(chashdb_header_src);
    CHASHDB_HEADER_BMOFF(chashdb_header_des)        = CHASHDB_HEADER_BMOFF(chashdb_header_src);
    CHASHDB_HEADER_BKOFF(chashdb_header_des)        = CHASHDB_HEADER_BKOFF(chashdb_header_src);
    CHASHDB_HEADER_IOFF(chashdb_header_des)         = CHASHDB_HEADER_IOFF(chashdb_header_src) ;
    CHASHDB_HEADER_EOFF(chashdb_header_des)         = CHASHDB_HEADER_EOFF(chashdb_header_src) ;
    CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header_des)   = CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header_src) ;
    CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header_des)  = CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header_src);

    return (EC_TRUE);
}

EC_BOOL chashdb_header_clean(CHASHDB_HEADER *chashdb_header)
{
    CHASHDB_HEADER_FSIZE(chashdb_header)   = 0;
    CHASHDB_HEADER_IMNUM(chashdb_header)   = 0;
    CHASHDB_HEADER_ICNUM(chashdb_header)   = 0;
    CHASHDB_HEADER_BKNUM(chashdb_header)   = 0;
    CHASHDB_HEADER_BMROW(chashdb_header)   = 0;
    CHASHDB_HEADER_BMCOL(chashdb_header)   = 0;
    CHASHDB_HEADER_BMOFF(chashdb_header)   = 0;
    CHASHDB_HEADER_BKOFF(chashdb_header)   = 0;
    CHASHDB_HEADER_IOFF(chashdb_header)    = 0;
    CHASHDB_HEADER_EOFF(chashdb_header)    = 0;

    CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header)   = CHASH_ERR_ALGO_ID;
    CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header)  = CHASH_ERR_ALGO_ID;

    return (EC_TRUE);
}

EC_BOOL chashdb_header_is_valid(const CHASHDB_HEADER *chashdb_header)
{
    if(
        CHASHDB_HEADER_ICNUM(chashdb_header) > CHASHDB_HEADER_IMNUM(chashdb_header)
    )
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid item cur num %ld to max num %ld\n",
                            CHASHDB_HEADER_ICNUM(chashdb_header),
                            CHASHDB_HEADER_IMNUM(chashdb_header));
        return (EC_FALSE);
    }

    if(
        CHASHDB_HEADER_BKNUM(chashdb_header) > CHASHDB_HEADER_IMNUM(chashdb_header)
    )
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid bucket num %ld to item max num %ld\n",
                            CHASHDB_HEADER_BKNUM(chashdb_header),
                            CHASHDB_HEADER_IMNUM(chashdb_header));
        return (EC_FALSE);
    }

    if(
        sizeof(CHASHDB_HEADER) != CHASHDB_HEADER_BMOFF(chashdb_header)
    )
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid bloom offset %ld\n",
                            CHASHDB_HEADER_BMOFF(chashdb_header));
        return (EC_FALSE);
    }

    if(
        CHASHDB_HEADER_BMOFF(chashdb_header)
        + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(CHASHDB_HEADER_BMROW(chashdb_header) * CHASHDB_HEADER_BMCOL(chashdb_header)))
        != CHASHDB_HEADER_BKOFF(chashdb_header)
    )
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid bucket offset %ld to bloom row num %ld, bloom col num %ld and bloom offset %ld\n",
                            CHASHDB_HEADER_BKOFF(chashdb_header),
                            CHASHDB_HEADER_BMROW(chashdb_header),
                            CHASHDB_HEADER_BMCOL(chashdb_header),
                            CHASHDB_HEADER_BMOFF(chashdb_header));
        return (EC_FALSE);
    }

    if(
        CHASHDB_HEADER_BKOFF(chashdb_header) + CHASHDB_HEADER_BKNUM(chashdb_header) * sizeof(CHASHDB_BUCKET)
        != CHASHDB_HEADER_IOFF(chashdb_header)
    )
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid item offset %ld to bucket num %ld and bucket offset %ld\n",
                            CHASHDB_HEADER_IOFF(chashdb_header),
                            CHASHDB_HEADER_BKNUM(chashdb_header),
                            CHASHDB_HEADER_BKOFF(chashdb_header));
        return (EC_FALSE);
    }

#if 1/*ATTENTION: EOFF checking only works for fixed-width item, but not for flexiable width item !!!*/
    if(
        CHASHDB_HEADER_IOFF(chashdb_header) + CHASHDB_HEADER_ICNUM(chashdb_header) * sizeof(CHASHDB_ITEM)
        != CHASHDB_HEADER_EOFF(chashdb_header)
    )
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid end off %ld to item cur num %ld and item offset %ld\n",
                            CHASHDB_HEADER_EOFF(chashdb_header),
                            CHASHDB_HEADER_ICNUM(chashdb_header),
                            CHASHDB_HEADER_IOFF(chashdb_header));
        return (EC_FALSE);
    }

    if(
        CHASHDB_HEADER_IOFF(chashdb_header) + CHASHDB_HEADER_IMNUM(chashdb_header) * sizeof(CHASHDB_ITEM)
        != CHASHDB_HEADER_FSIZE(chashdb_header)
    )
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid file size %ld to item max num %ld and item offset %ld\n",
                            CHASHDB_HEADER_FSIZE(chashdb_header),
                            CHASHDB_HEADER_IMNUM(chashdb_header),
                            CHASHDB_HEADER_IOFF(chashdb_header));
        return (EC_FALSE);
    }
#endif

    if(0 < (CHASHDB_HEADER_EOFF(chashdb_header) >> (WORDSIZE - 1)))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: end offset %ld overflow\n", CHASHDB_HEADER_EOFF(chashdb_header));
        return (EC_FALSE);
    }

    if(0 < (CHASHDB_HEADER_FSIZE(chashdb_header) >> (WORDSIZE - 1)))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: file size %ld overflow\n",
                    CHASHDB_HEADER_FSIZE(chashdb_header));
        return (EC_FALSE);
    }

    if(CHASH_ERR_ALGO_ID == CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid first hash algo id %ld\n",
                            CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header));
        return (EC_FALSE);
    }

    if(CHASH_ERR_ALGO_ID == CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_is_valid: invalid second hash algo id %ld\n",
                            CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


void chashdb_header_print(LOG *log, const CHASHDB_HEADER *chashdb_header)
{
    sys_log(log, "item max num %ld, item cur num %ld, bucket num %ld, "
                 "bloom row num %ld, bloom col num %ld, bloom offset %ld, "
                 "bucket offset %ld, item offset %ld, end offset %ld, "
                 "file size %ld, first hash algo id %ld, second hash algo id %ld\n",
                CHASHDB_HEADER_IMNUM(chashdb_header) ,
                CHASHDB_HEADER_ICNUM(chashdb_header) ,
                CHASHDB_HEADER_BKNUM(chashdb_header)   ,
                CHASHDB_HEADER_BMROW(chashdb_header),
                CHASHDB_HEADER_BMCOL(chashdb_header),
                CHASHDB_HEADER_BMOFF(chashdb_header) ,
                CHASHDB_HEADER_BKOFF(chashdb_header),
                CHASHDB_HEADER_IOFF(chashdb_header)  ,
                CHASHDB_HEADER_EOFF(chashdb_header)   ,
                CHASHDB_HEADER_FSIZE(chashdb_header)   ,
                CHASHDB_HEADER_FIRST_CHASH_ALGO_ID(chashdb_header),
                CHASHDB_HEADER_SECOND_CHASH_ALGO_ID(chashdb_header)
        );
    return;
}

EC_BOOL chashdb_header_create(CHASHDB_HEADER *chashdb_header, const UINT32 chashdb_mode, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id)
{
    switch(chashdb_mode)
    {
        case CHASHDB_4K_MODE:
        return chashdb_header_init(chashdb_header,
                                   CHASHDB_4K_CFG_ITEM_MAX_NUM,
                                   0,
                                   CHASHDB_4K_CFG_BUCKET_NUM,
                                   CHASHDB_4K_CFG_BLOOW_ROW_NUM,
                                   CHASHDB_4K_CFG_BLOOW_COL_NUM,
                                   first_chash_algo_id,
                                   second_chash_algo_id);
        case CHASHDB_1M_MODE:
        return chashdb_header_init(chashdb_header,
                                   CHASHDB_1M_CFG_ITEM_MAX_NUM,
                                   0,
                                   CHASHDB_1M_CFG_BUCKET_NUM,
                                   CHASHDB_1M_CFG_BLOOW_ROW_NUM,
                                   CHASHDB_1M_CFG_BLOOW_COL_NUM,
                                   first_chash_algo_id,
                                   second_chash_algo_id);
        case CHASHDB_2M_MODE:
        return chashdb_header_init(chashdb_header,
                                   CHASHDB_2M_CFG_ITEM_MAX_NUM,
                                   0,
                                   CHASHDB_2M_CFG_BUCKET_NUM,
                                   CHASHDB_2M_CFG_BLOOW_ROW_NUM,
                                   CHASHDB_2M_CFG_BLOOW_COL_NUM,
                                   first_chash_algo_id,
                                   second_chash_algo_id);
        case CHASHDB_500M_MODE:
        return chashdb_header_init(chashdb_header,
                                   CHASHDB_500M_CFG_ITEM_MAX_NUM,
                                   0,
                                   CHASHDB_500M_CFG_BUCKET_NUM,
                                   CHASHDB_500M_CFG_BLOOW_ROW_NUM,
                                   CHASHDB_500M_CFG_BLOOW_COL_NUM,
                                   first_chash_algo_id,
                                   second_chash_algo_id);
        case CHASHDB_1G_MODE:
        return chashdb_header_init(chashdb_header,
                                   CHASHDB_1G_CFG_ITEM_MAX_NUM,
                                   0,
                                   CHASHDB_1G_CFG_BUCKET_NUM,
                                   CHASHDB_1G_CFG_BLOOW_ROW_NUM,
                                   CHASHDB_1G_CFG_BLOOW_COL_NUM,
                                   first_chash_algo_id,
                                   second_chash_algo_id);
        case CHASHDB_2G_MODE:
        return chashdb_header_init(chashdb_header,
                                   CHASHDB_2G_CFG_ITEM_MAX_NUM,
                                   0,
                                   CHASHDB_2G_CFG_BUCKET_NUM,
                                   CHASHDB_2G_CFG_BLOOW_ROW_NUM,
                                   CHASHDB_2G_CFG_BLOOW_COL_NUM,
                                   first_chash_algo_id,
                                   second_chash_algo_id);
    }
    dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_init_header: invalid chashdb mode %ld\n", chashdb_mode);
    return (EC_FALSE);
}

EC_BOOL chashdb_header_load(CHASHDB *chashdb, const UINT32 offset, CHASHDB_HEADER *chashdb_header)
{
    RWSIZE rsize;

    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    rsize = sizeof(CHASHDB_HEADER);
    if(rsize != read(CHASHDB_FD(chashdb), chashdb_header, rsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_load: load header from offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_header_flush(CHASHDB *chashdb, const UINT32 offset, const CHASHDB_HEADER *chashdb_header)
{
    RWSIZE wsize;

    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    wsize = sizeof(CHASHDB_HEADER);
    if(wsize != write(CHASHDB_FD(chashdb), chashdb_header, wsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_flush: flush header to offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_cbloom_load(CHASHDB *chashdb, const UINT32 offset, const RWSIZE rsize, CBLOOM *chashdb_cbloom)
{
    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_cbloom_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    if(rsize != read(CHASHDB_FD(chashdb), CBLOOM_DATA_BUFF(chashdb_cbloom), rsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_load: load bloom from offset %ld failed where rsize = %u\n",
                        offset, (uint32_t)rsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_cbloom_flush(CHASHDB *chashdb, const UINT32 offset, const RWSIZE wsize, const CBLOOM *chashdb_cbloom)
{
    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_cbloom_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    if(wsize != write(CHASHDB_FD(chashdb), CBLOOM_DATA_BUFF(chashdb_cbloom), wsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_cbloom_flush: flush cbloom to offset %ld failed where wsize = %u\n",
                            offset, (uint32_t)wsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_cbloom_word_flush(CHASHDB *chashdb, const UINT32 offset, const UINT32 word_offset, const CBLOOM *chashdb_cbloom)
{
    RWSIZE wsize;

    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_cbloom_word_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    wsize = sizeof(UINT32);
    if(wsize != write(CHASHDB_FD(chashdb), CBLOOM_DATA_BUFF(chashdb_cbloom) + word_offset, wsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_cbloom_word_flush: "
                                                "flush cbloom to offset %ld failed where wsize = %u\n",
                                                offset, (uint32_t)wsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}
#if 0
EC_BOOL chashdb_cbloom_is_set(const CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash)
{
    if(EC_FALSE == cbloom_check_bit(CHASHDB_CBLOOM(chashdb), (first_hash % CHASHDB_IMNUM(chashdb))))
    {
        return (EC_FALSE);
    }

    if(EC_FALSE == cbloom_check_bit(CHASHDB_CBLOOM(chashdb), (second_hash % CHASHDB_IMNUM(chashdb))))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_cbloom_set(CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash)
{
    cbloom_set_bit(CHASHDB_CBLOOM(chashdb), (first_hash % CHASHDB_IMNUM(chashdb)));
    cbloom_set_bit(CHASHDB_CBLOOM(chashdb), (second_hash % CHASHDB_IMNUM(chashdb)));

    return (EC_TRUE);
}

EC_BOOL chashdb_cbloom_set_and_flush(CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash)
{
    UINT32 word_offset_a;
    UINT32 word_offset_b;
    UINT32 old_a;
    UINT32 old_b;

    old_a = cbloom_set_bit_and_ret_old(CHASHDB_CBLOOM(chashdb), (first_hash % CHASHDB_IMNUM(chashdb)), &word_offset_a);
    old_b = cbloom_set_bit_and_ret_old(CHASHDB_CBLOOM(chashdb), (second_hash % CHASHDB_IMNUM(chashdb)), &word_offset_b);

    if(0 == old_a)
    {
        UINT32 offset;
        offset = CHASHDB_BMOFF(chashdb) + NWORDS_TO_NBYTES(word_offset_a);
        chashdb_cbloom_word_flush(chashdb, offset, word_offset_a, CHASHDB_CBLOOM(chashdb));
    }

    if(0 == old_b && word_offset_b != word_offset_a)
    {
        UINT32 offset;
        offset = CHASHDB_BMOFF(chashdb) + NWORDS_TO_NBYTES(word_offset_b);
        chashdb_cbloom_word_flush(chashdb, offset, word_offset_b, CHASHDB_CBLOOM(chashdb));
    }

    return (EC_TRUE);
}
#endif
#if 1
EC_BOOL chashdb_cbloom_is_set(const CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash)
{
    UINT32 row_idx;
    UINT32 col_idx;
    UINT32 bit_pos;

    row_idx = CHASHDB_BLOOM_ROW_IDX(chashdb, first_hash);
    col_idx = CHASHDB_BLOOM_COL_IDX(chashdb, second_hash);

    bit_pos = (row_idx * CHASHDB_BMROW(chashdb) + CHASHDB_BMCOL(chashdb));
    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDNULL, "[DEBUG] chashdb_cbloom_is_set: (first hash %ld, second hash %ld) => (row idx %ld, col idx %ld) => (bit pos %ld) => %ld\n",
                        first_hash, second_hash, row_idx, col_idx, bit_pos, bit_pos % CBLOOM_MAX_NBIT(CHASHDB_CBLOOM(chashdb)));
    return cbloom_check_bit(CHASHDB_CBLOOM(chashdb), bit_pos);
}

EC_BOOL chashdb_cbloom_set(CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash)
{
    UINT32 row_idx;
    UINT32 col_idx;
    UINT32 bit_pos;

    row_idx = CHASHDB_BLOOM_ROW_IDX(chashdb, first_hash);
    col_idx = CHASHDB_BLOOM_COL_IDX(chashdb, second_hash);

    bit_pos = (row_idx * CHASHDB_BMROW(chashdb) + CHASHDB_BMCOL(chashdb));
    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDNULL, "[DEBUG] chashdb_cbloom_set: (first hash %ld, second hash %ld) => (row idx %ld, col idx %ld) => (bit pos %ld) => %ld\n",
                        first_hash, second_hash, row_idx, col_idx, bit_pos, bit_pos % CBLOOM_MAX_NBIT(CHASHDB_CBLOOM(chashdb)));

    return cbloom_set_bit(CHASHDB_CBLOOM(chashdb), bit_pos);
}

EC_BOOL chashdb_cbloom_set_and_flush(CHASHDB *chashdb, const UINT32 first_hash, const UINT32 second_hash)
{
    UINT32 word_offset;
    UINT32 old;

    UINT32 row_idx;
    //UINT32 col_idx;
    UINT32 bit_pos;

    row_idx = CHASHDB_BLOOM_ROW_IDX(chashdb, first_hash);
    //col_idx = CHASHDB_BLOOM_COL_IDX(chashdb, second_hash);

    bit_pos = (row_idx * CHASHDB_BMROW(chashdb) + CHASHDB_BMCOL(chashdb));

    old = cbloom_set_bit_and_ret_old(CHASHDB_CBLOOM(chashdb), bit_pos, &word_offset);

    if(0 == old)
    {
        UINT32 byte_offset;
        byte_offset = CHASHDB_BMOFF(chashdb) + NWORDS_TO_NBYTES(word_offset);
        chashdb_cbloom_word_flush(chashdb, byte_offset, word_offset, CHASHDB_CBLOOM(chashdb));
    }

    return (EC_TRUE);
}
#endif

EC_BOOL chashdb_cmutexs_init(CHASHDB *chashdb)
{
    UINT32 pos;

    for(pos = 0; pos < CHASHDB_BUCKET_CMUTEX_MAX_NUM; pos ++)
    {
        cmutex_init(CHASHDB_BUCKET_CMUTEX(chashdb, pos), CMUTEX_PROCESS_PRIVATE, LOC_CHASHDB_0007);
    }
    return (EC_TRUE);
}

EC_BOOL chashdb_cmutexs_clean(CHASHDB *chashdb)
{
    UINT32 pos;

    for(pos = 0; pos < CHASHDB_BUCKET_CMUTEX_MAX_NUM; pos ++)
    {
        cmutex_clean(CHASHDB_BUCKET_CMUTEX(chashdb, pos), LOC_CHASHDB_0008);
    }
    return (EC_TRUE);
}

CHASHDB *chashdb_new(const char *dbname)
{
    CHASHDB *chashdb;

    alloc_static_mem(MM_CHASHDB, &chashdb, LOC_CHASHDB_0009);
    chashdb_init(chashdb, dbname);
    return (chashdb);
}

EC_BOOL chashdb_init(CHASHDB *chashdb, const char *dbname)
{
    CHASHDB_DBNAME(chashdb) = cstring_new((UINT8 *)dbname, LOC_CHASHDB_0010);

    CHASHDB_FD(chashdb) = ERR_FD;

    CHASHDB_HDR(chashdb)    = NULL_PTR;
    CHASHDB_CBLOOM(chashdb) = NULL_PTR;

    CHASHDB_BUCKET_VEC(chashdb) = NULL_PTR;
    CHASHDB_ITEM_VEC(chashdb) = NULL_PTR;

    chashdb_cmutexs_init(chashdb);

    CHASHDB_FIRST_CHASH_ALGO(chashdb)  = NULL_PTR;
    CHASHDB_SECOND_CHASH_ALGO(chashdb) = NULL_PTR;

    CHASHDB_BASE_BUFF(chashdb) = NULL_PTR;
    CHASHDB_BASE_BUFF_LEN(chashdb) = 0;

    return (EC_TRUE);
}

EC_BOOL chashdb_clean(CHASHDB *chashdb)
{
    cstring_free(CHASHDB_DBNAME(chashdb));
    CHASHDB_DBNAME(chashdb) = NULL_PTR;

    if(ERR_FD != CHASHDB_FD(chashdb))
    {
        c_file_close(CHASHDB_FD(chashdb));
        CHASHDB_FD(chashdb) = ERR_FD;
    }

    CHASHDB_HDR(chashdb)    = NULL_PTR;
    CHASHDB_CBLOOM(chashdb) = NULL_PTR;/*unlink*/

    CHASHDB_BUCKET_VEC(chashdb) = NULL_PTR;
    CHASHDB_ITEM_VEC(chashdb) = NULL_PTR;

    chashdb_cmutexs_clean(chashdb);

    CHASHDB_FIRST_CHASH_ALGO(chashdb) = NULL_PTR;
    CHASHDB_SECOND_CHASH_ALGO(chashdb) = NULL_PTR;

    if(NULL_PTR != CHASHDB_BASE_BUFF(chashdb))
    {
        SAFE_FREE(CHASHDB_BASE_BUFF(chashdb), LOC_CHASHDB_0011);
        CHASHDB_BASE_BUFF(chashdb) = NULL_PTR;
    }

    CHASHDB_BASE_BUFF_LEN(chashdb) = 0;

    return (EC_TRUE);
}

EC_BOOL chashdb_free(CHASHDB *chashdb)
{
    if(NULL_PTR != chashdb)
    {
        chashdb_clean(chashdb);
        free_static_mem(MM_CHASHDB, chashdb, LOC_CHASHDB_0012);
    }
    return (EC_TRUE);
}

EC_BOOL chashdb_is_full(const CHASHDB *chashdb)
{
    if(CHASHDB_ICNUM(chashdb) >= CHASHDB_IMNUM(chashdb))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void chashdb_print_buckets(LOG *log, const UINT32 bucket_num, const CHASHDB_BUCKET *chashdb_bucket_vec)
{
    UINT32 pos;

    for(pos = 0; pos < bucket_num; pos ++)
    {
        CHASHDB_BUCKET *chashdb_bucket;

        chashdb_bucket = (CHASHDB_BUCKET *)(chashdb_bucket_vec + pos);
        sys_log(log, "bucket %ld# ", pos);
        chashdb_bucket_print(log, chashdb_bucket);
    }
    return;
}

void chashdb_print(LOG *log, const CHASHDB *chashdb)
{
    sys_log(log, "chashdb %lx: dbname: %s\n", chashdb, (char *)CHASHDB_DBNAME_STR(chashdb));

    sys_log(log, "chashdb %lx: header: \n", chashdb);
    chashdb_header_print(log, CHASHDB_HDR(chashdb));

    sys_log(log, "chashdb %lx: bloom fiter: \n", chashdb);
    cbloom_print(log, CHASHDB_CBLOOM(chashdb) );
    sys_print(log, "\n");

    sys_log(log, "chashdb %lx: bucket ec: ", chashdb);
    chashdb_print_buckets(log, CHASHDB_BKNUM(chashdb), CHASHDB_BUCKET_VEC(chashdb));
    sys_print(log, "\n");

    return;
}

EC_BOOL chashdb_buff_flush(const CHASHDB *chashdb, const UINT32 offset, const RWSIZE wsize, const UINT8 *buff)
{
    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_buff_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    if(wsize != write(CHASHDB_FD(chashdb), buff, wsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_header_flush: flush buff to offset %ld failed where wsize %u\n",
                    offset, (uint32_t)wsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_buff_load(const CHASHDB *chashdb, const UINT32 offset, const RWSIZE rsize, UINT8 *buff)
{
    if(ERR_SEEK == lseek(CHASHDB_FD(chashdb), offset, SEEK_SET))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_buff_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    if(rsize != read(CHASHDB_FD(chashdb), buff, rsize))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_buff_load: load buff from offset %ld failed where rsize %d\n",
                            offset, (uint32_t)rsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_link(CHASHDB *chashdb, const CHASHDB_HEADER *chashdb_header, const UINT32 base_buff_len, const UINT8 *base_buff)
{
    if(CHASHDB_HDR(chashdb) !=  (CHASHDB_HEADER *)base_buff)
    {
        CHASHDB_HDR(chashdb) = (CHASHDB_HEADER *)base_buff;
        chashdb_header_clone(chashdb_header, CHASHDB_HDR(chashdb));
    }

    CHASHDB_CBLOOM(chashdb) = (CBLOOM *)(base_buff + CHASHDB_HEADER_BMOFF(chashdb_header));

    CHASHDB_BUCKET_VEC(chashdb) = (CHASHDB_BUCKET *)(base_buff + CHASHDB_HEADER_BKOFF(chashdb_header));
    CHASHDB_ITEM_VEC(chashdb) = (CHASHDB_ITEM *)(base_buff + CHASHDB_HEADER_IOFF(chashdb_header));

    CHASHDB_BASE_BUFF_LEN(chashdb) = base_buff_len;
    CHASHDB_BASE_BUFF(chashdb) = (UINT8 *)base_buff;

    return (EC_TRUE);
}

EC_BOOL chashdb_ahead_create(CHASHDB *chashdb, const CHASHDB_HEADER *chashdb_header, const UINT32 base_buff_len, const UINT8 *base_buff)
{
    UINT32 pos;

    /*validity checking*/
    if(EC_FALSE == chashdb_header_is_valid(chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_ahead_create: invalid header\n");
        return (EC_FALSE);
    }

    /*link & initialize*/
    chashdb_link(chashdb, chashdb_header, base_buff_len, base_buff);
    cbloom_init(CHASHDB_CBLOOM(chashdb));
    for(pos = 0; pos < CHASHDB_BKNUM(chashdb); pos ++)
    {
        CHASHDB_BUCKET *chashdb_bucket;

        chashdb_bucket = (CHASHDB_BUCKET_VEC(chashdb) + pos);
        chashdb_bucket_init(chashdb_bucket);
    }

    /*flush ahead*/
    if(EC_FALSE == chashdb_buff_flush(chashdb, 0, CHASHDB_IOFF(chashdb), CHASHDB_BASE_BUFF(chashdb)))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_ahead_create: flush header failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_ahead_flush(const CHASHDB *chashdb)
{
    if(EC_FALSE == chashdb_buff_flush(chashdb, 0, CHASHDB_IOFF(chashdb), CHASHDB_BASE_BUFF(chashdb)))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_ahead_flush: flush header failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL chashdb_ahead_load(CHASHDB *chashdb)
{
    CHASHDB_HEADER  chashdb_header_t;
    CHASHDB_HEADER *chashdb_header;
    UINT8 *base_buff;
    UINT32 base_buff_len;

    chashdb_header = &chashdb_header_t;

    /*load header*/
    if(EC_FALSE == chashdb_header_load(chashdb, 0, chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_ahead_load: load header failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chashdb_header_is_valid(chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_ahead_load: corrupted header\n");
        return (EC_FALSE);
    }

    base_buff_len = CHASHDB_HEADER_IOFF(chashdb_header);
    base_buff = (UINT8 *)SAFE_MALLOC(base_buff_len, LOC_CHASHDB_0013);
    if(NULL_PTR == base_buff)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_ahead_load: alloc ahead memory failed where item offset %ld\n",
                        CHASHDB_HEADER_IOFF(chashdb_header));
        return (EC_FALSE);
    }

    chashdb_link(chashdb, chashdb_header, base_buff_len, base_buff);

    return (EC_TRUE);
}

CHASHDB_ITEM * chasdb_find_item_by_key(const CHASHDB *chashdb, const UINT32 klen, const UINT8 *key, const UINT32 first_hash, const UINT32 second_hash)
{
    CHASHDB_BUCKET *chashdb_bucket;
    UINT32 offset;

    if(EC_FALSE == chashdb_cbloom_is_set(chashdb, first_hash, second_hash))
    {
        dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDNULL, "[DEBUG] chasdb_find_item_by_key: bloom not set\n");
        return (NULL_PTR);
    }

    chashdb_bucket = chashdb_bucket_fetch(chashdb, first_hash);
    for(offset = CHASHDB_BUCKET_BOFFSET(chashdb_bucket); 0 < offset && offset < CHASHDB_EOFF(chashdb) && offset < CHASHDB_BASE_BUFF_LEN(chashdb); )
    {
        CHASHDB_ITEM   *chashdb_item;
        int cmp;

        chashdb_item = (CHASHDB_ITEM *)(CHASHDB_BASE_BUFF(chashdb) + offset);
        dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDNULL, "[DEBUG] chasdb_find_item_by_key: check: [bucket pos %ld] item (shash %ld, klen %ld, key %s) V.S. second hash %ld, klen %ld, key %s\n",
                            (first_hash % (CHASHDB_BKNUM(chashdb))),
                            CHASHDB_ITEM_SHASH(chashdb_item),
                            (UINT32)CHASHDB_ITEM_KLEN(chashdb_item),
                            (char *)CHASHDB_ITEM_KEY(chashdb_item),
                            second_hash, klen, (char *)key
                            );
        cmp = chashdb_item_cmp(chashdb_item, klen, key, second_hash);
        if(0 == cmp)
        {
            return (chashdb_item);
        }

        /*note: item is organized in increasement order of second hash*/
        if(0 > cmp)
        {
            return (NULL_PTR);
        }

        offset = CHASHDB_ITEM_SHASH_NEXT(chashdb_item);
    }
    return (NULL_PTR);

}

EC_BOOL chashdb_insert_item_by_key(CHASHDB *chashdb, const UINT32 klen, const UINT8 *key, const UINT32 first_hash, const UINT32 second_hash, const CHASHDB_ITEM *chashdb_item_insert)
{
    CHASHDB_BUCKET *chashdb_bucket;
    CHASHDB_ITEM   *chashdb_item_prev;
    UINT32 offset;

    if(CHASHDB_ICNUM(chashdb) >= CHASHDB_IMNUM(chashdb))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_insert_item_by_key: chashdb is full where item cur num %ld and max num %ld\n",
                            CHASHDB_ICNUM(chashdb),
                            CHASHDB_IMNUM(chashdb));
        return (EC_FALSE);
    }

    if(CHASHDB_EOFF(chashdb) + sizeof(CHASHDB_ITEM) > CHASHDB_BASE_BUFF_LEN(chashdb))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_insert_item_by_key: no space to insert item where end offset %ld, buff len %ld\n",
                            CHASHDB_EOFF(chashdb), CHASHDB_BASE_BUFF_LEN(chashdb));
        return (EC_FALSE);
    }

    chashdb_item_prev = NULL_PTR;

    chashdb_bucket = chashdb_bucket_fetch(chashdb, first_hash);
    for(offset = CHASHDB_BUCKET_BOFFSET(chashdb_bucket); 0 < offset && offset < CHASHDB_EOFF(chashdb) && offset < CHASHDB_BASE_BUFF_LEN(chashdb); )
    {
        CHASHDB_ITEM   *chashdb_item;
        int cmp;

        chashdb_item = (CHASHDB_ITEM *)(CHASHDB_BASE_BUFF(chashdb) + offset);

        /*note: item is organized in increasement order of second hash*/
        cmp = chashdb_item_cmp(chashdb_item, klen, key, second_hash);
        if(0 == cmp)
        {
            dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_insert_item_by_key: found collision\n");
            return (EC_FALSE);
        }

        if(0 > cmp)
        {
            break;
        }

        chashdb_item_prev = chashdb_item;
        offset = CHASHDB_ITEM_SHASH_NEXT(chashdb_item);
    }


    if(NULL_PTR == chashdb_item_prev)
    {
        CHASHDB_ITEM   *chashdb_item;

        chashdb_item = (CHASHDB_ITEM *)(CHASHDB_BASE_BUFF(chashdb) + CHASHDB_EOFF(chashdb));
        chashdb_item_clone(chashdb_item_insert, chashdb_item);
        CHASHDB_ITEM_SHASH_NEXT(chashdb_item) = CHASHDB_BUCKET_BOFFSET(chashdb_bucket);
        CHASHDB_BUCKET_BOFFSET(chashdb_bucket) = CHASHDB_EOFF(chashdb);/*first one item of bucket*/
        CHASHDB_EOFF(chashdb) += sizeof(CHASHDB_ITEM);
        chashdb_cbloom_set(chashdb, first_hash, second_hash);
        CHASHDB_ICNUM(chashdb) ++;
    }
    else
    {
        CHASHDB_ITEM   *chashdb_item;

        chashdb_item = (CHASHDB_ITEM *)(CHASHDB_BASE_BUFF(chashdb) + CHASHDB_EOFF(chashdb));
        chashdb_item_clone(chashdb_item_insert, chashdb_item);
        CHASHDB_ITEM_SHASH_NEXT(chashdb_item) = CHASHDB_ITEM_SHASH_NEXT(chashdb_item_prev);
        CHASHDB_ITEM_SHASH_NEXT(chashdb_item_prev) = CHASHDB_EOFF(chashdb);
        CHASHDB_EOFF(chashdb) += sizeof(CHASHDB_ITEM);
        chashdb_cbloom_set(chashdb, first_hash, second_hash);
        CHASHDB_ICNUM(chashdb) ++;
    }

    return (EC_TRUE);
}

EC_BOOL chashdb_set(CHASHDB *chashdb, const UINT32 klen, const UINT8 *key, const UINT32 vlen, const UINT8 *value, const UINT32 replica_num)
{
    CHASHDB_ITEM * chashdb_item;

    UINT32 first_hash;
    UINT32 second_hash;

    UINT32 pos;

    if(CHASHDB_KEY_MAX_SIZE < klen)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_set: klen %ld overflow\n", klen);
        return (EC_FALSE);
    }

    chashdb_item = chashdb_item_new();
    if(NULL_PTR == chashdb_item)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_set: new item failed\n");
        return (EC_FALSE);
    }

    first_hash  = CHASHDB_FIRST_CHASH_ALGO_COMPUTE(chashdb, klen, key);
    second_hash = CHASHDB_SECOND_CHASH_ALGO_COMPUTE(chashdb, klen, key);

    CHASHDB_ITEM_FLAG(chashdb_item)             = CHASHDB_ITEM_FILE_IS_REG;
    CHASHDB_ITEM_STAT(chashdb_item)             = CHASHDB_ITEM_STAT_IS_CACHED;
    CHASHDB_ITEM_KLEN(chashdb_item)             = klen;
    CHASHDB_ITEM_SHASH(chashdb_item)            = second_hash;
    CHASHDB_ITEM_SHASH_NEXT(chashdb_item)       = 0;
    CHASHDB_ITEM_BROTHER_NEXT(chashdb_item)     = 0;
    CHASHDB_ITEM_SON_NEXT(chashdb_item)         = 0;
    CHASHDB_ITEM_DLEN(chashdb_item)             = vlen;
    CHASHDB_ITEM_DREPLICA_NUM(chashdb_item)     = replica_num;

    chashdb_item_set_key(chashdb_item, klen, key);

    for(pos = 0; pos < CHASHDB_DATA_REPLICA_MAX_NUM; pos ++)
    {
        chashdb_inode_init(CHASHDB_ITEM_DATA_NODE(chashdb_item, pos));
    }

    if(EC_FALSE == chashdb_insert_item_by_key(chashdb, klen, key, first_hash, second_hash, chashdb_item))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_set: set item failed where klen %ld, key %s\n", klen, (char *)key);
        chashdb_item_free(chashdb_item);
        return (EC_FALSE);
    }

    chashdb_item_free(chashdb_item);
    return (EC_TRUE);
}

EC_BOOL chashdb_get(const CHASHDB *chashdb, const UINT32 klen, const UINT8 *key,  UINT32 *vlen, UINT8 **value)
{
    CHASHDB_ITEM   *chashdb_item;

    UINT32 first_hash;
    UINT32 second_hash;

    first_hash  = CHASHDB_FIRST_CHASH_ALGO(chashdb)(klen, key);
    second_hash = CHASHDB_SECOND_CHASH_ALGO(chashdb)(klen, key);

    chashdb_item = chasdb_find_item_by_key(chashdb, klen, key, first_hash, second_hash);
    if(NULL_PTR == chashdb_item)
    {
        return (EC_FALSE);
    }

    (*vlen)  = CHASHDB_ITEM_DLEN(chashdb_item);
    (*value) = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL chashdb_flush(const CHASHDB *chashdb)
{
    UINT32 wsize;

    wsize = CHASHDB_EOFF(chashdb);/*general expectation wsize*/
    if(wsize > CHASHDB_BASE_BUFF_LEN(chashdb))/*adjust wsize if need*/
    {
        wsize = CHASHDB_BASE_BUFF_LEN(chashdb);
    }

    if(0 < (wsize >> (WORDSIZE - 1)))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_flush: wsize %lx overflow\n", wsize);
        return (EC_FALSE);
    }

    return chashdb_buff_flush(chashdb, 0, (RWSIZE)wsize, CHASHDB_BASE_BUFF(chashdb));
}

EC_BOOL chashdb_load(CHASHDB *chashdb)
{
    CHASHDB_HEADER  chashdb_header_t;
    CHASHDB_HEADER *chashdb_header;

    UINT8 *base_buff;
    UINT32 base_buff_len;

    chashdb_header = &chashdb_header_t;

    /*load header*/
    if(EC_FALSE == chashdb_header_load(chashdb, 0, chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_load: load header failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chashdb_header_is_valid(chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_load: corrupted header\n");
        return (EC_FALSE);
    }
#if 0
    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDOUT, "[DEBUG] chashdb_load: header is:\n");
    chashdb_header_print(LOGSTDOUT, chashdb_header);
#endif

    base_buff_len = CHASHDB_HEADER_FSIZE(chashdb_header);
    base_buff = (UINT8 *)SAFE_MALLOC(base_buff_len, LOC_CHASHDB_0014);

    if(NULL_PTR == base_buff)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_load: alloc whole file memory failed where file size %ld\n",
                    CHASHDB_HEADER_FSIZE(chashdb_header));
        return (EC_FALSE);
    }

    if(EC_FALSE == chashdb_buff_load(chashdb, 0, base_buff_len, base_buff))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_load: load %ld bytes failed\n", base_buff_len);
        SAFE_FREE(base_buff, LOC_CHASHDB_0015);
        return (EC_FALSE);
    }

    /*link*/
    chashdb_link(chashdb, chashdb_header, base_buff_len, base_buff);
    chashdb_cmutexs_init(chashdb);
    CHASHDB_FIRST_CHASH_ALGO(chashdb)  = chash_algo_fetch(CHASHDB_FIRST_CHASH_ALGO_ID(chashdb));
    CHASHDB_SECOND_CHASH_ALGO(chashdb) = chash_algo_fetch(CHASHDB_SECOND_CHASH_ALGO_ID(chashdb));

    return (EC_TRUE);
}

EC_BOOL chashdb_unlink(const char *dbname)
{
    if (NULL_PTR == dbname)
    {
        return (EC_FALSE);
    }

    if( 0 != unlink(dbname))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CHASHDB *chashdb_open(const char *dbname)
{
    CHASHDB *chashdb;

    if(0 != access(dbname, F_OK))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_open: chashdb file %s not exist\n", dbname);
        return (NULL_PTR);
    }

    chashdb = chashdb_new(dbname);
    if(NULL_PTR == chashdb)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_open: new chashdb for file %s failed\n", dbname);
        return (NULL_PTR);
    }

    CHASHDB_FD(chashdb) = open(dbname, O_RDWR, 0666);
    if(ERR_FD == CHASHDB_FD(chashdb))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_open: open chashdb file %s failed\n", dbname);
        chashdb_free(chashdb);
        return (NULL_PTR);
    }

    if(EC_FALSE == chashdb_load(chashdb))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_open: load chashdb file %s failed\n", dbname);
        chashdb_free(chashdb);
        return (NULL_PTR);
    }
    return (chashdb);
}

EC_BOOL chashdb_close(CHASHDB *chashdb)
{
    chashdb_free(chashdb);
    return (EC_TRUE);
}

EC_BOOL chashdb_close_with_flush(CHASHDB *chashdb)
{
    chashdb_flush(chashdb);
    chashdb_close(chashdb);
    return (EC_TRUE);
}

EC_BOOL chashdb_create(const char *dbname, const UINT32 chashdb_mode, const UINT32 first_chash_algo_id, const UINT32 second_chash_algo_id)
{
    CHASHDB_HEADER  chashdb_header_t;
    CHASHDB_HEADER *chashdb_header;
    UINT32 chashdb_bucket_pos;
    UINT32 chashdb_item_pos;
    UINT8 *base_buff;
    UINT32 base_buff_len;

    CHASHDB *chashdb;

    chashdb_header = &chashdb_header_t;

    if(0 == access(dbname, F_OK))/*exist*/
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_create: file %s exist already\n", dbname);
        return (EC_FALSE);
    }

    if(EC_FALSE == chashdb_header_create(chashdb_header, chashdb_mode, first_chash_algo_id, second_chash_algo_id))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_create: create header failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == chashdb_header_is_valid(chashdb_header))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_create: create header is invalid\n");
        return (EC_FALSE);
    }

    chashdb = chashdb_new(dbname);
    if(NULL_PTR == chashdb)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_create: new chashdb for file %s failed\n", dbname);
        return (EC_FALSE);
    }

    base_buff_len = CHASHDB_HEADER_FSIZE(chashdb_header);
    base_buff = (UINT8 *)SAFE_MALLOC(base_buff_len, LOC_CHASHDB_0016);;
    if(NULL_PTR == base_buff)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_create: alloc buff failed where buff len %ld\n", base_buff_len);
        chashdb_free(chashdb);
        return (EC_FALSE);
    }

    chashdb_link(chashdb, chashdb_header, base_buff_len, base_buff);

    /*init bloom*/
    cbloom_init(CHASHDB_CBLOOM(chashdb));

    /*init bucket vec*/
    for(chashdb_bucket_pos = 0; chashdb_bucket_pos < CHASHDB_BKNUM(chashdb); chashdb_bucket_pos ++)
    {
        CHASHDB_BUCKET *chashdb_bucket;

        chashdb_bucket = (CHASHDB_BUCKET_VEC(chashdb) + chashdb_bucket_pos);
        chashdb_bucket_init(chashdb_bucket);
    }
#if 1
    /*init item vec*/
    for(chashdb_item_pos = 0; chashdb_item_pos < CHASHDB_IMNUM(chashdb); chashdb_item_pos ++)
    {
        CHASHDB_ITEM *chashdb_item;

        chashdb_item = (CHASHDB_ITEM *)(CHASHDB_ITEM_VEC(chashdb) + chashdb_item_pos);
        chashdb_item_init(chashdb_item);
    }
#endif

    CHASHDB_FD(chashdb) = open(dbname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CHASHDB_FD(chashdb))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_create: cannot open file %s\n", dbname);
        chashdb_free(chashdb);
        return (EC_FALSE);
    }

    if(EC_FALSE == chashdb_buff_flush(chashdb, 0, CHASHDB_HEADER_FSIZE(chashdb_header), CHASHDB_BASE_BUFF(chashdb)))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_create: create chashdb file %s failed\n", dbname);
        chashdb_free(chashdb);
        return (EC_FALSE);
    }

    chashdb_free(chashdb);

    return (EC_TRUE);
}

EC_BOOL chashdb_show(LOG *log, const char *dbname)
{
    CHASHDB_HEADER  chashdb_header_t;
    CHASHDB_HEADER *chashdb_header;

    CBLOOM *cbloom;
    UINT32  max_nbits;
    UINT8  *data_area;

    RWSIZE rwsize;
    UINT32  offset;
    UINT32  chashdb_bucket_pos;
    UINT32  chashdb_item_pos;

    int db_fd;

    chashdb_header = &chashdb_header_t;

    if(0 != access(dbname, F_OK))/*exist*/
    {
        sys_log(log, "error:chashdb_show: db %s not exist\n", dbname);
        return (EC_FALSE);
    }

    db_fd = c_file_open(dbname, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == db_fd)
    {
        sys_log(log, "error:chashdb_show: cannot open db %s\n", dbname);
        return (EC_FALSE);
    }

    /*load header*/
    if(ERR_SEEK == lseek(db_fd, 0, SEEK_SET))
    {
        sys_log(log, "error:chashdb_show: seek BEG failed\n");
        return (EC_FALSE);
    }

    rwsize = sizeof(CHASHDB_HEADER);
    if(rwsize != read(db_fd, chashdb_header, rwsize))
    {
        sys_log(log, "error:chashdb_show: load header failed\n");
        return (EC_FALSE);
    }

    sys_log(log, "header: ");
    chashdb_header_print(log, chashdb_header);
    sys_print(log, "\n");

    /*load bloom filter*/
    if(ERR_SEEK == lseek(db_fd, CHASHDB_HEADER_BMOFF(chashdb_header), SEEK_SET))
    {
        sys_log(log, "error:chashdb_show: seek boff failed\n");
        return (EC_FALSE);
    }

    max_nbits = (CHASHDB_HEADER_BMROW(chashdb_header) * CHASHDB_HEADER_BMCOL(chashdb_header));
    data_area = (UINT8 *)SAFE_MALLOC(sizeof(UINT32) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(max_nbits)), LOC_CHASHDB_0017);
    if(NULL_PTR == data_area)
    {
        sys_log(log, "error:chashdb_show: alloc %ld bytes failed\n", NWORDS_TO_NBYTES(NBITS_TO_NWORDS(max_nbits)));
        return (EC_FALSE);
    }

    rwsize = CHASHDB_HEADER_BKOFF(chashdb_header) - CHASHDB_HEADER_BMOFF(chashdb_header);
    if(rwsize != read(db_fd, data_area, rwsize))
    {
        sys_log(log, "error:chashdb_show: load bloom failed where rwsize = %u\n", (uint32_t)rwsize);
        return (EC_FALSE);
    }

    cbloom = (CBLOOM *)data_area;

    sys_log(log, "bloom: ");
    cbloom_print(log, cbloom);

    SAFE_FREE(data_area, LOC_CHASHDB_0018);

    rwsize = sizeof(CHASHDB_BUCKET);
    for(offset = CHASHDB_HEADER_BKOFF(chashdb_header), chashdb_bucket_pos = 0;
        offset < CHASHDB_HEADER_IOFF(chashdb_header) && chashdb_bucket_pos < CHASHDB_HEADER_BKNUM(chashdb_header);
        offset += rwsize, chashdb_bucket_pos ++)
    {
        CHASHDB_BUCKET  chashdb_bucket_t;
        CHASHDB_BUCKET *chashdb_bucket;

        chashdb_bucket = &chashdb_bucket_t;

        if(ERR_SEEK == lseek(db_fd, offset, SEEK_SET))
        {
            sys_log(log, "error:chashdb_show: seek bucket %ld# failed where offset = %u\n", chashdb_bucket_pos, offset);
            return (EC_FALSE);
        }

        if(rwsize != read(db_fd, chashdb_bucket, rwsize))
        {
            sys_log(log, "error:chashdb_show: load bucket %ld# failed where rwsize = %u\n", chashdb_bucket_pos, (uint32_t)rwsize);
            return (EC_FALSE);
        }

        sys_log(log, "bucket %ld#: ", chashdb_bucket_pos);
        chashdb_bucket_print(log, chashdb_bucket);
    }

    rwsize = sizeof(CHASHDB_ITEM);
    for(offset = CHASHDB_HEADER_IOFF(chashdb_header), chashdb_item_pos = 0;
        offset < CHASHDB_HEADER_EOFF(chashdb_header) && chashdb_item_pos < CHASHDB_HEADER_ICNUM(chashdb_header);
        offset += rwsize, chashdb_item_pos ++)
    {
        CHASHDB_ITEM    chashdb_item_t;
        CHASHDB_ITEM   *chashdb_item;

        chashdb_item = &chashdb_item_t;

        if(ERR_SEEK == lseek(db_fd, offset, SEEK_SET))
        {
            sys_log(log, "error:chashdb_show: seek item %ld# failed where offset = %u\n", chashdb_item_pos, offset);
            return (EC_FALSE);
        }

        if (rwsize != read(db_fd, chashdb_item, rwsize))
        {
            sys_log(log, "error:chashdb_show: load item %ld# failed\n", chashdb_item_pos);
            return (EC_FALSE);
        }
        sys_log(log, "item %ld#, offset %ld: ", chashdb_item_pos, offset);
        chashdb_item_print(log, chashdb_item);
    }

    return (EC_TRUE);

}

void chashdb_set_test(const char *dbname)
{
    CHASHDB *chashdb;

    UINT32 record_max;
    UINT32 record_pos;

    record_max = CHASHDB_500M_CFG_ITEM_MAX_NUM + 1024;

    chashdb_unlink(dbname);
    if(EC_FALSE == chashdb_create(dbname, CHASHDB_500M_MODE, CHASH_AP_ALGO_ID, CHASH_SDBM_ALGO_ID))
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_set_test: create chashdb failed\n");
        return;
    }

    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDOUT, "[DEBUG] chashdb_set_test: create %s successfully\n", dbname);

    chashdb = chashdb_open(dbname);
    if(NULL_PTR == chashdb)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_set_test: open chashdb failed\n");
        return;
    }

    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDOUT, "[DEBUG] chashdb_set_test: open %s successfully\n", dbname);

    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDOUT, "[DEBUG] chashdb_set_test: header is:\n");
    chashdb_header_print(LOGSTDOUT, CHASHDB_HDR(chashdb));

    for(record_pos = 0; record_pos < record_max; record_pos ++)
    {
        UINT32 klen;
        UINT32 vlen;

        UINT8 key[ CHASHDB_KEY_MAX_SIZE ];
        UINT8 *value;

        klen = snprintf((char *)key  , CHASHDB_KEY_MAX_SIZE - 1, "%ld", record_pos);
        value = NULL_PTR;
        vlen = record_pos;

        if(EC_FALSE == chashdb_set(chashdb, klen, key, vlen, value, CHASHDB_DATA_REPLICA_MAX_NUM))
        {
            //dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_test: set chashdb failed where key = %s\n", (char *)key);
            continue;
        }
    }

    chashdb_close_with_flush(chashdb);
    //chashdb_close(chashdb);

    return;
}

void chashdb_get_test(const char *dbname)
{
    CHASHDB *chashdb;

    UINT32 record_max;
    UINT32 record_pos;

    record_max = CHASHDB_500M_CFG_ITEM_MAX_NUM + 1024;

    chashdb = chashdb_open(dbname);
    if(NULL_PTR == chashdb)
    {
        dbg_log(SEC_0061_CHASHDB, 0)(LOGSTDOUT, "error:chashdb_get_test: open chashdb failed\n");
        return;
    }

    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDOUT, "[DEBUG] chashdb_get_test: open %s successfully\n", dbname);

    dbg_log(SEC_0061_CHASHDB, 9)(LOGSTDOUT, "[DEBUG] chashdb_get_test: header is:\n");
    chashdb_header_print(LOGSTDOUT, CHASHDB_HDR(chashdb));

    for(record_pos = 0; record_pos < record_max; record_pos ++)
    {
        UINT32 klen;
        UINT32 vlen;

        UINT8 key[ CHASHDB_KEY_MAX_SIZE ];
        UINT8 *value;

        klen = snprintf((char *)key  , CHASHDB_KEY_MAX_SIZE - 1, "%ld", record_pos);

        if(EC_FALSE == chashdb_get(chashdb, klen, key, &vlen, &value))
        {
            dbg_log(SEC_0061_CHASHDB, 5)(LOGSTDOUT, "chashdb_get_test: got failed: key = %s\n", (char *)key);
            continue;
        }
        //dbg_log(SEC_0061_CHASHDB, 5)(LOGSTDOUT, "chashdb_get_test: got successful: key = %s\n", (char *)key);
    }

    chashdb_close(chashdb);

    return;
}

void chashdb_test()
{
    UINT32 index;

    char *dbname = (char *)"/tmp/chashdb.dat";

    for(index = 0; index < 1; index ++)
    {
        //chashdb_set_test(dbname);
        chashdb_get_test(dbname);
        //dbg_log(SEC_0061_CHASHDB, 5)(LOGSTDOUT, "loop %ld end\n", index);
    }

    //dbg_log(SEC_0061_CHASHDB, 5)(LOGSTDOUT, "===========================================================================\n");
    //chashdb_show(LOGSTDOUT, dbname);

    print_static_mem_status(LOGSTDOUT);
    //print_static_mem_diag_info(LOGSTDOUT);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

