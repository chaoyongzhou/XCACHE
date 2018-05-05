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

#ifndef _CSFSNP_INC
#define _CSFSNP_INC

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
#include "csfsnprb.h"

#define CSFSNP_KEY_MAX_SIZE             ( 16)  /*max len of file or dir seg name*/

#define CSFSNP_008M_MODEL   ((uint8_t) 0)
#define CSFSNP_016M_MODEL   ((uint8_t) 1)
#define CSFSNP_032M_MODEL   ((uint8_t) 2)
#define CSFSNP_064M_MODEL   ((uint8_t) 3)
#define CSFSNP_128M_MODEL   ((uint8_t) 4)
#define CSFSNP_256M_MODEL   ((uint8_t) 5)
#define CSFSNP_512M_MODEL   ((uint8_t) 6)
#define CSFSNP_001G_MODEL   ((uint8_t) 7)

#define CSFSNP_FILE_REPLICA_MAX_NUM     ((uint32_t) 1)  /*max num of supported replicas up to*/
//#define CSFSNP_ERR_BUCKET               (CSFSNPRB_ERR_POS)

#define CSFSNP_ITEM_STAT_IS_NOT_USED    ((uint32_t) 0x1)  /*4 bits*/
#define CSFSNP_ITEM_STAT_IS_USED        ((uint32_t) 0x8)

typedef struct
{
    uint16_t    rsvd2;          /*tcid: not used yet*/
    uint16_t    disk_no;        /*local disk_no*/
    uint16_t    block_no;       /*block_no in above disk*/
    uint16_t    page_no;        /*page_no in above block*/
}CSFSNP_INODE;

#define CSFSNP_INODE_DISK_NO(csfsnp_inode)           ((csfsnp_inode)->disk_no)
#define CSFSNP_INODE_BLOCK_NO(csfsnp_inode)          ((csfsnp_inode)->block_no)
#define CSFSNP_INODE_PAGE_NO(csfsnp_inode)           ((csfsnp_inode)->page_no)

typedef struct
{
    uint32_t      file_size;    /*data/value length < 64M = 2^26B*/
    uint32_t      file_replica_num;

    CSFSNP_INODE  inodes[ CSFSNP_FILE_REPLICA_MAX_NUM ];
}CSFSNP_FNODE;/*16B*/

#define CSFSNP_FNODE_FILESZ(csfsnp_fnode)        ((csfsnp_fnode)->file_size)
#define CSFSNP_FNODE_REPNUM(csfsnp_fnode)        ((csfsnp_fnode)->file_replica_num)
#define CSFSNP_FNODE_INODES(csfsnp_fnode)        ((csfsnp_fnode)->inodes)
#define CSFSNP_FNODE_INODE(csfsnp_fnode, idx)    (&((csfsnp_fnode)->inodes[ (idx) ]))

#define CSFSNP_FNODE_INODE_DISK_NO(csfsnp_fnode, idx)    CSFSNP_INODE_DISK_NO(CSFSNP_FNODE_INODE(csfsnp_fnode, idx))
#define CSFSNP_FNODE_INODE_BLOCK_NO(csfsnp_fnode, idx)   CSFSNP_INODE_BLOCK_NO(CSFSNP_FNODE_INODE(csfsnp_fnode, idx))
#define CSFSNP_FNODE_INODE_PAGE_NO(csfsnp_fnode, idx)    CSFSNP_INODE_PAGE_NO(CSFSNP_FNODE_INODE(csfsnp_fnode, idx))

typedef struct
{
    CSFSNPRB_NODE   rb_node;/*16B*/

    /*8B: c_time + rsvd1(only for 32bit OS)*/
    /*ctime_t is 32 bits for 32bit OS, 64 bits for 64bit OS*/
    ctime_t       c_time; /*create time       */

#if (32 == WORDSIZE)
    uint32_t      rsvd1;
#endif /*(32 == WORDSIZE)*/

    /*8B*/
    uint32_t      bucket_pos;
    uint32_t      rsvd3:20;
    uint32_t      stat :4;
    uint32_t      klen :8;

    /*16B*/
    uint8_t       key[ CSFSNP_KEY_MAX_SIZE ];  /* file name or hash/digest value*/

    union
    {
        CSFSNP_FNODE fnode;
    }u;/*16B*/
} CSFSNP_ITEM; /*64B*/

#define CSFSNP_ITEM_RB_NODE(csfsnp_item)          (&((csfsnp_item)->rb_node))
#define CSFSNP_ITEM_C_TIME(csfsnp_item)           ((csfsnp_item)->c_time)
#define CSFSNP_ITEM_BUCKET_POS(csfsnp_item)       ((csfsnp_item)->bucket_pos)
#define CSFSNP_ITEM_STAT(csfsnp_item)             ((csfsnp_item)->stat)
#define CSFSNP_ITEM_KLEN(csfsnp_item)             ((csfsnp_item)->klen)
#define CSFSNP_ITEM_KEY(csfsnp_item)              ((csfsnp_item)->key)
#define CSFSNP_ITEM_FNODE(csfsnp_item)            (&((csfsnp_item)->u.fnode))
#define CSFSNP_ITEM_F_SIZE(csfsnp_item)           (CSFSNP_FNODE_FILESZ(CSFSNP_ITEM_FNODE(csfsnp_item)))

/*get CSFSNP_ITEM from CSFSNPRB_NODE*/
#define CSFSNP_RB_NODE_ITEM(csfsnprb_node)        ((NULL_PTR == (csfsnprb_node)) ? NULL_PTR : \
    ((CSFSNP_ITEM *)((char *)(csfsnprb_node)-(unsigned long)(&((CSFSNP_ITEM *)0)->rb_node))))

/*item max num = file size / sizeof(CSFSNP_ITEM) where sizeof(CSFSNP_ITEM) = 64B = 2^6*/
#define CSFSNP_ITEM_BIT_SIZE             (6)
#define CSFSNP_RESERVED_SIZE             ((UINT32)(UINT32_ONE << 22)) /*4MB*/

#define CSFSNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CSFSNP_008M_CFG_ITEM_MAX_NUM     ((CSFSNP_008M_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

#define CSFSNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CSFSNP_016M_CFG_ITEM_MAX_NUM     ((CSFSNP_016M_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

#define CSFSNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CSFSNP_032M_CFG_ITEM_MAX_NUM     ((CSFSNP_032M_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

#define CSFSNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CSFSNP_064M_CFG_ITEM_MAX_NUM     ((CSFSNP_064M_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

#define CSFSNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CSFSNP_128M_CFG_ITEM_MAX_NUM     ((CSFSNP_128M_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

#define CSFSNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CSFSNP_256M_CFG_ITEM_MAX_NUM     ((CSFSNP_256M_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

#define CSFSNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CSFSNP_512M_CFG_ITEM_MAX_NUM     ((CSFSNP_512M_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

#define CSFSNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CSFSNP_001G_CFG_ITEM_MAX_NUM     ((CSFSNP_001G_CFG_FILE_SIZE - CSFSNP_RESERVED_SIZE) >> CSFSNP_ITEM_BIT_SIZE)

/*2G or 4G NP may be more waste ...*/

#define CSFSNP_BUCKET_NUM                ((uint32_t)(1 << 19)) /*2MB/4B*/


typedef struct
{
    char    *mode_str;
    UINT32   file_size;
    uint32_t item_max_num;
    uint32_t rsvd;
}CSFSNP_CFG;

#define CSFSNP_CFG_MOD_STR(csfsnp_cfg)                ((csfsnp_cfg)->mode_str)
#define CSFSNP_CFG_FILE_SIZE(csfsnp_cfg)              ((csfsnp_cfg)->file_size)
#define CSFSNP_CFG_ITEM_MAX_NUM(csfsnp_cfg)           ((csfsnp_cfg)->item_max_num)

#define CSFSNP_ERR_MODEL             ((uint32_t)0xF)  /*4 bits*/

#define CSFSNP_O_RDONLY              ((uint32_t)O_RDONLY)
#define CSFSNP_O_WRONLY              ((uint32_t)O_WRONLY)
#define CSFSNP_O_RDWR                ((uint32_t)O_RDWR  )
#define CSFSNP_O_CREATE              ((uint32_t)O_CREAT )

#define CSFSNP_ERR_ID                     ((uint32_t)0xFFFFFFFF)


/*upper limit of bitmap size: (2MB - 4KB)*/
/*note: CSFSNP_XXXX_CFG_ITEM_MAX_NUM < CSFSNP_DEL_ITEMS_BITMAP_UPPER_LIMIT * 8*/
#define CSFSNP_DEL_ITEMS_BITMAP_U8_TAB_SIZE            ((1 << 21) - (1 << 12))  /*2MB - 4KB = 2093056*/
#define CSFSNP_DEL_ITEMS_BITMAP_U32_TAB_SIZE           (CSFSNP_DEL_ITEMS_BITMAP_U8_TAB_SIZE >> 2)/* (2MB - 4KB)/4 = 523264*/

#define CSFSNP_U32_BIT_POS_TO_U32_OFFSET(bit_pos)      ((bit_pos) >>  5)
#define CSFSNP_U32_BIT_POS_TO_BIT_OFFSET(bit_pos)      ((bit_pos)  & 31)

#define CSFSNP_DEL_ITEMS_BIT_NOT_SET                   ((uint8_t) 0)
#define CSFSNP_DEL_ITEMS_BIT_WAS_SET                   ((uint8_t) 1)

/*each np own one header*/
typedef struct
{
    /*8B*/
    uint32_t       np_id;               /*csfsnp id              */
    uint8_t        np_model;            /*csfsnp model           */
    uint8_t        rsvd1;
    uint8_t        chash_algo_1st_id ;  /*first hash algo func id : used to compute bucket pos in dnode   */
    uint8_t        chash_algo_2nd_id;   /*second hash algo func id: used to compute csfsnprb_node hash data*/

    /*8B + (2MB - 4KB)*/
    uint32_t       del_items_max_num;   /*format: CFG_ITEM_MAX_NUM < CRFSNP_DEL_ITEM_BITMAP_UPPER_LIMIT * 8*/
    uint32_t       del_items_cur_num;
    uint32_t       del_items_bitmap[ CSFSNP_DEL_ITEMS_BITMAP_U32_TAB_SIZE ];

    /*4KB - 24B*/
    uint8_t        pad_a[ (1 << 12) -  24 - 16]; /*4KB - 24B: pad the first part to 2 MB*/

    /*8B*/
    uint32_t       bucket_max_num;
    uint32_t       bucket_offset;       /*bucket start position, offset from CSFSNP_HEADER*/

    /*1GB - 4MB. note: the tail 2MB is for buckets*/
    CSFSNPRB_POOL  pool;                /*pool of CSFSNP_ITEM, CSFSNP_ITEM head must be CSFSNPRB_NODE*/
} CSFSNP_HEADER;

#define CSFSNP_HEADER_NP_ID(csfsnp_header)                      ((csfsnp_header)->np_id)
#define CSFSNP_HEADER_NP_MODEL(csfsnp_header)                   ((csfsnp_header)->np_model)

#define CSFSNP_HEADER_1ST_CHASH_ALGO_ID(csfsnp_header)          ((csfsnp_header)->chash_algo_1st_id)
#define CSFSNP_HEADER_2ND_CHASH_ALGO_ID(csfsnp_header)          ((csfsnp_header)->chash_algo_2nd_id)

#define CSFSNP_HEADER_DEL_ITEMS_MAX_NUM(csfsnp_header)          ((csfsnp_header)->del_items_max_num)
#define CSFSNP_HEADER_DEL_ITEMS_CUR_NUM(csfsnp_header)          ((csfsnp_header)->del_items_cur_num)
#define CSFSNP_HEADER_DEL_ITEMS_BITMAP(csfsnp_header)           ((csfsnp_header)->del_items_bitmap)

#define CSFSNP_HEADER_ITEMS_POOL(csfsnp_header)                 (&((csfsnp_header)->pool))
#define CSFSNP_HEADER_ITEMS_MAX_NUM(csfsnp_header)              (CSFSNPRB_POOL_NODE_MAX_NUM(CSFSNP_HEADER_ITEMS_POOL(csfsnp_header)))
#define CSFSNP_HEADER_ITEMS_USED_NUM(csfsnp_header)             (CSFSNPRB_POOL_NODE_USED_NUM(CSFSNP_HEADER_ITEMS_POOL(csfsnp_header)))

#define CSFSNP_HEADER_BUCKET_MAX_NUM(csfsnp_header)             ((csfsnp_header)->bucket_max_num)
#define CSFSNP_HEADER_BUCKET_OFFSET(csfsnp_header)              ((csfsnp_header)->bucket_offset)

typedef struct
{
    int              fd;              /* sfs name node fd  */
    uint32_t         retire_node_pos; /*retire node_pos*/
    UINT32           fsize;

    uint8_t         *fname;

    uint64_t         del_size;        /* deleted but not recycled bytes*/
    uint64_t         recycle_size;    /* recycled bytes*/

    CRWLOCK          crwlock;         /* bucket crwlock*/
    CSFSNP_HEADER   *header;          /* hashdb header */
    uint32_t        *bucket_addr;

    CHASH_ALGO       chash_algo_1st;  /* hash algo for hash bucket              : used to compute bucket pos in dnode   */
    CHASH_ALGO       chash_algo_2nd;  /* hash algo for rbtree in the hash bucket: used to compute csfsnprb_node hash data*/
} CSFSNP;

#define CSFSNP_FD(csfsnp)                     ((csfsnp)->fd)
#define CSFSNP_FSIZE(csfsnp)                  ((csfsnp)->fsize)
#define CSFSNP_FNAME(csfsnp)                  ((csfsnp)->fname)
#define CSFSNP_RETIRE_NODE_POS(csfsnp)        ((csfsnp)->retire_node_pos)
#define CSFSNP_DEL_SIZE(csfsnp)               ((csfsnp)->del_size)
#define CSFSNP_RECYCLE_SIZE(csfsnp)           ((csfsnp)->recycle_size)
#define CSFSNP_CRWLOCK(csfsnp)                (&((csfsnp)->crwlock))
#define CSFSNP_HDR(csfsnp)                    ((csfsnp)->header)
#define CSFSNP_BUCKET_ADDR(csfsnp)            ((csfsnp)->bucket_addr)
#define CSFSNP_BUCKET_MAX_NUM(csfsnp)         (CSFSNP_HEADER_BUCKET_MAX_NUM(CSFSNP_HDR(csfsnp)))

#define CSFSNP_1ST_CHASH_ALGO(csfsnp)         ((csfsnp)->chash_algo_1st)
#define CSFSNP_2ND_CHASH_ALGO(csfsnp)         ((csfsnp)->chash_algo_2nd)

#define CSFSNP_INIT_LOCK(csfsnp, location)    (crwlock_init(CSFSNP_CRWLOCK(csfsnp), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSNP_CLEAN_LOCK(csfsnp, location)   (crwlock_clean(CSFSNP_CRWLOCK(csfsnp), location))
#if 0
#define CSFSNP_RDLOCK(csfsnp, location)       (crwlock_rdlock(CSFSNP_CRWLOCK(csfsnp), location))
#define CSFSNP_WRLOCK(csfsnp, location)       (crwlock_wrlock(CSFSNP_CRWLOCK(csfsnp), location))
#define CSFSNP_UNLOCK(csfsnp, location)       (crwlock_unlock(CSFSNP_CRWLOCK(csfsnp), location))
#endif

#if 1/*note: lock/unlock happen in csfs.c*/
#define CSFSNP_RDLOCK(csfsnp, location)       do{}while(0)
#define CSFSNP_WRLOCK(csfsnp, location)       do{}while(0)
#define CSFSNP_UNLOCK(csfsnp, location)       do{}while(0)

#endif


#define CSFSNP_ID(csfsnp)                     (CSFSNP_HEADER_NP_ID(CSFSNP_HDR(csfsnp)))
#define CSFSNP_MODEL(csfsnp)                  (CSFSNP_HEADER_NP_MODEL(CSFSNP_HDR(csfsnp)))
#define CSFSNP_FIRST_CHASH_ALGO_ID(csfsnp)    (CSFSNP_HEADER_1ST_CHASH_ALGO_ID(CSFSNP_HDR(csfsnp)) )
#define CSFSNP_SECOND_CHASH_ALGO_ID(csfsnp)   (CSFSNP_HEADER_2ND_CHASH_ALGO_ID(CSFSNP_HDR(csfsnp)))
#define CSFSNP_ITEMS_POOL(csfsnp)             (CSFSNP_HEADER_ITEMS_POOL(CSFSNP_HDR(csfsnp)))
#define CSFSNP_ITEMS_MAX_NUM(csfsnp)          (CSFSNPRB_POOL_NODE_MAX_NUM(CSFSNP_ITEMS_POOL(csfsnp)))
#define CSFSNP_ITEMS_USED_NUM(csfsnp)         (CSFSNPRB_POOL_NODE_USED_NUM(CSFSNP_ITEMS_POOL(csfsnp)))

#define CSFSNP_1ST_CHASH_ALGO_COMPUTE(csfsnp, klen, key)  (CSFSNP_1ST_CHASH_ALGO(csfsnp)(klen, key))
#define CSFSNP_2ND_CHASH_ALGO_COMPUTE(csfsnp, klen, key)  (CSFSNP_2ND_CHASH_ALGO(csfsnp)(klen, key))

#define CSFSNP_BUCKET_POS(csfsnp, first_hash)      ( (first_hash) % CSFSNP_BUCKET_MAX_NUM(csfsnp))
#define CSFSNP_BUCKET(csfsnp, bucket_pos)          (CSFSNP_BUCKET_ADDR(csfsnp)[(bucket_pos)])

typedef EC_BOOL (*CSFSNP_RECYCLE_DN_FUNC)(const UINT32, const CSFSNP_FNODE *);

typedef struct
{
    UINT32 arg1;

    CSFSNP_RECYCLE_DN_FUNC recycle_dn;
}CSFSNP_RECYCLE_DN;

#define CSFSNP_RECYCLE_DN_ARG1(csfsnp_recycle_dn)      ((csfsnp_recycle_dn)->arg1)
#define CSFSNP_RECYCLE_DN_FUNC(csfsnp_recycle_dn)      ((csfsnp_recycle_dn)->recycle_dn)

typedef EC_BOOL (*CSFSNP_RECYCLE_NP_FUNC)(const UINT32, const uint32_t);
typedef struct
{
    UINT32 arg1;

    CSFSNP_RECYCLE_NP_FUNC recycle_np;
}CSFSNP_RECYCLE_NP;

#define CSFSNP_RECYCLE_NP_ARG1(csfsnp_recycle_np)      ((csfsnp_recycle_np)->arg1)
#define CSFSNP_RECYCLE_NP_FUNC(csfsnp_recycle_np)      ((csfsnp_recycle_np)->recycle_np)

#endif/* _CSFSNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

