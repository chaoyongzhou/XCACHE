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

#ifndef _CHFSNP_INC
#define _CHFSNP_INC

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
#include "chfsnprb.h"

#define CHFSNP_KEY_MAX_SIZE             ( 16)  /*max len of file or dir seg name*/

#define CHFSNP_008M_MODEL   ((uint8_t) 0)
#define CHFSNP_016M_MODEL   ((uint8_t) 1)
#define CHFSNP_032M_MODEL   ((uint8_t) 2)
#define CHFSNP_064M_MODEL   ((uint8_t) 3)
#define CHFSNP_128M_MODEL   ((uint8_t) 4)
#define CHFSNP_256M_MODEL   ((uint8_t) 5)
#define CHFSNP_512M_MODEL   ((uint8_t) 6)
#define CHFSNP_001G_MODEL   ((uint8_t) 7)

#define CHFSNP_FILE_REPLICA_MAX_NUM     ((uint32_t) 1)  /*max num of supported replicas up to*/
//#define CHFSNP_ERR_BUCKET               (CHFSNPRB_ERR_POS)

#define CHFSNP_ITEM_STAT_IS_NOT_USED    ((uint32_t) 0x1)  /*4 bits*/
#define CHFSNP_ITEM_STAT_IS_USED        ((uint32_t) 0x8)

typedef struct
{
    uint16_t    rsvd2;          /*tcid: not used yet*/
    uint16_t    disk_no;        /*local disk_no*/
    uint16_t    block_no;       /*block_no in above disk*/
    uint16_t    page_no;        /*page_no in above block*/    
}CHFSNP_INODE;

#define CHFSNP_INODE_DISK_NO(chfsnp_inode)           ((chfsnp_inode)->disk_no)
#define CHFSNP_INODE_BLOCK_NO(chfsnp_inode)          ((chfsnp_inode)->block_no)
#define CHFSNP_INODE_PAGE_NO(chfsnp_inode)           ((chfsnp_inode)->page_no)

typedef struct
{
    uint32_t      file_size;    /*data/value length < 64M = 2^26B*/
    uint32_t      file_replica_num;

    CHFSNP_INODE  inodes[ CHFSNP_FILE_REPLICA_MAX_NUM ];
}CHFSNP_FNODE;/*16B*/

#define CHFSNP_FNODE_FILESZ(chfsnp_fnode)        ((chfsnp_fnode)->file_size)
#define CHFSNP_FNODE_REPNUM(chfsnp_fnode)        ((chfsnp_fnode)->file_replica_num)
#define CHFSNP_FNODE_INODES(chfsnp_fnode)        ((chfsnp_fnode)->inodes)
#define CHFSNP_FNODE_INODE(chfsnp_fnode, idx)    (&((chfsnp_fnode)->inodes[ (idx) ]))

#define CHFSNP_FNODE_INODE_DISK_NO(chfsnp_fnode, idx)    CHFSNP_INODE_DISK_NO(CHFSNP_FNODE_INODE(chfsnp_fnode, idx))
#define CHFSNP_FNODE_INODE_BLOCK_NO(chfsnp_fnode, idx)   CHFSNP_INODE_BLOCK_NO(CHFSNP_FNODE_INODE(chfsnp_fnode, idx))
#define CHFSNP_FNODE_INODE_PAGE_NO(chfsnp_fnode, idx)    CHFSNP_INODE_PAGE_NO(CHFSNP_FNODE_INODE(chfsnp_fnode, idx))

typedef struct
{   
    CHFSNPRB_NODE   rb_node;/*16B*/

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
    uint8_t       key[ CHFSNP_KEY_MAX_SIZE ];  /* file name or hash/digest value*/

    union
    {
        CHFSNP_FNODE fnode;
    }u;/*16B*/
} CHFSNP_ITEM; /*64B*/

#define CHFSNP_ITEM_RB_NODE(chfsnp_item)          (&((chfsnp_item)->rb_node))
#define CHFSNP_ITEM_C_TIME(chfsnp_item)           ((chfsnp_item)->c_time)
#define CHFSNP_ITEM_BUCKET_POS(chfsnp_item)       ((chfsnp_item)->bucket_pos)
#define CHFSNP_ITEM_STAT(chfsnp_item)             ((chfsnp_item)->stat)
#define CHFSNP_ITEM_KLEN(chfsnp_item)             ((chfsnp_item)->klen)
#define CHFSNP_ITEM_KEY(chfsnp_item)              ((chfsnp_item)->key)
#define CHFSNP_ITEM_FNODE(chfsnp_item)            (&((chfsnp_item)->u.fnode))
#define CHFSNP_ITEM_F_SIZE(chfsnp_item)           (CHFSNP_FNODE_FILESZ(CHFSNP_ITEM_FNODE(chfsnp_item)))

/*get CHFSNP_ITEM from CHFSNPRB_NODE*/
#define CHFSNP_RB_NODE_ITEM(chfsnprb_node)        ((NULL_PTR == (chfsnprb_node)) ? NULL_PTR : \
    ((CHFSNP_ITEM *)((char *)(chfsnprb_node)-(unsigned long)(&((CHFSNP_ITEM *)0)->rb_node))))

/*item max num = file size / sizeof(CHFSNP_ITEM) where sizeof(CHFSNP_ITEM) = 64B = 2^6*/
#define CHFSNP_ITEM_BIT_SIZE             (6)
#define CHFSNP_RESERVED_SIZE             ((UINT32)(UINT32_ONE << 22)) /*4MB*/

#define CHFSNP_008M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 23))
#define CHFSNP_008M_CFG_ITEM_MAX_NUM     ((CHFSNP_008M_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

#define CHFSNP_016M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 24))
#define CHFSNP_016M_CFG_ITEM_MAX_NUM     ((CHFSNP_016M_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

#define CHFSNP_032M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 25))
#define CHFSNP_032M_CFG_ITEM_MAX_NUM     ((CHFSNP_032M_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

#define CHFSNP_064M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 26))
#define CHFSNP_064M_CFG_ITEM_MAX_NUM     ((CHFSNP_064M_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

#define CHFSNP_128M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 27))
#define CHFSNP_128M_CFG_ITEM_MAX_NUM     ((CHFSNP_128M_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

#define CHFSNP_256M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 28))
#define CHFSNP_256M_CFG_ITEM_MAX_NUM     ((CHFSNP_256M_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

#define CHFSNP_512M_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 29))
#define CHFSNP_512M_CFG_ITEM_MAX_NUM     ((CHFSNP_512M_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

#define CHFSNP_001G_CFG_FILE_SIZE        ((UINT32)(UINT32_ONE << 30))
#define CHFSNP_001G_CFG_ITEM_MAX_NUM     ((CHFSNP_001G_CFG_FILE_SIZE - CHFSNP_RESERVED_SIZE) >> CHFSNP_ITEM_BIT_SIZE)

/*2G or 4G NP may be more waste ...*/

#define CHFSNP_BUCKET_NUM                ((uint32_t)(1 << 19)) /*2MB/4B*/


typedef struct
{
    char    *mode_str;
    UINT32   file_size;
    uint32_t item_max_num;
    uint32_t rsvd;
}CHFSNP_CFG;

#define CHFSNP_CFG_MOD_STR(chfsnp_cfg)                ((chfsnp_cfg)->mode_str)
#define CHFSNP_CFG_FILE_SIZE(chfsnp_cfg)              ((chfsnp_cfg)->file_size)
#define CHFSNP_CFG_ITEM_MAX_NUM(chfsnp_cfg)           ((chfsnp_cfg)->item_max_num)

#define CHFSNP_ERR_MODEL             ((uint32_t)0xF)  /*4 bits*/

#define CHFSNP_O_RDONLY              ((uint32_t)O_RDONLY)
#define CHFSNP_O_WRONLY              ((uint32_t)O_WRONLY)
#define CHFSNP_O_RDWR                ((uint32_t)O_RDWR  )
#define CHFSNP_O_CREATE              ((uint32_t)O_CREAT )

#define CHFSNP_ERR_ID                     ((uint32_t)0xFFFFFFFF)


/*upper limit of bitmap size: (2MB - 4KB)*/
/*note: CHFSNP_XXXX_CFG_ITEM_MAX_NUM < CHFSNP_DEL_ITEMS_BITMAP_UPPER_LIMIT * 8*/
#define CHFSNP_DEL_ITEMS_BITMAP_U8_TAB_SIZE            ((1 << 21) - (1 << 12))  /*2MB - 4KB = 2093056*/
#define CHFSNP_DEL_ITEMS_BITMAP_U32_TAB_SIZE           (CHFSNP_DEL_ITEMS_BITMAP_U8_TAB_SIZE >> 2)/* (2MB - 4KB)/4 = 523264*/

#define CHFSNP_U32_BIT_POS_TO_U32_OFFSET(bit_pos)      ((bit_pos) >>  5)
#define CHFSNP_U32_BIT_POS_TO_BIT_OFFSET(bit_pos)      ((bit_pos)  & 31)

#define CHFSNP_DEL_ITEMS_BIT_NOT_SET                   ((uint8_t) 0)
#define CHFSNP_DEL_ITEMS_BIT_WAS_SET                   ((uint8_t) 1)

/*each np own one header*/
typedef struct
{
    /*8B*/
    uint32_t       np_id;               /*chfsnp id              */    
    uint8_t        np_model;            /*chfsnp model           */    
    uint8_t        rsvd1;                    
    uint8_t        chash_algo_1st_id ;  /*first hash algo func id : used to compute bucket pos in dnode   */
    uint8_t        chash_algo_2nd_id;   /*second hash algo func id: used to compute chfsnprb_node hash data*/   

    /*8B + (2MB - 4KB)*/
    uint32_t       del_items_max_num;   /*format: CFG_ITEM_MAX_NUM < CRFSNP_DEL_ITEM_BITMAP_UPPER_LIMIT * 8*/
    uint32_t       del_items_cur_num;
    uint32_t       del_items_bitmap[ CHFSNP_DEL_ITEMS_BITMAP_U32_TAB_SIZE ]; 

    /*4KB - 24B*/
    uint8_t        pad_a[ (1 << 12) -  24 - 16]; /*4KB - 24B: pad the first part to 2 MB*/

    /*8B*/
    uint32_t       bucket_max_num;
    uint32_t       bucket_offset;       /*bucket start position, offset from CHFSNP_HEADER*/

    /*1GB - 4MB. note: the tail 2MB is for buckets*/
    CHFSNPRB_POOL  pool;                /*pool of CHFSNP_ITEM, CHFSNP_ITEM head must be CHFSNPRB_NODE*/    
} CHFSNP_HEADER;

#define CHFSNP_HEADER_NP_ID(chfsnp_header)                      ((chfsnp_header)->np_id)
#define CHFSNP_HEADER_NP_MODEL(chfsnp_header)                   ((chfsnp_header)->np_model)

#define CHFSNP_HEADER_1ST_CHASH_ALGO_ID(chfsnp_header)          ((chfsnp_header)->chash_algo_1st_id)
#define CHFSNP_HEADER_2ND_CHASH_ALGO_ID(chfsnp_header)          ((chfsnp_header)->chash_algo_2nd_id)

#define CHFSNP_HEADER_DEL_ITEMS_MAX_NUM(chfsnp_header)          ((chfsnp_header)->del_items_max_num)
#define CHFSNP_HEADER_DEL_ITEMS_CUR_NUM(chfsnp_header)          ((chfsnp_header)->del_items_cur_num)
#define CHFSNP_HEADER_DEL_ITEMS_BITMAP(chfsnp_header)           ((chfsnp_header)->del_items_bitmap)

#define CHFSNP_HEADER_ITEMS_POOL(chfsnp_header)                 (&((chfsnp_header)->pool))
#define CHFSNP_HEADER_ITEMS_MAX_NUM(chfsnp_header)              (CHFSNPRB_POOL_NODE_MAX_NUM(CHFSNP_HEADER_ITEMS_POOL(chfsnp_header)))
#define CHFSNP_HEADER_ITEMS_USED_NUM(chfsnp_header)             (CHFSNPRB_POOL_NODE_USED_NUM(CHFSNP_HEADER_ITEMS_POOL(chfsnp_header)))

#define CHFSNP_HEADER_BUCKET_MAX_NUM(chfsnp_header)             ((chfsnp_header)->bucket_max_num)
#define CHFSNP_HEADER_BUCKET_OFFSET(chfsnp_header)              ((chfsnp_header)->bucket_offset)

typedef struct
{
    int              fd;              /* hfs name node fd  */
    uint32_t         retire_node_pos; /*retire node_pos*/
    UINT32           fsize;
    
    uint8_t         *fname;

    uint64_t         del_size;        /* deleted but not recycled bytes*/
    uint64_t         recycle_size;    /* recycled bytes*/
 
    CRWLOCK          crwlock;         /* bucket crwlock*/
    CHFSNP_HEADER   *header;          /* hashdb header */
    uint32_t        *bucket_addr;

    CHASH_ALGO       chash_algo_1st;  /* hash algo for hash bucket              : used to compute bucket pos in dnode   */
    CHASH_ALGO       chash_algo_2nd;  /* hash algo for rbtree in the hash bucket: used to compute chfsnprb_node hash data*/   
} CHFSNP;

#define CHFSNP_FD(chfsnp)                     ((chfsnp)->fd)
#define CHFSNP_FSIZE(chfsnp)                  ((chfsnp)->fsize)
#define CHFSNP_FNAME(chfsnp)                  ((chfsnp)->fname)
#define CHFSNP_RETIRE_NODE_POS(chfsnp)        ((chfsnp)->retire_node_pos)
#define CHFSNP_DEL_SIZE(chfsnp)               ((chfsnp)->del_size)
#define CHFSNP_RECYCLE_SIZE(chfsnp)           ((chfsnp)->recycle_size)
#define CHFSNP_CRWLOCK(chfsnp)                (&((chfsnp)->crwlock))
#define CHFSNP_HDR(chfsnp)                    ((chfsnp)->header)
#define CHFSNP_BUCKET_ADDR(chfsnp)            ((chfsnp)->bucket_addr)
#define CHFSNP_BUCKET_MAX_NUM(chfsnp)         (CHFSNP_HEADER_BUCKET_MAX_NUM(CHFSNP_HDR(chfsnp)))

#define CHFSNP_1ST_CHASH_ALGO(chfsnp)         ((chfsnp)->chash_algo_1st)
#define CHFSNP_2ND_CHASH_ALGO(chfsnp)         ((chfsnp)->chash_algo_2nd)

#define CHFSNP_INIT_LOCK(chfsnp, location)    (crwlock_init(CHFSNP_CRWLOCK(chfsnp), CMUTEX_PROCESS_PRIVATE, location))
#define CHFSNP_CLEAN_LOCK(chfsnp, location)   (crwlock_clean(CHFSNP_CRWLOCK(chfsnp), location))
#if 0
#define CHFSNP_RDLOCK(chfsnp, location)       (crwlock_rdlock(CHFSNP_CRWLOCK(chfsnp), location))
#define CHFSNP_WRLOCK(chfsnp, location)       (crwlock_wrlock(CHFSNP_CRWLOCK(chfsnp), location))
#define CHFSNP_UNLOCK(chfsnp, location)       (crwlock_unlock(CHFSNP_CRWLOCK(chfsnp), location))
#endif

#if 1/*note: lock/unlock happen in chfs.c*/
#define CHFSNP_RDLOCK(chfsnp, location)       do{}while(0)
#define CHFSNP_WRLOCK(chfsnp, location)       do{}while(0)
#define CHFSNP_UNLOCK(chfsnp, location)       do{}while(0)

#endif


#define CHFSNP_ID(chfsnp)                     (CHFSNP_HEADER_NP_ID(CHFSNP_HDR(chfsnp)))
#define CHFSNP_MODEL(chfsnp)                  (CHFSNP_HEADER_NP_MODEL(CHFSNP_HDR(chfsnp)))
#define CHFSNP_FIRST_CHASH_ALGO_ID(chfsnp)    (CHFSNP_HEADER_1ST_CHASH_ALGO_ID(CHFSNP_HDR(chfsnp)) )
#define CHFSNP_SECOND_CHASH_ALGO_ID(chfsnp)   (CHFSNP_HEADER_2ND_CHASH_ALGO_ID(CHFSNP_HDR(chfsnp)))
#define CHFSNP_ITEMS_POOL(chfsnp)             (CHFSNP_HEADER_ITEMS_POOL(CHFSNP_HDR(chfsnp)))
#define CHFSNP_ITEMS_MAX_NUM(chfsnp)          (CHFSNPRB_POOL_NODE_MAX_NUM(CHFSNP_ITEMS_POOL(chfsnp)))
#define CHFSNP_ITEMS_USED_NUM(chfsnp)         (CHFSNPRB_POOL_NODE_USED_NUM(CHFSNP_ITEMS_POOL(chfsnp)))

#define CHFSNP_1ST_CHASH_ALGO_COMPUTE(chfsnp, klen, key)  (CHFSNP_1ST_CHASH_ALGO(chfsnp)(klen, key))
#define CHFSNP_2ND_CHASH_ALGO_COMPUTE(chfsnp, klen, key)  (CHFSNP_2ND_CHASH_ALGO(chfsnp)(klen, key))

#define CHFSNP_BUCKET_POS(chfsnp, first_hash)      ( (first_hash) % CHFSNP_BUCKET_MAX_NUM(chfsnp))
#define CHFSNP_BUCKET(chfsnp, bucket_pos)          (CHFSNP_BUCKET_ADDR(chfsnp)[(bucket_pos)])

typedef EC_BOOL (*CHFSNP_RECYCLE_DN_FUNC)(const UINT32, const CHFSNP_FNODE *);

typedef struct
{
    UINT32 arg1;

    CHFSNP_RECYCLE_DN_FUNC recycle_dn;
}CHFSNP_RECYCLE_DN;

#define CHFSNP_RECYCLE_DN_ARG1(chfsnp_recycle_dn)      ((chfsnp_recycle_dn)->arg1)
#define CHFSNP_RECYCLE_DN_FUNC(chfsnp_recycle_dn)      ((chfsnp_recycle_dn)->recycle_dn)

typedef EC_BOOL (*CHFSNP_RECYCLE_NP_FUNC)(const UINT32, const uint32_t);
typedef struct
{
    UINT32 arg1;

    CHFSNP_RECYCLE_NP_FUNC recycle_np;
}CHFSNP_RECYCLE_NP;

#define CHFSNP_RECYCLE_NP_ARG1(chfsnp_recycle_np)      ((chfsnp_recycle_np)->arg1)
#define CHFSNP_RECYCLE_NP_FUNC(chfsnp_recycle_np)      ((chfsnp_recycle_np)->recycle_np)


#endif/* _CHFSNP_INC */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

