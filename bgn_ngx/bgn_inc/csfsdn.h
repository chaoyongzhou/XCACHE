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

/*Simple File System Data Node*/

#ifndef _CSFSDN_H
#define _CSFSDN_H

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
#include "csfsb.h"
#include "csfsd.h"
#include "csfsv.h"

#define CSFSDN_DB_NAME      ((const char *)"dn_cfg.dat")

#define CSFSDN_NODE_NAME_MAX_SIZE       (256)

#define CSFSDN_NODE_O_RDONLY           ((UINT32)O_RDONLY)
#define CSFSDN_NODE_O_WRONLY           ((UINT32)O_WRONLY)
#define CSFSDN_NODE_O_RDWR             ((UINT32)O_RDWR  )
#define CSFSDN_NODE_O_CREATE           ((UINT32)O_CREAT )

/**********************************************************************************
*   node_id bits (for 1 virtual disk = 1 TB)
*   ========================================
*   
*   64                              32               16  14       6      0
*   |--------------------------------|----------------|--|--------|------|
*           rsvd                         |              |     |       |
*       (for 32-bit os, not exist)       |              |     |       |- seg no(6b)
*                                        |              |     |    
*                                        |              |     |- path no(8b)
*                                        |              |
*                                        |              |- rsvd(2b) for 1T-disk
*                                        |                 used for 4T-disk
*                                        |- disk no(16b)
*
**********************************************************************************/

#if (32 == WORDSIZE)
#define CSFSDN_SEG_NO_NBITS              (0)
#define CSFSDN_SEG_NO_MASK               (((UINT32)(UINT32_ONE << CSFSDN_SEG_NO_NBITS)) - 1)

#define CSFSDN_PATH_NO_NBITS             (16) /*rsvd + path no*/
#define CSFSDN_PATH_NO_MASK              (((UINT32)(UINT32_ONE << CSFSDN_PATH_NO_NBITS)) - 1)
#endif/*(32 == WORDSIZE)*/

#if (64 == WORDSIZE)
#if 1 /*4G-block*/
#define CSFSDN_SEG_NO_NBITS              (6)
#define CSFSDN_SEG_NO_MASK               (((UINT32)(UINT32_ONE << CSFSDN_SEG_NO_NBITS)) - 1)

#define CSFSDN_PATH_NO_NBITS             (10) /*rsvd + path no*/
#define CSFSDN_PATH_NO_MASK              (((UINT32)(UINT32_ONE << CSFSDN_PATH_NO_NBITS)) - 1)
#endif
#if 0 /*64M-block*/
#define CSFSDN_SEG_NO_NBITS              (0)
#define CSFSDN_SEG_NO_MASK               (((UINT32)(UINT32_ONE << CSFSDN_SEG_NO_NBITS)) - 1)

#define CSFSDN_PATH_NO_NBITS             (16) /*rsvd + path no*/
#define CSFSDN_PATH_NO_MASK              (((UINT32)(UINT32_ONE << CSFSDN_PATH_NO_NBITS)) - 1)
#endif
#endif/*(64 == WORDSIZE)*/

#define CSFSDN_CACHE_MAX_BYTE_SIZE       ((UINT32)(UINT32_ONE << (CSFSDN_SEG_NO_NBITS + CSFSB_CACHE_BIT_SIZE)))

#define CSFSDN_EXPIRED_IN_NSEC               ((uint32_t) 30 * 60) /*30 minutes*/

/*memory cached block info*/
typedef struct
{  
    UINT32          id;         /*id = disk_no | block_no*/

    CMUTEX          cmutex;     /*cmutex for node read/write*/
    ctime_t         atime;      /*last access time (in seconds)*/
    
    int             block_fd;   /* block fd */

#if (64 == WORDSIZE)
    uint32_t        rsvd;
#endif
}CSFSDN_NODE;

#define CSFSDN_NODE_ID(csfsdn_node)                       ((csfsdn_node)->id)
#define CSFSDN_NODE_CMUTEX(csfsdn_node)                   (&((csfsdn_node)->cmutex))
#define CSFSDN_NODE_ATIME(csfsdn_node)                    ((csfsdn_node)->atime)
#define CSFSDN_NODE_FD(csfsdn_node)                       ((csfsdn_node)->block_fd)

#define CSFSDN_NODE_ID_MAKE(disk_no, block_no)            ((((UINT32)(disk_no)) << 16) | (((UINT32)(block_no)) << 0))
#define CSFSDN_NODE_ID_GET_DISK_NO(node_id)               ((uint16_t)(((node_id) >> 16) & 0xFFFF))
#define CSFSDN_NODE_ID_GET_BLOCK_NO(node_id)              ((uint16_t)(((node_id) >>  0) & 0xFFFF))
#define CSFSDN_NODE_ERR_ID                                (CSFSDN_NODE_ID_MAKE(CSFSB_ERR_POS, CSFSB_ERR_POS))

#define CSFSDN_NODE_ID_GET_SEG_NO(node_id)                ((uint16_t)(((node_id) >>  0) & CSFSDN_SEG_NO_MASK))
#define CSFSDN_NODE_ID_GET_PATH_NO(node_id)               ((uint16_t)(((node_id) >>  CSFSDN_SEG_NO_NBITS) & CSFSDN_PATH_NO_MASK))

#define CSFSDN_NODE_DISK_NO(csfsdn_node)                  (CSFSDN_NODE_ID_GET_DISK_NO(CSFSDN_NODE_ID(csfsdn_node)))
#define CSFSDN_NODE_BLOCK_NO(csfsdn_node)                 (CSFSDN_NODE_ID_GET_BLOCK_NO(CSFSDN_NODE_ID(csfsdn_node)))


#if 1
#define CSFSDN_NODE_CMUTEX_INIT(csfsdn_node, location)    (cmutex_init(CSFSDN_NODE_CMUTEX(csfsdn_node), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSDN_NODE_CMUTEX_CLEAN(csfsdn_node, location)   (cmutex_clean(CSFSDN_NODE_CMUTEX(csfsdn_node), location))
#define CSFSDN_NODE_CMUTEX_LOCK(csfsdn_node, location)    (cmutex_lock(CSFSDN_NODE_CMUTEX(csfsdn_node), location))
#define CSFSDN_NODE_CMUTEX_UNLOCK(csfsdn_node, location)  (cmutex_unlock(CSFSDN_NODE_CMUTEX(csfsdn_node), location))
#endif


typedef struct
{
    CRWLOCK            rwlock;
    CRB_TREE           open_nodes;  /*open nodes to read or write, item is CSFSDN_NODE*/
    CMUTEX             cmutex;      /*cmutex for open nodes which was accessed by do_slave thread and task_brd_cbtimer_do thread*/

    uint8_t           *root_dname;
    CSFSV             *csfsv;
}CSFSDN;

#define CSFSDN_CRWLOCK(csfsdn)                             (&((csfsdn)->rwlock))
#define CSFSDN_CMUTEX(csfsdn)                              (&((csfsdn)->cmutex))
#define CSFSDN_OPEN_NODES(csfsdn)                          (&((csfsdn)->open_nodes))
#define CSFSDN_ROOT_DNAME(csfsdn)                          ((csfsdn)->root_dname)
#define CSFSDN_CSFSV(csfsdn)                               ((csfsdn)->csfsv)

#define CSFSDN_OPEN_NODE(_csfsdn, node_id)                 (csfsdn_node_fetch((_csfsdn), (node_id)))

#if 0
#define CSFSDN_CRWLOCK_INIT(csfsdn, location)       (crwlock_init(CSFSDN_CRWLOCK(csfsdn), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSDN_CRWLOCK_CLEAN(csfsdn, location)      (crwlock_clean(CSFSDN_CRWLOCK(csfsdn), location))

#define CSFSDN_CRWLOCK_RDLOCK(csfsdn, location)     (crwlock_rdlock(CSFSDN_CRWLOCK(csfsdn), location))
#define CSFSDN_CRWLOCK_WRLOCK(csfsdn, location)     (crwlock_wrlock(CSFSDN_CRWLOCK(csfsdn), location))
#define CSFSDN_CRWLOCK_UNLOCK(csfsdn, location)     (crwlock_unlock(CSFSDN_CRWLOCK(csfsdn), location))
#endif

#if 1
#define CSFSDN_CRWLOCK_INIT(csfsdn, location)       (crwlock_init(CSFSDN_CRWLOCK(csfsdn), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSDN_CRWLOCK_CLEAN(csfsdn, location)      (crwlock_clean(CSFSDN_CRWLOCK(csfsdn), location))

#define CSFSDN_CRWLOCK_RDLOCK(csfsdn, location)     do{}while(0)
#define CSFSDN_CRWLOCK_WRLOCK(csfsdn, location)     do{}while(0)
#define CSFSDN_CRWLOCK_UNLOCK(csfsdn, location)     do{}while(0)
#endif

#if 0
#define CSFSDN_CRWLOCK_INIT(csfsdn, location)  do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFSDN_CRWLOCK_INIT: CSFSDN_CRWLOCK %p, at %s:%ld\n", CSFSDN_CRWLOCK(csfsdn), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_init(CSFSDN_CRWLOCK(csfsdn), CMUTEX_PROCESS_PRIVATE, location);\
}while(0)

#define CSFSDN_CRWLOCK_CLEAN(csfsdn, location) do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFSDN_CRWLOCK_CLEAN: CSFSDN_CRWLOCK %p, at %s:%ld\n", CSFSDN_CRWLOCK(csfsdn), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_clean(CSFSDN_CRWLOCK(csfsdn), location);\
}while(0)    

#define CSFSDN_CRWLOCK_RDLOCK(csfsdn, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFSDN_CRWLOCK_RDLOCK: CSFSDN_CRWLOCK %p, at %s:%ld\n", CSFSDN_CRWLOCK(csfsdn), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_rdlock(CSFSDN_CRWLOCK(csfsdn), location);\
    sys_log(LOGSTDOUT, "[DEBUG] CSFSDN_CRWLOCK_RDLOCK: CSFSDN_CRWLOCK %p, at %s:%ld done\n", CSFSDN_CRWLOCK(csfsdn), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
}while(0)

#define CSFSDN_CRWLOCK_WRLOCK(csfsdn, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFSDN_CRWLOCK_WRLOCK: CSFSDN_CRWLOCK %p, at %s:%ld\n", CSFSDN_CRWLOCK(csfsdn), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_wrlock(CSFSDN_CRWLOCK(csfsdn), location);\
    sys_log(LOGSTDOUT, "[DEBUG] CSFSDN_CRWLOCK_WRLOCK: CSFSDN_CRWLOCK %p, at %s:%ld done\n", CSFSDN_CRWLOCK(csfsdn), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
}while(0)
#define CSFSDN_CRWLOCK_UNLOCK(csfsdn, location)     do{\
    sys_log(LOGSTDOUT, "[DEBUG] CSFSDN_CRWLOCK_UNLOCK: CSFSDN_CRWLOCK %p, at %s:%ld\n", CSFSDN_CRWLOCK(csfsdn), MM_LOC_FILE_NAME(location),MM_LOC_LINE_NO(location));\
    croutine_rwlock_unlock(CSFSDN_CRWLOCK(csfsdn), location);\
}while(0)
#endif

#if 0
#define CSFSDN_CMUTEX_INIT(csfsdn, location)         (croutine_mutex_init(CSFSDN_CMUTEX(csfsdn), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSDN_CMUTEX_CLEAN(csfsdn, location)        (croutine_mutex_clean(CSFSDN_CMUTEX(csfsdn), location))
#define CSFSDN_CMUTEX_LOCK(csfsdn, location)         (croutine_mutex_lock(CSFSDN_CMUTEX(csfsdn), location))
#define CSFSDN_CMUTEX_UNLOCK(csfsdn, location)       (croutine_mutex_unlock(CSFSDN_CMUTEX(csfsdn), location))
#endif

#if 1
#define CSFSDN_CMUTEX_INIT(csfsdn, location)         (cmutex_init(CSFSDN_CMUTEX(csfsdn), CMUTEX_PROCESS_PRIVATE, location))
#define CSFSDN_CMUTEX_CLEAN(csfsdn, location)        (cmutex_clean(CSFSDN_CMUTEX(csfsdn), location))
#define CSFSDN_CMUTEX_LOCK(csfsdn, location)         (cmutex_lock(CSFSDN_CMUTEX(csfsdn), location))
#define CSFSDN_CMUTEX_UNLOCK(csfsdn, location)       (cmutex_unlock(CSFSDN_CMUTEX(csfsdn), location))
#endif


CSFSDN_NODE *csfsdn_node_new();

EC_BOOL csfsdn_node_init(CSFSDN_NODE *csfsdn_node);

EC_BOOL csfsdn_node_clean(CSFSDN_NODE *csfsdn_node);

EC_BOOL csfsdn_node_free(CSFSDN_NODE *csfsdn_node);

int csfsdn_node_cmp(const CSFSDN_NODE *csfsdn_node_1st, const CSFSDN_NODE *csfsdn_node_2nd);

void csfsdn_node_print(LOG *log, const CSFSDN_NODE *csfsdn_node);

/*for debug only*/
void csfsdn_node_fname_print(LOG *log, const CSFSDN *csfsdn, const UINT32 node_id);

CSFSDN_NODE *csfsdn_node_fetch(const CSFSDN *csfsdn, const UINT32 node_id);

EC_BOOL csfsdn_node_delete(CSFSDN *csfsdn, const UINT32 node_id);

CSFSDN_NODE *csfsdn_node_create(CSFSDN *csfsdn, const UINT32 node_id);

CSFSDN_NODE *csfsdn_node_open(CSFSDN *csfsdn, const UINT32 node_id, const UINT32 open_flags);
#if 0
EC_BOOL csfsdn_node_unlink(CSFSDN *csfsdn, const UINT32 node_id);
#endif
EC_BOOL csfsdn_node_write(CSFSDN *csfsdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset);

EC_BOOL csfsdn_node_read(CSFSDN *csfsdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset);

EC_BOOL csfsdn_expire_open_nodes(CSFSDN *csfsdn);

CSFSDN *csfsdn_create(const char *root_dname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp);

EC_BOOL csfsdn_add_disk(CSFSDN *csfsdn, const uint16_t disk_no);

EC_BOOL csfsdn_del_disk(CSFSDN *csfsdn, const uint16_t disk_no);

EC_BOOL csfsdn_mount_disk(CSFSDN *csfsdn, const uint16_t disk_no);

EC_BOOL csfsdn_umount_disk(CSFSDN *csfsdn, const uint16_t disk_no);

CSFSDN *csfsdn_new();

EC_BOOL csfsdn_init(CSFSDN *csfsdn);

EC_BOOL csfsdn_clean(CSFSDN *csfsdn);

EC_BOOL csfsdn_free(CSFSDN *csfsdn);

void csfsdn_print(LOG *log, const CSFSDN *csfsdn);

EC_BOOL csfsdn_flush(CSFSDN *csfsdn);

EC_BOOL csfsdn_load(CSFSDN *csfsdn, const char *root_dname, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp);

EC_BOOL csfsdn_exist(const char *root_dname);

CSFSDN *csfsdn_open(const char *root_dir, const uint32_t np_node_err_pos, CSFSNP_RECYCLE np_node_recycle, void *npp);

EC_BOOL csfsdn_close(CSFSDN *csfsdn);

EC_BOOL csfsdn_fetch_block_fd(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, int *block_fd);

/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL csfsdn_read_o(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL csfsdn_write_o(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset);

EC_BOOL csfsdn_read_b(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

EC_BOOL csfsdn_write_b(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, UINT32 *offset);

EC_BOOL csfsdn_read_p(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

EC_BOOL csfsdn_write_p(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL csfsdn_read_e(CSFSDN *csfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL csfsdn_write_e(CSFSDN *csfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset);

EC_BOOL csfsdn_show(LOG *log, const char *root_dir);

EC_BOOL csfsdn_rdlock(CSFSDN *csfsdn, const UINT32 location);

EC_BOOL csfsdn_wrlock(CSFSDN *csfsdn, const UINT32 location);

EC_BOOL csfsdn_unlock(CSFSDN *csfsdn, const UINT32 location);

#endif/* _CSFSDN_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

