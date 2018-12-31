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

/*Random File System Data Node*/

#ifndef _CXFSDN_H
#define _CXFSDN_H

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
#include "crb.h"

#include "cxfscfg.h"
#include "cxfspgrb.h"
#include "cxfspgb.h"
#include "cxfspgd.h"
#include "cxfspgv.h"

#define CXFSDN_MEM_ALIGNMENT           (1 << 20)

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

#define CXFSDN_NODE_ID_MAKE(disk_no, block_no)            ((((UINT32)(disk_no)) << (CXFSPGD_SIZE_NBITS - CXFSPGB_CACHE_BIT_SIZE)) | (((UINT32)(block_no)) << 0))
#define CXFSDN_NODE_ID_GET_DISK_NO(node_id)               ((uint16_t)(((node_id) >> (CXFSPGD_SIZE_NBITS - CXFSPGB_CACHE_BIT_SIZE)) & 0xFFFF))
#define CXFSDN_NODE_ID_GET_BLOCK_NO(node_id)              ((uint16_t)(((node_id) >>  0) & 0xFFFF))
#define CXFSDN_NODE_ERR_ID                                (CXFSDN_NODE_ID_MAKE(CXFSPGRB_ERR_POS, CXFSPGRB_ERR_POS))


typedef struct
{
    CXFSPGV           *cxfspgv;

    int                fd;
    int                rsvd01;

    UINT32             offset;
    UINT32             size;

    UINT8             *mem_cache;
}CXFSDN;

#define CXFSDN_CXFSPGV(cxfsdn)                             ((cxfsdn)->cxfspgv)
#define CXFSDN_FD(cxfsdn)                                  ((cxfsdn)->fd)
#define CXFSDN_OFFSET(cxfsdn)                              ((cxfsdn)->offset)
#define CXFSDN_SIZE(cxfsdn)                                ((cxfsdn)->size)
#define CXFSDN_MEM_CACHE(cxfsdn)                           ((cxfsdn)->mem_cache)


EC_BOOL cxfsdn_node_write(CXFSDN *cxfsdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset);

EC_BOOL cxfsdn_node_read(CXFSDN *cxfsdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset);

CXFSDN *cxfsdn_create(const int cxfsdn_dev_fd, const UINT32 cxfsdn_dev_size, const UINT32 cxfsdn_dev_offset);

EC_BOOL cxfsdn_add_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

EC_BOOL cxfsdn_del_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

EC_BOOL cxfsdn_mount_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

EC_BOOL cxfsdn_umount_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

CXFSDN *cxfsdn_new();

EC_BOOL cxfsdn_init(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_clean(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_free(CXFSDN *cxfsdn);

void cxfsdn_print(LOG *log, const CXFSDN *cxfsdn);

EC_BOOL cxfsdn_is_full(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_flush(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_load(CXFSDN *cxfsdn, const int cxfsnp_dev_fd, const CXFSCFG *cxfscfg);

CXFSDN *cxfsdn_open(const int cxfsnp_dev_fd, const CXFSCFG *cxfscfg);

EC_BOOL cxfsdn_close(CXFSDN *cxfsdn);


/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL cxfsdn_read_o(CXFSDN *cxfsdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL cxfsdn_write_o(CXFSDN *cxfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset);

EC_BOOL cxfsdn_read_b(CXFSDN *cxfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

EC_BOOL cxfsdn_write_b(CXFSDN *cxfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, UINT32 *offset);

EC_BOOL cxfsdn_update_b(CXFSDN *cxfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset);

EC_BOOL cxfsdn_read_p(CXFSDN *cxfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

EC_BOOL cxfsdn_write_p(CXFSDN *cxfsdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cxfsdn_read_e(CXFSDN *cxfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cxfsdn_write_e(CXFSDN *cxfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset);

EC_BOOL cxfsdn_remove(CXFSDN *cxfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len);

#endif/* _CXFSDN_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

