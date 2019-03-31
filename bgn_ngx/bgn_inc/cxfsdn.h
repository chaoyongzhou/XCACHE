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

#include "cbadbitmap.h"

#include "cmsync.h"

#include "cxfscfg.h"
#include "cxfspgrb.h"
#include "cxfspgb.h"
#include "cxfspgd.h"
#include "cxfspgv.h"

#include "camd.h"

#define CXFSDN_MEM_ALIGNMENT           (1 << 20)

#define CXFSDN_MSYNC_SIZE              (256 << 10) /*256K*/

#define CXFSDN_002K_BAD_PAGE      ( 1)
#define CXFSDN_004K_BAD_PAGE      ( 2)
#define CXFSDN_008K_BAD_PAGE      ( 3)
#define CXFSDN_016K_BAD_PAGE      ( 4)
#define CXFSDN_032K_BAD_PAGE      ( 5)
#define CXFSDN_064K_BAD_PAGE      ( 6)
#define CXFSDN_128K_BAD_PAGE      ( 7)
#define CXFSDN_256K_BAD_PAGE      ( 8)
#define CXFSDN_512K_BAD_PAGE      ( 9)
#define CXFSDN_001M_BAD_PAGE      (10)
#define CXFSDN_002M_BAD_PAGE      (11)
#define CXFSDN_004M_BAD_PAGE      (12)
#define CXFSDN_008M_BAD_PAGE      (13)
#define CXFSDN_016M_BAD_PAGE      (14)
#define CXFSDN_032M_BAD_PAGE      (15)

#if (CXFSDN_002K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)11)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("2K-page")
#endif/*(CXFSDN_002K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_004K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)12)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("4K-page")
#endif/*(CXFSDN_004K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_008K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)

#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)13)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("8K-page")
#endif/*(CXFSDN_008K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_016K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)14)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("16K-page")
#endif/*(CXFSDN_016K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_032K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)15)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("32K-page")
#endif/*(CXFSDN_032K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_064K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)16)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("64K-page")
#endif/*(CXFSDN_064K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_128K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)17)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("128K-page")
#endif/*(CXFSDN_128K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_256K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)18)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("256K-page")
#endif/*(CXFSDN_256K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_512K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)19)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("512K-page")
#endif/*(CXFSDN_512K_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_001M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)20)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("1M-page")
#endif/*(CXFSDN_001M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_002M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)21)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("2M-page")
#endif/*(CXFSDN_002M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_004M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)22)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("4M-page")
#endif/*(CXFSDN_004M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_008M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)23)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("8M-page")
#endif/*(CXFSDN_008M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_016M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)24)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("16M-page")
#endif/*(CXFSDN_016M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

#if (CXFSDN_032M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)
#define CXFSDN_BAD_PAGE_SIZE_NBITS           ((uint32_t)25)
#define CXFSDN_BAD_PAGE_SIZE_NBYTES          ((uint32_t)(1 << CXFSDN_BAD_PAGE_SIZE_NBITS))
#define CXFSDN_BAD_PAGE_DESC                 ("32M-page")
#endif/*(CXFSDN_032M_BAD_PAGE == CXFSDN_BAD_PAGE_CHOICE)*/

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
    uint32_t           read_only_flag:1;
    uint32_t           rsvd01        :31;
    uint16_t           writer_num;
    uint16_t           reader_num;

    CXFSPGV           *cxfspgv;

    int                ssd_disk_fd;
    int                sata_disk_fd;

    UINT32             offset;
    UINT32             size;

    UINT8             *mem_cache;

    CAMD_MD           *camd_md;

    CBAD_BITMAP       *sata_bad_bitmap;

    CMSYNC_NODE       *dn_msync_node;
}CXFSDN;

#define CXFSDN_READ_ONLY_FLAG(cxfsdn)                      ((cxfsdn)->read_only_flag)
#define CXFSDN_WRITER_NUM(cxfsdn)                          ((cxfsdn)->writer_num)
#define CXFSDN_READER_NUM(cxfsdn)                          ((cxfsdn)->reader_num)
#define CXFSDN_CXFSPGV(cxfsdn)                             ((cxfsdn)->cxfspgv)
#define CXFSDN_SSD_DISK_FD(cxfsdn)                         ((cxfsdn)->ssd_disk_fd)
#define CXFSDN_SATA_DISK_FD(cxfsdn)                        ((cxfsdn)->sata_disk_fd)
#define CXFSDN_OFFSET(cxfsdn)                              ((cxfsdn)->offset)
#define CXFSDN_SIZE(cxfsdn)                                ((cxfsdn)->size)
#define CXFSDN_MEM_CACHE(cxfsdn)                           ((cxfsdn)->mem_cache)
#define CXFSDN_CAMD_MD(cxfsdn)                             ((cxfsdn)->camd_md)
#define CXFSDN_SATA_BAD_BITMAP(cxfsdn)                     ((cxfsdn)->sata_bad_bitmap)
#define CXFSDN_MSYNC_NODE(cxfsdn)                          ((cxfsdn)->dn_msync_node)

EC_BOOL cxfsdn_node_write(CXFSDN *cxfsdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset);

EC_BOOL cxfsdn_node_read(CXFSDN *cxfsdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset);

CXFSDN *cxfsdn_create(const int cxfsdn_sata_fd, const UINT32 cxfsdn_sata_size, const UINT32 cxfsdn_sata_offset,
                         const UINT32 cxfsdn_mem_size,
                         const int cxfsdn_ssd_fd, const UINT32 cxfsdn_ssd_size, const UINT32 cxfsdn_ssd_offset);

EC_BOOL cxfsdn_add_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

EC_BOOL cxfsdn_del_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

EC_BOOL cxfsdn_mount_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

EC_BOOL cxfsdn_umount_disk(CXFSDN *cxfsdn, const uint16_t disk_no);

EC_BOOL cxfsdn_mount_sata_bad_bitmap(CXFSDN *cxfsdn, CBAD_BITMAP *cbad_bitmap);

EC_BOOL cxfsdn_umount_sata_bad_bitmap(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_sync_sata_bad_bitmap(CXFSDN *cxfsdn, const UINT32 sata_bad_bitmap_offset, const UINT32 sata_bad_bitmap_size);

EC_BOOL cxfsdn_cover_sata_bad_page(CXFSDN *cxfsdn, const uint32_t size, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no);

EC_BOOL cxfsdn_discard_sata_bad_page(CXFSDN *cxfsdn, const uint32_t size, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no);

CXFSDN *cxfsdn_new();

EC_BOOL cxfsdn_init(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_clean(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_free(CXFSDN *cxfsdn);

void cxfsdn_print(LOG *log, const CXFSDN *cxfsdn);

EC_BOOL cxfsdn_is_full(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_set_read_only(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_unset_read_only(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_is_read_only(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_flush(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_load(CXFSDN *cxfsdn, const CXFSCFG *cxfscfg,
                       const int cxfsdn_sata_fd,
                       const UINT32 cxfsdn_mem_size,
                       const int cxfsdn_ssd_fd);

CXFSDN *cxfsdn_open(const CXFSCFG *cxfscfg, const int cxfsdn_sata_fd, const int cxfsdn_ssd_fd);

EC_BOOL cxfsdn_close(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_dump(CXFSDN *cxfsdn, const UINT32 cxfsdn_zone_s_offset);

EC_BOOL cxfsdn_start_sync(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_end_sync(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_process_sync(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_is_sync(CXFSDN *cxfsdn);

EC_BOOL cxfsdn_can_sync(CXFSDN *cxfsdn);

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

EC_BOOL cxfsdn_reserve_space(CXFSDN *cxfsdn, const uint32_t size, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no);

EC_BOOL cxfsdn_release_space(CXFSDN *cxfsdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t size);

#endif/* _CXFSDN_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

