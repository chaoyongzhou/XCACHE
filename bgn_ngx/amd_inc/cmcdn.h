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

/*Memory Cache Data Node*/

#ifndef _CMCDN_H
#define _CMCDN_H

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

#include "cmcpgrb.h"
#include "cmcpgb.h"
#include "cmcpgd.h"
#include "cmcpgv.h"

#define CMCDN_032M_NODE_SIZE_NBITS      (25)
#define CMCDN_064M_NODE_SIZE_NBITS      (26)
#define CMCDN_128M_NODE_SIZE_NBITS      (27)
#define CMCDN_256M_NODE_SIZE_NBITS      (28)
#define CMCDN_512M_NODE_SIZE_NBITS      (29)
#define CMCDN_001G_NODE_SIZE_NBITS      (30)
#define CMCDN_002G_NODE_SIZE_NBITS      (31)
#define CMCDN_004G_NODE_SIZE_NBITS      (32)

#define CMCDN_032M_NODE                 (1)
#define CMCDN_064M_NODE                 (2)
#define CMCDN_128M_NODE                 (3)
#define CMCDN_256M_NODE                 (4)
#define CMCDN_512M_NODE                 (5)
#define CMCDN_001G_NODE                 (6)
#define CMCDN_002G_NODE                 (7)
#define CMCDN_004G_NODE                 (8)

//#define CMCDN_NODE_CHOICE               (CMCDN_032M_NODE)
//#define CMCDN_NODE_CHOICE               (CMCDN_064M_NODE)
//#define CMCDN_NODE_CHOICE               (CMCDN_128M_NODE)
//#define CMCDN_NODE_CHOICE               (CMCDN_256M_NODE)
//#define CMCDN_NODE_CHOICE               (CMCDN_512M_NODE)
//#define CMCDN_NODE_CHOICE               (CMCDN_001G_NODE)
//#define CMCDN_NODE_CHOICE               (CMCDN_002G_NODE)
//#define CMCDN_NODE_CHOICE               (CMCDN_004G_NODE)

#if (CMCDN_032M_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_032M_NODE_SIZE_NBITS)
#endif/*(CMCDN_032M_NODE == CMCDN_NODE_CHOICE)*/

#if (CMCDN_064M_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_064M_NODE_SIZE_NBITS)
#endif/*(CMCDN_064M_NODE == CMCDN_NODE_CHOICE)*/

#if (CMCDN_128M_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_128M_NODE_SIZE_NBITS)
#endif/*(CMCDN_128M_NODE == CMCDN_NODE_CHOICE)*/

#if (CMCDN_256M_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_256M_NODE_SIZE_NBITS)
#endif/*(CMCDN_256M_NODE == CMCDN_NODE_CHOICE)*/

#if (CMCDN_512M_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_512M_NODE_SIZE_NBITS)
#endif/*(CMCDN_512M_NODE == CMCDN_NODE_CHOICE)*/

#if (CMCDN_001G_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_001G_NODE_SIZE_NBITS)
#endif/*(CMCDN_001G_NODE == CMCDN_NODE_CHOICE)*/

#if (CMCDN_002G_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_002G_NODE_SIZE_NBITS)
#endif/*(CMCDN_002G_NODE == CMCDN_NODE_CHOICE)*/

#if (CMCDN_004G_NODE == CMCDN_NODE_CHOICE)
#define CMCDN_NODE_SIZE_NBITS           (CMCDN_004G_NODE_SIZE_NBITS)
#endif/*(CMCDN_004G_NODE == CMCDN_NODE_CHOICE)*/

#define CMCDN_NODE_SIZE_NBYTES          ((UINT32)(UINT32_ONE << CMCDN_NODE_SIZE_NBITS))
#define CMCDN_SEG_NO_NBITS              (CMCDN_NODE_SIZE_NBITS - CMCPGB_SIZE_NBITS) /*how many blocks in one node*/
#define CMCDN_SEG_NO_MASK               (((UINT32)(UINT32_ONE << CMCDN_SEG_NO_NBITS)) - 1)

/*node id = disk_no | block_no*/

#define CMCDN_NODE_ID_MAKE(disk_no, block_no)           ((((UINT32)(disk_no)) << (CMCPGD_SIZE_NBITS - CMCPGB_SIZE_NBITS)) | (((UINT32)(block_no)) << 0))
#define CMCDN_NODE_ID_GET_DISK_NO(node_id)              ((uint16_t)(((node_id) >> (CMCPGD_SIZE_NBITS - CMCPGB_SIZE_NBITS)) & 0xFFFF))
#define CMCDN_NODE_ID_GET_BLOCK_NO(node_id)             ((uint16_t)(((node_id) >>  0) & 0xFFFF))
#define CMCDN_NODE_ERR_ID                               (CMCDN_NODE_ID_MAKE(CMCPGRB_ERR_POS, CMCPGRB_ERR_POS))

#define CMCDN_NODE_ID_GET_SEG_NO(node_id)               ((uint16_t)(((node_id) >>  0) & CMCDN_SEG_NO_MASK))

typedef struct
{
    UINT32             node_num;

    void              *node_base_addr;

    /*storage memory range: [start, end)*/
    void              *node_start_addr; /*start address of storage*/
    void              *node_end_addr;   /*end address of storage. end = start + len*/

    CMCPGV            *cmcpgv;
}CMCDN;

#define CMCDN_NODE_NUM(cmcdn)                            ((cmcdn)->node_num)
#define CMCDN_NODE_BASE_ADDR(cmcdn)                      ((cmcdn)->node_base_addr)
#define CMCDN_NODE_START_ADDR(cmcdn)                     ((cmcdn)->node_start_addr)
#define CMCDN_NODE_END_ADDR(cmcdn)                       ((cmcdn)->node_end_addr)
#define CMCDN_CMCPGV(cmcdn)                              ((cmcdn)->cmcpgv)

#define CMCDN_OPEN_NODE(_cmcdn, node_id)                 (cmcdn_node_fetch((_cmcdn), (node_id)))

void *cmcdn_node_fetch(const CMCDN *cmcdn, const UINT32 node_id);

EC_BOOL cmcdn_node_write(CMCDN *cmcdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset);

EC_BOOL cmcdn_node_read(CMCDN *cmcdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset);

UINT8 *cmcdn_node_locate(CMCDN *cmcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no);

CMCDN *cmcdn_create(const uint16_t disk_num);

EC_BOOL cmcdn_add_disk(CMCDN *cmcdn, const uint16_t disk_no);

EC_BOOL cmcdn_del_disk(CMCDN *cmcdn, const uint16_t disk_no);

CMCDN *cmcdn_new();

EC_BOOL cmcdn_init(CMCDN *cmcdn);

EC_BOOL cmcdn_clean(CMCDN *cmcdn);

EC_BOOL cmcdn_free(CMCDN *cmcdn);

void cmcdn_print(LOG *log, const CMCDN *cmcdn);

EC_BOOL cmcdn_is_full(CMCDN *cmcdn);

/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL cmcdn_read_o(CMCDN *cmcdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL cmcdn_write_o(CMCDN *cmcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset);

/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cmcdn_read_e(CMCDN *cmcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cmcdn_write_e(CMCDN *cmcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset);

EC_BOOL cmcdn_read_p(CMCDN *cmcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len);

EC_BOOL cmcdn_write_p(CMCDN *cmcdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

#endif/* _CMCDN_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

