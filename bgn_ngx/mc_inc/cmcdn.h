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


#if 0 /*2G-block*/
#define CMCDN_SEG_NO_NBITS              (6)
#define CMCDN_SEG_NO_MASK               (((UINT32)(UINT32_ONE << CMCDN_SEG_NO_NBITS)) - 1)
#endif

#if 1 /*32M-block*/
#define CMCDN_SEG_NO_NBITS              (0)
#define CMCDN_SEG_NO_MASK               (((UINT32)(UINT32_ONE << CMCDN_SEG_NO_NBITS)) - 1)
#endif

#define CMCDN_NODE_BIT_SIZE             (CMCDN_SEG_NO_NBITS + CMCPGB_CACHE_BIT_SIZE)
#define CMCDN_NODE_BYTE_SIZE            ((UINT32)(UINT32_ONE << CMCDN_NODE_BIT_SIZE))

/*node id = disk_no | block_no*/

#define CMCDN_NODE_ID_MAKE(disk_no, block_no)           ((((UINT32)(disk_no)) << 16) | (((UINT32)(block_no)) << 0))
#define CMCDN_NODE_ID_GET_DISK_NO(node_id)              ((uint16_t)(((node_id) >> 16) & 0xFFFF))
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

EC_BOOL cmcdn_write_p(CMCDN *cmcdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no);

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

