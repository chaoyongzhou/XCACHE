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
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "real.h"

#include "cdcdn.h"
#include "cdcpgrb.h"
#include "cdcpgb.h"
#include "cdcpgd.h"
#include "cdcpgv.h"

#include "cmmap.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDCDN_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDCDN_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

/*Data Node*/
UINT32 cdcdn_node_fetch(const CDCDN *cdcdn, const UINT32 node_id)
{
    UINT32      node_id_t;

    node_id_t = (node_id >> CDCDN_SEG_NO_NBITS);
    if(node_id_t >= CDCDN_NODE_NUM(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_fetch: node_id %ld overflow\n", node_id);
        return (CDCDN_NODE_ERR_OFFSET);
    }

    return (CDCDN_NODE_S_OFFSET(cdcdn) + (node_id_t << CDCDN_NODE_SIZE_NBITS));
}

UINT32 cdcdn_node_locate(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no)
{
    UINT32               node_id;
    UINT32               offset_n;

    UINT32               offset;
    UINT32               offset_b; /*base offset in block*/
    UINT32               offset_r; /*real offset in block*/

    node_id = CDCDN_NODE_ID_MAKE(disk_no, block_no);

    offset_n = cdcdn_node_fetch(cdcdn, node_id);
    if(CDCDN_NODE_ERR_OFFSET == offset_n)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_locate: fetch node %ld failed\n",
                                              node_id);
        return (CDCDN_NODE_ERR_OFFSET);
    }

    offset   = (((UINT32)(page_no)) << (CDCPGB_PAGE_SIZE_NBITS));
    offset_b = (((UINT32)CDCDN_NODE_ID_GET_SEG_NO(node_id)) << CDCPGB_SIZE_NBITS);
    offset_r = offset_b + offset;

    return (offset_n + offset_r);
}

EC_BOOL cdcdn_node_write(CDCDN *cdcdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset)
{
    UINT32       offset_n; /*offset of cdcdn_node*/
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/
    UINT32       offset_f; /*real offset in file*/

    if(EC_TRUE == cdcdn_is_read_only(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 3)(LOGSTDOUT, "error:cdcdn_node_write: dn is read-only\n");
        return (EC_FALSE);
    }

    offset_n = cdcdn_node_fetch(cdcdn, node_id);
    if(CDCDN_NODE_ERR_OFFSET == offset_n)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_write: open node %ld failed\n",
                                              node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CDCDN_NODE_ID_GET_SEG_NO(node_id)) << CDCPGB_SIZE_NBITS);
    offset_r = offset_b + (*offset);

    offset_f = offset_n + offset_r;

    if(EC_FALSE == c_file_pwrite(CDCDN_NODE_FD(cdcdn), &offset_f, data_max_len, data_buff))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_write: "
                                              "write node %ld to offset %ld, size %ld failed\n",
                                              node_id, offset_f, data_max_len);
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 6)(LOGSTDOUT, "[DEBUG] cdcdn_node_write: "
                                          "write node %ld to offset %ld, size %ld done\n",
                                          node_id, offset_n + offset_r, data_max_len);

    (*offset) += data_max_len;

    return (EC_TRUE);
}

EC_BOOL cdcdn_node_read(CDCDN *cdcdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset)
{
    UINT32       offset_n; /*offset of cdcdn_node*/
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/
    UINT32       offset_f; /*real offset in file*/

    offset_n = cdcdn_node_fetch(cdcdn, node_id);
    if(CDCDN_NODE_ERR_OFFSET == offset_n)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_read: open node %ld failed\n",
                                              node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CDCDN_NODE_ID_GET_SEG_NO(node_id)) << CDCPGB_SIZE_NBITS);
    offset_r = offset_b + (*offset);

    offset_f = offset_n + offset_r;
    if(EC_FALSE == c_file_pread(CDCDN_NODE_FD(cdcdn), &offset_f, data_max_len, data_buff))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_node_read: "
                                              "read node %ld from offset %ld, size %ld failed\n",
                                              node_id, offset_f, data_max_len);
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 6)(LOGSTDOUT, "[DEBUG] cdcdn_node_read: "
                                          "read node %ld from offset %ld, size %ld done\n",
                                          node_id, offset_n + offset_r, data_max_len);

    (*offset) += data_max_len;
    return (EC_TRUE);
}

CDCDN *cdcdn_create(UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN           *cdcdn;
    CDCPGV_HDR      *cdcpgv_hdr;

    UINT32           f_s_offset;
    UINT32           f_e_offset;

    UINT8           *base;
    UINT32           pos;

    UINT32           disk_max_size;
    UINT32           block_max_num;

    UINT32           cdcpgv_size;
    UINT32           disk_size;
    UINT32           node_num;
    UINT32           block_num;
    uint16_t         disk_num;

    uint16_t         disk_no;

    if(1)
    {
        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGV_HDR_SIZE           = %ld\n",
                                              CDCPGV_HDR_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGV_MAX_DISK_NUM       = %u\n",
                                              CDCPGV_MAX_DISK_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGD_HDR_SIZE           = %ld\n",
                                              CDCPGD_HDR_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGD_MAX_BLOCK_NUM      = %u\n",
                                              CDCPGD_MAX_BLOCK_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_SIZE               = %ld\n",
                                              CDCPGB_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_PAGE_SIZE_NBYTES   = %u\n",
                                              CDCPGB_PAGE_SIZE_NBYTES);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_PAGE_NUM           = %u\n",
                                              CDCPGB_PAGE_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_RB_BITMAP_SIZE     = %u\n",
                                              CDCPGB_RB_BITMAP_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                              "CDCPGB_RB_BITMAP_PAD_SIZE = %u\n",
                                              CDCPGB_RB_BITMAP_PAD_SIZE);
    }

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "range [%ld, %ld) aligned to invalid [%ld, %ld)\n",
                                              (*s_offset), e_offset,
                                              f_s_offset, f_e_offset);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "range [%ld, %ld) aligned to [%ld, %ld)\n",
                                          (*s_offset), e_offset,
                                          f_s_offset, f_e_offset);

    /*determine data node header size in storage*/
    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "cdcpgv_size %ld\n",
                                          cdcpgv_size);

    //CDCDN_ASSERT(CDCPGB_SIZE_NBYTES >= cdcpgv_size);

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (NULL_PTR);
    }

    disk_max_size = (f_e_offset - f_s_offset - cdcpgv_size);
    block_max_num = (disk_max_size >> CDCPGB_SIZE_NBITS);

    disk_num      = (uint16_t)(block_max_num / CDCPGD_MAX_BLOCK_NUM);
    block_num     = ((UINT32)disk_num) * ((UINT32)CDCPGD_MAX_BLOCK_NUM);
    node_num      = (block_num >> CDCDN_SEG_NO_NBITS);/*num of nodes.  one node = several continuous blocks*/

    disk_size     = block_num * CDCPGB_SIZE_NBYTES;

    if(0 == disk_num)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "no enough space for one disk: "
                                              "disk_max_size %ld, block_max_num %ld => disk_num %u\n",
                                              disk_max_size, block_max_num, disk_num);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "disk_max_size %ld, block_max_num %ld => disk_num %u\n",
                                          disk_max_size, block_max_num, disk_num);

    CDCDN_ASSERT(0 == (block_num % node_num));

    base = cdcpgv_mcache_new(cdcpgv_size);
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: "
                                              "new header cache with size %ld failed\n",
                                              cdcpgv_size);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "new header cache [%p, %p), size %ld\n",
                                          base, base + cdcpgv_size, cdcpgv_size);

    pos = 0; /*initialize*/

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: new cdcdn failed\n");
        cdcpgv_mcache_free(base);
        return (NULL_PTR);
    }

    CDCDN_RDONLY_FLAG(cdcdn)   = BIT_FALSE;
    CDCDN_DONTDUMP_FLAG(cdcdn) = BIT_FALSE;
    CDCDN_NODE_FD(cdcdn)       = ERR_FD;
    CDCDN_NODE_NUM(cdcdn)      = node_num;
    CDCDN_BASE_S_OFFSET(cdcdn) = f_s_offset;
    CDCDN_BASE_E_OFFSET(cdcdn) = f_s_offset + cdcpgv_size;
    CDCDN_NODE_S_OFFSET(cdcdn) = VAL_ALIGN_NEXT(CDCDN_BASE_E_OFFSET(cdcdn), ((UINT32)CDCPGB_SIZE_MASK));
    CDCDN_NODE_E_OFFSET(cdcdn) = CDCDN_NODE_S_OFFSET(cdcdn) + disk_size;

    CDCDN_ASSERT(f_e_offset >= CDCDN_NODE_E_OFFSET(cdcdn));

    CDCDN_CDCPGV(cdcdn) = cdcpgv_new();
    if(NULL_PTR == CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: new vol failed\n");

        cdcpgv_mcache_free(base);
        cdcdn_free(cdcdn);
        return (NULL_PTR);
    }

    CDCPGV_HEADER(CDCDN_CDCPGV(cdcdn)) = (CDCPGV_HDR *)base;
    if(EC_FALSE == cdcpgv_hdr_init(CDCDN_CDCPGV(cdcdn)))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: init hdr failed\n");

        cdcdn_free(cdcdn);
        return (NULL_PTR);
    }

    /*cdcpgv header inherit data from data node where header would be flushed to disk*/
    cdcpgv_hdr = CDCPGV_HEADER(CDCDN_CDCPGV(cdcdn));
    CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)      = CDCDN_NODE_NUM(cdcdn);
    CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr) = CDCDN_BASE_S_OFFSET(cdcdn);
    CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr) = CDCDN_BASE_E_OFFSET(cdcdn);
    CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr) = CDCDN_NODE_S_OFFSET(cdcdn);
    CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr) = CDCDN_NODE_E_OFFSET(cdcdn);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: "
                                          "cdcpgv nodes: %ld, offset: base %ld, start %ld, end %ld\n",
                                          CDCPGV_HDR_NODE_NUM(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr));

    pos += CDCPGV_HDR_SIZE;

    for(disk_no = 0; disk_no < disk_num; disk_no ++)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "[DEBUG] cdcdn_create: add disk_no %u to pos %ld\n",
                                               disk_no, pos);

        if(EC_FALSE == cdcdn_add_disk(cdcdn, disk_no, base, &pos))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create: add disk %u failed\n",
                                                  disk_no);
            cdcdn_free(cdcdn);
            return (NULL_PTR);
        }
    }

    (*s_offset) = CDCDN_BASE_E_OFFSET(cdcdn);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create: create vol done\n");

    return (cdcdn);
}

CDCDN *cdcdn_create_shm(CMMAP_NODE *cmmap_node, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN           *cdcdn;
    CDCPGV_HDR      *cdcpgv_hdr;

    UINT32           f_s_offset;
    UINT32           f_e_offset;

    UINT8           *base;
    UINT32           pos;

    UINT32           disk_max_size;
    UINT32           block_max_num;

    UINT32           cdcpgv_size;
    UINT32           disk_size;
    UINT32           node_num;
    UINT32           block_num;
    uint16_t         disk_num;

    uint16_t         disk_no;

    if(1)
    {
        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGV_HDR_SIZE           = %ld\n",
                                              CDCPGV_HDR_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGV_MAX_DISK_NUM       = %u\n",
                                              CDCPGV_MAX_DISK_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGD_HDR_SIZE           = %ld\n",
                                              CDCPGD_HDR_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGD_MAX_BLOCK_NUM      = %u\n",
                                              CDCPGD_MAX_BLOCK_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGB_SIZE               = %ld\n",
                                              CDCPGB_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGB_PAGE_SIZE_NBYTES   = %u\n",
                                              CDCPGB_PAGE_SIZE_NBYTES);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGB_PAGE_NUM           = %u\n",
                                              CDCPGB_PAGE_NUM);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGB_RB_BITMAP_SIZE     = %u\n",
                                              CDCPGB_RB_BITMAP_SIZE);

        dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                              "CDCPGB_RB_BITMAP_PAD_SIZE = %u\n",
                                              CDCPGB_RB_BITMAP_PAD_SIZE);
    }

    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: "
                                              "range [%ld, %ld) aligned to invalid [%ld, %ld)\n",
                                              (*s_offset), e_offset,
                                              f_s_offset, f_e_offset);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                          "range [%ld, %ld) aligned to [%ld, %ld)\n",
                                          (*s_offset), e_offset,
                                          f_s_offset, f_e_offset);

    /*determine data node header size in storage*/
    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                          "cdcpgv_size %ld\n",
                                          cdcpgv_size);

    //CDCDN_ASSERT(CDCPGB_SIZE_NBYTES >= cdcpgv_size);

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (NULL_PTR);
    }

    disk_max_size = (f_e_offset - f_s_offset - cdcpgv_size);
    block_max_num = (disk_max_size >> CDCPGB_SIZE_NBITS);

    disk_num      = (uint16_t)(block_max_num / CDCPGD_MAX_BLOCK_NUM);
    block_num     = ((UINT32)disk_num) * ((UINT32)CDCPGD_MAX_BLOCK_NUM);
    node_num      = (block_num >> CDCDN_SEG_NO_NBITS);/*num of nodes.  one node = several continuous blocks*/

    disk_size     = block_num * CDCPGB_SIZE_NBYTES;

    if(0 == disk_num)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: "
                                              "no enough space for one disk: "
                                              "disk_max_size %ld, block_max_num %ld => disk_num %u\n",
                                              disk_max_size, block_max_num, disk_num);
        return (NULL_PTR);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                          "disk_max_size %ld, block_max_num %ld => disk_num %u\n",
                                          disk_max_size, block_max_num, disk_num);

    CDCDN_ASSERT(0 == (block_num % node_num));

    base = cmmap_node_alloc(cmmap_node, cdcpgv_size, CDCDN_MEM_ALIGNMENT, "cdc dn");
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: "
                                              "create dn failed\n");
        return (NULL_PTR);
    }

    pos = 0; /*initialize*/

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: new cdcdn failed\n");
        return (NULL_PTR);
    }

    CDCDN_RDONLY_FLAG(cdcdn)   = BIT_FALSE;
    CDCDN_DONTDUMP_FLAG(cdcdn) = BIT_FALSE;
    CDCDN_NODE_FD(cdcdn)       = ERR_FD;
    CDCDN_NODE_NUM(cdcdn)      = node_num;
    CDCDN_BASE_S_OFFSET(cdcdn) = f_s_offset;
    CDCDN_BASE_E_OFFSET(cdcdn) = f_s_offset + cdcpgv_size;
    CDCDN_NODE_S_OFFSET(cdcdn) = VAL_ALIGN_NEXT(CDCDN_BASE_E_OFFSET(cdcdn), ((UINT32)CDCPGB_SIZE_MASK));
    CDCDN_NODE_E_OFFSET(cdcdn) = CDCDN_NODE_S_OFFSET(cdcdn) + disk_size;

    CDCDN_ASSERT(f_e_offset >= CDCDN_NODE_E_OFFSET(cdcdn));

    CDCDN_CDCPGV(cdcdn) = cdcpgv_open();
    if(NULL_PTR == CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: new vol failed\n");

        cdcdn_close(cdcdn);
        return (NULL_PTR);
    }

    CDCPGV_HEADER(CDCDN_CDCPGV(cdcdn)) = (CDCPGV_HDR *)base;
    if(EC_FALSE == cdcpgv_hdr_init(CDCDN_CDCPGV(cdcdn)))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: init hdr failed\n");

        /*not need munmap base which was taken over by cdcpgv*/
        cdcdn_close(cdcdn);
        return (NULL_PTR);
    }

    /*cdcpgv header inherit data from data node where header would be flushed to disk*/
    cdcpgv_hdr = CDCPGV_HEADER(CDCDN_CDCPGV(cdcdn));
    CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)      = CDCDN_NODE_NUM(cdcdn);
    CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr) = CDCDN_BASE_S_OFFSET(cdcdn);
    CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr) = CDCDN_BASE_E_OFFSET(cdcdn);
    CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr) = CDCDN_NODE_S_OFFSET(cdcdn);
    CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr) = CDCDN_NODE_E_OFFSET(cdcdn);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: "
                                          "cdcpgv nodes: %ld, offset: base %ld, start %ld, end %ld\n",
                                          CDCPGV_HDR_NODE_NUM(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr));

    pos += CDCPGV_HDR_SIZE;

    for(disk_no = 0; disk_no < disk_num; disk_no ++)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: add disk_no %u to pos %ld\n",
                                               disk_no, pos);

        if(EC_FALSE == cdcdn_add_disk(cdcdn, disk_no, base, &pos))
        {
            dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_create_shm: add disk %u failed\n",
                                                  disk_no);
            /*not need munmap base which was taken over by cdcpgv*/
            cdcdn_close(cdcdn);
            return (NULL_PTR);
        }
    }

    (*s_offset) = CDCDN_BASE_E_OFFSET(cdcdn);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_create_shm: create vol done\n");

    return (cdcdn);
}

EC_BOOL cdcdn_add_disk(CDCDN *cdcdn, const uint16_t disk_no, UINT8 *base, UINT32 *pos)
{
    if(EC_FALSE == cdcpgv_add_disk(CDCDN_CDCPGV(cdcdn), disk_no, base, pos))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_add_disk: cdcpgv add disk %u failed\n",
                                              disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_del_disk(CDCDN *cdcdn, const uint16_t disk_no)
{
    if(EC_FALSE == cdcpgv_del_disk(CDCDN_CDCPGV(cdcdn), disk_no))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_del_disk: cdcpgv del disk %u failed\n",
                                              disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CDCDN *cdcdn_new()
{
    CDCDN *cdcdn;

    alloc_static_mem(MM_CDCDN, &cdcdn, LOC_CDCDN_0001);
    if(NULL_PTR != cdcdn)
    {
        cdcdn_init(cdcdn);
        return (cdcdn);
    }
    return (cdcdn);
}

EC_BOOL cdcdn_init(CDCDN *cdcdn)
{
    CDCDN_RDONLY_FLAG(cdcdn)   = BIT_FALSE;
    CDCDN_DONTDUMP_FLAG(cdcdn) = BIT_FALSE;
    CDCDN_NODE_FD(cdcdn)       = ERR_FD;

    CDCDN_NODE_NUM(cdcdn)      = 0;

    CDCDN_BASE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_BASE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    CDCDN_NODE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_NODE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    CDCDN_CDCPGV(cdcdn)        = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdcdn_clean(CDCDN *cdcdn)
{
    CDCDN_RDONLY_FLAG(cdcdn)   = BIT_FALSE;
    CDCDN_DONTDUMP_FLAG(cdcdn) = BIT_FALSE;
    CDCDN_NODE_FD(cdcdn)       = ERR_FD;

    CDCDN_NODE_NUM(cdcdn)      = 0;

    CDCDN_BASE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_BASE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    CDCDN_NODE_S_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;
    CDCDN_NODE_E_OFFSET(cdcdn) = CDCDN_NODE_ERR_OFFSET;

    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        cdcpgv_free(CDCDN_CDCPGV(cdcdn));
        CDCDN_CDCPGV(cdcdn) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_free(CDCDN *cdcdn)
{
    if(NULL_PTR != cdcdn)
    {
        cdcdn_clean(cdcdn);
        free_static_mem(MM_CDCDN, cdcdn, LOC_CDCDN_0002);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_close(CDCDN *cdcdn)
{
    if(NULL_PTR != cdcdn)
    {
        if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
        {
            cdcpgv_close(CDCDN_CDCPGV(cdcdn));
            CDCDN_CDCPGV(cdcdn) = NULL_PTR;
        }

        return cdcdn_free(cdcdn);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_set_read_only(CDCDN *cdcdn)
{
    if(BIT_TRUE == CDCDN_RDONLY_FLAG(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_set_read_only: "
                                              "cdcdn was set already read-only\n");

        return (EC_FALSE);
    }

    CDCDN_RDONLY_FLAG(cdcdn) = BIT_TRUE;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "[DEBUG] cdcdn_set_read_only: "
                                          "set cdcdn read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdcdn_unset_read_only(CDCDN *cdcdn)
{
    if(BIT_FALSE == CDCDN_RDONLY_FLAG(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_unset_read_only: "
                                              "cdcdn was not set read-only\n");

        return (EC_FALSE);
    }

    CDCDN_RDONLY_FLAG(cdcdn) = BIT_FALSE;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "[DEBUG] cdcdn_unset_read_only: "
                                          "unset cdcdn read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdcdn_is_read_only(const CDCDN *cdcdn)
{
    if(BIT_FALSE == CDCDN_RDONLY_FLAG(cdcdn))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdcdn_set_dontdump(CDCDN *cdcdn)
{
    if(BIT_TRUE == CDCDN_DONTDUMP_FLAG(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_set_dontdump: "
                                              "cdcdn was set already do-not-dump\n");

        return (EC_FALSE);
    }

    CDCDN_DONTDUMP_FLAG(cdcdn) = BIT_TRUE;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "[DEBUG] cdcdn_set_dontdump: "
                                          "set cdcdn do-not-dump\n");

    return (EC_TRUE);
}

EC_BOOL cdcdn_unset_dontdump(CDCDN *cdcdn)
{
    if(BIT_FALSE == CDCDN_DONTDUMP_FLAG(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_unset_dontdump: "
                                              "cdcdn was not set do-not-dump\n");

        return (EC_FALSE);
    }

    CDCDN_DONTDUMP_FLAG(cdcdn) = BIT_FALSE;

    dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "[DEBUG] cdcdn_unset_dontdump: "
                                          "unset cdcdn do-not-dump\n");

    return (EC_TRUE);
}

EC_BOOL cdcdn_is_dontdump(const CDCDN *cdcdn)
{
    if(BIT_FALSE == CDCDN_DONTDUMP_FLAG(cdcdn))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cdcdn_print(LOG *log, const CDCDN *cdcdn)
{
    if(NULL_PTR != cdcdn)
    {
        sys_log(log, "cdcdn_print: cdcdn %p: read-only %u, fd %d, node num %ld, base offset %ld, size %ld, range [%ld, %ld)\n",
                     cdcdn,
                     CDCDN_RDONLY_FLAG(cdcdn),
                     CDCDN_NODE_FD(cdcdn),
                     CDCDN_NODE_NUM(cdcdn),
                     CDCDN_BASE_S_OFFSET(cdcdn),
                     CDCDN_NODE_E_OFFSET(cdcdn) - CDCDN_NODE_S_OFFSET(cdcdn),
                     CDCDN_NODE_S_OFFSET(cdcdn), CDCDN_NODE_E_OFFSET(cdcdn));

        cdcpgv_print(log, CDCDN_CDCPGV(cdcdn));
    }
    return;
}

REAL cdcdn_used_ratio(const CDCDN *cdcdn)
{
    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        return cdcpgv_used_ratio(CDCDN_CDCPGV(cdcdn));
    }

    return (0.0);
}

EC_BOOL cdcdn_is_full(CDCDN *cdcdn)
{
    return cdcpgv_is_full(CDCDN_CDCPGV(cdcdn));
}

/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL cdcdn_read_o(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES <= offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: offset %ld overflow\n", offset);
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < offset + data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: offset %ld + data_max_len %ld = %ld overflow\n",
                            offset, data_max_len, offset + data_max_len);
        return (EC_FALSE);
    }

    node_id  = CDCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = offset;
    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_o: disk %u, block %u  ==> node %ld, start\n", disk_no, block_no, node_id);
    if(EC_FALSE == cdcdn_node_read(cdcdn, node_id, data_max_len, data_buff, &offset_t))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_o: read %ld bytes at offset %ld from node %ld failed\n",
                           data_max_len, offset, node_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_o: disk %u, block %u  ==> node %ld, end\n", disk_no, block_no, node_id);

    if(NULL_PTR != data_len)
    {
        (*data_len) = offset_t - offset;
    }

    return (EC_TRUE);
}

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL cdcdn_write_o(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    node_id  = CDCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = (*offset);

    if(EC_FALSE == cdcdn_node_write(cdcdn, node_id, data_max_len, data_buff, offset))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_o: write %ld bytes to disk %u block %u offset %ld failed\n",
                            data_max_len, disk_no, block_no, offset_t);

        return (EC_FALSE);
    }

    //dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_write_o: write %ld bytes to disk %u block %u offset %ld done\n",
    //                    data_max_len, disk_no, block_no, offset_t);

    return (EC_TRUE);
}

/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cdcdn_read_e(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS)) + offset;
    if(EC_FALSE == cdcdn_read_o(cdcdn, disk_no, block_no, offset_t, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_e: read %ld bytes from disk %u block %u page %u offset %u failed\n",
                           data_max_len, disk_no, block_no, page_no, offset);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cdcdn_write_e(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS)) + offset;
    if(EC_FALSE == cdcdn_write_o(cdcdn, data_max_len, data_buff, disk_no, block_no, &offset_t))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_e: write %ld bytes to disk %u block %u page %u offset %ld failed\n",
                           data_max_len, disk_no, block_no, page_no, offset_t);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_read_p(CDCDN *cdcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)page_no) << (CDCPGB_PAGE_SIZE_NBITS));
    //dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_read_p: disk %u, block %u, page %u ==> offset %ld\n", disk_no, block_no, page_no, offset);
    if(EC_FALSE == cdcdn_read_o(cdcdn, disk_no, block_no, offset, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_read_p: read %ld bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdcdn_write_p(CDCDN *cdcdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    UINT32   offset;
    uint32_t size;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES < data_max_len)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    if(EC_FALSE == cdcpgv_new_space(CDCDN_CDCPGV(cdcdn), size, disk_no, block_no,  page_no))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: new %ld bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)(*page_no)) << (CDCPGB_PAGE_SIZE_NBITS));

    if(EC_FALSE == cdcdn_write_o(cdcdn, data_max_len, data_buff, *disk_no, *block_no, &offset))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_write_p: write %ld bytes to disk %u block %u page %u failed\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));

        cdcpgv_free_space(CDCDN_CDCPGV(cdcdn), *disk_no, *block_no, *page_no, size);
        return (EC_FALSE);
    }
    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_write_p: write %ld bytes to disk %u block %u page %u done\n",
                        data_max_len, (*disk_no), (*block_no), (*page_no));

    return (EC_TRUE);
}

EC_BOOL cdcdn_flush(CDCDN *cdcdn)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       cdcpgv_size;
    UINT32       cdcpgv_offset;

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(ERR_FD == CDCDN_NODE_FD(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: cdcpgv is null\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDCDN_DONTDUMP_FLAG(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: "
                                              "asked not to flush\n");
        return (EC_FALSE);
    }

    cdcpgv     = CDCDN_CDCPGV(cdcdn);
    cdcpgv_hdr = CDCPGV_HEADER(cdcpgv);

    base       = (UINT8 *)cdcpgv_hdr;
    f_s_offset = CDCDN_BASE_S_OFFSET(cdcdn);

    CDCDN_ASSERT(0 == (f_s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK)));

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush: "
                                          "f_s_offset %ld\n",
                                          f_s_offset);

    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);
    CDCDN_ASSERT(CDCDN_BASE_S_OFFSET(cdcdn) + cdcpgv_size == CDCDN_BASE_E_OFFSET(cdcdn));
    CDCDN_ASSERT(CDCDN_NODE_S_OFFSET(cdcdn) == VAL_ALIGN_NEXT(CDCDN_BASE_E_OFFSET(cdcdn), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv_offset = f_s_offset;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush: "
                                          "cdcpgv node num: %ld, cdcpgv header: base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr),
                                          CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr));

    CDCDN_ASSERT(CDCPGV_HDR_NODE_NUM(cdcpgv_hdr)      == CDCDN_NODE_NUM(cdcdn));
    CDCDN_ASSERT(CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr) == CDCDN_BASE_S_OFFSET(cdcdn));
    CDCDN_ASSERT(CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr) == CDCDN_BASE_E_OFFSET(cdcdn));
    CDCDN_ASSERT(CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr) == CDCDN_NODE_S_OFFSET(cdcdn));
    CDCDN_ASSERT(CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr) == CDCDN_NODE_E_OFFSET(cdcdn));

    if(EC_FALSE == c_file_pwrite(CDCDN_NODE_FD(cdcdn), &cdcpgv_offset, cdcpgv_size, base))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_flush: "
                                              "flush cdcpgv to offset %ld, size %ld failed\n",
                                              f_s_offset, cdcpgv_size);
        return (EC_FALSE);
    }

    CDCDN_ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_flush: "
                                          "flush cdcpgv to fd %d, offset %ld => %ld, size %ld done\n",
                                          CDCDN_NODE_FD(cdcdn), f_s_offset, cdcpgv_offset, cdcpgv_size);

    return (EC_TRUE);
}

EC_BOOL cdcdn_load(CDCDN *cdcdn, int fd, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       f_e_offset;
    UINT32       cdcpgv_size;
    UINT32       cdcpgv_offset;
    UINT32       pos;

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: cdcpgv is not null\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: "
                                          "enter: fd %d, s_offset %ld, e_offset %ld\n",
                                          fd, (*s_offset), e_offset);

    /*determine data node header size*/
    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);

    /*determine data node header offset in storage*/
    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (EC_FALSE);
    }

    cdcpgv_offset = f_s_offset;

    base = cdcpgv_mcache_new(cdcpgv_size);
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: new mem cache with size %ld failed\n",
                                              cdcpgv_size);
        return (EC_FALSE);
    }

    /*load data node header from storage*/
    if(EC_FALSE == c_file_pread(fd, &cdcpgv_offset, cdcpgv_size, (UINT8 *)base))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: "
                                              "load cdcpgv from fd %d, offset %ld, size %ld failed\n",
                                              fd, f_s_offset, cdcpgv_size);

        cdcpgv_mcache_free(base);
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: "
                                          "load cdcpgv from fd %d, offset %ld => %ld, size %ld done\n",
                                          fd, f_s_offset, cdcpgv_offset, cdcpgv_size);

    CDCDN_ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: "
                                          "cdcpgv node num: %ld, base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_E_OFFSET((CDCPGV_HDR *)base));

    CDCDN_ASSERT(f_s_offset == CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base));
    CDCDN_ASSERT(f_s_offset + cdcpgv_size == CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base));
    CDCDN_ASSERT(CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base)
            == VAL_ALIGN_NEXT(CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv = cdcpgv_new();
    if(NULL_PTR == cdcpgv)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: new cdcpgv failed\n");

        cdcpgv_mcache_free(base);
        return (EC_FALSE);
    }

    pos = 0;

    CDCPGV_HEADER(cdcpgv) = (CDCPGV_HDR *)base;
    pos += CDCPGV_HDR_SIZE;

    if(EC_FALSE == cdcpgv_load(cdcpgv, base, &pos))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load: load cdcpgv failed\n");

        cdcpgv_free(cdcpgv);
        return (EC_FALSE);
    }
    CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;

    cdcpgv_hdr = (CDCPGV_HDR *)CDCPGV_HEADER(cdcpgv);

    CDCDN_CDCPGV(cdcdn)         = cdcpgv;

    CDCDN_NODE_NUM(cdcdn)       = CDCPGV_HDR_NODE_NUM(cdcpgv_hdr);
    CDCDN_BASE_S_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr);
    CDCDN_BASE_E_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_S_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_E_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr);

    (*s_offset) = f_s_offset + cdcpgv_size;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load: load vol from %d, offset %ld done\n",
                                          fd, f_s_offset);

    return (EC_TRUE);
}

EC_BOOL cdcdn_load_shm(CDCDN *cdcdn, CMMAP_NODE *cmmap_node, int fd, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       f_e_offset;
    UINT32       cdcpgv_size;
    //UINT32       cdcpgv_offset;
    UINT32       pos;

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_shm: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_shm: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_shm: cdcpgv is not null\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_shm: "
                                          "enter: fd %d, s_offset %ld, e_offset %ld\n",
                                          fd, (*s_offset), e_offset);

    /*determine data node header size*/
    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);

    /*determine data node header offset in storage*/
    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_shm: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (EC_FALSE);
    }

    //cdcpgv_offset = f_s_offset;

    base = cmmap_node_alloc(cmmap_node, cdcpgv_size, CDCDN_MEM_ALIGNMENT, "cdc dn");
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_shm: "
                                              "mmap dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_shm: "
                                          "mmap dn done\n");

    //CDCDN_ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_shm: "
                                          "cdcpgv node num: %ld, base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_E_OFFSET((CDCPGV_HDR *)base));

    CDCDN_ASSERT(f_s_offset == CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base));
    CDCDN_ASSERT(f_s_offset + cdcpgv_size == CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base));
    CDCDN_ASSERT(CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base)
            == VAL_ALIGN_NEXT(CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv = cdcpgv_new();
    if(NULL_PTR == cdcpgv)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_shm: new cdcpgv failed\n");

        return (EC_FALSE);
    }

    pos = 0;

    CDCPGV_HEADER(cdcpgv) = (CDCPGV_HDR *)base;
    pos += CDCPGV_HDR_SIZE;

    if(EC_FALSE == cdcpgv_load(cdcpgv, base, &pos))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_load_shm: load cdcpgv failed\n");

        cdcpgv_close(cdcpgv);
        return (EC_FALSE);
    }
    CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;

    cdcpgv_hdr = (CDCPGV_HDR *)CDCPGV_HEADER(cdcpgv);

    CDCDN_CDCPGV(cdcdn)         = cdcpgv;

    CDCDN_NODE_NUM(cdcdn)       = CDCPGV_HDR_NODE_NUM(cdcpgv_hdr);
    CDCDN_BASE_S_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr);
    CDCDN_BASE_E_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_S_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_E_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr);

    (*s_offset) = f_s_offset + cdcpgv_size;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_load_shm: load vol from %d, offset %ld done\n",
                                          fd, f_s_offset);

    return (EC_TRUE);
}

/*retrieve dn from ssd*/
EC_BOOL cdcdn_retrieve_shm(CDCDN *cdcdn, CMMAP_NODE *cmmap_node, int fd, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCPGV      *cdcpgv;
    CDCPGV_HDR  *cdcpgv_hdr;
    UINT8       *base;
    UINT32       f_s_offset;
    UINT32       f_e_offset;
    UINT32       cdcpgv_size;
    UINT32       cdcpgv_offset;
    UINT32       pos;

    if(ERR_FD == fd)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: no fd\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: cdcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CDCDN_CDCPGV(cdcdn))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: cdcpgv is not null\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_retrieve_shm: "
                                          "enter: fd %d, s_offset %ld, e_offset %ld\n",
                                          fd, (*s_offset), e_offset);

    /*determine data node header size*/
    cdcpgv_aligned_size(&cdcpgv_size, (UINT32)CDCPGB_PAGE_SIZE_MASK);

    /*determine data node header offset in storage*/
    f_s_offset = VAL_ALIGN_NEXT(*s_offset, ((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to one page*/
    f_e_offset = VAL_ALIGN_HEAD(e_offset , ((UINT32)CDCPGB_SIZE_MASK));      /*align to one block*/

    if(f_s_offset + cdcpgv_size >= f_e_offset)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: "
                                              "header size %ld >= range covers [%ld, %ld) "
                                              "which is aligned from range [%ld, %ld)\n",
                                              cdcpgv_size,
                                              f_s_offset, f_e_offset,
                                              (*s_offset), e_offset);
        return (EC_FALSE);
    }

    //cdcpgv_offset = f_s_offset;

    base = cmmap_node_alloc(cmmap_node, cdcpgv_size, CDCDN_MEM_ALIGNMENT, "cdc dn");
    if(NULL_PTR == base)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: "
                                              "mmap dn failed\n");
        return (EC_FALSE);
    }

    cdcpgv_offset = f_s_offset;

    /*load data node header from storage*/
    if(EC_FALSE == c_file_pread(fd, &cdcpgv_offset, cdcpgv_size, (UINT8 *)base))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: "
                                              "load cdcpgv from fd %d, offset %ld, size %ld failed\n",
                                              fd, f_s_offset, cdcpgv_size);

        return (EC_FALSE);
    }

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_retrieve_shm: "
                                          "load cdcpgv from fd %d, offset %ld => %ld, size %ld done\n",
                                          fd, f_s_offset, cdcpgv_offset, cdcpgv_size);

    //CDCDN_ASSERT(f_s_offset + cdcpgv_size == cdcpgv_offset);

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_retrieve_shm: "
                                          "cdcpgv node num: %ld, base [%ld, %ld), node [%ld, %ld)\n",
                                          CDCPGV_HDR_NODE_NUM((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base),
                                          CDCPGV_HDR_NODE_E_OFFSET((CDCPGV_HDR *)base));

    CDCDN_ASSERT(f_s_offset == CDCPGV_HDR_BASE_S_OFFSET((CDCPGV_HDR *)base));
    CDCDN_ASSERT(f_s_offset + cdcpgv_size == CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base));
    CDCDN_ASSERT(CDCPGV_HDR_NODE_S_OFFSET((CDCPGV_HDR *)base)
            == VAL_ALIGN_NEXT(CDCPGV_HDR_BASE_E_OFFSET((CDCPGV_HDR *)base), ((UINT32)CDCPGB_SIZE_MASK)));

    cdcpgv = cdcpgv_new();
    if(NULL_PTR == cdcpgv)
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: new cdcpgv failed\n");

        return (EC_FALSE);
    }

    pos = 0;

    CDCPGV_HEADER(cdcpgv) = (CDCPGV_HDR *)base;
    pos += CDCPGV_HDR_SIZE;

    if(EC_FALSE == cdcpgv_load(cdcpgv, base, &pos))
    {
        dbg_log(SEC_0187_CDCDN, 0)(LOGSTDOUT, "error:cdcdn_retrieve_shm: load cdcpgv failed\n");

        cdcpgv_close(cdcpgv);
        return (EC_FALSE);
    }
    CDCPGV_SIZE(cdcpgv) = CDCPGV_HDR_SIZE;

    cdcpgv_hdr = (CDCPGV_HDR *)CDCPGV_HEADER(cdcpgv);

    CDCDN_CDCPGV(cdcdn)         = cdcpgv;

    CDCDN_NODE_NUM(cdcdn)       = CDCPGV_HDR_NODE_NUM(cdcpgv_hdr);
    CDCDN_BASE_S_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_S_OFFSET(cdcpgv_hdr);
    CDCDN_BASE_E_OFFSET(cdcdn)  = CDCPGV_HDR_BASE_E_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_S_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_S_OFFSET(cdcpgv_hdr);
    CDCDN_NODE_E_OFFSET(cdcdn)  = CDCPGV_HDR_NODE_E_OFFSET(cdcpgv_hdr);

    (*s_offset) = f_s_offset + cdcpgv_size;

    dbg_log(SEC_0187_CDCDN, 9)(LOGSTDOUT, "[DEBUG] cdcdn_retrieve_shm: load vol from %d, offset %ld done\n",
                                          fd, f_s_offset);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

