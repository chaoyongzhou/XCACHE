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
#include <ctype.h>
#include <errno.h>

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cmisc.h"

#include "real.h"

#include "cmcdn.h"
#include "cmcpgrb.h"
#include "cmcpgb.h"
#include "cmcpgd.h"
#include "cmcpgv.h"


/*Memory Cache Data Node*/
void *cmcdn_node_fetch(const CMCDN *cmcdn, const UINT32 node_id)
{
    UINT32      node_id_t;

    node_id_t = (node_id >> CMCDN_SEG_NO_NBITS);
    if(node_id_t >= CMCDN_NODE_NUM(cmcdn))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_node_fetch: node_id %ld overflow\n", node_id);
        return (NULL_PTR);
    }

    return (CMCDN_NODE_START_ADDR(cmcdn) + (node_id_t << CMCDN_NODE_BIT_SIZE));
}

EC_BOOL cmcdn_node_write(CMCDN *cmcdn, const UINT32 node_id, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *offset)
{
    void        *cmcdn_node;
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/

    cmcdn_node = cmcdn_node_fetch(cmcdn, node_id);
    if(NULL_PTR == cmcdn_node)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_node_write: open node %ld failed\n", node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CMCDN_NODE_ID_GET_SEG_NO(node_id)) << CMCPGB_CACHE_BIT_SIZE);
    offset_r = offset_b + (*offset);

    BCOPY(data_buff, cmcdn_node + offset_r, data_max_len);

    (*offset) += data_max_len;

    return (EC_TRUE);
}

EC_BOOL cmcdn_node_read(CMCDN *cmcdn, const UINT32 node_id, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *offset)
{
    void        *cmcdn_node;
    UINT32       offset_b; /*base offset in block*/
    UINT32       offset_r; /*real offset in block*/

    cmcdn_node = cmcdn_node_fetch(cmcdn, node_id);
    if(NULL_PTR == cmcdn_node)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_node_read: open node %ld failed\n", node_id);
        return (EC_FALSE);
    }

    offset_b = (((UINT32)CMCDN_NODE_ID_GET_SEG_NO(node_id)) << CMCPGB_CACHE_BIT_SIZE);
    offset_r = offset_b + (*offset);

    BCOPY(cmcdn_node + offset_r, data_buff, data_max_len);

    (*offset) += data_max_len;
    return (EC_TRUE);
}

CMCDN *cmcdn_create(const uint16_t disk_num)
{
    CMCDN   *cmcdn;
    UINT32   block_num;
    UINT32   node_num;
    UINT32   size;
    void    *base;

    uint16_t disk_no;

    block_num = ((UINT32)disk_num) * ((UINT32)CMCPGD_MAX_BLOCK_NUM);
    node_num  = (block_num >> CMCDN_SEG_NO_NBITS); /*num of nodes.  one node = several continuous blocks*/

    size      = block_num * CMCDN_NODE_BYTE_SIZE;

    /*align to one node size*/
    if(0 != posix_memalign(&base, (size_t)CMCDN_NODE_BYTE_SIZE, (size_t)size))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_create: alloc %ld bytes with alignment %ld failed\n",
                                              size, CMCDN_NODE_BYTE_SIZE);
        return (NULL_PTR);
    }

    ASSERT(NULL_PTR != base);

    cmcdn = cmcdn_new();
    if(NULL_PTR == cmcdn)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_create: new cmcdn failed\n");
        free(base);
        return (NULL_PTR);
    }

    CMCDN_NODE_NUM(cmcdn)        = node_num;
    CMCDN_NODE_BASE_ADDR(cmcdn)  = base;
    CMCDN_NODE_START_ADDR(cmcdn) = CMCDN_NODE_BASE_ADDR(cmcdn)  + 0;
    CMCDN_NODE_END_ADDR(cmcdn)   = CMCDN_NODE_START_ADDR(cmcdn) + size;

    CMCDN_CMCPGV(cmcdn) = cmcpgv_new();
    if(NULL_PTR == CMCDN_CMCPGV(cmcdn))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_create: new vol failed\n");
        cmcdn_free(cmcdn);
        return (NULL_PTR);
    }

    for(disk_no = 0; disk_no < disk_num; disk_no ++)
    {
        if(EC_FALSE == cmcdn_add_disk(cmcdn, disk_no))
        {
            dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_create: add disk %u failed\n", disk_no);
            cmcdn_free(cmcdn);
            return (NULL_PTR);
        }
    }

    dbg_log(SEC_0110_CMCDN, 9)(LOGSTDOUT, "[DEBUG] cmcdn_create: vol was created\n");

    return (cmcdn);
}

EC_BOOL cmcdn_add_disk(CMCDN *cmcdn, const uint16_t disk_no)
{
    if(EC_FALSE == cmcpgv_add_disk(CMCDN_CMCPGV(cmcdn), disk_no))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_add_disk: cmcpgv add disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cmcdn_del_disk(CMCDN *cmcdn, const uint16_t disk_no)
{
    if(EC_FALSE == cmcpgv_del_disk(CMCDN_CMCPGV(cmcdn), disk_no))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_del_disk: cmcpgv del disk %u failed\n", disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

CMCDN *cmcdn_new()
{
    CMCDN *cmcdn;

    alloc_static_mem(MM_CMCDN, &cmcdn, LOC_CMCDN_0001);
    if(NULL_PTR != cmcdn)
    {
        cmcdn_init(cmcdn);
        return (cmcdn);
    }
    return (cmcdn);
}

EC_BOOL cmcdn_init(CMCDN *cmcdn)
{
    CMCDN_NODE_NUM(cmcdn) = 0;

    CMCDN_NODE_BASE_ADDR(cmcdn)  = NULL_PTR;
    CMCDN_NODE_START_ADDR(cmcdn) = NULL_PTR;
    CMCDN_NODE_END_ADDR(cmcdn)   = NULL_PTR;

    CMCDN_CMCPGV(cmcdn)          = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cmcdn_clean(CMCDN *cmcdn)
{
    CMCDN_NODE_NUM(cmcdn) = 0;

    if(NULL_PTR != CMCDN_NODE_BASE_ADDR(cmcdn))
    {
        free(CMCDN_NODE_BASE_ADDR(cmcdn));
        CMCDN_NODE_BASE_ADDR(cmcdn) = NULL_PTR;
    }

    CMCDN_NODE_START_ADDR(cmcdn) = NULL_PTR;
    CMCDN_NODE_END_ADDR(cmcdn)   = NULL_PTR;

    if(NULL_PTR != CMCDN_CMCPGV(cmcdn))
    {
        cmcpgv_free(CMCDN_CMCPGV(cmcdn));
        CMCDN_CMCPGV(cmcdn) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cmcdn_free(CMCDN *cmcdn)
{
    if(NULL_PTR != cmcdn)
    {
        cmcdn_clean(cmcdn);
        free_static_mem(MM_CMCDN, cmcdn, LOC_CMCDN_0002);
    }
    return (EC_TRUE);
}

void cmcdn_print(LOG *log, const CMCDN *cmcdn)
{
    if(NULL_PTR != cmcdn)
    {
        sys_log(log, "cmcdn_print: cmcdn %p: node num %ld, base addr %p\n",
                     cmcdn,
                     CMCDN_NODE_NUM(cmcdn),
                     CMCDN_NODE_BASE_ADDR(cmcdn));

        cmcpgv_print(log, CMCDN_CMCPGV(cmcdn));
    }
    return;
}

EC_BOOL cmcdn_is_full(CMCDN *cmcdn)
{
    return cmcpgv_is_full(CMCDN_CMCPGV(cmcdn));
}

/*random access for reading, the offset is for the whole 64M page-block */
EC_BOOL cmcdn_read_o(CMCDN *cmcdn, const uint16_t disk_no, const uint16_t block_no, const UINT32 offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cmcdn)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_o: cmcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    if(CMCPGB_CACHE_MAX_BYTE_SIZE <= offset)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_o: offset %ld overflow\n", offset);
        return (EC_FALSE);
    }

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < offset + data_max_len)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_o: offset %ld + data_max_len %ld = %ld overflow\n",
                            offset, data_max_len, offset + data_max_len);
        return (EC_FALSE);
    }

    node_id  = CMCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = offset;
    dbg_log(SEC_0110_CMCDN, 9)(LOGSTDOUT, "[DEBUG] cmcdn_read_o: disk %u, block %u  ==> node %ld, start\n", disk_no, block_no, node_id);
    if(EC_FALSE == cmcdn_node_read(cmcdn, node_id, data_max_len, data_buff, &offset_t))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_o: read %ld bytes at offset %ld from node %ld failed\n",
                           data_max_len, offset, node_id);
        return (EC_FALSE);
    }
    dbg_log(SEC_0110_CMCDN, 9)(LOGSTDOUT, "[DEBUG] cmcdn_read_o: disk %u, block %u  ==> node %ld, end\n", disk_no, block_no, node_id);

    if(NULL_PTR != data_len)
    {
        (*data_len) = offset_t - offset;
    }

    return (EC_TRUE);
}

/*random access for writting */
/*offset: IN/OUT, the offset is for the whole 64M page-block*/
EC_BOOL cmcdn_write_o(CMCDN *cmcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, UINT32 *offset)
{
    UINT32 node_id;
    UINT32 offset_t;

    if(NULL_PTR == cmcdn)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_o: cmcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_o: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_o: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    node_id  = CMCDN_NODE_ID_MAKE(disk_no, block_no);
    offset_t = (*offset);

    if(EC_FALSE == cmcdn_node_write(cmcdn, node_id, data_max_len, data_buff, offset))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_o: write %ld bytes to disk %u block %u offset %ld failed\n",
                            data_max_len, disk_no, block_no, offset_t);

        return (EC_FALSE);
    }

    //dbg_log(SEC_0110_CMCDN, 9)(LOGSTDOUT, "[DEBUG] cmcdn_write_o: write %ld bytes to disk %u block %u offset %ld done\n",
    //                    data_max_len, disk_no, block_no, offset_t);

    return (EC_TRUE);
}

/*random access for reading, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cmcdn_read_e(CMCDN *cmcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CMCPGB_PAGE_BIT_SIZE)) + offset;
    if(EC_FALSE == cmcdn_read_o(cmcdn, disk_no, block_no, offset_t, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_e: read %ld bytes from disk %u block %u page %u offset %u failed\n",
                           data_max_len, disk_no, block_no, page_no, offset);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/*random access for writting, the offset is for the user file but not for the whole 64M page-block */
EC_BOOL cmcdn_write_e(CMCDN *cmcdn, const UINT32 data_max_len, const UINT8 *data_buff, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const uint32_t offset)
{
    UINT32 offset_t;

    offset_t  = (((UINT32)page_no) << (CMCPGB_PAGE_BIT_SIZE)) + offset;
    if(EC_FALSE == cmcdn_write_o(cmcdn, data_max_len, data_buff, disk_no, block_no, &offset_t))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_e: write %ld bytes to disk %u block %u page %u offset %ld failed\n",
                           data_max_len, disk_no, block_no, page_no, offset_t);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cmcdn_read_p(CMCDN *cmcdn, const uint16_t disk_no, const uint16_t block_no, const uint16_t page_no, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 offset;

    if(NULL_PTR == cmcdn)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_p: cmcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)page_no) << (CMCPGB_PAGE_BIT_SIZE));
    //dbg_log(SEC_0110_CMCDN, 9)(LOGSTDOUT, "[DEBUG] cmcdn_read_p: disk %u, block %u, page %u ==> offset %ld\n", disk_no, block_no, page_no, offset);
    if(EC_FALSE == cmcdn_read_o(cmcdn, disk_no, block_no, offset, data_max_len, data_buff, data_len))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_read_p: read %ld bytes from disk %u block %u page %u failed\n",
                           data_max_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cmcdn_write_p(CMCDN *cmcdn, const UINT32 data_max_len, const UINT8 *data_buff, uint16_t *disk_no, uint16_t *block_no, uint16_t *page_no)
{
    UINT32   offset;
    uint32_t size;

    if(NULL_PTR == cmcdn)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_p: cmcdn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == data_buff)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_p: data_buff is null\n");
        return (EC_FALSE);
    }

    if(CMCPGB_CACHE_MAX_BYTE_SIZE < data_max_len)
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_p: data max len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    size = (uint32_t)(data_max_len);

    if(EC_FALSE == cmcpgv_new_space(CMCDN_CMCPGV(cmcdn), size, disk_no, block_no,  page_no))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_p: new %ld bytes space from vol failed\n", data_max_len);
        return (EC_FALSE);
    }

    offset  = (((UINT32)(*page_no)) << (CMCPGB_PAGE_BIT_SIZE));

    if(EC_FALSE == cmcdn_write_o(cmcdn, data_max_len, data_buff, *disk_no, *block_no, &offset))
    {
        dbg_log(SEC_0110_CMCDN, 0)(LOGSTDOUT, "error:cmcdn_write_p: write %ld bytes to disk %u block %u page %u failed\n",
                            data_max_len, (*disk_no), (*block_no), (*page_no));

        cmcpgv_free_space(CMCDN_CMCPGV(cmcdn), *disk_no, *block_no, *page_no, size);
        return (EC_FALSE);
    }
    dbg_log(SEC_0110_CMCDN, 9)(LOGSTDOUT, "[DEBUG] cmcdn_write_p: write %ld bytes to disk %u block %u page %u done\n",
                        data_max_len, (*disk_no), (*block_no), (*page_no));

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

