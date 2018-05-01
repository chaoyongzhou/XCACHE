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
#include "cmpic.inc"
#include "cmutex.h"
#include "cmisc.h"

#include "clist.h"

#include "task.h"

#include "cdsk.h"
#include "cdfsdn.h"


STATIC_CAST static void cdfsdn_clean_buff(UINT8 *buff, const UINT32 len)
{
    BSET(buff, '\0', len);
    return;
}

CDFSDN_CACHE *cdfsdn_cache_new()
{
    CDFSDN_CACHE *cdfsdn_cache;

    alloc_static_mem(MM_CDFSDN_CACHE, &cdfsdn_cache, LOC_CDFSDN_0001);
    if(NULL_PTR != cdfsdn_cache)
    {
        cdfsdn_cache_init(cdfsdn_cache);
    }
    return (cdfsdn_cache);
}

EC_BOOL cdfsdn_cache_init(CDFSDN_CACHE *cdfsdn_cache)
{
    UINT32FIXED partition_idx;

    for(partition_idx = 0; partition_idx < CDFSDN_BLOCK_PART_MAX_NUM; partition_idx ++)
    {
        CDFSDN_CACHE_PART_NEXT_IDX(cdfsdn_cache, partition_idx) = (partition_idx + 1);
    }

    CDFSDN_CACHE_PART_NEXT_IDX(cdfsdn_cache, CDFSDN_BLOCK_PART_MAX_NUM - 1) = CDFSDN_ERR_PART_IDX;

    return (EC_TRUE);
}

EC_BOOL cdfsdn_cache_clean(CDFSDN_CACHE *cdfsdn_cache)
{
    return (EC_TRUE);
}

EC_BOOL cdfsdn_cache_free(CDFSDN_CACHE *cdfsdn_cache)
{
    if(NULL_PTR != cdfsdn_cache)
    {
        cdfsdn_cache_clean(cdfsdn_cache);
        free_static_mem(MM_CDFSDN_CACHE, cdfsdn_cache, LOC_CDFSDN_0002);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsdn_cache_clone(const CDFSDN_CACHE *cdfsdn_cache_src, CDFSDN_CACHE *cdfsdn_cache_des)
{
    UINT8 *src;
    UINT8 *des;

    src = (UINT8 *)CDFSDN_CACHE_DATA(cdfsdn_cache_src);
    des = (UINT8 *)CDFSDN_CACHE_DATA(cdfsdn_cache_des);
    BCOPY(src, des, CDFSDN_BLOCK_DATA_MAX_SIZE);
    return (EC_TRUE);
}

void cdfsdn_cache_print(LOG *log, const CDFSDN_CACHE *cdfsdn_cache)
{
    UINT32 pos;
    sys_print(log, "cdfsdn_cache %lx: data: ", cdfsdn_cache);
    for(pos = 0; pos < CDFSDN_BLOCK_DATA_MAX_SIZE; pos ++)
    {
        sys_print(log, "%02x,", CDFSDN_CACHE_DATA(cdfsdn_cache)[ pos ]);
    }
    sys_print(log, "\n");
    return;
}

CDFSDN_STAT *cdfsdn_stat_new()
{
    CDFSDN_STAT *cdfsdn_stat;
    alloc_static_mem(MM_CDFSDN_STAT, &cdfsdn_stat, LOC_CDFSDN_0003);
    cdfsdn_stat_init(cdfsdn_stat);
    return (cdfsdn_stat);
}

EC_BOOL cdfsdn_stat_init(CDFSDN_STAT *cdfsdn_stat)
{
    CDFSDN_STAT_TCID(cdfsdn_stat) = CMPI_ERROR_TCID;
    CDFSDN_STAT_FULL(cdfsdn_stat) = CDFSDN_STAT_IS_NOT_FULL;
    return (EC_TRUE);
}

EC_BOOL cdfsdn_stat_clean(CDFSDN_STAT *cdfsdn_stat)
{
    CDFSDN_STAT_TCID(cdfsdn_stat) = CMPI_ERROR_TCID;
    CDFSDN_STAT_FULL(cdfsdn_stat) = CDFSDN_STAT_IS_NOT_FULL;
    return (EC_TRUE);
}

EC_BOOL cdfsdn_stat_free(CDFSDN_STAT *cdfsdn_stat)
{
    if(NULL_PTR != cdfsdn_stat)
    {
        cdfsdn_stat_clean(cdfsdn_stat);
        free_static_mem(MM_CDFSDN_STAT, cdfsdn_stat, LOC_CDFSDN_0004);
    }
    return (EC_TRUE);
}

CDFSDN_RECORD_MGR *cdfsdn_record_mgr_new(const UINT32 disk_num, const UINT32 record_num, const UINT32 record_beg)
{
    CDFSDN_RECORD_MGR *cdfsdn_record_mgr;
    CDFSDN_RECORD *data_area;

    data_area = (CDFSDN_RECORD *)SAFE_MALLOC(record_num * sizeof(CDFSDN_RECORD), LOC_CDFSDN_0005);
    if(NULL_PTR == data_area)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_new: alloc bitmap of %ld block files failed\n", record_num);
        return (NULL_PTR);
    }

    alloc_static_mem(MM_CDFSDN_RECORD_MGR, &cdfsdn_record_mgr, LOC_CDFSDN_0006);
    if(NULL_PTR == cdfsdn_record_mgr)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_new: alloc record mgr failed\n");
        SAFE_FREE(data_area, LOC_CDFSDN_0007);
        return (NULL_PTR);
    }

    CDFSDN_RECORD_MGR_NODE_TBL(cdfsdn_record_mgr) = data_area;
    cdfsdn_record_mgr_init(cdfsdn_record_mgr, disk_num, record_num, record_beg);

    return (cdfsdn_record_mgr);

}

EC_BOOL cdfsdn_record_mgr_init(CDFSDN_RECORD_MGR *cdfsdn_record_mgr, const UINT32 disk_num, const UINT32 record_num, const UINT32 record_beg)
{
    UINT32 record_pos;

    CDFSDN_RECORD_MGR_INIT_CMUTEX_LOCK(cdfsdn_record_mgr, LOC_CDFSDN_0008);

    CDFSDN_RECORD_MGR_DISK_NUM(cdfsdn_record_mgr) = disk_num;
    CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr) = record_num;
    CDFSDN_RECORD_MGR_NODE_BEG(cdfsdn_record_mgr) = record_beg;

    for(record_pos = 0; record_pos < record_num; record_pos ++)
    {
        CDFSDN_RECORD *cdfsdn_record;
        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, record_pos);

        CDFSDN_RECORD_FLAG(cdfsdn_record)               = (UINT32) 0;
        CDFSDN_RECORD_READER_NUM(cdfsdn_record)         = (UINT32) 0;
        CDFSDN_RECORD_SIZE(cdfsdn_record)               = (UINT32) 0;
        CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record)     = (UINT32) 0;
        //never set CDFSDN_RECORD_NEXT
    }
    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_mgr_link(CDFSDN_RECORD_MGR *cdfsdn_record_mgr)
{
    UINT32 record_pos;

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_record_mgr_link: CDFSDN_RECORD_MGR_NODE_NUM = %ld\n", 
                        (UINT32)CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr));

    for(record_pos = 0; record_pos < CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr); record_pos ++)
    {
        CDFSDN_RECORD *cdfsdn_record;
        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, record_pos);
        CDFSDN_RECORD_NEXT(cdfsdn_record) =  record_pos + 1;
    }
    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_mgr_clear_flags(CDFSDN_RECORD_MGR *cdfsdn_record_mgr)
{
    UINT32 record_pos;

    for(record_pos = 0; record_pos < CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr); record_pos ++)
    {
        CDFSDN_RECORD *cdfsdn_record;
        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, record_pos);

        CDFSDN_RECORD_FLAG(cdfsdn_record)               = (UINT32) 0;
        CDFSDN_RECORD_READER_NUM(cdfsdn_record)         = (UINT32) 0;
        CDFSDN_RECORD_SIZE(cdfsdn_record)              &= (UINT32) CDFSDN_32BIT_MASK;
        //never clear CDFSDN_RECORD_NEXT
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_mgr_clean(CDFSDN_RECORD_MGR *cdfsdn_record_mgr)
{
    if(NULL_PTR != cdfsdn_record_mgr)
    {
        CDFSDN_RECORD_MGR_CLEAN_CMUTEX_LOCK(cdfsdn_record_mgr, LOC_CDFSDN_0009);

        CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr) = 0;
        CDFSDN_RECORD_MGR_NODE_BEG(cdfsdn_record_mgr) = 0;

        SAFE_FREE(CDFSDN_RECORD_MGR_NODE_TBL(cdfsdn_record_mgr), LOC_CDFSDN_0010);
        CDFSDN_RECORD_MGR_NODE_TBL(cdfsdn_record_mgr) = NULL_PTR;
    }
    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_mgr_free(CDFSDN_RECORD_MGR *cdfsdn_record_mgr)
{
    if(NULL_PTR != cdfsdn_record_mgr)
    {
        SAFE_FREE(CDFSDN_RECORD_MGR_NODE_TBL(cdfsdn_record_mgr), LOC_CDFSDN_0011);
        CDFSDN_RECORD_MGR_NODE_TBL(cdfsdn_record_mgr) = NULL_PTR;
        free_static_mem(MM_CDFSDN_RECORD_MGR, cdfsdn_record_mgr, LOC_CDFSDN_0012);
    }
    return (EC_TRUE);
}

void cdfsdn_record_mgr_print(LOG *log, const CDFSDN_RECORD_MGR *cdfsdn_record_mgr)
{
    UINT32 record_pos;
    UINT32 total_size_in_kb;

    sys_log(log, "disk num %ld, record num %ld, beg pos %ld\n",
                 (UINT32)CDFSDN_RECORD_MGR_DISK_NUM(cdfsdn_record_mgr),
                 (UINT32)CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr),
                 (UINT32)CDFSDN_RECORD_MGR_NODE_BEG(cdfsdn_record_mgr));

    for(record_pos = 0, total_size_in_kb = 0; record_pos < CDFSDN_RECORD_MGR_NODE_NUM(cdfsdn_record_mgr); record_pos ++)
    {
        CDFSDN_RECORD *cdfsdn_record;
        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(cdfsdn_record_mgr, record_pos);

        if(0 == CDFSDN_RECORD_SIZE(cdfsdn_record))
        {
            continue;
        }

        /*only print the used record info*/
        sys_log(log, "record %ld#: cached flag %ld, updated flag %ld, write flag %ld, swapout flag %ld, reader num %ld, size %ld, room %ld, first free partition %ld, next record %ld\n",
                    record_pos,
                    CDFSDN_RECORD_CACHED_FLAG(cdfsdn_record),
                    CDFSDN_RECORD_UPDATED_FLAG(cdfsdn_record),
                    CDFSDN_RECORD_WRITE_FLAG(cdfsdn_record),
                    CDFSDN_RECORD_SWAPOUT_FLAG(cdfsdn_record),
                    CDFSDN_RECORD_READER_NUM(cdfsdn_record) & CDFSDN_32BIT_MASK,
                    CDFSDN_RECORD_SIZE(cdfsdn_record),
                    CDFSDN_RECORD_ROOM(cdfsdn_record),
                    CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record),
                    CDFSDN_RECORD_NEXT(cdfsdn_record));

        total_size_in_kb += (CDFSDN_RECORD_SIZE(cdfsdn_record) >> 10);
    }

    /*note: on 32bit OS, the counted size only support up to 4TB*/
    sys_log(log, "total size %ld KB or %ld MB or %ld GB\n", total_size_in_kb, (total_size_in_kb >> 10), (total_size_in_kb >> 20));
    return;
}

EC_BOOL cdfsdn_record_mgr_load(CDFSDN *cdfsdn)
{
    RWSIZE rsize;
    RWSIZE csize;/*read completed size*/
    RWSIZE osize;/*read once size*/

    UINT32 disk_num;

    UINT8 *buff;

    if(ERR_FD == CDFSDN_RECORD_FD(cdfsdn))
    {
        CDFSDN_RECORD_FD(cdfsdn) = c_file_open((char *)CDFSDN_RECORD_NAME(cdfsdn), O_RDWR, 0666);
        if(ERR_FD == CDFSDN_RECORD_FD(cdfsdn))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_load: cannot open record file %s\n", (char *)CDFSDN_RECORD_NAME(cdfsdn));
            return (EC_FALSE);
        }
    }

    if(ERR_SEEK == lseek(CDFSDN_RECORD_FD(cdfsdn), 0, SEEK_SET))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_load: seek record file beg failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSDN_RECORD_MGR(cdfsdn))
    {
        UINT32  record_num;
        UINT32  record_beg;

        rsize = sizeof(UINT32);
        if(rsize != read(CDFSDN_RECORD_FD(cdfsdn), &disk_num, rsize))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_load: load disk num failed\n");
            return (EC_FALSE);
        }

        rsize = sizeof(UINT32);
        if(rsize != read(CDFSDN_RECORD_FD(cdfsdn), &record_num, rsize))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_load: load record num failed\n");
            return (EC_FALSE);
        }

        rsize = sizeof(UINT32);
        if(rsize != read(CDFSDN_RECORD_FD(cdfsdn), &record_beg, rsize))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_load: load record beg pos failed\n");
            return (EC_FALSE);
        }

        CDFSDN_RECORD_MGR(cdfsdn) = cdfsdn_record_mgr_new(disk_num, record_num, record_beg);
        if(NULL_PTR == CDFSDN_RECORD_MGR(cdfsdn))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_load: new record failed where record num = %ld\n", record_num);
            return (EC_FALSE);
        }
    }

    rsize = CDFSDN_NODE_NUM(cdfsdn) * sizeof(CDFSDN_RECORD);
    buff = (UINT8 *)CDFSDN_NODE_TBL(cdfsdn);
    for(csize = 0, osize = CDFSDN_READ_ONCE_MAX_BYTES; csize < rsize; csize += osize)
    {
        if(csize + osize > rsize)
        {
            osize = rsize - csize;
        }

        if(osize != read(CDFSDN_RECORD_FD(cdfsdn), buff + csize, osize))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_load: load record table failed where record num %ld, rsize %ld, csize %ld, osize %ld, errno %d, errstr %s\n",
                                (UINT32)CDFSDN_NODE_NUM(cdfsdn), rsize, csize, osize, errno, strerror(errno));
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == cdfsdn_record_mgr_clear_flags(CDFSDN_RECORD_MGR(cdfsdn)))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_load: clear record mgr flags failed\n");
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_mgr_flush(CDFSDN *cdfsdn)
{
    RWSIZE wsize;
    RWSIZE csize;/*write completed size*/
    RWSIZE osize;/*write once size*/

    UINT32  disk_num;

    UINT32  record_num;
    UINT32  record_beg;

    UINT8 *buff;

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_record_mgr_flush was called\n");

    if(ERR_SEEK == lseek(CDFSDN_RECORD_FD(cdfsdn), 0, SEEK_SET))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_flush: seek record file beg failed\n");
        return (EC_FALSE);
    }

    disk_num = CDFSDN_DISK_NUM(cdfsdn);
    wsize = sizeof(UINT32);
    if(wsize != write(CDFSDN_RECORD_FD(cdfsdn), &disk_num, wsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_flush: flush disk num %ld failed \n", disk_num);
        return (EC_FALSE);
    }

    record_num = CDFSDN_NODE_NUM(cdfsdn);
    wsize = sizeof(UINT32);
    if(wsize != write(CDFSDN_RECORD_FD(cdfsdn), &record_num, wsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_flush: flush record num %ld failed \n", record_num);
        return (EC_FALSE);
    }

    record_beg = CDFSDN_NODE_BEG(cdfsdn);
    wsize = sizeof(UINT32);
    if(wsize != write(CDFSDN_RECORD_FD(cdfsdn), &record_beg, wsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_flush: flush record beg pos %ld failed \n", record_beg);
        return (EC_FALSE);
    }

    wsize = record_num * sizeof(CDFSDN_RECORD);
    buff = (UINT8 *)CDFSDN_NODE_TBL(cdfsdn);
    for(csize = 0, osize = CDFSDN_WRITE_ONCE_MAX_BYTES; csize < wsize; csize += osize)
    {
        if(csize + osize > wsize)
        {
            osize = wsize - csize;
        }

        if(osize != write(CDFSDN_RECORD_FD(cdfsdn), buff + csize, osize))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_flush: flush record table failed where record num %ld, wsize %ld, csize %ld, osize %ld, errno %d, errstr %s\n",
                                record_num, wsize, csize, osize, errno, strerror(errno));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_mgr_flush_has_lock(CDFSDN *cdfsdn)
{
    EC_BOOL ret;
    CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0013);
    ret = cdfsdn_record_mgr_flush(cdfsdn);
    CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0014);
    return (ret);
}

EC_BOOL cdfsdn_record_mgr_set(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 cache_size)
{
    if(path_layout > CDFSDN_NODE_NUM(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_set: path layout %ld overflow record num %ld\n",
                            path_layout, (UINT32)CDFSDN_NODE_NUM(cdfsdn));
        return (EC_FALSE);
    }

    CDFSDN_NODE_SIZE(cdfsdn, path_layout) = cache_size;
    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_mgr_get(const CDFSDN *cdfsdn, const UINT32 path_layout, UINT32 *cache_size)
{
    if(path_layout > CDFSDN_NODE_NUM(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_mgr_get: path layout %ld overflow record num %ld\n",
                            path_layout, (UINT32)CDFSDN_NODE_NUM(cdfsdn));
        return (EC_FALSE);
    }

    (*cache_size) = CDFSDN_NODE_SIZE(cdfsdn, path_layout);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_is_full(const CDFSDN *cdfsdn, const UINT32 path_layout)
{
    if(path_layout > CDFSDN_NODE_NUM(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_record_is_full: path layout %ld overflow record num %ld\n",
                            path_layout, (UINT32)CDFSDN_NODE_NUM(cdfsdn));
        return (EC_TRUE);
    }
    if(CDFSDN_NODE_IS_FULL(cdfsdn, path_layout))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdfsdn_record_rmv(const CDFSDN * cdfsdn)
{
    if (NULL_PTR == CDFSDN_RECORD_NAME(cdfsdn))
    {
        return (EC_FALSE);
    }

    if(0 != unlink((char *)CDFSDN_RECORD_NAME(cdfsdn)))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_init(CDFSDN_RECORD *cdfsdn_record)
{
    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_clean(CDFSDN_RECORD *cdfsdn_record)
{
    return (EC_TRUE);
}

EC_BOOL cdfsdn_record_free(CDFSDN_RECORD *cdfsdn_record)
{
    return (EC_TRUE);
}

CDFSDN_BLOCK *cdfsdn_block_new(const char *block_root_dir)
{
    CDFSDN_BLOCK *cdfsdn_block;

    alloc_static_mem(MM_CDFSDN_BLOCK, &cdfsdn_block, LOC_CDFSDN_0015);
    if(NULL_PTR != cdfsdn_block)
    {
        cdfsdn_block_init(cdfsdn_block, block_root_dir);
    }
    return (cdfsdn_block);
}

EC_BOOL cdfsdn_block_init(CDFSDN_BLOCK *cdfsdn_block, const char *block_root_dir)
{
    CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)    = (UINT32)0;
    CDFSDN_BLOCK_FD(cdfsdn_block)             = ERR_FD;
    CDFSDN_BLOCK_CACHE(cdfsdn_block)          = NULL_PTR;

    snprintf((char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block), CDFSDN_ROOT_DIR_MAX_SIZE, "%s", block_root_dir);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_init_0(CDFSDN_BLOCK *cdfsdn_block)
{
    CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)    = (UINT32)0;
    CDFSDN_BLOCK_FD(cdfsdn_block)             = ERR_FD;
    CDFSDN_BLOCK_CACHE(cdfsdn_block)          = NULL_PTR;

    BSET((char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block), 0x00, CDFSDN_ROOT_DIR_MAX_SIZE);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_clean(CDFSDN_BLOCK *cdfsdn_block)
{
    CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) = (UINT32)0;

    if(NULL_PTR != CDFSDN_BLOCK_CACHE(cdfsdn_block))
    {
        cdfsdn_cache_free(CDFSDN_BLOCK_CACHE(cdfsdn_block));
        CDFSDN_BLOCK_CACHE(cdfsdn_block) = NULL_PTR;
    }

    if(ERR_FD != CDFSDN_BLOCK_FD(cdfsdn_block))
    {
        c_file_close(CDFSDN_BLOCK_FD(cdfsdn_block));
        CDFSDN_BLOCK_FD(cdfsdn_block) = ERR_FD;
    }

    cdfsdn_clean_buff(CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block), CDFSDN_ROOT_DIR_MAX_SIZE);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_free(CDFSDN_BLOCK *cdfsdn_block)
{
    if(NULL_PTR != cdfsdn_block)
    {
        cdfsdn_block_clean(cdfsdn_block);
        free_static_mem(MM_CDFSDN_BLOCK, cdfsdn_block, LOC_CDFSDN_0016);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_cache_flush(const CDFSDN_BLOCK *cdfsdn_block)
{
    RWSIZE wsize;
    if(ERR_SEEK == lseek(CDFSDN_BLOCK_FD(cdfsdn_block), 0, SEEK_SET))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_flush: seek beg failed\n");
        return (EC_FALSE);
    }

    wsize = /*CDFSDN_BLOCK_CACHE_SIZE(cdfsdn_block)*/CDFSDN_BLOCK_MAX_SIZE;
    if(wsize != write(CDFSDN_BLOCK_FD(cdfsdn_block), CDFSDN_BLOCK_CACHE_DATA(cdfsdn_block), wsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_flush: flush block data failed where wsize %ld\n", wsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_cache_load(CDFSDN_BLOCK *cdfsdn_block)
{
    RWSIZE rsize;
    if(ERR_SEEK == lseek(CDFSDN_BLOCK_FD(cdfsdn_block), 0, SEEK_SET))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_load: seek beg failed\n");
        return (EC_FALSE);
    }

    rsize = CDFSDN_BLOCK_MAX_SIZE;
    if(rsize != read(CDFSDN_BLOCK_FD(cdfsdn_block), CDFSDN_BLOCK_CACHE_DATA(cdfsdn_block), rsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_load: load data failed where rsize %ld\n", rsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_cache_flush_to(int fd, const CDFSDN_BLOCK *cdfsdn_block)
{
    RWSIZE wsize;
    if(ERR_SEEK == lseek(fd, 0, SEEK_SET))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_flush: seek beg failed\n");
        return (EC_FALSE);
    }

    wsize = CDFSDN_BLOCK_MAX_SIZE;
    if(wsize != write(fd, CDFSDN_BLOCK_CACHE_DATA(cdfsdn_block), wsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_flush: flush block data failed where wsize %ld\n", wsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_cache_load_from(int fd, CDFSDN_BLOCK *cdfsdn_block)
{
    RWSIZE rsize;
    if(ERR_SEEK == lseek(fd, 0, SEEK_SET))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_load_from: seek beg failed\n");
        return (EC_FALSE);
    }

    rsize = CDFSDN_BLOCK_MAX_SIZE;
    if(rsize != read(fd, CDFSDN_BLOCK_CACHE_DATA(cdfsdn_block), rsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_load_from: load data failed where rsize %ld\n", rsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_partition_flush(CDFSDN_BLOCK *cdfsdn_block)
{
    UINT32 offset;
    RWSIZE wsize;

    offset = CDFSDN_BLOCK_DATA_MAX_SIZE;
    if(ERR_SEEK == lseek(CDFSDN_BLOCK_FD(cdfsdn_block), offset, SEEK_SET))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_flush: seek beg failed\n");
        return (EC_FALSE);
    }

    wsize = CDFSDN_BLOCK_PART_MAX_SIZE;
    if(wsize != write(CDFSDN_BLOCK_FD(cdfsdn_block), CDFSDN_BLOCK_CACHE_DATA(cdfsdn_block) + CDFSDN_BLOCK_DATA_MAX_SIZE, wsize))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_cache_flush: flush block data failed where wsize %ld\n", wsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

void cdfsdn_block_print(LOG *log, const CDFSDN_BLOCK *cdfsdn_block)
{
    if(NULL_PTR != cdfsdn_block)
    {
        sys_print(log, "cdfsdn_block %lx: block %ld root dir %s\n",
                        cdfsdn_block,
                        CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block),
                        (char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block)
                        );
    }

    return;
}

/*for debug only*/
void cdfsdn_block_fname_print(LOG *log, const UINT32 disk_num, const UINT32 block_path_layout)
{
    CDSK_SHARD cdsk_shard;

    cdsk_pathlayout_to_shard(block_path_layout, disk_num, &cdsk_shard);

    sys_log(log, "${ROOT}/dsk%ld/%ld/%ld/%ld/%ld\n",
                CDSK_SHARD_DISK_ID(&cdsk_shard),
                CDFSDN_PATH_LAYOUT_DIR0_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR1_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR2_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR3_NO(CDSK_SHARD_PATH_ID(&cdsk_shard))
                );
}

STATIC_CAST static EC_BOOL cdfsdn_block_fname_gen(const char *root_dir, const UINT32 disk_num, const UINT32 block_path_layout, char *path, const UINT32 max_len)
{
    CDSK_SHARD cdsk_shard;

    cdsk_pathlayout_to_shard(block_path_layout, disk_num, &cdsk_shard);

    snprintf(path, max_len, "%s/dsk%ld/%ld/%ld/%ld/%ld",
                root_dir,
                CDSK_SHARD_DISK_ID(&cdsk_shard),
                CDFSDN_PATH_LAYOUT_DIR0_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR1_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR2_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR3_NO(CDSK_SHARD_PATH_ID(&cdsk_shard))
                );
    //dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_fname_gen: disk num %ld, block_path_layout %ld, path %s\n", disk_num, block_path_layout, path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL cdfsdn_block_dname_gen(const char *root_dir, const UINT32 disk_num, const UINT32 block_path_layout, char *path, const UINT32 max_len)
{
    CDSK_SHARD cdsk_shard;

    cdsk_pathlayout_to_shard(block_path_layout, disk_num, &cdsk_shard);

    snprintf(path, max_len, "%s/dsk%ld/%ld/%ld/%ld/",
                root_dir,
                CDSK_SHARD_DISK_ID(&cdsk_shard),
                CDFSDN_PATH_LAYOUT_DIR0_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR1_NO(CDSK_SHARD_PATH_ID(&cdsk_shard)),
                CDFSDN_PATH_LAYOUT_DIR2_NO(CDSK_SHARD_PATH_ID(&cdsk_shard))
                );
    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_create(CDFSDN_BLOCK *cdfsdn_block, const UINT32 disk_num, const UINT32 block_path_layout)
{
    char path[ CDFSDN_BLOCK_NAME_MAX_SIZE ];

    cdfsdn_block_dname_gen((char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block), disk_num, block_path_layout, path, CDFSDN_BLOCK_NAME_MAX_SIZE);
    if(EC_FALSE == c_dir_create(path))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_create: create dir %s failed\n", path);
        return (EC_FALSE);
    }

    cdfsdn_block_fname_gen((char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block), disk_num, block_path_layout, path, CDFSDN_BLOCK_NAME_MAX_SIZE);
    if(0 == access(path, F_OK))
    {
        dbg_log(SEC_0087_CDFSDN, 1)(LOGSTDOUT, "warn:cdfsdn_block_create: block file %s already exist\n", path);
        return (EC_FALSE);
    }

    CDFSDN_BLOCK_FD(cdfsdn_block) = open(path, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CDFSDN_BLOCK_FD(cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_create: open block file %s failed\n", path);
        return (EC_FALSE);
    }
#if 1/*optimize*/
    if(0 != ftruncate(CDFSDN_BLOCK_FD(cdfsdn_block), CDFSDN_BLOCK_MAX_SIZE))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_create: truncate file %s failed\n", path);
        c_file_close(CDFSDN_BLOCK_FD(cdfsdn_block));
        CDFSDN_BLOCK_FD(cdfsdn_block) = ERR_FD;
        return (EC_FALSE);
    }
#endif

    CDFSDN_BLOCK_CACHE(cdfsdn_block) = cdfsdn_cache_new();
    if(NULL_PTR == CDFSDN_BLOCK_CACHE(cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_create: new block cache failed for block file %s\n", path);
        c_file_close(CDFSDN_BLOCK_FD(cdfsdn_block));
        CDFSDN_BLOCK_FD(cdfsdn_block) = ERR_FD;
        return (EC_FALSE);
    }

    cdfsdn_block_partition_flush(cdfsdn_block);/*here flush partition index table to disk*/

    CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) = block_path_layout;

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_open(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 block_path_layout, const UINT32 open_flags)
{
    char path[ CDFSDN_BLOCK_NAME_MAX_SIZE ];

    cdfsdn_block_fname_gen((char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block), CDFSDN_DISK_NUM(cdfsdn), block_path_layout, path, CDFSDN_BLOCK_NAME_MAX_SIZE);
    /*when block file not exit, then create it and return*/
    if(0 != access(path, F_OK))
    {
        if(open_flags & CDFSDN_BLOCK_O_CREATE)
        {
            dbg_log(SEC_0087_CDFSDN, 1)(LOGSTDOUT, "warn:cdfsdn_block_open: block file %s not exist, try to create it\n", path);
            if(EC_TRUE == cdfsdn_block_create(cdfsdn_block, CDFSDN_DISK_NUM(cdfsdn), block_path_layout))
            {
                CDFSDN_NODE_PART_IDX(cdfsdn, block_path_layout) = 0;/*point to the first partition*/
                return (EC_TRUE);
            }
        }

        dbg_log(SEC_0087_CDFSDN, 1)(LOGSTDOUT, "warn:cdfsdn_block_open: block file %s not exist\n", path);
        return (EC_FALSE);
    }

    /*when block file exit, then open and load it*/
    CDFSDN_BLOCK_FD(cdfsdn_block) = open(path, O_RDWR, 0666);
    if(ERR_FD == CDFSDN_BLOCK_FD(cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_open: open block file %s failed\n", path);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsdn_block_load(cdfsdn, cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_open: load block file %s failed\n", path);
        c_file_close(CDFSDN_BLOCK_FD(cdfsdn_block));
        CDFSDN_BLOCK_FD(cdfsdn_block) = ERR_FD;
        return (EC_FALSE);
    }

    CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) = block_path_layout;

    CDFSDN_NODE_SET_NOT_CACHED(cdfsdn, block_path_layout);/*xx*/
    CDFSDN_NODE_SET_NOT_UPDATED(cdfsdn, block_path_layout);
    CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, block_path_layout);
    CDFSDN_NODE_SET_NOT_SWAPOUT(cdfsdn, block_path_layout);
    CDFSDN_NODE_SET_NO_READER(cdfsdn, block_path_layout);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_flush(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block)
{
    if(EC_FALSE == cdfsdn_block_cache_flush(cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_flush: flush block cache failed where path layout %ld\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
        return (EC_FALSE);
    }

    //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0017);
    //CDFSDN_NODE_LOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0018);
    CDFSDN_NODE_SET_NOT_UPDATED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    //CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0019);
    //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0020);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_load(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block)
{
    if(ERR_FD == CDFSDN_BLOCK_FD(cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_load: block was not open\n");
        return (EC_FALSE);
    }

    CDFSDN_BLOCK_CACHE(cdfsdn_block) = cdfsdn_cache_new();
    if(NULL_PTR == CDFSDN_BLOCK_CACHE(cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_load: block cache is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsdn_block_cache_load(cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_load: block load cache failed\n");
        cdfsdn_cache_free(CDFSDN_BLOCK_CACHE(cdfsdn_block));
        CDFSDN_BLOCK_CACHE(cdfsdn_block) = NULL_PTR;
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_unlink(const CDFSDN_BLOCK *cdfsdn_block, const UINT32 disk_num, const UINT32 block_path_layout)
{
    char path[CDFSDN_BLOCK_NAME_MAX_SIZE];

    cdfsdn_block_fname_gen((char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block), disk_num, block_path_layout, path, CDFSDN_BLOCK_NAME_MAX_SIZE);
    if(0 != access(path, F_OK))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_unlink: block file %s not exist\n", path);
        return (EC_FALSE);
    }

    if( 0 != unlink(path))
    {
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_unlink: unlink block %s failed\n", path);
        return (EC_FALSE);
    }
    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_unlink: unlink block %s successfully\n", path);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_clear_flags(CDFSDN *cdfsdn, const CDFSDN_BLOCK *cdfsdn_block)
{
    CDFSDN_NODE_SET_NOT_CACHED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    CDFSDN_NODE_SET_NOT_UPDATED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    CDFSDN_NODE_SET_NOT_SWAPOUT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    CDFSDN_NODE_SET_NO_READER(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_burn(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_len)
{
    CDFSDN_NODE_SET_UPDATED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    /*move to next un-full block record*/
    CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0021);
    while(CDFSDN_NODE_NUM(cdfsdn) > CDFSDN_NODE_BEG(cdfsdn) && CDFSDN_NODE_IS_FULL(cdfsdn, CDFSDN_NODE_BEG(cdfsdn)))
    {
        UINT32 path_layout_next;
        path_layout_next = CDFSDN_NODE_NEXT(cdfsdn, CDFSDN_NODE_BEG(cdfsdn));
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_burn: CDFSDN_NODE_BEG move %ld => %ld\n", 
                        (UINT32)CDFSDN_NODE_BEG(cdfsdn), path_layout_next);
        CDFSDN_NODE_NEXT(cdfsdn, CDFSDN_NODE_BEG(cdfsdn)) = CDFSDN_ERR_PATH;
        CDFSDN_NODE_BEG(cdfsdn) = path_layout_next;
    }
    CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0022);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_return(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block)
{
    CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0023);
    CDFSDN_NODE_NEXT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)) = CDFSDN_NODE_BEG(cdfsdn);
    CDFSDN_NODE_BEG(cdfsdn) = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
    CDFSDN_NODE_SET_UPDATED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0024);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_truncate(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_max_len, const CVECTOR *part_idx_vec)
{
    UINT32 pos;
    UINT32 data_pos;

    for(pos = 0, data_pos = 0; pos < cvector_size(part_idx_vec) && data_pos < data_max_len; pos ++)
    {
        UINT32 len;

        len = DMIN((data_max_len - data_pos), CDFSDN_BLOCK_PER_PART_SIZE);
        data_pos += len;
    }

    if(data_pos != data_max_len)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_truncate: block path layout %ld expect to truncate %ld bytes but accept %ld bytes only\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), data_max_len, data_pos);
        //CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0025);
        return (EC_FALSE);
    }

    cdfsdn_block_burn(cdfsdn, cdfsdn_block, data_pos * CDFSDN_BLOCK_PER_PART_SIZE);
    //CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0026);

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_truncate: block path layout %ld accept %ld bytes successfully\n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), data_pos);
    //dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_block_write: ");
    //sys_print(LOGSTDNULL, "%.*s\n", data_len, (char *)data_buff);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_update(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_max_len, const UINT8 *data_buff, const UINT32 partition_beg)
{
    UINT32 data_pos;
    UINT32 partition_idx;

    if(partition_beg >= CDFSDN_BLOCK_PART_MAX_NUM)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_update: path layout %ld, partition_beg %ld overflow the partition max idx %ld\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), partition_beg, CDFSDN_BLOCK_PART_MAX_NUM);
        return (EC_FALSE);
    }

    for(data_pos = 0, partition_idx = partition_beg;
        data_pos < data_max_len && partition_idx < CDFSDN_BLOCK_PART_MAX_NUM;
        partition_idx = CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx))
    {
        UINT32 len;
        len = DMIN((data_max_len - data_pos), CDFSDN_BLOCK_PER_PART_SIZE);
        BCOPY(data_buff + data_pos, CDFSDN_BLOCK_PART_DATA(cdfsdn_block, partition_idx), len);
        data_pos += len;
    }

    if(data_pos != data_max_len)/*make sure data is written*/
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_update: block path layout %ld expect to update %ld bytes but accept %ld bytes only\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), data_max_len, data_pos);
        return (EC_FALSE);
    }

    CDFSDN_NODE_SET_UPDATED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_update: block path layout %ld accept %ld bytes successfully\n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), data_pos);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_write(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 data_max_len, const UINT8 *data_buff, const CVECTOR *part_idx_vec)
{
    UINT32 pos;
    UINT32 data_pos;

    for(pos = 0, data_pos = 0; pos < cvector_size(part_idx_vec) && data_pos < data_max_len; pos ++)
    {
        UINT32 partition_idx;
        UINT32 len;

        partition_idx  = (UINT32)cvector_get_no_lock(part_idx_vec, pos);
        len = DMIN((data_max_len - data_pos), CDFSDN_BLOCK_PER_PART_SIZE);
        BCOPY(data_buff + data_pos, CDFSDN_BLOCK_PART_DATA(cdfsdn_block, partition_idx), len);
        data_pos += len;
    }

    if(data_pos != data_max_len)/*make sure data is written*/
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_write: block path layout %ld expect to write %ld bytes but accept %ld bytes only\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), data_max_len, data_pos);
        //CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0027);
        return (EC_FALSE);
    }

    cdfsdn_block_burn(cdfsdn, cdfsdn_block, data_pos * CDFSDN_BLOCK_PER_PART_SIZE);
    //CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0028);

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_write: block path layout %ld accept %ld bytes successfully\n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), data_pos);
    //dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_block_write: ");
    //sys_print(LOGSTDNULL, "%.*s\n", data_len, (char *)data_buff);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_read(const CDFSDN_BLOCK *cdfsdn_block, const UINT32 first_partition_idx, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    UINT32 partition_idx;
    UINT32 data_pos;

    if(first_partition_idx >= CDFSDN_BLOCK_PART_MAX_NUM)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_read: path layout %ld, first_partition_idx %ld overflow the partition max idx %ld\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), first_partition_idx, CDFSDN_BLOCK_PART_MAX_NUM);
        return (EC_FALSE);
    }

    for(data_pos = 0, partition_idx = first_partition_idx;
        data_pos < data_max_len && partition_idx < CDFSDN_BLOCK_PART_MAX_NUM;
        partition_idx = CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx))
    {
        UINT32 len;
        len = DMIN(data_max_len - data_pos, CDFSDN_BLOCK_PER_PART_SIZE);
        BCOPY(CDFSDN_BLOCK_PART_DATA(cdfsdn_block, partition_idx), data_buff + data_pos, len);
        data_pos += len;
    }

    if(data_pos != data_max_len)/*make sure data is written*/
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_read: block path layout %ld expect to read %ld bytes but get %ld bytes only\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), data_max_len, data_pos);
        //CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0029);
        return (EC_FALSE);
    }

    (*data_len) = data_pos;

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_block_read: path layout %ld, first_partition_idx %ld, max len %ld, ret len %ld\n",
                        CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), first_partition_idx, data_max_len, (*data_len));

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_reserve_partition(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 room, UINT32 *partition_beg, CVECTOR *partition_idx_vec)
{
    UINT32 burn_cache_len;
    UINT32FIXED partition_idx_cur;
    UINT32FIXED partition_idx_next;
    CDFSDN_RECORD *cdfsdn_record;

    cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    partition_idx_next = CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record);
    if(CDFSDN_BLOCK_PART_MAX_NUM <= partition_idx_next)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_reserve_partition: block %ld is full where first partition idx = %d\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                            partition_idx_next);
        return (EC_FALSE);
    }

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_reserve_partition: beg: block %ld, next part idx %ld, cache room %ld, cache size %ld\n",
                        (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                        (UINT32)CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record),
                        (UINT32)CDFSDN_RECORD_ROOM(cdfsdn_record), 
                        (UINT32)CDFSDN_RECORD_SIZE(cdfsdn_record));

    partition_idx_cur = ~(UINT32FIXED)0;

    for(burn_cache_len = 0; burn_cache_len < room && CDFSDN_BLOCK_PART_MAX_NUM > partition_idx_next; burn_cache_len += CDFSDN_BLOCK_PER_PART_SIZE)
    {
        UINT32 data;
        partition_idx_cur = partition_idx_next;
        partition_idx_next = CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx_cur);

        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_block_reserve_partition: push: block %ld, partition_idx_cur = %d, burn_cache_len = %ld ==> room %ld\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                            partition_idx_cur, 
                            burn_cache_len, 
                            room);

        data = partition_idx_cur;
        cvector_push_no_lock(partition_idx_vec, (void *)data);
    }

    if(burn_cache_len < room)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_reserve_partition: block %ld can burn %ld bytes which is unable to accept %ld bytes\n",
                        CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), burn_cache_len, room);
        return (EC_FALSE);
    }

    (*partition_beg) = CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record);
    CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx_cur) = CDFSDN_ERR_PART_IDX;
    CDFSDN_RECORD_SIZE(cdfsdn_record) += burn_cache_len;
    CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record) = partition_idx_next;

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_reserve_partition: end: block %ld, next part idx %ld, cache room %ld, cache size %ld\n",
                        (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                        (UINT32)CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record),
                        (UINT32)CDFSDN_RECORD_ROOM(cdfsdn_record), 
                        (UINT32)CDFSDN_RECORD_SIZE(cdfsdn_record));

    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_release_partition(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, CVECTOR *partition_idx_vec)
{
    UINT32 partition_num;
    UINT32 burn_cache_len;
    CDFSDN_RECORD *cdfsdn_record;

    cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    partition_num = cvector_size(partition_idx_vec);
    burn_cache_len = (partition_num * CDFSDN_BLOCK_PER_PART_SIZE);

    while(EC_FALSE == cvector_is_empty(partition_idx_vec))
    {
        UINT32 data;
        UINT32FIXED partition_idx;
        data = (UINT32)cvector_pop_no_lock(partition_idx_vec);
        partition_idx = (UINT32FIXED)data;
        CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx) = CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record);
        CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record) = partition_idx;
    }

    CDFSDN_RECORD_SIZE(cdfsdn_record) -= burn_cache_len;
    return (EC_TRUE);
}

EC_BOOL cdfsdn_block_recycle_partition(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block, const UINT32 first_partition_idx)
{
    UINT32 partition_idx_cur;
    UINT32 partition_idx_next;
    UINT32 burn_cache_len;
    UINT32 record_next;
    CDFSDN_RECORD *cdfsdn_record;

    if(CDFSDN_BLOCK_PART_MAX_NUM <= first_partition_idx)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_block_recycle_partition: invalid first partition idx %ld\n", first_partition_idx);
        return (EC_FALSE);
    }

    if(0)/*debug only*/
    {
        UINT32 idx_cur;

        for(idx_cur = first_partition_idx; CDFSDN_BLOCK_PART_MAX_NUM > idx_cur; idx_cur = CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, idx_cur))
        {
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_recycle_partition: %ld => \n", idx_cur);
        }
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_recycle_partition: %ld\n", idx_cur);
        dbg_log(SEC_0087_CDFSDN, 5)(LOGSTDOUT, "=====================================================\n");
    }

    cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    partition_idx_cur = first_partition_idx;
    burn_cache_len = CDFSDN_BLOCK_PER_PART_SIZE;
    while(CDFSDN_BLOCK_PART_MAX_NUM > (partition_idx_next = CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx_cur)))
    {
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_block_recycle_partition: block %ld, partition_idx_cur = %ld\n",
                            (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                            (UINT32)partition_idx_cur);
        partition_idx_cur = partition_idx_next;
        burn_cache_len += CDFSDN_BLOCK_PER_PART_SIZE;
    }

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_recycle_partition: [1] block %ld, partition_idx_cur = %ld, CDFSDN_BLOCK_NEXT_PART_IDX %ld, CDFSDN_RECORD_FIRST_PART_IDX %ld\n",
                        (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                        (UINT32)partition_idx_cur,
                        (UINT32)CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx_cur) , 
                        (UINT32)CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record));

    CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx_cur) = CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record);
    CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record) = first_partition_idx;

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_block_recycle_partition: [2] block %ld, partition_idx_cur = %ld, CDFSDN_BLOCK_NEXT_PART_IDX %ld, CDFSDN_RECORD_FIRST_PART_IDX %ld\n",
                        (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), partition_idx_cur,
                        (UINT32)CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, partition_idx_cur), 
                        (UINT32)CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record));

    CDFSDN_RECORD_SIZE(cdfsdn_record) -= burn_cache_len;

    record_next = CDFSDN_NODE_NEXT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0030);
    if(CDFSDN_NODE_BEG(cdfsdn) != CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) && record_next >= CDFSDN_NODE_NUM(cdfsdn))
    {
        CDFSDN_NODE_NEXT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)) = CDFSDN_NODE_BEG(cdfsdn);
        CDFSDN_NODE_BEG(cdfsdn) = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
    }
    CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0031);
    return (EC_TRUE);
}

CDFSDN *cdfsdn_new(const char *root_dir)
{
    CDFSDN *cdfsdn;

    alloc_static_mem(MM_CDFSDN, &cdfsdn, LOC_CDFSDN_0032);
    if(NULL_PTR != cdfsdn)
    {
        cdfsdn_init(cdfsdn, root_dir);
    }
    return (cdfsdn);
}

EC_BOOL cdfsdn_init(CDFSDN *cdfsdn, const char *root_dir)
{
    UINT32 pos;

    snprintf((char *)CDFSDN_ROOT_DIR(cdfsdn), CDFSDN_ROOT_DIR_MAX_SIZE, "%s", root_dir);
    snprintf((char *)CDFSDN_RECORD_NAME(cdfsdn), CDFSDN_BLOOM_NAME_MAX_SIZE, "%s/records.dat", root_dir);

    CDFSDN_RECORD_FD(cdfsdn)  = ERR_FD;
    CDFSDN_RECORD_MGR(cdfsdn) = NULL_PTR;

    for(pos = 0; pos < CDFSDN_CMUTEX_MAX_NUM; pos ++)
    {
        CDFSDN_NODE_INIT_LOCK(cdfsdn, pos, LOC_CDFSDN_0033);
    }

    clist_init(CDFSDN_BLOCK_TBL(cdfsdn), MM_IGNORE, LOC_CDFSDN_0034);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_clean(CDFSDN *cdfsdn)
{
    UINT32 pos;

    cdfsdn_clean_buff(CDFSDN_ROOT_DIR(cdfsdn), CDFSDN_ROOT_DIR_MAX_SIZE);
    cdfsdn_clean_buff(CDFSDN_RECORD_NAME(cdfsdn), CDFSDN_BLOOM_NAME_MAX_SIZE);

    if(ERR_FD != CDFSDN_RECORD_FD(cdfsdn))
    {
        c_file_close(CDFSDN_RECORD_FD(cdfsdn));
        CDFSDN_RECORD_FD(cdfsdn) = ERR_FD;
    }

    if(NULL_PTR != CDFSDN_RECORD_MGR(cdfsdn))
    {
        cdfsdn_record_mgr_free(CDFSDN_RECORD_MGR(cdfsdn));
        CDFSDN_RECORD_MGR(cdfsdn) = NULL_PTR;
    }

    for(pos = 0; pos < CDFSDN_CMUTEX_MAX_NUM; pos ++)
    {
        CDFSDN_NODE_CLEAN_LOCK(cdfsdn, pos, LOC_CDFSDN_0035);
    }

    clist_clean(CDFSDN_BLOCK_TBL(cdfsdn), (CLIST_DATA_DATA_CLEANER)cdfsdn_block_free);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_free(CDFSDN *cdfsdn)
{
    if(NULL_PTR != cdfsdn)
    {
        cdfsdn_clean(cdfsdn);
        free_static_mem(MM_CDFSDN, cdfsdn, LOC_CDFSDN_0036);
    }
    return (EC_TRUE);
}

void cdfsdn_block_free_part_idx_print(LOG *log, const UINT32 first_free_part_idx, const CDFSDN_BLOCK *cdfsdn_block)
{
    UINT32 free_part_idx_next;

    sys_log(log, "block %ld free partition idx table: \n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
    for(free_part_idx_next = first_free_part_idx;
        CDFSDN_ERR_PART_IDX != free_part_idx_next && CDFSDN_BLOCK_PART_MAX_NUM > free_part_idx_next;
        free_part_idx_next = CDFSDN_BLOCK_NEXT_PART_IDX(cdfsdn_block, free_part_idx_next)
    )
    {
        sys_log(log, "%ld -> \n", free_part_idx_next);
    }
    sys_log(log, "%ld\n", free_part_idx_next);
    return;
}

void cdfsdn_print(LOG *log, const CDFSDN *cdfsdn)
{
    sys_log(log, "cdfsdn %lx: root dir: %s, record name: %s\n",
                 cdfsdn,
                 (char *)CDFSDN_ROOT_DIR(cdfsdn),
                 (char *)CDFSDN_RECORD_NAME(cdfsdn)
                 );
    cdfsdn_record_mgr_print(log, CDFSDN_RECORD_MGR(cdfsdn));

    //clist_print(log, CDFSDN_BLOCK_TBL(cdfsdn), (CLIST_DATA_DATA_PRINT)cdfsdn_block_print);

    if(1)
    {
        CLIST_DATA *clist_data;
        CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0037);
        CLIST_LOOP_NEXT(CDFSDN_BLOCK_TBL(cdfsdn), clist_data)
        {
            CDFSDN_BLOCK  *cdfsdn_block;
            CDFSDN_RECORD *cdfsdn_record;
            UINT32         first_free_fpart_idx;

            cdfsdn_block = (CDFSDN_BLOCK *)CLIST_DATA_DATA(clist_data);
            cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
            first_free_fpart_idx = CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record);

            sys_log(log, "block %ld root dir %s, size %ld, room %ld, first free partition %ld\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block),
                            (char *)CDFSDN_BLOCK_ROOT_DIR(cdfsdn_block),
                            CDFSDN_RECORD_SIZE(cdfsdn_record),
                            CDFSDN_RECORD_ROOM(cdfsdn_record),
                            first_free_fpart_idx
                            );

            //cdfsdn_block_free_part_idx_print(log, first_free_fpart_idx, cdfsdn_block);
        }
        CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0038);
    }
    return;
}

EC_BOOL cdfsdn_is_full(CDFSDN *cdfsdn)
{
    if(CDFSDN_NODE_BEG(cdfsdn) >= CDFSDN_NODE_NUM(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_is_full: cdfsdn is full where node beg %ld num %ld\n", 
                        (UINT32)CDFSDN_NODE_BEG(cdfsdn), 
                        (UINT32)CDFSDN_NODE_NUM(cdfsdn));
        cdfsdn_print(LOGSTDOUT, cdfsdn);
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

UINT32 cdfsdn_stat_fetch(CDFSDN *cdfsdn)
{
    if(EC_TRUE == cdfsdn_is_full(cdfsdn))
    {
        return (CDFSDN_STAT_IS_FULL);
    }
    return (CDFSDN_STAT_IS_NOT_FULL);
}

EC_BOOL cdfsdn_flush(CDFSDN *cdfsdn)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0039);
    CLIST_LOOP_NEXT(CDFSDN_BLOCK_TBL(cdfsdn), clist_data)
    {
        CDFSDN_BLOCK * cdfsdn_block;

        cdfsdn_block = (CDFSDN_BLOCK *)CLIST_DATA_DATA(clist_data);
        if(CDFSDN_RECORD_MGR_NODE_IS_UPDATED(CDFSDN_RECORD_MGR(cdfsdn), CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)))
        {
            cdfsdn_block_flush(cdfsdn, cdfsdn_block);
        }

    }
    CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0040);

    cdfsdn_record_mgr_flush_has_lock(cdfsdn);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_load(CDFSDN *cdfsdn)
{
    UINT32 path_layout;

    if(EC_FALSE == cdfsdn_record_mgr_load(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_load: load record failed where record name is %s\n", (char *)CDFSDN_RECORD_NAME(cdfsdn));
        return (EC_FALSE);
    }

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_load: record mgr is\n");
    cdfsdn_record_mgr_print(LOGSTDOUT, CDFSDN_RECORD_MGR(cdfsdn));

    for(path_layout = CDFSDN_NODE_BEG(cdfsdn);
        CDFSDN_LOAD_BLOCK_MAX_NUM > clist_size(CDFSDN_BLOCK_TBL(cdfsdn)) && path_layout < CDFSDN_NODE_NUM(cdfsdn);
        path_layout = CDFSDN_NODE_NEXT(cdfsdn, path_layout)
    )
    {
        CDFSDN_BLOCK *cdfsdn_block;

        if(CDFSDN_NODE_IS_FULL(cdfsdn, path_layout))
        {
            continue;
        }

        cdfsdn_block = cdfsdn_swapin(cdfsdn, path_layout, CDFSDN_BLOCK_O_RDWR | CDFSDN_BLOCK_O_CREATE, CDFSDN_RECORD_FLAG_CACHED_BIT);
        if(NULL_PTR == cdfsdn_block)
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_load: swapin block %ld failed\n", path_layout);
            break;
        }
    }

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_load: load completed\n");
    return (EC_TRUE);
}

CDFSDN *cdfsdn_open(const char *root_dir)
{
    CDFSDN *cdfsdn;

    if(EC_FALSE == c_dir_exist(root_dir))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_open: root dir %s not exist\n", root_dir);
        return (NULL_PTR);
    }

    cdfsdn = cdfsdn_new(root_dir);
    if(NULL_PTR == cdfsdn)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_open: new cdfsdn with root dir %s failed\n", root_dir);
        return (NULL_PTR);
    }

    if(EC_FALSE == cdfsdn_load(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_open: load cdfsdn with root dir %s failed\n", root_dir);
        cdfsdn_free(cdfsdn);
        return (NULL_PTR);
    }
    return (cdfsdn);
}

EC_BOOL cdfsdn_close(CDFSDN *cdfsdn)
{
    cdfsdn_free(cdfsdn);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_close_with_flush(CDFSDN *cdfsdn)
{
    cdfsdn_flush(cdfsdn);
    cdfsdn_close(cdfsdn);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_create(const char *root_dir, const UINT32 disk_num, const UINT32 max_gb_num_of_disk_space)
{
    CDFSDN *cdfsdn;
    UINT32  record_beg;

    if(EC_FALSE == c_dir_create(root_dir))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_create: root dir %s not exist and create failed\n", root_dir);
        return (EC_FALSE);
    }

    cdfsdn = cdfsdn_new(root_dir);
    if(NULL_PTR == cdfsdn)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_create: new cdfsdn with root dir %s failed\n", root_dir);
        return (EC_FALSE);
    }

    if(0 == access((char *)CDFSDN_RECORD_NAME(cdfsdn), F_OK))/*exist*/
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_create: record file %s already exist\n", (char *)CDFSDN_RECORD_NAME(cdfsdn));
        cdfsdn_free(cdfsdn);
        return (EC_FALSE);
    }

    CDFSDN_RECORD_FD(cdfsdn) = c_file_open((char *)CDFSDN_RECORD_NAME(cdfsdn), O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CDFSDN_RECORD_FD(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_create: cannot open record file %s\n", (char *)CDFSDN_RECORD_NAME(cdfsdn));
        cdfsdn_free(cdfsdn);
        return (EC_FALSE);
    }

    record_beg = 0;
    CDFSDN_RECORD_MGR(cdfsdn) = cdfsdn_record_mgr_new(disk_num, max_gb_num_of_disk_space * CDFSDN_MAX_BLOCKS_PER_GB, record_beg);
    if(NULL_PTR == CDFSDN_RECORD_MGR(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_create: cannot new record with nbits %ld\n", max_gb_num_of_disk_space * CDFSDN_MAX_BLOCKS_PER_GB);
        cdfsdn_free(cdfsdn);
        return (EC_FALSE);
    }

    cdfsdn_record_mgr_link(CDFSDN_RECORD_MGR(cdfsdn));

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_create: record mgr is\n");
    cdfsdn_record_mgr_print(LOGSTDOUT, CDFSDN_RECORD_MGR(cdfsdn));

    if(EC_FALSE == cdfsdn_record_mgr_flush_has_lock(cdfsdn))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_create:flush record failed\n");
        cdfsdn_free(cdfsdn);
        return (EC_FALSE);
    }

    cdfsdn_free(cdfsdn);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_reserve_block_to_swapin(CDFSDN *cdfsdn, const UINT32 room, UINT32 *path_layout_reserved)
{
    UINT32 path_layout;

    for(path_layout = CDFSDN_NODE_BEG(cdfsdn); path_layout < CDFSDN_NODE_NUM(cdfsdn); path_layout = CDFSDN_NODE_NEXT(cdfsdn, path_layout))
    {
        CDFSDN_RECORD *cdfsdn_record;

        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), path_layout);

        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_reserve_block_to_swapin: check record %ld, record room %ld, record size %ld, flag %lx => expect room %ld\n",
                            (UINT32)path_layout, 
                            (UINT32)CDFSDN_RECORD_ROOM(cdfsdn_record), 
                            (UINT32)CDFSDN_RECORD_SIZE(cdfsdn_record), 
                            (UINT32)CDFSDN_RECORD_FLAG(cdfsdn_record), room);
        if(CDFSDN_RECORD_IS_CACHED(cdfsdn_record) || CDFSDN_RECORD_IS_WRITE(cdfsdn_record) || CDFSDN_RECORD_IS_SWAPOUT(cdfsdn_record))
        {
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_reserve_block_to_swapin: ...... invalid stat[1]: %lx\n", 
                            (UINT32)CDFSDN_RECORD_FLAG(cdfsdn_record));
            continue;
        }

        if(room <= CDFSDN_RECORD_ROOM(cdfsdn_record))
        {

            if(CDFSDN_RECORD_IS_CACHED(cdfsdn_record)
            || CDFSDN_RECORD_IS_WRITE(cdfsdn_record)
            || CDFSDN_RECORD_IS_SWAPOUT(cdfsdn_record))
            {
                dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_reserve_block_to_swapin: ...... invalid stat[2]: %lx\n", 
                                (UINT32)CDFSDN_RECORD_FLAG(cdfsdn_record));
                continue;
            }

            //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0041);
            CDFSDN_NODE_LOCK(cdfsdn, path_layout, LOC_CDFSDN_0042);
            CDFSDN_NODE_SET_WRITE(cdfsdn, path_layout);
            CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0043);
            //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0044);

            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_reserve_block_to_swapin: reserve record %ld\n", path_layout);
            (*path_layout_reserved) = path_layout;
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

CDFSDN_BLOCK *cdfsdn_search_block_to_swapout(CDFSDN *cdfsdn, const UINT32 except_cdfsdn_node_lock)
{
    CLIST_DATA *clist_data;

    /*no lock on CDFSDN_BLOCK_TBL(cdfsdn)*/
    CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0045);
    if(CDFSDN_LOAD_BLOCK_MAX_NUM > clist_size(CDFSDN_BLOCK_TBL(cdfsdn)))
    {
        CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0046);
        return (NULL_PTR);
    }

    CLIST_LOOP_NEXT(CDFSDN_BLOCK_TBL(cdfsdn), clist_data)
    {
        CDFSDN_BLOCK *cdfsdn_block;
        cdfsdn_block = (CDFSDN_BLOCK *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cdfsdn_block)
        {
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_search_block_to_swapout: block is null\n");
            continue;
        }

        if(except_cdfsdn_node_lock == (CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) % CDFSDN_CMUTEX_MAX_NUM))
        {
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_search_block_to_swapout: found node lock collision, give up further checking\n");
            continue;
        }

        if(
            CDFSDN_NODE_IS_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)) ||
            CDFSDN_NODE_IS_READ(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)) ||
            CDFSDN_NODE_IS_SWAPOUT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
           )
        {
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_search_block_to_swapout: ignore block of path layout %ld to swapout where write flag %lx, reader num %ld, swapout flag %lx\n",
                                (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block),
                                (UINT32)CDFSDN_NODE_WRITE_FLAG(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)),
                                (UINT32)CDFSDN_NODE_READER_NUM(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)),
                                (UINT32)CDFSDN_NODE_SWAPOUT_FLAG(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
                                );

            continue;
        }
        else
        {
            clist_rmv_no_lock(CDFSDN_BLOCK_TBL(cdfsdn), clist_data);

            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_search_block_to_swapout: umount block of path layout %ld to swapout\n",
                                CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

            //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0047);
            CDFSDN_NODE_SET_SWAPOUT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));/*set swapout flag*/
            //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0048);

            CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0049);
            return (cdfsdn_block);
        }
    }

    CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0050);
    return (NULL_PTR);
}

CDFSDN_BLOCK *cdfsdn_lookup_block(CDFSDN *cdfsdn, const UINT32 path_layout)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0051);
    CLIST_LOOP_NEXT(CDFSDN_BLOCK_TBL(cdfsdn), clist_data)
    {
        CDFSDN_BLOCK *cdfsdn_block;
        cdfsdn_block = (CDFSDN_BLOCK *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cdfsdn_block)
        {
            continue;
        }

        if(path_layout == CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
        {
            CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0052);
            return (cdfsdn_block);
        }
    }
    CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0053);
    return (NULL_PTR);
}

CDFSDN_BLOCK *cdfsdn_lookup_block_no_lock(CDFSDN *cdfsdn, const UINT32 path_layout)
{
    CLIST_DATA *clist_data;
    CLIST_LOOP_NEXT(CDFSDN_BLOCK_TBL(cdfsdn), clist_data)
    {
        CDFSDN_BLOCK *cdfsdn_block;
        cdfsdn_block = (CDFSDN_BLOCK *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cdfsdn_block)
        {
            continue;
        }

        if(path_layout == CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
        {
            return (cdfsdn_block);
        }
    }
    return (NULL_PTR);
}

CDFSDN_BLOCK *cdfsdn_search_block_to_write(CDFSDN *cdfsdn, const UINT32 room)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0054);
    CLIST_LOOP_NEXT(CDFSDN_BLOCK_TBL(cdfsdn), clist_data)
    {
        CDFSDN_BLOCK *cdfsdn_block;
        CDFSDN_RECORD *cdfsdn_record;
        UINT32 path_layout;

        cdfsdn_block = (CDFSDN_BLOCK *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cdfsdn_block)
        {
            continue;
        }

        path_layout = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), path_layout);

        if(room <= CDFSDN_RECORD_ROOM(cdfsdn_record))
        {

            if(
                CDFSDN_NODE_IS_WRITE(cdfsdn, path_layout) ||
                CDFSDN_NODE_IS_SWAPOUT(cdfsdn, path_layout)
             )
            {
                dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_search_block_to_write: block %ld is writting(%ld) or swapout(%ld)\n",
                                    path_layout,
                                    (UINT32)CDFSDN_NODE_WRITE_FLAG(cdfsdn, path_layout),
                                    (UINT32)CDFSDN_NODE_SWAPOUT_FLAG(cdfsdn, path_layout)
                                    );
                continue;
            }

            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_search_block_to_write: block %ld room %ld has room to accept %ld bytes\n",
                                path_layout,
                                CDFSDN_RECORD_ROOM(cdfsdn_record),
                                room
                                );
            CDFSDN_NODE_SET_WRITE(cdfsdn, path_layout);/*xxx*/
            CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0055);
            return (cdfsdn_block);
        }

        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_search_block_to_write: block %ld room %ld is not enough to accept %ld bytes\n",
                            path_layout,
                            CDFSDN_RECORD_ROOM(cdfsdn_record),
                            room
                            );
    }

    CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0056);
    return (NULL_PTR);
}

CDFSDN_BLOCK *cdfsdn_reserve_block_to_write(CDFSDN *cdfsdn, const UINT32 room, UINT32 *partition_beg, CVECTOR *partition_idx_vec)
{
    UINT32 loop;

    /*the design principle is to prevent from dead lock, i.e., prevent from LOCK V -> LOCK NODE -> UNLOCK NODE -> UNLOCK V*/
    /*since the basic idea is LOCK NODE -> LOCK V -> UNLOCK V -> UNLOCK NODE or LOCK NODE -> UNLOCK NODE, LOCK V -> UNLOCK V*/
    for(loop = 0; loop < CDFSDN_LOAD_BLOCK_MAX_NUM; loop ++)/*try!*/
    {
        CDFSDN_BLOCK *cdfsdn_block;
        CDFSDN_RECORD *cdfsdn_record;

        cdfsdn_block = cdfsdn_search_block_to_write(cdfsdn, room);
        if(NULL_PTR == cdfsdn_block)
        {
            continue;
        }

        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

        CDFSDN_NODE_LOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0057);
        if(
            /*CDFSDN_NODE_IS_NOT_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)) &&*/
            CDFSDN_NODE_IS_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)) &&
            CDFSDN_NODE_IS_NOT_SWAPOUT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)) &&
            room <= CDFSDN_RECORD_ROOM(cdfsdn_record)
        )
        {
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_reserve_block_to_write: block %ld expect room %ld, cache room %ld, cache size %ld\n",
                                (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                                (UINT32)room, 
                                (UINT32)CDFSDN_RECORD_ROOM(cdfsdn_record), 
                                (UINT32)CDFSDN_RECORD_SIZE(cdfsdn_record));
            if(EC_FALSE == cdfsdn_block_reserve_partition(cdfsdn, cdfsdn_block, room, partition_beg, partition_idx_vec))
            {
                dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_reserve_block_to_write: reserve partition from block %ld failed\n",
                                    (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) );

                cdfsdn_block_release_partition(cdfsdn, cdfsdn_block, partition_idx_vec);
                CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0058);
                return (NULL_PTR);
            }
            /*CDFSDN_NODE_SET_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));*/
            CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0059);
            return (cdfsdn_block);
        }
        CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
        CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0060);
    }

    return (NULL_PTR);
}

EC_BOOL cdfsdn_fexist_block(const CDFSDN *cdfsdn, const UINT32 path_layout)
{
    char path[CDFSDN_BLOCK_NAME_MAX_SIZE];

    cdfsdn_block_fname_gen((char *)CDFSDN_ROOT_DIR(cdfsdn), CDFSDN_DISK_NUM(cdfsdn), path_layout, path, CDFSDN_BLOCK_NAME_MAX_SIZE);
    /*when block file not exit, then create it and return*/
    if(0 != access(path, F_OK))
    {
        dbg_log(SEC_0087_CDFSDN, 1)(LOGSTDOUT, "warn:cdfsdn_fexist_block: path layout %ld => block file %s not exist\n",
                            path_layout, path);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsdn_swapout(CDFSDN *cdfsdn, CDFSDN_BLOCK  *cdfsdn_block)
{
    if(CDFSDN_NODE_IS_UPDATED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)))
    {
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_swapout: try to swapout %ld\n",
                            CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)
                            );
        if(EC_FALSE == cdfsdn_block_flush(cdfsdn, cdfsdn_block))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_swapout: block of path layout %ld flushed failed\n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

            cdfsdn_record_mgr_flush_has_lock(cdfsdn);

            cdfsdn_block_clear_flags(cdfsdn, cdfsdn_block);
            cdfsdn_block_free(cdfsdn_block);
            return (EC_FALSE);
        }

        cdfsdn_record_mgr_flush_has_lock(cdfsdn);
    }
    else
    {
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_swapout: give up flush path layout %ld where flag %lx\n",
                            (UINT32)CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), 
                            (UINT32)CDFSDN_NODE_FLAG(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
                            );
    }

    cdfsdn_block_clear_flags(cdfsdn, cdfsdn_block);
    cdfsdn_block_free(cdfsdn_block);

    return (EC_TRUE);
}


CDFSDN_BLOCK * cdfsdn_swapin_no_lock(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 open_flags, const UINT32 bit_flags)
{
    CDFSDN_BLOCK *cdfsdn_block;
    CDFSDN_RECORD *cdfsdn_record;

    cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), path_layout);

    if(CDFSDN_NODE_IS_CACHED(cdfsdn, path_layout))
    {
        CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0061);
        cdfsdn_block = cdfsdn_lookup_block_no_lock(cdfsdn, path_layout);
        if(NULL_PTR != cdfsdn_block)
        {
            CDFSDN_NODE_FLAG(cdfsdn, path_layout) |= (bit_flags & CDFSDN_RECORD_FLAG_MASK);
            if(bit_flags & CDFSDN_RECORD_FLAG_READ_BIT)
            {
                CDFSDN_NODE_INC_READER(cdfsdn, path_layout);
            }

            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_swapin_no_lock: block of path layout %ld was already cached and searched\n", path_layout);
            CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0062);
            return (cdfsdn_block);
        }
        CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0063);
    }

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_swapin_no_lock: try to swapin path layout %ld\n", path_layout);
    cdfsdn_block = cdfsdn_block_new((char *)CDFSDN_ROOT_DIR(cdfsdn));
    if(NULL_PTR == cdfsdn_block)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_swapin_no_lock: new block failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdfsdn_block_open(cdfsdn, cdfsdn_block, path_layout, open_flags))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_swapin_no_lock: open block failed where path layout %lx\n", path_layout);
        cdfsdn_block_free(cdfsdn_block);
        return (NULL_PTR);
    }

#if 1
    /*shrink here will increate the success possibility of pushing cdfsdn_block into CDFSDN_BLOCK_VEC(cdfsdn)*/
    if(EC_FALSE == cdfsdn_shrink(cdfsdn, path_layout % CDFSDN_CMUTEX_MAX_NUM))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_swapin_no_lock: refuse swapin path layout %ld due to cdfsdn shrink failed where size %ld\n",
                            path_layout, clist_size(CDFSDN_BLOCK_TBL(cdfsdn)));

        cdfsdn_block_free(cdfsdn_block);
        return (NULL_PTR);
    }
#endif

#if 0
    /*shrink here will increate the success possibility of pushing cdfsdn_block into CDFSDN_BLOCK_VEC(cdfsdn)*/
    if(EC_FALSE == cdfsdn_shrink_opt(cdfsdn, path_layout % CDFSDN_CMUTEX_MAX_NUM, CDFSDN_SHRINK_BLOCK_MAX_NUM))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_swapin: refuse swapin path layout %ld due to cdfsdn shrink failed where size %ld\n",
                            path_layout, cvector_size(CDFSDN_BLOCK_VEC(cdfsdn)));
        cdfsdn_block_free(cdfsdn_block);
        return (NULL_PTR);
    }
#endif

    CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0064);

#if 1
    if(CDFSDN_NODE_IS_CACHED(cdfsdn, path_layout))/*double confirm*/
    {
        CDFSDN_BLOCK *cdfsdn_block_t;

        cdfsdn_block_t = cdfsdn_lookup_block_no_lock(cdfsdn, path_layout);
        if(NULL_PTR != cdfsdn_block_t)
        {
            dbg_log(SEC_0087_CDFSDN, 5)(LOGSTDOUT, "cdfsdn_swapin_no_lock: block of path layout %ld was already cached and searched without lock\n", path_layout);

            //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0065);
            CDFSDN_NODE_FLAG(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block_t)) |= (bit_flags & CDFSDN_RECORD_FLAG_MASK);
            //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0066);

            cdfsdn_block_free(cdfsdn_block);
            CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0067);
            return (cdfsdn_block_t);
        }
    }
#endif

    //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0068);
    CDFSDN_NODE_SET_FLAG(cdfsdn, path_layout, (bit_flags & CDFSDN_RECORD_FLAG_MASK));

    if(bit_flags & CDFSDN_RECORD_FLAG_READ_BIT)
    {
        CDFSDN_NODE_INC_READER(cdfsdn, path_layout);
    }

    CDFSDN_NODE_SET_CACHED(cdfsdn, path_layout);
    //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0069);

    clist_push_back_no_lock(CDFSDN_BLOCK_TBL(cdfsdn), (void *)cdfsdn_block);

    CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0070);

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_swapin_no_lock: swapin block %ld, cache size %ld, flag %lx\n",
                        path_layout,
                        (UINT32)CDFSDN_RECORD_SIZE(cdfsdn_record),
                        (UINT32)CDFSDN_NODE_FLAG(cdfsdn, path_layout)
                        );
    //dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_swapin_no_lock: after swapin, the block vec is:\n");
    //clist_print(LOGSTDNULL, CDFSDN_BLOCK_TBL(cdfsdn), (CLIST_DATA_DATA_PRINT)cdfsdn_block_print);

    return (cdfsdn_block);
}

CDFSDN_BLOCK * cdfsdn_swapin(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 open_flags, const UINT32 bit_flags)
{
    CDFSDN_BLOCK *cdfsdn_block;

    //CLIST_LOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0071);
    CDFSDN_NODE_LOCK(cdfsdn, path_layout, LOC_CDFSDN_0072);

    cdfsdn_block = cdfsdn_swapin_no_lock(cdfsdn, path_layout, open_flags, bit_flags);

    CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0073);
    //CLIST_UNLOCK(CDFSDN_BLOCK_TBL(cdfsdn), LOC_CDFSDN_0074);

    return (cdfsdn_block);
}

EC_BOOL cdfsdn_shrink(CDFSDN *cdfsdn, const UINT32 except_cdfsdn_node_lock)
{
    while(CDFSDN_LOAD_BLOCK_MAX_NUM <= clist_size(CDFSDN_BLOCK_TBL(cdfsdn)))/*force swapout one block*/
    {
        CDFSDN_BLOCK *cdfsdn_block;

        cdfsdn_block = cdfsdn_search_block_to_swapout(cdfsdn, except_cdfsdn_node_lock);
        if(NULL_PTR == cdfsdn_block)
        {
            if(CDFSDN_LOAD_BLOCK_MAX_NUM > clist_size(CDFSDN_BLOCK_TBL(cdfsdn)))
            {
                return (EC_TRUE);
            }

            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_shrink: find block to swapout failed where except %ld\n", except_cdfsdn_node_lock);
            return (EC_FALSE);
        }

        if(EC_FALSE == cdfsdn_swapout(cdfsdn, cdfsdn_block))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_shrink: swapout block failed failed where path layout %ld\n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cdfsdn_shrink_opt(CDFSDN *cdfsdn, const UINT32 except_cdfsdn_node_lock, const UINT32 swapout_block_max_num)
{
    CLIST_DATA *clist_data;
    UINT32  swapout_block_cur_num;
    EC_BOOL record_mgr_flush_flag;

    swapout_block_cur_num = 0;
    record_mgr_flush_flag = EC_FALSE;

    CLIST_LOOP_NEXT(CDFSDN_BLOCK_TBL(cdfsdn), clist_data)
    {
        CDFSDN_BLOCK *cdfsdn_block;
        cdfsdn_block = (CDFSDN_BLOCK *)CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cdfsdn_block)
        {
            continue;
        }

        if(except_cdfsdn_node_lock == (CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) % CDFSDN_CMUTEX_MAX_NUM))
        {
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_shrink_opt: found node lock collision, give up further checking\n");
            continue;
        }

        if(
               CDFSDN_NODE_IS_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
            || CDFSDN_NODE_IS_READ(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
            || CDFSDN_NODE_IS_SWAPOUT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
         /* ||CDFSDN_NODE_IS_NOT_FULL(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))*/
           )
        {
            continue;
        }
        else
        {
            CLIST_DATA *clist_data_rmv;
            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);

            clist_rmv_no_lock(CDFSDN_BLOCK_TBL(cdfsdn), clist_data_rmv);
            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_shrink_opt: umount block of path layout %ld to swapout\n",
                                CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

            //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0075);
            CDFSDN_NODE_SET_SWAPOUT(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));/*set swapout flag*/
            //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0076);

            if(CDFSDN_NODE_IS_UPDATED(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block)))
            {
                record_mgr_flush_flag = EC_TRUE;

                dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_shrink_opt: try to swapout %ld\n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
                if(EC_FALSE == cdfsdn_block_flush(cdfsdn, cdfsdn_block))
                {
                    dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_shrink_opt: block of path layout %ld flushed failed\n", CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

                    cdfsdn_record_mgr_flush_has_lock(cdfsdn);

                    cdfsdn_block_clear_flags(cdfsdn, cdfsdn_block);
                    cdfsdn_block_free(cdfsdn_block);

                    return (EC_FALSE);
                }
            }
            else
            {
                dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_shrink_opt: give up swapout %ld where flag %lx\n",
                                    CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), (UINT32)CDFSDN_NODE_FLAG(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block))
                                    );
            }

            cdfsdn_block_clear_flags(cdfsdn, cdfsdn_block);
            cdfsdn_block_free(cdfsdn_block);

            swapout_block_cur_num ++;

            if(swapout_block_max_num <= swapout_block_cur_num)
            {
                break;
            }
        }
    }

    if(EC_TRUE == record_mgr_flush_flag)
    {
        cdfsdn_record_mgr_flush_has_lock(cdfsdn);
    }

    return (EC_TRUE);
}

/**
* note: dead lock scenario:
*   lock A, B: NODE locks
*   lock V: CDFSDN_BLOCK_TBL lock
*
*   LOCK A -> LOCK V -> LOCK B
*   LOCK B -> LOCK V -> LOCK A
*
* or
*
*   LOCK A -> LOCK B -> UNLOCK B -> UNLOCK A
*   LOCK B -> LOCK A -> UNLOCK A -> UNLOCK B
*
**/
EC_BOOL cdfsdn_read(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 partition_idx, const UINT32 data_max_len, UINT8 *data_buff, UINT32 *data_len)
{
    CDFSDN_BLOCK *cdfsdn_block;
#if 0
    if(EC_FALSE == cdfsdn_fexist_block(cdfsdn, path_layout))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_read: no existing file corresponding to block path layout %ld\n", path_layout);
        return (EC_FALSE);
    }
#endif

    cdfsdn_block = cdfsdn_swapin(cdfsdn, path_layout, CDFSDN_BLOCK_O_RDWR, CDFSDN_RECORD_FLAG_CACHED_BIT | CDFSDN_RECORD_FLAG_READ_BIT);
    if(NULL_PTR != cdfsdn_block)
    {
        if(EC_FALSE == cdfsdn_block_read(cdfsdn_block, partition_idx, data_max_len, data_buff, data_len))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_read: block read failed where path layout %ld\n", path_layout);
            //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0077);
            CDFSDN_NODE_LOCK(cdfsdn, path_layout, LOC_CDFSDN_0078);
            CDFSDN_NODE_DEC_READER(cdfsdn, path_layout);
            CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0079);
            //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0080);
            return (EC_FALSE);
        }

        //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0081);
        CDFSDN_NODE_LOCK(cdfsdn, path_layout, LOC_CDFSDN_0082);
        CDFSDN_NODE_DEC_READER(cdfsdn, path_layout);
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0083);
        //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0084);
        return (EC_TRUE);
    }
    dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_read: swapin block of path layout %ld failed\n", path_layout);
    return (EC_FALSE);
}

EC_BOOL cdfsdn_write(CDFSDN *cdfsdn, const UINT32 data_max_len, const UINT8 *data_buff, UINT32 *path_layout, UINT32 *partition_idx)
{
    CDFSDN_BLOCK *cdfsdn_block;
    UINT32 path_layout_reserved;
    UINT32 partition_beg;

    CVECTOR *partition_idx_vec;

    if(CDFSDN_BLOCK_DATA_MAX_SIZE <= data_max_len)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_write: data len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    partition_idx_vec = cvector_new(0, MM_UINT32, LOC_CDFSDN_0085);

    cdfsdn_block = cdfsdn_reserve_block_to_write(cdfsdn, data_max_len, &partition_beg, partition_idx_vec);
    if(NULL_PTR != cdfsdn_block)
    {
        if(EC_TRUE == cdfsdn_block_write(cdfsdn, cdfsdn_block, data_max_len, data_buff, partition_idx_vec))
        {
            //cdfsdn_record_mgr_set(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), CDFSDN_BLOCK_CACHE_EOFF(cdfsdn_block));

            (*path_layout) = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
            (*partition_idx) = partition_beg;

            //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0086);
            CDFSDN_NODE_LOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0087);
            CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
            CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0088);
            //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0089);

            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_write[1]: write %ld bytes to path layout %ld successfully\n",
                                data_max_len, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

            cvector_free(partition_idx_vec, LOC_CDFSDN_0090);
            return (EC_TRUE);
        }

        //CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0091);
        CDFSDN_NODE_LOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0092);
        CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
        CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0093);
        //CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0094);
    }

    if(EC_FALSE == cdfsdn_reserve_block_to_swapin(cdfsdn, data_max_len, &path_layout_reserved))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_write: not find record with room more than %ld bytes\n", data_max_len);
        cvector_free(partition_idx_vec, LOC_CDFSDN_0095);
        return (EC_FALSE);
    }

    cdfsdn_block = cdfsdn_swapin(cdfsdn, path_layout_reserved,
                                        CDFSDN_BLOCK_O_RDWR | CDFSDN_BLOCK_O_CREATE,
                                        CDFSDN_RECORD_FLAG_CACHED_BIT | CDFSDN_RECORD_FLAG_WRITE_BIT);
    if(NULL_PTR == cdfsdn_block)
    {
        CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0096);
        CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, path_layout_reserved);
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0097);

        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_write: swapin path layout %ld failed\n", path_layout_reserved);
        cvector_free(partition_idx_vec, LOC_CDFSDN_0098);
        return (EC_FALSE);
    }

    CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0099);
    if(EC_FALSE == cdfsdn_block_reserve_partition(cdfsdn, cdfsdn_block, data_max_len, &partition_beg, partition_idx_vec))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_write: reserve partition failed\n");
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0100);
        cvector_free(partition_idx_vec, LOC_CDFSDN_0101);
        return (EC_FALSE);
    }
    CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0102);

    if(EC_TRUE == cdfsdn_block_write(cdfsdn, cdfsdn_block, data_max_len, data_buff, partition_idx_vec))
    {
        (*path_layout) = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
        (*partition_idx) = partition_beg;

        CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0103);
        CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, path_layout_reserved);
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0104);

        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_write[2]: write %ld bytes to path layout %ld successfully\n",
                            data_max_len, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
        cvector_free(partition_idx_vec, LOC_CDFSDN_0105);
        return (EC_TRUE);
    }

    CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0106);
    cdfsdn_block_release_partition(cdfsdn, cdfsdn_block, partition_idx_vec);
    CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, path_layout_reserved);
    CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0107);

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDNULL, "[DEBUG] cdfsdn_write[3]: write %ld bytes to path layout %ld failed\n",
                        data_max_len, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    cvector_free(partition_idx_vec, LOC_CDFSDN_0108);
    return (EC_FALSE);
}

EC_BOOL cdfsdn_update(CDFSDN *cdfsdn, const UINT32 data_max_len, const UINT8 *data_buff, const UINT32 path_layout, const UINT32 partition_beg)
{
    CDFSDN_BLOCK *cdfsdn_block;

    if(CDFSDN_BLOCK_DATA_MAX_SIZE <= data_max_len)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_update: data len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    cdfsdn_block = cdfsdn_swapin(cdfsdn, path_layout, CDFSDN_BLOCK_O_RDWR, CDFSDN_RECORD_FLAG_CACHED_BIT | CDFSDN_RECORD_FLAG_READ_BIT);
    if(NULL_PTR != cdfsdn_block)
    {
        if(EC_FALSE == cdfsdn_block_update(cdfsdn, cdfsdn_block, data_max_len, data_buff, partition_beg))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_update: block update failed where path layout %ld\n", path_layout);
            CDFSDN_NODE_LOCK(cdfsdn, path_layout, LOC_CDFSDN_0109);
            CDFSDN_NODE_DEC_READER(cdfsdn, path_layout);
            CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0110);
            return (EC_FALSE);
        }

        CDFSDN_NODE_LOCK(cdfsdn, path_layout, LOC_CDFSDN_0111);
        CDFSDN_NODE_DEC_READER(cdfsdn, path_layout);
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0112);
        return (EC_TRUE);
    }
    dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_update: swapin block of path layout %ld failed\n", path_layout);
    return (EC_FALSE);
}

EC_BOOL cdfsdn_truncate(CDFSDN *cdfsdn, const UINT32 data_max_len, UINT32 *path_layout, UINT32 *partition_idx)
{
    CDFSDN_BLOCK *cdfsdn_block;
    UINT32 path_layout_reserved;
    UINT32 partition_beg;

    CVECTOR *partition_idx_vec;

    if(CDFSDN_BLOCK_DATA_MAX_SIZE <= data_max_len)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_truncate: data len %ld overflow\n", data_max_len);
        return (EC_FALSE);
    }

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_truncate: try to truncate %ld bytes\n", data_max_len);

    partition_idx_vec = cvector_new(0, MM_UINT32, LOC_CDFSDN_0113);

    cdfsdn_block = cdfsdn_reserve_block_to_write(cdfsdn, data_max_len, &partition_beg, partition_idx_vec);
    if(NULL_PTR != cdfsdn_block)
    {
        if(EC_TRUE == cdfsdn_block_truncate(cdfsdn, cdfsdn_block, data_max_len, partition_idx_vec))
        {
            (*path_layout) = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
            (*partition_idx) = partition_beg;

            CDFSDN_NODE_LOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0114);
            CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
            CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0115);

            dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_truncate[1]: truncate %ld bytes to path layout %ld successfully\n",
                                data_max_len, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

            cvector_free(partition_idx_vec, LOC_CDFSDN_0116);
            return (EC_TRUE);
        }

        CDFSDN_NODE_LOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0117);
        CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
        CDFSDN_NODE_UNLOCK(cdfsdn, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block), LOC_CDFSDN_0118);
    }

    if(EC_FALSE == cdfsdn_reserve_block_to_swapin(cdfsdn, data_max_len, &path_layout_reserved))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_truncate: not find record with room more than %ld bytes\n", data_max_len);
        cvector_free(partition_idx_vec, LOC_CDFSDN_0119);
        return (EC_FALSE);
    }

    cdfsdn_block = cdfsdn_swapin(cdfsdn, path_layout_reserved,
                                        CDFSDN_BLOCK_O_RDWR | CDFSDN_BLOCK_O_CREATE,
                                        CDFSDN_RECORD_FLAG_CACHED_BIT | CDFSDN_RECORD_FLAG_WRITE_BIT);
    if(NULL_PTR == cdfsdn_block)
    {
        CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0120);
        CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, path_layout_reserved);
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0121);

        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_truncate: swapin path layout %ld failed\n", path_layout_reserved);
        cvector_free(partition_idx_vec, LOC_CDFSDN_0122);
        return (EC_FALSE);
    }

    CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0123);
    if(EC_FALSE == cdfsdn_block_reserve_partition(cdfsdn, cdfsdn_block, data_max_len, &partition_beg, partition_idx_vec))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_truncate: reserve partition failed\n");
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0124);
        cvector_free(partition_idx_vec, LOC_CDFSDN_0125);
        return (EC_FALSE);
    }
    CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0126);

    if(EC_TRUE == cdfsdn_block_truncate(cdfsdn, cdfsdn_block, data_max_len, partition_idx_vec))
    {
        (*path_layout) = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
        (*partition_idx) = partition_beg;

        CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0127);
        CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, path_layout_reserved);
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0128);

        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_truncate[2]: truncate %ld bytes to path layout %ld successfully\n",
                            data_max_len, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));
        cvector_free(partition_idx_vec, LOC_CDFSDN_0129);
        return (EC_TRUE);
    }

    CDFSDN_NODE_LOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0130);
    cdfsdn_block_release_partition(cdfsdn, cdfsdn_block, partition_idx_vec);
    CDFSDN_NODE_SET_NOT_WRITE(cdfsdn, path_layout_reserved);
    CDFSDN_NODE_UNLOCK(cdfsdn, path_layout_reserved, LOC_CDFSDN_0131);

    dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_truncate[3]: truncate %ld bytes to path layout %ld failed\n",
                        data_max_len, CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block));

    cvector_free(partition_idx_vec, LOC_CDFSDN_0132);
    return (EC_FALSE);
}

EC_BOOL cdfsdn_remove(CDFSDN *cdfsdn, const UINT32 path_layout, const UINT32 partition_idx)
{
    CDFSDN_BLOCK *cdfsdn_block;

    cdfsdn_block = cdfsdn_swapin(cdfsdn, path_layout, CDFSDN_BLOCK_O_RDWR, CDFSDN_RECORD_FLAG_CACHED_BIT | CDFSDN_RECORD_FLAG_READ_BIT);
    if(NULL_PTR != cdfsdn_block)
    {
        CDFSDN_NODE_LOCK(cdfsdn, path_layout, LOC_CDFSDN_0133);
        if(EC_FALSE == cdfsdn_block_recycle_partition(cdfsdn, cdfsdn_block, partition_idx))
        {
            dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_remove: block %ld read failed\n", path_layout);

            CDFSDN_NODE_DEC_READER(cdfsdn, path_layout);
            CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0134);
            return (EC_FALSE);
        }

        CDFSDN_NODE_SET_UPDATED(cdfsdn, path_layout);
        CDFSDN_NODE_DEC_READER(cdfsdn, path_layout);
        CDFSDN_NODE_UNLOCK(cdfsdn, path_layout, LOC_CDFSDN_0135);
        return (EC_TRUE);
    }
    dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_remove: swapin block %ld failed\n", path_layout);
    return (EC_FALSE);
}

CDFSDN_BLOCK * cdfsdn_get(CDFSDN *cdfsdn, const UINT32 block_path_layout)
{
    char path[ CDFSDN_BLOCK_NAME_MAX_SIZE ];
    CDFSDN_BLOCK *cdfsdn_block;

    int block_fd;

    //dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_get: cdfsdn disk num = %ld\n", CDFSDN_DISK_NUM(cdfsdn));

    cdfsdn_block_fname_gen((char *)CDFSDN_ROOT_DIR(cdfsdn), CDFSDN_DISK_NUM(cdfsdn), block_path_layout, path, CDFSDN_BLOCK_NAME_MAX_SIZE);
    if(0 != access(path, F_OK))
    {
        dbg_log(SEC_0087_CDFSDN, 1)(LOGSTDOUT, "warn:cdfsdn_get: block file %s not exist\n", path);
        return (NULL_PTR);
    }

    /*when block file exit, then open and load it*/
    block_fd = c_file_open(path, O_RDWR, 0666);
    if(ERR_FD == block_fd)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_get: open block file %s failed\n", path);
        return (NULL_PTR);
    }

    cdfsdn_block = cdfsdn_block_new((char *)CDFSDN_ROOT_DIR(cdfsdn));
    if(NULL_PTR == cdfsdn_block)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_get: new block failed\n");
        c_file_close(block_fd);
        return (NULL_PTR);
    }

    CDFSDN_BLOCK_FD(cdfsdn_block) = block_fd;

    if(EC_FALSE == cdfsdn_block_load(cdfsdn, cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_get: load block file %s failed\n", path);
        c_file_close(CDFSDN_BLOCK_FD(cdfsdn_block));
        CDFSDN_BLOCK_FD(cdfsdn_block) = ERR_FD;
        cdfsdn_block_free(cdfsdn_block);
        return (NULL_PTR);
    }

    CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block) = block_path_layout;

    c_file_close(CDFSDN_BLOCK_FD(cdfsdn_block));
    CDFSDN_BLOCK_FD(cdfsdn_block) = ERR_FD;
    return (cdfsdn_block);
}

EC_BOOL cdfsdn_set(CDFSDN *cdfsdn, const UINT32 block_path_layout, const CDFSDN_BLOCK *cdfsdn_block)
{
    char path[ CDFSDN_BLOCK_NAME_MAX_SIZE ];

    int block_fd;

    cdfsdn_block_fname_gen((char *)CDFSDN_ROOT_DIR(cdfsdn), CDFSDN_DISK_NUM(cdfsdn), block_path_layout, path, CDFSDN_BLOCK_NAME_MAX_SIZE);
    if(0 == access(path, F_OK))
    {
        dbg_log(SEC_0087_CDFSDN, 1)(LOGSTDOUT, "warn:cdfsdn_set: block file %s already exist\n", path);
        return (EC_FALSE);
    }

    /*when block file exit, then open and load it*/
    block_fd = c_file_open(path, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == block_fd)
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_set: open block file %s failed\n", path);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsdn_block_cache_flush_to(block_fd, cdfsdn_block))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_set: load block file %s failed\n", path);
        c_file_close(block_fd);
        return (EC_FALSE);
    }

    c_file_close(block_fd);
    return (EC_TRUE);
}

EC_BOOL cdfsdn_transfer_in_do(CDFSDN *cdfsdn, const UINT32 size, const UINT32 first_part_idx, const CDFSDN_BLOCK *cdfsdn_block, UINT32 *des_block_path_layout)
{
    UINT32 record_pos;

    CDFSDN_RECORD_MGR_CMUTEX_LOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0136);
    for(record_pos = CDFSDN_NODE_BEG(cdfsdn); record_pos < CDFSDN_NODE_NUM(cdfsdn); record_pos = CDFSDN_NODE_NEXT(cdfsdn, record_pos))
    {
        CDFSDN_RECORD *cdfsdn_record;
        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), record_pos);
        if(0 == CDFSDN_RECORD_SIZE(cdfsdn_record) && CDFSDN_RECORD_IS_NOT_CACHED(cdfsdn_record))
        {
            cdfsdn_set(cdfsdn, record_pos, cdfsdn_block);
            CDFSDN_RECORD_SIZE(cdfsdn_record) = size;
            CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record) = first_part_idx;

            /*we did not umount cdfsdn_record from the list due to its single-direction list*/
            CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0137);

            (*des_block_path_layout) = record_pos;
            return (EC_TRUE);
        }
    }
    CDFSDN_RECORD_MGR_CMUTEX_UNLOCK(CDFSDN_RECORD_MGR(cdfsdn), LOC_CDFSDN_0138);
    return (EC_FALSE);
}

/*get one block to transfer once time*/
CDFSDN_BLOCK * cdfsdn_transfer_out_start(CDFSDN *cdfsdn)
{
    UINT32 record_pos;

    for(record_pos = 0; record_pos < CDFSDN_NODE_NUM(cdfsdn); record_pos ++)
    {
        CDFSDN_RECORD *cdfsdn_record;
        cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), record_pos);
        dbg_log(SEC_0087_CDFSDN, 9)(LOGSTDOUT, "[DEBUG] cdfsdn_transfer_out_start: check block %ld: flag %lx, size %ld, room %ld, first part idx %ld, record next %ld\n",
                            record_pos,
                            (UINT32)CDFSDN_RECORD_FLAG(cdfsdn_record),
                            (UINT32)CDFSDN_RECORD_SIZE(cdfsdn_record),
                            (UINT32)CDFSDN_RECORD_ROOM(cdfsdn_record),
                            (UINT32)CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record),
                            (UINT32)CDFSDN_RECORD_NEXT(cdfsdn_record)
                );
        if(CDFSDN_RECORD_IS_FULL(cdfsdn_record) && CDFSDN_RECORD_IS_NOT_CACHED(cdfsdn_record))
        {
            return cdfsdn_get(cdfsdn, record_pos);
        }
    }
    return (NULL_PTR);
}

EC_BOOL cdfsdn_transfer_out_end(CDFSDN *cdfsdn, CDFSDN_BLOCK *cdfsdn_block)
{
    UINT32 path_layout;

    CDFSDN_RECORD *cdfsdn_record;

    path_layout = CDFSDN_BLOCK_PATH_LAYOUT(cdfsdn_block);
    if(EC_FALSE == cdfsdn_block_unlink(cdfsdn_block, CDFSDN_DISK_NUM(cdfsdn), path_layout))
    {
        dbg_log(SEC_0087_CDFSDN, 0)(LOGSTDOUT, "error:cdfsdn_transfer_out_end: unlink block %ld failed\n", path_layout);
        cdfsdn_block_free(cdfsdn_block);
        return (EC_FALSE);
    }

    cdfsdn_record = CDFSDN_RECORD_MGR_NODE(CDFSDN_RECORD_MGR(cdfsdn), path_layout);

    CDFSDN_RECORD_FLAG(cdfsdn_record) = 0;
    CDFSDN_RECORD_SIZE(cdfsdn_record) = 0;
    CDFSDN_RECORD_READER_NUM(cdfsdn_record) = 0;
    CDFSDN_RECORD_FIRST_PART_IDX(cdfsdn_record) = CDFSDN_ERR_PART_IDX;
    CDFSDN_RECORD_NEXT(cdfsdn_record) = CDFSDN_NODE_BEG(cdfsdn);
    CDFSDN_NODE_BEG(cdfsdn) = path_layout;

    cdfsdn_block_free(cdfsdn_block);

    return (EC_TRUE);
}

EC_BOOL cdfsdn_show(LOG *log, const char *root_dir)
{
    CDFSDN *cdfsdn;

    if(EC_FALSE == c_dir_exist(root_dir))
    {
        sys_log(log, "error:cdfsdn_show: root dir %s not exist\n", root_dir);
        return (EC_FALSE);
    }

    cdfsdn = cdfsdn_new(root_dir);
    if(NULL_PTR == cdfsdn)
    {
        sys_log(log, "error:cdfsdn_show: new cdfsdn failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsdn_record_mgr_load(cdfsdn))
    {
        sys_log(log, "error:cdfsdn_show: load record failed\n");
        return (EC_FALSE);
    }

    cdfsdn_print(log, cdfsdn);
    //cdfsdn_record_mgr_print(log, CDFSDN_RECORD_MGR(cdfsdn));

    cdfsdn_free(cdfsdn);

    return (EC_TRUE);

}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

