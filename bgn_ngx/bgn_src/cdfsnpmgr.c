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
#include "clist.h"
#include "cstring.h"
#include "cmisc.h"

#include "task.inc"
#include "task.h"

#include "cbloom.h"
#include "cdfsnp.h"
#include "cdfsnpmgr.h"
#include "chashalgo.h"

#include "findex.inc"

STATIC_CAST static EC_BOOL cdfsnp_mgr_get_file_size(const int fd, UINT32 *file_size)
{
    UINT32 cur_offset;
    UINT32 end_offset;

    if(ERR_SEEK == (cur_offset = lseek(fd, 0, SEEK_CUR)))/*save current offset*/
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_get_file_size: seek cur offset failed\n");
        return (EC_FALSE);
    }

    if(ERR_SEEK == (end_offset = lseek(fd, 0, SEEK_END)))/*skip to end of file*/
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_get_file_size: seek end offset failed\n");
        return (EC_FALSE);
    }

    if(ERR_SEEK == lseek(fd, cur_offset, SEEK_SET))/*restore the saved offset*/
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_get_file_size: seek offset %ld failed\n", cur_offset);
        return (EC_FALSE);
    }

    (*file_size) = end_offset;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_buff_flush(const int fd, const UINT32 offset, const RWSIZE wsize, const UINT8 *buff)
{
    RWSIZE csize;/*write completed size*/
    RWSIZE osize;/*write once size*/

    if(ERR_SEEK == lseek(fd, offset, SEEK_SET))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_buff_flush: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    for(csize = 0, osize = CDFSNP_MGR_WRITE_ONCE_MAX_BYTES; csize < wsize; csize += osize)
    {
        if(csize + osize > wsize)
        {
            osize = wsize - csize;
        }

        if(osize != write(fd, buff + csize, osize))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_buff_flush: flush buff failed where wsize %ld, csize %ld, osize %ld, errno %d, errstr %s\n",
                                wsize, csize, osize, errno, strerror(errno));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_buff_load(const int fd, const UINT32 offset, const RWSIZE rsize, UINT8 *buff)
{
    RWSIZE csize;/*read completed size*/
    RWSIZE osize;/*read once size*/

    if(ERR_SEEK == lseek(fd, offset, SEEK_SET))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_buff_load: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    for(csize = 0, osize = CDFSNP_MGR_READ_ONCE_MAX_BYTES; csize < rsize; csize += osize)
    {
        if(csize + osize > rsize)
        {
            osize = rsize - csize;
        }

        if(osize != read(fd, buff + csize, osize))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_buff_load: load buff failed where rsize %ld, csize %ld, osize %ld, errno %d, errstr %s\n",
                                rsize, csize, osize, errno, strerror(errno));
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_cfg_init(CDFSNP_MGR_CFG *cdfsnp_mgr_cfg)
{
    CDFSNP_MGR_CFG_NP_MODE(cdfsnp_mgr_cfg)                 = CDFSNP_ERR_MODE;
    CDFSNP_MGR_CFG_NP_FIRST_CHASH_ALGO_ID(cdfsnp_mgr_cfg)  = CHASH_ERR_ALGO_ID;
    CDFSNP_MGR_CFG_NP_SECOND_CHASH_ALGO_ID(cdfsnp_mgr_cfg) = CHASH_ERR_ALGO_ID;
    CDFSNP_MGR_CFG_NP_DISK_MAX_NUM(cdfsnp_mgr_cfg)         = 0;
    CDFSNP_MGR_CFG_NP_SUPPORT_MAX_NUM(cdfsnp_mgr_cfg)      = 0;
    CDFSNP_MGR_CFG_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr_cfg) = 0;
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_cfg_clean(CDFSNP_MGR_CFG *cdfsnp_mgr_cfg)
{
    CDFSNP_MGR_CFG_NP_MODE(cdfsnp_mgr_cfg)                 = CDFSNP_ERR_MODE;
    CDFSNP_MGR_CFG_NP_FIRST_CHASH_ALGO_ID(cdfsnp_mgr_cfg)  = CHASH_ERR_ALGO_ID;
    CDFSNP_MGR_CFG_NP_SECOND_CHASH_ALGO_ID(cdfsnp_mgr_cfg) = CHASH_ERR_ALGO_ID;
    CDFSNP_MGR_CFG_NP_DISK_MAX_NUM(cdfsnp_mgr_cfg)         = 0;
    CDFSNP_MGR_CFG_NP_SUPPORT_MAX_NUM(cdfsnp_mgr_cfg)      = 0;
    CDFSNP_MGR_CFG_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr_cfg) = 0;
    return (EC_TRUE);
}

CDFSNP_MGR *cdfsnp_mgr_new()
{
    CDFSNP_MGR *cdfsnp_mgr;

    alloc_static_mem(MM_CDFSNP_MGR, &cdfsnp_mgr, LOC_CDFSNPMGR_0001);
    if(NULL_PTR != cdfsnp_mgr)
    {
        cdfsnp_mgr_init(cdfsnp_mgr);
    }

    return (cdfsnp_mgr);
}

EC_BOOL cdfsnp_mgr_init(CDFSNP_MGR *cdfsnp_mgr)
{
    CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr) = NULL_PTR;

    CDFSNP_MGR_LOST_FNODE_LOG(cdfsnp_mgr)   = NULL_PTR;
    CDFSNP_MGR_LOST_REPLICA_LOG(cdfsnp_mgr) = NULL_PTR;

    cdfsnp_mgr_cfg_init(CDFSNP_MGR_CFG(cdfsnp_mgr));

    cvector_init(CDFSNP_MGR_NP_VEC(cdfsnp_mgr), 0, MM_CDFSNP, CVECTOR_LOCK_ENABLE, LOC_CDFSNPMGR_0002);

    clist_init(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), MM_IGNORE, LOC_CDFSNPMGR_0003);

    CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;
    CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;

    CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr) = 0;
    CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr) = NULL_PTR;

    CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr) = 0;
    CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr) = NULL_PTR;

    CDFSNP_MGR_INIT_LOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0004);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_clean(CDFSNP_MGR *cdfsnp_mgr)
{
    cdfsnp_mgr_log_close(cdfsnp_mgr);

    if(NULL_PTR != CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr))
    {
        cstring_free(CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr));
        CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr) = NULL_PTR;
    }

    cdfsnp_mgr_cfg_clean(CDFSNP_MGR_CFG(cdfsnp_mgr));

    cvector_clean(CDFSNP_MGR_NP_VEC(cdfsnp_mgr), (CVECTOR_DATA_CLEANER)cdfsnp_free, LOC_CDFSNPMGR_0005);
    clist_clean(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), NULL_PTR);

    if(ERR_FD != CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr))
    {
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;
    }

    if(ERR_FD != CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr))
    {
        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;
    }

    if(NULL_PTR != CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr))
    {
        SAFE_FREE(CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr), LOC_CDFSNPMGR_0006);
        CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr) = NULL_PTR;
    }
    CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr) = 0;

    if(NULL_PTR != CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr))
    {
        SAFE_FREE(CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr), LOC_CDFSNPMGR_0007);
        CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr) = NULL_PTR;
    }
    CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr) = 0;

    CDFSNP_MGR_CLEAN_LOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0008);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_free(CDFSNP_MGR *cdfsnp_mgr)
{
    if(NULL_PTR != cdfsnp_mgr)
    {
        cdfsnp_mgr_clean(cdfsnp_mgr);
        free_static_mem(MM_CDFSNP_MGR, cdfsnp_mgr, LOC_CDFSNPMGR_0009);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_load_one_header(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, CDFSNP_HEADER *cdfsnp_header)
{
    RWSIZE rsize;

    if(ERR_SEEK == lseek(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr), offset, SEEK_SET))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_one_header: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    rsize = sizeof(CDFSNP_HEADER);
    if(rsize != read(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr), cdfsnp_header, rsize))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_one_header: load header from offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_flush_one_header(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, const CDFSNP_HEADER *cdfsnp_header)
{
    RWSIZE wsize;

    if(ERR_SEEK == lseek(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr), offset, SEEK_SET))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_one_header: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    wsize = sizeof(CDFSNP_HEADER);
    if(wsize != write(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr), cdfsnp_header, wsize))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_one_header: flush header to offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_load_one_cbloom(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, const RWSIZE rsize, CBLOOM *cdfsnp_cbloom)
{
    if(ERR_SEEK == lseek(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr), offset, SEEK_SET))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_one_cbloom: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    if(rsize != read(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr), (UINT8 *)cdfsnp_cbloom, rsize))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_one_cbloom: load bloom from offset %ld failed where rsize = %ld\n", offset, rsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_flush_one_cbloom(CDFSNP_MGR *cdfsnp_mgr, const UINT32 offset, const RWSIZE wsize, const CBLOOM *cdfsnp_cbloom)
{
    if(ERR_SEEK == lseek(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr), offset, SEEK_SET))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_one_cbloom: seek offset %ld failed\n", offset);
        return (EC_FALSE);
    }

    if(wsize != write(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr), (UINT8 *)cdfsnp_cbloom, wsize))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_one_cbloom: flush cbloom to offset %ld failed where wsize = %ld\n", offset, wsize);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_load_header_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    UINT8 cdfsnp_mgr_header_db_name[ CDFSNP_MGR_HEADER_DB_NAME_MAX_SIZE ];
    UINT32 cdfsnp_mgr_header_db_size;
    UINT8* cdfsnp_mgr_header_db_buff;

    UINT32 cdfsnp_mgr_header_offset;

    snprintf((char *)cdfsnp_mgr_header_db_name, CDFSNP_MGR_HEADER_DB_NAME_MAX_SIZE, "%s/header.db", (char *)cstring_get_str(cdfsnp_db_root_dir));
    if(0 != access((char *)cdfsnp_mgr_header_db_name, F_OK))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_header_db: cdfsnp mgr header db %s not exist\n", (char *)cdfsnp_mgr_header_db_name);
        return (EC_FALSE);
    }

    CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = c_file_open((char *)cdfsnp_mgr_header_db_name, O_RDWR, 0666);
    if(ERR_FD == CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_header_db: open cdfsnp mgr header db %s failed\n", cdfsnp_mgr_header_db_name);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_get_file_size(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr), &cdfsnp_mgr_header_db_size))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_header_db: get cdfsnp mgr header db %s size failed\n", cdfsnp_mgr_header_db_name);
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    /*check file size validity*/
    if(sizeof(CDFSNP_HEADER) * CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr) != cdfsnp_mgr_header_db_size)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_header_db: mismatched cdfsnp support max num %ld and header db size %ld\n",
                            CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr), cdfsnp_mgr_header_db_size);
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    cdfsnp_mgr_header_db_buff = (UINT8 *)SAFE_MALLOC(cdfsnp_mgr_header_db_size, LOC_CDFSNPMGR_0010);
    if(NULL_PTR == cdfsnp_mgr_header_db_buff)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_header_db: alloc %ld bytes failed for cdfsnp mgr header db %s\n",
                            cdfsnp_mgr_header_db_size, cdfsnp_mgr_header_db_name);
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_buff_load(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr), (UINT32)0, cdfsnp_mgr_header_db_size, cdfsnp_mgr_header_db_buff))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_header_db: load %ld bytes failed from cdfsnp mgr header db %s\n",
                            cdfsnp_mgr_header_db_size, cdfsnp_mgr_header_db_name);
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;

        SAFE_FREE(cdfsnp_mgr_header_db_buff, LOC_CDFSNPMGR_0011);
        return (EC_FALSE);
    }

    /*reset header state*/
    for(cdfsnp_mgr_header_offset = 0; cdfsnp_mgr_header_offset < cdfsnp_mgr_header_db_size; cdfsnp_mgr_header_offset += sizeof(CDFSNP_HEADER))
    {
        CDFSNP_HEADER *cdfsnp_header;

        cdfsnp_header = (CDFSNP_HEADER *)(cdfsnp_mgr_header_db_buff + cdfsnp_mgr_header_offset);

        if(CDFSNP_HEADER_IS_FULL(cdfsnp_header))
        {
            CDFSNP_HEADER_STATE(cdfsnp_header) = CDFSNP_STATE_RDONLY;
        }
        else
        {
            CDFSNP_HEADER_STATE(cdfsnp_header) = CDFSNP_STATE_RDWR;
        }
    }

    CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr) = cdfsnp_mgr_header_db_size;
    CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr)     = cdfsnp_mgr_header_db_buff;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_load_cbloom_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    UINT8 cdfsnp_mgr_cbloom_db_name[ CDFSNP_MGR_CBLOOM_DB_NAME_MAX_SIZE ];

    UINT32 cdfsnp_mgr_cbloom_db_size;
    UINT8* cdfsnp_mgr_cbloom_db_buff;

    UINT32 cdfsnp_cbloom_row_num;
    UINT32 cdfsnp_cbloom_col_num;

    UINT32 cdfsnp_cbloom_size;

    snprintf((char *)cdfsnp_mgr_cbloom_db_name, CDFSNP_MGR_CBLOOM_DB_NAME_MAX_SIZE, "%s/cbloom.db", (char *)cstring_get_str(cdfsnp_db_root_dir));

    if(0 != access((char *)cdfsnp_mgr_cbloom_db_name, F_OK))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cbloom_db: cdfsnp mgr cbloom db %s not exist\n", (char *)cdfsnp_mgr_cbloom_db_name);
        return (EC_FALSE);
    }

    if(
        EC_FALSE == cdfsnp_mode_bloom_row_num(CDFSNP_MGR_NP_MODE(cdfsnp_mgr), &cdfsnp_cbloom_row_num)
     || EC_FALSE == cdfsnp_mode_bloom_col_num(CDFSNP_MGR_NP_MODE(cdfsnp_mgr), &cdfsnp_cbloom_col_num)
    )
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cbloom_db: unknow cdfsnp mode %ld\n", CDFSNP_MGR_NP_MODE(cdfsnp_mgr));
        return (EC_FALSE);
    }

    cdfsnp_cbloom_size = sizeof(CBLOOM) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(cdfsnp_cbloom_row_num * cdfsnp_cbloom_col_num));

    CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = c_file_open((char *)cdfsnp_mgr_cbloom_db_name, O_RDWR, 0666);
    if(ERR_FD == CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cbloom_db: open cdfsnp mgr cbloom db %s failed\n", cdfsnp_mgr_cbloom_db_name);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_get_file_size(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr), &cdfsnp_mgr_cbloom_db_size))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cbloom_db: get cdfsnp mgr cbloom db %s size failed\n", (char *)cdfsnp_mgr_cbloom_db_name);

        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    if(cdfsnp_cbloom_size * CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr) != cdfsnp_mgr_cbloom_db_size)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cbloom_db: mismatched cdfsnp support max num %ld and cbloom db size %ld\n",
                            CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr), cdfsnp_mgr_cbloom_db_size);
        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    cdfsnp_mgr_cbloom_db_buff = (UINT8 *)SAFE_MALLOC(cdfsnp_mgr_cbloom_db_size, LOC_CDFSNPMGR_0012);
    if(NULL_PTR == cdfsnp_mgr_cbloom_db_buff)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cbloom_db: alloc %ld bytes failed for cdfsnp mgr cbloom db %s\n",
                            cdfsnp_mgr_cbloom_db_size, cdfsnp_mgr_cbloom_db_name);

        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_buff_load(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr), (UINT32)0, cdfsnp_mgr_cbloom_db_size, cdfsnp_mgr_cbloom_db_buff))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cbloom_db: load %ld bytes failed from cdfsnp mgr cbloom db %s\n",
                            cdfsnp_mgr_cbloom_db_size, (char *)cdfsnp_mgr_cbloom_db_name);
        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;

        SAFE_FREE(cdfsnp_mgr_cbloom_db_buff, LOC_CDFSNPMGR_0013);
        return (EC_FALSE);
    }

    CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr) = cdfsnp_mgr_cbloom_db_size;
    CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr)     = cdfsnp_mgr_cbloom_db_buff;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_flush_header_db(const CDFSNP_MGR *cdfsnp_mgr)
{
    if(ERR_FD != CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr))
    {
        if(EC_FALSE == cdfsnp_mgr_buff_flush(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr),
                                             (UINT32)0, CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr), CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr)))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_header_db: flush header db failed where len %ld\n", CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_flush_cbloom_db(const CDFSNP_MGR *cdfsnp_mgr)
{
    if(ERR_FD != CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr))
    {
        if(EC_FALSE == cdfsnp_mgr_buff_flush(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr),
                                             (UINT32)0, CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr), CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr)))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_header_db: flush cbloom db failed where len %ld\n", CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr));
            return (EC_FALSE);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_close_header_db(CDFSNP_MGR *cdfsnp_mgr)
{
    if(ERR_FD != CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr))
    {
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_close_cbloom_db(CDFSNP_MGR *cdfsnp_mgr)
{
    if(ERR_FD != CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr))
    {
        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_close_header_db_with_flush(CDFSNP_MGR *cdfsnp_mgr)
{
    if(EC_FALSE == cdfsnp_mgr_flush_header_db(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_close_header_db_with_flush: flush header db failed\n");
        return (EC_FALSE);
    }
    return cdfsnp_mgr_close_header_db(cdfsnp_mgr);;
}

EC_BOOL cdfsnp_mgr_close_cbloom_db_with_flush(CDFSNP_MGR *cdfsnp_mgr)
{
    if(EC_FALSE == cdfsnp_mgr_flush_cbloom_db(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_close_header_db_with_flush: flush cbloom db failed\n");
        return (EC_FALSE);
    }
    return cdfsnp_mgr_close_cbloom_db(cdfsnp_mgr);;
}

EC_BOOL cdfsnp_mgr_create_header_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    UINT8  cdfsnp_mgr_header_db_name[ CDFSNP_MGR_HEADER_DB_NAME_MAX_SIZE ];
    UINT32 cdfsnp_mgr_header_db_size;
    UINT8* cdfsnp_mgr_header_db_buff;
    UINT32 cdfsnp_mgr_header_offset;

    snprintf((char *)cdfsnp_mgr_header_db_name, CDFSNP_MGR_HEADER_DB_NAME_MAX_SIZE, "%s/header.db", (char *)cstring_get_str(cdfsnp_db_root_dir));
    if(0 == access((char *)cdfsnp_mgr_header_db_name, F_OK))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_header_db: cdfsnp mgr header db %s already exist\n", (char *)cdfsnp_mgr_header_db_name);
        return (EC_FALSE);
    }

    CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = c_file_open((char *)cdfsnp_mgr_header_db_name, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_header_db: open cdfsnp mgr header db %s failed\n", (char *)cdfsnp_mgr_header_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_header_db_size = sizeof(CDFSNP_HEADER) * CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr);
    cdfsnp_mgr_header_db_buff = (UINT8 *)SAFE_MALLOC(cdfsnp_mgr_header_db_size, LOC_CDFSNPMGR_0014);
    if(NULL_PTR == cdfsnp_mgr_header_db_buff)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_header_db: alloc %ld bytes failed for cdfsnp mgr header db %s\n",
                            cdfsnp_mgr_header_db_size, (char *)cdfsnp_mgr_header_db_name);
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    for(cdfsnp_mgr_header_offset = 0; cdfsnp_mgr_header_offset < cdfsnp_mgr_header_db_size; cdfsnp_mgr_header_offset += sizeof(CDFSNP_HEADER))
    {
        CDFSNP_HEADER *cdfsnp_header;

        cdfsnp_header = (CDFSNP_HEADER *)(cdfsnp_mgr_header_db_buff + cdfsnp_mgr_header_offset);
        cdfsnp_header_init(cdfsnp_header,
                            CDFSNP_MGR_NP_DISK_MAX_NUM(cdfsnp_mgr),
                            CDFSNP_MGR_NP_ITEM_MAX_NUM(cdfsnp_mgr),
                            0,
                            CDFSNP_MGR_NP_CBLOOM_ROW_NUM(cdfsnp_mgr),
                            CDFSNP_MGR_NP_CBLOOM_COL_NUM(cdfsnp_mgr),
                            CDFSNP_MGR_NP_FIRST_CHASH_ALGO_ID(cdfsnp_mgr),
                            CDFSNP_MGR_NP_SECOND_CHASH_ALGO_ID(cdfsnp_mgr)
                            );
    }

    if(EC_FALSE == cdfsnp_mgr_buff_flush(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr), (UINT32)0, cdfsnp_mgr_header_db_size, cdfsnp_mgr_header_db_buff))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_header_db: load %ld bytes failed from cdfsnp mgr header db %s\n",
                            cdfsnp_mgr_header_db_size, (char *)cdfsnp_mgr_header_db_name);
        c_file_close(CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_HEADER_TBL_FD(cdfsnp_mgr) = ERR_FD;

        SAFE_FREE(cdfsnp_mgr_header_db_buff, LOC_CDFSNPMGR_0015);
        return (EC_FALSE);
    }

    CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr) = cdfsnp_mgr_header_db_size;
    CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr)     = cdfsnp_mgr_header_db_buff;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_create_cbloom_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    UINT8 cdfsnp_mgr_cbloom_db_name[ CDFSNP_MGR_CBLOOM_DB_NAME_MAX_SIZE ];

    UINT32 cdfsnp_mgr_cbloom_db_size;
    UINT8* cdfsnp_mgr_cbloom_db_buff;
    UINT32 cdfsnp_mgr_cbloom_offset;

    UINT32 cdfsnp_cbloom_row_num;
    UINT32 cdfsnp_cbloom_col_num;

    UINT32 cdfsnp_cbloom_size;

    snprintf((char *)cdfsnp_mgr_cbloom_db_name, CDFSNP_MGR_CBLOOM_DB_NAME_MAX_SIZE, "%s/cbloom.db", (char *)cstring_get_str(cdfsnp_db_root_dir));

    if(0 == access((char *)cdfsnp_mgr_cbloom_db_name, F_OK))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cbloom_db: cdfsnp mgr cbloom db %s already exist\n", (char *)cdfsnp_mgr_cbloom_db_name);
        return (EC_FALSE);
    }

    if(
        EC_FALSE == cdfsnp_mode_bloom_row_num(CDFSNP_MGR_NP_MODE(cdfsnp_mgr), &cdfsnp_cbloom_row_num)
     || EC_FALSE == cdfsnp_mode_bloom_col_num(CDFSNP_MGR_NP_MODE(cdfsnp_mgr), &cdfsnp_cbloom_col_num)
    )
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cbloom_db: unknow cdfsnp mode %ld\n", CDFSNP_MGR_NP_MODE(cdfsnp_mgr));
        return (EC_FALSE);
    }

    cdfsnp_cbloom_size = sizeof(CBLOOM) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(cdfsnp_cbloom_row_num * cdfsnp_cbloom_col_num));
    cdfsnp_mgr_cbloom_db_size = cdfsnp_cbloom_size * CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr);

    CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = c_file_open((char *)cdfsnp_mgr_cbloom_db_name, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cbloom_db: open cdfsnp mgr cbloom db %s failed\n", (char *)cdfsnp_mgr_cbloom_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_cbloom_db_buff = (UINT8 *)SAFE_MALLOC(cdfsnp_mgr_cbloom_db_size, LOC_CDFSNPMGR_0016);
    if(NULL_PTR == cdfsnp_mgr_cbloom_db_buff)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cbloom_db: alloc %ld bytes failed for cdfsnp mgr cbloom db %s\n",
                            cdfsnp_mgr_cbloom_db_size, (char *)cdfsnp_mgr_cbloom_db_name);

        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;
        return (EC_FALSE);
    }

    for(cdfsnp_mgr_cbloom_offset = 0; cdfsnp_mgr_cbloom_offset < cdfsnp_mgr_cbloom_db_size; cdfsnp_mgr_cbloom_offset += cdfsnp_cbloom_size)
    {
        CBLOOM *cbloom;

        cbloom = (CBLOOM *)(cdfsnp_mgr_cbloom_db_buff + cdfsnp_mgr_cbloom_offset);
        CBLOOM_MAX_NBIT(cbloom) = cdfsnp_cbloom_row_num * cdfsnp_cbloom_col_num;

        cbloom_init(cbloom);
    }

    if(EC_FALSE == cdfsnp_mgr_buff_flush(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr), (UINT32)0, cdfsnp_mgr_cbloom_db_size, cdfsnp_mgr_cbloom_db_buff))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cbloom_db: create %ld bytes failed from cdfsnp mgr cbloom db %s\n",
                            cdfsnp_mgr_cbloom_db_size, cdfsnp_mgr_cbloom_db_name);
        c_file_close(CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr));
        CDFSNP_MGR_NP_CBLOOM_TBL_FD(cdfsnp_mgr) = ERR_FD;

        SAFE_FREE(cdfsnp_mgr_cbloom_db_buff, LOC_CDFSNPMGR_0017);
        return (EC_FALSE);
    }

    CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr) = cdfsnp_mgr_cbloom_db_size;
    CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr)     = cdfsnp_mgr_cbloom_db_buff;

    return (EC_TRUE);
}

void cdfsnp_mgr_print_header_db(LOG *log, const CDFSNP_MGR *cdfsnp_mgr)
{
    sys_log(log, "support max np num : %ld (loaded num %ld) => header tbl should occupy %ld bytes\n",
                    CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr), cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr)),
                    CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr) * sizeof(CDFSNP_HEADER));

    sys_log(log, "header tbl buff len: %ld\n", CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr));

    cvector_print(log, CDFSNP_MGR_NP_VEC(cdfsnp_mgr), (CVECTOR_DATA_PRINT)cdfsnp_print_header);
    return;
}

void cdfsnp_mgr_print_cbloom_db(LOG *log, const CDFSNP_MGR *cdfsnp_mgr)
{
    UINT32 cdfsnp_cbloom_row_num;
    UINT32 cdfsnp_cbloom_col_num;

    UINT32 cdfsnp_cbloom_size;
    if(
        EC_FALSE == cdfsnp_mode_bloom_row_num(CDFSNP_MGR_NP_MODE(cdfsnp_mgr), &cdfsnp_cbloom_row_num)
     || EC_FALSE == cdfsnp_mode_bloom_col_num(CDFSNP_MGR_NP_MODE(cdfsnp_mgr), &cdfsnp_cbloom_col_num)
    )
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_print_cbloom_db: unknow cdfsnp mode %ld\n", CDFSNP_MGR_NP_MODE(cdfsnp_mgr));
        return ;
    }

    cdfsnp_cbloom_size = sizeof(CBLOOM) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(cdfsnp_cbloom_row_num * cdfsnp_cbloom_col_num));

    sys_log(log, "support max np num : %ld (loaded num %ld) => cbloom tbl should occupy %ld bytes\n",
                    CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr), cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr)),
                    CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr) * cdfsnp_cbloom_size);

    sys_log(log, "cbloom tbl buff len: %ld\n", CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr));

    cvector_print(log, CDFSNP_MGR_NP_VEC(cdfsnp_mgr), (CVECTOR_DATA_PRINT)cdfsnp_print_cbloom);
    return;
}

EC_BOOL cdfsnp_mgr_load_cfg_db(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    UINT8  cdfsnp_mgr_cfg_db_name[ CDFSNP_MGR_CONFIG_DB_NAME_MAX_SIZE ];
    UINT32 cdfsnp_mgr_cfg_db_size;
    UINT8* cdfsnp_mgr_cfg_db_buff;

    int    cdfsnp_mgr_cfg_fd;

    snprintf((char *)cdfsnp_mgr_cfg_db_name, CDFSNP_MGR_CONFIG_DB_NAME_MAX_SIZE, "%s/config.db", (char *)cstring_get_str(cdfsnp_db_root_dir));
    if(0 != access((char *)cdfsnp_mgr_cfg_db_name, F_OK))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cfg_db: cdfsnp mgr cfg db %s not exist\n", (char *)cdfsnp_mgr_cfg_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_cfg_fd = c_file_open((char *)cdfsnp_mgr_cfg_db_name, O_RDONLY, 0666);
    if(ERR_FD == cdfsnp_mgr_cfg_fd)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cfg_db: open cdfsnp mgr cfg db %s failed\n", (char *)cdfsnp_mgr_cfg_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_cfg_db_size = sizeof(CDFSNP_MGR_CFG);
    cdfsnp_mgr_cfg_db_buff = (UINT8 *)CDFSNP_MGR_CFG(cdfsnp_mgr);
    if(EC_FALSE == cdfsnp_mgr_buff_load(cdfsnp_mgr_cfg_fd, (UINT32)0, cdfsnp_mgr_cfg_db_size, cdfsnp_mgr_cfg_db_buff))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load_cfg_db: load %ld bytes failed from cdfsnp mgr cfg db %s\n",
                            cdfsnp_mgr_cfg_db_size, (char *)cdfsnp_mgr_cfg_db_name);
        c_file_close(cdfsnp_mgr_cfg_fd);
        cdfsnp_mgr_cfg_fd = ERR_FD;

        return (EC_FALSE);
    }

    c_file_close(cdfsnp_mgr_cfg_fd);
    cdfsnp_mgr_cfg_fd = ERR_FD;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_create_cfg_db(const CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    UINT8  cdfsnp_mgr_cfg_db_name[ CDFSNP_MGR_CONFIG_DB_NAME_MAX_SIZE ];
    UINT32 cdfsnp_mgr_cfg_db_size;
    UINT8* cdfsnp_mgr_cfg_db_buff;

    int    cdfsnp_mgr_cfg_fd;

    snprintf((char *)cdfsnp_mgr_cfg_db_name, CDFSNP_MGR_CONFIG_DB_NAME_MAX_SIZE, "%s/config.db", (char *)cstring_get_str(cdfsnp_db_root_dir));
    if(0 == access((char *)cdfsnp_mgr_cfg_db_name, F_OK))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cfg_db: cdfsnp mgr cfg db %s already exist\n", (char *)cdfsnp_mgr_cfg_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_cfg_fd = c_file_open((char *)cdfsnp_mgr_cfg_db_name, O_RDWR | O_CREAT, 0666);
    if(ERR_FD == cdfsnp_mgr_cfg_fd)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cfg_db: open cdfsnp mgr cfg db %s failed\n", (char *)cdfsnp_mgr_cfg_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_cfg_db_size = sizeof(CDFSNP_MGR_CFG);
    cdfsnp_mgr_cfg_db_buff = (UINT8 *)CDFSNP_MGR_CFG(cdfsnp_mgr);
    if(EC_FALSE == cdfsnp_mgr_buff_flush(cdfsnp_mgr_cfg_fd, (UINT32)0, cdfsnp_mgr_cfg_db_size, cdfsnp_mgr_cfg_db_buff))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create_cfg_db: flush %ld bytes failed from cdfsnp mgr cfg db %s\n",
                            cdfsnp_mgr_cfg_db_size, (char *)cdfsnp_mgr_cfg_db_name);
        c_file_close(cdfsnp_mgr_cfg_fd);
        cdfsnp_mgr_cfg_fd = ERR_FD;

        return (EC_FALSE);
    }

    c_file_close(cdfsnp_mgr_cfg_fd);
    cdfsnp_mgr_cfg_fd = ERR_FD;

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_flush_cfg_db(CDFSNP_MGR *cdfsnp_mgr)
{
    UINT8  cdfsnp_mgr_cfg_db_name[ CDFSNP_MGR_CONFIG_DB_NAME_MAX_SIZE ];
    UINT32 cdfsnp_mgr_cfg_db_size;
    UINT8* cdfsnp_mgr_cfg_db_buff;

    CSTRING *cdfsnp_db_root_dir;

    int    cdfsnp_mgr_cfg_fd;

    cdfsnp_db_root_dir = CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr);

    snprintf((char *)cdfsnp_mgr_cfg_db_name, CDFSNP_MGR_CONFIG_DB_NAME_MAX_SIZE, "%s/config.db", (char *)cstring_get_str(cdfsnp_db_root_dir));
    if(0 != access((char *)cdfsnp_mgr_cfg_db_name, F_OK))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_cfg_db: cdfsnp mgr cfg db %s not exist\n", (char *)cdfsnp_mgr_cfg_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_cfg_fd = c_file_open((char *)cdfsnp_mgr_cfg_db_name, O_RDWR, 0666);
    if(ERR_FD == cdfsnp_mgr_cfg_fd)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_cfg_db: open cdfsnp mgr cfg db %s failed\n", (char *)cdfsnp_mgr_cfg_db_name);
        return (EC_FALSE);
    }

    cdfsnp_mgr_cfg_db_size = sizeof(CDFSNP_MGR_CFG);
    cdfsnp_mgr_cfg_db_buff = (UINT8 *)CDFSNP_MGR_CFG(cdfsnp_mgr);
    if(EC_FALSE == cdfsnp_mgr_buff_flush(cdfsnp_mgr_cfg_fd, (UINT32)0, cdfsnp_mgr_cfg_db_size, cdfsnp_mgr_cfg_db_buff))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_cfg_db: flush %ld bytes failed from cdfsnp mgr cfg db %s\n",
                            cdfsnp_mgr_cfg_db_size, (char *)cdfsnp_mgr_cfg_db_name);
        c_file_close(cdfsnp_mgr_cfg_fd);
        cdfsnp_mgr_cfg_fd = ERR_FD;

        return (EC_FALSE);
    }

    c_file_close(cdfsnp_mgr_cfg_fd);
    cdfsnp_mgr_cfg_fd = ERR_FD;

    return (EC_TRUE);
}

void cdfsnp_mgr_print_cfg_db(LOG *log, const CDFSNP_MGR *cdfsnp_mgr)
{
    sys_log(log, "cdfsnp mode                : %ld\n", CDFSNP_MGR_NP_MODE(cdfsnp_mgr));
    sys_log(log, "cdfsnp first hash algo id  : %ld\n", CDFSNP_MGR_NP_FIRST_CHASH_ALGO_ID(cdfsnp_mgr));
    sys_log(log, "cdfsnp second hash algo id : %ld\n", CDFSNP_MGR_NP_SECOND_CHASH_ALGO_ID(cdfsnp_mgr));
    sys_log(log, "cdfsnp item max num        : %ld\n", CDFSNP_MGR_NP_ITEM_MAX_NUM(cdfsnp_mgr));
    sys_log(log, "cdfsnp cbloom row num      : %ld\n", CDFSNP_MGR_NP_CBLOOM_ROW_NUM(cdfsnp_mgr));
    sys_log(log, "cdfsnp cbloom col num      : %ld\n", CDFSNP_MGR_NP_CBLOOM_COL_NUM(cdfsnp_mgr));
    sys_log(log, "cdfsnp support max num     : %ld\n", CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr));
    sys_log(log, "cdfsnp used max path layout: %ld\n", CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr));
    return;
}

void cdfsnp_mgr_print(LOG *log, const CDFSNP_MGR *cdfsnp_mgr)
{
    sys_log(log, "cdfsnp mgr db root dir      : %s\n", (char *)CDFSNP_MGR_DB_ROOT_DIR_STR(cdfsnp_mgr));
    sys_log(log, "cdfsnp mgr cached np max num: %ld\n", CDFSNP_MGR_NP_CACHED_MAX_NUM(cdfsnp_mgr));
    sys_log(log, "cdfsnp mgr cached np cur num: %ld\n", clist_size(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr)));
    sys_log(log, "cdfsnp header tbl buff len  : %ld\n", CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr));
    //sys_log(log, "cdfsnp header tbl buff      : %lx\n", CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr));
    sys_log(log, "cdfsnp cbloom tbl buff len  : %ld\n", CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr));
    //sys_log(log, "cdfsnp cbloom tbl buff      : %lx\n", CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr));

    sys_log(log, "cdfsnp mgr cfg:\n");
    cdfsnp_mgr_print_cfg_db(log, cdfsnp_mgr);

    sys_log(log, "cdfsnp mgr header tbl:\n");
    cdfsnp_mgr_print_header_db(log, cdfsnp_mgr);

    //sys_log(log, "cdfsnp mgr cbloom tbl:\n");
    //cdfsnp_mgr_print_cbloom_db(log, cdfsnp_mgr);
    return;
}

EC_BOOL cdfsnp_mgr_log_open(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    UINT8  cdfsnp_mgr_lost_fnode_log_name[ CDFSNP_MGR_LOST_FNODE_LOG_NAME_MAX_SIZE ];
    UINT8  cdfsnp_mgr_lost_replica_log_name[ CDFSNP_MGR_LOST_REPLICA_LOG_NAME_MAX_SIZE ];

    snprintf((char *)cdfsnp_mgr_lost_fnode_log_name, CDFSNP_MGR_LOST_FNODE_LOG_NAME_MAX_SIZE, "%s/rank_%s_lost_fnode",
             (char *)cstring_get_str(cdfsnp_db_root_dir), c_word_to_ipv4(CMPI_LOCAL_TCID));

    CDFSNP_MGR_LOST_FNODE_LOG(cdfsnp_mgr) = log_file_open((char *)cdfsnp_mgr_lost_fnode_log_name, "w+",
                                                CMPI_LOCAL_TCID, CMPI_LOCAL_RANK,
                                                LOGD_FILE_RECORD_LIMIT_DISABLED, (UINT32)SWITCH_ON,
                                                LOGD_SWITCH_OFF_DISABLE, LOGD_PID_INFO_ENABLE);

    if(NULL_PTR == CDFSNP_MGR_LOST_FNODE_LOG(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_log_open: open lost fnode log file %s failed\n", (char *)cdfsnp_mgr_lost_fnode_log_name);
        return (EC_FALSE);
    }

    snprintf((char *)cdfsnp_mgr_lost_replica_log_name, CDFSNP_MGR_LOST_REPLICA_LOG_NAME_MAX_SIZE, "%s/rank_%s_lost_replica",
             (char *)cstring_get_str(cdfsnp_db_root_dir), c_word_to_ipv4(CMPI_LOCAL_TCID));

    CDFSNP_MGR_LOST_REPLICA_LOG(cdfsnp_mgr) = log_file_open((char *)cdfsnp_mgr_lost_replica_log_name, "w+",
                                                  CMPI_LOCAL_TCID, CMPI_LOCAL_RANK,
                                                  LOGD_FILE_RECORD_LIMIT_DISABLED, (UINT32)SWITCH_ON,
                                                  LOGD_SWITCH_OFF_DISABLE, LOGD_PID_INFO_ENABLE);

    if(NULL_PTR == CDFSNP_MGR_LOST_REPLICA_LOG(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_log_open: open lost replica log file %s failed\n", (char *)cdfsnp_mgr_lost_replica_log_name);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_log_close(CDFSNP_MGR *cdfsnp_mgr)
{
    if(NULL_PTR != CDFSNP_MGR_LOST_FNODE_LOG(cdfsnp_mgr))
    {
        log_file_close(CDFSNP_MGR_LOST_FNODE_LOG(cdfsnp_mgr));
        CDFSNP_MGR_LOST_FNODE_LOG(cdfsnp_mgr) = NULL_PTR;
    }

    if(NULL_PTR != CDFSNP_MGR_LOST_REPLICA_LOG(cdfsnp_mgr))
    {
        log_file_close(CDFSNP_MGR_LOST_REPLICA_LOG(cdfsnp_mgr));
        CDFSNP_MGR_LOST_REPLICA_LOG(cdfsnp_mgr) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_load(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *cdfsnp_db_root_dir)
{
    if(NULL_PTR != CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr))
    {
        cstring_clean(CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr));
        cstring_clone(cdfsnp_db_root_dir, CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr));
    }
    else
    {
        CDFSNP_MGR_DB_ROOT_DIR(cdfsnp_mgr) = cstring_new(cstring_get_str(cdfsnp_db_root_dir), LOC_CDFSNPMGR_0018);
    }

    if(EC_FALSE == cdfsnp_mgr_load_cfg_db(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load: load cfg db failed from dir %s\n", (char *)cstring_get_str(cdfsnp_db_root_dir));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_load_header_db(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load: load header db failed from dir %s\n", (char *)cstring_get_str(cdfsnp_db_root_dir));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_load_cbloom_db(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_load: load cbloom db failed from dir %s\n", (char *)cstring_get_str(cdfsnp_db_root_dir));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_link(CDFSNP_MGR *cdfsnp_mgr)
{
    UINT32 cdfsnp_header_offset;
    UINT32 cdfsnp_cbloom_offset;
    UINT32 cdfsnp_path_layout;

    cdfsnp_header_offset = 0;
    cdfsnp_cbloom_offset = 0;
    cdfsnp_path_layout   = 0;

    for(;;)
    {
        CDFSNP_HEADER *cdfsnp_header;
        CBLOOM  *cdfsnp_cbloom;
        CDFSNP  *cdfsnp;

        cdfsnp_header = (CDFSNP_HEADER *)(CDFSNP_MGR_NP_HEADER_TBL_BUFF(cdfsnp_mgr) + cdfsnp_header_offset);
        cdfsnp_cbloom = (CBLOOM *)(CDFSNP_MGR_NP_CBLOOM_TBL_BUFF(cdfsnp_mgr) + cdfsnp_cbloom_offset);

        cdfsnp = cdfsnp_new(cdfsnp_path_layout, cdfsnp_header, cdfsnp_cbloom);
        if(NULL_PTR == cdfsnp)
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_link:new np %ld failed\n", cdfsnp_path_layout);
            return (EC_FALSE);
        }

        cvector_push(CDFSNP_MGR_NP_VEC(cdfsnp_mgr), (void *)cdfsnp );

        cdfsnp_header_offset += sizeof(CDFSNP_HEADER);
        cdfsnp_cbloom_offset += sizeof(CBLOOM) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(CDFSNP_HEADER_BMROW(cdfsnp_header) * CDFSNP_HEADER_BMCOL(cdfsnp_header)));
        cdfsnp_path_layout   ++;

        if(cdfsnp_header_offset >= CDFSNP_MGR_NP_HEADER_TBL_BUFF_LEN(cdfsnp_mgr))
        {
            break;
        }

        if(cdfsnp_cbloom_offset >= CDFSNP_MGR_NP_CBLOOM_TBL_BUFF_LEN(cdfsnp_mgr))
        {
            break;
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_cache(CDFSNP_MGR *cdfsnp_mgr)
{
    UINT32 cdfsnp_path_layout;

    CDFSNP *cdfsnp;

    cdfsnp_path_layout = CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr);

    cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
    if(NULL_PTR == cdfsnp)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_cache: fetch np %ld failed\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_HDR(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_cache: fetched np %ld not link to header\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_CBLOOM(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_cache: fetched np %ld not link to cbloom\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(CDFSNP_IS_NOT_RDWR(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 1)(LOGSTDOUT, "warn:cdfsnp_mgr_cache: fetched np %ld stat %ld was not RDWR\n",
                            cdfsnp_path_layout, CDFSNP_STATE(cdfsnp));
    }

    if(CDFSNP_IS_CACHED(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 1)(LOGSTDOUT, "warn:cdfsnp_mgr_cache: fetched np %ld stat %ld was already cached\n",
                            cdfsnp_path_layout, CDFSNP_STATE(cdfsnp));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_cache: swapin np %ld failed from root dir %s\n",
                            cdfsnp_path_layout, (char *)CDFSNP_MGR_DB_ROOT_DIR_STR(cdfsnp_mgr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_flush_np(CDFSNP_MGR *cdfsnp_mgr, const UINT32 cdfsnp_path_layout)
{
    CDFSNP *cdfsnp;

    UINT32 cdfsnp_header_offset;
    UINT32 cdfsnp_bloom_offset;

    UINT32 cdfsnp_cbloom_row_num;
    UINT32 cdfsnp_cbloom_col_num;
    UINT32 cdfsnp_cbloom_size;

    cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
    if(NULL_PTR == cdfsnp)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_np: invalid np %ld\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_HDR(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_np: np %ld header is null\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_CBLOOM(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_np: np %ld cbloom is null\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(CDFSNP_IS_NOT_CACHED(cdfsnp) || CDFSNP_IS_NOT_UPDATED(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 1)(LOGSTDOUT, "warn:cdfsnp_mgr_flush_np: invalid np %ld state %lx\n", cdfsnp_path_layout, CDFSNP_STATE(cdfsnp));
        return (EC_TRUE);
    }

    dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_flush_np: np %ld state %lx\n", cdfsnp_path_layout, CDFSNP_STATE(cdfsnp));

    if(EC_FALSE == cdfsnp_flush(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_np: flush cdfsnp %ld failed\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    cdfsnp_cbloom_row_num = CDFSNP_HEADER_BMROW(CDFSNP_HDR(cdfsnp));
    cdfsnp_cbloom_col_num = CDFSNP_HEADER_BMCOL(CDFSNP_HDR(cdfsnp));

    cdfsnp_cbloom_size = sizeof(CBLOOM) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(cdfsnp_cbloom_row_num * cdfsnp_cbloom_col_num));

    cdfsnp_header_offset = cdfsnp_path_layout * sizeof(CDFSNP_HEADER);
    cdfsnp_bloom_offset  = cdfsnp_path_layout * cdfsnp_cbloom_size;

    if(EC_FALSE == cdfsnp_mgr_flush_cfg_db(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_np: flush cdfsnp %ld config failed\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_flush_one_header(cdfsnp_mgr, cdfsnp_header_offset, CDFSNP_HDR(cdfsnp)))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_np: flush cdfsnp %ld header failed\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_flush_one_cbloom(cdfsnp_mgr, cdfsnp_bloom_offset, cdfsnp_cbloom_size, CDFSNP_CBLOOM(cdfsnp)))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush_np: flush cdfsnp %ld cbloom failed\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    CDFSNP_SET_NOT_UPDATED(cdfsnp);

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_flush(CDFSNP_MGR *cdfsnp_mgr)
{
    CLIST_DATA *clist_data;
    EC_BOOL ret;

    ret = EC_TRUE;

    if(EC_FALSE == cdfsnp_mgr_flush_cfg_db(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush: flush config db failed\n");
        ret = EC_FALSE;
    }

    if(EC_FALSE == cdfsnp_mgr_flush_header_db(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush: flush header db failed\n");
        ret = EC_FALSE;
    }

    if(EC_FALSE == cdfsnp_mgr_flush_cbloom_db(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush: flush cbloom db failed\n");
        ret = EC_FALSE;
    }

    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0019);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);

        if(CDFSNP_IS_FULL(cdfsnp))
        {
            CDFSNP_SET_RDONLY(cdfsnp);
            CDFSNP_SET_NOT_RDWR(cdfsnp);
        }

        if(CDFSNP_IS_UPDATED(cdfsnp))
        {
            if(EC_FALSE == cdfsnp_flush(cdfsnp))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_flush: flush np %ld failed to root dir %s\n",
                                    CDFSNP_PATH_LAYOUT(cdfsnp), (char *)CDFSNP_MGR_DB_ROOT_DIR_STR(cdfsnp_mgr));
                ret = EC_FALSE;
            }
            else
            {
                CDFSNP_SET_NOT_UPDATED(cdfsnp);
            }
        }
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0020);

    return (ret);
}

EC_BOOL cdfsnp_mgr_showup_np(CDFSNP_MGR *cdfsnp_mgr, const UINT32 cdfsnp_path_layout, LOG *log)
{
    CDFSNP *cdfsnp;

    UINT32 cdfsnp_item_pos;

    cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
    if(NULL_PTR == cdfsnp)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_showup_np: invalid np %ld\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_HDR(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_showup_np: np %ld header is null\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_CBLOOM(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_showup_np: np %ld cbloom is null\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0021);

    if(CDFSNP_IS_NOT_CACHED(cdfsnp))
    {
        if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_showup_np: swapin np %ld failed\n", cdfsnp_path_layout);
            CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0022);
            return (EC_FALSE);
        }
    }

    if(NULL_PTR == CDFSNP_ITEM_VEC(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_showup_np: np %ld item vec is null\n", cdfsnp_path_layout);
        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0023);
        return (EC_FALSE);
    }

    sys_log(log, "np %ld:\n", cdfsnp_path_layout);
    cdfsnp_print_header(log, cdfsnp);

    for(cdfsnp_item_pos = 0; cdfsnp_item_pos < CDFSNP_IMNUM(cdfsnp); cdfsnp_item_pos ++)
    {
        CDFSNP_ITEM *cdfsnp_item;

        cdfsnp_item = (CDFSNP_ITEM *)(CDFSNP_ITEM_VEC(cdfsnp) + cdfsnp_item_pos);
        if(CDFSNP_ITEM_STAT_IS_NOT_USED == CDFSNP_ITEM_STAT(cdfsnp_item))
        {
            continue;
        }

        sys_log(log, "[pos %ld, offset %ld] ", cdfsnp_item_pos, cdfsnp_item_pos * sizeof(CDFSNP_ITEM));
        cdfsnp_item_print(log, cdfsnp_item);
    }
    CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0024);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_swapout(CDFSNP_MGR *cdfsnp_mgr)
{
    CLIST_DATA *clist_data;

    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0025);
    if(CDFSNP_MGR_NP_CACHED_MAX_NUM(cdfsnp_mgr) > clist_size(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr)))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_swapout: not need to swapout anyone\n");
        CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0026);
        return (EC_TRUE);
    }

    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);
        dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_swapout: check np %ld state %lx\n", CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp));

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0027);

        if(CDFSNP_IS_RDONLY(cdfsnp) && CDFSNP_IS_NOT_UPDATED(cdfsnp) && CDFSNP_NO_READER(cdfsnp))
        {
            CLIST_DATA *clist_data_rmv;

            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);
            clist_rmv_no_lock(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data_rmv);

            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_swapout: swapout np %ld state %lx\n", CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp));

            /*cached np list mount np which comes from np vec, hence do not free it but umount*/
            if(EC_FALSE == cdfsnp_swapout(cdfsnp))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapout: swapout np %ld failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));

                CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0028);
                CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0029);
                return (EC_FALSE);
            }

            CDFSNP_SET_NOT_CACHED(cdfsnp);

            CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0030);
            CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0031);
            return (EC_TRUE);
        }

        if(CDFSNP_IS_RDONLY(cdfsnp) && CDFSNP_IS_UPDATED(cdfsnp) && CDFSNP_IS_FULL(cdfsnp) && CDFSNP_NO_READER(cdfsnp))
        {
            CLIST_DATA *clist_data_rmv;

            clist_data_rmv = clist_data;
            clist_data = CLIST_DATA_PREV(clist_data);
            clist_rmv_no_lock(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data_rmv);

            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_swapout: flush np %ld state %lx\n", CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp));
            if(EC_FALSE == cdfsnp_mgr_flush_np(cdfsnp_mgr, CDFSNP_PATH_LAYOUT(cdfsnp)))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapout: flush np %ld and config db and its header and its cbloom failed\n",
                                    CDFSNP_PATH_LAYOUT(cdfsnp));

                CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0032);
                CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0033);
                return (EC_FALSE);
            }

            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_swapout: swapout np %ld state %lx\n", CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp));

            if(EC_FALSE == cdfsnp_swapout(cdfsnp))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapout: after flush, swapout np %ld failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));
                CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0034);
                CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0035);
                return (EC_FALSE);
            }

            CDFSNP_SET_NOT_CACHED(cdfsnp);
            CDFSNP_SET_NOT_RDWR(cdfsnp);
            CDFSNP_SET_RDONLY(cdfsnp);

            CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0036);
            CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0037);
            return (EC_TRUE);
        }

        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0038);
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0039);
    return (EC_FALSE);
}

EC_BOOL cdfsnp_mgr_swapin(CDFSNP_MGR *cdfsnp_mgr, const UINT32 cdfsnp_path_layout)
{
    CDFSNP *cdfsnp;
    UINT32  create_flag;

    while(CDFSNP_MGR_NP_CACHED_MAX_NUM(cdfsnp_mgr) <= clist_size(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr)))
    {
        if(EC_FALSE == cdfsnp_mgr_swapout(cdfsnp_mgr))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapin: swapout cached cdfsnp failed for swapin %ld where cached np num %ld and support max %ld\n",
                                cdfsnp_path_layout, clist_size(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr)), CDFSNP_MGR_NP_CACHED_MAX_NUM(cdfsnp_mgr));
            return (EC_FALSE);
        }
    }

    cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
    if(NULL_PTR == cdfsnp)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapin: invalid np %ld\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_HDR(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapin: fetched np %ld not link to header\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDFSNP_CBLOOM(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapin: fetched np %ld not link to cbloom\n", cdfsnp_path_layout);
        return (EC_FALSE);
    }

    CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0040);
    if(CDFSNP_IS_CACHED(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 1)(LOGSTDOUT, "warn:cdfsnp_mgr_swapin: np %ld was already cached\n", cdfsnp_path_layout);

        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0041);
        return (EC_TRUE);
    }

    if(CDFSNP_IS_LOADING(cdfsnp))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 1)(LOGSTDOUT, "warn:cdfsnp_mgr_swapin: np %ld is loading\n", cdfsnp_path_layout);

        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0042);
        return (EC_FALSE);
    }

    CDFSNP_SET_LOADING(cdfsnp);
    CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0043);

    create_flag = (~CDFSNP_O_CREATE);
    if(EC_FALSE == cdfsnp_open(cdfsnp, (char *)CDFSNP_MGR_DB_ROOT_DIR_STR(cdfsnp_mgr), &create_flag))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapin: open np %ld failed from root dir %s\n",
                            cdfsnp_path_layout, (char *)CDFSNP_MGR_DB_ROOT_DIR_STR(cdfsnp_mgr));
        CDFSNP_SET_NOT_LOADING(cdfsnp);
        return (EC_FALSE);
    }

    if(create_flag & CDFSNP_O_CREATE)
    {
        UINT32 cdfsnp_header_offset;
        UINT32 cdfsnp_cbloom_offset;

        UINT32 cdfsnp_cbloom_row_num;
        UINT32 cdfsnp_cbloom_col_num;
        UINT32 cdfsnp_cbloom_size;

        cdfsnp_header_offset = CDFSNP_PATH_LAYOUT(cdfsnp) * sizeof(CDFSNP_HEADER);

        /*flush cdfsnp header*/
        if(EC_FALSE == cdfsnp_mgr_flush_one_header(cdfsnp_mgr, cdfsnp_header_offset, CDFSNP_HDR(cdfsnp)))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapin: flush cdfsnp %ld header failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));
            cdfsnp_swapout(cdfsnp);
            CDFSNP_SET_NOT_LOADING(cdfsnp);
            return (EC_FALSE);
        }

        /*flush cdfsnp cbloom filter*/
        cdfsnp_cbloom_row_num = CDFSNP_MGR_NP_CBLOOM_ROW_NUM(cdfsnp_mgr);
        cdfsnp_cbloom_col_num = CDFSNP_MGR_NP_CBLOOM_COL_NUM(cdfsnp_mgr);;

        cdfsnp_cbloom_size = sizeof(CBLOOM) + NWORDS_TO_NBYTES(NBITS_TO_NWORDS(cdfsnp_cbloom_row_num * cdfsnp_cbloom_col_num));
        cdfsnp_cbloom_offset = cdfsnp_cbloom_size * CDFSNP_PATH_LAYOUT(cdfsnp);

        if(EC_FALSE == cdfsnp_mgr_flush_one_cbloom(cdfsnp_mgr, cdfsnp_cbloom_offset, cdfsnp_cbloom_size, CDFSNP_CBLOOM(cdfsnp)))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_swapin: flush cdfsnp %ld cbloom failed\n", CDFSNP_PATH_LAYOUT(cdfsnp));
            cdfsnp_swapout(cdfsnp);
            CDFSNP_SET_NOT_LOADING(cdfsnp);
            return (EC_FALSE);
        }
    }

    CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0044);
    CDFSNP_SET_CACHED(cdfsnp);
    CDFSNP_SET_NOT_LOADING(cdfsnp);
    CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0045);

    dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_swapin: swapin np %ld, state %lx\n", CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp));
    clist_push_back(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), (void *)cdfsnp);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_search(CDFSNP_MGR *cdfsnp_mgr, const UINT32 path_len, const UINT8 *path, const UINT32 dflag, UINT32 *searched_cdfsnp_path_layout, UINT32 *searched_offset)
{
    UINT32 cdfsnp_path_layout;
    CLIST_DATA *clist_data;

    CVECTOR *checked_cdfsnp_path_layout_vec;

    checked_cdfsnp_path_layout_vec = cvector_new(0, MM_UINT32, LOC_CDFSNPMGR_0046);

    /*search in cached np list*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0047);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;
        UINT32  offset;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);

        //CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0048);
        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0049);
        offset = cdfsnp_search_no_lock(cdfsnp, path_len, path, dflag);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            (*searched_cdfsnp_path_layout) = CDFSNP_PATH_LAYOUT(cdfsnp);
            (*searched_offset) = offset;

            CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0050);
            //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0051);

            CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0052);
            cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0053);
            return (EC_TRUE);
        }
        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)CDFSNP_PATH_LAYOUT(cdfsnp));
        //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0054);
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0055);
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0056);

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;
        UINT32  first_hash;
        UINT32  second_hash;
        UINT32  offset;

        if(CVECTOR_ERR_POS != cvector_search_front_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout, NULL_PTR))
        {
            continue;
        }

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path);
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path);

        if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0057);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_search: swapin np %ld failed with state %lx\n",
                                    cdfsnp_path_layout, CDFSNP_STATE(cdfsnp));
                cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0058);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0059);
                return (EC_FALSE);
            }
        }

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0060);
        offset = cdfsnp_search_no_lock(cdfsnp, path_len, path, dflag);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            (*searched_cdfsnp_path_layout) = cdfsnp_path_layout;
            (*searched_offset) = offset;

            //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0061);
            CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0062);

            cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0063);

            return (EC_TRUE);
        }
        //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0064);
        CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0065);
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0066);

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout);
    }

    cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0067);
    return (EC_FALSE);
}

EC_BOOL cdfsnp_mgr_update(CDFSNP_MGR *cdfsnp_mgr, const UINT32 src_datanode_tcid, const UINT32 src_block_path_layout, const UINT32 des_datanode_tcid, const UINT32 des_block_path_layout)
{
    UINT32 cdfsnp_path_layout;
    CLIST_DATA *clist_data;

    CVECTOR *checked_cdfsnp_path_layout_vec;

    checked_cdfsnp_path_layout_vec = cvector_new(0, MM_UINT32, LOC_CDFSNPMGR_0068);

    /*search in cached np list*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0069);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0070);
        cdfsnp_update_no_lock(cdfsnp, src_datanode_tcid, src_block_path_layout, des_datanode_tcid, des_block_path_layout);
        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)CDFSNP_PATH_LAYOUT(cdfsnp));
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0071);
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0072);

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;

        if(CVECTOR_ERR_POS != cvector_search_front_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout, NULL_PTR))
        {
            continue;
        }

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0073);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_search: swapin np %ld failed with state %lx\n",
                                    cdfsnp_path_layout, CDFSNP_STATE(cdfsnp));
                cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0074);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0075);
                return (EC_FALSE);
            }
        }

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0076);
        cdfsnp_update_no_lock(cdfsnp, src_datanode_tcid, src_block_path_layout, des_datanode_tcid, des_block_path_layout);
        CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0077);
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0078);

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout);
    }

    cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0079);
    return (EC_FALSE);
}

EC_BOOL cdfsnp_mgr_create(const UINT32 cdfsnp_mode, const UINT32 cdfsnp_disk_max_num, const UINT32 cdfsnp_support_max_num, const UINT32 cdfsnp_first_chash_algo_id, const UINT32 cdfsnp_second_chash_algo_id, const CSTRING *cdfsnp_db_root_dir)
{
    CDFSNP_MGR *cdfsnp_mgr;

    UINT32 cdfsnp_item_max_num;
    UINT32 cdfsnp_cbloom_row_num;
    UINT32 cdfsnp_cbloom_col_num;

    if(
        EC_FALSE == cdfsnp_mode_item_max_num(cdfsnp_mode , &cdfsnp_item_max_num)
     || EC_FALSE == cdfsnp_mode_bloom_row_num(cdfsnp_mode, &cdfsnp_cbloom_row_num)
     || EC_FALSE == cdfsnp_mode_bloom_col_num(cdfsnp_mode, &cdfsnp_cbloom_col_num)
    )
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create: invalid cdfsnp mode %ld\n", cdfsnp_mode);
        return (EC_FALSE);
    }

    cdfsnp_mgr = cdfsnp_mgr_new();

    CDFSNP_MGR_NP_MODE(cdfsnp_mgr)                 = cdfsnp_mode;
    CDFSNP_MGR_NP_FIRST_CHASH_ALGO_ID(cdfsnp_mgr)  = cdfsnp_first_chash_algo_id;
    CDFSNP_MGR_NP_SECOND_CHASH_ALGO_ID(cdfsnp_mgr) = cdfsnp_second_chash_algo_id;
    CDFSNP_MGR_NP_ITEM_MAX_NUM(cdfsnp_mgr)         = cdfsnp_item_max_num;
    CDFSNP_MGR_NP_CBLOOM_ROW_NUM(cdfsnp_mgr)       = cdfsnp_cbloom_row_num;
    CDFSNP_MGR_NP_CBLOOM_COL_NUM(cdfsnp_mgr)       = cdfsnp_cbloom_col_num;
    CDFSNP_MGR_NP_DISK_MAX_NUM(cdfsnp_mgr)         = cdfsnp_disk_max_num;
    CDFSNP_MGR_NP_SUPPORT_MAX_NUM(cdfsnp_mgr)      = cdfsnp_support_max_num;
    CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) = 0;

    if(EC_FALSE == cdfsnp_mgr_create_cfg_db(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create: create cfg db failed in root dir %s\n",
                            (char *)cstring_get_str(cdfsnp_db_root_dir));
        cdfsnp_mgr_free(cdfsnp_mgr);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_create_header_db(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create: create header db failed in root dir %s\n",
                            (char *)cstring_get_str(cdfsnp_db_root_dir));
        cdfsnp_mgr_free(cdfsnp_mgr);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_create_cbloom_db(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_create: create cbloom db failed in root dir %s\n",
                            (char *)cstring_get_str(cdfsnp_db_root_dir));
        cdfsnp_mgr_free(cdfsnp_mgr);
        return (EC_FALSE);
    }

    cdfsnp_mgr_free(cdfsnp_mgr);
    return (EC_TRUE);
}

CDFSNP_MGR * cdfsnp_mgr_open(const CSTRING *cdfsnp_db_root_dir, const UINT32 cdfsnp_cached_max_num)
{
    CDFSNP_MGR *cdfsnp_mgr;

    cdfsnp_mgr = cdfsnp_mgr_new();
    if(NULL_PTR == cdfsnp_mgr)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_open: new cdfsnp mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdfsnp_mgr_log_open(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_open: open log failed\n");
        cdfsnp_mgr_free(cdfsnp_mgr);
        return (NULL_PTR);
    }

    CDFSNP_MGR_NP_CACHED_MAX_NUM(cdfsnp_mgr) = cdfsnp_cached_max_num;

    if(EC_FALSE == cdfsnp_mgr_load(cdfsnp_mgr, cdfsnp_db_root_dir))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_open: load failed\n");
        cdfsnp_mgr_free(cdfsnp_mgr);
        return (NULL_PTR);
    }

    if(EC_FALSE == cdfsnp_mgr_link(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_open: link failed\n");
        cdfsnp_mgr_free(cdfsnp_mgr);
        return (NULL_PTR);
    }

    if(EC_FALSE == cdfsnp_mgr_cache(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_open: cache failed\n");
        cdfsnp_mgr_free(cdfsnp_mgr);
        return (NULL_PTR);
    }
    return (cdfsnp_mgr);
}

EC_BOOL cdfsnp_mgr_close(CDFSNP_MGR *cdfsnp_mgr)
{
    return cdfsnp_mgr_free(cdfsnp_mgr);
}

EC_BOOL cdfsnp_mgr_close_with_flush(CDFSNP_MGR *cdfsnp_mgr)
{
    cdfsnp_mgr_flush(cdfsnp_mgr);
    cdfsnp_mgr_close(cdfsnp_mgr);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_collect_items(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_item_vec)
{
    UINT32 cdfsnp_path_layout;
    CDFSNP_ITEM *cdfsnp_item;

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;
        UINT32  first_hash;
        UINT32  second_hash;
        UINT32  offset;

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(path), cstring_get_str(path));
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(path), cstring_get_str(path));

        if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0080);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))/*already searched the cached np*/
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_collect_items: swapin np %ld failed\n", cdfsnp_path_layout);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0081);
                return (EC_FALSE);
            }
        }

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0082);
        offset = cdfsnp_search_no_lock(cdfsnp, cstring_get_len(path), cstring_get_str(path), dflag);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            CDFSNP_ITEM *cdfsnp_item_collected;

            cdfsnp_item = cdfsnp_fetch(cdfsnp, offset);

            cdfsnp_item_collected = cdfsnp_item_new();
            cdfsnp_item_clone(cdfsnp_item, cdfsnp_item_collected);

            cvector_push_no_lock(cdfsnp_item_vec, (void *)cdfsnp_item_collected);
        }
        //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0083);
        CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0084);
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0085);
    }
    return (EC_TRUE);
}

CDFSNP *cdfsnp_mgr_reserve_np_to_write(CDFSNP_MGR *cdfsnp_mgr)
{
    CDFSNP *cdfsnp;
    UINT32 cdfsnp_path_layout;
#if 0
    /*search in cached np list*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0086);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);
        dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_reserve_np_to_write: np %ld state %lx\n",
                            CDFSNP_PATH_LAYOUT(cdfsnp), CDFSNP_STATE(cdfsnp));

        if(CDFSNP_IS_RDWR(cdfsnp))
        {
            CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0087);
            return (cdfsnp);
        }
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0088);
#endif
    CDFSNP_MGR_LOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0089);
    cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr));
    if(NULL_PTR == cdfsnp)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_reserve_np_to_write: invalid np %ld failed\n", CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr));
        CDFSNP_MGR_UNLOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0090);
        return (NULL_PTR);
    }

    if(CDFSNP_IS_CACHED(cdfsnp) && CDFSNP_IS_RDWR(cdfsnp))
    {
        CDFSNP_MGR_UNLOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0091);
        return (cdfsnp);
    }

    if(CDFSNP_MGR_IS_FULL(cdfsnp_mgr))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_reserve_np_to_write: cdfsnp mgr is full\n");
        CDFSNP_MGR_UNLOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0092);
        return (NULL_PTR);
    }

    /*move to next un-used np*/
    cdfsnp_path_layout = CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) + 1;
    if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_reserve_np_to_write: swapin np %ld failed\n", cdfsnp_path_layout);
        CDFSNP_MGR_UNLOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0093);
        return (NULL_PTR);
    }

    CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) ++;/*move forward*/

    cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
    CDFSNP_MGR_UNLOCK(cdfsnp_mgr, LOC_CDFSNPMGR_0094);

    return (cdfsnp);
}

EC_BOOL cdfsnp_mgr_reserve_np_to_read(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CDFSNP_ITEM *cdfsnp_item)
{
    UINT32 cdfsnp_path_layout;
    CLIST_DATA *clist_data;
    CVECTOR *checked_cdfsnp_path_layout_vec;
    UINT32   pos;
    EC_BOOL  ret;

    UINT32 path_len;
    UINT8 *path_str;

    path_len = cstring_get_len(path);
    path_str = cstring_get_str(path);

    checked_cdfsnp_path_layout_vec = cvector_new(0, MM_UINT32, LOC_CDFSNPMGR_0095);

    /*pre-check cbloom in cached np list to shorten the lock period*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0096);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0097);
        if(EC_FALSE == cdfsnp_check_cbloom(cdfsnp, path_len, path_str))
        {
            CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0098);
        }
        else
        {
            cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)CDFSNP_PATH_LAYOUT(cdfsnp));
        }
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0099);

    ret = EC_FALSE;
    for(pos = 0; pos < cvector_size(checked_cdfsnp_path_layout_vec); pos ++)
    {
        CDFSNP *cdfsnp;

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, (UINT32)cvector_get_no_lock(checked_cdfsnp_path_layout_vec, pos));
        if(EC_FALSE == ret)/*if not searched/read, do it!*/
        {
            UINT32  offset;

            offset = cdfsnp_search_no_lock(cdfsnp, path_len, path_str, dflag);
            if(CDFSNP_ITEM_ERR_OFFSET != offset)
            {
                cdfsnp_item_clone(cdfsnp_fetch(cdfsnp, offset), cdfsnp_item);
                ret = EC_TRUE;
            }
        }
        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0100);
    }

    if(EC_TRUE == ret)
    {
        cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0101);
        return (EC_TRUE);
    }

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;
        UINT32  first_hash;
        UINT32  second_hash;
        UINT32  offset;

        if(CVECTOR_ERR_POS != cvector_search_front_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout, NULL_PTR))
        {
            continue;
        }

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path_str);
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path_str);

        if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0102);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_reserve_np_to_read: swapin np %ld failed\n", cdfsnp_path_layout);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0103);

                cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0104);
                return (EC_FALSE);
            }
        }

        //CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0105);
        offset = cdfsnp_search_no_lock(cdfsnp, path_len, path_str, dflag);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            cdfsnp_item_clone(cdfsnp_fetch(cdfsnp, offset), cdfsnp_item);

            CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0106);
            //CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0107);
            //CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0108);

            cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0109);
            return (EC_TRUE);
        }
        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0110);
        //CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0111);
        //CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0112);

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout);
    }

    cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0113);
    return (EC_FALSE);
}

EC_BOOL cdfsnp_mgr_reserve_np_to_delete(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec)
{
    UINT32 cdfsnp_path_layout;
    CLIST_DATA *clist_data;
    CVECTOR *checked_cdfsnp_path_layout_vec;
    UINT32   pos;

    UINT32 path_len;
    UINT8 *path_str;

    path_len = cstring_get_len(path);
    path_str = cstring_get_str(path);

    checked_cdfsnp_path_layout_vec = cvector_new(0, MM_UINT32, LOC_CDFSNPMGR_0114);

    /*pre-check cbloom in cached np list to shorten the lock period*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0115);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0116);
        if(EC_FALSE == cdfsnp_check_cbloom(cdfsnp, path_len, path_str))
        {
            CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0117);
        }
        else
        {
            cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)CDFSNP_PATH_LAYOUT(cdfsnp));
        }
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0118);

    for(pos = 0; pos < cvector_size(checked_cdfsnp_path_layout_vec); pos ++)
    {
        CDFSNP *cdfsnp;
        UINT32  offset;

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, (UINT32)cvector_get_no_lock(checked_cdfsnp_path_layout_vec, pos));
        offset = cdfsnp_search_no_lock(cdfsnp, path_len, path_str, dflag);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            cdfsnp_del_item(cdfsnp, cdfsnp_fetch(cdfsnp, offset), cdfsnp_fnode_vec);
        }
        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0119);
    }

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;
        UINT32  first_hash;
        UINT32  second_hash;
        UINT32  offset;

        if(CVECTOR_ERR_POS != cvector_search_front_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout, NULL_PTR))
        {
            continue;
        }

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path_str);
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, path_len, path_str);

        if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0120);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_reserve_np_to_read: swapin np %ld failed\n", cdfsnp_path_layout);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0121);

                cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0122);
                return (EC_FALSE);
            }
        }

        //CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0123);
        offset = cdfsnp_search_no_lock(cdfsnp, path_len, path_str, dflag);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            cdfsnp_del_item(cdfsnp, cdfsnp_fetch(cdfsnp, offset), cdfsnp_fnode_vec);

            CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0124);
            //CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0125);
            //CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0126);

            cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0127);
        }
        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0128);
        //CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0129);
        //CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0130);

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout);
    }

    cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0131);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_update_np_fnode(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const CDFSNP_FNODE *cdfsnp_fnode)
{
    UINT32 cdfsnp_path_layout;
    CLIST_DATA *clist_data;
    CVECTOR *checked_cdfsnp_path_layout_vec;

    checked_cdfsnp_path_layout_vec = cvector_new(0, MM_UINT32, LOC_CDFSNPMGR_0132);

    /*search in cached np list*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0133);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;
        UINT32  offset;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0134);
        //CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0135);
        offset = cdfsnp_search_no_lock(cdfsnp, cstring_get_len(path), cstring_get_str(path), CDFSNP_ITEM_FILE_IS_REG);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            CDFSNP_ITEM *cdfsnp_item;

            cdfsnp_item = cdfsnp_fetch(cdfsnp, offset);
            cdfsnp_fnode_clone(cdfsnp_fnode, CDFSNP_ITEM_FNODE(cdfsnp_item));
            cdfsnp_item_flush(cdfsnp, offset, cdfsnp_item);/*flush item now. if np is already full and updated, flush item here will save much time*/

            //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0136);
            CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0137);

            CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0138);

            cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0139);
            return (EC_TRUE);
        }

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)CDFSNP_PATH_LAYOUT(cdfsnp));
        //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0140);
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0141);
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0142);

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;
        UINT32  first_hash;
        UINT32  second_hash;
        UINT32  offset;

        if(CVECTOR_ERR_POS != cvector_search_front_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout, NULL_PTR))
        {
            continue;
        }

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(path), cstring_get_str(path));
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(path), cstring_get_str(path));

        if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0143);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_update_np_fnode: swapin np %ld failed\n", cdfsnp_path_layout);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0144);

                cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0145);
                return (EC_FALSE);
            }
        }

        CDFSNP_LOCK(cdfsnp, LOC_CDFSNPMGR_0146);

        offset = cdfsnp_search_no_lock(cdfsnp, cstring_get_len(path), cstring_get_str(path), CDFSNP_ITEM_FILE_IS_REG);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            CDFSNP_ITEM *cdfsnp_item;

            cdfsnp_item = cdfsnp_fetch(cdfsnp, offset);
            cdfsnp_fnode_clone(cdfsnp_fnode, CDFSNP_ITEM_FNODE(cdfsnp_item));
            cdfsnp_item_flush(cdfsnp, offset, cdfsnp_item);/*flush item now. if np is already full and updated, flush item here will save much time*/

            //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0147);
            CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0148);
            CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0149);

            cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0150);
            return (EC_TRUE);
        }
        //CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0151);
        CDFSNP_DEC_READER_WITHOUT_LOCK(cdfsnp, LOC_CDFSNPMGR_0152);
        CDFSNP_UNLOCK(cdfsnp, LOC_CDFSNPMGR_0153);

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout);
    }

    cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0154);
    return (EC_FALSE);
}

EC_BOOL cdfsnp_mgr_find_dir(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *dir_path)
{
    UINT32 cdfsnp_path_layout;
    UINT32 offset;

    return cdfsnp_mgr_search(cdfsnp_mgr, cstring_get_len(dir_path), cstring_get_str(dir_path), CDFSNP_ITEM_FILE_IS_DIR, &cdfsnp_path_layout, &offset);
}

EC_BOOL cdfsnp_mgr_find_file(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path)
{
    UINT32 cdfsnp_path_layout;
    UINT32 offset;

    return cdfsnp_mgr_search(cdfsnp_mgr, cstring_get_len(file_path), cstring_get_str(file_path), CDFSNP_ITEM_FILE_IS_REG, &cdfsnp_path_layout, &offset);
}

EC_BOOL cdfsnp_mgr_find(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    UINT32 cdfsnp_path_layout;
    UINT32 offset;

    if(0 == strcmp("/", (char *)cstring_get_str(path)))/*patch*/
    {
        if(CDFSNP_ITEM_FILE_IS_ANY == dflag || CDFSNP_ITEM_FILE_IS_DIR == dflag)
        {
            return (EC_TRUE);
        }
        return (EC_FALSE);
    }

    return cdfsnp_mgr_search(cdfsnp_mgr, cstring_get_len(path), cstring_get_str(path), dflag, &cdfsnp_path_layout, &offset);
}

EC_BOOL cdfsnp_mgr_write(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, const CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFSNP *cdfsnp;
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp = cdfsnp_mgr_reserve_np_to_write(cdfsnp_mgr);
    if(NULL_PTR == cdfsnp)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_write: reserve np to write failed\n");
        return (EC_FALSE);
    }

    cdfsnp_item = cdfsnp_set(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CDFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cdfsnp_item)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_write: set file %s to np %ld failed\n",
                            (char *)cstring_get_str(file_path), CDFSNP_PATH_LAYOUT(cdfsnp));
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG != CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_write: file path %s is not regular file\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(CDFSNP_IS_FULL(cdfsnp) && CDFSNP_IS_UPDATED(cdfsnp) && CDFSNP_IS_CACHED(cdfsnp))
    {
        MOD_NODE send_mod_node;
        MOD_NODE recv_mod_node;
        TASK_MGR *task_mgr;

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&send_mod_node) = 0;
        MOD_NODE_HOPS(&send_mod_node) = 0;
        MOD_NODE_LOAD(&send_mod_node) = 0;

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, NULL_PTR, FI_cdfs_flush_np, CMPI_ERROR_MODI, CDFSNP_PATH_LAYOUT(cdfsnp));
        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        //cdfsnp_mgr_flush_np(cdfsnp_mgr, CDFSNP_PATH_LAYOUT(cdfsnp));
    }

    if(EC_FALSE == cdfsnp_fnode_import(cdfsnp_fnode, CDFSNP_ITEM_FNODE(cdfsnp_item)))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_write: import fnode to item failed where path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_write: import fnode to item successfully where path %s\n", (char *)cstring_get_str(file_path));
    cdfsnp_item_print(LOGSTDOUT, cdfsnp_item);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_read(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, CDFSNP_FNODE *cdfsnp_fnode)
{
    CDFSNP_ITEM cdfsnp_item;

    if(EC_FALSE == cdfsnp_mgr_reserve_np_to_read(cdfsnp_mgr, file_path, CDFSNP_ITEM_FILE_IS_REG, &cdfsnp_item))
    {
        return (EC_FALSE);
    }

    return cdfsnp_fnode_import(CDFSNP_ITEM_FNODE(&cdfsnp_item), cdfsnp_fnode);
}

EC_BOOL cdfsnp_mgr_delete(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path, const UINT32 dflag, CVECTOR *cdfsnp_fnode_vec)
{
    return cdfsnp_mgr_reserve_np_to_delete(cdfsnp_mgr, path, dflag, cdfsnp_fnode_vec);
}

EC_BOOL cdfsnp_mgr_mkdir(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path)
{
    CDFSNP *cdfsnp;
    CDFSNP_ITEM *cdfsnp_item;

    cdfsnp = cdfsnp_mgr_reserve_np_to_write(cdfsnp_mgr);
    if(NULL_PTR == cdfsnp)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_mkdir: reserve np to mkdir failed\n");
        return (EC_FALSE);
    }

    cdfsnp_item = cdfsnp_set(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CDFSNP_ITEM_FILE_IS_DIR);
    if(NULL_PTR == cdfsnp_item)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_mkdir: mkdir %s to np %ld failed\n",
                            (char *)cstring_get_str(file_path), CDFSNP_PATH_LAYOUT(cdfsnp));
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_DIR != CDFSNP_ITEM_DFLG(cdfsnp_item))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_mkdir: path %s is not dir\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(CDFSNP_IS_FULL(cdfsnp) && CDFSNP_IS_UPDATED(cdfsnp) && CDFSNP_IS_CACHED(cdfsnp))
    {
        MOD_NODE send_mod_node;
        MOD_NODE recv_mod_node;
        TASK_MGR *task_mgr;

        task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        MOD_NODE_TCID(&send_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&send_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&send_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&send_mod_node) = 0;
        MOD_NODE_HOPS(&send_mod_node) = 0;
        MOD_NODE_LOAD(&send_mod_node) = 0;

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;
        MOD_NODE_HOPS(&recv_mod_node) = 0;
        MOD_NODE_LOAD(&recv_mod_node) = 0;

        task_super_inc(task_mgr, &send_mod_node, &recv_mod_node, NULL_PTR, FI_cdfs_flush_np, CMPI_ERROR_MODI, CDFSNP_PATH_LAYOUT(cdfsnp));
        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

        //cdfsnp_mgr_flush_np(cdfsnp_mgr, CDFSNP_PATH_LAYOUT(cdfsnp));
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_list_path(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    UINT32 cdfsnp_path_layout;

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;
        UINT32  first_hash;
        UINT32  second_hash;
        UINT32  offset;

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path));
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path));

        if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_list_path: path %s (len %ld) not set cbloom in np %ld\n",
                                (char *)cstring_get_str(file_path), cstring_get_len(file_path),
                                cdfsnp_path_layout);
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0155);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))/*already searched the cached np*/
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_list_path: swapin np %ld failed\n", cdfsnp_path_layout);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0156);
                return (EC_FALSE);
            }
        }

        offset = cdfsnp_search_no_lock(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CDFSNP_ITEM_FILE_IS_ANY);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_list_path: path %s found in np %ld at offset %ld\n",
                                (char *)cstring_get_str(file_path), cdfsnp_path_layout, offset);

            cdfsnp_list_path_vec(cdfsnp, offset, path_cstr_vec);
        }
        else
        {
            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_list_path: path %s not found in np %ld\n",
                                (char *)cstring_get_str(file_path), cdfsnp_path_layout);
        }

        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0157);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_list_seg(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, CVECTOR  *seg_cstr_vec)
{
    UINT32 cdfsnp_path_layout;

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;
        UINT32  first_hash;
        UINT32  second_hash;
        UINT32  offset;

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        first_hash  = CDFSNP_FIRST_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path));
        second_hash = CDFSNP_SECOND_CHASH_ALGO_COMPUTE(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path));

        if(EC_FALSE == cdfsnp_cbloom_is_set(cdfsnp, first_hash, second_hash))
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0158);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))/*already searched the cached np*/
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_list_seg: swapin np %ld failed\n", cdfsnp_path_layout);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0159);
                return (EC_FALSE);
            }
        }

        offset = cdfsnp_search_no_lock(cdfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CDFSNP_ITEM_FILE_IS_ANY);
        if(CDFSNP_ITEM_ERR_OFFSET != offset)
        {
            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_list_seg: path %s found in np %ld at offset %ld\n",
                                (char *)cstring_get_str(file_path), cdfsnp_path_layout, offset);

            cdfsnp_list_seg_vec(cdfsnp, offset, seg_cstr_vec);
        }
        else
        {
            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_list_seg: path %s not found in np %ld\n",
                                (char *)cstring_get_str(file_path), cdfsnp_path_layout);
        }

        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0160);
    }
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_file_num(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_num)
{
    CVECTOR *cdfsnp_item_vec;
    UINT32 cdfsnp_item_pos;

    (*file_num) = 0;

    cdfsnp_item_vec = cvector_new(0, MM_CDFSNP_ITEM, LOC_CDFSNPMGR_0161);
    if(NULL_PTR == cdfsnp_item_vec)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_file_num: new cvector failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_collect_items(cdfsnp_mgr, path_cstr, CDFSNP_ITEM_FILE_IS_ANY, cdfsnp_item_vec))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_file_num: collect item of path %s failed\n", (char *)cstring_get_str(path_cstr));

        cvector_clean_no_lock(cdfsnp_item_vec, (CVECTOR_DATA_CLEANER)cdfsnp_item_free, LOC_CDFSNPMGR_0162);
        cvector_free_no_lock(cdfsnp_item_vec, LOC_CDFSNPMGR_0163);
        return (EC_FALSE);
    }

    for(cdfsnp_item_pos = 0; cdfsnp_item_pos < cvector_size(cdfsnp_item_vec); cdfsnp_item_pos ++)
    {
        CDFSNP_ITEM *cdfsnp_item;

        cdfsnp_item = (CDFSNP_ITEM *)cvector_get_no_lock(cdfsnp_item_vec, cdfsnp_item_pos);
        if(NULL_PTR == cdfsnp_item)
        {
            continue;
        }

        if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            (*file_num) ++;
            continue;
        }

        if(CDFSNP_ITEM_FILE_IS_DIR == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            CDFSNP_DNODE *cdfsnp_dnode;
            cdfsnp_dnode = CDFSNP_ITEM_DNODE(cdfsnp_item);

            (*file_num) += (CDFSNP_DNODE_FILE_NUM(cdfsnp_dnode) & CDFSNP_32BIT_MASK);
            continue;
        }

        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_file_num: invalid dflg %lx\n",
                            (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item));
    }

    cvector_clean_no_lock(cdfsnp_item_vec, (CVECTOR_DATA_CLEANER)cdfsnp_item_free, LOC_CDFSNPMGR_0164);
    cvector_free_no_lock(cdfsnp_item_vec, LOC_CDFSNPMGR_0165);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_file_size(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_size)
{
    CVECTOR *cdfsnp_item_vec;
    UINT32 cdfsnp_item_pos;

    (*file_size) = 0;

    cdfsnp_item_vec = cvector_new(0, MM_CDFSNP_ITEM, LOC_CDFSNPMGR_0166);
    if(NULL_PTR == cdfsnp_item_vec)
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_file_size: new cvector failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdfsnp_mgr_collect_items(cdfsnp_mgr, path_cstr, CDFSNP_ITEM_FILE_IS_ANY, cdfsnp_item_vec))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_file_size: collect item of path %s failed\n", (char *)cstring_get_str(path_cstr));
        cvector_clean_no_lock(cdfsnp_item_vec, (CVECTOR_DATA_CLEANER)cdfsnp_item_free, LOC_CDFSNPMGR_0167);
        cvector_free_no_lock(cdfsnp_item_vec, LOC_CDFSNPMGR_0168);
        return (EC_FALSE);
    }

    for(cdfsnp_item_pos = 0; cdfsnp_item_pos < cvector_size(cdfsnp_item_vec); cdfsnp_item_pos ++)
    {
        CDFSNP_ITEM *cdfsnp_item;

        cdfsnp_item = (CDFSNP_ITEM *)cvector_get_no_lock(cdfsnp_item_vec, cdfsnp_item_pos);
        if(NULL_PTR == cdfsnp_item)
        {
            continue;
        }

        if(CDFSNP_ITEM_FILE_IS_REG == CDFSNP_ITEM_DFLG(cdfsnp_item))
        {
            CDFSNP_FNODE *cdfsnp_fnode;
            cdfsnp_fnode = CDFSNP_ITEM_FNODE(cdfsnp_item);

            (*file_size) += CDFSNP_FNODE_FILESZ(cdfsnp_fnode);
            continue;
        }

        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_file_size: invalid dflg %lx\n",
                            (UINT32)CDFSNP_ITEM_DFLG(cdfsnp_item));
    }

    cvector_clean_no_lock(cdfsnp_item_vec, (CVECTOR_DATA_CLEANER)cdfsnp_item_free, LOC_CDFSNPMGR_0169);
    cvector_free_no_lock(cdfsnp_item_vec, LOC_CDFSNPMGR_0170);
    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_check_replicas(CDFSNP_MGR *cdfsnp_mgr, const CSTRING *file_path, const UINT32 replica_num, const CVECTOR *tcid_vec)
{
    CDFSNP_ITEM   cdfsnp_item;
    CDFSNP_FNODE *cdfsnp_fnode;
    UINT32 cdfsnp_inode_pos;

    if(EC_FALSE == cdfsnp_mgr_reserve_np_to_read(cdfsnp_mgr, file_path, CDFSNP_ITEM_FILE_IS_REG, &cdfsnp_item))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_check_replicas: query file %s from nnp failed\n", cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(CDFSNP_ITEM_FILE_IS_REG != CDFSNP_ITEM_DFLG(&cdfsnp_item))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_check_replicas: file path %s is not regular file\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    cdfsnp_fnode = CDFSNP_ITEM_FNODE(&cdfsnp_item);

    if(replica_num != CDFSNP_FNODE_REPNUM(cdfsnp_fnode))
    {
        dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_check_replicas: file %s replica num %ld not matched to the expected %ld\n",
                            (char *)cstring_get_str(file_path), (UINT32)CDFSNP_FNODE_REPNUM(cdfsnp_fnode), replica_num);
        return (EC_FALSE);
    }

    for(cdfsnp_inode_pos = 0; cdfsnp_inode_pos < replica_num; cdfsnp_inode_pos ++)
    {
        CDFSNP_INODE *cdfsnp_inode;

        cdfsnp_inode = CDFSNP_FNODE_INODE(cdfsnp_fnode, cdfsnp_inode_pos);
        if(CDFSNP_ERR_PATH == (CDFSNP_INODE_PATH(cdfsnp_inode) & CDFSNP_32BIT_MASK))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_check_replicas: file %s inode %ld# has invalid path layout\n",
                                (char *)cstring_get_str(file_path), cdfsnp_inode_pos
                    );

            dbg_log(SEC_0127_CDFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cdfsnp_mgr_check_replicas: cdfsnp_item is\n");
            cdfsnp_item_print(LOGSTDOUT, &cdfsnp_item);
            return (EC_FALSE);
        }

        if(CVECTOR_ERR_POS == cvector_search_front(tcid_vec, (void *)CDFSNP_INODE_TCID(cdfsnp_inode), NULL_PTR))
        {
            dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_check_replicas: file %s inode %ld# has tcid %s not in expected tcid vec\n",
                                (char *)cstring_get_str(file_path), cdfsnp_inode_pos, c_word_to_ipv4(CDFSNP_INODE_TCID(cdfsnp_inode))
                    );
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cdfsnp_mgr_figure_out_block(CDFSNP_MGR *cdfsnp_mgr, const UINT32 tcid, const UINT32 block_path_layout, LOG *log)
{
    UINT32 cdfsnp_path_layout;
    CLIST_DATA *clist_data;
    CVECTOR *checked_cdfsnp_path_layout_vec;

    checked_cdfsnp_path_layout_vec = cvector_new(0, MM_UINT32, LOC_CDFSNPMGR_0171);

    /*search in cached np list*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0172);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);
        cdfsnp_figure_out_block(cdfsnp, tcid, block_path_layout, log);

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)CDFSNP_PATH_LAYOUT(cdfsnp));
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0173);

    for(cdfsnp_path_layout = 0;
        cdfsnp_path_layout <= CDFSNP_MGR_NP_USED_MAX_PATH_LAYOUT(cdfsnp_mgr) && cdfsnp_path_layout < cvector_size(CDFSNP_MGR_NP_VEC(cdfsnp_mgr));
        cdfsnp_path_layout ++
        )
    {
        CDFSNP *cdfsnp;

        if(CVECTOR_ERR_POS != cvector_search_front_no_lock(checked_cdfsnp_path_layout_vec, (void *)cdfsnp_path_layout, NULL_PTR))
        {
            continue;
        }

        cdfsnp = CDFSNP_MGR_NP_GET_NO_LOCK(cdfsnp_mgr, cdfsnp_path_layout);
        if(NULL_PTR == cdfsnp)
        {
            continue;
        }

        CDFSNP_INC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0174);

        if(CDFSNP_IS_NOT_CACHED(cdfsnp))
        {
            if(EC_FALSE == cdfsnp_mgr_swapin(cdfsnp_mgr, cdfsnp_path_layout))
            {
                dbg_log(SEC_0127_CDFSNPMGR, 0)(LOGSTDOUT, "error:cdfsnp_mgr_figure_out_block: swapin np %ld failed\n", cdfsnp_path_layout);

                CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0175);

                cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0176);
                return (EC_FALSE);
            }
        }

        cdfsnp_figure_out_block(cdfsnp, tcid, block_path_layout, log);

        CDFSNP_DEC_READER_WITH_LOCK(cdfsnp, LOC_CDFSNPMGR_0177);

        cvector_push_no_lock(checked_cdfsnp_path_layout_vec, (void *)CDFSNP_PATH_LAYOUT(cdfsnp));
    }

    cvector_free_no_lock(checked_cdfsnp_path_layout_vec, LOC_CDFSNPMGR_0178);
    return (EC_TRUE);
}

/*debug only*/
EC_BOOL cdfsnp_mgr_show_cached_np(const CDFSNP_MGR *cdfsnp_mgr, LOG *log)
{
    CLIST_DATA *clist_data;

    /*search in cached np list*/
    CLIST_LOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0179);
    CLIST_LOOP_NEXT(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), clist_data)
    {
        CDFSNP *cdfsnp;

        cdfsnp = (CDFSNP *)CLIST_DATA_DATA(clist_data);
        cdfsnp_print(log, cdfsnp);
    }
    CLIST_UNLOCK(CDFSNP_MGR_NP_CACHED_LIST(cdfsnp_mgr), LOC_CDFSNPMGR_0180);
    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

