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
#include "real.h"

#include "task.inc"
#include "task.h"

#include "cmmap.h"
#include "camd.h"

#include "cxfsnp.h"
#include "cxfsnprb.h"
#include "cxfsnpque.h"
#include "cxfsnpmgr.h"
#include "cxfscfg.h"
#include "cxfsop.h"

#include "chashalgo.h"
#include "cmd5.h"
#include "findex.inc"

STATIC_CAST static uint32_t __cxfsnp_mgr_path_hash(const uint32_t path_len, const uint8_t *path)
{
    uint8_t   digest[ CMD5_DIGEST_LEN ];
    uint32_t  hash_val;

    cmd5_sum(path_len, path, digest);

    hash_val = (
               ((uint32_t)(digest[ 0 ] << 24))
             | ((uint32_t)(digest[ 1 ] << 16))
             | ((uint32_t)(digest[ 2 ] <<  8))
             | ((uint32_t)(digest[ 3 ] <<  0))
             );
    return (hash_val);
}

CXFSNP_MGR *cxfsnp_mgr_new()
{
    CXFSNP_MGR *cxfsnp_mgr;

    alloc_static_mem(MM_CXFSNP_MGR, &cxfsnp_mgr, LOC_CXFSNPMGR_0001);
    if(NULL_PTR != cxfsnp_mgr)
    {
        cxfsnp_mgr_init(cxfsnp_mgr);
    }

    return (cxfsnp_mgr);
}

EC_BOOL cxfsnp_mgr_init(CXFSNP_MGR *cxfsnp_mgr)
{
    CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr)       = BIT_FALSE;
    CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr)       = BIT_FALSE;

    CXFSNP_MGR_FD(cxfsnp_mgr)                   = ERR_FD;

    CXFSNP_MGR_NP_MODEL(cxfsnp_mgr)             = CXFSNP_ERR_MODEL;
    CXFSNP_MGR_NP_2ND_CHASH_ALGO_ID(cxfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CXFSNP_MGR_NP_ITEM_MAX_NUM(cxfsnp_mgr)      = 0;
    CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr)           = 0;

    CXFSNP_MGR_NP_SIZE(cxfsnp_mgr)              = 0;
    CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr)          = 0;
    CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr)          = 0;

    CXFSNP_MGR_NP_CACHE(cxfsnp_mgr)             = NULL_PTR;
    CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr)            = NULL_PTR;

    cvector_init(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), 0, MM_CXFSNP, CVECTOR_LOCK_ENABLE, LOC_CXFSNPMGR_0002);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_clean(CXFSNP_MGR *cxfsnp_mgr)
{
    if(SWITCH_OFF == CXFS_NP_MMAP_SWITCH
    && NULL_PTR != CXFSNP_MGR_NP_CACHE(cxfsnp_mgr))
    {
        c_memalign_free(CXFSNP_MGR_NP_CACHE(cxfsnp_mgr));
        CXFSNP_MGR_NP_CACHE(cxfsnp_mgr) = NULL_PTR;
    }

    if(SWITCH_ON == CXFS_NP_MMAP_SWITCH
    && NULL_PTR != CXFSNP_MGR_NP_CACHE(cxfsnp_mgr))
    {
        UINT32      wsize;
        UINT8      *mem_cache;

        wsize     = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);
        mem_cache = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr);

        if(0 != munmap(mem_cache, wsize))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "warn:cxfsnp_mgr_clean: "
                                                      "munmap size %ld failed\n",
                                                      wsize);
        }
        else
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_clean: "
                                                      "munmap size %ld done\n",
                                                      wsize);
        }

        CXFSNP_MGR_NP_CACHE(cxfsnp_mgr) = NULL_PTR;
    }

    CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr)            = NULL_PTR;

    CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr)       = BIT_FALSE;
    CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr)       = BIT_FALSE;

    CXFSNP_MGR_FD(cxfsnp_mgr)                   = ERR_FD;

    CXFSNP_MGR_NP_MODEL(cxfsnp_mgr)             = CXFSNP_ERR_MODEL;
    CXFSNP_MGR_NP_2ND_CHASH_ALGO_ID(cxfsnp_mgr) = (uint8_t)CHASH_ERR_ALGO_ID;
    CXFSNP_MGR_NP_ITEM_MAX_NUM(cxfsnp_mgr)      = 0;
    CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr)           = 0;

    CXFSNP_MGR_NP_SIZE(cxfsnp_mgr)              = 0;
    CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr)          = 0;
    CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr)          = 0;

    cvector_clean(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), (CVECTOR_DATA_CLEANER)cxfsnp_free, LOC_CXFSNPMGR_0003);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_free(CXFSNP_MGR *cxfsnp_mgr)
{
    if(NULL_PTR != cxfsnp_mgr)
    {
        cxfsnp_mgr_clean(cxfsnp_mgr);
        free_static_mem(MM_CXFSNP_MGR, cxfsnp_mgr, LOC_CXFSNPMGR_0004);
    }
    return (EC_TRUE);
}

CXFSNP *cxfsnp_mgr_open_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id)
{
    CXFSNP *cxfsnp;
    UINT32  offset;
    UINT8  *base;

    cxfsnp = (CXFSNP *)cvector_get_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), (UINT32)cxfsnp_id);
    if(NULL_PTR != cxfsnp)
    {
        return (cxfsnp);
    }

    offset = CXFSNP_MGR_NP_SIZE(cxfsnp_mgr) * ((UINT32)cxfsnp_id);
    base   = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr) + offset;

    cxfsnp = cxfsnp_open(base, CXFSNP_MGR_NP_SIZE(cxfsnp_mgr), cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_open_np: "
                                                  "open np %u failed\n",
                                                  cxfsnp_id);
        return (NULL_PTR);
    }

    if(NULL_PTR != cvector_set_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr),
                                        (UINT32)(cxfsnp_id),
                                        (void *)(cxfsnp)))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_open_np: "
                                                  "np %u already open\n",
                                                  cxfsnp_id);
        return (cxfsnp);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_open_np: "
                                              "set np %u done\n",
                                              cxfsnp_id);
    return (cxfsnp);
}

EC_BOOL cxfsnp_mgr_close_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id)
{
    CXFSNP *cxfsnp;

    cxfsnp = (CXFSNP *)cvector_get_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), (UINT32)cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:cxfsnp_mgr_close_np: np %u not open yet\n", cxfsnp_id);
        return (EC_TRUE);
    }

    cvector_set_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), cxfsnp_id, NULL_PTR);
    cxfsnp_close(cxfsnp);
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_open_np_all(CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_open_np_all: open np %u failed\n",
                                                      cxfsnp_id);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_close_np_all(CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        if(EC_FALSE == cxfsnp_mgr_close_np(cxfsnp_mgr, cxfsnp_id))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_close_np_all: close np %u failed\n",
                            cxfsnp_id);
        }
    }

    return (EC_TRUE);
}

uint32_t cxfsnp_mgr_item_max_num(const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;
    uint32_t cxfsnp_max_num;

    cxfsnp_max_num = 0;
    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        const CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR != cxfsnp)
        {
            cxfsnp_max_num += CXFSNP_ITEMS_MAX_NUM(cxfsnp);
        }
    }

    return (cxfsnp_max_num);
}

uint32_t cxfsnp_mgr_item_used_num(const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;
    uint32_t cxfsnp_used_num;

    cxfsnp_used_num = 0;
    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        const CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR != cxfsnp)
        {
            cxfsnp_used_num += CXFSNP_ITEMS_USED_NUM(cxfsnp);
        }
    }

    return (cxfsnp_used_num);
}


void cxfsnp_mgr_print_db(LOG *log, const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    sys_log(log, "cxfsnp model            : %u\n" , CXFSNP_MGR_NP_MODEL(cxfsnp_mgr));
    sys_log(log, "cxfsnp hash algo id     : %u\n" , CXFSNP_MGR_NP_2ND_CHASH_ALGO_ID(cxfsnp_mgr));
    sys_log(log, "cxfsnp item max num     : %u\n" , CXFSNP_MGR_NP_ITEM_MAX_NUM(cxfsnp_mgr));
    sys_log(log, "cxfsnp max num          : %u\n" , CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr));
    sys_log(log, "cxfsnp np size          : %ld\n", CXFSNP_MGR_NP_SIZE(cxfsnp_mgr));
    sys_log(log, "cxfsnp np start offset  : %ld\n", CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr));
    sys_log(log, "cxfsnp np end   offset  : %ld\n", CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr));
    sys_log(log, "cxfsnp np total size    : %ld\n", CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr));

    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            sys_log(log, "np %u #: (null)\n", cxfsnp_id);
        }
        else
        {
            cxfsnp_print(log, cxfsnp);
        }
    }
    return;
}

void cxfsnp_mgr_print_que_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            sys_log(log, "np %u #: (null)\n", cxfsnp_id);
        }
        else
        {
            cxfsnp_print_que_list(log, cxfsnp);
        }
    }
    return;
}

void cxfsnp_mgr_print_del_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            sys_log(log, "np %u #: (null)\n", cxfsnp_id);
        }
        else
        {
            cxfsnp_print_del_list(log, cxfsnp);
        }
    }
    return;
}

void cxfsnp_mgr_print(LOG *log, const CXFSNP_MGR *cxfsnp_mgr)
{
    sys_log(log, "cxfsnp mgr:\n");
    cxfsnp_mgr_print_db(log, cxfsnp_mgr);
    return;
}

uint64_t cxfsnp_mgr_count_meta_size(const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    uint64_t total_size;

    total_size = 0;
    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR != cxfsnp)
        {
            total_size += CXFSNP_FSIZE(cxfsnp);
        }
    }
    return (total_size);
}

uint64_t cxfsnp_mgr_count_delete_size(const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    uint64_t total_size;

    total_size = 0;
    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR != cxfsnp)
        {
            total_size += CXFSNP_DEL_SIZE(cxfsnp);
        }
    }
    return (total_size);
}

uint64_t cxfsnp_mgr_count_recycle_size(const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    uint64_t total_size;

    total_size = 0;
    cxfsnp_num = (uint32_t)cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR != cxfsnp)
        {
            total_size += CXFSNP_RECYCLE_SIZE(cxfsnp);
        }
    }
    return (total_size);
}

EC_BOOL cxfsnp_mgr_flush(CXFSNP_MGR *cxfsnp_mgr)
{
    if(SWITCH_OFF == CXFS_NP_MMAP_SWITCH
    && NULL_PTR != CXFSNP_MGR_NP_CACHE(cxfsnp_mgr)
    && ERR_FD != CXFSNP_MGR_FD(cxfsnp_mgr))
    {
        UINT32      offset;
        UINT32      wsize;
        UINT8      *mem_cache;

        offset    = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);
        wsize     = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);
        mem_cache = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr);

        if(EC_FALSE == c_file_pwrite(CXFSNP_MGR_FD(cxfsnp_mgr), &offset, wsize, mem_cache))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_flush: "
                                                      "flush npp to [%ld, %ld), size %ld failed\n",
                                                      CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr),
                                                      CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr),
                                                      wsize);
            return (EC_FALSE);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_flush: "
                                                  "flush npp to [%ld, %ld), size %ld done\n",
                                                  CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr),
                                                  CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr),
                                                  wsize);
   }

    if(SWITCH_ON == CXFS_NP_MMAP_SWITCH
    && NULL_PTR != CXFSNP_MGR_NP_CACHE(cxfsnp_mgr)
    && ERR_FD != CXFSNP_MGR_FD(cxfsnp_mgr))
    {
        UINT32      wsize;
        UINT8      *mem_cache;

        wsize     = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);
        mem_cache = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr);

        if(0 != msync(mem_cache, wsize, MS_SYNC))
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "warn:cxfsnp_mgr_flush: "
                                                   "sync np with size %ld failed\n",
                                                   wsize);
        }
        else
        {
            dbg_log(SEC_0081_CRFSNP, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_flush: "
                                                   "sync np with size %ld done\n",
                                                   wsize);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_load(CXFSNP_MGR *cxfsnp_mgr, const int cxfsnp_dev_fd, const CXFSCFG *cxfscfg)
{
    UINT32            np_offset;
    UINT32            np_mem_size;
    UINT32            np_mem_align;
    UINT8            *np_mem_cache;
    UINT32            cxfsnp_id;
    const CXFSZONE   *cxfszone;

    /*active zone*/
    cxfszone = CXFSCFG_NP_ZONE(cxfscfg, CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg));

    np_mem_size  = CXFSZONE_E_OFFSET(cxfszone) - CXFSZONE_S_OFFSET(cxfszone);
    np_mem_align = CXFSNP_MGR_MEM_ALIGNMENT;

    ASSERT(0 == (np_mem_size & (CXFSNP_MGR_MEM_ALIGNMENT - 1)));

    if(SWITCH_OFF == CXFS_NP_MMAP_SWITCH)
    {
        np_mem_cache = c_memalign_new(np_mem_size, CXFSNP_MGR_MEM_ALIGNMENT);
        if(NULL_PTR == np_mem_cache)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_load: "
                                                      "alloc %ld bytes with alignment %ld failed\n",
                                                      np_mem_size, np_mem_align);
            return (EC_FALSE);
        }

        np_offset = CXFSZONE_S_OFFSET(cxfszone);
        if(EC_FALSE == c_file_pread(cxfsnp_dev_fd, &np_offset, np_mem_size, np_mem_cache))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_load: "
                                                      "load %ld bytes from active zone %ld, offset %ld failed\n",
                                                      np_mem_size,
                                                      CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg),
                                                      CXFSZONE_S_OFFSET(cxfszone));
            c_memalign_free(np_mem_cache);
            return (EC_FALSE);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_load: "
                                                  "load %ld bytes from active zone %ld, offset %ld done\n",
                                                  np_mem_size,
                                                  CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg),
                                                  CXFSZONE_S_OFFSET(cxfszone));
    }

    if(SWITCH_ON == CXFS_NP_MMAP_SWITCH)
    {
        UINT8   *addr;

        addr = c_mmap_aligned_addr(np_mem_size, CXFSNP_MGR_MEM_ALIGNMENT);
        if(NULL_PTR == addr)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_load: "
                                                      "fetch mmap aligned addr of size %ld align %ld failed\n",
                                                      np_mem_size, (UINT32)CXFSNP_MGR_MEM_ALIGNMENT);
            return (EC_FALSE);
        }

        np_offset = CXFSZONE_S_OFFSET(cxfszone);

        np_mem_cache = (UINT8 *)mmap(addr, np_mem_size,
                                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                                     cxfsnp_dev_fd, np_offset);
        if(MAP_FAILED == np_mem_cache)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_load: "
                               "mmap fd %d offset %ld size %ld, failed, errno = %d, errstr = %s\n",
                               cxfsnp_dev_fd, np_offset, np_mem_size, errno, strerror(errno));
            return (EC_FALSE);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_load: "
                                                  "mmap %ld bytes from active zone %ld, offset %ld done\n",
                                                  np_mem_size,
                                                  CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg),
                                                  CXFSZONE_S_OFFSET(cxfszone));
    }

    /*init*/
    CXFSNP_MGR_NP_MODEL(cxfsnp_mgr)              = CXFSCFG_NP_MODEL(cxfscfg);
    CXFSNP_MGR_NP_2ND_CHASH_ALGO_ID(cxfsnp_mgr)  = CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg);
    CXFSNP_MGR_NP_ITEM_MAX_NUM(cxfsnp_mgr)       = CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg);
    CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr)            = CXFSCFG_NP_MAX_NUM(cxfscfg);
    CXFSNP_MGR_NP_SIZE(cxfsnp_mgr)               = CXFSCFG_NP_SIZE(cxfscfg);
    CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr)           = CXFSZONE_S_OFFSET(cxfszone);
    CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr)           = CXFSZONE_E_OFFSET(cxfszone);

    CXFSNP_MGR_NP_CACHE(cxfsnp_mgr)              = np_mem_cache;

    for(cxfsnp_id = cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
        cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);
        cxfsnp_id ++)
    {
        cvector_push_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), NULL_PTR);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_show_np_que_list(LOG *log, CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id)
{
    CXFSNP *cxfsnp;

    cxfsnp = (CXFSNP *)cvector_get_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        /*try to open the np and print it*/
        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_show_np_que_list: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        cxfsnp_print_que_list(log, cxfsnp);

        cxfsnp_mgr_close_np(cxfsnp_mgr, cxfsnp_id);
    }
    else
    {
        cxfsnp_print_que_list(log, cxfsnp);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_show_np_del_list(LOG *log, CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id)
{
    CXFSNP *cxfsnp;

    cxfsnp = (CXFSNP *)cvector_get_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        /*try to open the np and print it*/
        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_show_np_del_list: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        cxfsnp_print_del_list(log, cxfsnp);

        cxfsnp_mgr_close_np(cxfsnp_mgr, cxfsnp_id);
    }
    else
    {
        cxfsnp_print_del_list(log, cxfsnp);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_show_np(LOG *log, CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id)
{
    CXFSNP *cxfsnp;

    cxfsnp = (CXFSNP *)cvector_get_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        /*try to open the np and print it*/
        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_show_np: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        cxfsnp_print(log, cxfsnp);

        cxfsnp_mgr_close_np(cxfsnp_mgr, cxfsnp_id);
    }
    else
    {
        cxfsnp_print(log, cxfsnp);
    }

    return (EC_TRUE);
}

STATIC_CAST static uint32_t __cxfsnp_mgr_get_np_id_of_path(const CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;
    uint32_t hash_val;

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);
    if(1 == cxfsnp_num)
    {
        cxfsnp_id = 0;

        dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_get_np_id_of_path: cxfsnp num %u => cxfsnp id %u\n", cxfsnp_num, cxfsnp_id);
        return (cxfsnp_id);
    }

    hash_val   = __cxfsnp_mgr_path_hash(path_len, path);
    cxfsnp_id  = (hash_val % cxfsnp_num);

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_get_np_id_of_path: hash %u, cxfsnp num %u => cxfsnp id %u\n", hash_val, cxfsnp_num, cxfsnp_id);
    return (cxfsnp_id);
}

STATIC_CAST static CXFSNP *__cxfsnp_mgr_get_np_of_id(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id)
{
    CXFSNP  * cxfsnp;

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_get_np_of_id: cannot open np %u\n", cxfsnp_id);
        return (NULL_PTR);
    }

    return (cxfsnp);
}

STATIC_CAST static CXFSNP *__cxfsnp_mgr_get_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path, uint32_t *np_id)
{
    CXFSNP  * cxfsnp;
    uint32_t  cxfsnp_id;

    cxfsnp_id = __cxfsnp_mgr_get_np_id_of_path(cxfsnp_mgr, path_len, path);
    if(CXFSNP_ERR_ID == cxfsnp_id)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_get_np: no np for path %.*s\n", path_len, (char *)path);
        return (NULL_PTR);
    }

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_get_np: path %.*s in np %u but cannot open\n", path_len, path, cxfsnp_id);
        return (NULL_PTR);
    }

    if(NULL_PTR != np_id)
    {
        (*np_id) = cxfsnp_id;
    }
    //dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_get_np: path %.*s was in np %u\n", path_len, path, cxfsnp_id);

    return (cxfsnp);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_search_file(CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_cxfsnp_id)
{
    CXFSNP   *cxfsnp;
    uint32_t  cxfsnp_id;
    uint32_t  node_pos;

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, path_len, path, &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_search_file: path %.*s in np %u but cannot open\n", path_len, path, cxfsnp_id);
        return (EC_FALSE);
    }

    node_pos = cxfsnp_search(cxfsnp, path_len, path, dflag);
    if(CXFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_search_file: path %.*s in np %u but not found indeed\n", path_len, path, cxfsnp_id);
        return (EC_FALSE);
    }

    if(NULL_PTR != searched_cxfsnp_id)
    {
        (*searched_cxfsnp_id) = cxfsnp_id;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_search_dir(CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_cxfsnp_id)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;
        uint32_t  node_pos;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_search_dir: open np %u failed\n", cxfsnp_id);
            continue;
        }

        node_pos = cxfsnp_search(cxfsnp, path_len, path, dflag);
        if(CXFSNPRB_ERR_POS == node_pos)
        {
            continue;
        }

        /*found*/
        dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_search_dir: found path %.*s in np %u \n", path_len, path, cxfsnp_id);

        if(NULL_PTR != searched_cxfsnp_id)
        {
            (*searched_cxfsnp_id) = cxfsnp_id;
        }

        return (EC_TRUE);/*succ*/
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_search(CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag, uint32_t *searched_cxfsnp_id)
{
    if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __cxfsnp_mgr_search_file(cxfsnp_mgr, path_len, path, dflag, searched_cxfsnp_id);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __cxfsnp_mgr_search_dir(cxfsnp_mgr, path_len, path, dflag, searched_cxfsnp_id);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_search: path %.*s but dflag %x is not supported\n", path_len, path, dflag);
    return (EC_FALSE);
}

CXFSNP_ITEM *cxfsnp_mgr_search_item(CXFSNP_MGR *cxfsnp_mgr, const uint32_t path_len, const uint8_t *path, const uint32_t dflag)
{
    CXFSNP   *cxfsnp;
    uint32_t  cxfsnp_id;
    uint32_t  node_pos;

    CXFSNP_ITEM *cxfsnp_item;

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, path_len, path, &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_search_item: path %.*s in np %u but cannot open\n", path_len, path, cxfsnp_id);
        return (NULL_PTR);
    }

    node_pos = cxfsnp_search(cxfsnp, path_len, path, dflag);
    if(CXFSNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_search_item: path %.*s in np %u but not found indeed\n", path_len, path, cxfsnp_id);
        return (NULL_PTR);
    }

    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
    return (cxfsnp_item);
}

CXFSNP_MGR *cxfsnp_mgr_create(const uint8_t cxfsnp_model,
                                  const uint32_t cxfsnp_max_num,
                                  const uint8_t  cxfsnp_2nd_chash_algo_id,
                                  const int      cxfsnp_dev_fd,
                                  const UINT32   cxfsnp_dev_size,
                                  const UINT32   cxfsnp_dev_offset)
{
    CXFSNP     *src_cxfsnp;
    CXFSNP_MGR *cxfsnp_mgr;
    uint32_t    cxfsnp_item_max_num;
    uint32_t    cxfsnp_id;

    UINT32      np_total_size;
    UINT32      np_mem_align;
    UINT8      *np_mem_cache;

    UINT32      offset;
    UINT32      np_size;

    if(EC_FALSE == cxfsnp_model_file_size(cxfsnp_model, &np_size))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: "
                                                  "invalid np_model %u\n",
                                                  cxfsnp_model);
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsnp_model_item_max_num(cxfsnp_model, &cxfsnp_item_max_num))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: "
                                                  "invalid cxfsnp model %u\n",
                                                  cxfsnp_model);
        return (NULL_PTR);
    }

    np_total_size = ((UINT32)cxfsnp_max_num) * np_size;

    if(cxfsnp_dev_size <= np_total_size + cxfsnp_dev_offset)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: size %ld <= %ld\n",
                                                  cxfsnp_dev_size, np_total_size + cxfsnp_dev_offset);
        return (NULL_PTR);
    }

    /*align to 1MB*/
    np_mem_align = CXFSNP_MGR_MEM_ALIGNMENT;

    if(SWITCH_OFF == CXFS_NP_MMAP_SWITCH)
    {
        np_mem_cache = c_memalign_new(np_total_size, np_mem_align);
        if(NULL_PTR == np_mem_cache)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: "
                                                      "alloc %ld bytes with alignment %ld failed\n",
                                                      np_total_size, np_mem_align);
            return (NULL_PTR);
        }
    }

    if(SWITCH_ON == CXFS_NP_MMAP_SWITCH)
    {
        UINT8   *addr;

        addr = c_mmap_aligned_addr(np_total_size, CXFSNP_MGR_MEM_ALIGNMENT);
        if(NULL_PTR == addr)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: "
                                                      "fetch mmap aligned addr of size %ld align %ld failed\n",
                                                      np_total_size, (UINT32)CXFSNP_MGR_MEM_ALIGNMENT);
            return (NULL_PTR);
        }

        np_mem_cache = (UINT8 *)mmap(addr, np_total_size,
                                     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                                     cxfsnp_dev_fd, cxfsnp_dev_offset);
        if(MAP_FAILED == np_mem_cache)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: "
                               "mmap fd %d [%ld, %ld), size %ld failed, errno = %d, errstr = %s\n",
                               cxfsnp_dev_fd,
                               cxfsnp_dev_offset,
                               cxfsnp_dev_offset + np_total_size,
                               np_total_size,
                               errno, strerror(errno));
            return (NULL_PTR);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_create: "
                                                  "mmap [%ld, %ld), size %ld done\n",
                                                  cxfsnp_dev_offset,
                                                  cxfsnp_dev_offset + np_total_size,
                                                  np_total_size);
    }

    cxfsnp_mgr = cxfsnp_mgr_new();

    CXFSNP_MGR_FD(cxfsnp_mgr)                      = cxfsnp_dev_fd;
    CXFSNP_MGR_NP_MODEL(cxfsnp_mgr)                = cxfsnp_model;
    CXFSNP_MGR_NP_2ND_CHASH_ALGO_ID(cxfsnp_mgr)    = cxfsnp_2nd_chash_algo_id;
    CXFSNP_MGR_NP_ITEM_MAX_NUM(cxfsnp_mgr)         = cxfsnp_item_max_num;
    CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr)              = cxfsnp_max_num;
    CXFSNP_MGR_NP_SIZE(cxfsnp_mgr)                 = np_size;
    CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr)             = cxfsnp_dev_offset;
    CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr)             = cxfsnp_dev_offset + np_total_size;
    CXFSNP_MGR_NP_CACHE(cxfsnp_mgr)                = np_mem_cache;

    src_cxfsnp = NULL_PTR;

    offset = 0; /*np start offset*/

    for(cxfsnp_id = 0; cxfsnp_id < 1/*cxfsnp_max_num*/; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;
        UINT8  *base;

        base   = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr) + offset;
        cxfsnp = cxfsnp_create(base, cxfsnp_id, cxfsnp_model, cxfsnp_2nd_chash_algo_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: "
                                                      "create np %u failed\n",
                                                      cxfsnp_id);
            cxfsnp_mgr_free(cxfsnp_mgr);
            return (NULL_PTR);
        }

        src_cxfsnp = cxfsnp;
        /*cxfsnp_close(cxfsnp);*/

        cvector_push_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), (void *)NULL_PTR);

        offset += CXFSNP_FSIZE(cxfsnp);
    }

    for(cxfsnp_id = /*0*/1; cxfsnp_id < cxfsnp_max_num; cxfsnp_id ++)
    {
        CXFSNP *des_cxfsnp;
        UINT8  *base;

        base       = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr) + offset;
        des_cxfsnp = cxfsnp_clone(src_cxfsnp, base, cxfsnp_id);
        if(NULL_PTR == des_cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create: "
                                                      "clone np %d -> %u failed\n",
                                                      (uint32_t)0, cxfsnp_id);
            cxfsnp_close(src_cxfsnp);

            cxfsnp_mgr_free(cxfsnp_mgr);
            return (NULL_PTR);
        }

        offset += CXFSNP_FSIZE(des_cxfsnp);

        cxfsnp_close(des_cxfsnp);

        cvector_push_no_lock(CXFSNP_MGR_NP_VEC(cxfsnp_mgr), (void *)NULL_PTR);
    }

    if(NULL_PTR != src_cxfsnp)
    {
        cxfsnp_close(src_cxfsnp);
        src_cxfsnp = NULL_PTR;
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_create: create one\n");

    return (cxfsnp_mgr);
}

CXFSNP_MGR * cxfsnp_mgr_open(const int cxfsnp_dev_fd, const CXFSCFG *cxfscfg)
{
    CXFSNP_MGR *cxfsnp_mgr;

    cxfsnp_mgr = cxfsnp_mgr_new();
    if(NULL_PTR == cxfsnp_mgr)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_open: new cxfsnp mgr failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsnp_mgr_load(cxfsnp_mgr, cxfsnp_dev_fd, cxfscfg))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_open: load failed\n");
        cxfsnp_mgr_free(cxfsnp_mgr);
        return (NULL_PTR);
    }

    CXFSNP_MGR_FD(cxfsnp_mgr) = cxfsnp_dev_fd;

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_open: cxfsnp mgr load done\n");
    return (cxfsnp_mgr);
}

EC_BOOL cxfsnp_mgr_close(CXFSNP_MGR *cxfsnp_mgr)
{
    if(NULL_PTR != cxfsnp_mgr)
    {
        cxfsnp_mgr_flush(cxfsnp_mgr);
        cxfsnp_mgr_free(cxfsnp_mgr);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_dump(CXFSNP_MGR *cxfsnp_mgr, const UINT32 cxfsnp_zone_s_offset)
{
    if(NULL_PTR != CXFSNP_MGR_NP_CACHE(cxfsnp_mgr)
    && ERR_FD != CXFSNP_MGR_FD(cxfsnp_mgr))
    {
        UINT32      offset;
        UINT32      wsize;
        UINT8      *mem_cache;

        offset    = cxfsnp_zone_s_offset;
        wsize     = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);
        mem_cache = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr);

        if(EC_FALSE == c_file_pwrite(CXFSNP_MGR_FD(cxfsnp_mgr), &offset, wsize, mem_cache))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_dump: "
                                                      "dump %ld bytes to [%ld, %ld) failed\n",
                                                      wsize,
                                                      cxfsnp_zone_s_offset,
                                                      cxfsnp_zone_s_offset + wsize);
            return (EC_FALSE);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_dump: "
                                                  "dump %ld bytes to [%ld, %ld) done\n",
                                                  wsize,
                                                  cxfsnp_zone_s_offset,
                                                  cxfsnp_zone_s_offset + wsize);
        ASSERT(cxfsnp_zone_s_offset + wsize == offset);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

CMMAP_NODE *cxfsnp_mgr_create_cmmap_node(CXFSNP_MGR *cxfsnp_mgr)
{
    if(NULL_PTR != cxfsnp_mgr
    && NULL_PTR != CXFSNP_MGR_NP_CACHE(cxfsnp_mgr))
    {
        CMMAP_NODE      *cmmap_node;
        UINT8           *mcache;
        UINT32           size;

        mcache = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr);
        size   = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);

        cmmap_node = cmmap_node_create(size, CXFSNP_MGR_MEM_ALIGNMENT);
        if(NULL_PTR == cmmap_node)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create_cmmap_node: "
                                                      "create np cmmap node failed\n");
            return (NULL_PTR);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_create_cmmap_node: "
                                                  "create np cmmap node done\n");

        /*clone*/
        if(EC_FALSE == cmmap_node_import(cmmap_node, mcache, size))
        {
            cmmap_node_free(cmmap_node);

            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_create_cmmap_node: "
                                                      "import mcache %p, size %ld failed\n",
                                                      mcache, size);
            return (NULL_PTR);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_create_cmmap_node: "
                                                  "import mcache %p, size %ld done\n",
                                                  mcache, size);

        return (cmmap_node);
    }

    return (NULL_PTR);
}

EC_BOOL cxfsnp_mgr_sync(CXFSNP_MGR *cxfsnp_mgr, CAMD_MD *camd_md, CXFSCFG *cxfscfg)
{
    if(BIT_FALSE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_sync: npp is not read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != cxfsnp_mgr
    && NULL_PTR != CXFSNP_MGR_NP_CACHE(cxfsnp_mgr))
    {
        CXFSZONE        *cxfszone;
        CMMAP_NODE      *cmmap_node;
        UINT8           *mcache;
        UINT32           size;

        mcache = CXFSNP_MGR_NP_CACHE(cxfsnp_mgr);
        size   = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);

        cmmap_node = cmmap_node_create(size, CXFSNP_MGR_MEM_ALIGNMENT);
        if(NULL_PTR == cmmap_node)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_sync: "
                                                      "create np cmmap node failed\n");
            return (EC_FALSE);
        }

        /*clone*/
        if(EC_FALSE == cmmap_node_import(cmmap_node, mcache, size))
        {
            cmmap_node_free(cmmap_node);

            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_sync: "
                                                      "import mcache %p, size %ld failed\n",
                                                      mcache, size);
            return (EC_FALSE);
        }

        cxfszone = CXFSCFG_NP_ZONE(cxfscfg, CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg));

        /*sync*/
        if(EC_FALSE == cmmap_node_sync(cmmap_node, camd_md, CXFSZONE_S_OFFSET(cxfszone)))
        {
            cmmap_node_free(cmmap_node);

            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_sync: "
                                                      "sync mcache %p, size %ld to offset %ld failed\n",
                                                      mcache, size, CXFSZONE_S_OFFSET(cxfszone));
            return (EC_FALSE);
        }

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_sync: "
                                                  "sync mcache %p, size %ld to offset %ld done\n",
                                                  mcache, size, CXFSZONE_S_OFFSET(cxfszone));

        cmmap_node_free(cmmap_node);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_set_read_only(CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_set_read_only: "
                                                  "npp is in read-only mode\n");
        return (EC_FALSE);
    }

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            continue;
        }

        cxfsnp_set_read_only(cxfsnp);
    }

    CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr) = BIT_TRUE;

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_set_read_only: "
                                              "npp set read-only done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_unset_read_only(CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    if(BIT_FALSE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_unset_read_only: "
                                                  "npp is not in read-only mode\n");
        return (EC_FALSE);
    }

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            continue;
        }

        cxfsnp_unset_read_only(cxfsnp);
    }

    CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr) = BIT_FALSE;

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_unset_read_only: "
                                              "npp unset read-only done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_is_read_only(CXFSNP_MGR *cxfsnp_mgr)
{
    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_set_op_replay(CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_set_op_replay: "
                                                  "npp is in op-replay mode\n");
        return (EC_FALSE);
    }

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            continue;
        }

        cxfsnp_set_op_replay(cxfsnp);
    }

    CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr) = BIT_TRUE;

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_set_op_replay: "
                                              "npp set op-replay done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_unset_op_replay(CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    if(BIT_FALSE == CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_unset_op_replay: "
                                                  "npp is not in op-replay mode\n");
        return (EC_FALSE);
    }

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            continue;
        }

        cxfsnp_unset_op_replay(cxfsnp);
    }

    CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr) = BIT_FALSE;

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_unset_op_replay: "
                                              "npp unset op-replay done\n");
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_is_op_replay(CXFSNP_MGR *cxfsnp_mgr)
{
    if(BIT_TRUE == CXFSNP_MGR_OP_REPLAY_FLAG(cxfsnp_mgr))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_mount_op_mgr(CXFSNP_MGR *cxfsnp_mgr, CXFSOP_MGR *cxfsop_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    if(NULL_PTR != CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_mount_op_mgr: "
                                                  "op mgr exists\n");
        return (EC_FALSE);
    }

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            continue;
        }

        cxfsnp_mount_op_mgr(cxfsnp, cxfsop_mgr);
    }

    CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr) = cxfsop_mgr;

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_mount_op_mgr: "
                                              "npp mount op mgr %p done\n",
                                              cxfsop_mgr);
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_umount_op_mgr(CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    if(NULL_PTR == CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount_op_mgr: "
                                                  "op mgr not exist\n");
        return (EC_FALSE);
    }

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            continue;
        }

        cxfsnp_umount_op_mgr(cxfsnp);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_mount_op_mgr: "
                                              "npp umount op mgr %p done\n",
                                              CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr));
    CXFSNP_MGR_NP_OP_MGR(cxfsnp_mgr) = NULL_PTR;

    return (EC_TRUE);
}

REAL cxfsnp_mgr_used_ratio(const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;
    REAL     used_ratio;

    used_ratio = 0.0;
    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;
        REAL    np_used_ratio;

        cxfsnp = __cxfsnp_mgr_get_np_of_id((CXFSNP_MGR *)cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            break;
        }

        np_used_ratio = cxfsnp_used_ratio(cxfsnp);
        if(used_ratio < np_used_ratio)
        {
            used_ratio = np_used_ratio;
        }
    }

    return (used_ratio);
}

EC_BOOL cxfsnp_mgr_find_dir(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *dir_path)
{
    return __cxfsnp_mgr_search_dir(cxfsnp_mgr,
                                   (uint32_t)cstring_get_len(dir_path),
                                   cstring_get_str(dir_path),
                                   CXFSNP_ITEM_FILE_IS_DIR,
                                   NULL_PTR);
}

EC_BOOL cxfsnp_mgr_find_file(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path)
{
    return __cxfsnp_mgr_search_file(cxfsnp_mgr,
                                    (uint32_t)cstring_get_len(file_path),
                                    cstring_get_str(file_path),
                                    CXFSNP_ITEM_FILE_IS_REG,
                                    NULL_PTR);
}

CXFSNP_FNODE *cxfsnp_mgr_reserve(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path)
{
    CXFSNP *cxfsnp;
    CXFSNP_ITEM *cxfsnp_item;
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_reserve: npp is read-only\n");
        return (NULL_PTR);
    }

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_reserve: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    cxfsnp_item = cxfsnp_set(cxfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CXFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_reserve: set file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), cxfsnp_id);
        return (NULL_PTR);
    }

    if(CXFSNP_ITEM_FILE_IS_REG != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_reserve: file path %s is not regular file\n",
                            (char *)cstring_get_str(file_path));
        return (NULL_PTR);
    }

    CXFSNP_ITEM_CREATE_TIME(cxfsnp_item) = (uint32_t)task_brd_default_get_time();

    /*not import yet*/
    return CXFSNP_ITEM_FNODE(cxfsnp_item);
}

EC_BOOL cxfsnp_mgr_release(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path)
{
    CXFSNP *cxfsnp;
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_release: npp is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_release: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_delete(cxfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CXFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_release: delete file %s from np %u failed\n",
                            (char *)cstring_get_str(file_path), cxfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*   retire up to max_num files where created nsec
*   and return the actual complete num of retired files
*
**/
EC_BOOL cxfsnp_mgr_retire_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id, const UINT32 expect_num, UINT32 *complete_num)
{
    CXFSNP  *cxfsnp;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_retire_np: npp is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_retire_np: get np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_retire(cxfsnp, expect_num, complete_num))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_retire_np: retire np %u failed where expect num %ld\n",
                    cxfsnp_id, expect_num);
        return (EC_FALSE);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_retire_np: retire np %u done where expect num %ld and complete num %ld\n",
                    cxfsnp_id, expect_num, (*complete_num));

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_write(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFSNP *cxfsnp;
    CXFSNP_ITEM *cxfsnp_item;
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_write: npp is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_write: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    cxfsnp_item = cxfsnp_set(cxfsnp, cstring_get_len(file_path), cstring_get_str(file_path), CXFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_write: set file %s to np %u failed\n",
                            (char *)cstring_get_str(file_path), cxfsnp_id);
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_write: file path %s is not regular file\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_fnode_import(cxfsnp_fnode, CXFSNP_ITEM_FNODE(cxfsnp_item)))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_write: import fnode to item failed where path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0190_CXFSNPMGR, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_write: import fnode to item successfully where path %s\n",
                           (char *)cstring_get_str(file_path));
        cxfsnp_item_and_key_print(LOGSTDOUT, cxfsnp_item);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_read(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path, CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFSNP *cxfsnp;
    uint32_t cxfsnp_id;
    uint32_t node_pos;

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_read: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    node_pos = cxfsnp_search_no_lock(cxfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CXFSNP_ITEM_FILE_IS_REG);
    if(CXFSNPRB_ERR_POS != node_pos)
    {
        CXFSNP_ITEM    *cxfsnp_item;

        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
        if(NULL_PTR != cxfsnp_fnode)
        {
            cxfsnp_fnode_import(CXFSNP_ITEM_FNODE(cxfsnp_item), cxfsnp_fnode);
        }

        if(BIT_FALSE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
        {
            cxfsnpque_node_move_head(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
        }

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_update(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFSNP *cxfsnp;
    uint32_t cxfsnp_id;
    uint32_t node_pos;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_update: npp is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_update: no np for path %s\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    node_pos = cxfsnp_search_no_lock(cxfsnp, (uint32_t)cstring_get_len(file_path), cstring_get_str(file_path), CXFSNP_ITEM_FILE_IS_REG);
    if(CXFSNPRB_ERR_POS != node_pos)
    {
        CXFSNP_ITEM *cxfsnp_item;

        cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);
        cxfsnpque_node_move_head(cxfsnp, CXFSNP_ITEM_QUE_NODE(cxfsnp_item), node_pos);
        return cxfsnp_fnode_import(cxfsnp_fnode, CXFSNP_ITEM_FNODE(cxfsnp_item));
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_file(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    CXFSNP  *cxfsnp;
    uint32_t cxfsnp_id;

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_file: no np for path %.*s\n",
                           (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_file: cxfsnp %p, header %p, %s ...\n",
                        cxfsnp, CXFSNP_HDR(cxfsnp), (char *)cstring_get_str(path));

    if(EC_FALSE == cxfsnp_umount(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_file: np %u umount %.*s failed\n",
                            cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_file: np %u umount %.*s done\n",
                        cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_file_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    CXFSNP  *cxfsnp;
    uint32_t cxfsnp_id;

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_file_deep: no np for path %.*s\n",
                           (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_file_deep: cxfsnp %p, header %p, %s ...\n",
                        cxfsnp, CXFSNP_HDR(cxfsnp), (char *)cstring_get_str(path));

    if(EC_FALSE == cxfsnp_umount_deep(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_file_deep: np %u umount %.*s failed\n",
                            cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_file_deep: np %u umount %.*s done\n",
                        cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_dir(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t cxfsnp_id;

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_dir: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsnp_umount(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:__cxfsnp_mgr_umount_dir: np %u umount %.*s failed\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_dir_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t cxfsnp_id;

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_dir_deep: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsnp_umount_deep(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:__cxfsnp_mgr_umount_dir_deep: np %u umount %.*s failed\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_umount(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount: npp is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __cxfsnp_mgr_umount_file(cxfsnp_mgr, path, dflag);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __cxfsnp_mgr_umount_dir(cxfsnp_mgr, path, dflag);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount: found invalid dflag 0x%lx before umount %.*s\n",
                        dflag, (uint32_t)cstring_get_len(path), (char *)cstring_get_str(path));
    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_umount_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount_deep: npp is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __cxfsnp_mgr_umount_file_deep(cxfsnp_mgr, path, dflag);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __cxfsnp_mgr_umount_dir_deep(cxfsnp_mgr, path, dflag);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount_deep: found invalid dflag 0x%lx before umount %.*s\n",
                        dflag, (uint32_t)cstring_get_len(path), (char *)cstring_get_str(path));
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_file_wildcard(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t cxfsnp_id;
    EC_BOOL  ret;

    ret = EC_FALSE;
    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP  *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_file_wildcard: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_TRUE == cxfsnp_umount_wildcard(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_file_wildcard: np %u umount %.*s succ\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            ret = EC_TRUE;
        }
    }

    /*return true if any np succ*/
    return (ret);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_file_wildcard_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t cxfsnp_id;
    EC_BOOL  ret;

    ret = EC_FALSE;
    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP  *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_file_wildcard_deep: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_TRUE == cxfsnp_umount_wildcard_deep(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_file_wildcard_deep: np %u umount %.*s succ\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            ret = EC_TRUE;
        }
    }

    /*return true if any np succ*/
    return (ret);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_dir_wildcard(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t cxfsnp_id;

    EC_BOOL  ret;

    ret = EC_FALSE;
    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_dir_wildcard: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_TRUE == cxfsnp_umount_wildcard(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_dir_wildcard: np %u umount %.*s succ\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            ret = EC_TRUE;
        }
    }

    /*return true if any np succ*/
    return (ret);
}

STATIC_CAST static EC_BOOL __cxfsnp_mgr_umount_dir_wildcard_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    uint32_t cxfsnp_id;

    EC_BOOL  ret;

    ret = EC_FALSE;
    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:__cxfsnp_mgr_umount_dir_wildcard_deep: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_TRUE == cxfsnp_umount_wildcard_deep(cxfsnp, (uint32_t)cstring_get_len(path), cstring_get_str(path), dflag))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] __cxfsnp_mgr_umount_dir_wildcard_deep: np %u umount %.*s succ\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path), cstring_get_str(path));
            ret = EC_TRUE;
        }
    }

    /*return true if any np succ*/
    return (ret);
}

EC_BOOL cxfsnp_mgr_umount_wildcard(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount_wildcard: npp is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __cxfsnp_mgr_umount_file_wildcard(cxfsnp_mgr, path, dflag);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __cxfsnp_mgr_umount_dir_wildcard(cxfsnp_mgr, path, dflag);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount_wildcard: found invalid dflag 0x%lx before umount %.*s\n",
                        dflag, (uint32_t)cstring_get_len(path), (char *)cstring_get_str(path));
    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_umount_wildcard_deep(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const UINT32 dflag)
{
    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount_wildcard_deep: npp is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return __cxfsnp_mgr_umount_file_wildcard_deep(cxfsnp_mgr, path, dflag);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return __cxfsnp_mgr_umount_dir_wildcard_deep(cxfsnp_mgr, path, dflag);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_umount_wildcard_deep: found invalid dflag 0x%lx before umount %.*s\n",
                        dflag, (uint32_t)cstring_get_len(path), (char *)cstring_get_str(path));
    return (EC_FALSE);
}

EC_BOOL cxfsnp_mgr_mkdir(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path)
{
    CXFSNP *cxfsnp;
    CXFSNP_ITEM *cxfsnp_item;
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_mkdir: npp is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(path), cstring_get_str(path), &cxfsnp_id);;
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_mkdir: no np for path %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    cxfsnp_item = cxfsnp_set(cxfsnp, cstring_get_len(path), cstring_get_str(path), CXFSNP_ITEM_FILE_IS_DIR);
    if(NULL_PTR == cxfsnp_item)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_mkdir: mkdir %s in np %u failed\n",
                            (char *)cstring_get_str(path), cxfsnp_id);
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR != CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_mkdir: path %s is not dir in np %u\n", (char *)cstring_get_str(path), cxfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_list_path_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, const uint32_t cxfsnp_id, CVECTOR  *path_cstr_vec)
{
    CXFSNP   *cxfsnp;
    CVECTOR  *cur_path_cstr_vec;
    uint32_t  node_pos;

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_path_of_np: open np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    node_pos = cxfsnp_search_no_lock(cxfsnp, cstring_get_len(path), cstring_get_str(path), dflag);
    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    cur_path_cstr_vec = cvector_new(0, MM_CSTRING, LOC_CXFSNPMGR_0005);
    if(NULL_PTR == cur_path_cstr_vec)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_path_of_np: new cur_path_cstr_vec failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_list_path_vec(cxfsnp, node_pos, cur_path_cstr_vec))
    {
        cvector_clean(cur_path_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CXFSNPMGR_0006);
        cvector_free(cur_path_cstr_vec, LOC_CXFSNPMGR_0007);

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_path_of_np: list path %s in np %u failed\n",
                           (char *)cstring_get_str(path), cxfsnp_id);
        return (EC_FALSE);
    }

    if(0 < cvector_size(cur_path_cstr_vec))
    {
        /*merge*/
        cvector_merge_direct_no_lock(cur_path_cstr_vec, path_cstr_vec);
    }
    cvector_free(cur_path_cstr_vec, LOC_CXFSNPMGR_0008);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_list_path(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, CVECTOR  *path_cstr_vec)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        if(EC_FALSE == cxfsnp_mgr_list_path_of_np(cxfsnp_mgr, path, dflag, cxfsnp_id, path_cstr_vec))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_path: list path '%s' of np %u failed\n",
                               (char *)cstring_get_str(path), cxfsnp_id);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_list_seg_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, const uint32_t cxfsnp_id, CVECTOR  *seg_cstr_vec)
{
    CXFSNP   *cxfsnp;
    CVECTOR  *cur_seg_cstr_vec;
    uint32_t  node_pos;

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_seg_of_np: open np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    node_pos = cxfsnp_search_no_lock(cxfsnp, cstring_get_len(path), cstring_get_str(path), dflag);
    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    cur_seg_cstr_vec = cvector_new(0, MM_CSTRING, LOC_CXFSNPMGR_0009);
    if(NULL_PTR == cur_seg_cstr_vec)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_seg_of_np: new cur_seg_cstr_vec failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_list_seg_vec(cxfsnp, node_pos, cur_seg_cstr_vec))
    {
        cvector_clean(cur_seg_cstr_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CXFSNPMGR_0010);
        cvector_free(cur_seg_cstr_vec, LOC_CXFSNPMGR_0011);

        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_seg_of_np: list seg of path %s in np %u failed\n",
                           (char *)cstring_get_str(path), cxfsnp_id);
        return (EC_FALSE);
    }

    if(0 < cvector_size(cur_seg_cstr_vec))
    {
        /*merge*/
        cvector_merge_direct_no_lock(cur_seg_cstr_vec, seg_cstr_vec);
    }
    cvector_free(cur_seg_cstr_vec, LOC_CXFSNPMGR_0012);

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_list_seg(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path, const uint32_t dflag, CVECTOR  *seg_cstr_vec)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        if(EC_FALSE == cxfsnp_mgr_list_seg_of_np(cxfsnp_mgr, path, dflag, cxfsnp_id, seg_cstr_vec))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_list_seg: list path '%s' of np %u failed\n",
                               (char *)cstring_get_str(path), cxfsnp_id);
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_file_num_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t cxfsnp_id, UINT32 *file_num)
{
    CXFSNP *cxfsnp;
    uint32_t  cur_file_num;

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_num_of_np: open np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    cur_file_num = 0;
    if(EC_FALSE == cxfsnp_file_num(cxfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_num))
    {
        return (EC_TRUE);
    }

    (*file_num) += cur_file_num;
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_file_num(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, UINT32 *file_num)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_id;

    (*file_num) = 0;

    cxfsnp_num = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);
    for(cxfsnp_id = 0; cxfsnp_id < cxfsnp_num; cxfsnp_id ++)
    {
        UINT32  cur_file_num;

        cur_file_num = 0;
        if(EC_FALSE == cxfsnp_mgr_file_num_of_np(cxfsnp_mgr, path_cstr, cxfsnp_id, &cur_file_num))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_num: count file num of path '%s' of np %u failed\n",
                               (char *)cstring_get_str(path_cstr), cxfsnp_id);
            return (EC_FALSE);
        }

        (*file_num) += cur_file_num;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_node_size(CXFSNP_MGR *cxfsnp_mgr, CXFSNP *cxfsnp, uint32_t node_pos, uint64_t *file_size)
{
    CXFSNPRB_POOL *pool;
    CXFSNPRB_NODE *node;
    CXFSNP_ITEM   *item;

    if(CXFSNPRB_ERR_POS == node_pos)
    {
        return (EC_TRUE);
    }

    pool = CXFSNP_ITEMS_POOL(cxfsnp);
    node  = CXFSNPRB_POOL_NODE(pool, node_pos);

    item = (CXFSNP_ITEM *)CXFSNP_RB_NODE_ITEM(node);
    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(item))
    {
        CXFSNP_FNODE *cxfsnp_fnode;
        cxfsnp_fnode = CXFSNP_ITEM_FNODE(item);

        (*file_size) += CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
    }
    else if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(item))
    {
        /*skip it, never step down*/
    }
    else
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_node_size: invalid dflg %x\n", CXFSNP_ITEM_DIR_FLAG(item));
        return (EC_FALSE);
    }

    /*run through left subtree*/
    cxfsnp_mgr_node_size(cxfsnp_mgr, cxfsnp, CXFSNPRB_NODE_LEFT_POS(node), file_size);

    /*run through right subtree*/
    cxfsnp_mgr_node_size(cxfsnp_mgr, cxfsnp, CXFSNPRB_NODE_RIGHT_POS(node), file_size);

    return (EC_TRUE);
}

/*total file size under the directory, never search the directory in depth*/
EC_BOOL cxfsnp_mgr_dir_size(CXFSNP_MGR *cxfsnp_mgr, uint32_t cxfsnp_id, const CXFSNP_DNODE *cxfsnp_dnode, uint64_t *file_size)
{
    CXFSNP  *cxfsnp;
    uint32_t node_pos;

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_dir_size: open np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    node_pos = CXFSNP_DNODE_ROOT_POS(cxfsnp_dnode);
    if(CXFSNPRB_ERR_POS != node_pos)
    {
        cxfsnp_mgr_node_size(cxfsnp_mgr, cxfsnp, node_pos, file_size);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_file_size_of_np(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t cxfsnp_id, uint64_t *file_size)
{
    CXFSNP *cxfsnp;
    uint64_t  cur_file_size;

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_size_of_np: open np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    cur_file_size = 0;
    if(EC_FALSE == cxfsnp_file_size(cxfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_size))
    {
        return (EC_TRUE);
    }

    (*file_size) += cur_file_size;
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_file_size(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, uint64_t *file_size)
{
    CXFSNP  *cxfsnp;
    uint64_t cur_file_size;
    uint32_t cxfsnp_id;

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_size: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_file_size(cxfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cur_file_size))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "error:cxfsnp_mgr_file_size: get size of file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    if(NULL_PTR != file_size)
    {
        (*file_size) = cur_file_size;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_file_expire(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr)
{
    CXFSNP  *cxfsnp;
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_expire: npp is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_expire: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_expire(cxfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), CXFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_expire: expire file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_dir_expire(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr)
{
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_dir_expire: npp is read-only\n");
        return (EC_FALSE);
    }

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_dir_expire: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsnp_expire(cxfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), CXFSNP_ITEM_FILE_IS_DIR))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:cxfsnp_mgr_dir_expire: np %u expire %.*s failed\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_expire(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag)
{
    uint32_t cxfsnp_id;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_expire: npp is read-only\n");
        return (EC_FALSE);
    }

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_expire: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsnp_expire(cxfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:cxfsnp_mgr_expire: np %u expire %.*s failed\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_file_walk(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    CXFSNP  *cxfsnp;
    uint32_t cxfsnp_id;

    cxfsnp = __cxfsnp_mgr_get_np(cxfsnp_mgr, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), &cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_walk: no np for path %s\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_walk(cxfsnp, cstring_get_len(path_cstr), cstring_get_str(path_cstr), CXFSNP_ITEM_FILE_IS_REG, cxfsnp_dit_node))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_file_walk: walk file %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_dir_walk(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    uint32_t cxfsnp_id;

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_dir_walk: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsnp_walk(cxfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), CXFSNP_ITEM_FILE_IS_DIR, cxfsnp_dit_node))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:cxfsnp_mgr_dir_walk: np %u walk %.*s failed\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_walk(CXFSNP_MGR *cxfsnp_mgr, const CSTRING *path_cstr, const uint32_t dflag, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    uint32_t cxfsnp_id;

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
        if(NULL_PTR == cxfsnp)
        {
            dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_walk: open np %u failed\n", cxfsnp_id);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsnp_walk(cxfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag, cxfsnp_dit_node))
        {
            dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:cxfsnp_mgr_walk: np %u walk %.*s failed\n",
                                cxfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
            //return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_walk_of_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id, const CSTRING *path_cstr, const uint32_t dflag, CXFSNP_DIT_NODE *cxfsnp_dit_node)
{
    CXFSNP *cxfsnp;

    cxfsnp = cxfsnp_mgr_open_np(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_walk_of_np: open np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_walk(cxfsnp, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag, cxfsnp_dit_node))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 1)(LOGSTDOUT, "warn:cxfsnp_mgr_walk_of_np: np %u walk %.*s failed\n",
                            cxfsnp_id, (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_show_cached_np(LOG *log, const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_pos;

    cxfsnp_num = cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_pos = 0; cxfsnp_pos < cxfsnp_num; cxfsnp_pos ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_pos);
        if(NULL_PTR != cxfsnp)
        {
            cxfsnp_print(log, cxfsnp);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_show_cached_np_que_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_pos;

    cxfsnp_num = cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_pos = 0; cxfsnp_pos < cxfsnp_num; cxfsnp_pos ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_pos);
        if(NULL_PTR != cxfsnp)
        {
            cxfsnp_print_que_list(log, cxfsnp);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_show_cached_np_del_list(LOG *log, const CXFSNP_MGR *cxfsnp_mgr)
{
    uint32_t cxfsnp_num;
    uint32_t cxfsnp_pos;

    cxfsnp_num = cvector_size(CXFSNP_MGR_NP_VEC(cxfsnp_mgr));
    for(cxfsnp_pos = 0; cxfsnp_pos < cxfsnp_num; cxfsnp_pos ++)
    {
        CXFSNP *cxfsnp;

        cxfsnp = CXFSNP_MGR_NP(cxfsnp_mgr, cxfsnp_pos);
        if(NULL_PTR != cxfsnp)
        {
            cxfsnp_print_del_list(log, cxfsnp);
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnp_mgr_recycle_np(CXFSNP_MGR *cxfsnp_mgr, const uint32_t cxfsnp_id, const UINT32 max_num, CXFSNP_RECYCLE_NP *cxfsnp_recycle_np, CXFSNP_RECYCLE_DN *cxfsnp_recycle_dn, UINT32 *complete_num)
{
    CXFSNP  *cxfsnp;

    if(BIT_TRUE == CXFSNP_MGR_READ_ONLY_FLAG(cxfsnp_mgr))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_recycle_np: npp is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp = __cxfsnp_mgr_get_np_of_id(cxfsnp_mgr, cxfsnp_id);
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_recycle_np: get np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_recycle(cxfsnp, max_num, cxfsnp_recycle_np, cxfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfsnp_mgr_recycle_np: recycle np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0190_CXFSNPMGR, 9)(LOGSTDOUT, "[DEBUG] cxfsnp_mgr_recycle_np: recycle np %u done\n", cxfsnp_id);

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

