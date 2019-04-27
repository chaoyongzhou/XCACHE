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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>

#include <sys/stat.h>

#include "type.h"
#include "mm.h"
#include "log.h"

#include "cmisc.h"

#include "cbytes.h"

#include "cbadbitmap.h"

#include "cdc.h"
#include "cdcnpdeg.h"

#include "caio.h"

#include "cmmap.h"

#if (SWITCH_ON == CDC_ASSERT_SWITCH)
#define CDC_ASSERT(condition)   ASSERT(condition)
#endif/*(SWITCH_ON == CDC_ASSERT_SWITCH)*/

#if (SWITCH_OFF == CDC_ASSERT_SWITCH)
#define CDC_ASSERT(condition)   do{}while(0)
#endif/*(SWITCH_OFF == CDC_ASSERT_SWITCH)*/

#if 0
#define CDC_CRC32(data, len)   c_crc32_long((data), (len))
#else
#define CDC_CRC32(data, len)   0
#endif

STATIC_CAST const char *__cdc_op_str(const UINT32 op)
{
    if(CDC_OP_RD == op)
    {
        return ((const char *)"RD");
    }

    if(CDC_OP_WR == op)
    {
        return ((const char *)"WR");
    }

    if(CDC_OP_RW == op)
    {
        return ((const char *)"RW");
    }

    if(CDC_OP_ERR == op)
    {
        return ((const char *)"ERR");
    }

    return ((const char *)"UNKNOWN");
}

/*----------------------------------- cdc mem cache (posix memalign) interface -----------------------------------*/
static UINT32 g_cdc_mem_cache_counter = 0;
STATIC_CAST static UINT8 *__cdc_mem_cache_new(const UINT32 size, const UINT32 align)
{
    if(g_cdc_mem_cache_counter < CDC_MEM_CACHE_MAX_NUM)
    {
        UINT8    *mem_cache;

        mem_cache = (UINT8 *)c_memalign_new(size, align);
        if(NULL_PTR == mem_cache)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_mem_cache_new: alloc memory failed\n");

            return (NULL_PTR);
        }

        dbg_log(SEC_0182_CDC, 8)(LOGSTDOUT, "[DEBUG] __cdc_mem_cache_new: mem_cache = %p\n", mem_cache);
        g_cdc_mem_cache_counter ++;
        return (mem_cache);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_mem_cache_new: counter %ld reached max\n",
                                        g_cdc_mem_cache_counter);
    return (NULL_PTR);
}

STATIC_CAST static EC_BOOL __cdc_mem_cache_free(UINT8 *mem_cache)
{
    if(NULL_PTR != mem_cache)
    {
        dbg_log(SEC_0182_CDC, 8)(LOGSTDOUT, "[DEBUG] __cdc_mem_cache_free: mem_cache = %p\n", mem_cache);
        c_memalign_free(mem_cache);
        g_cdc_mem_cache_counter --;
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cdc_mem_cache_check(UINT8 *mem_cache, const UINT32 align)
{
    UINT32      addr;
    UINT32      mask;

    addr = ((UINT32)mem_cache);
    mask = (align - 1);

    if(0 == (addr & mask))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

void cdc_mem_cache_counter_print(LOG *log)
{
    sys_log(log, "g_cdc_mem_cache_counter: %ld\n", g_cdc_mem_cache_counter);
}

/**
*
* start CDC module
*
**/
CDC_MD *cdc_start(const int ssd_fd, const UINT32 ssd_offset, const UINT32 ssd_disk_size/*in byte*/,
                    const int sata_fd, const UINT32 sata_disk_size/*in byte*/)
{
    CDC_MD  *cdc_md;

    UINT32   f_s_offset;
    UINT32   f_e_offset;
    UINT32   f_size;
    UINT32   key_max_num;

    init_static_mem();

    if(ERR_FD == ssd_fd)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: no ssd_fd\n");
        return (NULL_PTR);
    }

    f_s_offset  = ssd_offset;
    f_e_offset  = f_s_offset + ssd_disk_size;

    /*adjust f_e_offset*/
    if(EC_FALSE == c_file_size(ssd_fd, &f_size))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: file size of ssd_fd %d failed\n", ssd_fd);
        return (NULL_PTR);
    }
    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_start: ssd_fd %d => ssd size %ld\n", ssd_fd, f_size);

    if(f_s_offset >= f_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: f_s_offset %ld >= f_size %ld of ssd_fd %d\n",
                                            f_s_offset, f_size, ssd_fd);
        return (NULL_PTR);
    }

    if(f_e_offset > f_size)
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_start: f_e_offset: %ld => %ld of ssd_fd %d\n",
                                            f_e_offset, f_size, ssd_fd);
        f_e_offset = f_size;
    }

    /*one key for one page in sata disk*/
    key_max_num = (sata_disk_size >> CDCPGB_PAGE_SIZE_NBITS);
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_start: "
                    "sata disk size %ld, page size %u => key max num %ld\n",
                    sata_disk_size, CDCPGB_PAGE_SIZE_NBITS, key_max_num);

    /* create a new module node */
    cdc_md = safe_malloc(sizeof(CDC_MD), LOC_CDC_0001);
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: start cdc module failed\n");
        return (NULL_PTR);
    }

    /* initialize new one CDC module */
    CDC_MD_SSD_FD(cdc_md)                       = ssd_fd;
    CDC_MD_SATA_FD(cdc_md)                      = sata_fd;
    CDC_MD_S_OFFSET(cdc_md)                     = f_s_offset;
    CDC_MD_E_OFFSET(cdc_md)                     = f_e_offset;
    CDC_MD_C_OFFSET(cdc_md)                     = CDC_ERR_OFFSET;
    CDC_MD_KEY_MAX_NUM(cdc_md)                  = key_max_num;
    CDC_MD_LOCKED_PAGE_NUM(cdc_md)              = 0;
    CDC_MD_DN(cdc_md)                           = NULL_PTR;
    CDC_MD_NP(cdc_md)                           = NULL_PTR;
    CDC_MD_CMMAP_NODE(cdc_md)                   = NULL_PTR;
    CDC_MD_CAIO_MD(cdc_md)                      = NULL_PTR;
    CDC_MD_SSD_BAD_BITMAP(cdc_md)               = NULL_PTR;
    CDC_MD_SATA_BAD_BITMAP(cdc_md)              = NULL_PTR;
    CDC_MD_FC_MAX_SPEED_FLAG(cdc_md)            = BIT_FALSE;
    CDC_MD_SHM_NP_FLAG(cdc_md)                  = BIT_FALSE;
    CDC_MD_SHM_DN_FLAG(cdc_md)                  = BIT_FALSE;
    CDC_MD_RDONLY_FLAG(cdc_md)                  = BIT_FALSE;
    CDC_MD_RESTART_FLAG(cdc_md)                 = BIT_FALSE;
    CDC_MD_DONTDUMP_FLAG(cdc_md)                = BIT_FALSE;

    CDC_MD_SEQ_NO(cdc_md)  = 0;

    clist_init(CDC_MD_REQ_LIST(cdc_md), MM_CDC_REQ, LOC_CDC_0002);

    CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) = 0;   /*set page tree[0] is active*/
    crb_tree_init(CDC_MD_PAGE_TREE(cdc_md, 0), /*init active page tree*/
                  (CRB_DATA_CMP)cdc_page_cmp,
                  (CRB_DATA_FREE)NULL_PTR, /*note: not define*/
                  (CRB_DATA_PRINT)cdc_page_print);

    crb_tree_init(CDC_MD_PAGE_TREE(cdc_md, 1), /*init standby page tree*/
                  (CRB_DATA_CMP)cdc_page_cmp,
                  (CRB_DATA_FREE)NULL_PTR, /*note: not define*/
                  (CRB_DATA_PRINT)cdc_page_print);

    clist_init(CDC_MD_POST_EVENT_REQS(cdc_md), MM_CDC_REQ, LOC_CDC_0003);

    cdcnp_degrade_cb_init(CDC_MD_NP_DEGRADE_CB(cdc_md));

    if(SWITCH_OFF == CAMD_SYNC_CDC_SWITCH
    && SWITCH_OFF == CDC_BIND_AIO_SWITCH)
    {
        UINT32   aio_model;

        aio_model = CAIO_MODEL_CHOICE;

        CDC_MD_CAIO_MD(cdc_md) = caio_start(aio_model);
        if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_start: start caio module failed\n");
            cdc_end(cdc_md);
            return (NULL_PTR);
        }
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_start: start cdc done\n");

    return (cdc_md);
}

/**
*
* end CDC module
*
**/
void cdc_end(CDC_MD *cdc_md)
{
    if(NULL_PTR != cdc_md)
    {
        if(BIT_FALSE == CDC_MD_RDONLY_FLAG(cdc_md))
        {
            cdc_poll(cdc_md);
        }

        cdc_cleanup_pages(cdc_md, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md));
        cdc_cleanup_pages(cdc_md, CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md));
        CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) = 0;

        cdc_cleanup_reqs(cdc_md);
        cdc_cleanup_post_event_reqs(cdc_md);

        cdc_flush_dn(cdc_md);
        cdc_flush_np(cdc_md);

        cdc_close_np(cdc_md);
        cdc_close_dn(cdc_md);

        CDC_MD_S_OFFSET(cdc_md)                     = CDC_ERR_OFFSET;
        CDC_MD_E_OFFSET(cdc_md)                     = CDC_ERR_OFFSET;
        CDC_MD_C_OFFSET(cdc_md)                     = CDC_ERR_OFFSET;
        CDC_MD_KEY_MAX_NUM(cdc_md)                  = 0;
        CDC_MD_LOCKED_PAGE_NUM(cdc_md)              = 0;

        if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
        {
            if(0)
            {
                caio_end(CDC_MD_CAIO_MD(cdc_md));
                CDC_MD_CAIO_MD(cdc_md) = NULL_PTR;
            }
            else
            {
                CDC_MD_CAIO_MD(cdc_md) = NULL_PTR;
            }
        }

        CDC_MD_SEQ_NO(cdc_md)                       = 0;

        CDC_MD_SSD_FD(cdc_md)                       = ERR_FD;
        CDC_MD_SATA_FD(cdc_md)                      = ERR_FD;

        CDC_MD_FC_MAX_SPEED_FLAG(cdc_md)            = BIT_FALSE;
        CDC_MD_SHM_NP_FLAG(cdc_md)                  = BIT_FALSE;
        CDC_MD_SHM_DN_FLAG(cdc_md)                  = BIT_FALSE;
        CDC_MD_RDONLY_FLAG(cdc_md)                  = BIT_FALSE;
        CDC_MD_RESTART_FLAG(cdc_md)                 = BIT_FALSE;
        CDC_MD_DONTDUMP_FLAG(cdc_md)                = BIT_FALSE;

        cdcnp_degrade_cb_clean(CDC_MD_NP_DEGRADE_CB(cdc_md));

        CDC_MD_SSD_BAD_BITMAP(cdc_md)               = NULL_PTR;
        CDC_MD_SATA_BAD_BITMAP(cdc_md)              = NULL_PTR;

        CDC_MD_CMMAP_NODE(cdc_md)                   = NULL_PTR;

        safe_free(cdc_md, LOC_CDC_0004);

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_end: stop cdc done\n");

    }

    return;
}

/**
*
* erase CDC
*
**/
EC_BOOL cdc_erase(CDC_MD *cdc_md)
{
    UINT32   f_s_offset;
    UINT32   f_e_offset;

    f_s_offset  = CDC_MD_S_OFFSET(cdc_md);
    f_e_offset  = CDC_MD_E_OFFSET(cdc_md);

    if(EC_FALSE == cdc_erase_np(cdc_md, f_s_offset, f_e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_erase: "
                                            "erase cdc np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_create: "
                                        "erase cdc np done\n");

    return (EC_TRUE);
}

/**
*
* cleanup CDC
*
**/
EC_BOOL cdc_clean(CDC_MD *cdc_md)
{
    if(NULL_PTR != cdc_md)
    {
        cdc_close_np(cdc_md);
        cdc_close_dn(cdc_md);

        cdc_umount_ssd_bad_bitmap(cdc_md);
        cdc_umount_sata_bad_bitmap(cdc_md);
    }

    return (EC_TRUE);
}

/**
*
* create CDC
*
**/
EC_BOOL cdc_create(CDC_MD *cdc_md)
{
    UINT32   f_s_offset;
    UINT32   f_e_offset;
    UINT32   key_max_num;

    f_s_offset  = CDC_MD_S_OFFSET(cdc_md);
    f_e_offset  = CDC_MD_E_OFFSET(cdc_md);
    key_max_num = CDC_MD_KEY_MAX_NUM(cdc_md);

    if(EC_FALSE == cdc_create_np(cdc_md, &f_s_offset, f_e_offset, key_max_num))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create: "
                                            "cdc module %p create np failed\n",
                                            cdc_md);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_create: "
                                        "after create np, f_s_offset = %ld\n",
                                        f_s_offset);

    if(EC_FALSE == cdc_create_dn(cdc_md, &f_s_offset, f_e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create: "
                                            "cdc module %p create dn failed\n",
                                            cdc_md);

        cdc_close_np(cdc_md);

        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_create: "
                                        "after create dn, f_s_offset = %ld\n",
                                        f_s_offset);

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_create: "
                                        "create cdc module %p\n",
                                        cdc_md);

    return (EC_TRUE);
}

/**
*
* create CDC in shared memory
*
**/
EC_BOOL cdc_create_shm(CDC_MD *cdc_md)
{
    UINT32   f_s_offset;
    UINT32   f_e_offset;
    UINT32   key_max_num;

    f_s_offset  = CDC_MD_S_OFFSET(cdc_md);
    f_e_offset  = CDC_MD_E_OFFSET(cdc_md);
    key_max_num = CDC_MD_KEY_MAX_NUM(cdc_md);

    if(EC_FALSE == cdc_create_np_shm(cdc_md, CDC_MD_CMMAP_NODE(cdc_md), &f_s_offset, f_e_offset, key_max_num))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_shm: "
                                            "cdc module %p create np failed\n",
                                            cdc_md);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_create_shm: "
                                        "after create np, f_s_offset = %ld\n",
                                        f_s_offset);

    if(EC_FALSE == cdc_create_dn_shm(cdc_md, CDC_MD_CMMAP_NODE(cdc_md), &f_s_offset, f_e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_shm: "
                                            "cdc module %p create dn failed\n",
                                            cdc_md);

        cdc_close_np(cdc_md);

        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_create_shm: "
                                        "after create dn, f_s_offset = %ld\n",
                                        f_s_offset);

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_create_shm: "
                                        "create cdc module %p\n",
                                        cdc_md);

    return (EC_TRUE);
}

/**
*
* load CDC
*
**/
EC_BOOL cdc_load(CDC_MD *cdc_md)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load: no cdc module\n");
        return (EC_FALSE);
    }

    CDC_MD_C_OFFSET(cdc_md) = CDC_MD_S_OFFSET(cdc_md);

    if(EC_FALSE == cdc_load_np(cdc_md, &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load: load np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load: load np done\n");

    if(EC_FALSE == cdc_load_dn(cdc_md, &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load: load dn failed\n");

        cdc_close_np(cdc_md);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load: load dn done\n");

    return (EC_TRUE);
}

/**
*
* load CDC from shared memory
*
**/
EC_BOOL cdc_load_shm(CDC_MD *cdc_md)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_shm: no cdc module\n");
        return (EC_FALSE);
    }

    CDC_MD_C_OFFSET(cdc_md) = CDC_MD_S_OFFSET(cdc_md);

    if(EC_FALSE == cdc_load_np_shm(cdc_md, CDC_MD_CMMAP_NODE(cdc_md), &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_shm: load np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_shm: load np done\n");

    if(EC_FALSE == cdc_load_dn_shm(cdc_md, CDC_MD_CMMAP_NODE(cdc_md), &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_shm: load dn failed\n");

        cdc_close_np(cdc_md);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_shm: load dn done\n");

    return (EC_TRUE);
}

/**
*
* retrieve CDC from ssd
*
**/
EC_BOOL cdc_retrieve_shm(CDC_MD *cdc_md)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_shm: no cdc module\n");
        return (EC_FALSE);
    }

    CDC_MD_C_OFFSET(cdc_md) = CDC_MD_S_OFFSET(cdc_md);

    if(EC_FALSE == cdc_retrieve_np_shm(cdc_md, CDC_MD_CMMAP_NODE(cdc_md), &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_shm: load np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_retrieve_shm: load np done\n");

    if(EC_FALSE == cdc_retrieve_dn_shm(cdc_md, CDC_MD_CMMAP_NODE(cdc_md), &CDC_MD_C_OFFSET(cdc_md), CDC_MD_E_OFFSET(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_shm: load dn failed\n");

        cdc_close_np(cdc_md);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_retrieve_shm: load dn done\n");

    return (EC_TRUE);
}

/**
*
* flush CDC
*
**/
EC_BOOL cdc_flush(CDC_MD *cdc_md)
{
    if(NULL_PTR == cdc_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush: no cdc module\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdc_flush_np(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush: flush np failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_flush: flush np done\n");

    if(EC_FALSE == cdc_flush_dn(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush: flush dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush: flush dn done\n");

    return (EC_TRUE);
}

/*mount mmap node*/
EC_BOOL cdc_mount_mmap(CDC_MD *cdc_md, CMMAP_NODE *cmmap_node)
{
    if(NULL_PTR == CDC_MD_CMMAP_NODE(cdc_md))
    {
        CDC_MD_CMMAP_NODE(cdc_md) = cmmap_node;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*umount mmap node*/
EC_BOOL cdc_umount_mmap(CDC_MD *cdc_md)
{
    if(NULL_PTR != cdc_md
    && NULL_PTR != CDC_MD_CMMAP_NODE(cdc_md))
    {
        cdc_close_np(cdc_md);
        cdc_close_dn(cdc_md);

        cdc_umount_ssd_bad_bitmap(cdc_md);
        cdc_umount_sata_bad_bitmap(cdc_md);

        CDC_MD_CMMAP_NODE(cdc_md) = NULL_PTR;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/*get mmap node*/
CMMAP_NODE *cdc_get_mmap(CDC_MD *cdc_md)
{
    return CDC_MD_CMMAP_NODE(cdc_md);
}

/**
*
* bind CAIO module to CDC module
*
**/
EC_BOOL cdc_bind_aio(CDC_MD *cdc_md, CAIO_MD *caio_md)
{
    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_bind_aio: "
                                            "caio module exists already\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == caio_md)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_bind_aio: "
                                            "caio module is null\n");
        return (EC_FALSE);
    }

    CDC_MD_CAIO_MD(cdc_md) = caio_md;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_bind_aio: done\n");

    return (EC_TRUE);
}

/**
*
* unbind CAIO module from CDC module
*
**/
EC_BOOL cdc_unbind_aio(CDC_MD *cdc_md)
{
    if(NULL_PTR == CDC_MD_CAIO_MD(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_unbind_aio: "
                                            "caio module is null\n");
        return (EC_FALSE);
    }

    CDC_MD_CAIO_MD(cdc_md) = NULL_PTR;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_unbind_aio: done\n");

    return (EC_TRUE);
}

/*note: register eventfd and event handler to epoll READ event*/
int cdc_get_eventfd(CDC_MD *cdc_md)
{
    if(SWITCH_OFF == CAMD_SYNC_CDC_SWITCH
    && SWITCH_OFF == CDC_BIND_AIO_SWITCH)
    {
        if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
        {
            return caio_get_eventfd(CDC_MD_CAIO_MD(cdc_md));
        }
    }

    return (ERR_FD);
}

/*note: register eventfd and event handler to epoll READ event*/
EC_BOOL cdc_event_handler(CDC_MD *cdc_md)
{
    if(SWITCH_OFF == CAMD_SYNC_CDC_SWITCH
    && SWITCH_OFF == CDC_BIND_AIO_SWITCH)
    {
        if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
        {
            return caio_event_handler(CDC_MD_CAIO_MD(cdc_md));
        }
    }
    return (EC_TRUE);
}

/**
*
* try to quit cdc
*
**/
EC_BOOL cdc_try_quit(CDC_MD *cdc_md)
{
    UINT32 tree_idx;

    static UINT32  warning_counter = 0; /*suppress warning report*/

    cdc_process(cdc_md, CDC_DEGRADE_TRAFFIC_36MB, (REAL)0.0,
                CDC_READ_TRAFFIC_08MB, CDC_WRITE_TRAFFIC_08MB,
                CDC_READ_TRAFFIC_08MB, CDC_WRITE_TRAFFIC_08MB); /*process once*/

    tree_idx = 0;
    if(EC_TRUE == cdc_has_page(cdc_md, tree_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "page tree %ld# is not empty\n",
                                                tree_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    tree_idx = 1;
    if(EC_TRUE == cdc_has_page(cdc_md, tree_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "page tree %ld# is not empty\n",
                                                tree_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    if(EC_TRUE == cdc_has_event(cdc_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "has event yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    if(EC_TRUE == cdc_has_req(cdc_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "has req yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    warning_counter = 0;

    return (EC_TRUE);
}

EC_BOOL cdc_try_restart(CDC_MD *cdc_md)
{
    UINT32 tree_idx;

    static UINT32  warning_counter = 0; /*suppress warning report*/

    //cdc_process_no_degrade(cdc_md); /*process once*/

    CDC_MD_RESTART_FLAG(cdc_md) = BIT_TRUE; /*set restart flag*/

   if(EC_TRUE == cdc_has_locked_page(cdc_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "cdc has locked page\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    tree_idx = 0;
    if(EC_TRUE == cdc_has_wr_page(cdc_md, tree_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "page tree %ld# has wr page\n",
                                                tree_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    tree_idx = 1;
    if(EC_TRUE == cdc_has_wr_page(cdc_md, tree_idx))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "page tree %ld# has wr page\n",
                                                tree_idx);
        }

        warning_counter ++;

        return (EC_FALSE);
    }

#if 0
    if(EC_TRUE == cdc_has_event(cdc_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "has event yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }
#endif

    if(EC_TRUE == cdc_has_wr_req(cdc_md))
    {
        if(0 == (warning_counter % 1000))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_try_quit: "
                                                "has wr req yet\n");
        }

        warning_counter ++;

        return (EC_FALSE);
    }

    warning_counter = 0;

    return (EC_TRUE);
}

EC_BOOL cdc_set_read_only(CDC_MD *cdc_md)
{
    if(BIT_TRUE == CDC_MD_RDONLY_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_set_read_only: "
                                            "cdc is set already read-only\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        cdcnp_set_read_only(CDC_MD_NP(cdc_md));
    }

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        cdcdn_set_read_only(CDC_MD_DN(cdc_md));
    }

    CDC_MD_RDONLY_FLAG(cdc_md) = BIT_TRUE;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_set_read_only: "
                                        "set cdc read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdc_unset_read_only(CDC_MD *cdc_md)
{
    if(BIT_FALSE == CDC_MD_RDONLY_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_unset_read_only: "
                                            "cdc was not set read-only\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        cdcnp_unset_read_only(CDC_MD_NP(cdc_md));
    }

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        cdcdn_unset_read_only(CDC_MD_DN(cdc_md));
    }

    CDC_MD_RDONLY_FLAG(cdc_md) = BIT_FALSE;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_unset_read_only: "
                                        "unset cdc read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdc_is_read_only(const CDC_MD *cdc_md)
{
    if(BIT_FALSE == CDC_MD_RDONLY_FLAG(cdc_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_set_dontdump(CDC_MD *cdc_md)
{
    if(BIT_TRUE == CDC_MD_DONTDUMP_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_set_dontdump: "
                                            "cdc is set already read-only\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        cdcnp_set_dontdump(CDC_MD_NP(cdc_md));
    }

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        cdcdn_set_dontdump(CDC_MD_DN(cdc_md));
    }

    CDC_MD_DONTDUMP_FLAG(cdc_md) = BIT_TRUE;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_set_dontdump: "
                                        "set cdc read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdc_unset_dontdump(CDC_MD *cdc_md)
{
    if(BIT_FALSE == CDC_MD_DONTDUMP_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_unset_dontdump: "
                                            "cdc was not set read-only\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        cdcnp_unset_dontdump(CDC_MD_NP(cdc_md));
    }

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        cdcdn_unset_dontdump(CDC_MD_DN(cdc_md));
    }

    CDC_MD_DONTDUMP_FLAG(cdc_md) = BIT_FALSE;

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_unset_dontdump: "
                                        "unset cdc read-only\n");

    return (EC_TRUE);
}

EC_BOOL cdc_is_dontdump(const CDC_MD *cdc_md)
{
    if(BIT_FALSE == CDC_MD_DONTDUMP_FLAG(cdc_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}


/**
*
* flow control enable max speed
*
**/
EC_BOOL cdc_flow_control_enable_max_speed(CDC_MD *cdc_md)
{
    if(NULL_PTR != cdc_md)
    {
        CDC_MD_FC_MAX_SPEED_FLAG(cdc_md) = BIT_TRUE;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/**
*
* flow control disable max speed
*
**/
EC_BOOL cdc_flow_control_disable_max_speed(CDC_MD *cdc_md)
{
    if(NULL_PTR != cdc_md)
    {
        CDC_MD_FC_MAX_SPEED_FLAG(cdc_md) = BIT_FALSE;
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/**
 *
 *  note: traffic flow determined by both cdc used capacity and traffic speed
 *
 *  when cdc has enough capacity (< low ratio), do not control traffic flow as possible as we can.
 *  when cdc used capacity reaches high ratio, control traffic flow as traffic speed marked.
 *
 *  cdc traffic flow has 3 categories: 10Mbps, 20Mbps, 30Mbps, or 40Mbps per disk.
 *
 *  note: limit cdc degrade traffic <= 30Mbps
 *
 **/
STATIC_CAST static void __cdc_flow_control(const uint64_t ssd_traffic_bps, const REAL deg_ratio,
                                                uint64_t *degrade_traffic_bps)
{
    if(CDC_DEGRADE_LO_RATIO > deg_ratio)
    {
        if(ssd_traffic_bps >= CDC_DEGRADE_TRAFFIC_32MB)
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_16MB;
        }
        else
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_08MB;
        }
    }
    else if(CDC_DEGRADE_MD_RATIO > deg_ratio)
    {
        if(ssd_traffic_bps >= CDC_DEGRADE_TRAFFIC_32MB)
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_24MB;
        }
        else if(ssd_traffic_bps >= CDC_DEGRADE_TRAFFIC_24MB)
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_16MB;
        }
        else
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_08MB;
        }
    }
    else if(CDC_DEGRADE_HI_RATIO > deg_ratio)
    {
        if(ssd_traffic_bps >= CDC_DEGRADE_TRAFFIC_32MB)
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_32MB;
        }
        else if(ssd_traffic_bps >= CDC_DEGRADE_TRAFFIC_24MB)
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_16MB;
        }
        else
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_08MB;
        }
    }
    else
    {
        if(ssd_traffic_bps >= CDC_DEGRADE_TRAFFIC_32MB)
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_32MB;
        }
        else if(ssd_traffic_bps >= CDC_DEGRADE_TRAFFIC_24MB)
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_16MB;
        }
        else
        {
            (*degrade_traffic_bps) = CDC_DEGRADE_TRAFFIC_08MB;
        }
    }

    return;
}

/**
*
* process CDC
* 1, recycle deleted or retired space
* 2, process CAIO
*
**/
void cdc_process(CDC_MD *cdc_md, const uint64_t ssd_traffic_bps, const REAL ssd_hit_ratio,
                 const uint64_t amd_read_traffic_bps, const uint64_t amd_write_traffic_bps,
                 const uint64_t sata_read_traffic_bps, const uint64_t sata_write_traffic_bps)
{
    uint64_t    degrade_traffic_bps;

    UINT32      degrade_complete_num;
    UINT32      retire_complete_num;
    UINT32      recycle_complete_num;

    REAL        used_ratio;

    REAL        deg_ratio;
    uint32_t    deg_num;

    cdc_process_pages(cdc_md);
    cdc_process_events(cdc_md);
    cdc_process_reqs(cdc_md);

    used_ratio = cdc_used_ratio(cdc_md);

    deg_ratio  = cdc_deg_ratio(cdc_md);
    deg_num    = cdc_deg_num(cdc_md);

    degrade_complete_num = 0;
    retire_complete_num  = 0;
    recycle_complete_num = 0;

    __cdc_flow_control(ssd_traffic_bps,
                       deg_ratio,
                       &degrade_traffic_bps);

    if(BIT_TRUE == CDC_MD_FC_MAX_SPEED_FLAG(cdc_md))
    {
        /*override*/
        degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_36MB;
    }
    else
    {
        if(CDC_READ_TRAFFIC_08MB  >= amd_read_traffic_bps
        && CDC_WRITE_TRAFFIC_08MB >= amd_write_traffic_bps)
        {
            /*override*/
            degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_24MB;
        }
        else if(CDC_READ_TRAFFIC_12MB  >= amd_read_traffic_bps
             && CDC_WRITE_TRAFFIC_12MB >= amd_write_traffic_bps)
        {
            /*override*/
            degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_16MB;
        }
        else if(CDC_READ_TRAFFIC_16MB  <= sata_read_traffic_bps
             && CDC_WRITE_TRAFFIC_16MB <= sata_write_traffic_bps
             && CDC_DEGRADE_MD_RATIO  <= used_ratio
             && CDC_DEGRADE_LO_RATIO  >= deg_ratio
             && CDC_DEGRADE_TRAFFIC_08MB < degrade_traffic_bps)
        {
            /*override*/
            degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_08MB; /*speed down*/
        }
    }

    if(CDC_DEGRADE_HI_RATIO < used_ratio) /*high risk*/
    {
        if(CDC_DEGRADE_LO_RATIO >= deg_ratio)
        {
            /*override*/
            if(CDC_DEGRADE_TRAFFIC_08MB > degrade_traffic_bps)
            {
                degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_08MB;
            }
        }
        else if(CDC_DEGRADE_MD_RATIO >= deg_ratio)
        {
            /*override*/
            if(CDC_DEGRADE_TRAFFIC_16MB > degrade_traffic_bps)
            {
                degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_16MB;
            }
        }
        else if(CDC_DEGRADE_HI_RATIO >= deg_ratio)
        {
            /*override*/
            if(CDC_DEGRADE_TRAFFIC_24MB > degrade_traffic_bps)
            {
                degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_24MB;
            }
        }
        else
        {
            /*override*/
            if(CDC_DEGRADE_TRAFFIC_32MB > degrade_traffic_bps)
            {
                degrade_traffic_bps = CDC_DEGRADE_TRAFFIC_32MB;
            }
        }

    }

    cdc_process_degrades(cdc_md, degrade_traffic_bps,
                         (UINT32)CDC_SCAN_DEGRADE_MAX_NUM,
                         (UINT32)CDC_PROCESS_DEGRADE_MAX_NUM,
                         &degrade_complete_num);

    if(CDC_DEGRADE_HI_RATIO <= used_ratio)
    {
        cdc_retire(cdc_md, CDC_TRY_RETIRE_MAX_NUM << 2, &retire_complete_num);
    }
#if 0
    if(CDC_DEGRADE_HI_RATIO >= deg_ratio)
    {
        /*speed up retire*/
        if(CDC_READ_TRAFFIC_08MB  >= amd_read_traffic_bps
        && CDC_WRITE_TRAFFIC_08MB >= amd_write_traffic_bps)
        {
            cdc_retire(cdc_md, CDC_TRY_RETIRE_MAX_NUM << 2, &retire_complete_num);
        }
        else if(CDC_READ_TRAFFIC_12MB  >= amd_read_traffic_bps
             && CDC_WRITE_TRAFFIC_12MB >= amd_write_traffic_bps)
        {
            cdc_retire(cdc_md, CDC_TRY_RETIRE_MAX_NUM << 1, &retire_complete_num);
        }
        else if(CDC_READ_TRAFFIC_16MB  <= sata_read_traffic_bps
             && CDC_WRITE_TRAFFIC_16MB <= sata_write_traffic_bps
             && CDC_DEGRADE_MD_RATIO  <= used_ratio
             && CDC_DEGRADE_TRAFFIC_08MB < degrade_traffic_bps)
        {
            cdc_retire(cdc_md, CDC_TRY_RETIRE_MAX_NUM << 3, &retire_complete_num);
        }
    }
#endif
    cdc_recycle(cdc_md, CDC_TRY_RECYCLE_MAX_NUM, &recycle_complete_num);

    if(0 < degrade_complete_num
    || 0 < retire_complete_num
    || 0 < recycle_complete_num)
    {
        dbg_log(SEC_0182_CDC, 2)(LOGSTDOUT, "[DEBUG] cdc_process: "
                                            "used %.2f, r/w %ld/%ld MBps, hit %.2f, "
                                            "deg: %u, %.2f, %ld MBps, "
                                            "=> degrade %ld, retire %ld, recycle %ld\n",
                                            used_ratio,
                                            amd_read_traffic_bps >> 23,
                                            amd_write_traffic_bps >> 23,
                                            ssd_hit_ratio,
                                            deg_num,
                                            deg_ratio,
                                            degrade_traffic_bps >> 23,
                                            degrade_complete_num,
                                            retire_complete_num,
                                            recycle_complete_num);
    }

#if 0
    /*ignore caio process which is bound only*/

    if(SWITCH_OFF == CAMD_SYNC_CDC_SWITCH)
    {
        if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
        {
            caio_process(CDC_MD_CAIO_MD(cdc_md));
        }
    }
#endif
    return;
}

void cdc_process_no_degrade(CDC_MD *cdc_md)
{
    cdc_process_pages(cdc_md);
    cdc_process_events(cdc_md);
    cdc_process_reqs(cdc_md);

    if(EC_FALSE == cdc_is_read_only(cdc_md))
    {
        UINT32      retire_complete_num;
        UINT32      recycle_complete_num;

        REAL        used_ratio;

        REAL        deg_ratio;
        uint32_t    deg_num;

        used_ratio = cdc_used_ratio(cdc_md);

        deg_ratio  = cdc_deg_ratio(cdc_md);
        deg_num    = cdc_deg_num(cdc_md);

        retire_complete_num  = 0;
        recycle_complete_num = 0;

        cdc_retire(cdc_md, CDC_TRY_RETIRE_MAX_NUM, &retire_complete_num);

        cdc_recycle(cdc_md, CDC_TRY_RECYCLE_MAX_NUM, &recycle_complete_num);

        if(0 < retire_complete_num
        || 0 < recycle_complete_num)
        {
            dbg_log(SEC_0182_CDC, 2)(LOGSTDOUT, "[DEBUG] cdc_process_no_degrade: "
                                                "used %.2f, "
                                                "deg: %u, %.2f "
                                                "=> retire %ld, recycle %ld\n",
                                                used_ratio,
                                                deg_num,
                                                deg_ratio,
                                                retire_complete_num,
                                                recycle_complete_num);
        }
    }

    return;
}

/*for debug*/
EC_BOOL cdc_poll(CDC_MD *cdc_md)
{
    UINT32      degrade_complete_num;
    UINT32      retire_complete_num;
    UINT32      recycle_complete_num;

    cdc_process_pages(cdc_md);
    cdc_process_events(cdc_md);
    cdc_process_reqs(cdc_md);

    degrade_complete_num = 0;
    retire_complete_num  = 0;
    recycle_complete_num = 0;

    cdc_process_degrades(cdc_md, CDC_DEGRADE_TRAFFIC_32MB,
                         (UINT32)CDC_SCAN_DEGRADE_MAX_NUM,
                         (UINT32)CDC_PROCESS_DEGRADE_MAX_NUM,
                         &degrade_complete_num);

    //cdc_retire(cdc_md, retire_max_num, &retire_complete_num);

    cdc_recycle(cdc_md, CDC_TRY_RECYCLE_MAX_NUM, &recycle_complete_num);

    dbg_log(SEC_0182_CDC, 2)(LOGSTDOUT, "[DEBUG] cdc_poll: "
                                        "complete degrade %ld, retire %ld, recycle %ld\n",
                                        degrade_complete_num,
                                        retire_complete_num,
                                        recycle_complete_num);

    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        caio_poll(CDC_MD_CAIO_MD(cdc_md));
    }

    return (EC_TRUE);
}

/*for debug only!*/
EC_BOOL cdc_poll_debug(CDC_MD *cdc_md)
{
    cdc_process_pages(cdc_md);
    cdc_process_events(cdc_md);
    cdc_process_reqs(cdc_md);

    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        caio_poll(CDC_MD_CAIO_MD(cdc_md));
    }

    return (EC_TRUE);
}

/**
*
*  create name node
*
**/
EC_BOOL cdc_create_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset, const UINT32 key_max_num)
{
    CDCNP      *cdcnp;
    UINT32      size;
    uint8_t     np_model;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: np already exist\n");
        return (EC_FALSE);
    }

    size = e_offset - (*s_offset);

    if(CDCNP_PAGE_MAX_NUM < key_max_num)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: key num %ld overflow!\n",
                                            key_max_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_model_search(size, &np_model))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: size %ld => no matched np_model\n",
                                            size);
        return (EC_FALSE);
    }

    cdcnp = cdcnp_create((uint32_t)0/*cdcnp_id*/, (uint8_t)np_model,
                        (uint32_t)key_max_num, s_offset, e_offset);
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np: create np failed\n");
        return (EC_FALSE);
    }

    /*inherit from cdc module*/
    CDCNP_FD(cdcnp)             = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_NP(cdc_md)           = cdcnp;
    CDC_MD_SHM_NP_FLAG(cdc_md)  = BIT_FALSE;

    if(ERR_FD != CDC_MD_SATA_FD(cdc_md))
    {
        /*np inherit degrade callback from cdc module*/
        cdcnp_degrade_cb_clone(CDC_MD_NP_DEGRADE_CB(cdc_md), CDCNP_DEGRADE_CB(cdcnp));
    }

    return (EC_TRUE);
}

/**
*
*  create name node in shared memory
*
**/
EC_BOOL cdc_create_np_shm(CDC_MD *cdc_md, CMMAP_NODE *cmmap_node, UINT32 *s_offset, const UINT32 e_offset, const UINT32 key_max_num)
{
    CDCNP      *cdcnp;
    UINT32      size;
    uint8_t     np_model;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np_shm: np already exist\n");
        return (EC_FALSE);
    }

    size = e_offset - (*s_offset);

    if(CDCNP_PAGE_MAX_NUM < key_max_num)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np_shm: key num %ld overflow!\n",
                                            key_max_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_model_search(size, &np_model))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np_shm: size %ld => no matched np_model\n",
                                            size);
        return (EC_FALSE);
    }

    cdcnp = cdcnp_create_shm(cmmap_node, (uint32_t)0/*cdcnp_id*/, (uint8_t)np_model,
                        (uint32_t)key_max_num, s_offset, e_offset);
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_np_shm: create np failed\n");
        return (EC_FALSE);
    }

    /*inherit from cdc module*/
    CDCNP_FD(cdcnp)             = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_NP(cdc_md)           = cdcnp;
    CDC_MD_SHM_NP_FLAG(cdc_md)  = BIT_TRUE;

    if(ERR_FD != CDC_MD_SATA_FD(cdc_md))
    {
        /*np inherit degrade callback from cdc module*/
        cdcnp_degrade_cb_clone(CDC_MD_NP_DEGRADE_CB(cdc_md), CDCNP_DEGRADE_CB(cdcnp));
    }

    return (EC_TRUE);
}

/**
*
*  erase name node
*
**/
EC_BOOL cdc_erase_np(CDC_MD *cdc_md, const UINT32 s_offset, const UINT32 e_offset)
{
    if(EC_FALSE == cdcnp_erase(CDC_MD_NP(cdc_md), 0 /*np id*/, CDC_MD_SSD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_erase_np: load np failed\n");

        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_erase_np: load np done\n");

    return (EC_TRUE);
}

/**
*
*  close name node
*
**/
EC_BOOL cdc_close_np(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        if(BIT_TRUE == CDC_MD_SHM_NP_FLAG(cdc_md))
        {
            cdcnp_close(CDC_MD_NP(cdc_md));
        }
        else
        {
            cdcnp_free(CDC_MD_NP(cdc_md));
        }

        CDC_MD_NP(cdc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}

/**
*
*  load name node from disk
*
**/
EC_BOOL cdc_load_np(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP   *cdcnp;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np: np already exist\n");
        return (EC_FALSE);
    }

    cdcnp = cdcnp_new();
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np: new cdncp failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_load(cdcnp, 0 /*np id*/, CDC_MD_SSD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np: load np failed\n");

        cdcnp_free(cdcnp);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_reset(cdcnp))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np: reset np failed\n");

        cdcnp_free(cdcnp);
        return (EC_FALSE);
    }

    /*inherit caio from cdc*/
    CDCNP_FD(cdcnp)             = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_NP(cdc_md)           = cdcnp;/*bind*/
    CDC_MD_SHM_NP_FLAG(cdc_md)  = BIT_FALSE;

    if(ERR_FD != CDC_MD_SATA_FD(cdc_md))
    {
        /*np inherit degrade callback from cdc module*/
        cdcnp_degrade_cb_clone(CDC_MD_NP_DEGRADE_CB(cdc_md), CDCNP_DEGRADE_CB(cdcnp));
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_np: load np done\n");

    if(1)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_np: np %p is\n", cdcnp);
        cdcnp_print(LOGSTDOUT, cdcnp);
    }

    return (EC_TRUE);
}

/**
*
*  load name node from shared memory
*
**/
EC_BOOL cdc_load_np_shm(CDC_MD *cdc_md, CMMAP_NODE *cmmap_node, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP   *cdcnp;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_shm: np already exist\n");
        return (EC_FALSE);
    }

    cdcnp = cdcnp_new();
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_shm: new cdncp failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_load_shm(cdcnp, cmmap_node, 0 /*np id*/, CDC_MD_SSD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_shm: load np failed\n");

        cdcnp_close(cdcnp);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_reset(cdcnp))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_np_shm: reset np failed\n");

        cdcnp_close(cdcnp);
        return (EC_FALSE);
    }

    /*inherit caio from cdc*/
    CDCNP_FD(cdcnp)             = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_NP(cdc_md)           = cdcnp;/*bind*/
    CDC_MD_SHM_NP_FLAG(cdc_md)  = BIT_TRUE;

    if(ERR_FD != CDC_MD_SATA_FD(cdc_md))
    {
        /*np inherit degrade callback from cdc module*/
        cdcnp_degrade_cb_clone(CDC_MD_NP_DEGRADE_CB(cdc_md), CDCNP_DEGRADE_CB(cdcnp));
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_np_shm: load np done\n");

    return (EC_TRUE);
}

/**
*
*  retrieve name node from ssd
*
**/
EC_BOOL cdc_retrieve_np_shm(CDC_MD *cdc_md, CMMAP_NODE *cmmap_node, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCNP   *cdcnp;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_np_shm: np already exist\n");
        return (EC_FALSE);
    }

    cdcnp = cdcnp_new();
    if(NULL_PTR == cdcnp)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_np_shm: new cdncp failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_retrieve_shm(cdcnp, cmmap_node, 0 /*np id*/, CDC_MD_SSD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_np_shm: retrieve np failed\n");

        cdcnp_close(cdcnp);
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_reset(cdcnp))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_np_shm: reset np failed\n");

        cdcnp_close(cdcnp);
        return (EC_FALSE);
    }

    /*inherit caio from cdc*/
    CDCNP_FD(cdcnp)             = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_NP(cdc_md)           = cdcnp;/*bind*/
    CDC_MD_SHM_NP_FLAG(cdc_md)  = BIT_TRUE;

    if(ERR_FD != CDC_MD_SATA_FD(cdc_md))
    {
        /*np inherit degrade callback from cdc module*/
        cdcnp_degrade_cb_clone(CDC_MD_NP_DEGRADE_CB(cdc_md), CDCNP_DEGRADE_CB(cdcnp));
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_retrieve_np_shm: retrieve np done\n");

    return (EC_TRUE);
}

/**
*
*  flush name node to disk
*
**/
EC_BOOL cdc_flush_np(CDC_MD *cdc_md)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np: no np to flush\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_DONTDUMP_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np: "
                                            "asked not to flush\n");
        return (EC_FALSE);
    }

    if(BIT_FALSE == CDC_MD_SHM_NP_FLAG(cdc_md)
    || BIT_FALSE == CDC_MD_RESTART_FLAG(cdc_md))
    {
        if(EC_FALSE == cdcnp_flush(CDC_MD_NP(cdc_md)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_np: flush np failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_np: flush np done\n");
    }
    return (EC_TRUE);
}

/**
*
*  create data node
*
**/
EC_BOOL cdc_create_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN           *cdcdn;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_dn: dn already exist\n");
        return (EC_FALSE);
    }

    cdcdn = cdcdn_create(s_offset, e_offset);
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_dn: create dn failed\n");
        return (EC_FALSE);
    }

    /*inherit data from cdc module*/
    CDCDN_RDONLY_FLAG(cdcdn)    = CDC_MD_RDONLY_FLAG(cdc_md);
    CDCDN_DONTDUMP_FLAG(cdcdn)  = CDC_MD_DONTDUMP_FLAG(cdc_md);
    CDCDN_NODE_FD(cdcdn)        = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_DN(cdc_md)           = cdcdn;
    CDC_MD_SHM_DN_FLAG(cdc_md)  = BIT_FALSE;

    return (EC_TRUE);
}

/**
*
*  create data node in shared memory
*
**/
EC_BOOL cdc_create_dn_shm(CDC_MD *cdc_md, CMMAP_NODE *cmmap_node, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN           *cdcdn;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_dn_shm: dn already exist\n");
        return (EC_FALSE);
    }

    cdcdn = cdcdn_create_shm(cmmap_node, s_offset, e_offset);
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_create_dn_shm: create dn failed\n");
        return (EC_FALSE);
    }

    /*inherit data from cdc module*/
    CDCDN_RDONLY_FLAG(cdcdn)    = CDC_MD_RDONLY_FLAG(cdc_md);
    CDCDN_DONTDUMP_FLAG(cdcdn)  = CDC_MD_DONTDUMP_FLAG(cdc_md);
    CDCDN_NODE_FD(cdcdn)        = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_DN(cdc_md)           = cdcdn;
    CDC_MD_SHM_DN_FLAG(cdc_md)  = BIT_TRUE;

    return (EC_TRUE);
}


/**
*
*  load data node from disk
*
**/
EC_BOOL cdc_load_dn(CDC_MD *cdc_md, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN   *cdcdn;
    UINT32   f_s_offset;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn: dn already exist\n");
        return (EC_FALSE);
    }

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn: new dn failed\n");
        return (EC_FALSE);
    }

    f_s_offset = (*s_offset);/*save*/

    if(EC_FALSE == cdcdn_load(cdcdn, CDC_MD_SSD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn: "
                                            "load dn from fd %d, offset %ld failed\n",
                                            CDC_MD_SSD_FD(cdc_md), f_s_offset);

        cdcdn_free(cdcdn);
        return (EC_FALSE);
    }

    /*inherit from cdc*/
    CDCDN_RDONLY_FLAG(cdcdn)    = CDC_MD_RDONLY_FLAG(cdc_md);
    CDCDN_DONTDUMP_FLAG(cdcdn)  = CDC_MD_DONTDUMP_FLAG(cdc_md);
    CDCDN_NODE_FD(cdcdn)        = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_DN(cdc_md)           = cdcdn; /*bind*/
    CDC_MD_SHM_DN_FLAG(cdc_md)  = BIT_FALSE;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn: "
                                        "load dn from fd %d, offset %ld => %ld done\n",
                                        CDC_MD_SSD_FD(cdc_md), f_s_offset, (*s_offset));

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_dn: load dn done\n");

    if(1)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_load_dn: dn %p is\n", cdcdn);
        cdcdn_print(LOGSTDOUT, cdcdn);
    }

    return (EC_TRUE);
}

/**
*
*  load data node from shared memory
*
**/
EC_BOOL cdc_load_dn_shm(CDC_MD *cdc_md, CMMAP_NODE *cmmap_node, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN   *cdcdn;
    UINT32   f_s_offset;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_shm: dn already exist\n");
        return (EC_FALSE);
    }

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_shm: new dn failed\n");
        return (EC_FALSE);
    }

    f_s_offset = (*s_offset);/*save*/

    if(EC_FALSE == cdcdn_load_shm(cdcdn, cmmap_node, CDC_MD_SSD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_load_dn_shm: "
                                            "load dn from fd %d, offset %ld failed\n",
                                            CDC_MD_SSD_FD(cdc_md), f_s_offset);

        cdcdn_close(cdcdn);
        return (EC_FALSE);
    }

    /*inherit from cdc*/
    CDCDN_RDONLY_FLAG(cdcdn)    = CDC_MD_RDONLY_FLAG(cdc_md);
    CDCDN_DONTDUMP_FLAG(cdcdn)  = CDC_MD_DONTDUMP_FLAG(cdc_md);
    CDCDN_NODE_FD(cdcdn)        = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_DN(cdc_md)           = cdcdn; /*bind*/
    CDC_MD_SHM_DN_FLAG(cdc_md)  = BIT_TRUE;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn_shm: "
                                        "load dn from fd %d, offset %ld => %ld done\n",
                                        CDC_MD_SSD_FD(cdc_md), f_s_offset, (*s_offset));

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_load_dn_shm: load dn done\n");

    return (EC_TRUE);
}

/**
*
*  retrieve data node from ssd
*
**/
EC_BOOL cdc_retrieve_dn_shm(CDC_MD *cdc_md, CMMAP_NODE *cmmap_node, UINT32 *s_offset, const UINT32 e_offset)
{
    CDCDN   *cdcdn;
    UINT32   f_s_offset;

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_dn_shm: dn already exist\n");
        return (EC_FALSE);
    }

    cdcdn = cdcdn_new();
    if(NULL_PTR == cdcdn)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_dn_shm: new dn failed\n");
        return (EC_FALSE);
    }

    f_s_offset = (*s_offset);/*save*/

    if(EC_FALSE == cdcdn_retrieve_shm(cdcdn, cmmap_node, CDC_MD_SSD_FD(cdc_md), s_offset, e_offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_retrieve_dn_shm: "
                                            "load dn from fd %d, offset %ld failed\n",
                                            CDC_MD_SSD_FD(cdc_md), f_s_offset);

        cdcdn_close(cdcdn);
        return (EC_FALSE);
    }

    /*inherit from cdc*/
    CDCDN_RDONLY_FLAG(cdcdn)    = CDC_MD_RDONLY_FLAG(cdc_md);
    CDCDN_DONTDUMP_FLAG(cdcdn)  = CDC_MD_DONTDUMP_FLAG(cdc_md);
    CDCDN_NODE_FD(cdcdn)        = CDC_MD_SSD_FD(cdc_md);

    CDC_MD_DN(cdc_md)           = cdcdn; /*bind*/
    CDC_MD_SHM_DN_FLAG(cdc_md)  = BIT_TRUE;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_retrieve_dn_shm: "
                                        "load dn from fd %d, offset %ld => %ld done\n",
                                        CDC_MD_SSD_FD(cdc_md), f_s_offset, (*s_offset));

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_retrieve_dn_shm: load dn done\n");

    return (EC_TRUE);
}

/**
*
*  flush data node to disk
*
**/
EC_BOOL cdc_flush_dn(CDC_MD *cdc_md)
{
    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_dn: no dn to flush\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_MD_DONTDUMP_FLAG(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_dn: "
                                            "asked not to flush\n");
        return (EC_FALSE);
    }

    if(BIT_FALSE == CDC_MD_SHM_DN_FLAG(cdc_md)
    || BIT_FALSE == CDC_MD_RESTART_FLAG(cdc_md))
    {
        CDCDN       *cdcdn;

        cdcdn = CDC_MD_DN(cdc_md);

        if(EC_FALSE == cdcdn_flush(cdcdn))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_flush_dn: flush dn failed\n");
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_flush_dn: flush dn done\n");
    }

    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL cdc_close_dn(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        if(BIT_TRUE == CDC_MD_SHM_DN_FLAG(cdc_md) )
        {
            cdcdn_close(CDC_MD_DN(cdc_md));
        }
        else
        {
            cdcdn_free(CDC_MD_DN(cdc_md));
        }
        CDC_MD_DN(cdc_md) = NULL_PTR;
    }

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __cdc_reserve_hash_dn(CDC_MD *cdc_md, const UINT32 data_len, const uint32_t path_hash, CDCNP_FNODE *cdcnp_fnode)
{
    CDCNP_INODE *cdcnp_inode;
    CDCPGV      *cdcpgv;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint16_t fail_tries;

    if(CDCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: "
                                            "data_len %ld overflow\n",
                                            data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDCDN_CDCPGV(CDC_MD_DN(cdc_md)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cdcpgv = CDCDN_CDCPGV(CDC_MD_DN(cdc_md));
    if(NULL_PTR == CDCPGV_HEADER(cdcpgv))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCPGV_PAGE_DISK_NUM(cdcpgv))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: pgv has no disk yet\n");
        return (EC_FALSE);
    }

    fail_tries = 0;
    for(;;)
    {
        size    = (uint32_t)(data_len);
        disk_no = (uint16_t)(path_hash % CDCPGV_PAGE_DISK_NUM(cdcpgv));

        if(EC_TRUE == cdcpgv_new_space_from_disk(cdcpgv, size, disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        /*try again*/
        if(EC_TRUE == cdcpgv_new_space(cdcpgv, size, &disk_no, &block_no, &page_no))
        {
            break;/*fall through*/
        }

        fail_tries ++;

        if(1 < fail_tries) /*try once only*/
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_hash_dn: "
                                                "new %ld bytes space from vol failed\n",
                                                data_len);
            return (EC_FALSE);
        }

        /*try to retire & recycle some files*/
        dbg_log(SEC_0182_CDC, 7)(LOGSTDOUT, "warn:__cdc_reserve_hash_dn: "
                                            "no %ld bytes space, try to retire & recycle\n",
                                            data_len);
        cdc_retire(cdc_md, (UINT32)CDC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cdc_recycle(cdc_md, (UINT32)CDC_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == size);

    cdcnp_fnode_init(cdcnp_fnode);
    CDCNP_FNODE_PAGENUM(cdcnp_fnode) = (uint16_t)(size >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_FNODE_REPNUM(cdcnp_fnode)  = 1;

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    CDCNP_INODE_DISK_NO(cdcnp_inode)    = disk_no;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = block_no;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL cdc_reserve_dn(CDC_MD *cdc_md, const UINT32 data_len, CDCNP_FNODE *cdcnp_fnode)
{
    CDCNP_INODE *cdcnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(CDCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    if(EC_FALSE == cdcpgv_new_space(CDCDN_CDCPGV(CDC_MD_DN(cdc_md)), size, &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_dn: new %ld bytes space from vol failed\n", data_len);
        return (EC_FALSE);
    }

    CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == size);

    cdcnp_fnode_init(cdcnp_fnode);
    CDCNP_FNODE_PAGENUM(cdcnp_fnode) = (uint16_t)(size >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_FNODE_REPNUM(cdcnp_fnode)  = 1;

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    CDCNP_INODE_DISK_NO(cdcnp_inode)    = disk_no;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = block_no;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  release space to dn
*
**/
EC_BOOL cdc_release_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_release_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

    CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == file_size);

    if(CDCPGB_SIZE_NBYTES < file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_release_dn: file_size %u overflow\n", file_size);
        return (EC_FALSE);
    }

    /*refer cdc_page_write: when file size is zero, only reserve np but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_release_dn: file_size is zero\n");
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    if(EC_FALSE == cdcpgv_free_space(CDCDN_CDCPGV(CDC_MD_DN(cdc_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_release_dn: "
                            "free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_release_dn: "
                       "remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  reserve a fnode from name node
*
**/
STATIC_CAST static CDCNP_ITEM * __cdc_reserve_np(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, uint32_t *cdcnp_item_pos)
{
    CDCNP_ITEM  *cdcnp_item;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_np: np was not open\n");
        return (NULL_PTR);
    }

    if(EC_TRUE == cdcnp_is_full(CDC_MD_NP(cdc_md)))
    {
        /*try to retire & recycle some files*/
        dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "warn:__cdc_reserve_np: "
                                            "no name node accept key, try to retire & recycle\n");
        cdc_retire(cdc_md, (UINT32)CDC_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cdc_recycle(cdc_md, (UINT32)CDC_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    cdcnp_item = cdcnp_reserve(CDC_MD_NP(cdc_md), cdcnp_key, cdcnp_item_pos);
    if(NULL_PTR != cdcnp_item) /*succ*/
    {
        return (cdcnp_item);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_np: no name node accept key => retire & recycle\n");

    cdc_retire(cdc_md, (UINT32)CDC_TRY_RETIRE_MAX_NUM, NULL_PTR);
    cdc_recycle(cdc_md, (UINT32)CDC_TRY_RECYCLE_MAX_NUM, NULL_PTR);

    /*retry*/
    cdcnp_item = cdcnp_reserve(CDC_MD_NP(cdc_md), cdcnp_key, cdcnp_item_pos);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_reserve_np: no name node accept key\n");
        return (NULL_PTR);
    }

    return (cdcnp_item);
}


/**
*
*  release a fnode from name node
*
**/
STATIC_CAST static EC_BOOL __cdc_release_np(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_release_np: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_release(CDC_MD_NP(cdc_md), cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:__cdc_release_np: release key from np failed\n");
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  find item
*
**/
CDCNP_ITEM *cdc_find(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    uint32_t          node_pos;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_find: np was not open\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 7)(LOGSTDOUT, "warn:cdc_find: miss key [%u, %u)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (NULL_PTR);
    }

    node_pos = cdcnp_search(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS == node_pos)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_find: search failed\n");
        return (NULL_PTR);
    }

    return cdcnp_fetch(CDC_MD_NP(cdc_md), node_pos);
}

/**
*
*  read a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_read(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    s_offset = (*offset);
    e_offset = (*offset) + rsize;
    m_buff   = buff;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_read: "
                                        "offset %ld, rsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), rsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES        cbytes;

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(&cdcnp_key) = s_page + 1;

        if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
        {
            dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_file_read: ssd miss page %ld\n",
                            s_page);
            break;
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_read: ssd hit page %ld\n",
                        s_page);

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, ((UINT32)CDCPGB_PAGE_SIZE_NBYTES) - offset_t);

        CBYTES_BUF(&cbytes) = m_buff;
        CBYTES_LEN(&cbytes) = e_offset - s_offset;

        if(EC_FALSE == cdc_page_read_e(cdc_md, &cdcnp_key, &offset_t, max_len, &cbytes))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_read: "
                            "read page %ld, offset %ld, len %ld failed\n",
                            s_page, (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK)), max_len);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_read: "
                        "read page %ld => offset %ld, len %ld\n",
                        s_page, offset_t, CBYTES_LEN(&cbytes));

        CDC_ASSERT(CBYTES_BUF(&cbytes) == m_buff);

        s_offset += CBYTES_LEN(&cbytes);
        m_buff   += CBYTES_LEN(&cbytes);
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  write a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_write(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;
    UINT8      *m_buff;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_file_write: cdc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + wsize;
    m_buff   = buff;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/
        CBYTES        cbytes;

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(&cdcnp_key) = s_page + 1;

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, ((UINT32)CDCPGB_PAGE_SIZE_NBYTES) - offset_t);

        CBYTES_BUF(&cbytes) = m_buff;
        CBYTES_LEN(&cbytes) = max_len;

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || ((UINT32)CDCPGB_PAGE_SIZE_NBYTES) != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdc_page_write_e(cdc_md, &cdcnp_key, &offset_t, max_len, &cbytes))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "override page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                            "override page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            if(EC_FALSE == cdc_page_write(cdc_md, &cdcnp_key, &cbytes))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write: "
                                "write page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write: "
                            "write page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        CDC_ASSERT(CBYTES_BUF(&cbytes) == m_buff);

        s_offset += CBYTES_LEN(&cbytes);
        m_buff   += CBYTES_LEN(&cbytes);
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  delete a file (POSIX style interface)
*
**/
EC_BOOL cdc_file_delete(CDC_MD *cdc_md, UINT32 *offset, const UINT32 dsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_file_delete: cdc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + dsize;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                        "offset %ld, dsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), dsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = s_page;
        CDCNP_KEY_E_PAGE(&cdcnp_key) = s_page + 1;

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, ((UINT32)CDCPGB_PAGE_SIZE_NBYTES) - offset_t);

        /*skip non-existence*/
        if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
        {
            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                            "page %ld absent, [%ld, %ld), offset %ld, len %ld in page\n",
                            s_page,
                            s_offset, e_offset,
                            offset_t, max_len);
            s_offset += max_len;
            continue;
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                        "ssd hit page %ld, [%ld, %ld), offset %ld, len %ld in page\n",
                        s_page,
                        s_offset, e_offset,
                        offset_t, max_len);

        /*when partial delete, need the whole page exists*/
        if(0 < offset_t || ((UINT32)CDCPGB_PAGE_SIZE_NBYTES) != max_len)
        {
            CDCNP_FNODE   cdcnp_fnode;
            UINT32        file_size;

            cdcnp_fnode_init(&cdcnp_fnode);

            /*found inconsistency*/
            if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), &cdcnp_key, &cdcnp_fnode))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                "read page %ld failed, "
                                "[%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
                return (EC_FALSE);
            }

            file_size   = (UINT32)(((UINT32)CDCNP_FNODE_PAGENUM(&cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);

            if(file_size > offset_t + max_len)
            {
                /*do nothing*/
                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "ignore page %ld "
                                "(file size %ld > %ld + %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t, max_len,
                                s_offset, e_offset,
                                offset_t, max_len);
            }

            else if (file_size <= offset_t)
            {
                /*do nothing*/
                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "ignore page %ld "
                                "(file size %ld <= %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t,
                                s_offset, e_offset,
                                offset_t, max_len);
            }

            /*now: offset_t < file_size <= offset_t + max_len*/

            else if(0 == offset_t)
            {
                if(EC_FALSE == cdc_page_delete(cdc_md, &cdcnp_key))
                {
                    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                    "delete page %ld failed, "
                                    "[%ld, %ld), offset %ld, len %ld in page\n",
                                    s_page,
                                    s_offset, e_offset,
                                    offset_t, max_len);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "delete page %ld done, "
                                "[%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
            }
            else
            {
                CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == (uint32_t)offset_t);
                CDCNP_FNODE_PAGENUM(&cdcnp_fnode) = (uint16_t)((uint32_t)offset_t >> CDCPGB_PAGE_SIZE_NBITS);

                if(EC_FALSE == cdcnp_update(CDC_MD_NP(cdc_md), &cdcnp_key, &cdcnp_fnode))
                {
                    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                    "update page %ld failed "
                                    "(file size %ld => %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                    s_page,
                                    file_size, offset_t,
                                    s_offset, e_offset,
                                    offset_t, max_len);
                    return (EC_FALSE);
                }

                dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                                "update page %ld done "
                                "(file size %ld => %ld), [%ld, %ld), offset %ld, len %ld in page\n",
                                s_page,
                                file_size, offset_t,
                                s_offset, e_offset,
                                offset_t, max_len);
            }
        }

        else
        {
            if(EC_FALSE == cdc_page_delete(cdc_md, &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_delete: "
                                "delete page %ld failed, [%ld, %ld), offset %ld, len %ld\n",
                                s_page,
                                s_offset, e_offset,
                                offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_delete: "
                            "delete page %ld done, [%ld, %ld), offset %ld, len %ld\n",
                            s_page,
                            s_offset, e_offset,
                            offset_t, max_len);
        }

        s_offset += max_len;
    }

    (*offset) = s_offset;

    return (EC_TRUE);
}

/**
*
*  set file ssd dirty flag which means cdc should flush it to sata later
*
**/
EC_BOOL cdc_file_set_sata_dirty(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_file_set_sata_dirty: cdc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + wsize;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_dirty: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(s_page + 0);
        CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(s_page + 1);

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CDCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_dirty: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdcnp_set_sata_dirty(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_dirty: "
                                "set sata dirty flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_dirty: "
                            "set sata dirty flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_dirty: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdcnp_set_sata_dirty(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_dirty: "
                                "set sata dirty flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_dirty: "
                            "set sata dirty flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        s_offset += max_len;
        (*offset) = s_offset;
    }

    return (EC_TRUE);
}

/**
*
*  set file sata flushed flag which means cdc should not flush it to sata
*
**/
EC_BOOL cdc_file_set_sata_flushed(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_file_set_sata_flushed: cdc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + wsize;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_flushed: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(s_page + 0);
        CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(s_page + 1);

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CDCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_flushed: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdcnp_set_sata_flushed(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_flushed: "
                                "set sata flush flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_flushed: "
                            "set sata flush flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_flushed: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdcnp_set_sata_flushed(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_flushed: "
                                "set sata flush flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_flushed: "
                            "set sata flush flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        s_offset += max_len;
        (*offset) = s_offset;
    }

    return (EC_TRUE);
}

/**
*
*  set file sata not flushed flag which means cdc should flush it to sata later
*
**/
EC_BOOL cdc_file_set_sata_not_flushed(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize)
{
    UINT32      s_offset;
    UINT32      e_offset;
    UINT32      s_page;
    UINT32      e_page;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_file_set_sata_not_flushed: cdc is read-only\n");
        return (EC_FALSE);
    }

    s_offset = (*offset);
    e_offset = (*offset) + wsize;

    s_page   = (s_offset >> CDCPGB_PAGE_SIZE_NBITS);
    e_page   = ((e_offset + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_not_flushed: "
                                        "offset %ld, wsize %ld => offset [%ld, %ld) => page [%ld, %ld)\n",
                                        (*offset), wsize,
                                        s_offset, e_offset,
                                        s_page, e_page);

    for(; s_page < e_page; s_page ++)
    {
        CDCNP_KEY     cdcnp_key;
        UINT32        offset_t; /*offset in page*/
        UINT32        max_len;  /*max len in page*/

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(s_page + 0);
        CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(s_page + 1);

        offset_t = (s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK));
        max_len  = DMIN(e_offset - s_offset, CDCPGB_PAGE_SIZE_NBYTES - offset_t);

        /*when partial override, need  the whole page exists*/
        if(0 < offset_t || CDCPGB_PAGE_SIZE_NBYTES != max_len)
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_not_flushed: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdcnp_set_sata_not_flushed(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_not_flushed: "
                                "set sata not flush flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_not_flushed: "
                            "set sata not flush flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }
        else
        {
            /*check existing*/
            if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_not_flushed: "
                                "page %ld absent, offset %ld (%ld in page), len %ld\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            if(EC_FALSE == cdcnp_set_sata_not_flushed(CDC_MD_NP(cdc_md), &cdcnp_key))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_set_sata_not_flushed: "
                                "set sata not flush flag of page %ld, offset %ld (%ld in page), len %ld failed\n",
                                s_page, s_offset, offset_t, max_len);
                return (EC_FALSE);
            }

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_set_sata_not_flushed: "
                            "set sata not flush flag of page %ld, offset %ld (%ld in page), len %ld done\n",
                            s_page, s_offset, offset_t, max_len);
        }

        s_offset += max_len;
        (*offset) = s_offset;
    }

    return (EC_TRUE);
}

/**
*
*  reserve a page
*
**/
EC_BOOL cdc_page_reserve(CDC_MD *cdc_md, CDC_PAGE *cdc_page, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ITEM   *cdcnp_item;
    CDCNP_FNODE  *cdcnp_fnode;

    UINT32        page_num;
    UINT32        data_len;
    uint32_t      path_hash;

    uint32_t      cdcnp_item_pos;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_reserve: cdc is read-only\n");
        return (EC_FALSE);
    }

    cdcnp_item = __cdc_reserve_np(cdc_md, cdcnp_key, &cdcnp_item_pos);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_reserve: reserve np failed\n");

        return (EC_FALSE);
    }
    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);

    path_hash = cdcnp_key_hash(cdcnp_key);

    /*note: when reserve space from data node, the length depends on cdcnp_key but not cbytes*/
    page_num  = (CDCNP_KEY_E_PAGE(cdcnp_key) - CDCNP_KEY_S_PAGE(cdcnp_key));
    data_len  = (page_num << CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == data_len);

    /*when fnode is duplicate, do not reserve data node anymore*/
    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        for(;;)
        {
            CDCNP_INODE     *cdcnp_inode;
            UINT32           d_s_offset;
            uint32_t         page_no;

            if(EC_FALSE == __cdc_reserve_hash_dn(cdc_md, data_len, path_hash, cdcnp_fnode))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_reserve: reserve dn %ld bytes failed\n",
                                data_len);

                __cdc_release_np(cdc_md, cdcnp_key);

                return (EC_FALSE);
            }

            /*check bad page*/

            cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

            d_s_offset = cdcdn_node_locate(CDC_MD_DN(cdc_md),
                                    CDCNP_INODE_DISK_NO(cdcnp_inode),
                                    CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                    CDCNP_INODE_PAGE_NO(cdcnp_inode));
            if(CDCDN_NODE_ERR_OFFSET == d_s_offset)
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_reserve: "
                                                    "locate (disk %u, block %u, page %u) failed\n",
                                                    CDCNP_INODE_DISK_NO(cdcnp_inode),
                                                    CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                                    CDCNP_INODE_PAGE_NO(cdcnp_inode));
                __cdc_release_np(cdc_md, cdcnp_key);
                return (EC_FALSE);
            }

            CDC_ASSERT(0 == (d_s_offset & CDCPGB_PAGE_SIZE_MASK));

            page_no = (uint32_t)(d_s_offset >> CDCPGB_PAGE_SIZE_NBITS);

            if(EC_FALSE == cdc_is_ssd_bad_page(cdc_md, page_no))/*not bad page*/
            {
                dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "[DEBUG] cdc_page_reserve: "
                                                    "reserve ssd page [%ld, %ld), page no %u\n",
                                                    d_s_offset,
                                                    d_s_offset + CDCPGB_PAGE_SIZE_NBYTES,
                                                    page_no);
                /*terminate*/
                break;
            }

            /*note: keep bad page reserved but not use it*/

            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_reserve: "
                                                "reserve ssd bad page [%ld, %ld), page no %u\n",
                                                d_s_offset,
                                                d_s_offset + CDCPGB_PAGE_SIZE_NBYTES,
                                                page_no);
        }
    }
    else
    {
        /*when fnode is duplicate, update file size*/
        CDCNP_FNODE_PAGENUM(cdcnp_fnode) = (uint16_t)(data_len >> CDCPGB_PAGE_SIZE_NBITS);
    }

    CDC_PAGE_CDCNP_ITEM(cdc_page)     = cdcnp_item;
    CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = cdcnp_item_pos;

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_reserve: write to dn where fnode is \n");
        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
    }

    return (EC_TRUE);
}

/**
*
*  release a page
*
**/
EC_BOOL cdc_page_release(CDC_MD *cdc_md, CDC_PAGE *cdc_page, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ITEM   *cdcnp_item;
    CDCNP_FNODE  *cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_release: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_PAGE_CDCNP_ITEM(cdc_page))
    {
        uint32_t        cdcnp_item_pos;

        cdcnp_item = cdcnp_get(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG, &cdcnp_item_pos);
        if(NULL_PTR == cdcnp_item)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_release: "
                                                "np has no key [%u, %u)\n",
                                                CDCNP_KEY_S_PAGE(cdcnp_key),
                                                CDCNP_KEY_E_PAGE(cdcnp_key));

            return (EC_FALSE);
        }

        CDC_PAGE_CDCNP_ITEM(cdc_page)     = cdcnp_item;
        CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = cdcnp_item_pos;
    }
    else
    {
        cdcnp_item = CDC_PAGE_CDCNP_ITEM(cdc_page);
    }

    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);

    if(EC_FALSE == cdc_release_dn(cdc_md, cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_release: "
                                            "release dn of key [%u, %u) failed, where fnode is\n",
                                            CDCNP_KEY_S_PAGE(cdcnp_key),
                                            CDCNP_KEY_E_PAGE(cdcnp_key));

        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        return (EC_FALSE);
    }

    if(EC_FALSE == __cdc_release_np(cdc_md, cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_release: "
                                            "release np of key [%u, %u) failed, where fnode is\n",
                                            CDCNP_KEY_S_PAGE(cdcnp_key),
                                            CDCNP_KEY_E_PAGE(cdcnp_key));

        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        return (EC_FALSE);
    }

    CDC_PAGE_D_S_OFFSET(cdc_page)     = CDC_ERR_OFFSET;
    CDC_PAGE_D_E_OFFSET(cdc_page)     = CDC_ERR_OFFSET;
    CDC_PAGE_CDCNP_ITEM(cdc_page)     = NULL_PTR;
    CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = CDCNPRB_ERR_POS;

    return (EC_TRUE);
}

/**
*
*  discard a page (note: mark a ssd page as bad page)
*
*  release np but NOT release dn, thus dn would not be accessed again.
*
*
**/
EC_BOOL cdc_page_discard(CDC_MD *cdc_md, CDC_PAGE *cdc_page, const CDCNP_KEY *cdcnp_key)
{
    CDCNP_ITEM   *cdcnp_item;
    CDCNP_FNODE  *cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_discard: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_PAGE_CDCNP_ITEM(cdc_page))
    {
        uint32_t        cdcnp_item_pos;

        cdcnp_item = cdcnp_get(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG, &cdcnp_item_pos);
        if(NULL_PTR == cdcnp_item)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_discard: "
                                                "np has no key [%u, %u)\n",
                                                CDCNP_KEY_S_PAGE(cdcnp_key),
                                                CDCNP_KEY_E_PAGE(cdcnp_key));

            return (EC_FALSE);
        }

        CDC_PAGE_CDCNP_ITEM(cdc_page)     = cdcnp_item;
        CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = cdcnp_item_pos;
    }
    else
    {
        cdcnp_item = CDC_PAGE_CDCNP_ITEM(cdc_page);
    }

    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);

#if 0
    if(EC_FALSE == cdc_release_dn(cdc_md, cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_discard: "
                                            "release dn of key [%u, %u) failed, where fnode is\n",
                                            CDCNP_KEY_S_PAGE(cdcnp_key),
                                            CDCNP_KEY_E_PAGE(cdcnp_key));

        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        return (EC_FALSE);
    }
#endif

    if(EC_FALSE == __cdc_release_np(cdc_md, cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_discard: "
                                            "release np of key [%u, %u) failed, where fnode is\n",
                                            CDCNP_KEY_S_PAGE(cdcnp_key),
                                            CDCNP_KEY_E_PAGE(cdcnp_key));

        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        return (EC_FALSE);
    }

    if(1)
    {
        uint32_t    ssd_page_no;

        /*set ssd bad page*/
        ssd_page_no = (CDC_PAGE_D_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
        if(EC_FALSE == cdc_set_ssd_bad_page(cdc_md, ssd_page_no))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_discard: "
                            "set ssd bad page [%ld, %ld), page no %u failed\n",
                            CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                            ssd_page_no);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_discard: "
                        "set ssd bad page [%ld, %ld), page no %u done\n",
                        CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                        ssd_page_no);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "warn:cdc_page_discard: "
                                        "discard [%ld, %ld)\n",
                                        CDC_PAGE_D_S_OFFSET(cdc_page),
                                        CDC_PAGE_D_E_OFFSET(cdc_page));

    CDC_PAGE_D_S_OFFSET(cdc_page)     = CDC_ERR_OFFSET;
    CDC_PAGE_D_E_OFFSET(cdc_page)     = CDC_ERR_OFFSET;
    CDC_PAGE_CDCNP_ITEM(cdc_page)     = NULL_PTR;
    CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = CDCNPRB_ERR_POS;

    return (EC_TRUE);
}

/**
*
*  write a page
*
**/
EC_BOOL cdc_page_write(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes)
{
    CDCNP_ITEM   *cdcnp_item;
    CDCNP_FNODE  *cdcnp_fnode;

    UINT32        page_num;
    UINT32        space_len;
    UINT32        data_len;
    uint32_t      path_hash;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_write: cdc is read-only\n");
        return (EC_FALSE);
    }

    cdcnp_item = __cdc_reserve_np(cdc_md, cdcnp_key, NULL_PTR);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write: reserve np failed\n");

        return (EC_FALSE);
    }
    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);

    path_hash = cdcnp_key_hash(cdcnp_key);

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cdcnp_fnode_init(cdcnp_fnode);

        if(do_log(SEC_0182_CDC, 1))
        {
            sys_log(LOGSTDOUT, "warn:cdc_page_write: write with zero len to dn where fnode is \n");
            cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
        }

        return (EC_TRUE);
    }

    /*note: when reserve space from data node, the length depends on cdcnp_key but not cbytes*/
    page_num  = (CDCNP_KEY_E_PAGE(cdcnp_key) - CDCNP_KEY_S_PAGE(cdcnp_key));
    space_len = (page_num << CDCPGB_PAGE_SIZE_NBITS);
    data_len  = DMIN(space_len, CBYTES_LEN(cbytes));/*xxx*/

    CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == data_len);

    /*when fnode is duplicate, do not reserve data node anymore*/
    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        if(EC_FALSE == __cdc_reserve_hash_dn(cdc_md, data_len, path_hash, cdcnp_fnode))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write: reserve dn %ld bytes failed\n",
                            data_len);

            __cdc_release_np(cdc_md, cdcnp_key);

            return (EC_FALSE);
        }
    }
    else
    {
        /*when fnode is duplicate, update file size*/
        CDCNP_FNODE_PAGENUM(cdcnp_fnode) = (uint16_t)(data_len >> CDCPGB_PAGE_SIZE_NBITS);
    }

    if(EC_FALSE == cdc_export_dn(cdc_md, cbytes, cdcnp_fnode))
    {
        cdc_release_dn(cdc_md, cdcnp_fnode);

        __cdc_release_np(cdc_md, cdcnp_key);

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write: export content to dn failed\n");

        return (EC_FALSE);
    }

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_write: write to dn where fnode is \n");
        cdcnp_fnode_print(LOGSTDOUT, cdcnp_fnode);
    }

    return (EC_TRUE);
}

/**
*
*  read a page
*
**/
EC_BOOL cdc_page_read(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, CBYTES *cbytes)
{
    CDCNP_FNODE   cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_read: read start\n");

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read: read from np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_read: read from np done\n");

    /*exception*/
    if(0 == CDCNP_FNODE_PAGENUM(&cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read: read with zero len from np and fnode %p is \n", &cdcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cdc_read_dn(cdc_md, &cdcnp_fnode, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read: read from dn failed where fnode is \n");
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        return (EC_FALSE);
    }

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_read: read with size %ld done\n",
                            cbytes_len(cbytes));
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
    }
    return (EC_TRUE);
}

/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a page at offset
*
**/
EC_BOOL cdc_page_write_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CDCNP_FNODE   cdcnp_fnode;
    uint16_t      file_old_page_num;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_write_e: cdc is read-only\n");
        return (EC_FALSE);
    }

    cdcnp_fnode_init(&cdcnp_fnode);

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e: read from np failed\n");
        return (EC_FALSE);
    }

    file_old_page_num = CDCNP_FNODE_PAGENUM(&cdcnp_fnode);

    if(EC_FALSE == cdc_write_e_dn(cdc_md, &cdcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e: offset write to dn failed\n");
        return (EC_FALSE);
    }

    if(file_old_page_num != CDCNP_FNODE_PAGENUM(&cdcnp_fnode))
    {
        if(EC_FALSE == cdcnp_update(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_write_e: offset write to np failed\n");
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
*  read a page from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL cdc_page_read_e(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CDCNP_FNODE   cdcnp_fnode;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    cdcnp_fnode_init(&cdcnp_fnode);

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, &cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_e: read from np failed\n");
        return (EC_FALSE);
    }

    if(do_log(SEC_0182_CDC, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cdc_page_read_e: read from np and fnode %p is \n",
                           &cdcnp_fnode);
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
    }

    /*exception*/
    if(0 == CDCNP_FNODE_PAGENUM(&cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_read_e: read with zero len from np and fnode %p is \n", &cdcnp_fnode);
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cdc_read_e_dn(cdc_md, &cdcnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_e: offset read from dn failed where fnode is\n");
        cdcnp_fnode_print(LOGSTDOUT, &cdcnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL cdc_export_dn(CDC_MD *cdc_md, const CBYTES *cbytes, const CDCNP_FNODE *cdcnp_fnode)
{
    const CDCNP_INODE *cdcnp_inode;

    UINT32   file_size;
    UINT32   offset;
    UINT32   data_len;
    //uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_export_dn: cdc is read-only\n");
        return (EC_FALSE);
    }

    file_size = (((UINT32)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);
    data_len = DMIN(CBYTES_LEN(cbytes), file_size);
    CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == data_len);

    if(CDCPGB_SIZE_NBYTES <= data_len)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn: CBYTES_LEN %u or CDCNP_FNODE_PAGENUM %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CDCNP_FNODE_PAGENUM(cdcnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    //size = (uint32_t)data_len;

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CDCPGB_PAGE_SIZE_NBITS));
    if(EC_FALSE == cdcdn_write_o(CDC_MD_DN(cdc_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_export_dn: write %ld bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_export_dn: write %ld bytes to disk %u block %u page %u done\n",
                        data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL cdc_write_dn(CDC_MD *cdc_md, const CBYTES *cbytes, CDCNP_FNODE *cdcnp_fnode)
{
    CDCNP_INODE *cdcnp_inode;
    UINT32   data_len;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_write_dn: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn: no dn was open\n");
        return (EC_FALSE);
    }

    cdcnp_fnode_init(cdcnp_fnode);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

    if(EC_FALSE == cdcdn_write_p(CDC_MD_DN(cdc_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CDCNP_INODE_DISK_NO(cdcnp_inode)    = disk_no;
    CDCNP_INODE_BLOCK_NO(cdcnp_inode)   = block_no;
    CDCNP_INODE_PAGE_NO(cdcnp_inode)    = page_no;

    data_len = CBYTES_LEN(cbytes);
    CDC_ASSERT(CDCPGB_PAGE_SIZE_NBYTES == data_len);

    CDCNP_FNODE_PAGENUM(cdcnp_fnode) = (uint16_t)(data_len >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_FNODE_REPNUM(cdcnp_fnode)  = 1;

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL cdc_read_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, CBYTES *cbytes)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    //dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

#if 0
    if(0 == CBYTES_LEN(cbytes))/*scenario: cbytes is not initialized*/
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CDC_0005);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CDC_0006);
        CBYTES_LEN(cbytes) = 0;
    }

    else if(CBYTES_LEN(cbytes) < (UINT32)file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: cbytes len %ld < file size %ld\n",
                        CBYTES_LEN(cbytes), (UINT32)file_size);
        return (EC_FALSE);
    }
#endif
#if 1
    CDC_ASSERT(0 < CBYTES_LEN(cbytes));

    if(CBYTES_LEN(cbytes) < (UINT32)file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: cbytes len %ld < file size %ld\n",
                        CBYTES_LEN(cbytes), (UINT32)file_size);
        return (EC_FALSE);
    }
#endif
    if(EC_FALSE == cdcdn_read_p(CDC_MD_DN(cdc_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
                           file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  write data node at offset in the specific file
*
**/
EC_BOOL cdc_write_e_dn(CDC_MD *cdc_md, CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint32_t file_max_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_write_e_dn: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(CDCPGB_SIZE_NBYTES <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: offset %ld + buff len (or file size) %ld = %ld overflow\n",
                            (*offset), CBYTES_LEN(cbytes), (*offset) + CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);

    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CDCPGB_PAGE_SIZE_NBYTES - 1) >> CDCPGB_PAGE_SIZE_NBITS) << CDCPGB_PAGE_SIZE_NBITS);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: offset %ld overflow due to file max size is %u\n", (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(EC_FALSE == cdcdn_write_e(CDC_MD_DN(cdc_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_write_e_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    (*offset) += max_len_t;
    if((*offset) > file_size)
    {
        /*update file size info*/
        CDC_ASSERT((*offset) == CDCPGB_PAGE_SIZE_NBYTES);
        CDCNP_FNODE_PAGENUM(cdcnp_fnode) = (uint16_t)((*offset) >> CDCPGB_PAGE_SIZE_NBITS);
    }

    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cdc_read_e_dn(CDC_MD *cdc_md, const CDCNP_FNODE *cdcnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    const CDCNP_INODE *cdcnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CDCNP_FNODE_REPNUM(cdcnp_fnode))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size   = (uint32_t)(((uint32_t)CDCNP_FNODE_PAGENUM(cdcnp_fnode)) << CDCPGB_PAGE_SIZE_NBITS);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);
    disk_no  = CDCNP_INODE_DISK_NO(cdcnp_inode) ;
    block_no = CDCNP_INODE_BLOCK_NO(cdcnp_inode);
    page_no  = CDCNP_INODE_PAGE_NO(cdcnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: due to offset %ld >= file size %u\n", (*offset), file_size);
        return (EC_FALSE);
    }

    offset_t = (uint32_t)(*offset);
    if(0 == max_len)
    {
        max_len_t = file_size - offset_t;
    }
    else
    {
        max_len_t = DMIN(max_len, file_size - offset_t);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_read_e_dn: file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

#if 0
    if(0 == CBYTES_LEN(cbytes))/*scenario: cbytes is not initialized*/
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CDC_0007);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CDC_0008);
        CBYTES_LEN(cbytes) = 0;
    }

    else if(CBYTES_LEN(cbytes) < max_len_t)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: cbytes len %ld < max len %ld\n",
                        CBYTES_LEN(cbytes), max_len_t);
        return (EC_FALSE);
    }
#endif
#if 1
    CDC_ASSERT(0 < CBYTES_LEN(cbytes));
    if(CBYTES_LEN(cbytes) < max_len_t)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: cbytes len %ld < max len %ld\n",
                        CBYTES_LEN(cbytes), max_len_t);
        return (EC_FALSE);
    }
#endif
    if(EC_FALSE == cdcdn_read_e(CDC_MD_DN(cdc_md), disk_no, block_no, page_no, offset_t, max_len_t,
                                CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_read_e_dn: read %ld bytes from disk %u, block %u, offset %u failed\n",
                           max_len_t, disk_no, block_no, offset_t);
        return (EC_FALSE);
    }

    (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}


/**
*
*  delete a page
*
**/
EC_BOOL cdc_page_delete(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key)
{
    uint32_t     node_pos;

    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_delete: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_page_delete: np was not open\n");
        return (EC_FALSE);
    }

    node_pos = cdcnp_search(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS == node_pos)
    {
        /*not found*/

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_delete: cdc %p, not found key [%u, %u)\n",
                            cdc_md, CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));

        return (EC_TRUE);
    }

    if(EC_FALSE == cdcnp_umount_item(CDC_MD_NP(cdc_md), node_pos))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_delete: umount failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_delete: cdc %p, key [%u, %u) done\n",
                        cdc_md, CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));

    return (EC_TRUE);
}

/**
*
*  update a page
*
**/
EC_BOOL cdc_page_update(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, const CBYTES *cbytes)
{
    CDC_ASSERT(CDCNP_KEY_S_PAGE(cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_update: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_read(CDC_MD_NP(cdc_md), cdcnp_key, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == cdc_page_write(cdc_md, cdcnp_key, cbytes))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_update: write failed\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_update: write done\n");
        return (EC_TRUE);
    }

    /*file exist, update it*/
    if(EC_FALSE == cdc_page_delete(cdc_md, cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_update: delete old failed\n");
        return (EC_FALSE);
    }
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_update: delete old done\n");

    if(EC_FALSE == cdc_page_write(cdc_md, cdcnp_key, cbytes))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_update: write new failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_update: write new done\n");

    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cdc_file_num(CDC_MD *cdc_md, UINT32 *file_num)
{
    uint32_t     file_num_t;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_file_num: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_file_num(CDC_MD_NP(cdc_md), &file_num_t))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_num: get file num of key failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != file_num)
    {
        (*file_num) = file_num_t;
    }
    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cdc_file_size(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, UINT32 *file_size)
{
    if(EC_FALSE == cdcnp_key_is_valid(cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_size: invalid key [%u, %u)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_file_size: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_file_size(CDC_MD_NP(cdc_md), cdcnp_key, file_size))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_size: cdcnp mgr get size of key [%u, %u) failed\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_size: key [%u, %u), size %ld\n",
                    CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key), (*file_size));
    return (EC_TRUE);
}

/**
*
*  name node used ratio
*
**/
REAL cdc_used_ratio(CDC_MD *cdc_md)
{
    REAL    np_used_ratio;
    REAL    dn_used_ratio;

    np_used_ratio = 0.0;
    dn_used_ratio = 0.0;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        np_used_ratio = cdcnp_used_ratio(CDC_MD_NP(cdc_md));
    }

    if(NULL_PTR != CDC_MD_DN(cdc_md))
    {
        dn_used_ratio = cdcdn_used_ratio(CDC_MD_DN(cdc_md));
    }

    return DMAX(np_used_ratio, dn_used_ratio);
}

/**
*
*  name node deg ratio
*
**/
REAL cdc_deg_ratio(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        return cdcnp_deg_ratio(CDC_MD_NP(cdc_md));
    }

    return (0.0);
}

/**
*
*  name node deg num
*
**/
uint32_t cdc_deg_num(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        return cdcnp_deg_num(CDC_MD_NP(cdc_md));
    }

    return (0);
}

/**
*
*  search in current name node
*
**/
EC_BOOL cdc_search(CDC_MD *cdc_md, const CDCNP_KEY *cdcnp_key, uint32_t *node_pos)
{
    uint32_t    node_pos_t;
    if(EC_FALSE == cdcnp_key_is_valid(cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_search: invalid key [%u, %u)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_search: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 7)(LOGSTDOUT, "warn:cdc_search: miss key [%u, %u)\n",
                        CDCNP_KEY_S_PAGE(cdcnp_key), CDCNP_KEY_E_PAGE(cdcnp_key));
        return (EC_FALSE);
    }

    node_pos_t = cdcnp_search(CDC_MD_NP(cdc_md), cdcnp_key, CDCNP_ITEM_FILE_IS_REG);
    if(CDCNPRB_ERR_POS == node_pos_t)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_search: search failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != node_pos)
    {
        (*node_pos) = node_pos_t;
    }

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL cdc_recycle(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num)
{
    CDCNP_RECYCLE_DN cdcnp_recycle_dn;
    UINT32           complete_recycle_num;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_recycle: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_recycle: cdc is read-only\n");
        return (EC_FALSE);
    }

    CDCNP_RECYCLE_DN_ARG1(&cdcnp_recycle_dn)   = (void *)cdc_md;
    CDCNP_RECYCLE_DN_FUNC(&cdcnp_recycle_dn)   = (CDCNP_RECYCLE_DN_FUNC)cdc_release_dn;

    complete_recycle_num = 0;/*initialization*/

    if(EC_FALSE == cdcnp_recycle(CDC_MD_NP(cdc_md), max_num, NULL_PTR, &cdcnp_recycle_dn, &complete_recycle_num))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_recycle: recycle np failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "[DEBUG] cdc_recycle: recycle complete %ld\n", complete_recycle_num);

    if(NULL_PTR != complete_num)
    {
        (*complete_num) += complete_recycle_num;
    }
    return (EC_TRUE);
}

/**
*
*  retire files
*
**/
EC_BOOL cdc_retire(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num)
{
    UINT32      complete_retire_num;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_retire: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_retire: cdc is read-only\n");
        return (EC_FALSE);
    }

    complete_retire_num = 0;/*initialization*/

    cdcnp_retire(CDC_MD_NP(cdc_md), CDC_SCAN_RETIRE_MAX_NUM, max_num, &complete_retire_num);

    dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "[DEBUG] cdc_retire: retire done where complete %ld\n", complete_retire_num);

    if(NULL_PTR != complete_num)
    {
        (*complete_num) += complete_retire_num;
    }

    return (EC_TRUE);
}

/**
*
*  degrade files
*
**/
EC_BOOL cdc_degrade(CDC_MD *cdc_md, const UINT32 max_num, UINT32 *complete_num)
{
    UINT32      complete_degrade_num;

    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_degrade: np was not open\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_degrade: cdc is read-only\n");
        return (EC_FALSE);
    }

    complete_degrade_num = 0;/*initialization*/

    cdcnp_degrade(CDC_MD_NP(cdc_md), CDC_SCAN_DEGRADE_MAX_NUM, max_num, &complete_degrade_num);

    dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "[DEBUG] cdc_degrade: degrade done where complete %ld\n", complete_degrade_num);

    if(NULL_PTR != complete_num)
    {
        (*complete_num) += complete_degrade_num;
    }

    return (EC_TRUE);
}

/**
*
*  set callback for degrading from ssd to sata
*
**/
EC_BOOL cdc_set_degrade_callback(CDC_MD *cdc_md, CDCNP_DEGRADE_CALLBACK func, void *arg)
{
    if(NULL_PTR != cdc_md)
    {
        cdcnp_degrade_cb_set(CDC_MD_NP_DEGRADE_CB(cdc_md), func, arg);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/**
*
*  show name node
*
*
**/
EC_BOOL cdc_show_np(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    if(NULL_PTR != CDC_MD_SSD_BAD_BITMAP(cdc_md))
    {
        sys_log(log, "cdc_show_np: ssd bad pages : %u\n",
                     CBAD_BITMAP_USED(CDC_MD_SSD_BAD_BITMAP(cdc_md)));
    }

    if(NULL_PTR != CDC_MD_SATA_BAD_BITMAP(cdc_md))
    {
        sys_log(log, "cdc_show_np: sata bad pages: %u\n",
                     CBAD_BITMAP_USED(CDC_MD_SATA_BAD_BITMAP(cdc_md)));
    }

    cdcnp_print(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show name node LRU
*
*
**/
EC_BOOL cdc_show_np_lru_list(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cdcnp_print_lru_list(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show name node DEL
*
*
**/
EC_BOOL cdc_show_np_del_list(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cdcnp_print_del_list(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show name node DEG
*
*
**/
EC_BOOL cdc_show_np_deg_list(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cdcnp_print_deg_list(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show name node BITMAP
*
*
**/
EC_BOOL cdc_show_np_bitmap(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cdcnp_print_bitmap(log, CDC_MD_NP(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show cdcdn info if it is dn
*
*
**/
EC_BOOL cdc_show_dn(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_DN(cdc_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cdcdn_print(log, CDC_MD_DN(cdc_md));

    return (EC_TRUE);
}

/**
*
*  show all files
*
**/

EC_BOOL cdc_show_files(const CDC_MD *cdc_md, LOG *log)
{
    if(NULL_PTR == CDC_MD_NP(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 1)(LOGSTDOUT, "warn:cdc_show_files: np was not open\n");
        return (EC_FALSE);
    }

    cdcnp_walk(CDC_MD_NP(cdc_md), (CDCNPRB_WALKER)cdcnp_file_print, (void *)log);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_show_files: walk cdcnp done\n");
    return (EC_TRUE);
}

/*-------------------------------------------- cdc aio interface --------------------------------------------*/

/*----------------------------------- cdc page interface -----------------------------------*/

CDC_PAGE *cdc_page_new()
{
    CDC_PAGE *cdc_page;

    alloc_static_mem(MM_CDC_PAGE, &cdc_page, LOC_CDC_0009);
    if(NULL_PTR == cdc_page)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    cdc_page_init(cdc_page);
    return (cdc_page);
}

EC_BOOL cdc_page_init(CDC_PAGE *cdc_page)
{
    CDC_PAGE_FD(cdc_page)                 = ERR_FD;

    CDC_PAGE_F_S_OFFSET(cdc_page)         = CDC_ERR_OFFSET;
    CDC_PAGE_F_E_OFFSET(cdc_page)         = CDC_ERR_OFFSET;

    CDC_PAGE_D_S_OFFSET(cdc_page)         = CDC_ERR_OFFSET;
    CDC_PAGE_D_E_OFFSET(cdc_page)         = CDC_ERR_OFFSET;
    CDC_PAGE_D_T_OFFSET(cdc_page)         = CDC_ERR_OFFSET;

    CDC_PAGE_OP(cdc_page)                 = CDC_OP_ERR;

    CDC_PAGE_TIMEOUT_NSEC(cdc_page)       = 0;

    CDC_PAGE_DIRTY_FLAG(cdc_page)         = BIT_FALSE;
    CDC_PAGE_SSD_LOADED_FLAG(cdc_page)    = BIT_FALSE;
    CDC_PAGE_SSD_LOADING_FLAG(cdc_page)   = BIT_FALSE;
    CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page)  = BIT_FALSE;
    CDC_PAGE_MEM_CACHE_FLAG(cdc_page)     = BIT_FALSE;
    CDC_PAGE_SATA_DIRTY_FLAG(cdc_page)    = BIT_FALSE;
    CDC_PAGE_SATA_DEG_FLAG(cdc_page)      = BIT_FALSE;

    CDC_PAGE_FAIL_COUNTER(cdc_page)       = 0;

    CDC_PAGE_M_CACHE(cdc_page)            = NULL_PTR;
    CDC_PAGE_CDCNP_ITEM(cdc_page)         = NULL_PTR;
    CDC_PAGE_CDCNP_ITEM_POS(cdc_page)     = CDCNPRB_ERR_POS;

    CDC_PAGE_CDC_MD(cdc_page)             = NULL_PTR;
    CDC_PAGE_MOUNTED_PAGES(cdc_page)      = NULL_PTR;
    CDC_PAGE_MOUNTED_TREE_IDX(cdc_page)   = CDC_PAGE_TREE_IDX_ERR;

    clist_init(CDC_PAGE_OWNERS(cdc_page), MM_CDC_NODE, LOC_CDC_0010);

    return (EC_TRUE);
}

EC_BOOL cdc_page_clean(CDC_PAGE *cdc_page)
{
    if(NULL_PTR != cdc_page)
    {
        /*clean up owners*/
        cdc_page_cleanup_nodes(cdc_page);

        if(NULL_PTR != CDC_PAGE_M_CACHE(cdc_page))
        {
            if(BIT_FALSE == CDC_PAGE_MEM_CACHE_FLAG(cdc_page))
            {
                __cdc_mem_cache_free(CDC_PAGE_M_CACHE(cdc_page));
            }

            CDC_PAGE_M_CACHE(cdc_page) = NULL_PTR;
        }

        if(NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
        && NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
        && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
        {
            CDC_MD     *cdc_md;

            cdc_md = CDC_PAGE_CDC_MD(cdc_page);
            cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
        }

        CDC_PAGE_FD(cdc_page)                 = ERR_FD;

        CDC_PAGE_F_S_OFFSET(cdc_page)         = CDC_ERR_OFFSET;
        CDC_PAGE_F_E_OFFSET(cdc_page)         = CDC_ERR_OFFSET;

        CDC_PAGE_D_S_OFFSET(cdc_page)         = CDC_ERR_OFFSET;
        CDC_PAGE_D_E_OFFSET(cdc_page)         = CDC_ERR_OFFSET;
        CDC_PAGE_D_T_OFFSET(cdc_page)         = CDC_ERR_OFFSET;

        CDC_PAGE_OP(cdc_page)                 = CDC_OP_ERR;

        CDC_PAGE_CDCNP_ITEM(cdc_page)         = NULL_PTR;
        CDC_PAGE_CDCNP_ITEM_POS(cdc_page)     = CDCNPRB_ERR_POS;

        CDC_PAGE_TIMEOUT_NSEC(cdc_page)       = 0;

        CDC_PAGE_DIRTY_FLAG(cdc_page)         = BIT_FALSE;
        CDC_PAGE_SSD_LOADED_FLAG(cdc_page)    = BIT_FALSE;
        CDC_PAGE_SSD_LOADING_FLAG(cdc_page)   = BIT_FALSE;
        CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page)  = BIT_FALSE;
        CDC_PAGE_MEM_CACHE_FLAG(cdc_page)     = BIT_FALSE;
        CDC_PAGE_SATA_DIRTY_FLAG(cdc_page)    = BIT_FALSE;
        CDC_PAGE_SATA_DEG_FLAG(cdc_page)      = BIT_FALSE;

        CDC_PAGE_FAIL_COUNTER(cdc_page)       = 0;

        CDC_PAGE_CDC_MD(cdc_page)             = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cdc_page_free(CDC_PAGE *cdc_page)
{
    if(NULL_PTR != cdc_page)
    {
        cdc_page_clean(cdc_page);
        free_static_mem(MM_CDC_PAGE, cdc_page, LOC_CDC_0011);
    }
    return (EC_TRUE);
}

void cdc_page_print(LOG *log, const CDC_PAGE *cdc_page)
{
    sys_log(log, "cdc_page_print: cdc_page %p: page range [%ld, %ld), "
                 "dirty %u, ssd loaded %u, ssd loading %u, ssd flushing %u, mem cache page %u, "
                 "sata dirty flag %u, sata degrade flag %u, "
                 "m_cache %p, item %p, item pos %u, mounted pages %p, mounted tree idx %ld, "
                 "timeout %ld seconds\n",
                 cdc_page,
                 CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                 CDC_PAGE_DIRTY_FLAG(cdc_page),
                 CDC_PAGE_SSD_LOADED_FLAG(cdc_page),
                 CDC_PAGE_SSD_LOADING_FLAG(cdc_page),
                 CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page),
                 CDC_PAGE_MEM_CACHE_FLAG(cdc_page),
                 CDC_PAGE_SATA_DIRTY_FLAG(cdc_page),
                 CDC_PAGE_SATA_DEG_FLAG(cdc_page),
                 CDC_PAGE_M_CACHE(cdc_page),
                 CDC_PAGE_CDCNP_ITEM(cdc_page),
                 CDC_PAGE_CDCNP_ITEM_POS(cdc_page),
                 CDC_PAGE_MOUNTED_PAGES(cdc_page),
                 CDC_PAGE_MOUNTED_TREE_IDX(cdc_page),
                 CDC_PAGE_TIMEOUT_NSEC(cdc_page));

    sys_log(log, "cdc_page_print: cdc_page %p: owners:\n", cdc_page);
    clist_print(log, CDC_PAGE_OWNERS(cdc_page), (CLIST_DATA_DATA_PRINT)cdc_node_print);

    return;
}

int cdc_page_cmp(const CDC_PAGE *cdc_page_1st, const CDC_PAGE *cdc_page_2nd)
{
    if(CDC_PAGE_FD(cdc_page_1st) == CDC_PAGE_FD(cdc_page_2nd))
    {
        if(CDC_PAGE_F_E_OFFSET(cdc_page_1st) <= CDC_PAGE_F_S_OFFSET(cdc_page_2nd))
        {
            return (-1);
        }

        if(CDC_PAGE_F_S_OFFSET(cdc_page_1st) >= CDC_PAGE_F_E_OFFSET(cdc_page_2nd))
        {
            return (1);
        }

        CDC_ASSERT(CDC_PAGE_F_S_OFFSET(cdc_page_1st) == CDC_PAGE_F_S_OFFSET(cdc_page_2nd));
        CDC_ASSERT(CDC_PAGE_F_E_OFFSET(cdc_page_1st) == CDC_PAGE_F_E_OFFSET(cdc_page_2nd));

        return (0);
    }

    if(CDC_PAGE_FD(cdc_page_1st) < CDC_PAGE_FD(cdc_page_2nd))
    {
        return (-1);
    }

    return (1);
}

EC_BOOL cdc_page_locate(CDC_PAGE *cdc_page)
{
    if(NULL_PTR == CDC_PAGE_CDCNP_ITEM(cdc_page)
    || CDC_ERR_OFFSET == CDC_PAGE_D_S_OFFSET(cdc_page)
    || CDC_ERR_OFFSET == CDC_PAGE_D_E_OFFSET(cdc_page))
    {
        if(NULL_PTR == CDC_PAGE_CDC_MD(cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_locate: "
                                                "page [%ld, %ld) has no cdc module info\n",
                                                CDC_PAGE_F_S_OFFSET(cdc_page),
                                                CDC_PAGE_F_E_OFFSET(cdc_page));
            return (EC_FALSE);
        }

        if(EC_FALSE == cdc_locate_page(CDC_PAGE_CDC_MD(cdc_page), cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_locate: "
                             "locate page [%ld, %ld) to disk failed\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_locate: "
                         "locate page [%ld, %ld) to disk [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_page_map(CDC_PAGE *cdc_page)
{
    if(NULL_PTR == CDC_PAGE_CDCNP_ITEM(cdc_page)
    || CDC_ERR_OFFSET == CDC_PAGE_D_S_OFFSET(cdc_page)
    || CDC_ERR_OFFSET == CDC_PAGE_D_E_OFFSET(cdc_page))
    {
        if(NULL_PTR == CDC_PAGE_CDC_MD(cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_map: "
                                                "page [%ld, %ld) has no cdc module info\n",
                                                CDC_PAGE_F_S_OFFSET(cdc_page),
                                                CDC_PAGE_F_E_OFFSET(cdc_page));
            return (EC_FALSE);
        }

        if(EC_FALSE == cdc_map_page(CDC_PAGE_CDC_MD(cdc_page), cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_map: "
                             "map page [%ld, %ld) to disk failed\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_map: "
                         "map page [%ld, %ld) to disk [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_TRUE);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_page_add_node(CDC_PAGE *cdc_page, CDC_NODE *cdc_node)
{
    CDC_ASSERT(NULL_PTR == CDC_NODE_MOUNTED_OWNERS(cdc_node));

    /*mount*/
    CDC_NODE_MOUNTED_OWNERS(cdc_node) = clist_push_back(CDC_PAGE_OWNERS(cdc_page), (void *)cdc_node);
    if(NULL_PTR == CDC_NODE_MOUNTED_OWNERS(cdc_node))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_add_node: "
                         "add node %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                         "to page [%ld, %ld) failed\n",
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node),
                         CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node),
                         CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node),
                         __cdc_op_str(CDC_NODE_OP(cdc_node)),
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    CDC_NODE_CDC_PAGE(cdc_node) = cdc_page; /*bind*/

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_add_node: "
                     "add node (%p) %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "to page [%ld, %ld) done\n", cdc_node,
                     CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                     CDC_NODE_SEQ_NO(cdc_node),
                     CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node),
                     CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node),
                     __cdc_op_str(CDC_NODE_OP(cdc_node)),
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

    return (EC_TRUE);
}

EC_BOOL cdc_page_del_node(CDC_PAGE *cdc_page, CDC_NODE *cdc_node)
{
    CDC_ASSERT(NULL_PTR != CDC_NODE_MOUNTED_OWNERS(cdc_node));

    clist_erase(CDC_PAGE_OWNERS(cdc_page), CDC_NODE_MOUNTED_OWNERS(cdc_node));
    CDC_NODE_MOUNTED_OWNERS(cdc_node) = NULL_PTR; /*umount*/
    CDC_NODE_CDC_PAGE(cdc_node)       = NULL_PTR; /*unbind*/

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_del_node: "
                     "del node (%p) %ld/%ld of req %ld, block range [%ld, %ld), file range [%ld, %ld) op %s "
                     "from page [%ld, %ld) done\n", cdc_node,
                     CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                     CDC_NODE_SEQ_NO(cdc_node),
                     CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node),
                     CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node),
                     __cdc_op_str(CDC_NODE_OP(cdc_node)),
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

    return (EC_TRUE);
}

EC_BOOL cdc_page_cleanup_nodes(CDC_PAGE *cdc_page)
{
    CDC_NODE       *cdc_node;

    /*clean up residue owners*/
    while(NULL_PTR != (cdc_node = cdc_page_pop_node_back(cdc_page)))
    {
        if(NULL_PTR != CDC_NODE_CDC_REQ(cdc_node))
        {
            CDC_REQ     *cdc_req;

            cdc_req = CDC_NODE_CDC_REQ(cdc_node);

            CDC_REQ_NODE_NUM(cdc_req) --; /*dec*/

            /*update upper offset at most*/
            if(CDC_NODE_F_S_OFFSET(cdc_node) < CDC_REQ_U_E_OFFSET(cdc_req))
            {
                CDC_REQ_U_E_OFFSET(cdc_req) = CDC_NODE_F_S_OFFSET(cdc_node);
            }
        }

        cdc_node_free(cdc_node);
    }

    return (EC_TRUE);
}

CDC_NODE *cdc_page_pop_node_front(CDC_PAGE *cdc_page)
{
    CDC_NODE *cdc_node;

    cdc_node = clist_pop_front(CDC_PAGE_OWNERS(cdc_page));
    if(NULL_PTR == cdc_node)
    {
        return (NULL_PTR);
    }

    CDC_NODE_MOUNTED_OWNERS(cdc_node) = NULL_PTR; /*umount*/
    CDC_NODE_CDC_PAGE(cdc_node)       = NULL_PTR; /*ubind*/

    return (cdc_node);
}

CDC_NODE *cdc_page_pop_node_back(CDC_PAGE *cdc_page)
{
    CDC_NODE *cdc_node;

    cdc_node = clist_pop_back(CDC_PAGE_OWNERS(cdc_page));
    if(NULL_PTR == cdc_node)
    {
        return (NULL_PTR);
    }

    CDC_NODE_MOUNTED_OWNERS(cdc_node) = NULL_PTR; /*umount*/
    CDC_NODE_CDC_PAGE(cdc_node)       = NULL_PTR; /*ubind*/

    return (cdc_node);
}

/**
 * process when page is in mem cache
 *
 * note:
 *   cdc_page_process calling path is not only
 *      scenario 1: cdc_process -> cdc_process_pages -> cdc_process_page -> cdc_page_process,
 *   but also
 *      scenario 2: caio_process -> cdc_page_load_aio_complete / cdc_page_flush_aio_complete -> cdc_page_process
 *
 *   for scenario 1, cdc_add_page called in cdc_page_process would add page to standby tree,
 *   and then cdc_process_pages switch active tree and standby tree,
 *   and then cdc_req_dispatch_node search active tree to check page existing.
 *   everything is ok.
 *
 *   for scenario 2, cdc_add_page called in cdc_page_process would add page to standby tree,
 *   and nobody trigger cdc_process_pages to switch active tree and standby tree,
 *   meanwhile if cdc_req_dispatch_node search active tree to check page existing which is residing
 *   on standby tree, we would have 2 same pages in cdc: one in active tree, the other in standby tree.
 *   this scenario should be prohibitted.
 *
 *   one solution is transfering the re-try page tree index to cdc_page_process which would be used by
 *   cdc_add_page.
 *
 *   for scenario 1, transfer the standby tree index
 *   for scenario 2, transfer the active tree index
 *
**/
EC_BOOL cdc_page_process(CDC_PAGE *cdc_page, const UINT32 retry_page_tree_idx)
{
    CDC_NODE       *cdc_node;

    while(NULL_PTR != (cdc_node = cdc_page_pop_node_front(cdc_page)))
    {
        if(CDC_OP_RD == CDC_NODE_OP(cdc_node))
        {
            CDC_ASSERT(NULL_PTR != CDC_PAGE_M_CACHE(cdc_page));

            if(NULL_PTR != CDC_NODE_M_BUFF(cdc_node))
            {
                dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_page_process: "
                                "[RD] node %ld/%ld of req %ld, "
                                "copy from page [%ld, %ld) to app cache [%ld, %ld)\n",
                                CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                                CDC_NODE_SEQ_NO(cdc_node),
                                CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node),
                                CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node));

                /*copy data from mem cache to application mem buff*/
                FCOPY(CDC_PAGE_M_CACHE(cdc_page) + CDC_NODE_B_S_OFFSET(cdc_node),
                      CDC_NODE_M_BUFF(cdc_node),
                      CDC_NODE_B_E_OFFSET(cdc_node) - CDC_NODE_B_S_OFFSET(cdc_node));
            }
            else
            {
                dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_page_process: "
                                "[RD] node %ld/%ld of req %ld, "
                                "ignore copy from page [%ld, %ld) to app cache [%ld, %ld)\n",
                                CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                                CDC_NODE_SEQ_NO(cdc_node),
                                CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node),
                                CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node));
            }

            cdc_node_complete(cdc_node);
        }

        else if(CDC_OP_WR == CDC_NODE_OP(cdc_node))
        {
            CDC_ASSERT(NULL_PTR != CDC_PAGE_M_CACHE(cdc_page));
            CDC_ASSERT(NULL_PTR != CDC_NODE_M_BUFF(cdc_node));

            dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_page_process: "
                            "[WR] node %ld/%ld of req %ld, "
                            "copy from app [%ld, %ld) to page [%ld, %ld)\n",
                            CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                            CDC_NODE_SEQ_NO(cdc_node),
                            CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node),
                            CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node));

            /*copy data from application mem buff to mem cache*/
            FCOPY(CDC_NODE_M_BUFF(cdc_node),
                  CDC_PAGE_M_CACHE(cdc_page) + CDC_NODE_B_S_OFFSET(cdc_node),
                  CDC_NODE_B_E_OFFSET(cdc_node) - CDC_NODE_B_S_OFFSET(cdc_node));

            cdc_node_complete(cdc_node);

            CDC_PAGE_DIRTY_FLAG(cdc_page) = BIT_TRUE; /*set dirty*/
        }
        else
        {
            /*should never reach here*/
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_process: "
                             "invalid op: node %ld/%ld of req %ld, "
                             "block range [%ld, %ld), file range [%ld, %ld) op %s "
                             "in page [%ld, %ld)\n",
                             CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                             CDC_NODE_SEQ_NO(cdc_node),
                             CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node),
                             CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node),
                             __cdc_op_str(CDC_NODE_OP(cdc_node)),
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

            cdc_node_free(cdc_node);
            cdc_page_unlock(cdc_page);
            cdc_page_free(cdc_page);
            return (EC_FALSE);
        }
    }

    if(EC_FALSE == cdc_page_notify_timeout(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_process: "
                                            "page [%ld, %ld) notify timeout nodes failed\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));

        cdc_page_unlock(cdc_page);
        cdc_page_free(cdc_page);
        return (EC_FALSE);
    }

    if(BIT_TRUE == CDC_PAGE_SATA_DIRTY_FLAG(cdc_page))
    {
        CDC_ASSERT(NULL_PTR != CDC_PAGE_CDCNP_ITEM(cdc_page));
        CDC_ASSERT(CDCNPRB_ERR_POS != CDC_PAGE_CDCNP_ITEM_POS(cdc_page));

        if(NULL_PTR != CDC_PAGE_CDCNP_ITEM(cdc_page))
        {
            CDCNP_ITEM  *cdcnp_item;

            cdcnp_item = CDC_PAGE_CDCNP_ITEM(cdc_page);

            CDCNP_ITEM_SATA_DIRTY_FLAG(cdcnp_item) = BIT_TRUE;/*set sata dirty*/

            CDC_PAGE_SATA_DIRTY_FLAG(cdc_page)     = BIT_FALSE; /*clear*/
        }
    }

    /*check flushing flag before dirty flag regarding re-entrance*/
    if(BIT_TRUE == CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page))
    {
        CDC_MD      *cdc_md;

        dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_page_process: "
                         "page [%ld, %ld) is flushing => retry\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

        CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
        cdc_md = CDC_PAGE_CDC_MD(cdc_page);

        /*add page to standby page tree temporarily*/
        cdc_add_page(cdc_md, retry_page_tree_idx, cdc_page);

        return (EC_TRUE);
    }

    /*page loaded from ssd => do nothing*/
    if(BIT_TRUE == CDC_PAGE_SSD_LOADED_FLAG(cdc_page))
    {
        CDC_PAGE_SSD_LOADED_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/
    }

    /*flush dirty page to ssd*/
    if(BIT_TRUE == CDC_PAGE_DIRTY_FLAG(cdc_page))
    {
        CDC_MD      *cdc_md;

        CDC_PAGE_OP(cdc_page) = CDC_OP_WR; /*reset flag*/

        CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
        cdc_md = CDC_PAGE_CDC_MD(cdc_page);

        if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
        {
            if(EC_FALSE == cdc_page_flush_aio(cdc_page))
            {
                /*page cannot be accessed again => do not output log*/
                return (EC_FALSE);
            }

            CDC_PAGE_DIRTY_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

            /*add page to standby page tree temporarily*/
            cdc_add_page(cdc_md, retry_page_tree_idx, cdc_page);
            CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page) = BIT_TRUE; /*set flag*/

            dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_page_process: "
                             "submit flushing page [%ld, %ld) to ssd done\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

            /*page would be free later*/
        }
        else
        {
            if(EC_FALSE == cdc_page_flush(cdc_page))
            {
                /*not flush aio*/
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_process: "
                                 "flush page [%ld, %ld) to ssd failed\n",
                                 CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

                cdc_page_free(cdc_page);
                return (EC_FALSE);
            }

            CDC_PAGE_DIRTY_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

            dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_page_process: "
                             "flush page [%ld, %ld) to ssd done\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

            cdc_page_unlock(cdc_page);
            cdc_page_free(cdc_page);
        }

        return (EC_TRUE);
    }

    dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_page_process: "
                     "process page [%ld, %ld) done\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

    cdc_page_unlock(cdc_page);
    cdc_page_free(cdc_page);
    return (EC_TRUE);
}

EC_BOOL cdc_page_purge_ssd(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    if(NULL_PTR != CDC_MD_NP(cdc_md)
    && NULL_PTR != CDC_MD_DN(cdc_md))
    {
        CDCNP_KEY     cdcnp_key;
        uint32_t      ssd_page_no;

        /*one page only*/
        CDCNP_KEY_S_PAGE(&cdcnp_key) = (CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
        CDCNP_KEY_E_PAGE(&cdcnp_key) = (CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

        CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

        if(EC_FALSE == cdc_page_delete(cdc_md, &cdcnp_key))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_purge_ssd: "
                            "del page [%ld, %ld) failed\n",
                            CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
            return (EC_FALSE);
        }

        /*set ssd bad page*/
        ssd_page_no = (CDC_PAGE_D_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
        if(EC_FALSE == cdc_set_ssd_bad_page(cdc_md, ssd_page_no))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_purge_ssd: "
                            "set ssd bad page [%ld, %ld), page no %u failed\n",
                            CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                            ssd_page_no);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_purge_ssd: "
                        "set ssd bad page [%ld, %ld), page no %u done\n",
                        CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                        ssd_page_no);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_page_purge_sata(CDC_PAGE *cdc_page)
{
    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page))
    {
        CDC_MD       *cdc_md;
        uint32_t      sata_page_no;

        cdc_md = CDC_PAGE_CDC_MD(cdc_page);

        /*set sata bad page*/
        sata_page_no = (CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
        if(EC_FALSE == cdc_set_sata_bad_page(cdc_md, sata_page_no))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_purge_sata: "
                            "set sata bad page [%ld, %ld), page no %u failed\n",
                            CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                            sata_page_no);
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_purge_sata: "
                        "set sata bad page [%ld, %ld), page no %u done\n",
                        CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                        sata_page_no);
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdc_page_purge_both(CDC_PAGE *cdc_page)
{
    if(EC_FALSE == cdc_page_purge_sata(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_purge_both: "
                        "purge sata page [%ld, %ld) failed\n",
                        CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdc_page_purge_ssd(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_purge_both: "
                        "purge ssd page [%ld, %ld) failed\n",
                        CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_purge_both: "
                    "purge sata page [%ld, %ld), ssd page [%ld, %ld) done\n",
                    CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                    CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    return (EC_TRUE);
}

EC_BOOL cdc_page_read_aio_timeout(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;
    CDC_NODE       *cdc_node;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    CDC_PAGE_FAIL_COUNTER(cdc_page) ++;

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio_timeout: "
                     "read page [%ld, %ld) timeout [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    while(NULL_PTR != (cdc_node = cdc_page_pop_node_front(cdc_page)))
    {
        cdc_node_timeout(cdc_node);
    }

    cdc_page_unlock(cdc_page);

#if 0
    /*retry*/

    if(CDC_AIO_FAIL_MAX_NUM > CDC_PAGE_FAIL_COUNTER(cdc_page)
    && EC_TRUE == cdc_page_read_aio(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio_timeout: "
                         "read page [%ld, %ld) from [%ld, %ld) retry\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_TRUE);
    }

    /*retry times would ensure application timeout callback is executed (async mode), */
    /*thus cdc np could be clean up by discard page */
    cdc_discard_page(cdc_md, cdc_page);

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_aio_timeout: "
                     "read page [%ld, %ld) from [%ld, %ld) retry and failed [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

#endif

#if 1
    if(EC_FALSE == cdc_page_purge_both(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_aio_timeout: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) failed\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
    else
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio_timeout: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
#endif

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    cdc_page_free(cdc_page);
    return (EC_TRUE);
}

EC_BOOL cdc_page_read_aio_terminate(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;
    CDC_NODE       *cdc_node;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    CDC_PAGE_FAIL_COUNTER(cdc_page) ++;

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio_terminate: "
                     "read page [%ld, %ld) terminated [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    while(NULL_PTR != (cdc_node = cdc_page_pop_node_front(cdc_page)))
    {
        cdc_node_terminate(cdc_node);
    }

    cdc_page_unlock(cdc_page);

#if 0
    /*retry*/

    if(CDC_AIO_FAIL_MAX_NUM > CDC_PAGE_FAIL_COUNTER(cdc_page)
    && EC_TRUE == cdc_page_read_aio(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio_terminate: "
                         "read page [%ld, %ld) from [%ld, %ld) retry\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_TRUE);
    }

    /*retry times would ensure application terminate callback is executed (async mode), */
    /*thus cdc np could be clean up by discard page */
    cdc_discard_page(cdc_md, cdc_page);

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_aio_terminate: "
                     "read page [%ld, %ld) retry and failed [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));
#endif

#if 1
    if(EC_FALSE == cdc_page_purge_both(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_read_aio_terminate: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) failed\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
    else
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio_terminate: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
#endif

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    cdc_page_free(cdc_page);
    return (EC_TRUE);
}

EC_BOOL cdc_page_read_aio_complete(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio_complete: "
                     "read page [%ld, %ld) [crc %u] from ssd [%ld, %ld) completed\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                  CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    CDC_PAGE_SSD_LOADED_FLAG(cdc_page)  = BIT_TRUE;  /*set ssd loaded*/
    CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    /*return to process procedure*/
    cdc_page_process(cdc_page, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md));

    return (EC_TRUE);
}

/*async model: read page from ssd to mem cache*/
EC_BOOL cdc_page_read_aio(CDC_PAGE *cdc_page)
{
    CDC_MD          *cdc_md;
    CAIO_MD         *caio_md;
    CAIO_CB          caio_cb;

    cdc_md = CDC_PAGE_CDC_MD(cdc_page);
    CDC_ASSERT(NULL_PTR != CDC_MD_CAIO_MD(cdc_md));

    caio_md = CDC_MD_CAIO_MD(cdc_md);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CDC_PAGE_TIMEOUT_NSEC(cdc_page),
                                (CAIO_CALLBACK)cdc_page_read_aio_timeout, (void *)cdc_page);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)cdc_page_read_aio_terminate, (void *)cdc_page);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)cdc_page_read_aio_complete, (void *)cdc_page);

    CDC_ASSERT(CDC_PAGE_F_S_OFFSET(cdc_page) + CDCPGB_PAGE_SIZE_NBYTES == CDC_PAGE_F_E_OFFSET(cdc_page));

    CDC_PAGE_D_T_OFFSET(cdc_page) = CDC_PAGE_D_S_OFFSET(cdc_page);

    if(EC_TRUE == caio_file_read(caio_md,
                    CDC_PAGE_FD(cdc_page),
                    &CDC_PAGE_D_T_OFFSET(cdc_page),
                    CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page),
                    CDC_PAGE_M_CACHE(cdc_page),
                    &caio_cb))
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_read_aio: "
                         "submit loading page [%ld, %ld) from ssd [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));

        cdc_page_lock(cdc_page);
        return (EC_TRUE);
    }

    /*WARNING: exception would be handled in terminate, */
    /*         and page cannot be accessed again! => do not output log*/

    return (EC_FALSE);
}

EC_BOOL cdc_page_load_aio_timeout(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;
    CDC_NODE       *cdc_node;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    CDC_PAGE_FAIL_COUNTER(cdc_page) ++;

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio_timeout: "
                     "load page [%ld, %ld) timeout [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    while(NULL_PTR != (cdc_node = cdc_page_pop_node_front(cdc_page)))
    {
        cdc_node_timeout(cdc_node);
    }

    cdc_page_unlock(cdc_page);

#if 0
    /*retry*/

    if(CDC_AIO_FAIL_MAX_NUM > CDC_PAGE_FAIL_COUNTER(cdc_page)
    && EC_TRUE == cdc_page_load_aio(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio_timeout: "
                         "load page [%ld, %ld) from [%ld, %ld) retry\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_TRUE);
    }

    /*retry times would ensure application timeout callback is executed (async mode), */
    /*thus cdc np could be clean up by discard page */
    cdc_discard_page(cdc_md, cdc_page);

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_load_aio_timeout: "
                     "load page [%ld, %ld) from [%ld, %ld) retry and failed [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));
#endif

#if 1
    if(EC_FALSE == cdc_page_purge_both(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_load_aio_timeout: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) failed\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
    else
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio_timeout: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
#endif

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    cdc_page_free(cdc_page);
    return (EC_TRUE);
}

EC_BOOL cdc_page_load_aio_terminate(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;
    CDC_NODE       *cdc_node;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    CDC_PAGE_FAIL_COUNTER(cdc_page) ++;

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio_terminate: "
                     "load page [%ld, %ld) terminated [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    while(NULL_PTR != (cdc_node = cdc_page_pop_node_front(cdc_page)))
    {
        cdc_node_terminate(cdc_node);
    }

    cdc_page_unlock(cdc_page);
#if 0
    /*retry*/

    if(CDC_AIO_FAIL_MAX_NUM > CDC_PAGE_FAIL_COUNTER(cdc_page)
    && EC_TRUE == cdc_page_load_aio(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio_terminate: "
                         "load page [%ld, %ld) from [%ld, %ld) retry\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_TRUE);
    }

    /*retry times would ensure application terminate callback is executed (async mode), */
    /*thus cdc np could be clean up by discard page */
    cdc_discard_page(cdc_md, cdc_page);

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_load_aio_terminate: "
                     "load page [%ld, %ld) retry and failed [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));
#endif

#if 1
    if(EC_FALSE == cdc_page_purge_both(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_load_aio_terminate: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) failed\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
    else
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio_terminate: "
                         "purge sata page [%ld, %ld) and ssd page [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
    }
#endif

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    cdc_page_free(cdc_page);
    return (EC_TRUE);
}

EC_BOOL cdc_page_load_aio_complete(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio_complete: "
                     "load page [%ld, %ld) [crc %u] from ssd [%ld, %ld) completed\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                  CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    CDC_PAGE_SSD_LOADED_FLAG(cdc_page)  = BIT_TRUE;  /*set ssd loaded*/
    CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    /*return to process procedure*/
    cdc_page_process(cdc_page, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md));

    return (EC_TRUE);
}

/*async model: load page from ssd to mem for degrading*/
EC_BOOL cdc_page_load_aio(CDC_PAGE *cdc_page)
{
    CDC_MD          *cdc_md;
    CAIO_MD         *caio_md;
    CAIO_CB          caio_cb;

    cdc_md = CDC_PAGE_CDC_MD(cdc_page);
    CDC_ASSERT(NULL_PTR != CDC_MD_CAIO_MD(cdc_md));

    caio_md = CDC_MD_CAIO_MD(cdc_md);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CDC_PAGE_TIMEOUT_NSEC(cdc_page),
                                (CAIO_CALLBACK)cdc_page_load_aio_timeout, (void *)cdc_page);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)cdc_page_load_aio_terminate, (void *)cdc_page);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)cdc_page_load_aio_complete, (void *)cdc_page);

    CDC_ASSERT(CDC_PAGE_F_S_OFFSET(cdc_page) + CDCPGB_PAGE_SIZE_NBYTES == CDC_PAGE_F_E_OFFSET(cdc_page));

    CDC_PAGE_D_T_OFFSET(cdc_page) = CDC_PAGE_D_S_OFFSET(cdc_page);

    if(EC_TRUE == caio_file_read(caio_md,
                    CDC_PAGE_FD(cdc_page),
                    &CDC_PAGE_D_T_OFFSET(cdc_page),
                    CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page),
                    CDC_PAGE_M_CACHE(cdc_page),
                    &caio_cb))
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_load_aio: "
                         "submit loading page [%ld, %ld) from ssd [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));

        cdc_page_lock(cdc_page);
        return (EC_TRUE);
    }

    /*WARNING: exception would be handled in terminate, */
    /*         and page cannot be accessed again! => do not output log*/

    return (EC_FALSE);
}

/*sync model: load page from disk to mem cache*/
EC_BOOL cdc_page_load(CDC_PAGE *cdc_page)
{
    CDC_MD                *cdc_md;

    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    if(EC_FALSE == cdc_file_write(cdc_md,
                                  &CDC_PAGE_D_T_OFFSET(cdc_page),
                                  CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page),
                                  CDC_PAGE_M_CACHE(cdc_page)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_load: "
                                            "load page [%ld, %ld) to ssd failed\n",
                                            CDC_PAGE_D_S_OFFSET(cdc_page),
                                            CDC_PAGE_D_E_OFFSET(cdc_page));

        return (EC_FALSE);
    }

    CDC_PAGE_SSD_LOADED_FLAG(cdc_page)  = BIT_TRUE;  /*set ssd loaded*/
    CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_load: "
                                        "load page [%ld, %ld) to ssd done\n",
                                        CDC_PAGE_D_S_OFFSET(cdc_page),
                                        CDC_PAGE_D_E_OFFSET(cdc_page));
    return (EC_TRUE);
}

EC_BOOL cdc_page_notify_timeout(CDC_PAGE *cdc_page)
{
    CLIST_DATA      *clist_data;
    uint64_t         cur_time_ms;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_notify_timeout: "
                     "page [%ld, %ld) notify the timeout nodes\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

    cur_time_ms = c_get_cur_time_msec();

    CLIST_LOOP_NEXT(CDC_PAGE_OWNERS(cdc_page), clist_data)
    {
        CDC_NODE       *cdc_node;

        cdc_node = (CDC_NODE *)CLIST_DATA_DATA(clist_data);
        CDC_ASSERT(clist_data == CDC_NODE_MOUNTED_OWNERS(cdc_node));
        if(cur_time_ms >= CDC_NODE_NTIME_MS(cdc_node))
        {
            clist_data = CLIST_DATA_PREV(clist_data);

            cdc_page_del_node(cdc_page, cdc_node);

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_page_notify_timeout: "
                             "notify node %ld/%ld of req %ld timeout\n",
                             CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                             CDC_NODE_SEQ_NO(cdc_node));

            cdc_node_timeout(cdc_node);
        }
    }

    /*not free page*/

    return (EC_TRUE);
}

/*aio flush timeout*/
EC_BOOL cdc_page_flush_aio_timeout(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;
    CDC_NODE       *cdc_node;

    /*ATTENTION: should never reach here!*/

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    CDC_PAGE_FAIL_COUNTER(cdc_page) ++;

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio_timeout: "
                     "flush page [%ld, %ld) [crc %u] to [%ld, %ld) timeout [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                  CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    while(NULL_PTR != (cdc_node = cdc_page_pop_node_front(cdc_page)))
    {
        cdc_node_timeout(cdc_node);
    }

    cdc_page_unlock(cdc_page);

    /*retry*/
    /*note: never timeout due to that flush always tranfer data to caio and return succ at once*/
    /*      which means flush always succ*/
    if(EC_TRUE == cdc_discard_page(cdc_md, cdc_page) /*discard old page*/
    && CDC_AIO_FAIL_MAX_NUM > CDC_PAGE_FAIL_COUNTER(cdc_page)
    && EC_TRUE == cdc_reserve_page(cdc_md, cdc_page) /*reserve new page and bind item*/
    && EC_TRUE == cdc_locate_page(cdc_md, cdc_page)  /*set offset in ssd*/
    && EC_TRUE == cdc_page_flush_aio(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio_timeout: "
                         "flush page [%ld, %ld) [crc %u] to ssd [%ld, %ld) retry\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                  CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));

        return (EC_TRUE);
    }

    /*if degrade cmc data to ssd failed, purge sata page as bad*/
    if(EC_FALSE == cdc_page_purge_sata(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_flush_aio_timeout: "
                         "purge sata page [%ld, %ld) failed\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
    }
    else
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio_timeout: "
                         "purge sata page [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_flush_aio_timeout: "
                     "flush page [%ld, %ld) [crc %u] to ssd [%ld, %ld) retry and failed [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                              CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    cdc_page_free(cdc_page);
    return (EC_TRUE);
}

/*aio flush terminate*/
EC_BOOL cdc_page_flush_aio_terminate(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;
    CDC_NODE       *cdc_node;

    /*ATTENTION: should never reach here!*/

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    CDC_PAGE_FAIL_COUNTER(cdc_page) ++;

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio_terminate: "
                     "flush page [%ld, %ld) [crc %u] to [%ld, %ld) terminated [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    while(NULL_PTR != (cdc_node = cdc_page_pop_node_front(cdc_page)))
    {
        cdc_node_terminate(cdc_node);
    }

    cdc_page_unlock(cdc_page);

    /*retry*/
    /*note: never terminate due to that flush always tranfer data to caio and return succ at once*/
    /*      which means flush always succ*/
    if(EC_TRUE == cdc_discard_page(cdc_md, cdc_page) /*discard old page at first*/
    && CDC_AIO_FAIL_MAX_NUM > CDC_PAGE_FAIL_COUNTER(cdc_page)
    && EC_TRUE == cdc_reserve_page(cdc_md, cdc_page) /*reserve new page and bind item*/
    && EC_TRUE == cdc_locate_page(cdc_md, cdc_page)  /*set offset in ssd*/
    && EC_TRUE == cdc_page_flush_aio(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio_terminate: "
                         "flush page [%ld, %ld) [crc %u] to [%ld, %ld) retry\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));
        return (EC_TRUE);
    }

    /*if degrade cmc data to ssd failed, mark sata page as bad*/
    if(EC_FALSE == cdc_page_purge_sata(cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_flush_aio_terminate: "
                         "purge sata page [%ld, %ld) failed\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
    }
    else
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio_terminate: "
                         "purge sata page [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_flush_aio_terminate: "
                     "flush page [%ld, %ld) [crc %u] to [%ld, %ld) retry and failed [fail %u]\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page),
                     CDC_PAGE_FAIL_COUNTER(cdc_page));

    CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    cdc_page_free(cdc_page);
    return (EC_TRUE);
}

/*aio flush complete*/
EC_BOOL cdc_page_flush_aio_complete(CDC_PAGE *cdc_page)
{
    CDC_MD         *cdc_md;

    CDC_ASSERT(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page));
    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio_complete: "
                     "flush page [%ld, %ld) [crc %u] to [%ld, %ld) completed\n",
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                     CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                     CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));

    CDC_ASSERT(CDC_PAGE_D_T_OFFSET(cdc_page) == CDC_PAGE_D_E_OFFSET(cdc_page));

    CDC_PAGE_SSD_FLUSHING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

    if(NULL_PTR != CDC_PAGE_CDC_MD(cdc_page)
    && NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page)
    && CDC_PAGE_TREE_IDX_ERR != CDC_PAGE_MOUNTED_TREE_IDX(cdc_page))
    {
        cdc_del_page(cdc_md, CDC_PAGE_MOUNTED_TREE_IDX(cdc_page), cdc_page);
    }

    /*return to process procedure*/
    cdc_page_process(cdc_page, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md));

    return (EC_TRUE);
}

/*async model: flush page to ssd*/
EC_BOOL cdc_page_flush_aio(CDC_PAGE *cdc_page)
{
    CDC_MD          *cdc_md;
    CAIO_MD         *caio_md;
    CAIO_CB          caio_cb;

    cdc_md = CDC_PAGE_CDC_MD(cdc_page);
    CDC_ASSERT(NULL_PTR != CDC_MD_CAIO_MD(cdc_md));

    caio_md = CDC_MD_CAIO_MD(cdc_md);

    caio_cb_set_timeout_handler(&caio_cb, (UINT32)CDC_PAGE_TIMEOUT_NSEC(cdc_page),
                                (CAIO_CALLBACK)cdc_page_flush_aio_timeout, (void *)cdc_page);

    caio_cb_set_terminate_handler(&caio_cb,
                                (CAIO_CALLBACK)cdc_page_flush_aio_terminate, (void *)cdc_page);
    caio_cb_set_complete_handler(&caio_cb,
                                (CAIO_CALLBACK)cdc_page_flush_aio_complete, (void *)cdc_page);

    CDC_ASSERT(CDC_PAGE_F_S_OFFSET(cdc_page) + CDCPGB_PAGE_SIZE_NBYTES == CDC_PAGE_F_E_OFFSET(cdc_page));

    CDC_PAGE_D_T_OFFSET(cdc_page) = CDC_PAGE_D_S_OFFSET(cdc_page);

    if(EC_TRUE == caio_file_write(caio_md,
                                  CDC_PAGE_FD(cdc_page),
                                  &CDC_PAGE_D_T_OFFSET(cdc_page),
                                  CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page),
                                  CDC_PAGE_M_CACHE(cdc_page),
                                  &caio_cb))
    {
        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_flush_aio: "
                         "submit flushing page [%ld, %ld) [crc %u] to ssd [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page),
                         CDC_CRC32(CDC_PAGE_M_CACHE(cdc_page),
                                      CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page)),
                         CDC_PAGE_D_S_OFFSET(cdc_page), CDC_PAGE_D_E_OFFSET(cdc_page));

        cdc_page_lock(cdc_page);
        return (EC_TRUE);
    }

    /*WARNING: exception would be handled in terminate, */
    /*         and page cannot be accessed again! => do not output log*/

    return (EC_FALSE);
}

/*sync model: flush page to ssd*/
EC_BOOL cdc_page_flush(CDC_PAGE *cdc_page)
{
    CDC_MD                *cdc_md;

    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    CDC_PAGE_D_T_OFFSET(cdc_page) = CDC_PAGE_D_S_OFFSET(cdc_page); /*reset*/

    if(EC_FALSE == cdc_file_write(cdc_md,
                                &CDC_PAGE_D_T_OFFSET(cdc_page),
                                CDC_PAGE_D_E_OFFSET(cdc_page) - CDC_PAGE_D_S_OFFSET(cdc_page),
                                CDC_PAGE_M_CACHE(cdc_page)))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_page_flush: "
                                            "flush page [%ld, %ld) to ssd failed\n",
                                            CDC_PAGE_D_S_OFFSET(cdc_page),
                                            CDC_PAGE_D_E_OFFSET(cdc_page));

        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_page_flush: "
                                        "flush page [%ld, %ld) to ssd done\n",
                                        CDC_PAGE_D_S_OFFSET(cdc_page),
                                        CDC_PAGE_D_E_OFFSET(cdc_page));
    return (EC_TRUE);
}

EC_BOOL cdc_page_lock(CDC_PAGE *cdc_page)
{
    CDC_MD                *cdc_md;

    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_lock: cdc is read-only\n");
        return (EC_FALSE);
    }

    return cdc_lock_page(cdc_md, cdc_page);
}

EC_BOOL cdc_page_unlock(CDC_PAGE *cdc_page)
{
    CDC_MD                *cdc_md;

    cdc_md = CDC_PAGE_CDC_MD(cdc_page);

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_page_unlock: cdc is read-only\n");
        return (EC_FALSE);
    }

    return cdc_unlock_page(cdc_md, cdc_page);
}

/*----------------------------------- cdc node interface -----------------------------------*/

CDC_NODE *cdc_node_new()
{
    CDC_NODE *cdc_node;

    alloc_static_mem(MM_CDC_NODE, &cdc_node, LOC_CDC_0012);
    if(NULL_PTR == cdc_node)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_node_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    cdc_node_init(cdc_node);
    return (cdc_node);
}

EC_BOOL cdc_node_init(CDC_NODE *cdc_node)
{
    CDC_NODE_CDC_REQ(cdc_node)          = NULL_PTR;
    CDC_NODE_CDC_PAGE(cdc_node)         = NULL_PTR;

    CDC_NODE_SEQ_NO(cdc_node)           = 0;
    CDC_NODE_SUB_SEQ_NO(cdc_node)       = 0;
    CDC_NODE_SUB_SEQ_NUM(cdc_node)      = 0;
    CDC_NODE_OP(cdc_node)               = CDC_OP_ERR;

    CDC_NODE_CDC_MD(cdc_node)           = NULL_PTR;
    CDC_NODE_FD(cdc_node)               = ERR_FD;
    CDC_NODE_M_CACHE(cdc_node)          = NULL_PTR;
    CDC_NODE_M_BUFF(cdc_node)           = NULL_PTR;
    CDC_NODE_M_BUFF_FLAG(cdc_node)      = BIT_FALSE;
    CDC_NODE_SATA_DIRTY_FLAG(cdc_node)  = BIT_FALSE;
    CDC_NODE_SATA_DEG_FLAG(cdc_node)    = BIT_FALSE;
    CDC_NODE_F_S_OFFSET(cdc_node)       = 0;
    CDC_NODE_F_E_OFFSET(cdc_node)       = 0;
    CDC_NODE_B_S_OFFSET(cdc_node)       = 0;
    CDC_NODE_B_E_OFFSET(cdc_node)       = 0;
    CDC_NODE_TIMEOUT_NSEC(cdc_node)     = 0;
    CDC_NODE_NTIME_MS(cdc_node)         = 0;

    CDC_NODE_MOUNTED_NODES(cdc_node)    = NULL_PTR;
    CDC_NODE_MOUNTED_OWNERS(cdc_node)   = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdc_node_clean(CDC_NODE *cdc_node)
{
    if(NULL_PTR != cdc_node)
    {
        if(NULL_PTR != CDC_NODE_MOUNTED_NODES(cdc_node)
        && NULL_PTR != CDC_NODE_CDC_REQ(cdc_node))
        {
            cdc_req_del_node(CDC_NODE_CDC_REQ(cdc_node), cdc_node);
        }

        if(NULL_PTR != CDC_NODE_MOUNTED_OWNERS(cdc_node)
        && NULL_PTR != CDC_NODE_CDC_PAGE(cdc_node))
        {
            cdc_page_del_node(CDC_NODE_CDC_PAGE(cdc_node), cdc_node);
        }

        if(BIT_TRUE == CDC_NODE_M_BUFF_FLAG(cdc_node)
        && NULL_PTR != CDC_NODE_M_BUFF(cdc_node))
        {
            __cdc_mem_cache_free(CDC_NODE_M_BUFF(cdc_node));
            CDC_NODE_M_BUFF(cdc_node) = NULL_PTR;
            CDC_NODE_M_BUFF_FLAG(cdc_node) = BIT_FALSE;
        }

        CDC_NODE_CDC_REQ(cdc_node)          = NULL_PTR;
        CDC_NODE_CDC_PAGE(cdc_node)         = NULL_PTR;

        CDC_NODE_SEQ_NO(cdc_node)           = 0;
        CDC_NODE_SUB_SEQ_NO(cdc_node)       = 0;
        CDC_NODE_SUB_SEQ_NUM(cdc_node)      = 0;
        CDC_NODE_OP(cdc_node)               = CDC_OP_ERR;

        CDC_NODE_CDC_MD(cdc_node)           = NULL_PTR;
        CDC_NODE_FD(cdc_node)               = ERR_FD;
        CDC_NODE_M_CACHE(cdc_node)          = NULL_PTR;
        CDC_NODE_M_BUFF(cdc_node)           = NULL_PTR;
        CDC_NODE_M_BUFF_FLAG(cdc_node)      = BIT_FALSE;
        CDC_NODE_SATA_DIRTY_FLAG(cdc_node)  = BIT_FALSE;
        CDC_NODE_SATA_DEG_FLAG(cdc_node)    = BIT_FALSE;
        CDC_NODE_F_S_OFFSET(cdc_node)       = 0;
        CDC_NODE_F_E_OFFSET(cdc_node)       = 0;
        CDC_NODE_B_S_OFFSET(cdc_node)        = 0;
        CDC_NODE_B_E_OFFSET(cdc_node)       = 0;
        CDC_NODE_TIMEOUT_NSEC(cdc_node)     = 0;
        CDC_NODE_NTIME_MS(cdc_node)         = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cdc_node_free(CDC_NODE *cdc_node)
{
    if(NULL_PTR != cdc_node)
    {
        cdc_node_clean(cdc_node);
        free_static_mem(MM_CDC_NODE, cdc_node, LOC_CDC_0013);
    }
    return (EC_TRUE);
}

EC_BOOL cdc_node_is(const CDC_NODE *cdc_node, const UINT32 sub_seq_no)
{
    if(sub_seq_no == CDC_NODE_SUB_SEQ_NO(cdc_node))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

void cdc_node_print(LOG *log, const CDC_NODE *cdc_node)
{
    sys_log(log, "cdc_node_print: cdc_node %p: req %p, mounted at %p\n",
                 cdc_node,
                 CDC_NODE_CDC_REQ(cdc_node), CDC_NODE_MOUNTED_NODES(cdc_node));

    sys_log(log, "cdc_node_print: cdc_node %p: page %p, mounted at %p\n",
                 cdc_node,
                 CDC_NODE_CDC_PAGE(cdc_node), CDC_NODE_MOUNTED_OWNERS(cdc_node));

    sys_log(log, "cdc_node_print: cdc_node %p: seq no %ld, sub seq no %ld, sub seq num %ld, op %s\n",
                 cdc_node,
                 CDC_NODE_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NO(cdc_node),
                 CDC_NODE_SUB_SEQ_NUM(cdc_node),
                 __cdc_op_str(CDC_NODE_OP(cdc_node)));

    sys_log(log, "cdc_node_print: cdc_node %p: fd %d, m_cache %p, m_buff %p, "
                 "file range [%ld, %ld), block range [%ld, %ld), "
                 "timeout %ld seconds, next access time %ld\n",
                 cdc_node, CDC_NODE_FD(cdc_node),
                 CDC_NODE_M_CACHE(cdc_node), CDC_NODE_M_BUFF(cdc_node),
                 CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node),
                 CDC_NODE_B_S_OFFSET(cdc_node), CDC_NODE_B_E_OFFSET(cdc_node),
                 CDC_NODE_TIMEOUT_NSEC(cdc_node), CDC_NODE_NTIME_MS(cdc_node));

    return;
}

EC_BOOL cdc_node_timeout(CDC_NODE *cdc_node)
{
    CDC_REQ        *cdc_req;

    if(do_log(SEC_0182_CDC, 9))
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_node_timeout: "
                         "node %ld/%ld of req %ld => timeout\n",
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node));
        cdc_node_print(LOGSTDOUT, cdc_node);

        cdc_req_print(LOGSTDOUT, CDC_NODE_CDC_REQ(cdc_node));
    }

    /*exception*/
    if(NULL_PTR == CDC_NODE_CDC_REQ(cdc_node))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_node_timeout: "
                         "node %ld/%ld of req %ld => timeout but req is null => free cdc_node\n",
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node));

        cdc_node_free(cdc_node);
        return (EC_TRUE);
    }

    CDC_ASSERT(NULL_PTR != CDC_NODE_CDC_REQ(cdc_node));
    cdc_req = CDC_NODE_CDC_REQ(cdc_node);

    /*update parent request*/
    if(CDC_NODE_F_S_OFFSET(cdc_node) < CDC_REQ_U_E_OFFSET(cdc_req))
    {
        CDC_REQ_U_E_OFFSET(cdc_req) = CDC_NODE_F_S_OFFSET(cdc_node);
    }

    cdc_req_del_node(cdc_req, cdc_node);
    cdc_node_free(cdc_node);

    return cdc_req_timeout(cdc_req);
}

EC_BOOL cdc_node_terminate(CDC_NODE *cdc_node)
{
    CDC_REQ        *cdc_req;

    if(do_log(SEC_0182_CDC, 9))
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_node_terminate: "
                         "node %ld/%ld of req %ld => terminate\n",
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node));
        cdc_node_print(LOGSTDOUT, cdc_node);
    }

    /*exception*/
    if(NULL_PTR == CDC_NODE_CDC_REQ(cdc_node))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_node_terminate: "
                         "node %ld/%ld of req %ld => terminate but req is null => free cdc_node\n",
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node));

        cdc_node_free(cdc_node);
        return (EC_TRUE);
    }

    CDC_ASSERT(NULL_PTR != CDC_NODE_CDC_REQ(cdc_node));
    cdc_req = CDC_NODE_CDC_REQ(cdc_node);

    /*update parent request*/
    if(CDC_NODE_F_S_OFFSET(cdc_node) < CDC_REQ_U_E_OFFSET(cdc_req))
    {
        CDC_REQ_U_E_OFFSET(cdc_req) = CDC_NODE_F_S_OFFSET(cdc_node);
    }

    cdc_req_del_node(cdc_req, cdc_node);
    cdc_node_free(cdc_node);

    return cdc_req_terminate(cdc_req);
}

EC_BOOL cdc_node_complete(CDC_NODE *cdc_node)
{
    CDC_REQ        *cdc_req;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_node_complete: "
                     "node %ld/%ld of req %ld => complete\n",
                     CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                     CDC_NODE_SEQ_NO(cdc_node));

    CDC_ASSERT(NULL_PTR != CDC_NODE_CDC_REQ(cdc_node));
    cdc_req = CDC_NODE_CDC_REQ(cdc_node);

    /*update parent request*/
    CDC_REQ_SUCC_NUM(cdc_req) ++;

    cdc_req_del_node(cdc_req, cdc_node);
    cdc_node_free(cdc_node);

    if(CDC_REQ_SUCC_NUM(cdc_req) >= CDC_REQ_NODE_NUM(cdc_req))
    {
        return cdc_req_complete(cdc_req);
    }

    return (EC_TRUE);
}

/*----------------------------------- cdc req interface -----------------------------------*/

CDC_REQ *cdc_req_new()
{
    CDC_REQ *cdc_req;

    alloc_static_mem(MM_CDC_REQ, &cdc_req, LOC_CDC_0014);
    if(NULL_PTR == cdc_req)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_new: alloc memory failed\n");
        return (NULL_PTR);
    }

    cdc_req_init(cdc_req);
    return (cdc_req);
}

EC_BOOL cdc_req_init(CDC_REQ *cdc_req)
{
    caio_cb_init(CDC_REQ_CAIO_CB(cdc_req));

    CDC_REQ_SEQ_NO(cdc_req)                   = 0;
    CDC_REQ_OP(cdc_req)                       = CDC_OP_ERR;

    CDC_REQ_SUB_SEQ_NUM(cdc_req)              = 0;
    CDC_REQ_NODE_NUM(cdc_req)                 = 0;
    CDC_REQ_SUCC_NUM(cdc_req)                 = 0;
    CDC_REQ_U_E_OFFSET(cdc_req)               = 0;

    CDC_REQ_CDC_MD(cdc_req)                   = NULL_PTR;
    CDC_REQ_FD(cdc_req)                       = ERR_FD;
    CDC_REQ_DETACHED_FLAG(cdc_req)            = BIT_FALSE;
    CDC_REQ_KEEP_LRU_FLAG(cdc_req)            = BIT_FALSE;
    CDC_REQ_SATA_DIRTY_FLAG(cdc_req)          = BIT_FALSE;
    CDC_REQ_SATA_DEG_FLAG(cdc_req)            = BIT_FALSE;
    CDC_REQ_M_CACHE(cdc_req)                  = NULL_PTR;
    CDC_REQ_M_BUFF(cdc_req)                   = NULL_PTR;
    CDC_REQ_OFFSET(cdc_req)                   = NULL_PTR;
    CDC_REQ_F_S_OFFSET(cdc_req)               = 0;
    CDC_REQ_F_E_OFFSET(cdc_req)               = 0;
    CDC_REQ_TIMEOUT_NSEC(cdc_req)             = 0;
    CDC_REQ_NTIME_MS(cdc_req)                 = 0;

    CDC_REQ_POST_EVENT_HANDLER(cdc_req)       = NULL_PTR;
    CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req)  = NULL_PTR;

    clist_init(CDC_REQ_NODES(cdc_req), MM_CDC_NODE, LOC_CDC_0015);

    CDC_REQ_MOUNTED_REQS(cdc_req)             = NULL_PTR;

    return (EC_TRUE);
}

EC_BOOL cdc_req_clean(CDC_REQ *cdc_req)
{
    if(NULL_PTR != cdc_req)
    {
        if(NULL_PTR != CDC_REQ_MOUNTED_REQS(cdc_req)
        && NULL_PTR != CDC_REQ_CDC_MD(cdc_req))
        {
            cdc_del_req(CDC_REQ_CDC_MD(cdc_req), cdc_req);
        }

        if(NULL_PTR != CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req))
        {
            cdc_req_del_post_event(cdc_req);
        }

        cdc_req_cleanup_nodes(cdc_req);

        caio_cb_clean(CDC_REQ_CAIO_CB(cdc_req));

        CDC_REQ_SEQ_NO(cdc_req)                   = 0;
        CDC_REQ_OP(cdc_req)                       = CDC_OP_ERR;

        CDC_REQ_SUB_SEQ_NUM(cdc_req)              = 0;
        CDC_REQ_NODE_NUM(cdc_req)                 = 0;
        CDC_REQ_SUCC_NUM(cdc_req)                 = 0;
        CDC_REQ_U_E_OFFSET(cdc_req)               = 0;

        CDC_REQ_CDC_MD(cdc_req)                   = NULL_PTR;
        CDC_REQ_FD(cdc_req)                       = ERR_FD;
        CDC_REQ_DETACHED_FLAG(cdc_req)            = BIT_FALSE;
        CDC_REQ_KEEP_LRU_FLAG(cdc_req)            = BIT_FALSE;
        CDC_REQ_SATA_DIRTY_FLAG(cdc_req)          = BIT_FALSE;
        CDC_REQ_SATA_DEG_FLAG(cdc_req)            = BIT_FALSE;
        CDC_REQ_M_CACHE(cdc_req)                  = NULL_PTR;
        CDC_REQ_M_BUFF(cdc_req)                   = NULL_PTR;
        CDC_REQ_OFFSET(cdc_req)                   = NULL_PTR;
        CDC_REQ_F_S_OFFSET(cdc_req)               = 0;
        CDC_REQ_F_E_OFFSET(cdc_req)               = 0;
        CDC_REQ_TIMEOUT_NSEC(cdc_req)             = 0;
        CDC_REQ_NTIME_MS(cdc_req)                 = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cdc_req_free(CDC_REQ *cdc_req)
{
    if(NULL_PTR != cdc_req)
    {
        cdc_req_clean(cdc_req);
        free_static_mem(MM_CDC_REQ, cdc_req, LOC_CDC_0016);
    }
    return (EC_TRUE);
}

EC_BOOL cdc_req_exec_timeout_handler(CDC_REQ *cdc_req)
{
    if(NULL_PTR != cdc_req)
    {
        CAIO_CB     caio_cb;

        caio_cb_clone(CDC_REQ_CAIO_CB(cdc_req), &caio_cb);
        cdc_req_free(cdc_req);

        return caio_cb_exec_timeout_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL cdc_req_exec_terminate_handler(CDC_REQ *cdc_req)
{
    if(NULL_PTR != cdc_req)
    {
        CAIO_CB     caio_cb;

        caio_cb_clone(CDC_REQ_CAIO_CB(cdc_req), &caio_cb);
        cdc_req_free(cdc_req);

        return caio_cb_exec_terminate_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL cdc_req_exec_complete_handler(CDC_REQ *cdc_req)
{
    if(NULL_PTR != cdc_req)
    {
        CAIO_CB     caio_cb;

        caio_cb_clone(CDC_REQ_CAIO_CB(cdc_req), &caio_cb);
        cdc_req_free(cdc_req);

        return caio_cb_exec_complete_handler(&caio_cb);
    }

    return (EC_FALSE);
}

EC_BOOL cdc_req_set_post_event(CDC_REQ *cdc_req, CDC_EVENT_HANDLER handler)
{
    CDC_MD     *cdc_md;

    if(NULL_PTR == CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req))
    {
        CDC_ASSERT(NULL_PTR != CDC_REQ_CDC_MD(cdc_req));

        cdc_md = CDC_REQ_CDC_MD(cdc_req);

        CDC_REQ_POST_EVENT_HANDLER(cdc_req) = handler;

        CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req) =
                clist_push_back(CDC_MD_POST_EVENT_REQS(cdc_md), (void *)cdc_req);
    }
    return (EC_TRUE);
}

EC_BOOL cdc_req_del_post_event(CDC_REQ *cdc_req)
{
    CDC_MD         *cdc_md;

    CDC_ASSERT(NULL_PTR != CDC_REQ_CDC_MD(cdc_req));

    cdc_md = CDC_REQ_CDC_MD(cdc_req);

    CDC_REQ_POST_EVENT_HANDLER(cdc_req) = NULL_PTR;

    if(NULL_PTR != CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req))
    {
        clist_erase(CDC_MD_POST_EVENT_REQS(cdc_md), CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req));
        CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req) = NULL_PTR;
    }

    return (EC_TRUE);
}

EC_BOOL cdc_req_is(const CDC_REQ *cdc_req, const UINT32 seq_no)
{
    if(seq_no == CDC_REQ_SEQ_NO(cdc_req))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}


void cdc_req_print(LOG *log, const CDC_REQ *cdc_req)
{
    sys_log(log, "cdc_req_print: cdc_req %p: caio_cb: \n", cdc_req);
    caio_cb_print(log, CDC_REQ_CAIO_CB(cdc_req));

    sys_log(log, "cdc_req_print: cdc_req %p: seq no %ld, sub seq num %ld, node num %ld, op %s\n",
                 cdc_req, CDC_REQ_SEQ_NO(cdc_req), CDC_REQ_SUB_SEQ_NUM(cdc_req),
                 CDC_REQ_NODE_NUM(cdc_req),
                 __cdc_op_str(CDC_REQ_OP(cdc_req)));

    if(NULL_PTR != CDC_REQ_OFFSET(cdc_req))
    {
        sys_log(log, "cdc_req_print: cdc_req %p: fd %d, m_cache %p, m_buff %p, "
                     "offset %p (%ld), range [%ld, %ld), "
                     "timeout %ld seconds, next access time %ld\n",
                     cdc_req, CDC_REQ_FD(cdc_req), CDC_REQ_M_CACHE(cdc_req), CDC_REQ_M_BUFF(cdc_req),
                     CDC_REQ_OFFSET(cdc_req), (*CDC_REQ_OFFSET(cdc_req)),
                     CDC_REQ_F_S_OFFSET(cdc_req), CDC_REQ_F_E_OFFSET(cdc_req),
                     CDC_REQ_TIMEOUT_NSEC(cdc_req), CDC_REQ_NTIME_MS(cdc_req));
    }
    else
    {
        sys_log(log, "cdc_req_print: cdc_req %p: fd %d, m_cache %p, m_buff %p, "
                     "offset (null), range [%ld, %ld), "
                     "timeout %ld seconds, next access time %ld\n",
                     cdc_req, CDC_REQ_FD(cdc_req), CDC_REQ_M_CACHE(cdc_req), CDC_REQ_M_BUFF(cdc_req),
                     CDC_REQ_F_S_OFFSET(cdc_req), CDC_REQ_F_E_OFFSET(cdc_req),
                     CDC_REQ_TIMEOUT_NSEC(cdc_req), CDC_REQ_NTIME_MS(cdc_req));
    }

    sys_log(log, "cdc_req_print: cdc_req %p: nodes: \n", cdc_req);
    clist_print(log, CDC_REQ_NODES(cdc_req), (CLIST_DATA_DATA_PRINT)cdc_node_print);
    return;
}

EC_BOOL cdc_req_cleanup_nodes(CDC_REQ *cdc_req)
{
    CDC_NODE       *cdc_node;

    /*clean up nodes*/
    while(NULL_PTR != (cdc_node = cdc_req_pop_node_back(cdc_req)))
    {
        cdc_node_free(cdc_node);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_req_push_node_back(CDC_REQ *cdc_req, CDC_NODE *cdc_node)
{
    CDC_ASSERT(CDC_NODE_SEQ_NO(cdc_node) == CDC_REQ_SEQ_NO(cdc_req));

    /*mount*/
    CDC_NODE_MOUNTED_NODES(cdc_node) = clist_push_back(CDC_REQ_NODES(cdc_req), (void *)cdc_node);
    if(NULL_PTR == CDC_NODE_MOUNTED_NODES(cdc_node))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_push_node_back: "
                                            "push node %ld to req %ld, op %s failed\n",
                                            CDC_NODE_SUB_SEQ_NO(cdc_node),
                                            CDC_REQ_SEQ_NO(cdc_req),
                                            __cdc_op_str(CDC_REQ_OP(cdc_req)));
        return (EC_FALSE);
    }

    CDC_NODE_CDC_REQ(cdc_node) = cdc_req; /*bind*/

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_push_node_back: "
                                        "push node %ld to req %ld, op %s done\n",
                                        CDC_NODE_SUB_SEQ_NO(cdc_node),
                                        CDC_REQ_SEQ_NO(cdc_req),
                                        __cdc_op_str(CDC_REQ_OP(cdc_req)));
    return (EC_TRUE);
}

CDC_NODE *cdc_req_pop_node_back(CDC_REQ *cdc_req)
{
    if(NULL_PTR != cdc_req)
    {
        CDC_NODE *cdc_node;

        cdc_node = clist_pop_back(CDC_REQ_NODES(cdc_req));
        if(NULL_PTR != cdc_node)
        {
            CDC_ASSERT(CDC_NODE_CDC_REQ(cdc_node) == cdc_req);

            CDC_NODE_MOUNTED_NODES(cdc_node) = NULL_PTR; /*umount*/
            CDC_NODE_CDC_REQ(cdc_node)       = NULL_PTR; /*unbind*/

            return (cdc_node);
        }
        return (NULL_PTR);
    }

    return (NULL_PTR);
}

EC_BOOL cdc_req_push_node_front(CDC_REQ *cdc_req, CDC_NODE *cdc_node)
{
    CDC_ASSERT(CDC_NODE_SEQ_NO(cdc_node) == CDC_REQ_SEQ_NO(cdc_req));

    /*mount*/
    CDC_NODE_MOUNTED_NODES(cdc_node) = clist_push_front(CDC_REQ_NODES(cdc_req), (void *)cdc_node);
    if(NULL_PTR == CDC_NODE_MOUNTED_NODES(cdc_node))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_push_node_front: "
                                            "push node %ld to req %ld, op %s failed\n",
                                            CDC_NODE_SUB_SEQ_NO(cdc_node),
                                            CDC_REQ_SEQ_NO(cdc_req),
                                            __cdc_op_str(CDC_REQ_OP(cdc_req)));
        return (EC_FALSE);
    }

    CDC_NODE_CDC_REQ(cdc_node) = cdc_req; /*bind*/

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_push_node_front: "
                                        "push node %ld to req %ld, op %s done\n",
                                        CDC_NODE_SUB_SEQ_NO(cdc_node),
                                        CDC_REQ_SEQ_NO(cdc_req),
                                        __cdc_op_str(CDC_REQ_OP(cdc_req)));
    return (EC_TRUE);
}

CDC_NODE *cdc_req_pop_node_front(CDC_REQ *cdc_req)
{
    if(NULL_PTR != cdc_req)
    {
        CDC_NODE *cdc_node;

        cdc_node = clist_pop_front(CDC_REQ_NODES(cdc_req));
        if(NULL_PTR != cdc_node)
        {
            CDC_ASSERT(CDC_NODE_CDC_REQ(cdc_node) == cdc_req);

            CDC_NODE_MOUNTED_NODES(cdc_node) = NULL_PTR; /*umount*/
            CDC_NODE_CDC_REQ(cdc_node)       = NULL_PTR; /*unbind*/

            return (cdc_node);
        }
        return (NULL_PTR);
    }

    return (NULL_PTR);
}

EC_BOOL cdc_req_del_node(CDC_REQ *cdc_req, CDC_NODE *cdc_node)
{
    CDC_ASSERT(CDC_NODE_SEQ_NO(cdc_node) == CDC_REQ_SEQ_NO(cdc_req));

    if(NULL_PTR != CDC_NODE_MOUNTED_NODES(cdc_node))
    {
        clist_erase(CDC_REQ_NODES(cdc_req), CDC_NODE_MOUNTED_NODES(cdc_node));
        CDC_NODE_MOUNTED_NODES(cdc_node) = NULL_PTR; /*umount*/
        CDC_NODE_CDC_REQ(cdc_node)       = NULL_PTR; /*unbind*/

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_del_node: "
                                            "pop node %ld from req %ld, op %s done\n",
                                            CDC_NODE_SUB_SEQ_NO(cdc_node),
                                            CDC_REQ_SEQ_NO(cdc_req),
                                            __cdc_op_str(CDC_REQ_OP(cdc_req)));

    }
    return (EC_TRUE);
}

EC_BOOL cdc_req_reorder_sub_seq_no(CDC_REQ *cdc_req)
{
    UINT32       sub_seq_no;
    UINT32       sub_seq_num;
    CLIST_DATA  *clist_data;

    sub_seq_no  = 0;
    sub_seq_num = CDC_REQ_SUB_SEQ_NUM(cdc_req);

    CLIST_LOOP_NEXT(CDC_REQ_NODES(cdc_req), clist_data)
    {
        CDC_NODE *cdc_node;

        cdc_node = (CDC_NODE *)CLIST_DATA_DATA(clist_data);

        CDC_NODE_SUB_SEQ_NO(cdc_node)  = ++ sub_seq_no;
        CDC_NODE_SUB_SEQ_NUM(cdc_node) = sub_seq_num;
    }

    CDC_ASSERT(sub_seq_no == sub_seq_num);

    return (EC_TRUE);
}

EC_BOOL cdc_req_make_read_op(CDC_REQ *cdc_req)
{
    UINT32              f_s_offset;
    UINT32              f_e_offset;

    UINT8              *m_buff;

    CDC_ASSERT(NULL_PTR != CDC_REQ_CDC_MD(cdc_req));

    f_s_offset = CDC_REQ_F_S_OFFSET(cdc_req);
    f_e_offset = CDC_REQ_F_E_OFFSET(cdc_req);
    m_buff     = (UINT8 *)CDC_REQ_M_BUFF(cdc_req);

    while(f_s_offset < f_e_offset)
    {
        UINT32              b_s_offset;
        UINT32              b_e_offset;

        CDC_NODE          *cdc_node;

        b_s_offset = f_s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK);
        f_s_offset = f_s_offset & (~((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to page starting*/

        b_e_offset = DMIN(f_s_offset + CDCPGB_PAGE_SIZE_NBYTES, f_e_offset) & ((UINT32)CDCPGB_PAGE_SIZE_MASK);
        if(0 == b_e_offset) /*adjust to next page boundary*/
        {
            b_e_offset = CDCPGB_PAGE_SIZE_NBYTES;
        }

        /*set up sub request*/
        cdc_node = cdc_node_new();
        if(NULL_PTR == cdc_node)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_read_op: "
                                                 "new cdc_node failed\n");
            return (EC_FALSE);
        }

        CDC_NODE_OP(cdc_node)               = CDC_OP_RD;

        /*inherited data from cdc req*/
        CDC_NODE_CDC_REQ(cdc_node)          = cdc_req;
        CDC_NODE_SEQ_NO(cdc_node)           = CDC_REQ_SEQ_NO(cdc_req);
        CDC_NODE_SUB_SEQ_NO(cdc_node)       = ++ CDC_REQ_SUB_SEQ_NUM(cdc_req);
        CDC_NODE_CDC_MD(cdc_node)           = CDC_REQ_CDC_MD(cdc_req);
        CDC_NODE_FD(cdc_node)               = CDC_REQ_FD(cdc_req);
        CDC_NODE_SATA_DEG_FLAG(cdc_node)    = CDC_REQ_SATA_DEG_FLAG(cdc_req); /*xxx*/
        CDC_NODE_M_CACHE(cdc_node)          = NULL_PTR;
        CDC_NODE_M_BUFF(cdc_node)           = m_buff;
        CDC_NODE_F_S_OFFSET(cdc_node)       = f_s_offset;
        CDC_NODE_F_E_OFFSET(cdc_node)       = f_s_offset + CDCPGB_PAGE_SIZE_NBYTES;
        CDC_NODE_B_S_OFFSET(cdc_node)       = b_s_offset;
        CDC_NODE_B_E_OFFSET(cdc_node)       = b_e_offset;
        CDC_NODE_TIMEOUT_NSEC(cdc_node)     = CDC_REQ_TIMEOUT_NSEC(cdc_req);
        CDC_NODE_NTIME_MS(cdc_node)         = CDC_REQ_NTIME_MS(cdc_req);

        /*bind: push back & mount*/
        if(EC_FALSE == cdc_req_push_node_back(cdc_req, cdc_node))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_read_op: "
                                                "push node %ld to req %ld, op %s failed\n",
                                                CDC_NODE_SUB_SEQ_NO(cdc_node),
                                                CDC_REQ_SEQ_NO(cdc_req),
                                                __cdc_op_str(CDC_REQ_OP(cdc_req)));
            cdc_node_free(cdc_node);
            return (EC_FALSE);
        }

        m_buff     += b_e_offset - b_s_offset;
        f_s_offset += CDCPGB_PAGE_SIZE_NBYTES;/*align to next page starting*/
    }

    return (EC_TRUE);
}

EC_BOOL cdc_req_make_write_op(CDC_REQ *cdc_req)
{
    UINT32              f_s_offset;
    UINT32              f_e_offset;

    UINT8              *m_buff;

    CDC_ASSERT(NULL_PTR != CDC_REQ_CDC_MD(cdc_req));

    f_s_offset = CDC_REQ_F_S_OFFSET(cdc_req);
    f_e_offset = CDC_REQ_F_E_OFFSET(cdc_req);
    m_buff     = (UINT8 *)CDC_REQ_M_BUFF(cdc_req);

    while(f_s_offset < f_e_offset)
    {
        UINT32              b_s_offset;
        UINT32              b_e_offset;

        CDC_NODE          *cdc_node;

        b_s_offset  = f_s_offset & ((UINT32)CDCPGB_PAGE_SIZE_MASK);
        f_s_offset  = f_s_offset & (~((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to page starting*/

        b_e_offset  = DMIN(f_s_offset + CDCPGB_PAGE_SIZE_NBYTES, f_e_offset) & ((UINT32)CDCPGB_PAGE_SIZE_MASK);
        if(0 == b_e_offset) /*adjust to next page boundary*/
        {
            b_e_offset = CDCPGB_PAGE_SIZE_NBYTES;
        }

        /*set up sub request*/
        cdc_node = cdc_node_new();
        if(NULL_PTR == cdc_node)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_write_op: "
                                                "new cdc_node failed\n");
            return (EC_FALSE);
        }

        CDC_NODE_OP(cdc_node)           = CDC_OP_WR;

        if(BIT_TRUE == CDC_REQ_DETACHED_FLAG(cdc_req))
        {
            CDC_NODE_M_BUFF(cdc_node) = __cdc_mem_cache_new(CDCPGB_PAGE_SIZE_NBYTES, CDCPGB_PAGE_SIZE_NBYTES);
            if(NULL_PTR == CDC_NODE_M_BUFF(cdc_node))
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_write_op: "
                                 "new mem cache for file [%ld, %ld) failed\n",
                                 f_s_offset, f_s_offset + CDCPGB_PAGE_SIZE_NBYTES);

                cdc_node_free(cdc_node);
                return (EC_FALSE);
            }

            /*copy data from application mem buff to mem cache*/
            FCOPY(m_buff, CDC_NODE_M_BUFF(cdc_node), b_e_offset - b_s_offset);
            CDC_NODE_M_BUFF_FLAG(cdc_node) = BIT_TRUE;
        }
        else
        {
            CDC_NODE_M_BUFF(cdc_node)      = NULL_PTR;
            CDC_NODE_M_BUFF_FLAG(cdc_node) = BIT_FALSE;
        }

        /*inherited data from cdc req*/
        CDC_NODE_CDC_REQ(cdc_node)          = cdc_req;
        CDC_NODE_SEQ_NO(cdc_node)           = CDC_REQ_SEQ_NO(cdc_req);
        CDC_NODE_SUB_SEQ_NO(cdc_node)       = ++ CDC_REQ_SUB_SEQ_NUM(cdc_req);
        CDC_NODE_CDC_MD(cdc_node)           = CDC_REQ_CDC_MD(cdc_req);
        CDC_NODE_FD(cdc_node)               = CDC_REQ_FD(cdc_req);
        CDC_NODE_M_CACHE(cdc_node)          = NULL_PTR;
        /*CDC_NODE_M_BUFF(cdc_node)         = m_buff;*/
        CDC_NODE_SATA_DIRTY_FLAG(cdc_node)  = CDC_REQ_SATA_DIRTY_FLAG(cdc_req); /*xxx*/
        CDC_NODE_F_S_OFFSET(cdc_node)       = f_s_offset;
        CDC_NODE_F_E_OFFSET(cdc_node)       = f_s_offset + CDCPGB_PAGE_SIZE_NBYTES;
        CDC_NODE_B_S_OFFSET(cdc_node)       = b_s_offset;
        CDC_NODE_B_E_OFFSET(cdc_node)       = b_e_offset;
        CDC_NODE_TIMEOUT_NSEC(cdc_node)     = CDC_REQ_TIMEOUT_NSEC(cdc_req);
        CDC_NODE_NTIME_MS(cdc_node)         = CDC_REQ_NTIME_MS(cdc_req);

        /*bind: push back & mount*/
        if(EC_FALSE == cdc_req_push_node_back(cdc_req, cdc_node))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_write_op: "
                                                "push node %ld to req %ld, op %s failed\n",
                                                CDC_NODE_SUB_SEQ_NO(cdc_node),
                                                CDC_REQ_SEQ_NO(cdc_req),
                                                __cdc_op_str(CDC_REQ_OP(cdc_req)));
            cdc_node_free(cdc_node);
            return (EC_FALSE);
        }

        m_buff     += b_e_offset - b_s_offset;
        f_s_offset += CDCPGB_PAGE_SIZE_NBYTES;/*align to next page starting*/
    }

    return (EC_TRUE);
}

EC_BOOL cdc_req_make_read(CDC_REQ *cdc_req)
{
    if(EC_FALSE == cdc_req_make_read_op(cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_read: "
                                            "make read op of req %ld failed\n",
                                            CDC_REQ_SEQ_NO(cdc_req));
        return (EC_FALSE);
    }

    /*here re-order always for debug purpose due to recording sub seq num info in node*/
    cdc_req_reorder_sub_seq_no(cdc_req);

    CDC_REQ_NODE_NUM(cdc_req) = CDC_REQ_SUB_SEQ_NUM(cdc_req); /*init*/

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_make_read: "
                                        "make %ld ops of req %ld, op %s done\n",
                                        CDC_REQ_SUB_SEQ_NUM(cdc_req),
                                        CDC_REQ_SEQ_NO(cdc_req),
                                        __cdc_op_str(CDC_REQ_OP(cdc_req)));

    return (EC_TRUE);
}

EC_BOOL cdc_req_make_write(CDC_REQ *cdc_req)
{
    UINT32              cdc_node_num;
    UINT32              s_offset;
    UINT32              e_offset;
    UINT32              rd_flag;

    if(EC_FALSE == cdc_req_make_write_op(cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_write: "
                                            "make write op of req %ld failed\n",
                                            CDC_REQ_SEQ_NO(cdc_req));
        return (EC_FALSE);
    }

    s_offset = CDC_REQ_F_S_OFFSET(cdc_req);
    e_offset = CDC_REQ_F_E_OFFSET(cdc_req);

    CDC_ASSERT(clist_size(CDC_REQ_NODES(cdc_req)) == CDC_REQ_SUB_SEQ_NUM(cdc_req));

    cdc_node_num = clist_size(CDC_REQ_NODES(cdc_req)); /*save node num*/
    rd_flag       = BIT_FALSE; /*init*/

    if(1 == cdc_node_num)
    {
        if((((UINT32)CDCPGB_PAGE_SIZE_MASK) & s_offset) || (((UINT32)CDCPGB_PAGE_SIZE_MASK) & e_offset))
        {
            CDC_NODE           *cdc_node;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read sub request*/
            cdc_node = cdc_node_new();
            if(NULL_PTR == cdc_node)
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_write: "
                                                    "new cdc_node failed\n");
                return (EC_FALSE);
            }

            /*the unique page*/
            f_s_offset = s_offset & (~((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = CDCPGB_PAGE_SIZE_NBYTES;

            CDC_NODE_OP(cdc_node)           = CDC_OP_RD;

            /*inherited data from cdc req*/
            CDC_NODE_CDC_REQ(cdc_node)      = cdc_req;
            CDC_NODE_SEQ_NO(cdc_node)       = CDC_REQ_SEQ_NO(cdc_req);
            CDC_NODE_SUB_SEQ_NO(cdc_node)   = ++ CDC_REQ_SUB_SEQ_NUM(cdc_req); /*would re-order later*/
            CDC_NODE_CDC_MD(cdc_node)       = CDC_REQ_CDC_MD(cdc_req);
            CDC_NODE_FD(cdc_node)           = CDC_REQ_FD(cdc_req);
            CDC_NODE_M_CACHE(cdc_node)      = NULL_PTR;
            CDC_NODE_M_BUFF(cdc_node)       = NULL_PTR; /*inherit only for write operation*/
            CDC_NODE_F_S_OFFSET(cdc_node)   = f_s_offset;
            CDC_NODE_F_E_OFFSET(cdc_node)   = f_s_offset + CDCPGB_PAGE_SIZE_NBYTES;
            CDC_NODE_B_S_OFFSET(cdc_node)   = b_s_offset;
            CDC_NODE_B_E_OFFSET(cdc_node)   = b_e_offset;
            CDC_NODE_TIMEOUT_NSEC(cdc_node) = CDC_REQ_TIMEOUT_NSEC(cdc_req);
            CDC_NODE_NTIME_MS(cdc_node)     = CDC_REQ_NTIME_MS(cdc_req);

            /*push front & bind*/
            cdc_req_push_node_front(cdc_req, cdc_node);

            rd_flag = BIT_TRUE;
        }
    }

    if(1 < cdc_node_num)
    {
        if(((UINT32)CDCPGB_PAGE_SIZE_MASK) & s_offset)
        {
            CDC_NODE           *cdc_node;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read aio request*/
            cdc_node = cdc_node_new();
            if(NULL_PTR == cdc_node)
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_write: "
                                                    "new cdc_node failed\n");
                return (EC_FALSE);
            }

            /*the first page*/
            f_s_offset = s_offset & (~((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = CDCPGB_PAGE_SIZE_NBYTES;

            CDC_NODE_OP(cdc_node)           = CDC_OP_RD;

            /*inherited data from cdc req*/
            CDC_NODE_CDC_REQ(cdc_node)      = cdc_req;
            CDC_NODE_SEQ_NO(cdc_node)       = CDC_REQ_SEQ_NO(cdc_req);
            CDC_NODE_SUB_SEQ_NO(cdc_node)   = ++ CDC_REQ_SUB_SEQ_NUM(cdc_req); /*would re-order later*/
            CDC_NODE_CDC_MD(cdc_node)       = CDC_REQ_CDC_MD(cdc_req);
            CDC_NODE_FD(cdc_node)           = CDC_REQ_FD(cdc_req);
            CDC_NODE_M_CACHE(cdc_node)      = NULL_PTR;
            CDC_NODE_M_BUFF(cdc_node)       = NULL_PTR; /*inherit only for write operation*/
            CDC_NODE_F_S_OFFSET(cdc_node)   = f_s_offset;
            CDC_NODE_F_E_OFFSET(cdc_node)   = f_s_offset + CDCPGB_PAGE_SIZE_NBYTES;
            CDC_NODE_B_S_OFFSET(cdc_node)   = b_s_offset;
            CDC_NODE_B_E_OFFSET(cdc_node)   = b_e_offset;
            CDC_NODE_TIMEOUT_NSEC(cdc_node) = CDC_REQ_TIMEOUT_NSEC(cdc_req);
            CDC_NODE_NTIME_MS(cdc_node)     = CDC_REQ_NTIME_MS(cdc_req);

            /*bind: push front & mount*/
            cdc_req_push_node_front(cdc_req, cdc_node);

            rd_flag = BIT_TRUE;
        }

        if(((UINT32)CDCPGB_PAGE_SIZE_MASK) & e_offset)
        {
            CDC_NODE           *cdc_node;
            CDC_NODE           *cdc_node_saved;

            UINT32              f_s_offset;

            UINT32              b_s_offset;
            UINT32              b_e_offset;

            /*set up read sub request*/
            cdc_node = cdc_node_new();
            if(NULL_PTR == cdc_node)
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_make_write: "
                                                    "new cdc_node failed\n");
                return (EC_FALSE);
            }

            /*the last page*/
            f_s_offset = e_offset & (~((UINT32)CDCPGB_PAGE_SIZE_MASK)); /*align to page starting*/
            b_s_offset = 0;
            b_e_offset = CDCPGB_PAGE_SIZE_NBYTES;

            CDC_NODE_OP(cdc_node)           = CDC_OP_RD;

            /*inherited data from cdc req*/
            CDC_NODE_CDC_REQ(cdc_node)     = cdc_req;
            CDC_NODE_SEQ_NO(cdc_node)       = CDC_REQ_SEQ_NO(cdc_req);
            CDC_NODE_SUB_SEQ_NO(cdc_node)   = ++ CDC_REQ_SUB_SEQ_NUM(cdc_req); /*would re-order later*/
            CDC_NODE_CDC_MD(cdc_node)      = CDC_REQ_CDC_MD(cdc_req);
            CDC_NODE_FD(cdc_node)           = CDC_REQ_FD(cdc_req);
            CDC_NODE_M_CACHE(cdc_node)      = NULL_PTR;
            CDC_NODE_M_BUFF(cdc_node)       = NULL_PTR; /*inherit only for write operation*/
            CDC_NODE_F_S_OFFSET(cdc_node)   = f_s_offset;
            CDC_NODE_F_E_OFFSET(cdc_node)   = f_s_offset + CDCPGB_PAGE_SIZE_NBYTES;
            CDC_NODE_B_S_OFFSET(cdc_node)   = b_s_offset;
            CDC_NODE_B_E_OFFSET(cdc_node)   = b_e_offset;
            CDC_NODE_TIMEOUT_NSEC(cdc_node) = CDC_REQ_TIMEOUT_NSEC(cdc_req);
            CDC_NODE_NTIME_MS(cdc_node)     = CDC_REQ_NTIME_MS(cdc_req);

            /*pop the last one and save it*/
            cdc_node_saved  = cdc_req_pop_node_back(cdc_req);

            /*bind: push back & mount*/
            cdc_req_push_node_back(cdc_req, cdc_node);

            /*bind: push back & mount the saved one*/
            cdc_req_push_node_back(cdc_req, cdc_node_saved);

            rd_flag = BIT_TRUE;
        }
    }

    CDC_ASSERT(clist_size(CDC_REQ_NODES(cdc_req)) == CDC_REQ_SUB_SEQ_NUM(cdc_req));

    /*if some read op inserted, re-order sub seq no. */
    /*here re-order always for debug purpose due to recording sub seq num info in node*/
    if(BIT_TRUE == rd_flag)
    {
        cdc_req_reorder_sub_seq_no(cdc_req);
    }
    else
    {
        cdc_req_reorder_sub_seq_no(cdc_req);
    }

    CDC_REQ_NODE_NUM(cdc_req) = CDC_REQ_SUB_SEQ_NUM(cdc_req); /*init*/

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_make_write: "
                                         "make %ld ops of req %ld, op %s done\n",
                                         CDC_REQ_SUB_SEQ_NUM(cdc_req),
                                         CDC_REQ_SEQ_NO(cdc_req),
                                         __cdc_op_str(CDC_REQ_OP(cdc_req)));
    return (EC_TRUE);
}

EC_BOOL cdc_req_timeout(CDC_REQ *cdc_req)
{
    CDC_NODE       *cdc_node;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_timeout: "
                     "req %ld, file range [%ld, %ld), op %s, "
                     "timeout %ld seconds, next access time %ld => timeout\n",
                     CDC_REQ_SEQ_NO(cdc_req),
                     CDC_REQ_F_S_OFFSET(cdc_req), CDC_REQ_F_E_OFFSET(cdc_req),
                     __cdc_op_str(CDC_REQ_OP(cdc_req)),
                     CDC_REQ_TIMEOUT_NSEC(cdc_req), CDC_REQ_NTIME_MS(cdc_req));

    /*determine offset & clean up nodes*/
    while(NULL_PTR != (cdc_node = cdc_req_pop_node_back(cdc_req)))
    {
        /*update upper offset at most*/
        if(CDC_NODE_F_S_OFFSET(cdc_node) < CDC_REQ_U_E_OFFSET(cdc_req))
        {
            CDC_REQ_U_E_OFFSET(cdc_req) = CDC_NODE_F_S_OFFSET(cdc_node);
        }

        cdc_node_free(cdc_node);
    }

    if(CDC_REQ_U_E_OFFSET(cdc_req) < CDC_REQ_F_S_OFFSET(cdc_req))
    {
        CDC_REQ_U_E_OFFSET(cdc_req) = CDC_REQ_F_S_OFFSET(cdc_req);
    }

    if(NULL_PTR != CDC_REQ_OFFSET(cdc_req))
    {
        (*CDC_REQ_OFFSET(cdc_req)) = CDC_REQ_U_E_OFFSET(cdc_req);
    }

    /*post timeout event*/
    cdc_req_set_post_event(cdc_req, (CDC_EVENT_HANDLER)cdc_req_exec_timeout_handler);

    return (EC_TRUE);
}

EC_BOOL cdc_req_terminate(CDC_REQ *cdc_req)
{
    CDC_NODE       *cdc_node;

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_terminate: "
                     "req %ld, file range [%ld, %ld), op %s terminate\n",
                     CDC_REQ_SEQ_NO(cdc_req),
                     CDC_REQ_F_S_OFFSET(cdc_req), CDC_REQ_F_E_OFFSET(cdc_req),
                     __cdc_op_str(CDC_REQ_OP(cdc_req)));

    /*determine offset & clean up nodes*/
    while(NULL_PTR != (cdc_node = cdc_req_pop_node_back(cdc_req)))
    {
        /*update upper offset at most*/
        if(CDC_NODE_F_S_OFFSET(cdc_node) < CDC_REQ_U_E_OFFSET(cdc_req))
        {
            CDC_REQ_U_E_OFFSET(cdc_req) = CDC_NODE_F_S_OFFSET(cdc_node);
        }

        cdc_node_free(cdc_node);
    }

    if(CDC_REQ_U_E_OFFSET(cdc_req) < CDC_REQ_F_S_OFFSET(cdc_req))
    {
        CDC_REQ_U_E_OFFSET(cdc_req) = CDC_REQ_F_S_OFFSET(cdc_req);
    }

    if(NULL_PTR != CDC_REQ_OFFSET(cdc_req))
    {
        (*CDC_REQ_OFFSET(cdc_req)) = CDC_REQ_U_E_OFFSET(cdc_req);
    }

    /*post terminate event*/
    cdc_req_set_post_event(cdc_req, (CDC_EVENT_HANDLER)cdc_req_exec_terminate_handler);

    return (EC_TRUE);
}

EC_BOOL cdc_req_complete(CDC_REQ *cdc_req)
{
    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_complete: "
                     "req %ld, file range [%ld, %ld), op %s complete\n",
                     CDC_REQ_SEQ_NO(cdc_req),
                     CDC_REQ_F_S_OFFSET(cdc_req), CDC_REQ_F_E_OFFSET(cdc_req),
                     __cdc_op_str(CDC_REQ_OP(cdc_req)));

    /*determine offset*/

    /*check validity*/
    CDC_ASSERT(0 == clist_size(CDC_REQ_NODES(cdc_req)));
    CDC_ASSERT(CDC_REQ_SUCC_NUM(cdc_req) == CDC_REQ_SUB_SEQ_NUM(cdc_req));
    CDC_ASSERT(CDC_REQ_SUCC_NUM(cdc_req) == CDC_REQ_NODE_NUM(cdc_req));

    if(CDC_REQ_U_E_OFFSET(cdc_req) < CDC_REQ_F_S_OFFSET(cdc_req))
    {
        CDC_REQ_U_E_OFFSET(cdc_req) = CDC_REQ_F_S_OFFSET(cdc_req);
    }

    if(NULL_PTR != CDC_REQ_OFFSET(cdc_req))
    {
        (*CDC_REQ_OFFSET(cdc_req)) = CDC_REQ_U_E_OFFSET(cdc_req);
    }

    /*post complete event*/
    cdc_req_set_post_event(cdc_req, (CDC_EVENT_HANDLER)cdc_req_exec_complete_handler);

    return (EC_TRUE);
}

EC_BOOL cdc_req_dispatch_node(CDC_REQ *cdc_req, CDC_NODE *cdc_node)
{
    CDC_MD     *cdc_md;
    CDC_PAGE   *cdc_page;

    cdc_md = CDC_REQ_CDC_MD(cdc_req);

    cdc_page = cdc_search_page(cdc_md, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md), CDC_NODE_FD(cdc_node),
                                CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node));
    if(NULL_PTR != cdc_page)
    {
        if(EC_FALSE == cdc_page_add_node(cdc_page, cdc_node))
        {
            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                             "dispatch node %ld/%ld of req %ld, op %s to existing page [%ld, %ld) failed\n",
                             CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                             CDC_NODE_SEQ_NO(cdc_node),
                             __cdc_op_str(CDC_NODE_OP(cdc_node)),
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
            return (EC_FALSE);
        }

        if(BIT_TRUE == CDC_NODE_SATA_DIRTY_FLAG(cdc_node))
        {
            CDC_PAGE_SATA_DIRTY_FLAG(cdc_page)  = BIT_TRUE; /*inherit sata dirty flag*/
        }

        if(CDC_OP_RD == CDC_NODE_OP(cdc_node)
        && BIT_TRUE == CDC_NODE_SATA_DEG_FLAG(cdc_node))/*xxx*/
        {
            CDC_PAGE_SATA_DEG_FLAG(cdc_page)  = BIT_TRUE; /*inherit sata deg flag*/
        }

        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_req_dispatch_node: "
                         "dispatch node %ld/%ld of req %ld, op %s to existing page [%ld, %ld) done\n",
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node),
                         __cdc_op_str(CDC_NODE_OP(cdc_node)),
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

        return (EC_TRUE);
    }

    CDC_ASSERT(NULL_PTR == cdc_search_page(cdc_md, CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md),
                                CDC_NODE_FD(cdc_node),
                                CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node)));

    /*create new page*/

    cdc_page = cdc_page_new();
    if(NULL_PTR == cdc_page)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                         "new page [%ld, %ld) for node %ld/%ld of req %ld, op %s failed\n",
                         CDC_NODE_F_S_OFFSET(cdc_node), CDC_NODE_F_E_OFFSET(cdc_node),
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node),
                         __cdc_op_str(CDC_NODE_OP(cdc_node)));

        return (EC_FALSE);
    }

    /*inherited data from node*/
    CDC_PAGE_FD(cdc_page)             = CDC_NODE_FD(cdc_node);
    CDC_PAGE_F_S_OFFSET(cdc_page)     = CDC_NODE_F_S_OFFSET(cdc_node);
    CDC_PAGE_F_E_OFFSET(cdc_page)     = CDC_NODE_F_E_OFFSET(cdc_node);
    CDC_PAGE_OP(cdc_page)             = CDC_NODE_OP(cdc_node);
    CDC_PAGE_TIMEOUT_NSEC(cdc_page)   = CDC_AIO_TIMEOUT_NSEC_DEFAULT;
    CDC_PAGE_CDC_MD(cdc_page)         = CDC_NODE_CDC_MD(cdc_node);
    CDC_PAGE_SATA_DEG_FLAG(cdc_page)  = CDC_NODE_SATA_DEG_FLAG(cdc_node);

    if(BIT_TRUE == CDC_NODE_SATA_DIRTY_FLAG(cdc_node))
    {
        CDC_PAGE_SATA_DIRTY_FLAG(cdc_page)  = BIT_TRUE; /*inherit sata dirty flag*/
    }

    /*reserve pages for writing req*/
    if(CDC_OP_WR == CDC_REQ_OP(cdc_req))
    {
        /*reserve page from name node and data node*/
        if(EC_FALSE == cdc_reserve_page(cdc_md, cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                             "reserve page [%ld, %ld) failed\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

            cdc_page_free(cdc_page);
            return (EC_FALSE);
        }

        CDC_ASSERT(NULL_PTR != CDC_PAGE_CDCNP_ITEM(cdc_page));
        CDC_ASSERT(CDCNPRB_ERR_POS != CDC_PAGE_CDCNP_ITEM_POS(cdc_page));

        /*now cdcnp item is mounted to page*/

        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_req_dispatch_node: "
                         "reserve [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
    }

    if(BIT_FALSE == CDC_REQ_KEEP_LRU_FLAG(cdc_req)) /*would impact on LRU*/
    {
        if(EC_FALSE == cdc_page_map(cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                             "map page [%ld, %ld) failed\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

            cdc_page_free(cdc_page);
            return (EC_FALSE);
        }

        CDC_ASSERT(NULL_PTR != CDC_PAGE_CDCNP_ITEM(cdc_page));
        CDC_ASSERT(CDCNPRB_ERR_POS != CDC_PAGE_CDCNP_ITEM_POS(cdc_page));

        /*now cdcnp item is mounted to page*/

        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_req_dispatch_node: "
                         "map [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
    }
    else /*would not impact on LRU*/
    {
        if(EC_FALSE == cdc_page_locate(cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                             "locate page [%ld, %ld) failed\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

            cdc_page_free(cdc_page);
            return (EC_FALSE);
        }

        CDC_ASSERT(NULL_PTR != CDC_PAGE_CDCNP_ITEM(cdc_page));
        CDC_ASSERT(CDCNPRB_ERR_POS != CDC_PAGE_CDCNP_ITEM_POS(cdc_page));

        /*now cdcnp item is mounted to page*/

        dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_req_dispatch_node: "
                         "locate [%ld, %ld) done\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));
    }

    if(NULL_PTR == CDC_PAGE_M_CACHE(cdc_page))
    {
        CDC_PAGE_M_CACHE(cdc_page) = __cdc_mem_cache_new(CDCPGB_PAGE_SIZE_NBYTES, CDCPGB_PAGE_SIZE_NBYTES);
        if(NULL_PTR == CDC_PAGE_M_CACHE(cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                             "new mem cache for page [%ld, %ld) failed\n",
                             CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

            if(CDC_OP_WR == CDC_REQ_OP(cdc_req))
            {
                /*release the reserved page space*/
                cdc_release_page(cdc_md, cdc_page);
            }

            cdc_page_free(cdc_page);
            return (EC_FALSE);
        }
    }

    /*add page to cdc module*/
    if(EC_FALSE == cdc_add_page(cdc_md, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md), cdc_page))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                         "add page [%ld, %ld) to cdc module failed\n",
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

        if(CDC_OP_WR == CDC_REQ_OP(cdc_req))
        {
            /*release the reserved page space*/
            cdc_release_page(cdc_md, cdc_page);
        }

        cdc_page_free(cdc_page);
        return (EC_FALSE);
    }

    /*add node to page*/
    if(EC_FALSE == cdc_page_add_node(cdc_page, cdc_node))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_req_dispatch_node: "
                         "dispatch node %ld/%ld of req %ld, op %s to new page [%ld, %ld) failed\n",
                         CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                         CDC_NODE_SEQ_NO(cdc_node),
                         __cdc_op_str(CDC_NODE_OP(cdc_node)),
                         CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

        if(CDC_OP_WR == CDC_REQ_OP(cdc_req))
        {
            /*release the reserved page space*/
            cdc_release_page(cdc_md, cdc_page);
        }

        cdc_del_page(cdc_md, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md), cdc_page);
        cdc_page_free(cdc_page);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_req_dispatch_node: "
                     "dispatch node %ld/%ld of req %ld, op %s to new page [%ld, %ld) done\n",
                     CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                     CDC_NODE_SEQ_NO(cdc_node),
                     __cdc_op_str(CDC_NODE_OP(cdc_node)),
                     CDC_PAGE_F_S_OFFSET(cdc_page), CDC_PAGE_F_E_OFFSET(cdc_page));

    return (EC_TRUE);
}

EC_BOOL cdc_req_cancel_node(CDC_REQ *cdc_req, CDC_NODE *cdc_node)
{
    if(NULL_PTR != CDC_NODE_MOUNTED_OWNERS(cdc_node)
    && NULL_PTR != CDC_NODE_CDC_PAGE(cdc_node))
    {
        /*delete node from page*/
        cdc_page_del_node(CDC_NODE_CDC_PAGE(cdc_node), cdc_node);
    }

    /*delete node from req*/
    cdc_req_del_node(cdc_req, cdc_node);

    CDC_ASSERT(CDC_NODE_SEQ_NO(cdc_node) == CDC_REQ_SEQ_NO(cdc_req));

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_req_cancel_node: "
                    "cancel node %ld/%ld of req %ld, op %s done\n",
                    CDC_NODE_SUB_SEQ_NO(cdc_node), CDC_NODE_SUB_SEQ_NUM(cdc_node),
                    CDC_NODE_SEQ_NO(cdc_node),
                    __cdc_op_str(CDC_REQ_OP(cdc_req)));

    return (EC_TRUE);
}

/*----------------------------------- cdc module interface -----------------------------------*/


void cdc_print(LOG *log, const CDC_MD *cdc_md)
{
    if(NULL_PTR != cdc_md)
    {
        sys_log(log, "cdc_print: cdc_md %p: caio_md :\n", cdc_md);
        caio_print(log, CDC_MD_CAIO_MD(cdc_md));

        sys_log(log, "cdc_print: cdc_md %p: seq_no: %ld\n", cdc_md, CDC_MD_SEQ_NO(cdc_md));

        sys_log(log, "cdc_print: cdc_md %p: %ld reqs:\n",
                     cdc_md, clist_size(CDC_MD_REQ_LIST(cdc_md)));
        if(0)
        {
            cdc_show_reqs(log, cdc_md);
        }

        sys_log(log, "cdc_print: cdc_md %p: %u active pages:\n",
                     cdc_md, crb_tree_node_num(CDC_MD_PAGE_TREE(cdc_md, 0)));

        sys_log(log, "cdc_print: cdc_md %p: %u standby pages:\n",
                     cdc_md, crb_tree_node_num(CDC_MD_PAGE_TREE(cdc_md, 1)));
        if(0)
        {
            cdc_show_pages(log, cdc_md);
        }

        sys_log(log, "cdc_print: cdc_md %p: %ld post event reqs: \n",
                     cdc_md, clist_size(CDC_MD_POST_EVENT_REQS(cdc_md)));

        if(0)
        {
            cdc_show_post_event_reqs(log, cdc_md);
        }
    }

    return;
}

void cdc_process_degrades(CDC_MD *cdc_md, const uint64_t degrade_traffic_bps,
                                 const UINT32 scan_max_num,
                                 const UINT32 expect_degrade_num,
                                 UINT32 *complete_degrade_num)
{
    static uint64_t     time_msec_next = 0; /*init*/

    UINT32      complete_degrade_num_t;

    complete_degrade_num_t = 0;

    if(NULL_PTR != CDC_MD_NP(cdc_md))
    {
        uint64_t    time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        /*flow control: degrade 20MB/s at most to sata*/
        while(time_msec_cur >= time_msec_next)
        {
            uint64_t    time_msec_cost; /*msec cost for degrading from ssd to sata*/

            /*degrade 4MB at most once time*/
            cdcnp_degrade(CDC_MD_NP(cdc_md), scan_max_num, expect_degrade_num, &complete_degrade_num_t);

            if(0 == complete_degrade_num_t)
            {
                break; /*fall through*/
            }

            if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_08MB) /*8MB/s*/
            {
                /*
                *
                * if flow control is 8MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (8MB/s)
                *                = ((n * 2^m * 125) / (2^20)) ms
                *                = (((n * 125) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 500
                * if n = 8 , time cost msec = 250
                * if n = 4 , time cost msec = 125
                * if n = 2 , time cost msec = 62
                * if n = 1 , time cost msec = 31
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 125) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_12MB) /*12MB/s*/
            {
                /*
                *
                * if flow control is 12MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (12MB/s)
                *                = ((n * 2^m * 83) / (2^20)) ms
                *                = (((n * 83) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 332
                * if n = 8 , time cost msec = 166
                * if n = 4 , time cost msec = 83
                * if n = 2 , time cost msec = 41
                * if n = 1 , time cost msec = 20
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 83) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_16MB) /*16MB/s*/
            {
                /*
                *
                * if flow control is 16MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (16MB/s)
                *                = ((n * 2^m * 62) / (2^20)) ms
                *                = (((n * 62) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 248
                * if n = 8 , time cost msec = 124
                * if n = 4 , time cost msec = 62
                * if n = 2 , time cost msec = 31
                * if n = 1 , time cost msec = 15
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 62) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_20MB) /*20MB/s*/
            {
                /*
                *
                * if flow control is 20MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (20MB/s)
                *                = ((n * 2^m * 50) / (2^20)) ms
                *                = (((n * 50) << m) >> 20) ms
                *                = (((n * 25) << m) >> 19) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 200
                * if n = 8 , time cost msec = 100
                * if n = 4 , time cost msec = 50
                * if n = 2 , time cost msec = 25
                * if n = 1 , time cost msec = 12
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 50) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_24MB) /*24MB/s*/
            {
                /*
                *
                * if flow control is 24MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (24MB/s)
                *                = ((n * 2^m * 41) / (2^20)) ms
                *                = (((n * 41) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 164
                * if n = 8 , time cost msec = 82
                * if n = 4 , time cost msec = 41
                * if n = 2 , time cost msec = 20
                * if n = 1 , time cost msec = 10
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 41) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_28MB) /*28MB/s*/
            {
                /*
                *
                * if flow control is 28MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (28MB/s)
                *                = ((n * 2^m * 36) / (2^20)) ms
                *                = (((n * 36) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 144
                * if n = 8 , time cost msec = 72
                * if n = 4 , time cost msec = 36
                * if n = 2 , time cost msec = 18
                * if n = 1 , time cost msec = 9
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 36) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_32MB)/*32MB/s*/
            {
                /*
                *
                * if flow control is 32MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (32MB/s)
                *        (about) = ((n * 2^m * 31) / (2^20)) ms
                *                = (((n * 31) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 124
                * if n = 8 , time cost msec = 62
                * if n = 4 , time cost msec = 31
                * if n = 2 , time cost msec = 15
                * if n = 1 , time cost msec = 7
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 31) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }
            else if(degrade_traffic_bps <= CDC_DEGRADE_TRAFFIC_36MB)/*36MB/s*/
            {
                /*
                *
                * if flow control is 36MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (36MB/s)
                *                = ((n * 2^m * 28) / (2^20)) ms
                *                = (((n * 28) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 112
                * if n = 8 , time cost msec = 56
                * if n = 4 , time cost msec = 28
                * if n = 2 , time cost msec = 14
                * if n = 1 , time cost msec = 7
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 28) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            else /*40MB/s*/
            {
                /*
                *
                * if flow control is 40MB/s
                *
                * time cost msec = ((n * 2^m B) * (1000 ms/s)) / (40MB/s)
                *                = ((n * 2^m * 25) / (2^20)) ms
                *                = (((n * 25) << m) >> 20) ms
                * where 2^m is cdc page size in bytes.
                * e.g.,
                * when cdc page size = 256KB, m = 18, now
                * if n = 16, time cost msec = 100
                * if n = 8 , time cost msec = 50
                * if n = 4 , time cost msec = 25
                * if n = 2 , time cost msec = 12
                * if n = 1 , time cost msec = 6
                *
                */
                time_msec_cost = (((complete_degrade_num_t * 25) << CDCPGB_PAGE_SIZE_NBITS) >> 20);
            }

            dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "[DEBUG] cdc_process_degrades: "
                                                "complete %ld, expected cost %ld msec\n",
                                                complete_degrade_num_t, time_msec_cost);

            time_msec_next = time_msec_cur + time_msec_cost;

            break; /*fall through*/
        }
    }

    if(NULL_PTR != complete_degrade_num)
    {
        (*complete_degrade_num) = complete_degrade_num_t;
    }

    return;
}

void cdc_process_reqs(CDC_MD *cdc_md)
{
    cdc_process_timeout_reqs(cdc_md);
    return;
}

/*check and process timeout reqs*/
void cdc_process_timeout_reqs(CDC_MD *cdc_md)
{
    CLIST_DATA      *clist_data;

    UINT32           req_num;
    uint64_t         cur_time_ms;

    cur_time_ms = c_get_cur_time_msec();
    req_num     = 0;

    CLIST_LOOP_NEXT(CDC_MD_REQ_LIST(cdc_md), clist_data)
    {
        CDC_REQ       *cdc_req;

        cdc_req = (CDC_REQ *)CLIST_DATA_DATA(clist_data);
        CDC_ASSERT(CDC_REQ_MOUNTED_REQS(cdc_req) == clist_data);

        if(cur_time_ms >= CDC_REQ_NTIME_MS(cdc_req))
        {
            clist_data = CLIST_DATA_PREV(clist_data);

            req_num ++;

            dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_process_timeout_reqs: "
                             "req %ld, file range [%ld, %ld), op %s timeout\n",
                             CDC_REQ_SEQ_NO(cdc_req),
                             CDC_REQ_F_S_OFFSET(cdc_req), CDC_REQ_F_E_OFFSET(cdc_req),
                             __cdc_op_str(CDC_REQ_OP(cdc_req)));

            cdc_del_req(cdc_md, cdc_req);
            cdc_req_timeout(cdc_req);
        }
    }

    dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_process_timeout_reqs: process %ld timeout reqs\n", req_num);

    return;
}


void cdc_process_pages(CDC_MD *cdc_md)
{
    CDC_PAGE       *cdc_page;

    UINT32           active_page_tree_idx;
    UINT32           standby_page_tree_idx;

    active_page_tree_idx  = CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md);
    standby_page_tree_idx = CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md);

    /*run through active tree and process page one by one*/
    while(NULL_PTR != (cdc_page = cdc_pop_first_page(cdc_md, active_page_tree_idx)))
    {
        if(BIT_TRUE == CDC_PAGE_SSD_LOADING_FLAG(cdc_page))
        {
            /*add to standby page tree temporarily*/
            cdc_add_page(cdc_md, standby_page_tree_idx, cdc_page);
            continue;
        }

        cdc_process_page(cdc_md, cdc_page);
    }

    /*switch page tree*/
    CDC_MD_SWITCH_PAGE_TREE(cdc_md);
    /*make sure standby has no page*/
    CDC_ASSERT(EC_FALSE == cdc_has_page(cdc_md, CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md)));

    return;
}

void cdc_process_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    if(CDC_OP_WR == CDC_PAGE_OP(cdc_page)
    && CDC_PAGE_F_S_OFFSET(cdc_page) + CDCPGB_PAGE_SIZE_NBYTES == CDC_PAGE_F_E_OFFSET(cdc_page))
    {
        /*page life cycle is determined by process => not need to free page*/
        /*page cannot be accessed again => do not output log*/
        cdc_page_process(cdc_page, CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md));
        return;
    }

    /*load page from ssd to mem cache*/
    if(NULL_PTR != CDC_MD_CAIO_MD(cdc_md))
    {
        if(BIT_TRUE == CDC_PAGE_SATA_DEG_FLAG(cdc_page))
        {
            if(EC_FALSE == cdc_page_load_aio(cdc_page))
            {
                /*page cannot be accessed again => do not output log*/
                return;
            }
        }
        else
        {
            if(EC_FALSE == cdc_page_read_aio(cdc_page))
            {
                /*page cannot be accessed again => do not output log*/
                return;
            }
        }

        /*add page to standby page tree temporarily*/
        cdc_add_page(cdc_md, CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md), cdc_page);
        CDC_PAGE_SSD_LOADING_FLAG(cdc_page)  = BIT_TRUE; /*set flag*/

        dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_process_page: "
                                            "submit loading page [%ld, %ld) done\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));

        /*cdc page would be free later*/
    }
    else
    {
        if(EC_FALSE == cdc_page_load(cdc_page))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_process_page: "
                                                "load page [%ld, %ld) failed\n",
                                                CDC_PAGE_F_S_OFFSET(cdc_page),
                                                CDC_PAGE_F_E_OFFSET(cdc_page));

            cdc_page_free(cdc_page);
            return;
        }

        dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_process_page: "
                                            "load page [%ld, %ld) done\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));

        CDC_PAGE_SSD_LOADED_FLAG(cdc_page)  = BIT_TRUE;  /*set ssd loaded*/
        CDC_PAGE_SSD_LOADING_FLAG(cdc_page) = BIT_FALSE; /*clear flag*/

        /*free cdc page determined by process*/
        cdc_page_process(cdc_page, CDC_MD_STANDBY_PAGE_TREE_IDX(cdc_md));
    }

    return;
}

void cdc_process_events(CDC_MD *cdc_md)
{
    cdc_process_post_event_reqs(cdc_md, CDC_PROCESS_EVENT_ONCE_NUM);

    return;
}

void cdc_process_post_event_reqs(CDC_MD *cdc_md, const UINT32 process_event_max_num)
{
    CDC_REQ        *cdc_req;
    UINT32           counter;
    UINT32           event_num;
    UINT32           max_num;

    event_num = clist_size(CDC_MD_POST_EVENT_REQS(cdc_md));
    max_num   = DMIN(event_num, process_event_max_num);
    counter   = 0;

    while(counter < max_num
    && NULL_PTR != (cdc_req = clist_pop_front(CDC_MD_POST_EVENT_REQS(cdc_md))))
    {
        CDC_EVENT_HANDLER      handler;

        counter ++;

        CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req) = NULL_PTR;

        handler = CDC_REQ_POST_EVENT_HANDLER(cdc_req);  /*save*/
        CDC_REQ_POST_EVENT_HANDLER(cdc_req) = NULL_PTR; /*clear*/

        /*note: node may be push back to list*/
        handler(cdc_req);
    }

    dbg_log(SEC_0182_CDC, 5)(LOGSTDOUT, "[DEBUG] cdc_process_post_event_reqs: "
                                        "process %ld reqs\n",
                                        counter);

    return;
}

EC_BOOL cdc_has_event(CDC_MD *cdc_md)
{
    return cdc_has_post_event_reqs(cdc_md);
}

EC_BOOL cdc_has_req(CDC_MD *cdc_md)
{
    if(EC_TRUE == clist_is_empty(CDC_MD_REQ_LIST(cdc_md)))
    {
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

EC_BOOL cdc_has_wr_req(CDC_MD *cdc_md)
{
    CLIST_DATA  *clist_data;

    CLIST_LOOP_NEXT(CDC_MD_REQ_LIST(cdc_md), clist_data)
    {
        CDC_REQ     *cdc_req;

        cdc_req = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cdc_req)
        {
            continue;
        }

        if(CDC_OP_WR == CDC_REQ_OP(cdc_req))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*lock page to prevent it from degrading*/
EC_BOOL cdc_lock_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    CDCNP_KEY       cdcnp_key;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_lock_page: np has no key for [%ld, %ld)\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    if(NULL_PTR != CDC_PAGE_CDCNP_ITEM(cdc_page))
    {
        CDCNP_ITEM     *cdcnp_item;

        cdcnp_item = CDC_PAGE_CDCNP_ITEM(cdc_page);

        if(BIT_FALSE == CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item))
        {
            CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item) = BIT_TRUE;

            CDC_MD_LOCKED_PAGE_NUM(cdc_md) ++;

            dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_lock_page: lock [%ld, %ld) done\n",
                                                CDC_PAGE_F_S_OFFSET(cdc_page),
                                                CDC_PAGE_F_E_OFFSET(cdc_page));
        }
    }
    return (EC_TRUE);
}

EC_BOOL cdc_unlock_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    CDCNP_KEY       cdcnp_key;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_unlock_page: np has no key for [%ld, %ld)\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    if(NULL_PTR != CDC_PAGE_CDCNP_ITEM(cdc_page))
    {
        CDCNP_ITEM     *cdcnp_item;

        cdcnp_item = CDC_PAGE_CDCNP_ITEM(cdc_page);

        if(BIT_TRUE == CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item))
        {
            CDCNP_ITEM_SSD_LOCKED_FLAG(cdcnp_item) = BIT_FALSE;

            CDC_ASSERT(CDC_MD_LOCKED_PAGE_NUM(cdc_md) > 0);

            CDC_MD_LOCKED_PAGE_NUM(cdc_md) --;

            dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_unlock_page: unlock [%ld, %ld) done\n",
                                                CDC_PAGE_F_S_OFFSET(cdc_page),
                                                CDC_PAGE_F_E_OFFSET(cdc_page));
        }
    }
    return (EC_TRUE);
}

/*map page range to disk range with LRU modification*/
EC_BOOL cdc_locate_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    CDCNP_KEY       cdcnp_key;
    CDCNP_ITEM     *cdcnp_item;
    CDCNP_FNODE    *cdcnp_fnode;
    CDCNP_INODE    *cdcnp_inode;
    UINT32          d_s_offset;
    UINT32          d_e_offset;
    uint32_t        cdcnp_item_pos;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_locate_page: np has no key for [%ld, %ld)\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    cdcnp_item = cdcnp_locate(CDC_MD_NP(cdc_md), &cdcnp_key, &cdcnp_item_pos);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_locate_page: locate [%ld, %ld) from np failed\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

    d_s_offset = cdcdn_node_locate(CDC_MD_DN(cdc_md),
                                    CDCNP_INODE_DISK_NO(cdcnp_inode),
                                    CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                    CDCNP_INODE_PAGE_NO(cdcnp_inode));
    if(CDCDN_NODE_ERR_OFFSET == d_s_offset)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_locate_page: "
                                            "locate (disk %u, block %u, page %u) failed\n",
                                            CDCNP_INODE_DISK_NO(cdcnp_inode),
                                            CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                            CDCNP_INODE_PAGE_NO(cdcnp_inode));
        return (EC_FALSE);
    }

    CDC_ASSERT(0 == (d_s_offset & CDCPGB_PAGE_SIZE_MASK));

    d_e_offset = d_s_offset + CDCPGB_PAGE_SIZE_NBYTES;

    CDC_PAGE_D_S_OFFSET(cdc_page) = d_s_offset;
    CDC_PAGE_D_E_OFFSET(cdc_page) = d_e_offset;

    CDC_PAGE_CDCNP_ITEM(cdc_page)     = cdcnp_item;
    CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = cdcnp_item_pos;

    return (EC_TRUE);
}

/*map page range to disk range with LRU modification*/
EC_BOOL cdc_map_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    CDCNP_KEY       cdcnp_key;
    CDCNP_ITEM     *cdcnp_item;
    CDCNP_FNODE    *cdcnp_fnode;
    CDCNP_INODE    *cdcnp_inode;
    UINT32          d_s_offset;
    UINT32          d_e_offset;
    uint32_t        cdcnp_item_pos;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_map_page: np has no key for [%ld, %ld)\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    cdcnp_item = cdcnp_map(CDC_MD_NP(cdc_md), &cdcnp_key, &cdcnp_item_pos);
    if(NULL_PTR == cdcnp_item)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_map_page: map [%ld, %ld) to np failed\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
    cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

    d_s_offset = cdcdn_node_locate(CDC_MD_DN(cdc_md),
                                    CDCNP_INODE_DISK_NO(cdcnp_inode),
                                    CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                    CDCNP_INODE_PAGE_NO(cdcnp_inode));
    if(CDCDN_NODE_ERR_OFFSET == d_s_offset)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_map_page: "
                                            "locate (disk %u, block %u, page %u) failed\n",
                                            CDCNP_INODE_DISK_NO(cdcnp_inode),
                                            CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                            CDCNP_INODE_PAGE_NO(cdcnp_inode));
        return (EC_FALSE);
    }

    CDC_ASSERT(0 == (d_s_offset & CDCPGB_PAGE_SIZE_MASK));

    d_e_offset = d_s_offset + CDCPGB_PAGE_SIZE_NBYTES;

    CDC_PAGE_D_S_OFFSET(cdc_page) = d_s_offset;
    CDC_PAGE_D_E_OFFSET(cdc_page) = d_e_offset;

    CDC_PAGE_CDCNP_ITEM(cdc_page)     = cdcnp_item;
    CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = cdcnp_item_pos;

    return (EC_TRUE);
}

/*reserve name node and data node for page*/
EC_BOOL cdc_reserve_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    CDCNP_KEY       cdcnp_key;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_reserve_page: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_reserve_page: "
                                            "np has already key for [%ld, %ld)\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));

        if(NULL_PTR == CDC_PAGE_CDCNP_ITEM(cdc_page)
        || CDCNPRB_ERR_POS == CDC_PAGE_CDCNP_ITEM_POS(cdc_page))
        {
            CDCNP_ITEM     *cdcnp_item;
            uint32_t        cdcnp_item_pos;

            cdcnp_item = cdcnp_get(CDC_MD_NP(cdc_md), &cdcnp_key, CDCNP_ITEM_FILE_IS_REG, &cdcnp_item_pos);
            if(NULL_PTR == cdcnp_item)
            {
                dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_page: "
                                                    "np has no key [%u, %u)\n",
                                                    CDCNP_KEY_S_PAGE(&cdcnp_key),
                                                    CDCNP_KEY_E_PAGE(&cdcnp_key));

                return (EC_FALSE);
            }

            CDC_PAGE_CDCNP_ITEM(cdc_page)     = cdcnp_item;
            CDC_PAGE_CDCNP_ITEM_POS(cdc_page) = cdcnp_item_pos;
        }

        return (EC_TRUE);
    }

    if(EC_FALSE == cdc_page_reserve(cdc_md, cdc_page, &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_reserve_page: "
                                            "reserve page [%ld, %ld) failed\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_reserve_page: "
                                        "reserve page [%ld, %ld) done\n",
                                        CDC_PAGE_F_S_OFFSET(cdc_page),
                                        CDC_PAGE_F_E_OFFSET(cdc_page));

    return (EC_TRUE);
}

/*release name node and data node of page*/
EC_BOOL cdc_release_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    CDCNP_KEY       cdcnp_key;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_release_page: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_release_page: "
                                            "np has no key for [%ld, %ld)\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdc_page_release(cdc_md, cdc_page, &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_release_page: "
                                            "release page [%ld, %ld) failed\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_release_page: "
                                        "release page [%ld, %ld) done\n",
                                        CDC_PAGE_F_S_OFFSET(cdc_page),
                                        CDC_PAGE_F_E_OFFSET(cdc_page));

    return (EC_TRUE);
}

/*release name node and discard data node of page => mark page as bad*/
EC_BOOL cdc_discard_page(CDC_MD *cdc_md, CDC_PAGE *cdc_page)
{
    CDCNP_KEY       cdcnp_key;

    CDCNP_KEY_S_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_S_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);
    CDCNP_KEY_E_PAGE(&cdcnp_key) = (uint32_t)(CDC_PAGE_F_E_OFFSET(cdc_page) >> CDCPGB_PAGE_SIZE_NBITS);

    CDC_ASSERT(CDCNP_KEY_S_PAGE(&cdcnp_key) + 1 == CDCNP_KEY_E_PAGE(&cdcnp_key));

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_discard_page: cdc is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cdcnp_has_key(CDC_MD_NP(cdc_md), &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_discard_page: "
                                            "np has no key for [%ld, %ld)\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    if(EC_FALSE == cdc_page_discard(cdc_md, cdc_page, &cdcnp_key))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_discard_page: "
                                            "discard page [%ld, %ld) failed\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 6)(LOGSTDOUT, "[DEBUG] cdc_discard_page: "
                                        "discard page [%ld, %ld) done\n",
                                        CDC_PAGE_F_S_OFFSET(cdc_page),
                                        CDC_PAGE_F_E_OFFSET(cdc_page));

    return (EC_TRUE);
}

void cdc_show_pages(LOG *log, const CDC_MD *cdc_md)
{
    //crb_tree_print(log, CDC_MD_PAGE_TREE(cdc_md));
    crb_tree_print_in_order(log, CDC_MD_PAGE_TREE(cdc_md, 0));
    crb_tree_print_in_order(log, CDC_MD_PAGE_TREE(cdc_md, 1));
    return;
}

void cdc_show_post_event_reqs(LOG *log, const CDC_MD *cdc_md)
{
    clist_print(log, CDC_MD_POST_EVENT_REQS(cdc_md), (CLIST_DATA_DATA_PRINT)cdc_req_print);
    return;
}

void cdc_show_page(LOG *log, const CDC_MD *cdc_md, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CDC_PAGE   *cdc_page;

    cdc_page = cdc_search_page((CDC_MD *)cdc_md, CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md), fd, f_s_offset, f_e_offset);
    if(NULL_PTR == cdc_page)
    {
        sys_log(log, "cdc_show_req: (no matched req)\n");
        return;
    }

    cdc_page_print(log, cdc_page);
    return;
}


void cdc_show_reqs(LOG *log, const CDC_MD *cdc_md)
{
    clist_print(log, CDC_MD_REQ_LIST(cdc_md), (CLIST_DATA_DATA_PRINT)cdc_req_print);
    return;
}

void cdc_show_req(LOG *log, const CDC_MD *cdc_md, const UINT32 seq_no)
{
    CDC_REQ  *cdc_req;

    cdc_req = clist_search_data_front(CDC_MD_REQ_LIST(cdc_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)cdc_req_is);


    if(NULL_PTR == cdc_req)
    {
        sys_log(log, "cdc_show_req: (none)\n");
        return;
    }

    cdc_req_print(log, cdc_req);
    return;
}

void cdc_show_node(LOG *log, const CDC_MD *cdc_md, const UINT32 seq_no, const UINT32 sub_seq_no)
{
    CDC_REQ  *cdc_req;
    CDC_NODE *cdc_node;

    cdc_req = clist_search_data_front(CDC_MD_REQ_LIST(cdc_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)cdc_req_is);


    if(NULL_PTR == cdc_req)
    {
        sys_log(log, "cdc_show_req: (no matched req)\n");
        return;
    }

    cdc_node = clist_search_data_front(CDC_REQ_NODES(cdc_req), (const void *)sub_seq_no,
                                        (CLIST_DATA_DATA_CMP)cdc_node_is);

    if(NULL_PTR == cdc_node)
    {
        sys_log(log, "cdc_show_req: (none)\n");
        return;
    }

    cdc_node_print(log, cdc_node);
    return;
}

EC_BOOL cdc_submit_req(CDC_MD *cdc_md, CDC_REQ *cdc_req)
{
    /*add req to request list of cdc module*/
    if(EC_FALSE == cdc_add_req(cdc_md, cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_submit_req: add req %ld, op %s failed\n",
                                             CDC_REQ_SEQ_NO(cdc_req),
                                             __cdc_op_str(CDC_REQ_OP(cdc_req)));
        return (EC_FALSE);
    }

    /*make r/w ops of req*/
    if(EC_FALSE == cdc_make_req_op(cdc_md, cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_submit_req: make ops of req %ld, op %s failed\n",
                                             CDC_REQ_SEQ_NO(cdc_req),
                                             __cdc_op_str(CDC_REQ_OP(cdc_req)));
        return (EC_FALSE);
    }

    /*dispatch req which would bind each r/w op to specific page*/
    if(EC_FALSE == cdc_dispatch_req(cdc_md, cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_submit_req: dispatch req %ld, op %s failed\n",
                                             CDC_REQ_SEQ_NO(cdc_req),
                                             __cdc_op_str(CDC_REQ_OP(cdc_req)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_submit_req: submit req %ld, op %s done\n",
                                         CDC_REQ_SEQ_NO(cdc_req),
                                         __cdc_op_str(CDC_REQ_OP(cdc_req)));
    return (EC_TRUE);
}

EC_BOOL cdc_add_req(CDC_MD *cdc_md, CDC_REQ *cdc_req)
{
    CDC_ASSERT(NULL_PTR == CDC_REQ_MOUNTED_REQS(cdc_req));

    /*push back*/
    CDC_REQ_MOUNTED_REQS(cdc_req) = clist_push_back(CDC_MD_REQ_LIST(cdc_md), (void *)cdc_req);
    if(NULL_PTR == CDC_REQ_MOUNTED_REQS(cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_add_req: push req %ld, op %s failed\n",
                                             CDC_REQ_SEQ_NO(cdc_req),
                                             __cdc_op_str(CDC_REQ_OP(cdc_req)));
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_add_req: push req %ld, op %s done\n",
                                         CDC_REQ_SEQ_NO(cdc_req),
                                         __cdc_op_str(CDC_REQ_OP(cdc_req)));
    return (EC_TRUE);
}

EC_BOOL cdc_del_req(CDC_MD *cdc_md, CDC_REQ *cdc_req)
{
    if(NULL_PTR != CDC_REQ_MOUNTED_REQS(cdc_req))
    {
        clist_erase(CDC_MD_REQ_LIST(cdc_md), CDC_REQ_MOUNTED_REQS(cdc_req));
        CDC_REQ_MOUNTED_REQS(cdc_req) = NULL_PTR;

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_del_req: req %ld, op %s\n",
                     CDC_REQ_SEQ_NO(cdc_req),
                     __cdc_op_str(CDC_REQ_OP(cdc_req)));

    }
    return (EC_TRUE);
}

EC_BOOL cdc_make_req_op(CDC_MD *cdc_md, CDC_REQ *cdc_req)
{
    if(CDC_OP_RD == CDC_REQ_OP(cdc_req))
    {
        if(EC_FALSE == cdc_req_make_read(cdc_req))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_make_req_op: make read req %ld ops failed\n",
                                                 CDC_REQ_SEQ_NO(cdc_req));
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_make_req_op: make read req %ld ops done\n",
                                             CDC_REQ_SEQ_NO(cdc_req));

        return (EC_TRUE);
    }

    if(CDC_OP_WR == CDC_REQ_OP(cdc_req))
    {
        if(EC_FALSE == cdc_req_make_write(cdc_req))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_make_req_op: make write req %ld ops failed\n",
                                                 CDC_REQ_SEQ_NO(cdc_req));
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_make_req_op: make write req %ld ops done\n",
                                             CDC_REQ_SEQ_NO(cdc_req));

        return (EC_TRUE);
    }

    dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_make_req_op: invalid req %ld, op %s\n",
                                         CDC_REQ_SEQ_NO(cdc_req),
                                         __cdc_op_str(CDC_REQ_OP(cdc_req)));
    return (EC_FALSE);
}

EC_BOOL cdc_dispatch_req(CDC_MD *cdc_md, CDC_REQ *cdc_req)
{
    CLIST_DATA  *clist_data;

    CLIST_LOOP_NEXT(CDC_REQ_NODES(cdc_req), clist_data)
    {
        CDC_NODE *cdc_node;

        cdc_node = (CDC_NODE *)CLIST_DATA_DATA(clist_data);

        if(EC_FALSE == cdc_req_dispatch_node(cdc_req, cdc_node))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_dispatch_req: "
                                                "dispatch %ld of req %ld, op %s failed => cancel\n",
                                                CDC_NODE_SUB_SEQ_NO(cdc_node),
                                                CDC_REQ_SEQ_NO(cdc_req),
                                                __cdc_op_str(CDC_REQ_OP(cdc_req)));

            cdc_cancel_req(cdc_md, cdc_req);

            return (EC_FALSE);
        }
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_dispatch_req: "
                                        "dispatch req %ld, op %s done\n",
                                        CDC_REQ_SEQ_NO(cdc_req),
                                        __cdc_op_str(CDC_REQ_OP(cdc_req)));

    return (EC_TRUE);
}

EC_BOOL cdc_cancel_req(CDC_MD *cdc_md, CDC_REQ *cdc_req)
{
    CDC_NODE *cdc_node;

    while(NULL_PTR != (cdc_node = cdc_req_pop_node_back(cdc_req)))
    {
        cdc_req_cancel_node(cdc_req, cdc_node);
        cdc_node_free(cdc_node);
    }

    /*delete post event regarding this req*/
    cdc_req_del_post_event(cdc_req);

    /*delete req from cdc module*/
    cdc_del_req(cdc_md, cdc_req);

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_cancel_req: "
                                         "cancel req %ld, op %s done\n",
                                         CDC_REQ_SEQ_NO(cdc_req),
                                         __cdc_op_str(CDC_REQ_OP(cdc_req)));
    return (EC_TRUE);
}

EC_BOOL cdc_has_locked_page(CDC_MD *cdc_md)
{
    if(0 < CDC_MD_LOCKED_PAGE_NUM(cdc_md))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cdc_add_page(CDC_MD *cdc_md, const UINT32 page_tree_idx, CDC_PAGE *cdc_page)
{
    CRB_NODE    *crb_node;

    CDC_ASSERT(NULL_PTR == CDC_PAGE_MOUNTED_PAGES(cdc_page));

    crb_node = crb_tree_insert_data(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx), (void *)cdc_page);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_add_page: "
                                            "add page [%ld, %ld) to %s tree failed\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page),
                                            ((CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) == page_tree_idx)?
                                            (const char *)"active" : (const char *)"standby"));
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cdc_page) /*found duplicate*/
    {
        CDC_ASSERT(CDC_PAGE_F_S_OFFSET(cdc_page) == CDC_PAGE_F_S_OFFSET((CDC_PAGE *)CRB_NODE_DATA(crb_node)));
        CDC_ASSERT(CDC_PAGE_F_E_OFFSET(cdc_page) == CDC_PAGE_F_E_OFFSET((CDC_PAGE *)CRB_NODE_DATA(crb_node)));

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_add_page: "
                                            "found duplicate page [%ld, %ld) in %ld (%s) tree\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page),
                                            page_tree_idx,
                                            ((CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) == page_tree_idx)?
                                            (const char *)"active" : (const char *)"standby"));
        return (EC_FALSE);
    }

    CDC_PAGE_MOUNTED_PAGES(cdc_page)    = crb_node;
    CDC_PAGE_MOUNTED_TREE_IDX(cdc_page) = page_tree_idx;

    dbg_log(SEC_0182_CDC, 7)(LOGSTDOUT, "[DEBUG] cdc_add_page: "
                                        "add page [%ld, %ld) to %ld (%s) tree done\n",
                                        CDC_PAGE_F_S_OFFSET(cdc_page),
                                        CDC_PAGE_F_E_OFFSET(cdc_page),
                                        page_tree_idx,
                                        ((CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) == page_tree_idx)?
                                        (const char *)"active" : (const char *)"standby"));
    return (EC_TRUE);
}

EC_BOOL cdc_del_page(CDC_MD *cdc_md, const UINT32 page_tree_idx, CDC_PAGE *cdc_page)
{
    if(NULL_PTR != CDC_PAGE_MOUNTED_PAGES(cdc_page))
    {
        CDC_ASSERT(page_tree_idx == CDC_PAGE_MOUNTED_TREE_IDX(cdc_page));

        crb_tree_erase(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx), CDC_PAGE_MOUNTED_PAGES(cdc_page));
        CDC_PAGE_MOUNTED_PAGES(cdc_page)    = NULL_PTR;
        CDC_PAGE_MOUNTED_TREE_IDX(cdc_page) = CDC_PAGE_TREE_IDX_ERR;

        dbg_log(SEC_0182_CDC, 7)(LOGSTDOUT, "[DEBUG] cdc_del_page: "
                                            "del page [%ld, %ld) from %ld (%s) tree done\n",
                                            CDC_PAGE_F_S_OFFSET(cdc_page),
                                            CDC_PAGE_F_E_OFFSET(cdc_page),
                                            page_tree_idx,
                                            ((CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) == page_tree_idx)?
                                            (const char *)"active" : (const char *)"standby"));
    }
    return (EC_TRUE);
}

EC_BOOL cdc_has_page(CDC_MD *cdc_md, const UINT32 page_tree_idx)
{
    if(EC_TRUE == crb_tree_is_empty(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx)))
    {
        return (EC_FALSE); /*no page*/
    }

    return (EC_TRUE); /*has page*/
}

STATIC_CAST EC_BOOL __cdc_page_is_rd(const void *cdc_page, void *UNUSED(none))
{
    if(CDC_OP_RD == CDC_PAGE_OP((const CDC_PAGE *)cdc_page))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdc_has_wr_page(CDC_MD *cdc_md, const UINT32 page_tree_idx)
{
    if(EC_TRUE == crb_inorder_walk(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx),
                                    __cdc_page_is_rd,
                                    NULL_PTR))
    {
        /*all are read pages*/
        return (EC_FALSE);
    }

    return (EC_TRUE); /*has wr page*/
}

CDC_PAGE *cdc_pop_first_page(CDC_MD *cdc_md, const UINT32 page_tree_idx)
{
    CRB_NODE   *crb_node;
    CDC_PAGE   *cdc_page;

    crb_node = (CRB_NODE *)crb_tree_first_node(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx));
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    cdc_page = crb_tree_erase(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx), crb_node);
    CDC_ASSERT(CDC_PAGE_MOUNTED_PAGES(cdc_page) == crb_node);
    CDC_PAGE_MOUNTED_PAGES(cdc_page)    = NULL_PTR;
    CDC_PAGE_MOUNTED_TREE_IDX(cdc_page) = CDC_PAGE_TREE_IDX_ERR;

    dbg_log(SEC_0182_CDC, 7)(LOGSTDOUT, "[DEBUG] cdc_pop_first_page: "
                                        "pop page [%ld, %ld) from %ld (%s) tree done\n",
                                        CDC_PAGE_F_S_OFFSET(cdc_page),
                                        CDC_PAGE_F_E_OFFSET(cdc_page),
                                        page_tree_idx,
                                        ((CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) == page_tree_idx)?
                                        (const char *)"active" : (const char *)"standby"));
    return (cdc_page);
}

CDC_PAGE *cdc_pop_last_page(CDC_MD *cdc_md, const UINT32 page_tree_idx)
{
    CRB_NODE   *crb_node;
    CDC_PAGE   *cdc_page;

    crb_node = (CRB_NODE *)crb_tree_last_node(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx));
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    cdc_page = crb_tree_erase(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx), crb_node);
    CDC_ASSERT(CDC_PAGE_MOUNTED_PAGES(cdc_page) == crb_node);
    CDC_PAGE_MOUNTED_PAGES(cdc_page)    = NULL_PTR;
    CDC_PAGE_MOUNTED_TREE_IDX(cdc_page) = CDC_PAGE_TREE_IDX_ERR;

    dbg_log(SEC_0182_CDC, 7)(LOGSTDOUT, "[DEBUG] cdc_pop_last_page: "
                                        "pop page [%ld, %ld) from %ld (%s) tree done\n",
                                        CDC_PAGE_F_S_OFFSET(cdc_page),
                                        CDC_PAGE_F_E_OFFSET(cdc_page),
                                        page_tree_idx,
                                        ((CDC_MD_ACTIVE_PAGE_TREE_IDX(cdc_md) == page_tree_idx)?
                                        (const char *)"active" : (const char *)"standby"));
    return (cdc_page);
}

CDC_PAGE *cdc_search_page(CDC_MD *cdc_md, const UINT32 page_tree_idx, const int fd, const UINT32 f_s_offset, const UINT32 f_e_offset)
{
    CDC_PAGE        cdc_page_t;
    CRB_NODE       *crb_node;

    CDC_PAGE_FD(&cdc_page_t)         = fd;
    CDC_PAGE_F_S_OFFSET(&cdc_page_t) = f_s_offset;
    CDC_PAGE_F_E_OFFSET(&cdc_page_t) = f_e_offset;

    crb_node = crb_tree_search_data(CDC_MD_PAGE_TREE(cdc_md, page_tree_idx), (void *)&cdc_page_t);
    if(NULL_PTR == crb_node)
    {
        return (NULL_PTR);
    }

    return ((CDC_PAGE *)CRB_NODE_DATA(crb_node));
}

EC_BOOL cdc_cleanup_pages(CDC_MD *cdc_md, const UINT32 page_tree_idx)
{
    CDC_PAGE        *cdc_page;

    while(NULL_PTR != (cdc_page = cdc_pop_first_page(cdc_md, page_tree_idx)))
    {
        cdc_page_free(cdc_page);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_cleanup_reqs(CDC_MD *cdc_md)
{
    CDC_REQ        *cdc_req;

    while(NULL_PTR != (cdc_req = clist_pop_front(CDC_MD_REQ_LIST(cdc_md))))
    {
        CDC_REQ_MOUNTED_REQS(cdc_req) = NULL_PTR;

        cdc_req_free(cdc_req);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_cleanup_post_event_reqs(CDC_MD *cdc_md)
{
    CDC_REQ        *cdc_req;

    while(NULL_PTR != (cdc_req = clist_pop_front(CDC_MD_POST_EVENT_REQS(cdc_md))))
    {
        CDC_REQ_POST_EVENT_HANDLER(cdc_req)      = NULL_PTR;
        CDC_REQ_MOUNTED_POST_EVENT_REQS(cdc_req) = NULL_PTR;

        cdc_req_free(cdc_req);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_has_post_event_reqs(CDC_MD *cdc_md)
{
    if(EC_TRUE == clist_is_empty(CDC_MD_POST_EVENT_REQS(cdc_md)))
    {
        return (EC_FALSE); /*not post event request*/
    }
    return (EC_TRUE);/*has post event request*/
}

CDC_REQ *cdc_search_req(CDC_MD *cdc_md, const UINT32 seq_no)
{
    CDC_REQ       *cdc_req;

    cdc_req = clist_search_data_front(CDC_MD_REQ_LIST(cdc_md),
                                       (const void *)seq_no,
                                       (CLIST_DATA_DATA_CMP)cdc_req_is);

    return (cdc_req);
}

EC_BOOL cdc_mount_ssd_bad_bitmap(CDC_MD *cdc_md, CBAD_BITMAP *ssd_bad_bitmap)
{
    if(NULL_PTR == CDC_MD_SSD_BAD_BITMAP(cdc_md) && NULL_PTR != ssd_bad_bitmap)
    {
        CDC_MD_SSD_BAD_BITMAP(cdc_md)           = ssd_bad_bitmap;

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdc_umount_ssd_bad_bitmap(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_SSD_BAD_BITMAP(cdc_md))
    {
        CDC_MD_SSD_BAD_BITMAP(cdc_md)           = NULL_PTR;

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdc_is_ssd_bad_page(CDC_MD *cdc_md, const uint32_t page_no)
{
    if(NULL_PTR == CDC_MD_SSD_BAD_BITMAP(cdc_md))
    {
        return (EC_FALSE);
    }

    return cbad_bitmap_is(CDC_MD_SSD_BAD_BITMAP(cdc_md), page_no, (uint8_t)1);
}

EC_BOOL cdc_set_ssd_bad_page(CDC_MD *cdc_md, const uint32_t page_no)
{
    if(NULL_PTR == CDC_MD_SSD_BAD_BITMAP(cdc_md))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] cdc_set_ssd_bad_page: "
                                         "set ssd bad page: page %u\n",
                                         page_no);

    if(EC_FALSE == cbad_bitmap_set(CDC_MD_SSD_BAD_BITMAP(cdc_md), page_no))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_clear_ssd_bad_page(CDC_MD *cdc_md, const uint32_t page_no)
{
    if(NULL_PTR == CDC_MD_SSD_BAD_BITMAP(cdc_md))
    {
        return (EC_FALSE);
    }

    return cbad_bitmap_clear(CDC_MD_SSD_BAD_BITMAP(cdc_md), page_no);
}

EC_BOOL cdc_mount_sata_bad_bitmap(CDC_MD *cdc_md, CBAD_BITMAP *sata_bad_bitmap)
{
    if(NULL_PTR == CDC_MD_SATA_BAD_BITMAP(cdc_md) && NULL_PTR != sata_bad_bitmap)
    {
        CDC_MD_SATA_BAD_BITMAP(cdc_md)              = sata_bad_bitmap;

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdc_umount_sata_bad_bitmap(CDC_MD *cdc_md)
{
    if(NULL_PTR != CDC_MD_SATA_BAD_BITMAP(cdc_md))
    {
        CDC_MD_SATA_BAD_BITMAP(cdc_md)              = NULL_PTR;

        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cdc_is_sata_bad_page(CDC_MD *cdc_md, const uint32_t page_no)
{
    if(NULL_PTR == CDC_MD_SATA_BAD_BITMAP(cdc_md))
    {
        return (EC_FALSE);
    }

    return cbad_bitmap_is(CDC_MD_SATA_BAD_BITMAP(cdc_md), page_no, (uint8_t)1);
}

EC_BOOL cdc_set_sata_bad_page(CDC_MD *cdc_md, const uint32_t page_no)
{
    if(NULL_PTR == CDC_MD_SATA_BAD_BITMAP(cdc_md))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0093_CAIO, 0)(LOGSTDOUT, "[DEBUG] cdc_set_sata_bad_page: "
                                         "set sata bad page: page %u\n",
                                         page_no);

    if(EC_FALSE == cbad_bitmap_set(CDC_MD_SATA_BAD_BITMAP(cdc_md), page_no))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cdc_clear_sata_bad_page(CDC_MD *cdc_md, const uint32_t page_no)
{
    if(NULL_PTR == CDC_MD_SATA_BAD_BITMAP(cdc_md))
    {
        return (EC_FALSE);
    }

    return cbad_bitmap_clear(CDC_MD_SATA_BAD_BITMAP(cdc_md), page_no);
}

EC_BOOL cdc_check_ssd_bad_page(CDC_MD *cdc_md, const uint32_t node_pos)
{
    if(NULL_PTR != CDC_MD_NP(cdc_md)
    && NULL_PTR != CDC_MD_DN(cdc_md)
    && CDCNPRB_ERR_POS != node_pos)
    {
        CDCNP_ITEM      *cdcnp_item;
        CDCNP_FNODE     *cdcnp_fnode;
        CDCNP_INODE     *cdcnp_inode;
        UINT32           d_s_offset;
        uint32_t         page_no;

        cdcnp_item = cdcnp_fetch(CDC_MD_NP(cdc_md), node_pos);
        if(NULL_PTR == cdcnp_item || CDCNP_ITEM_FILE_IS_REG != CDCNP_ITEM_DIR_FLAG(cdcnp_item))
        {
            return (EC_FALSE);
        }

        cdcnp_fnode = CDCNP_ITEM_FNODE(cdcnp_item);
        cdcnp_inode = CDCNP_FNODE_INODE(cdcnp_fnode, 0);

        d_s_offset = cdcdn_node_locate(CDC_MD_DN(cdc_md),
                                CDCNP_INODE_DISK_NO(cdcnp_inode),
                                CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                CDCNP_INODE_PAGE_NO(cdcnp_inode));
        if(CDCDN_NODE_ERR_OFFSET == d_s_offset)
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_check_ssd_bad_page: "
                                                "locate (disk %u, block %u, page %u) failed\n",
                                                CDCNP_INODE_DISK_NO(cdcnp_inode),
                                                CDCNP_INODE_BLOCK_NO(cdcnp_inode),
                                                CDCNP_INODE_PAGE_NO(cdcnp_inode));
            return (EC_FALSE);
        }

        CDC_ASSERT(0 == (d_s_offset & CDCPGB_PAGE_SIZE_MASK));

        page_no = (uint32_t)(d_s_offset >> CDCPGB_PAGE_SIZE_NBITS);

        if(EC_FALSE == cdc_is_ssd_bad_page(cdc_md, page_no))/*not ssd bad page*/
        {
            return (EC_FALSE);
        }

        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "[DEBUG] cdc_check_ssd_bad_page: "
                                            "ssd bad page [%ld, %ld), page no %u\n",
                                            d_s_offset,
                                            d_s_offset + CDCPGB_PAGE_SIZE_NBYTES,
                                            page_no);
        return (EC_TRUE);/*ssd bad page*/
    }

    return (EC_FALSE); /*not ssd bad page*/
}

/*----------------------------------- cdc external interface -----------------------------------*/

/*only for degrading data from ssd to sata*/
EC_BOOL cdc_file_load_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CDC_REQ  *cdc_req;

    CDC_ASSERT(NULL_PTR != offset);

    cdc_req = cdc_req_new();
    if(NULL_PTR == cdc_req)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_load_aio: new cdc_req failed\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != caio_cb)
    {
        if(EC_FALSE == caio_cb_clone(caio_cb, CDC_REQ_CAIO_CB(cdc_req)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_load_aio: clone caio_cb to cdc_req failed\n");

            cdc_req_free(cdc_req);
            return (EC_FALSE);
        }
    }

    CDC_REQ_SEQ_NO(cdc_req)         = ++ CDC_MD_SEQ_NO(cdc_md);
    CDC_REQ_OP(cdc_req)             = CDC_OP_RD;

    CDC_REQ_KEEP_LRU_FLAG(cdc_req)  = BIT_TRUE; /*would not impact on LRU*/
    CDC_REQ_SATA_DEG_FLAG(cdc_req)  = BIT_TRUE;

    CDC_REQ_CDC_MD(cdc_req)         = cdc_md;
    CDC_REQ_FD(cdc_req)             = CDC_MD_SSD_FD(cdc_md);
    CDC_REQ_M_BUFF(cdc_req)         = buff;
    CDC_REQ_M_CACHE(cdc_req)        = NULL_PTR;
    CDC_REQ_OFFSET(cdc_req)         = offset;
    CDC_REQ_F_S_OFFSET(cdc_req)     = (*offset);
    CDC_REQ_F_E_OFFSET(cdc_req)     = (*offset) + rsize;
    CDC_REQ_U_E_OFFSET(cdc_req)     = CDC_REQ_F_E_OFFSET(cdc_req);
    CDC_REQ_TIMEOUT_NSEC(cdc_req)   = CAIO_CB_TIMEOUT_NSEC(caio_cb);
    CDC_REQ_NTIME_MS(cdc_req)       = c_get_cur_time_msec() + CAIO_CB_TIMEOUT_NSEC(caio_cb) * 1000;

    if(EC_FALSE == cdc_submit_req(cdc_md, cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_load_aio: submit req %ld failed\n",
                                             CDC_REQ_SEQ_NO(cdc_req));

        cdc_req_free(cdc_req);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_load_aio: submit req %ld done\n",
                                         CDC_REQ_SEQ_NO(cdc_req));

    return (EC_TRUE);
}

EC_BOOL cdc_file_read_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 rsize, UINT8 *buff, CAIO_CB *caio_cb)
{
    CDC_REQ  *cdc_req;

    CDC_ASSERT(NULL_PTR != offset);

    cdc_req = cdc_req_new();
    if(NULL_PTR == cdc_req)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_read_aio: new cdc_req failed\n");

        return (EC_FALSE);
    }

    if(NULL_PTR != caio_cb)
    {
        if(EC_FALSE == caio_cb_clone(caio_cb, CDC_REQ_CAIO_CB(cdc_req)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_read_aio: clone caio_cb to cdc_req failed\n");

            cdc_req_free(cdc_req);
            return (EC_FALSE);
        }
    }

    CDC_REQ_SEQ_NO(cdc_req)         = ++ CDC_MD_SEQ_NO(cdc_md);
    CDC_REQ_OP(cdc_req)             = CDC_OP_RD;

    CDC_REQ_KEEP_LRU_FLAG(cdc_req)  = BIT_FALSE; /*would impact on LRU*/

    CDC_REQ_CDC_MD(cdc_req)         = cdc_md;
    CDC_REQ_FD(cdc_req)             = CDC_MD_SSD_FD(cdc_md);
    CDC_REQ_M_BUFF(cdc_req)         = buff;
    CDC_REQ_M_CACHE(cdc_req)        = NULL_PTR;
    CDC_REQ_OFFSET(cdc_req)         = offset;
    CDC_REQ_F_S_OFFSET(cdc_req)     = (*offset);
    CDC_REQ_F_E_OFFSET(cdc_req)     = (*offset) + rsize;
    CDC_REQ_U_E_OFFSET(cdc_req)     = CDC_REQ_F_E_OFFSET(cdc_req);
    CDC_REQ_TIMEOUT_NSEC(cdc_req)   = CAIO_CB_TIMEOUT_NSEC(caio_cb);
    CDC_REQ_NTIME_MS(cdc_req)       = c_get_cur_time_msec() + CAIO_CB_TIMEOUT_NSEC(caio_cb) * 1000;

    if(EC_FALSE == cdc_submit_req(cdc_md, cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_read_aio: submit req %ld failed\n",
                                             CDC_REQ_SEQ_NO(cdc_req));

        cdc_req_free(cdc_req);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_read_aio: submit req %ld done\n",
                                         CDC_REQ_SEQ_NO(cdc_req));

    return (EC_TRUE);
}

/*write in detached model*/
EC_BOOL cdc_file_write_aio(CDC_MD *cdc_md, UINT32 *offset, const UINT32 wsize, UINT8 *buff,
                              const uint32_t sata_dirty_flag,
                              CAIO_CB *caio_cb)
{
    CDC_REQ  *cdc_req;
    UINT32    timeout_nsec;
    uint32_t  detached_flag;

    CDC_ASSERT(NULL_PTR != offset);

    if(EC_TRUE == cdc_is_read_only(cdc_md))
    {
        dbg_log(SEC_0182_CDC, 3)(LOGSTDOUT, "error:cdc_file_write_aio: cdc is read-only\n");
        return (EC_FALSE);
    }

    /*WARNING: detached model need to copy app data to buff at once*/
    detached_flag = BIT_TRUE;

    cdc_req = cdc_req_new();
    if(NULL_PTR == cdc_req)
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write_aio: new cdc_req failed\n");

        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    if(NULL_PTR != caio_cb)
    {
        if(EC_FALSE == caio_cb_clone(caio_cb, CDC_REQ_CAIO_CB(cdc_req)))
        {
            dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write_aio: "
                                                "clone caio_cb to cdc_req failed\n");

            cdc_req_free(cdc_req);
            caio_cb_exec_terminate_handler(caio_cb);
            return (EC_FALSE);
        }
    }

    CDC_REQ_SEQ_NO(cdc_req)          = ++ CDC_MD_SEQ_NO(cdc_md);
    CDC_REQ_OP(cdc_req)              = CDC_OP_WR;

    CDC_REQ_KEEP_LRU_FLAG(cdc_req)   = BIT_FALSE; /*would impact on LRU*/
    CDC_REQ_SATA_DIRTY_FLAG(cdc_req) = sata_dirty_flag;

    CDC_REQ_CDC_MD(cdc_req)          = cdc_md;
    CDC_REQ_FD(cdc_req)              = CDC_MD_SSD_FD(cdc_md);
    CDC_REQ_M_BUFF(cdc_req)          = buff;
    CDC_REQ_M_CACHE(cdc_req)         = NULL_PTR;

    if(BIT_TRUE == detached_flag)
    {
        CDC_REQ_DETACHED_FLAG(cdc_req) = BIT_TRUE;
        CDC_REQ_OFFSET(cdc_req)        = NULL_PTR;
    }
    else
    {
        CDC_REQ_DETACHED_FLAG(cdc_req) = BIT_FALSE;
        CDC_REQ_OFFSET(cdc_req)        = offset;
    }

    if(NULL_PTR != caio_cb)
    {
        timeout_nsec = CAIO_CB_TIMEOUT_NSEC(caio_cb);
    }
    else
    {
        timeout_nsec = CDC_AIO_TIMEOUT_NSEC_DEFAULT;
    }

    CDC_REQ_F_S_OFFSET(cdc_req)   = (*offset);
    CDC_REQ_F_E_OFFSET(cdc_req)   = (*offset) + wsize;
    CDC_REQ_U_E_OFFSET(cdc_req)   = CDC_REQ_F_E_OFFSET(cdc_req);
    CDC_REQ_TIMEOUT_NSEC(cdc_req) = timeout_nsec;
    CDC_REQ_NTIME_MS(cdc_req)     = c_get_cur_time_msec() + timeout_nsec * 1000;

    if(EC_FALSE == cdc_submit_req(cdc_md, cdc_req))
    {
        dbg_log(SEC_0182_CDC, 0)(LOGSTDOUT, "error:cdc_file_write_aio: submit req %ld failed\n",
                                             CDC_REQ_SEQ_NO(cdc_req));

        cdc_req_free(cdc_req);
        caio_cb_exec_terminate_handler(caio_cb);
        return (EC_FALSE);
    }

    dbg_log(SEC_0182_CDC, 9)(LOGSTDOUT, "[DEBUG] cdc_file_write_aio: submit req %ld done\n",
                                         CDC_REQ_SEQ_NO(cdc_req));

    if(BIT_TRUE == detached_flag)
    {
        (*offset) += wsize;
        //caio_cb_exec_complete_handler(caio_cb);
    }

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

