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
#include "cstring.h"

#include "carray.h"
#include "cvector.h"

#include "cbc.h"
#include "ctimer.h"
#include "cbtimer.h"
#include "cmisc.h"

#include "real.h"

#include "task.h"

#include "csocket.h"

#include "cmpie.h"

#include "cbadbitmap.h"

#include "crb.h"
#include "chttp.h"
#include "chttps.h"

#include "cxfs.h"
#include "cxfshttp.h"
#include "cxfshttps.h"
#include "cxfscfg.h"

#include "cxfsop.h"
#include "cxfsnpdel.h"

#include "cmd5.h"
#include "cbase64code.h"

#include "findex.inc"

#define CXFS_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFS))

#define CXFS_MD_GET(cxfs_md_id)     ((CXFS_MD *)cbc_md_get(MD_CXFS, (cxfs_md_id)))

#define CXFS_MD_ID_CHECK_INVALID(cxfs_md_id)  \
    ((CMPI_ANY_MODI != (cxfs_md_id)) && ((NULL_PTR == CXFS_MD_GET(cxfs_md_id)) || (0 == (CXFS_MD_GET(cxfs_md_id)->usedcounter))))

STATIC_CAST static CXFSNP_FNODE * __cxfs_reserve_npp(const UINT32 cxfs_md_id, const CSTRING *file_path);
STATIC_CAST static EC_BOOL __cxfs_release_npp(const UINT32 cxfs_md_id, const CSTRING *file_path);
STATIC_CAST static EC_BOOL __cxfs_recycle_of_np(const UINT32 cxfs_md_id, const uint32_t cxfsnp_id, const UINT32 max_num, UINT32 *complete_num);

/**
*
*  delete file data from current dn
*
**/
STATIC_CAST static EC_BOOL __cxfs_delete_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode);

STATIC_CAST static EC_BOOL __cxfs_check_path_has_wildcard(const CSTRING *path);

/**
*   for test only
*
*   to query the status of CXFS Module
*
**/
void cxfs_print_module_status(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;
    UINT32 this_cxfs_md_id;

    for( this_cxfs_md_id = 0; this_cxfs_md_id < CXFS_MD_CAPACITY(); this_cxfs_md_id ++ )
    {
        cxfs_md = CXFS_MD_GET(this_cxfs_md_id);

        if ( NULL_PTR != cxfs_md && 0 < cxfs_md->usedcounter )
        {
            sys_log(log,"CXFS Module # %ld : %ld refered\n",
                    this_cxfs_md_id,
                    cxfs_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CXFS module
*
*
**/
UINT32 cxfs_free_module_static_mem(const UINT32 cxfs_md_id)
{
    //CXFS_MD  *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_free_module_static_mem: cxfs module #%ld not started.\n",
                cxfs_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    free_module_static_mem(MD_CXFS, cxfs_md_id);

    return 0;
}

/**
*
* start CXFS module
*
**/
UINT32 cxfs_start(const CSTRING *sata_disk_path, const CSTRING *ssd_disk_path)
{
    CXFS_MD    *cxfs_md;
    UINT32      cxfs_md_id;

    EC_BOOL     ret;

    CXFSCFG    *cxfscfg;

    UINT32      sata_disk_size;
    UINT32      ssd_disk_size;

    int         sata_disk_fd;
    int         ssd_disk_fd;

    cbc_md_reg(MD_CXFS, 32);

    cxfs_md_id = cbc_md_new(MD_CXFS, sizeof(CXFS_MD));
    if(CMPI_ERROR_MODI == cxfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /*check validity*/
    if(CXFS_MAX_MODI < cxfs_md_id) /*limited to 2-digital*/
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: cxfs_md_id %ld overflow\n", cxfs_md_id);

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    /*sata*/
    if(NULL_PTR == sata_disk_path)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: sata path is null\n");

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: sata path: %s\n",
                                         (char *)cstring_get_str(sata_disk_path));

    if(EC_FALSE == c_file_exist((char *)cstring_get_str(sata_disk_path))
    && EC_FALSE == c_dev_exist((char *)cstring_get_str(sata_disk_path)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: sata '%s' is not file or block device\n",
                                             (char *)cstring_get_str(sata_disk_path));

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    sata_disk_fd = c_file_open((char *)cstring_get_str(sata_disk_path), O_RDWR | O_DIRECT /*| O_SYNC*/, 0666);
    if(ERR_FD == sata_disk_fd)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open sata '%s' failed\n",
                                             (char *)cstring_get_str(sata_disk_path));

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == c_file_size(sata_disk_fd, &sata_disk_size))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: size of sata '%s' failed\n",
                                             (char *)cstring_get_str(sata_disk_path));

        cbc_md_free(MD_CXFS, cxfs_md_id);
        c_file_close(sata_disk_fd);
        return (CMPI_ERROR_MODI);
    }

    /*ssd*/
    if(NULL_PTR == ssd_disk_path)
    {
        ssd_disk_fd     = ERR_FD;
        ssd_disk_size   = 0;
    }
    else if(EC_FALSE == c_file_exist((char *)cstring_get_str(ssd_disk_path))
         && EC_FALSE == c_dev_exist((char *)cstring_get_str(ssd_disk_path)))
    {
        ssd_disk_fd     = ERR_FD;
        ssd_disk_size   = 0;
    }
    else
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: ssd path: %s\n",
                                     (char *)cstring_get_str(ssd_disk_path));


        ssd_disk_fd = c_file_open((char *)cstring_get_str(ssd_disk_path), O_RDWR | O_DIRECT /*| O_SYNC*/, 0666);
        if(ERR_FD == ssd_disk_fd)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open ssd '%s' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_size(ssd_disk_fd, &ssd_disk_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: size of ssd '%s' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(ssd_disk_fd);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }
    }

    /* initialize new one CXFS module */
    cxfs_md = (CXFS_MD *)cbc_md_get(MD_CXFS, cxfs_md_id);
    cxfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFS_MD_READ_ONLY_FLAG(cxfs_md) = BIT_FALSE;

    cstring_init(CXFS_MD_SATA_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;

    cstring_init(CXFS_MD_SSD_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ERR_FD;

    cxfscfg_init(CXFS_MD_CFG(cxfs_md));

    /*initialize LOCK_REQ file RB TREE*/
    crb_tree_init(CXFS_MD_LOCKED_FILES(cxfs_md),
                    (CRB_DATA_CMP)cxfs_locked_file_cmp,
                    (CRB_DATA_FREE)cxfs_locked_file_free,
                    (CRB_DATA_PRINT)cxfs_locked_file_print);

    /*initialize WAIT file RB TREE*/
    crb_tree_init(CXFS_MD_WAIT_FILES(cxfs_md),
                    (CRB_DATA_CMP)cxfs_wait_file_cmp,
                    (CRB_DATA_FREE)cxfs_wait_file_free,
                    (CRB_DATA_PRINT)cxfs_wait_file_print);

    CXFS_MD_SYNC_FLAG(cxfs_md)              = BIT_FALSE;
    CXFS_MD_NP_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_DN_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_DUMP_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_REPLAY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_DN(cxfs_md)                     = NULL_PTR;
    CXFS_MD_NPP(cxfs_md)                    = NULL_PTR;
    CXFS_MD_SATA_BAD_BITMAP(cxfs_md)        = NULL_PTR;
    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
    CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;
    CXFS_MD_OP_MGR(cxfs_md)                 = NULL_PTR;
    CXFS_MD_OP_DUMP_OFFSET(cxfs_md)         = 0;

    /*load config*/
    if(EC_FALSE == cxfscfg_load(CXFS_MD_CFG(cxfs_md), sata_disk_fd))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: load cfg failed\n");

        cbc_md_free(MD_CXFS, cxfs_md_id);
        c_file_close(ssd_disk_fd);
        c_file_close(sata_disk_fd);
        return (CMPI_ERROR_MODI);
    }

    CXFS_MD_SATA_DISK_FD(cxfs_md) = sata_disk_fd;
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ssd_disk_fd;

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    ret = EC_TRUE;

    if(CXFSCFG_MAGIC_NUM == CXFSCFG_MAGIC(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: cxfscfg is\n");
        cxfscfg_print(LOGSTDOUT, cxfscfg);

        if(EC_TRUE == ret)
        {
            if(EC_FALSE == cxfs_load_sata_bad_bitmap(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: load sata bad bitmap failed\n");
                ret = EC_FALSE;
            }
        }

        if(EC_TRUE == ret)
        {
            CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr_open(CXFS_MD_SATA_DISK_FD(cxfs_md), cxfscfg);
            if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open npp failed\n");
                ret = EC_FALSE;
            }
        }

        /*fix: to reduce the np loading time elapsed*/
        if(EC_TRUE == ret && NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            if(EC_FALSE == cxfsnp_mgr_open_np_all(CXFS_MD_NPP(cxfs_md)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open all np failed\n");

                cxfsnp_mgr_close_np_all(CXFS_MD_NPP(cxfs_md));/*roll back*/

                ret = EC_FALSE;
            }
        }

        if(EC_TRUE == ret)
        {
            CXFS_MD_DN(cxfs_md) = cxfsdn_open(cxfscfg,
                                              CXFS_MD_SATA_DISK_FD(cxfs_md),
                                              CXFS_MD_SSD_DISK_FD(cxfs_md));
            if(NULL_PTR == CXFS_MD_DN(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open dn failed\n");
                ret = EC_FALSE;
            }
        }

        if(EC_TRUE == ret && NULL_PTR != CXFS_MD_DN(cxfs_md) && NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cxfsdn_mount_sata_bad_bitmap(CXFS_MD_DN(cxfs_md), CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        }
    }

    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CXFS_MD_DN(cxfs_md))
        {
            cxfsdn_close(CXFS_MD_DN(cxfs_md));
            CXFS_MD_DN(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            cxfsnp_mgr_close(CXFS_MD_NPP(cxfs_md));
            CXFS_MD_NPP(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cbad_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
            CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;
        }

        CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
        CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;

        if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
            CXFS_MD_SSD_DISK_FD(cxfs_md) = ERR_FD;
        }

        if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
            CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
        }

        cbc_md_free(MD_CXFS, cxfs_md_id);

        return (CMPI_ERROR_MODI);
    }

    if(CXFSCFG_MAGIC_NUM != CXFSCFG_MAGIC(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: magic mismatched\n");

        cxfscfg_clean(cxfscfg); /*clean up dirty data*/

        CXFSCFG_OP_S_OFFSET(cxfscfg)        = CXFSCFG_SIZE
                                            + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

        CXFSCFG_OP_E_OFFSET(cxfscfg)        = CXFSCFG_SIZE
                                            + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES
                                            + CXFS_OP_TABLE_SIZE_NBYTES;


        /*set basic info to config for fresh xfs*/
        CXFSCFG_SATA_DISK_SIZE(cxfscfg)     = sata_disk_size;
        CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)   = CXFSCFG_SIZE
                                            + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES
                                            + CXFS_OP_TABLE_SIZE_NBYTES;

        CXFSCFG_SSD_DISK_SIZE(cxfscfg)      = ssd_disk_size;
        CXFSCFG_SSD_DISK_OFFSET(cxfscfg)    = CXFSDN_CAMD_SSD_DISK_OFFSET + 0;
    }

    CXFS_MD_STATE(cxfs_md) = CXFS_WORK_STATE;

    cxfs_md->usedcounter = 1;

    cstring_clone(sata_disk_path, CXFS_MD_SATA_DISK_PATH(cxfs_md));

    /*dump npp to standby zone*/
    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        if(EC_FALSE == cxfs_dump_npp(cxfs_md_id))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: dump npp to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    /*dump dn to standby zone*/
    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        if(EC_FALSE == cxfs_dump_dn(cxfs_md_id))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: dump dn to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    /*op mgr*/
    if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
    {
        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_create(CXFS_OP_MCACHE_SIZE_NBYTES);
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: create op mcache failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md)
        && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))
        && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
        {
            cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)));
            dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_start: mount camd to op mgr done\n");
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md)
        && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
        {
            cxfsnp_mgr_mount_op_mgr(CXFS_MD_NPP(cxfs_md), CXFS_MD_OP_MGR(cxfs_md));
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: create op mcache done\n");
    }

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfs_end, cxfs_md_id);

    task_brd_process_add(task_brd_default_get(),
                        TASK_BRD_PROCESS_LOOP,
                        (TASK_BRD_CALLBACK)cxfs_sync_sata_bad_bitmap,
                        (void *)cxfs_md);
#if 1
    task_brd_process_add(task_brd_default_get(),
                        TASK_BRD_PROCESS_LOOP,
                        (TASK_BRD_CALLBACK)cxfs_process_op,
                        (void *)cxfs_md_id);
#endif

    task_brd_process_add(task_brd_default_get(),
                        TASK_BRD_PROCESS_LOOP,
                        (TASK_BRD_CALLBACK)cxfs_process_space,
                        (void *)cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: start CXFS module #%ld\n", cxfs_md_id);

    if(SWITCH_ON == CXFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CXFS module is allowed to launch xfs http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled()
        && NULL_PTR != task_brd_default_get_cepoll()
        && 0 == cxfs_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: init cxfshttp defer request queue failed\n");
                cxfs_end(cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }

            cxfshttp_log_start();
            task_brd_default_bind_http_srv_modi(cxfs_md_id);
            chttp_rest_list_push((const char *)CXFSHTTP_REST_API_NAME, cxfshttp_commit_request);
        }

        /*https server*/
#if 1
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled()
        && NULL_PTR != task_brd_default_get_cepoll()
        && 0 == cxfs_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: init cxfshttp defer request queue failed\n");
                cxfs_end(cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }
            cxfshttps_log_start();
            task_brd_default_bind_https_srv_modi(cxfs_md_id);
            chttps_rest_list_push((const char *)CXFSHTTPS_REST_API_NAME, cxfshttps_commit_request);
        }
#endif
    }

    return ( cxfs_md_id );
}

/**
*
* retrieve CXFS module
*
**/
UINT32 cxfs_retrieve(const CSTRING *sata_disk_path, const CSTRING *ssd_disk_path)
{
    CXFS_MD    *cxfs_md;
    UINT32      cxfs_md_id;

    EC_BOOL     ret;

    CXFSCFG    *cxfscfg;

    UINT32      sata_disk_size;
    UINT32      ssd_disk_size;

    int         sata_disk_fd;
    int         ssd_disk_fd;

    cbc_md_reg(MD_CXFS, 32);

    cxfs_md_id = cbc_md_new(MD_CXFS, sizeof(CXFS_MD));
    if(CMPI_ERROR_MODI == cxfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /*check validity*/
    if(CXFS_MAX_MODI < cxfs_md_id) /*limited to 2-digital*/
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: cxfs_md_id %ld overflow\n", cxfs_md_id);

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    /*sata*/
    if(NULL_PTR == sata_disk_path)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: sata path is null\n");

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: sata path: %s\n",
                                         (char *)cstring_get_str(sata_disk_path));

    if(EC_FALSE == c_file_exist((char *)cstring_get_str(sata_disk_path))
    && EC_FALSE == c_dev_exist((char *)cstring_get_str(sata_disk_path)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: sata '%s' is not file or block device\n",
                                             (char *)cstring_get_str(sata_disk_path));

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    sata_disk_fd = c_file_open((char *)cstring_get_str(sata_disk_path), O_RDWR | O_DIRECT /*| O_SYNC*/, 0666);
    if(ERR_FD == sata_disk_fd)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open sata '%s' failed\n",
                                             (char *)cstring_get_str(sata_disk_path));

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    if(EC_FALSE == c_file_size(sata_disk_fd, &sata_disk_size))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: size of sata '%s' failed\n",
                                             (char *)cstring_get_str(sata_disk_path));

        cbc_md_free(MD_CXFS, cxfs_md_id);
        c_file_close(sata_disk_fd);
        return (CMPI_ERROR_MODI);
    }

    /*ssd*/
    if(NULL_PTR == ssd_disk_path)
    {
        ssd_disk_fd     = ERR_FD;
        ssd_disk_size   = 0;
    }
    else if(EC_FALSE == c_file_exist((char *)cstring_get_str(ssd_disk_path))
         && EC_FALSE == c_dev_exist((char *)cstring_get_str(ssd_disk_path)))
    {
        ssd_disk_fd     = ERR_FD;
        ssd_disk_size   = 0;
    }
    else
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: ssd path: %s\n",
                                             (char *)cstring_get_str(ssd_disk_path));

        ssd_disk_fd = c_file_open((char *)cstring_get_str(ssd_disk_path), O_RDWR | O_DIRECT /*| O_SYNC*/, 0666);
        if(ERR_FD == ssd_disk_fd)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open ssd '%s' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_size(ssd_disk_fd, &ssd_disk_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: size of ssd '%s' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(ssd_disk_fd);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }
    }

    /* initialize new one CXFS module */
    cxfs_md = (CXFS_MD *)cbc_md_get(MD_CXFS, cxfs_md_id);
    cxfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFS_MD_READ_ONLY_FLAG(cxfs_md) = BIT_FALSE;

    cstring_init(CXFS_MD_SATA_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;

    cstring_init(CXFS_MD_SSD_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ERR_FD;

    cxfscfg_init(CXFS_MD_CFG(cxfs_md));

    /*initialize LOCK_REQ file RB TREE*/
    crb_tree_init(CXFS_MD_LOCKED_FILES(cxfs_md),
                    (CRB_DATA_CMP)cxfs_locked_file_cmp,
                    (CRB_DATA_FREE)cxfs_locked_file_free,
                    (CRB_DATA_PRINT)cxfs_locked_file_print);

    /*initialize WAIT file RB TREE*/
    crb_tree_init(CXFS_MD_WAIT_FILES(cxfs_md),
                    (CRB_DATA_CMP)cxfs_wait_file_cmp,
                    (CRB_DATA_FREE)cxfs_wait_file_free,
                    (CRB_DATA_PRINT)cxfs_wait_file_print);

    CXFS_MD_SYNC_FLAG(cxfs_md)              = BIT_FALSE;
    CXFS_MD_NP_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_DN_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_DUMP_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_REPLAY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_DN(cxfs_md)                     = NULL_PTR;
    CXFS_MD_NPP(cxfs_md)                    = NULL_PTR;
    CXFS_MD_SATA_BAD_BITMAP(cxfs_md)        = NULL_PTR;
    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
    CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;
    CXFS_MD_OP_MGR(cxfs_md)                 = NULL_PTR;
    CXFS_MD_OP_DUMP_OFFSET(cxfs_md)         = 0;

    /*load config*/
    if(EC_FALSE == cxfscfg_load(CXFS_MD_CFG(cxfs_md), sata_disk_fd))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: load cfg failed\n");

        cbc_md_free(MD_CXFS, cxfs_md_id);
        c_file_close(ssd_disk_fd);
        c_file_close(sata_disk_fd);
        return (CMPI_ERROR_MODI);
    }

    CXFS_MD_SATA_DISK_FD(cxfs_md) = sata_disk_fd;
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ssd_disk_fd;

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    ret = EC_TRUE;

    /*do not check magic and switch active and standby*/
    CXFSCFG_NP_ZONE_SWITCH(cxfscfg);
    CXFSCFG_DN_ZONE_SWITCH(cxfscfg);

    CXFSCFG_MAGIC(cxfscfg) = CXFSCFG_MAGIC_NUM; /*reset*/

    if(CXFSCFG_MAGIC_NUM == CXFSCFG_MAGIC(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: cxfscfg is\n");
        cxfscfg_print(LOGSTDOUT, cxfscfg);

        if(EC_TRUE == ret)
        {
            if(EC_FALSE == cxfs_load_sata_bad_bitmap(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: load sata bad bitmap failed\n");
                ret = EC_FALSE;
            }
        }

        if(EC_TRUE == ret)
        {
            CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr_open(CXFS_MD_SATA_DISK_FD(cxfs_md), cxfscfg);
            if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open npp failed\n");
                ret = EC_FALSE;
            }
        }

        /*fix: to reduce the np loading time elapsed*/
        if(EC_TRUE == ret && NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            if(EC_FALSE == cxfsnp_mgr_open_np_all(CXFS_MD_NPP(cxfs_md)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open all np failed\n");

                cxfsnp_mgr_close_np_all(CXFS_MD_NPP(cxfs_md));/*roll back*/

                ret = EC_FALSE;
            }
        }

        if(EC_TRUE == ret)
        {
            CXFS_MD_DN(cxfs_md) = cxfsdn_open(cxfscfg,
                                              CXFS_MD_SATA_DISK_FD(cxfs_md),
                                              CXFS_MD_SSD_DISK_FD(cxfs_md));
            if(NULL_PTR == CXFS_MD_DN(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open dn failed\n");
                ret = EC_FALSE;
            }
        }

        if(EC_TRUE == ret && NULL_PTR != CXFS_MD_DN(cxfs_md) && NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cxfsdn_mount_sata_bad_bitmap(CXFS_MD_DN(cxfs_md), CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        }
    }

    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CXFS_MD_DN(cxfs_md))
        {
            cxfsdn_close(CXFS_MD_DN(cxfs_md));
            CXFS_MD_DN(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            cxfsnp_mgr_close(CXFS_MD_NPP(cxfs_md));
            CXFS_MD_NPP(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cbad_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
            CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;
        }

        CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
        CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;

        if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
            CXFS_MD_SSD_DISK_FD(cxfs_md) = ERR_FD;
        }

        if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
            CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
        }

        cbc_md_free(MD_CXFS, cxfs_md_id);

        return (CMPI_ERROR_MODI);
    }

    CXFS_MD_STATE(cxfs_md) = CXFS_WORK_STATE;

    cxfs_md->usedcounter = 1;

    cstring_clone(sata_disk_path, CXFS_MD_SATA_DISK_PATH(cxfs_md));

    /*replay op*/
    if(NULL_PTR != CXFS_MD_DN(cxfs_md)
    && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))
    && NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
    {
        void    *op_data;
        UINT32   op_offset;
        UINT32   op_size;

        op_offset = CXFSCFG_OP_S_OFFSET(cxfscfg);
        op_size   = CXFSCFG_OP_E_OFFSET(cxfscfg) - CXFSCFG_OP_S_OFFSET(cxfscfg);
        op_data   = c_file_mmap(sata_disk_fd,
                              op_offset,
                              op_size,
                              CXFS_MEM_ALIGNMENT,
                              PROT_READ /*| PROT_WRITE*/,
                              MAP_SHARED | MAP_FIXED);
        if(NULL_PTR == op_data)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: mmap sata [%ld, %ld) failed\n",
                                                 op_offset, op_offset + op_size);
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }

        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_new();
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: new op mgr failed\n");

            c_file_munmap(op_data, op_size);

            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }

        cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)));
        cxfsop_mgr_mount_data(CXFS_MD_OP_MGR(cxfs_md), op_size, op_data);

        cxfsnp_mgr_mount_op_mgr(CXFS_MD_NPP(cxfs_md), CXFS_MD_OP_MGR(cxfs_md));

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: mount op data %p, size %ld\n",
                                             op_data, op_size);

        if(EC_FALSE == cxfs_replay_op(cxfs_md_id))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: replay failed\n");

            cxfsop_mgr_umount_camd(CXFS_MD_OP_MGR(cxfs_md));
            cxfsop_mgr_umount_data(CXFS_MD_OP_MGR(cxfs_md), NULL_PTR, NULL_PTR);

            cxfsnp_mgr_umount_op_mgr(CXFS_MD_NPP(cxfs_md));

            c_file_munmap(op_data, op_size);

            cxfsop_mgr_free(CXFS_MD_OP_MGR(cxfs_md));
            CXFS_MD_OP_MGR(cxfs_md) = NULL_PTR;

            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }

        cxfsop_mgr_umount_camd(CXFS_MD_OP_MGR(cxfs_md));
        cxfsop_mgr_umount_data(CXFS_MD_OP_MGR(cxfs_md), NULL_PTR, NULL_PTR);

        cxfsnp_mgr_umount_op_mgr(CXFS_MD_NPP(cxfs_md));

        c_file_munmap(op_data, op_size);

        cxfsop_mgr_free(CXFS_MD_OP_MGR(cxfs_md));
        CXFS_MD_OP_MGR(cxfs_md) = NULL_PTR;
    }

    /*op mgr*/
    if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
    {
        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_create(CXFS_OP_MCACHE_SIZE_NBYTES);
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: create op mcache failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md)
        && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))
        && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
        {
            cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)));
            dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: mount camd to op mgr done\n");
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md)
        && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
        {
            cxfsnp_mgr_mount_op_mgr(CXFS_MD_NPP(cxfs_md), CXFS_MD_OP_MGR(cxfs_md));
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: create op mcache done\n");
    }

    /*dump npp to standby zone*/
    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        if(EC_FALSE == cxfs_dump_npp(cxfs_md_id))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: dump npp to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    /*dump dn to standby zone*/
    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        if(EC_FALSE == cxfs_dump_dn(cxfs_md_id))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: dump dn to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    CXFSCFG_OP_DUMP_TIME_MSEC(CXFS_MD_CFG(cxfs_md)) = c_get_cur_time_msec();

    /*dump cxfscfg*/
    cxfscfg_flush(CXFS_MD_CFG(cxfs_md), CXFS_MD_SATA_DISK_FD(cxfs_md));

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfs_end, cxfs_md_id);

    task_brd_process_add(task_brd_default_get(),
                        TASK_BRD_PROCESS_LOOP,
                        (TASK_BRD_CALLBACK)cxfs_sync_sata_bad_bitmap,
                        (void *)cxfs_md);

#if 1
    task_brd_process_add(task_brd_default_get(),
                        TASK_BRD_PROCESS_LOOP,
                        (TASK_BRD_CALLBACK)cxfs_process_op,
                        (void *)cxfs_md_id);
#endif

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: start CXFS module #%ld\n", cxfs_md_id);

    if(SWITCH_ON == CXFSHTTP_SWITCH && CMPI_FWD_RANK == CMPI_LOCAL_RANK)
    {
        /*note: only the first CXFS module is allowed to launch xfs http server*/
        /*http server*/
        if(EC_TRUE == task_brd_default_check_csrv_enabled()
        && NULL_PTR != task_brd_default_get_cepoll()
        && 0 == cxfs_md_id)
        {
            if(EC_FALSE == chttp_defer_request_queue_init())
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: init cxfshttp defer request queue failed\n");
                cxfs_end(cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }

            cxfshttp_log_start();
            task_brd_default_bind_http_srv_modi(cxfs_md_id);
            chttp_rest_list_push((const char *)CXFSHTTP_REST_API_NAME, cxfshttp_commit_request);
        }

        /*https server*/
#if 1
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled()
        && NULL_PTR != task_brd_default_get_cepoll()
        && 0 == cxfs_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: init cxfshttp defer request queue failed\n");
                cxfs_end(cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }
            cxfshttps_log_start();
            task_brd_default_bind_https_srv_modi(cxfs_md_id);
            chttps_rest_list_push((const char *)CXFSHTTPS_REST_API_NAME, cxfshttps_commit_request);
        }
#endif
    }

    return ( cxfs_md_id );
}

/**
*
* end CXFS module
*
**/
void cxfs_end(const UINT32 cxfs_md_id)
{
    CXFS_MD *cxfs_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cxfs_end, cxfs_md_id);

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == cxfs_md)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_end: cxfs_md_id = %ld not exist.\n", cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cxfs_md->usedcounter )
    {
        cxfs_md->usedcounter --;
        return ;
    }

    if ( 0 == cxfs_md->usedcounter )
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_end: cxfs_md_id = %ld is not started.\n", cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }

    CXFS_MD_STATE(cxfs_md) = CXFS_ERR_STATE;

    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        cxfsdn_close(CXFS_MD_DN(cxfs_md));
        CXFS_MD_DN(cxfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        cxfsnp_mgr_close(CXFS_MD_NPP(cxfs_md));
        CXFS_MD_NPP(cxfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_free(CXFS_MD_OP_MGR(cxfs_md));
        CXFS_MD_OP_MGR(cxfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        cxfs_flush_sata_bad_bitmap(cxfs_md);

        cbad_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;
    }

    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
    CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;

    if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_end: cxfscfg is\n");
        cxfscfg_print(LOGSTDOUT, CXFS_MD_CFG(cxfs_md));

        cxfscfg_flush(CXFS_MD_CFG(cxfs_md), CXFS_MD_SATA_DISK_FD(cxfs_md));
        cxfscfg_clean(CXFS_MD_CFG(cxfs_md));
    }

    if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
        CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
    }

    cstring_clean(CXFS_MD_SATA_DISK_PATH(cxfs_md));

    crb_tree_clean(CXFS_MD_LOCKED_FILES(cxfs_md));
    crb_tree_clean(CXFS_MD_WAIT_FILES(cxfs_md));

    cxfscfg_clean(CXFS_MD_CFG(cxfs_md));

    CXFS_MD_READ_ONLY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_SYNC_FLAG(cxfs_md)              = BIT_FALSE;
    CXFS_MD_NP_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_DN_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_DUMP_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_REPLAY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_OP_DUMP_OFFSET(cxfs_md)         = 0;

    /* free module : */
    //cxfs_free_module_static_mem(cxfs_md_id);

    cxfs_md->usedcounter = 0;

    cbc_md_free(MD_CXFS, cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_end: stop CXFS module #%ld\n", cxfs_md_id);

    return ;
}

/**
*
* sync CXFS to disk
*
**/
EC_BOOL cxfs_sync(const UINT32 cxfs_md_id)
{
    CXFS_MD  *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_sync: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_TRUE; /*set sync mode*/

        task_brd_process_add(task_brd_default_get(),
                             TASK_BRD_PROCESS_ONCE,
                             (TASK_BRD_CALLBACK)cxfs_sync,
                             (void *)cxfs_md_id);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync: "
                                             "add process\n");

        /*fall through*/
    }

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_FALSE == CXFS_MD_READ_ONLY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_DN(cxfs_md)
    && EC_FALSE == cxfsdn_can_sync(CXFS_MD_DN(cxfs_md)))
    {
        task_brd_process_add(task_brd_default_get(),
                             TASK_BRD_PROCESS_ONCE,
                             (TASK_BRD_CALLBACK)cxfs_sync,
                             (void *)cxfs_md_id);

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_sync: "
                                             "retry => add process\n");
        return (EC_TRUE);
    }

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_FALSE == CXFS_MD_READ_ONLY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_DN(cxfs_md)
    && EC_TRUE == cxfsdn_can_sync(CXFS_MD_DN(cxfs_md)))
    {
        EC_BOOL     ret;

        ret = EC_TRUE;

        cxfs_set_read_only(cxfs_md_id); /*set read-only mode*/

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md) && EC_TRUE == ret)
        {
            if(EC_FALSE == cxfsnp_mgr_start_sync(CXFS_MD_NPP(cxfs_md)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync: "
                                                     "npp start sync failed\n");
                ret = EC_FALSE;
            }
            else
            {
                CXFS_MD_NP_SYNC_FLAG(cxfs_md) = BIT_TRUE;
            }
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md) && EC_TRUE == ret)
        {
            if(EC_FALSE == cxfsdn_start_sync(CXFS_MD_DN(cxfs_md)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync: "
                                                     "dn start sync failed\n");
                ret = EC_FALSE;
            }
            else
            {
                CXFS_MD_DN_SYNC_FLAG(cxfs_md) = BIT_TRUE;
            }
        }

        if(EC_FALSE == ret)
        {
            if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
            {
                cxfsnp_mgr_end_sync(CXFS_MD_NPP(cxfs_md));
                CXFS_MD_NP_SYNC_FLAG(cxfs_md) = BIT_FALSE;
            }

            if(NULL_PTR != CXFS_MD_DN(cxfs_md))
            {
                cxfsdn_end_sync(CXFS_MD_DN(cxfs_md));
                CXFS_MD_DN_SYNC_FLAG(cxfs_md) = BIT_FALSE;
            }

            cxfs_unset_read_only(cxfs_md_id); /*unset read-only mode*/

            task_brd_process_add(task_brd_default_get(),
                                TASK_BRD_PROCESS_LOOP,
                                (TASK_BRD_CALLBACK)cxfs_process_op,
                                (void *)cxfs_md_id);

            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync: "
                                             "npp and dn start sync done\n");
        /*fall through*/
    }

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        if(NULL_PTR != CXFS_MD_NPP(cxfs_md)
        && BIT_TRUE == CXFS_MD_NP_SYNC_FLAG(cxfs_md))
        {
            if(EC_TRUE == cxfsnp_mgr_is_sync(CXFS_MD_NPP(cxfs_md)))
            {
                cxfsnp_mgr_process_sync(CXFS_MD_NPP(cxfs_md));
            }
            else
            {
                cxfsnp_mgr_end_sync(CXFS_MD_NPP(cxfs_md));
                CXFS_MD_NP_SYNC_FLAG(cxfs_md) = BIT_FALSE; /*clear*/
            }
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md)
        && BIT_TRUE == CXFS_MD_DN_SYNC_FLAG(cxfs_md))
        {
            if(EC_TRUE == cxfsdn_is_sync(CXFS_MD_DN(cxfs_md)))
            {
                cxfsdn_process_sync(CXFS_MD_DN(cxfs_md));
            }
            else
            {
                cxfsdn_end_sync(CXFS_MD_DN(cxfs_md));
                CXFS_MD_DN_SYNC_FLAG(cxfs_md) = BIT_FALSE; /*clear*/
            }
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md)
        && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))
        && BIT_FALSE == CXFS_MD_NP_SYNC_FLAG(cxfs_md)
        && BIT_FALSE == CXFS_MD_DN_SYNC_FLAG(cxfs_md))
        {
            MOD_NODE      mod_node;

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_process_op: "
                                                 "trigger dump cfg\n");

            MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
            MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
            MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
            MOD_NODE_MODI(&mod_node) = cxfs_md_id;

            task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &mod_node,
                         NULL_PTR,
                         FI_cxfs_dump_cfg, CMPI_ERROR_MODI);

            /*fall through*/
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md)
        && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))
        && BIT_FALSE == CXFS_MD_NP_SYNC_FLAG(cxfs_md)
        && BIT_FALSE == CXFS_MD_DN_SYNC_FLAG(cxfs_md))
        {
            CXFS_MD_OP_DUMP_OFFSET(cxfs_md) = 0;    /*rewind op dump offset*/

            CXFSCFG_OP_DUMP_TIME_MSEC(CXFS_MD_CFG(cxfs_md)) = c_get_cur_time_msec();

            cxfs_unset_read_only(cxfs_md_id);       /*unset read-only mode*/
            CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_FALSE; /*unset sync mode*/

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync: "
                                                 "npp and dn complete sync\n");

            task_brd_process_add(task_brd_default_get(),
                                TASK_BRD_PROCESS_LOOP,
                                (TASK_BRD_CALLBACK)cxfs_process_op,
                                (void *)cxfs_md_id);
        }
        else
        {
            task_brd_process_add(task_brd_default_get(),
                                 TASK_BRD_PROCESS_ONCE,
                                 (TASK_BRD_CALLBACK)cxfs_sync,
                                 (void *)cxfs_md_id);
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_flush(const UINT32 cxfs_md_id)
{
    CXFS_MD  *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_flush: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_flush_npp(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush: flush npp failed!\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_flush_dn(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush: flush dn failed!\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_flush_sata_bad_bitmap(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush: flush bad bitmap failed!\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_flush: flush done\n");
    return (EC_TRUE);
}

/*load bad bitmap from sata disk*/
EC_BOOL cxfs_load_sata_bad_bitmap(CXFS_MD *cxfs_md)
{
    CXFSCFG    *cxfscfg;
    UINT32      offset;
    UINT32      offset_saved;

    if(ERR_FD == CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_load_sata_bad_bitmap: "
                                             "xfs has no sata fd\n");
        return (EC_FALSE);
    }

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    if(CXFSCFG_SATA_DISK_SIZE(cxfscfg) < CXFSCFG_SIZE
                                       + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_load_sata_bad_bitmap: "
                                             "invalid sata disk size %ld\n",
                                             CXFSCFG_SATA_DISK_SIZE(cxfscfg));
        return (EC_FALSE);
    }

    offset = CXFSCFG_SIZE;
    offset_saved = offset;

    CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = cbad_bitmap_new(CXFS_SATA_BAD_BITMAP_SIZE_NBYTES,
                                                       CXFS_SATA_BAD_BITMAP_SIZE_NBITS,
                                                       CXFS_SATA_BAD_BITMAP_MEM_ALIGN);
    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_load_sata_bad_bitmap: "
                                             "new sata bad bitmap failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_pread(CXFS_MD_SATA_DISK_FD(cxfs_md), &offset,
                                CXFS_SATA_BAD_BITMAP_SIZE_NBYTES,
                                (UINT8 *)CXFS_MD_SATA_BAD_BITMAP(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_load_sata_bad_bitmap: "
                                             "load sata bad bitmap from fd %d, offset %ld failed\n",
                                             CXFS_MD_SATA_DISK_FD(cxfs_md), offset_saved);

        cbad_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;

        return (EC_FALSE);
    }

    cbad_bitmap_revise(CXFS_MD_SATA_BAD_BITMAP(cxfs_md), CXFS_SATA_BAD_BITMAP_SIZE_NBITS);

    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md) = CBAD_BITMAP_USED(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_load_sata_bad_bitmap: "
                                         "load sata bad bitmap done\n");

    return (EC_TRUE);
}

/*flush bad bitmap to sata disk*/
EC_BOOL cxfs_flush_sata_bad_bitmap(CXFS_MD *cxfs_md)
{
    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md)
    && ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        UINT32   sata_bad_bitmap_offset;
        UINT32   sata_bad_bitmap_offset_saved;
        UINT32   sata_bad_bitmap_size;

        sata_bad_bitmap_offset  = CXFSCFG_SIZE;
        sata_bad_bitmap_size    = CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

        sata_bad_bitmap_offset_saved = sata_bad_bitmap_offset;

        if(EC_FALSE == c_file_pwrite(CXFS_MD_SATA_DISK_FD(cxfs_md),
                                     &sata_bad_bitmap_offset,
                                     sata_bad_bitmap_size,
                                     (const UINT8 *)CXFS_MD_SATA_BAD_BITMAP(cxfs_md)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush_sata_bad_bitmap: "
                                                 "flush sata bad bitmap to fd %d "
                                                 "with offset %ld, size %ld failed\n",
                                                 CXFS_MD_SATA_DISK_FD(cxfs_md),
                                                 sata_bad_bitmap_offset_saved,
                                                 sata_bad_bitmap_size);
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_flush_sata_bad_bitmap: "
                                             "flush sata bad bitmap to fd %d "
                                             "with offset %ld, size %ld done\n",
                                             CXFS_MD_SATA_DISK_FD(cxfs_md),
                                             sata_bad_bitmap_offset_saved,
                                             sata_bad_bitmap_size);
    }

    return (EC_TRUE);
}

/*sync bad bitmap to sata disk*/
EC_BOOL cxfs_sync_sata_bad_bitmap(CXFS_MD *cxfs_md)
{
    CBAD_BITMAP         *sata_bad_bitmap;

    sata_bad_bitmap = CXFS_MD_SATA_BAD_BITMAP(cxfs_md);

    if(NULL_PTR != sata_bad_bitmap
    && CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md) != CBAD_BITMAP_USED(sata_bad_bitmap)
    && NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        uint64_t  time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        if(time_msec_cur >= CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md))
        {
            UINT32   sata_bad_bitmap_offset;
            UINT32   sata_bad_bitmap_size;

            sata_bad_bitmap_offset  = CXFSCFG_SIZE;
            sata_bad_bitmap_size    = CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

            if(EC_FALSE == cxfsdn_sync_sata_bad_bitmap(CXFS_MD_DN(cxfs_md),
                                            sata_bad_bitmap_offset,
                                            sata_bad_bitmap_size))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync_sata_bad_bitmap: "
                                                     "sync sata bad bitmap to sata "
                                                     "offset %ld, size %ld failed\n",
                                                     sata_bad_bitmap_offset,
                                                     sata_bad_bitmap_size);
                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync_sata_bad_bitmap: "
                                                 "sync sata bad bitmap to sata "
                                                 "offset %ld, size %ld done\n",
                                                 sata_bad_bitmap_offset,
                                                 sata_bad_bitmap_size);

            CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)   = CBAD_BITMAP_USED(sata_bad_bitmap); /*update*/

            CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md) = time_msec_cur + 60 * 1000; /*60s later*/

            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*close bad bitmap without flushing*/
EC_BOOL cxfs_close_sata_bad_bitmap(CXFS_MD *cxfs_md)
{
    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
       cbad_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
       CXFS_MD_SATA_BAD_BITMAP(cxfs_md)     = NULL_PTR;

       CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)   = 0;
       CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md) = 0;
    }

    return (EC_TRUE);
}

CXFSNP_FNODE *cxfs_fnode_new(const UINT32 cxfs_md_id)
{
    return cxfsnp_fnode_new();
}

EC_BOOL cxfs_fnode_init(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode)
{
    return cxfsnp_fnode_init(cxfsnp_fnode);
}

EC_BOOL cxfs_fnode_clean(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode)
{
    return cxfsnp_fnode_clean(cxfsnp_fnode);
}

EC_BOOL cxfs_fnode_free(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode)
{
    return cxfsnp_fnode_free(cxfsnp_fnode);
}

EC_BOOL cxfs_set_state(const UINT32 cxfs_md_id, const UINT32 cxfs_state)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_state: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_set_state: cxfs module #%ld: state %lx -> %lx\n",
                        cxfs_md_id, CXFS_MD_STATE(cxfs_md), cxfs_state);

    CXFS_MD_STATE(cxfs_md) = cxfs_state;

    return (EC_TRUE);
}

UINT32 cxfs_get_state(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_get_state: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    return CXFS_MD_STATE(cxfs_md);
}

EC_BOOL cxfs_is_state(const UINT32 cxfs_md_id, const UINT32 cxfs_state)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_state: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(CXFS_MD_STATE(cxfs_md) == cxfs_state)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfs_set_read_only(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_read_only: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_set_read_only: "
                                             "cxfs is in read-only mode\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        cxfsnp_mgr_set_read_only(CXFS_MD_NPP(cxfs_md));
    }

    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        cxfsdn_set_read_only(CXFS_MD_DN(cxfs_md));
    }

    CXFS_MD_READ_ONLY_FLAG(cxfs_md) = BIT_TRUE;

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_set_read_only: "
                                         "cxfs set read-only done\n");
    return (EC_TRUE);
}

EC_BOOL cxfs_unset_read_only(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_unset_read_only: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_FALSE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_unset_read_only: "
                                             "cxfs is not in read-only mode\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        cxfsnp_mgr_unset_read_only(CXFS_MD_NPP(cxfs_md));
    }

    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        cxfsdn_unset_read_only(CXFS_MD_DN(cxfs_md));
    }

    CXFS_MD_READ_ONLY_FLAG(cxfs_md) = BIT_FALSE;

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_unset_read_only: "
                                         "cxfs unset read-only done\n");
    return (EC_TRUE);
}

EC_BOOL cxfs_is_read_only(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_read_only: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

/**
*
*  get name node pool of the module
*
**/
CXFSNP_MGR *cxfs_get_npp(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_get_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    return CXFS_MD_NPP(cxfs_md);
}

/**
*
*  get data node of the module
*
**/
CXFSDN *cxfs_get_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_get_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    return CXFS_MD_DN(cxfs_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL cxfs_open_npp(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_open_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_open_npp: npp was open\n");
        return (EC_FALSE);
    }

    CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr_open(CXFS_MD_SATA_DISK_FD(cxfs_md), CXFS_MD_CFG(cxfs_md));
    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_open_npp: open npp failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsnp_mgr_mount_op_mgr(CXFS_MD_NPP(cxfs_md), CXFS_MD_OP_MGR(cxfs_md));
    }

    return (EC_TRUE);
}

/**
*
*  close name node pool
*
**/
EC_BOOL cxfs_close_npp(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_close_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_close_npp: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_mgr_close(CXFS_MD_NPP(cxfs_md));
    CXFS_MD_NPP(cxfs_md) = NULL_PTR;
    return (EC_TRUE);
}

/**
*
*  check this CXFS is name node pool or not
*
*
**/
EC_BOOL cxfs_is_npp(const UINT32 cxfs_md_id)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CXFS is data node or not
*
*
**/
EC_BOOL cxfs_is_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  check this CXFS is data node and namenode or not
*
*
**/
EC_BOOL cxfs_is_npp_and_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_npp_and_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md) || NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  create name node pool
*
**/
EC_BOOL cxfs_create_npp(const UINT32 cxfs_md_id,
                             const UINT32 cxfsnp_model,
                             const UINT32 cxfsnp_max_num,
                             const UINT32 cxfsnp_2nd_chash_algo_id)
{
    CXFS_MD     *cxfs_md;
    CXFSCFG     *cxfscfg;
    CXFSZONE    *cxfszone;
    CXFSNP_MGR  *cxfsnp_mgr;
    UINT32       np_total_size;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_create_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfscfg = CXFS_MD_CFG(cxfs_md);

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: "
                                             "npp already exist\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(cxfsnp_model))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: "
                                             "cxfsnp_model %u is invalid\n",
                                             (uint32_t)cxfsnp_model);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(cxfsnp_max_num))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: "
                                             "cxfsnp_disk_max_num %u is invalid\n",
                                             (uint32_t)cxfsnp_max_num);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint8_t(cxfsnp_2nd_chash_algo_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: "
                                             "hash algo %u is invalid\n",
                                             (uint32_t)cxfsnp_2nd_chash_algo_id);
        return (EC_FALSE);
    }

    if(ERR_FD == CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: no sata fd\n");
        return (EC_FALSE);
    }

    cxfsnp_mgr = cxfsnp_mgr_create((uint8_t ) cxfsnp_model,
                                   (uint32_t) cxfsnp_max_num,
                                   (uint8_t ) cxfsnp_2nd_chash_algo_id,
                                   CXFS_MD_SATA_DISK_FD(cxfs_md),
                                   CXFSCFG_SATA_DISK_SIZE(cxfscfg),
                                   CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg));
    if(NULL_PTR == cxfsnp_mgr)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: create npp failed\n");
        return (EC_FALSE);
    }

    CXFSCFG_NP_MODEL(cxfscfg)              = CXFSNP_MGR_NP_MODEL(cxfsnp_mgr);
    CXFSCFG_NP_2ND_CHASH_ALGO_ID(cxfscfg)  = CXFSNP_MGR_NP_2ND_CHASH_ALGO_ID(cxfsnp_mgr);
    CXFSCFG_NP_SIZE(cxfscfg)               = CXFSNP_MGR_NP_SIZE(cxfsnp_mgr);
    CXFSCFG_NP_ITEM_MAX_NUM(cxfscfg)       = CXFSNP_MGR_NP_ITEM_MAX_NUM(cxfsnp_mgr);
    CXFSCFG_NP_MAX_NUM(cxfscfg)            = CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr);

    CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg)    = 0;

    np_total_size = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) - CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr);

    cxfszone = CXFSCFG_NP_ZONE(cxfscfg, 0);
    CXFSZONE_S_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 0 * np_total_size;
    CXFSZONE_E_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 1 * np_total_size;


    cxfszone = CXFSCFG_NP_ZONE(cxfscfg, 1);
    CXFSZONE_S_OFFSET(cxfszone)            = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) + 1 * np_total_size;
    CXFSZONE_E_OFFSET(cxfszone)            = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) + 2 * np_total_size;

    CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)      = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 0 * np_total_size;
    CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg)      = CXFSNP_MGR_NP_E_OFFSET(cxfsnp_mgr) + 2 * np_total_size;

    CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr;

    /*op mgr*/
    if(NULL_PTR != cxfsnp_mgr
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsnp_mgr_mount_op_mgr(cxfsnp_mgr, CXFS_MD_OP_MGR(cxfs_md));
    }

    return (EC_TRUE);
}

/**
*
*  dump name node pool to sandby np zone
*
**/
EC_BOOL cxfs_dump_npp(const UINT32 cxfs_md_id)
{
    CXFS_MD     *cxfs_md;
    CXFSCFG     *cxfscfg;
    CXFSZONE    *cxfszone;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfscfg = CXFS_MD_CFG(cxfs_md);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_npp: "
                                             "npp is null\n");
        return (EC_FALSE);
    }

    if(ERR_FD == CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_npp: "
                                             "no sata fd\n");
        return (EC_FALSE);
    }

    /*standy zone*/
    cxfszone = CXFSCFG_NP_ZONE(cxfscfg, CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg));

    if(EC_FALSE == cxfsnp_mgr_dump(CXFS_MD_NPP(cxfs_md), CXFSZONE_S_OFFSET(cxfszone)))
    {
        task_brd_update_time_default();
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_npp: "
                                             "dump npp to standy zone %ld failed\n",
                                             CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg));
        return (EC_FALSE);
    }
    task_brd_update_time_default();
    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_dump_npp: "
                                         "dump npp to standy zone %ld done\n",
                                         CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg));

    return (EC_TRUE);
}

/**
*
*  create sata bad bitmap
*
**/
EC_BOOL cxfs_create_sata_bad_bitmap(const UINT32 cxfs_md_id)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_create_sata_bad_bitmap: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = cbad_bitmap_new(CXFS_SATA_BAD_BITMAP_SIZE_NBYTES,
                                                           CXFS_SATA_BAD_BITMAP_SIZE_NBITS,
                                                           CXFS_SATA_BAD_BITMAP_MEM_ALIGN);
        if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_sata_bad_bitmap: "
                                                 "create sata bad bitmap failed\n");
            return (EC_FALSE);
        }

        CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md) = CBAD_BITMAP_USED(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));

        if(NULL_PTR != CXFS_MD_DN(cxfs_md))
        {
            cxfsdn_mount_sata_bad_bitmap(CXFS_MD_DN(cxfs_md), CXFS_MD_SATA_BAD_BITMAP(cxfs_md));

            dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_create_sata_bad_bitmap: "
                                                 "mount sata bad bitmap to dn done\n");
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md))
        {
            UINT32   sata_bad_bitmap_offset;
            UINT32   sata_bad_bitmap_size;

            sata_bad_bitmap_offset  = CXFSCFG_SIZE;
            sata_bad_bitmap_size    = CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

            cxfsdn_sync_sata_bad_bitmap(CXFS_MD_DN(cxfs_md), sata_bad_bitmap_offset, sata_bad_bitmap_size);
        }

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_create_sata_bad_bitmap: "
                                             "create sata bad bitmap done\n");
    }

    return (EC_TRUE);
}

/**
*  for debug only !
*  set sata bad page
*
**/
EC_BOOL cxfs_set_sata_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_sata_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_set_sata_bad_page: "
                                             "sata bad bitmap is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_set_sata_bad_page: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_set_sata_bad_page: "
                                             "camd is null\n");
        return (EC_FALSE);
    }

    return camd_set_sata_bad_page(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)), (uint32_t)page_no);
}

/**
*  for debug only !
*  unset sata bad page
*
**/
EC_BOOL cxfs_unset_sata_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_unset_sata_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_unset_sata_bad_page: "
                                             "sata bad bitmap is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_unset_sata_bad_page: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_unset_sata_bad_page: "
                                             "camd is null\n");
        return (EC_FALSE);
    }

    return camd_clear_sata_bad_page(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)), (uint32_t)page_no);
}

/**
*
*  check sata bad pag
*
**/
EC_BOOL cxfs_check_sata_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_sata_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_sata_bad_page: "
                                             "sata bad bitmap is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_sata_bad_page: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_sata_bad_page: "
                                             "camd is null\n");
        return (EC_FALSE);
    }

    return camd_is_sata_bad_page(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)), (uint32_t)page_no);
}

/**
*
*  show sata bad pag
*
**/
void cxfs_show_sata_bad_pages(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_sata_bad_pages: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_sata_bad_pages: "
                                             "sata bad bitmap is null\n");
        return;
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_sata_bad_pages: "
                                             "dn is null\n");
        return;
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_sata_bad_pages: "
                                             "camd is null\n");
        return;
    }

    cbad_bitmap_print(log, CAMD_MD_SATA_BAD_BITMAP(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))));

    return;
}

/**
*  for debug only !
*  set ssd bad page
*
**/
EC_BOOL cxfs_set_ssd_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_ssd_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_set_ssd_bad_page: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_set_ssd_bad_page: "
                                             "camd is null\n");
        return (EC_FALSE);
    }

    return camd_set_ssd_bad_page(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)), (uint32_t)page_no);
}

/**
*  for debug only !
*  unset ssd bad page
*
**/
EC_BOOL cxfs_unset_ssd_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_unset_ssd_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_unset_ssd_bad_page: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_unset_ssd_bad_page: "
                                             "camd is null\n");
        return (EC_FALSE);
    }

    return camd_clear_ssd_bad_page(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)), (uint32_t)page_no);
}

/**
*
*  check ssd bad pag
*
**/
EC_BOOL cxfs_check_ssd_bad_page(const UINT32 cxfs_md_id, const UINT32 page_no)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_ssd_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_ssd_bad_page: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_ssd_bad_page: "
                                             "camd is null\n");
        return (EC_FALSE);
    }

    return camd_is_ssd_bad_page(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)), (uint32_t)page_no);
}

/**
*
*  show ssd bad pag
*
**/
void cxfs_show_ssd_bad_pages(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_ssd_bad_pages: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_ssd_bad_pages: "
                                             "dn is null\n");
        return;
    }

    if(NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_ssd_bad_pages: "
                                             "camd is null\n");
        return;
    }

    cbad_bitmap_print(log, CAMD_MD_SSD_BAD_BITMAP(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))));

    return;
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL cxfs_find_dir(const UINT32 cxfs_md_id, const CSTRING *dir_path)
{
    CXFS_MD   *cxfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_find_dir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_find_dir: npp was not open\n");
        return (EC_FALSE);
    }

    ret = cxfsnp_mgr_find_dir(CXFS_MD_NPP(cxfs_md), dir_path);

    return (ret);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL cxfs_find_file(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
    CXFS_MD   *cxfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_find_file: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_find_file: npp was not open\n");
        return (EC_FALSE);
    }

    ret = cxfsnp_mgr_find_file(CXFS_MD_NPP(cxfs_md), file_path);
    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL cxfs_find(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD   *cxfs_md;
    EC_BOOL    ret;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_find: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_find: npp was not open\n");
        return (EC_FALSE);
    }

    ret = cxfsnp_mgr_find(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_ANY/*xxx*/);

    return (ret);
}

/**
*
*  check existing of a file or a dir
*
**/
EC_BOOL cxfs_exists(const UINT32 cxfs_md_id, const CSTRING *path)
{
#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_exists: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    return cxfs_find(cxfs_md_id, path);
}

/**
*
*  check existing of a file
*
**/
EC_BOOL cxfs_is_file(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_file: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    return cxfs_find_file(cxfs_md_id, file_path);
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL cxfs_is_dir(const UINT32 cxfs_md_id, const CSTRING *dir_path)
{
#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_dir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    return cxfs_find_dir(cxfs_md_id, dir_path);
}

/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __cxfs_reserve_hash_dn(const UINT32 cxfs_md_id, const UINT32 data_len, const uint32_t path_hash, CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_INODE *cxfsnp_inode;
    CXFSPGV      *cxfspgv;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint16_t fail_tries;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_reserve_hash_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_hash_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cxfspgv = CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md));
    if(NULL_PTR == CXFSPGV_HEADER(cxfspgv))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CXFSPGV_DISK_NUM(cxfspgv))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_hash_dn: pgv has no disk yet\n");
        return (EC_FALSE);
    }

    fail_tries = 0;
    for(;;)
    {
        EC_BOOL     result;

        size    = (uint32_t)(data_len);
        disk_no = (uint16_t)(path_hash % CXFSPGV_DISK_NUM(cxfspgv));

        result  = EC_FALSE; /*init*/

        while(EC_FALSE == result)
        {
            if(EC_TRUE == cxfspgv_is_full(cxfspgv))
            {
                break;/*fail and fall through*/
            }

            if(EC_FALSE == cxfspgv_new_space_from_disk(cxfspgv, size, disk_no, &block_no, &page_no))
            {
                break;/*fail and fall through*/
            }

            if(EC_FALSE == cxfsdn_cover_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no))
            {
                result = EC_TRUE;
                break;/*succ and fall through*/
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] __cxfs_reserve_hash_dn: "
                                                 "(disk %u, block %u, page %u), size %u cover bad page\n",
                                                 disk_no, block_no, page_no, size);

            cxfsdn_discard_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no);
        }

        /*try again*/
        while(EC_FALSE == result)
        {
            if(EC_TRUE == cxfspgv_is_full(cxfspgv))
            {
                break;/*fail and fall through*/
            }

            if(EC_FALSE == cxfspgv_new_space(cxfspgv, size, &disk_no, &block_no, &page_no))
            {
                break;/*fail and fall through*/
            }

            if(EC_FALSE == cxfsdn_cover_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no))
            {
                result = EC_TRUE;
                break;/*succ and fall through*/
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] __cxfs_reserve_hash_dn: "
                                                 "(disk %u, block %u, page %u), size %u cover bad page\n",
                                                 disk_no, block_no, page_no, size);

            cxfsdn_discard_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no);
        }

        if(EC_TRUE == result)
        {
            break;/*fall through*/
        }

        fail_tries ++;

        if(1 < fail_tries) /*try once only*/
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_hash_dn: "
                                                 "new %ld bytes space from vol failed\n",
                                                 data_len);
            return (EC_FALSE);
        }

        /*try to retire & recycle some files*/
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:__cxfs_reserve_hash_dn: "
                                             "no %ld bytes space, try to retire & recycle\n",
                                             data_len);
        cxfs_retire(cxfs_md_id, (UINT32)CXFSNP_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cxfs_recycle(cxfs_md_id, (UINT32)CXFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    cxfsnp_fnode_init(cxfsnp_fnode);
    CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = size;
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 1;

    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    CXFSNP_INODE_DISK_NO(cxfsnp_inode)    = disk_no;
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)   = block_no;
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  reserve space from dn
*
**/
EC_BOOL cxfs_reserve_dn(const UINT32 cxfs_md_id, const UINT32 data_len, CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_INODE *cxfsnp_inode;

    uint32_t size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_reserve_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_reserve_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_reserve_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_reserve_dn: no dn was open\n");
        return (EC_FALSE);
    }

    size = (uint32_t)(data_len);

    for(;;)
    {
        if(EC_TRUE == cxfspgv_is_full(CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md))))
        {
            dbg_log(SEC_0191_CXFSDN, 0)(LOGSTDOUT, "error:cxfs_reserve_dn: vol is full\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfspgv_new_space(CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md)), size, &disk_no, &block_no, &page_no))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_reserve_dn: new %ld bytes space from vol failed\n", data_len);
            return (EC_FALSE);
        }

        if(EC_FALSE == cxfsdn_cover_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no))
        {
            break;
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_reserve_dn: (disk %u, block %u, page %u), size %u cover bad page\n",
                                             disk_no, block_no, page_no, size);

        cxfsdn_discard_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no);
    }

    cxfsnp_fnode_init(cxfsnp_fnode);
    CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = size;
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 1;

    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    CXFSNP_INODE_DISK_NO(cxfsnp_inode)    = disk_no;
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)   = block_no;
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)    = page_no;

    return (EC_TRUE);
}

/**
*
*  release space to dn
*
**/
EC_BOOL cxfs_release_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD *cxfs_md;
    const CXFSNP_INODE *cxfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_release_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_release_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_release_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size    = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < file_size)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_release_dn: file_size %u overflow\n", file_size);
        return (EC_FALSE);
    }

    /*refer __cxfs_write: when file size is zero, only reserve npp but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_release_dn: file_size is zero\n");
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no  = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    if(EC_FALSE == cxfspgv_free_space(CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_release_dn: free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_release_dn: remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    /*not push op*/

    return (EC_TRUE);
}

/**
*
*  recycle space to dn
*
**/
EC_BOOL cxfs_recycle_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD *cxfs_md;
    const CXFSNP_INODE *cxfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_recycle_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_recycle_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_recycle_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size    = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < file_size)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_recycle_dn: file_size %u overflow\n", file_size);
        return (EC_FALSE);
    }

    /*refer __cxfs_write: when file size is zero, only reserve npp but no dn space*/
    if(0 == file_size)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_recycle_dn: file_size is zero\n");
        return (EC_TRUE);/*Jan 4,2017 modify it from EC_FALSE to EC_TRUE*/
    }

    disk_no  = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no  = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    if(EC_FALSE == cxfspgv_free_space(CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md)), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_recycle_dn: free %u bytes to vol failed where disk %u, block %u, page %u\n",
                            file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_recycle_dn: remove file fsize %u, disk %u, block %u, page %u done\n",
                       file_size, disk_no, block_no, page_no);

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_dn_push_recycle_op(CXFS_MD_OP_MGR(cxfs_md),
                                  (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                  (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));
    }

    return (EC_TRUE);
}

/**
*
*  write a file (version 0.3)
*
**/
STATIC_CAST static EC_BOOL __cxfs_write(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_FNODE *cxfsnp_fnode;
    uint32_t      path_hash;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsnp_fnode = __cxfs_reserve_npp(cxfs_md_id, file_path);
    if(NULL_PTR == cxfsnp_fnode)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write: file %s reserve npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cxfsnp_fnode_init(cxfsnp_fnode);

        if(do_log(SEC_0192_CXFS, 1))
        {
            sys_log(LOGSTDOUT, "warn:__cxfs_write: write file %s with zero len to dn where fnode is \n", (char *)cstring_get_str(file_path));
            cxfsnp_fnode_print(LOGSTDOUT, cxfsnp_fnode);
        }

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/

        return (EC_TRUE);
    }

    /*calculate hash value of file_path*/
    path_hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

    if(EC_FALSE == __cxfs_reserve_hash_dn(cxfs_md_id, CBYTES_LEN(cbytes), path_hash, cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write: reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/

        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_export_dn(cxfs_md_id, cbytes, cxfsnp_fnode))
    {
        cxfs_release_dn(cxfs_md_id, cxfsnp_fnode);

        __cxfs_release_npp(cxfs_md_id, file_path);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cxfs_write: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        cxfsnp_fnode_print(LOGSTDOUT, cxfsnp_fnode);
    }

    /*notify all waiters*/
    cxfs_file_notify(cxfs_md_id, file_path);

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_dn_push_reserve_op(CXFS_MD_OP_MGR(cxfs_md),
                                  (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                  (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));

        cxfsop_mgr_np_push_file_add_op(CXFS_MD_OP_MGR(cxfs_md),
                                  (uint32_t )cstring_get_len(file_path),
                                  (uint8_t *)cstring_get_str(file_path),
                                  (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                  (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));
    }

    return (EC_TRUE);
}

/*Jan 16, 2017*/
STATIC_CAST static EC_BOOL __cxfs_write_no_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_FNODE *cxfsnp_fnode;
    uint32_t      path_hash;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsnp_fnode = __cxfs_reserve_npp(cxfs_md_id, file_path);
    if(NULL_PTR == cxfsnp_fnode)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write_no_lock: file %s reserve npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);/*patch*/

        return (EC_FALSE);
    }
    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        cxfsnp_fnode_init(cxfsnp_fnode);
        /*CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 1; */

        if(do_log(SEC_0192_CXFS, 1))
        {
            sys_log(LOGSTDOUT, "warn:__cxfs_write_no_lock: write file %s with zero len to dn where fnode is \n", (char *)cstring_get_str(file_path));
            cxfsnp_fnode_print(LOGSTDOUT, cxfsnp_fnode);
        }

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);

        return (EC_TRUE);
    }

    /*calculate hash value of file_path*/
    path_hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

    if(EC_FALSE == __cxfs_reserve_hash_dn(cxfs_md_id, CBYTES_LEN(cbytes), path_hash, cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write_no_lock: reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);/*patch*/
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_export_dn(cxfs_md_id, cbytes, cxfsnp_fnode))
    {
        cxfs_release_dn(cxfs_md_id, cxfsnp_fnode);

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);/*patch*/

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write_no_lock: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cxfs_write_no_lock: write file %s to dn where fnode is \n", (char *)cstring_get_str(file_path));
        cxfsnp_fnode_print(LOGSTDOUT, cxfsnp_fnode);
    }

    /*notify all waiters*/
    cxfs_file_notify(cxfs_md_id, file_path);

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_dn_push_reserve_op(CXFS_MD_OP_MGR(cxfs_md),
                                  (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                  (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));

        cxfsop_mgr_np_push_file_add_op(CXFS_MD_OP_MGR(cxfs_md),
                                  (uint32_t )cstring_get_len(file_path),
                                  (uint8_t *)cstring_get_str(file_path),
                                  (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                  (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_write(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write: cxfs is read-only\n");
        return (EC_FALSE);
    }

    return __cxfs_write(cxfs_md_id, file_path, cbytes);
}

EC_BOOL cxfs_write_no_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_no_lock: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_no_lock: cxfs is read-only\n");
        return (EC_FALSE);
    }

    return __cxfs_write_no_lock(cxfs_md_id, file_path, cbytes);
}

/**
*
*  read a file
*
**/
EC_BOOL cxfs_read_safe(const UINT32 cxfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_FNODE  cxfsnp_fnode;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_safe: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_safe: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    cxfsnp_fnode_init(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_safe: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

#if 0
    else
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read_safe: read file %s from npp and fnode %p is \n",
                           (char *)cstring_get_str(file_path),
                           &cxfsnp_fnode);
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
    }
#endif

    /*exception*/
    if(0 == CXFSNP_FNODE_FILESZ(&cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read_safe: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &cxfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_read_dn(cxfs_md_id, &cxfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_safe: read file %s from dn failed where fnode is \n", (char *)cstring_get_str(file_path));
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
        return (EC_FALSE);
    }

    //dbg_log(SEC_0192_CXFS, 9)(LOGSTDNULL, "[DEBUG] cxfs_read_safe: read file %s is %.*s\n", (char *)cstring_get_str(file_path), (uint32_t)DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));
    return (EC_TRUE);
}

EC_BOOL cxfs_read(const UINT32 cxfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_FNODE  cxfsnp_fnode;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    cxfsnp_fnode_init(&cxfsnp_fnode);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read: read file %s start\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read: read file %s from npp done\n", (char *)cstring_get_str(file_path));

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_read: read file %s with size %ld done\n",
                            (char *)cstring_get_str(file_path), cbytes_len(cbytes));
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
    }

    /*exception*/
    if(0 == CXFSNP_FNODE_FILESZ(&cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &cxfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_read_dn(cxfs_md_id, &cxfsnp_fnode, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read: read file %s from dn failed where fnode is \n", (char *)cstring_get_str(file_path));
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  write a file in cache
*
**/


/*----------------------------------- POSIX interface -----------------------------------*/
/**
*
*  write a file at offset
*
**/
EC_BOOL cxfs_write_e(const UINT32 cxfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_FNODE  cxfsnp_fnode;
    uint32_t      file_old_size;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_e: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: cxfs is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp_fnode_init(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    file_old_size = CXFSNP_FNODE_FILESZ(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_write_e_dn(cxfs_md_id, &cxfsnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: offset write to dn failed\n");
        return (EC_FALSE);
    }

    if(file_old_size != CXFSNP_FNODE_FILESZ(&cxfsnp_fnode))
    {
        if(EC_FALSE == cxfs_update_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: offset write file %s to npp failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
    }
    else
    {
        if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
        && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
        {
            cxfsop_mgr_dn_push_reserve_op(CXFS_MD_OP_MGR(cxfs_md),
                                      (uint32_t )CXFSNP_FNODE_FILESZ(&cxfsnp_fnode),
                                      (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(&cxfsnp_fnode, 0),
                                      (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(&cxfsnp_fnode, 0),
                                      (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(&cxfsnp_fnode, 0));

            cxfsop_mgr_np_push_file_add_op(CXFS_MD_OP_MGR(cxfs_md),
                                      (uint32_t )cstring_get_len(file_path),
                                      (uint8_t *)cstring_get_str(file_path),
                                      (uint32_t )CXFSNP_FNODE_FILESZ(&cxfsnp_fnode),
                                      (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(&cxfsnp_fnode, 0),
                                      (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(&cxfsnp_fnode, 0),
                                      (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(&cxfsnp_fnode, 0));
        }
    }
    return (EC_TRUE);
}

/**
*
*  read a file from offset
*
*  when max_len = 0, return the partial content from offset to EOF (end of file)
*
**/
EC_BOOL cxfs_read_e(const UINT32 cxfs_md_id, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_FNODE  cxfsnp_fnode;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_e: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    cxfsnp_fnode_init(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_read_e: read file %s from npp and fnode %p is \n",
                           (char *)cstring_get_str(file_path),
                           &cxfsnp_fnode);
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
    }

    /*exception*/
    if(0 == CXFSNP_FNODE_FILESZ(&cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read_e: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &cxfsnp_fnode);
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_read_e_dn(cxfs_md_id, &cxfsnp_fnode, offset, max_len, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e: offset read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  dump cfg
*
**/
EC_BOOL cxfs_dump_cfg(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_create_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR != CXFS_MD_DN(cxfs_md)
    && CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        return cxfscfg_dump(CXFS_MD_CFG(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)));
    }

    return (EC_FALSE);
}

/**
*
*  create data node
*
**/
EC_BOOL cxfs_create_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;
    CXFSCFG   *cxfscfg;
    CXFSZONE  *cxfszone;
    CXFSDN    *cxfsdn;

    UINT32     cxfsdn_disk_size; /*cxfs dn virtual disk size*/
    UINT32     cxfsdn_zone_size; /*cxfs dn meta data size*/

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_create_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_dn: dn already exist\n");
        return (EC_FALSE);
    }

    cxfscfg = CXFS_MD_CFG(cxfs_md);
    if(CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg) >= CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_dn: np not created yet\n");
        return (EC_FALSE);
    }

    CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) = CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg);

    if(EC_FALSE == cxfsdn_compute(CXFSCFG_SATA_DISK_SIZE(cxfscfg),
                                  CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg), /*now only know the start offset of dn zones*/
                                  &cxfsdn_disk_size, /*virtual size*/
                                  &cxfsdn_zone_size))/*dn data zone size*/
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_dn: compute dn size and vdisk num failed\n");
        return (EC_FALSE);
    }

    CXFSCFG_DN_ZONE_SIZE(cxfscfg)       = cxfsdn_zone_size;

    CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg) = 0;

    cxfszone = CXFSCFG_DN_ZONE(cxfscfg, 0);
    CXFSZONE_S_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 0 * cxfsdn_zone_size;
    CXFSZONE_E_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 1 * cxfsdn_zone_size;

    cxfszone = CXFSCFG_DN_ZONE(cxfscfg, 1);
    CXFSZONE_S_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 1 * cxfsdn_zone_size;
    CXFSZONE_E_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 2 * cxfsdn_zone_size;

    CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg)   = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 2 * cxfsdn_zone_size;

    CXFSCFG_SATA_DISK_OFFSET(cxfscfg)   = CXFSCFG_SATA_DISK_SIZE(cxfscfg) % cxfsdn_disk_size;

    while(CXFSCFG_SATA_DISK_OFFSET(cxfscfg) < CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_create_dn: "
                                             "CXFSCFG_SATA_DISK_OFFSET %ld < CXFSCFG_DN_ZONE_E_OFFSET %ld, "
                                             "update CXFSCFG_SATA_DISK_OFFSET to %ld, "
                                             "where disk size %ld, dn zone size %ld\n",
                                             CXFSCFG_SATA_DISK_OFFSET(cxfscfg),
                                             CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg),
                                             CXFSCFG_SATA_DISK_OFFSET(cxfscfg) + cxfsdn_disk_size,
                                             CXFSCFG_SATA_DISK_SIZE(cxfscfg),
                                             CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg));

        /*skip one more vdisk*/
        CXFSCFG_SATA_DISK_OFFSET(cxfscfg) += cxfsdn_disk_size;

        if(CXFSCFG_SATA_DISK_OFFSET(cxfscfg) >= CXFSCFG_SATA_DISK_SIZE(cxfscfg))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_dn: "
                                                 "CXFSCFG_SATA_DISK_OFFSET %ld < CXFSCFG_DN_ZONE_E_OFFSET %ld and overflow, "
                                                 "where disk size %ld, dn size %ld\n",
                                                 CXFSCFG_SATA_DISK_OFFSET(cxfscfg),
                                                 CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg),
                                                 CXFSCFG_SATA_DISK_SIZE(cxfscfg),
                                                 CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg));
            return (EC_FALSE);
        }
    }

    CXFSCFG_MAGIC(cxfscfg)              = CXFSCFG_MAGIC_NUM;

    cxfsdn = cxfsdn_create(cxfscfg,
                          CXFS_MD_SATA_DISK_FD(cxfs_md),
                           CXFSDN_CAMD_MEM_DISK_SIZE,
                           CXFS_MD_SSD_DISK_FD(cxfs_md));
    if(NULL_PTR == cxfsdn)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_dn: create dn failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        cxfsdn_mount_sata_bad_bitmap(cxfsdn, CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_create_dn: mount sata bad bitmap to dn done\n");
    }

    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        UINT32   sata_bad_bitmap_offset;
        UINT32   sata_bad_bitmap_size;

        sata_bad_bitmap_offset  = CXFSCFG_SIZE;
        sata_bad_bitmap_size    = CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

        cxfsdn_sync_sata_bad_bitmap(cxfsdn, sata_bad_bitmap_offset, sata_bad_bitmap_size);
    }

    /*op mgr*/
    if(NULL_PTR != CXFSDN_CAMD_MD(cxfsdn)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(cxfsdn));
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_create_dn: mount camd to op mgr done\n");
    }

    CXFS_MD_DN(cxfs_md) = cxfsdn;

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_create_dn: create dn done\n");

    return (EC_TRUE);
}

/**
*
*  dump data node to standby zone
*
**/
EC_BOOL cxfs_dump_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;
    CXFSCFG   *cxfscfg;
    CXFSZONE  *cxfszone;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_dn: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    /*standby zone*/
    cxfszone = CXFSCFG_DN_ZONE(cxfscfg, CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg));

    if(EC_FALSE == cxfsdn_dump(CXFS_MD_DN(cxfs_md), CXFSZONE_S_OFFSET(cxfszone)))
    {
        task_brd_update_time_default();
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_dn: "
                                             "dump dn to standy zone %ld failed\n",
                                             CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg));
        return (EC_FALSE);
    }

    task_brd_update_time_default();
    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_dump_dn: "
                                         "dump dn to standy zone %ld done\n",
                                         CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg));

    return (EC_TRUE);
}

/**
*
*  add a disk to data node
*
**/
EC_BOOL cxfs_add_disk(const UINT32 cxfs_md_id, const UINT32 disk_no)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_add_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_add_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_add_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_add_disk(CXFS_MD_DN(cxfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_add_disk: add disk %u to dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_add_disk: add disk %u to dn done\n", (uint16_t)disk_no);
    return (EC_TRUE);
}

/**
*
*  delete a disk from data node
*
**/
EC_BOOL cxfs_del_disk(const UINT32 cxfs_md_id, const UINT32 disk_no)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_del_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_del_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_del_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_del_disk(CXFS_MD_DN(cxfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_del_disk: del disk %u from dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  mount a disk to data node
*
**/
EC_BOOL cxfs_mount_disk(const UINT32 cxfs_md_id, const UINT32 disk_no)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_mount_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mount_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_mount_disk(CXFS_MD_DN(cxfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mount_disk: mount disk %u to dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  umount a disk from data node
*
**/
EC_BOOL cxfs_umount_disk(const UINT32 cxfs_md_id, const UINT32 disk_no)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_umount_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_umount_disk: dn not created yet\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint16_t(disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_umount_disk: disk_no %u is invalid\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_umount_disk(CXFS_MD_DN(cxfs_md), (uint16_t)disk_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_umount_disk: umount disk %u from dn failed\n", (uint16_t)disk_no);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  open data node
*
**/
EC_BOOL cxfs_open_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_open_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_open_dn: try to open dn ...\n");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_open_dn: dn was open\n");
        return (EC_FALSE);
    }

    CXFS_MD_DN(cxfs_md) = cxfsdn_open(CXFS_MD_CFG(cxfs_md),
                                      CXFS_MD_SATA_DISK_FD(cxfs_md),
                                      CXFS_MD_SSD_DISK_FD(cxfs_md));
    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_open_dn: open dn failed\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)));
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_open_dn: mount camd to op mgr done\n");
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_open_dn: open dn done\n");
    return (EC_TRUE);
}

/**
*
*  close data node
*
**/
EC_BOOL cxfs_close_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_close_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_close_dn: no dn was open\n");
        return (EC_FALSE);
    }

    cxfsdn_close(CXFS_MD_DN(cxfs_md));
    CXFS_MD_DN(cxfs_md) = NULL_PTR;
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_close_dn: dn was closed\n");

    return (EC_TRUE);
}

/**
*
*  export data into data node
*
**/
EC_BOOL cxfs_export_dn(const UINT32 cxfs_md_id, const CBYTES *cbytes, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;
    const CXFSNP_INODE *cxfsnp_inode;

    UINT32   offset;
    UINT32   data_len;
    //uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_export_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    data_len = DMIN(CBYTES_LEN(cbytes), CXFSNP_FNODE_FILESZ(cxfsnp_fnode));

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= data_len)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_export_dn: CBYTES_LEN %u or CXFSNP_FNODE_FILESZ %u overflow\n",
                            (uint32_t)CBYTES_LEN(cbytes), CXFSNP_FNODE_FILESZ(cxfsnp_fnode));
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_export_dn: no dn was open\n");
        return (EC_FALSE);
    }

    //size = (uint32_t)data_len;

    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    disk_no  = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no  = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    offset  = (((UINT32)(page_no)) << (CXFSPGB_PAGE_BIT_SIZE));
    if(EC_FALSE == cxfsdn_write_o(CXFS_MD_DN(cxfs_md), data_len, CBYTES_BUF(cbytes), disk_no, block_no, &offset))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_export_dn: write %ld bytes to disk %u block %u page %u failed\n",
                            data_len, disk_no, block_no, page_no);
        return (EC_FALSE);
    }
    //dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_export_dn: write %ld bytes to disk %u block %u page %u done\n",
    //                    data_len, disk_no, block_no, page_no);

    return (EC_TRUE);
}

/**
*
*  write data node
*
**/
EC_BOOL cxfs_write_dn(const UINT32 cxfs_md_id, const CBYTES *cbytes, CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_INODE *cxfsnp_inode;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_dn: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_dn: buff len (or file size) %ld overflow\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_dn: no dn was open\n");
        return (EC_FALSE);
    }

    cxfsnp_fnode_init(cxfsnp_fnode);
    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);

    if(EC_FALSE == cxfsdn_write_p(CXFS_MD_DN(cxfs_md), cbytes_len(cbytes), cbytes_buf(cbytes), &disk_no, &block_no, &page_no))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    CXFSNP_INODE_DISK_NO(cxfsnp_inode)    = disk_no;
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)   = block_no;
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)    = page_no;

    CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = CBYTES_LEN(cbytes);
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 1;

    return (EC_TRUE);
}

/**
*
*  read data node
*
**/
EC_BOOL cxfs_read_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode, CBYTES *cbytes)
{
    CXFS_MD *cxfs_md;
    const CXFSNP_INODE *cxfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CXFSNP_FNODE_REPNUM(cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    disk_no  = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no  = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    //dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read_dn: file size %u, disk %u, block %u, page %u\n", file_size, disk_no, block_no, page_no);

    if(CBYTES_LEN(cbytes) < file_size)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CXFS_0001);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(file_size, LOC_CXFS_0002);
        ASSERT(NULL_PTR != CBYTES_BUF(cbytes));
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cxfsdn_read_p(CXFS_MD_DN(cxfs_md), disk_no, block_no, page_no, file_size, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: read %u bytes from disk %u, block %u, page %u failed\n",
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
EC_BOOL cxfs_write_e_dn(const UINT32 cxfs_md_id, CXFSNP_FNODE *cxfsnp_fnode, UINT32 *offset, const UINT32 max_len, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_INODE *cxfsnp_inode;

    uint32_t file_size;
    uint32_t file_max_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_e_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e_dn: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= (*offset) + CBYTES_LEN(cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e_dn: offset %ld + buff len (or file size) %ld = %ld overflow\n",
                            (*offset), CBYTES_LEN(cbytes), (*offset) + CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e_dn: no dn was open\n");
        return (EC_FALSE);
    }

    file_size    = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    disk_no  = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no  = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    /*file_max_size = file_size alignment to one page*/
    file_max_size = (((file_size + CXFSPGB_PAGE_BYTE_SIZE - 1) >> CXFSPGB_PAGE_BIT_SIZE) << CXFSPGB_PAGE_BIT_SIZE);

    if(((UINT32)file_max_size) <= (*offset))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e_dn: offset %ld overflow due to file max size is %u\n", (*offset), file_max_size);
        return (EC_FALSE);
    }

    offset_t  = (uint32_t)(*offset);
    max_len_t = DMIN(DMIN(max_len, file_max_size - offset_t), cbytes_len(cbytes));

    if(EC_FALSE == cxfsdn_write_e(CXFS_MD_DN(cxfs_md), max_len_t, cbytes_buf(cbytes), disk_no, block_no, page_no, offset_t))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e_dn: write %ld bytes to dn failed\n", CBYTES_LEN(cbytes));
        return (EC_FALSE);
    }

    (*offset) += max_len_t;
    if((*offset) > file_size)
    {
        /*update file size info*/
        CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = (uint32_t)(*offset);
    }

    return (EC_TRUE);
}

/**
*
*  read data node from offset in the specific file
*
**/
EC_BOOL cxfs_read_e_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes)
{
    CXFS_MD *cxfs_md;
    const CXFSNP_INODE *cxfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint32_t offset_t;

    UINT32   max_len_t;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_e_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(0 == CXFSNP_FNODE_REPNUM(cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    disk_no  = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no  = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    if((*offset) >= file_size)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: due to offset %ld >= file size %u\n", (*offset), file_size);
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

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read_e_dn: file size %u, disk %u, block %u, page %u, offset %u, max len %ld\n",
                        file_size, disk_no, block_no, page_no, offset_t, max_len_t);

    if(CBYTES_LEN(cbytes) < max_len_t)
    {
        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            SAFE_FREE(CBYTES_BUF(cbytes), LOC_CXFS_0003);
        }
        CBYTES_BUF(cbytes) = (UINT8 *)SAFE_MALLOC(max_len_t, LOC_CXFS_0004);
        CBYTES_LEN(cbytes) = 0;
    }

    if(EC_FALSE == cxfsdn_read_e(CXFS_MD_DN(cxfs_md), disk_no, block_no, page_no, offset_t, max_len_t, CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: read %ld bytes from disk %u, block %u, offset %u failed\n",
                           max_len_t, disk_no, block_no, offset_t);
        return (EC_FALSE);
    }

    (*offset) += CBYTES_LEN(cbytes);
    return (EC_TRUE);
}

/**
*
*  reserve a fnode from name node
*
**/
STATIC_CAST static CXFSNP_FNODE * __cxfs_reserve_npp(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_FNODE *cxfsnp_fnode;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_reserve_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_npp: npp was not open\n");
        return (NULL_PTR);
    }

    cxfsnp_fnode = cxfsnp_mgr_reserve(CXFS_MD_NPP(cxfs_md), file_path);
    if(NULL_PTR == cxfsnp_fnode)
    {
        /*try to retire & recycle some files*/
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:__cxfs_reserve_npp: no name node accept file %s, try to retire & recycle\n",
                            (char *)cstring_get_str(file_path));

        cxfs_retire(cxfs_md_id, (UINT32)CXFSNP_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cxfs_recycle(cxfs_md_id, (UINT32)CXFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);

        /*try again*/
        cxfsnp_fnode = cxfsnp_mgr_reserve(CXFS_MD_NPP(cxfs_md), file_path);
        if(NULL_PTR == cxfsnp_fnode)/*Oops!*/
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_npp: no name node accept file %s\n",
                                (char *)cstring_get_str(file_path));
            return (NULL_PTR);
        }
    }

    return (cxfsnp_fnode);
}


/**
*
*  release a fnode from name node
*
**/
STATIC_CAST static EC_BOOL __cxfs_release_npp(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_release_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_release_npp: npp was not open\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsnp_mgr_release(CXFS_MD_NPP(cxfs_md), file_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_release_npp: release file %s from npp failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    return (EC_TRUE);
}

/**
*
*  write a fnode to name node
*
**/
EC_BOOL cxfs_write_npp(const UINT32 cxfs_md_id, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_npp: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_npp: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(0 == CXFSNP_FNODE_REPNUM(cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_npp: no valid replica in fnode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_write(CXFS_MD_NPP(cxfs_md), file_path, cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_npp: no name node accept file %s with %u replicas writting\n",
                            (char *)cstring_get_str(file_path), CXFSNP_FNODE_REPNUM(cxfsnp_fnode));
        return (EC_FALSE);
    }

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_dn_push_reserve_op(CXFS_MD_OP_MGR(cxfs_md),
                                  (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                  (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));

        cxfsop_mgr_np_push_file_add_op(CXFS_MD_OP_MGR(cxfs_md),
                                  (uint32_t )cstring_get_len(file_path),
                                  (uint8_t *)cstring_get_str(file_path),
                                  (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                  (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                  (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));
    }

    return (EC_TRUE);
}

/**
*
*  read a fnode from name node
*
**/
EC_BOOL cxfs_read_npp(const UINT32 cxfs_md_id, const CSTRING *file_path, CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_npp: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_read(CXFS_MD_NPP(cxfs_md), file_path, cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read_npp: cxfsnp mgr read %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  update a fnode to name node
*
**/
EC_BOOL cxfs_update_npp(const UINT32 cxfs_md_id, const CSTRING *file_path, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_npp: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_npp: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_npp: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_update(CXFS_MD_NPP(cxfs_md), file_path, cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_npp: no name node accept file %s with %u replicas updating\n",
                            (char *)cstring_get_str(file_path), CXFSNP_FNODE_REPNUM(cxfsnp_fnode));
        return (EC_FALSE);
    }

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_file_update_op(CXFS_MD_OP_MGR(cxfs_md),
                                         (uint32_t )cstring_get_len(file_path),
                                         (uint8_t *)cstring_get_str(file_path),
                                         (uint32_t )CXFSNP_FNODE_FILESZ(cxfsnp_fnode),
                                         (uint16_t )CXFSNP_FNODE_INODE_DISK_NO(cxfsnp_fnode, 0),
                                         (uint16_t )CXFSNP_FNODE_INODE_BLOCK_NO(cxfsnp_fnode, 0),
                                         (uint16_t )CXFSNP_FNODE_INODE_PAGE_NO(cxfsnp_fnode, 0));
    }
    return (EC_TRUE);
}

/**
*
*  renew a fnode to name node
*
**/
EC_BOOL cxfs_renew(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew: obsolete interface\n");
    return (EC_FALSE);
}

/**
*
*  renew a file which stores http headers
*
**/
EC_BOOL cxfs_renew_http_header(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRING *key, const CSTRING *val)
{
    CXFS_MD      *cxfs_md;
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    char         *v;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew_http_header: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_header: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_header: cxfs is read-only\n");
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);

        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRING_STR(key));
    if(NULL_PTR == v)
    {
        chttp_rsp_add_header(&chttp_rsp, (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));
    }
    else
    {
        chttp_rsp_renew_header(&chttp_rsp, (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));
    }

    cbytes_clean(&cbytes);
    if(EC_FALSE == chttp_rsp_encode(&chttp_rsp, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_header: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_update(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_header: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_renew_http_header: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));


    /*notify all waiters*/
    cxfs_file_notify(cxfs_md_id, file_path);
    return (EC_TRUE);
}

EC_BOOL cxfs_renew_http_headers(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr)
{
    CXFS_MD      *cxfs_md;
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew_http_headers: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: cxfs is read-only\n");
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV       *cstrkv;
        char         *v;

        cstrkv = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv));
        if(NULL_PTR == v)
        {
            chttp_rsp_add_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
        }
        else
        {
            chttp_rsp_renew_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
        }

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_renew_http_headers: '%s' renew '%s':%s done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    cbytes_clean(&cbytes);
    if(EC_FALSE == chttp_rsp_encode(&chttp_rsp, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_update(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);
    chttp_rsp_clean(&chttp_rsp);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_renew_http_headers: '%s' renew headers done\n",
                (char *)CSTRING_STR(file_path));


    /*notify all waiters*/
    cxfs_file_notify(cxfs_md_id, file_path);
    return (EC_TRUE);
}

EC_BOOL cxfs_renew_http_headers_with_token(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, const CSTRING *token_str)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew_http_headers_with_token: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers_with_token: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers_with_token: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_renew_http_headers(cxfs_md_id, file_path, cstrkv_mgr))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers_with_token: renew headers in '%s' failed\n", (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_is_empty(token_str))
    {
        cxfs_file_unlock(cxfs_md_id, file_path, token_str);
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_renew_http_headers_with_token: unlock '%s' done\n", (char *)CSTRING_STR(file_path));
    }

    return (EC_TRUE);
}

/**
*
*  wait a file which stores http headers util specific headers are ready
*
**/
EC_BOOL cxfs_wait_http_header(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRING *key, const CSTRING *val, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_http_header: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_header: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_header: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);

    (*header_ready) = EC_TRUE;
    do
    {
        char         *v;

        v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRING_STR(key));
        if(NULL_PTR == v)
        {
            (*header_ready) = EC_FALSE;
            break;
        }

        if(NULL_PTR != CSTRING_STR(val) && 0 != STRCASECMP((char *)CSTRING_STR(val), v))
        {
            (*header_ready) = EC_FALSE;
            break;
        }
    }while(0);

    chttp_rsp_clean(&chttp_rsp);

    if(EC_TRUE == (*header_ready))
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_http_header: '%s' wait header '%s':'%s' => ready\n",
                    (char *)CSTRING_STR(file_path),
                    (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_file_wait(cxfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_http_header: '%s' wait header '%s':'%s' => OK\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_http_headers(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_http_headers: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_headers: '%s' decode to http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    cbytes_clean(&cbytes);

    (*header_ready) = EC_TRUE;
    CLIST_LOOP_NEXT(CSTRKV_MGR_LIST(cstrkv_mgr), clist_data)
    {
        CSTRKV       *cstrkv;
        char         *v;

        cstrkv = CLIST_DATA_DATA(clist_data);
        if(NULL_PTR == cstrkv)
        {
            continue;
        }

        v = chttp_rsp_get_header(&chttp_rsp, (char *)CSTRKV_KEY_STR(cstrkv));
        if(NULL_PTR == v)
        {
            (*header_ready) = EC_FALSE;
            break;
        }

        if(NULL_PTR != CSTRKV_VAL_STR(cstrkv) && 0 != STRCASECMP((char *)CSTRKV_VAL_STR(cstrkv), v))
        {
            (*header_ready) = EC_FALSE;
            break;
        }

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_http_headers: '%s' wait '%s':'%s' done\n",
                (char *)CSTRING_STR(file_path),
                (char *)CSTRKV_KEY_STR(cstrkv), (char *)CSTRKV_VAL_STR(cstrkv));
    }

    chttp_rsp_clean(&chttp_rsp);

    if(EC_TRUE == (*header_ready))
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_http_headers: '%s' headers => ready\n",
                (char *)CSTRING_STR(file_path));

        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_file_wait(cxfs_md_id, tcid, file_path, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_http_headers: '%s' wait headers => OK\n",
                (char *)CSTRING_STR(file_path));

    return (EC_TRUE);
}

/**
*
*  delete file data from current dn
*
**/
STATIC_CAST static EC_BOOL __cxfs_delete_dn(const UINT32 cxfs_md_id, const CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD *cxfs_md;
    const CXFSNP_INODE *cxfsnp_inode;

    uint32_t file_size;
    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_delete_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_delete_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(0 == CXFSNP_FNODE_REPNUM(cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_delete_dn: no replica\n");
        return (EC_FALSE);
    }

    file_size    = CXFSNP_FNODE_FILESZ(cxfsnp_fnode);
    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    disk_no  = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no  = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    if(EC_FALSE == cxfsdn_remove(CXFS_MD_DN(cxfs_md), disk_no, block_no, page_no, file_size))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u failed\n", file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_delete_dn: remove file fsize %u, disk %u, block %u, page %u done\n", file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

EC_BOOL cxfs_delete_dn(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, const CXFSNP_ITEM *cxfsnp_item)
{
    CXFS_MD     *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dn: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != cxfsnp_item)
    {
        if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
        {
            if(EC_FALSE == __cxfs_delete_dn(cxfs_md_id, CXFSNP_ITEM_FNODE(cxfsnp_item)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dn: delete regular file from dn failed\n");
                return (EC_FALSE);
            }
            return (EC_TRUE);
        }

        /*Oops! not implement or not support yet ...*/
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dn: cxfsnp_item %p dflag flag 0x%x is unknown\n",
                            cxfsnp_item, CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
    }
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_check_path_has_wildcard(const CSTRING *path)
{
    const char     *str;
    UINT32          len;

    if(NULL_PTR == path)
    {
        return (EC_FALSE);
    }

    str = (const char *)cstring_get_str(path);
    len = cstring_get_len(path);
    if(1 >= len || '/' != (*str))
    {
        return (EC_FALSE);
    }

    /*now len > 1*/
    if('*' == str[ len - 1 ] && '/' == str[ len - 2 ])
    {
        return (EC_TRUE);
    }

    if(NULL_PTR != strstr(str, (const char *)"/*/"))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

/**
*
*  delete a file
*
**/
EC_BOOL cxfs_delete_file(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_file: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    if(EC_TRUE == __cxfs_check_path_has_wildcard(path))
    {
        return cxfs_delete_file_wildcard(cxfs_md_id, path);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_file: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file: cxfs_md_id %ld, path %s ...\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == cxfsnp_mgr_umount_deep(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file: cxfs_md_id %ld, path %s done\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    /*force to unlock the possible locked-file*/
    /*__cxfs_file_unlock(cxfs_md_id, path, NULL_PTR);*/

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_file_delete_op(CXFS_MD_OP_MGR(cxfs_md),
                                          (uint32_t )cstring_get_len(path),
                                          (uint8_t *)cstring_get_str(path));
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_delete_file_no_lock(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_file_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file_no_lock: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file_no_lock: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_file_no_lock: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file_no_lock: cxfs_md_id %ld, path %s ...\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == cxfsnp_mgr_umount_deep(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file_no_lock: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_file_delete_op(CXFS_MD_OP_MGR(cxfs_md),
                                         (uint32_t )cstring_get_len(path),
                                         (uint8_t *)cstring_get_str(path));
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file_no_lock: cxfs_md_id %ld, path %s done\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL cxfs_delete_file_wildcard(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD      *cxfs_md;
    MOD_NODE      mod_node;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_file_wildcard: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file_wildcard: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file_wildcard: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_file_wildcard: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file_wildcard: cxfs_md_id %ld, path %s ...\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_file_wildcard_delete_op(CXFS_MD_OP_MGR(cxfs_md),
                                                   (uint32_t )cstring_get_len(path),
                                                   (uint8_t *)cstring_get_str(path));
    }

    if(EC_FALSE == cxfsnp_mgr_umount_wildcard(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_file_wildcard: umount %.*s failed or terminated\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));

        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file_wildcard: cxfs_md_id %ld, path %s succ\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    /*force to unlock the possible locked-file*/
    /*__cxfs_file_unlock(cxfs_md_id, path, NULL_PTR);*/

    /*try to delete next matched file*/
    MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_md_id;

    task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &mod_node,
             NULL_PTR,
             FI_cxfs_delete_file_wildcard, CMPI_ERROR_MODI, path);

    return (EC_TRUE);
}

/**
*
*  delete a dir from all npp and all dn
*
**/
EC_BOOL cxfs_delete_dir(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    if(EC_TRUE == __cxfs_check_path_has_wildcard(path))
    {
        return cxfs_delete_dir_wildcard(cxfs_md_id, path);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_dir: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir: cxfs_md_id %ld, path %s ...\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == cxfsnp_mgr_umount_deep(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_dir_delete_op(CXFS_MD_OP_MGR(cxfs_md),
                                         (uint32_t )cstring_get_len(path),
                                         (uint8_t *)cstring_get_str(path));
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir: cxfs_md_id %ld, path %s done\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL cxfs_delete_dir_no_lock(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dir_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_no_lock: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_no_lock: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_dir_no_lock: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_no_lock: cxfs_md_id %ld, path %s ...\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    if(EC_FALSE == cxfsnp_mgr_umount_deep(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_no_lock: umount %.*s failed\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_dir_delete_op(CXFS_MD_OP_MGR(cxfs_md),
                                         (uint32_t )cstring_get_len(path),
                                         (uint8_t *)cstring_get_str(path));
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_no_lock: cxfs_md_id %ld, path %s done\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL cxfs_delete_dir_wildcard(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD      *cxfs_md;
    MOD_NODE      mod_node;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dir_wildcard: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_wildcard: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_wildcard: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_dir_wildcard: npp was not open\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_wildcard: cxfs_md_id %ld, path %s ...\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_dir_wildcard_delete_op(CXFS_MD_OP_MGR(cxfs_md),
                                                 (uint32_t )cstring_get_len(path),
                                                 (uint8_t *)cstring_get_str(path));
    }

    if(EC_FALSE == cxfsnp_mgr_umount_wildcard_deep(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_wildcard: umount %.*s failed or terminated\n",
                            (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_wildcard: cxfs_md_id %ld, path %s succ\n",
                        cxfs_md_id, (char *)cstring_get_str(path));

     /*try to delete next matched file*/
    MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
    MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
    MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
    MOD_NODE_MODI(&mod_node) = cxfs_md_id;

    task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
             &mod_node,
             NULL_PTR,
             FI_cxfs_delete_dir_wildcard, CMPI_ERROR_MODI, path);

    return (EC_TRUE);
}

/**
*
*  delete a file or dir from all npp and all dn
*
**/
EC_BOOL cxfs_delete(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 dflag)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return cxfs_delete_file(cxfs_md_id, path);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return cxfs_delete_dir(cxfs_md_id, path);
    }

    if(CXFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        cxfs_delete_file(cxfs_md_id, path);
        cxfs_delete_dir(cxfs_md_id, path);

        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete: cxfs_md_id %ld, path [invalid 0x%lx] %s\n",
                        cxfs_md_id, dflag, (char *)cstring_get_str(path));

    return (EC_FALSE);
}

EC_BOOL cxfs_delete_no_lock(const UINT32 cxfs_md_id, const CSTRING *path, const UINT32 dflag)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_no_lock: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_no_lock: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == dflag)
    {
        return cxfs_delete_file_no_lock(cxfs_md_id, path);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == dflag)
    {
        return cxfs_delete_dir_no_lock(cxfs_md_id, path);
    }

    if(CXFSNP_ITEM_FILE_IS_ANY == dflag)
    {
        cxfs_delete_file_no_lock(cxfs_md_id, path);
        cxfs_delete_dir_no_lock(cxfs_md_id, path);

        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_no_lock: cxfs_md_id %ld, path [invalid 0x%lx] %s\n",
                        cxfs_md_id, dflag, (char *)cstring_get_str(path));

    return (EC_FALSE);
}

/**
*
*  update a file
*  (atomic operation)
*
**/
EC_BOOL cxfs_update(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_update_no_lock(cxfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update: update file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update: update file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL cxfs_update_no_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == cxfs_write_no_lock(cxfs_md_id, file_path, cbytes))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: write file %s failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update_no_lock: write file %s done\n", (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*file exist, update it*/
    if(EC_FALSE == cxfs_delete_no_lock(cxfs_md_id, file_path, CXFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: delete old file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update_no_lock: delete old file %s done\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == cxfs_write_no_lock(cxfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: write new file %s failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update_no_lock: write new file %s done\n", (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL cxfs_update_with_token(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *token_str)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update_with_token: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_with_token: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_with_token: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_update(cxfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_update_with_token: update '%s' failed\n", (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == cstring_is_empty(token_str))
    {
        cxfs_file_unlock(cxfs_md_id, file_path, token_str);
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update_with_token: unlock '%s' done\n", (char *)CSTRING_STR(file_path));
    }

    return (EC_TRUE);
}

/**
*
*  query a file
*
**/
EC_BOOL cxfs_qfile(const UINT32 cxfs_md_id, const CSTRING *file_path, CXFSNP_ITEM  *cxfsnp_item, CXFSNP_KEY *cxfsnp_key)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_ITEM  *cxfsnp_item_src;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qfile: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qfile: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_item_src = cxfsnp_mgr_search_item(CXFS_MD_NPP(cxfs_md),
                                             (uint32_t)cstring_get_len(file_path),
                                             cstring_get_str(file_path),
                                             CXFSNP_ITEM_FILE_IS_REG);
    if(NULL_PTR == cxfsnp_item_src)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qfile: query file %s from npp failed\n",
                            (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*clone*/
    if(NULL_PTR != cxfsnp_item)
    {
        cxfsnp_item_clone(cxfsnp_item_src, cxfsnp_item);
    }

    if(NULL_PTR != cxfsnp_key)
    {
        cxfsnp_key_clone(CXFSNP_ITEM_KEY(cxfsnp_item_src), cxfsnp_key);
    }

    return (EC_TRUE);
}

/**
*
*  query a dir
*
**/
EC_BOOL cxfs_qdir(const UINT32 cxfs_md_id, const CSTRING *dir_path, CXFSNP_ITEM  *cxfsnp_item, CXFSNP_KEY *cxfsnp_key)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_ITEM  *cxfsnp_item_src;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qdir: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_item_src = cxfsnp_mgr_search_item(CXFS_MD_NPP(cxfs_md),
                                             (uint32_t)cstring_get_len(dir_path),
                                             cstring_get_str(dir_path),
                                             CXFSNP_ITEM_FILE_IS_DIR);
    if(NULL_PTR == cxfsnp_item_src)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qdir: query dir %s from npp failed\n",
                            (char *)cstring_get_str(dir_path));
        return (EC_FALSE);
    }

    /*clone*/
    if(NULL_PTR != cxfsnp_item)
    {
        cxfsnp_item_clone(cxfsnp_item_src, cxfsnp_item);
    }

    if(NULL_PTR != cxfsnp_key)
    {
        cxfsnp_key_clone(CXFSNP_ITEM_KEY(cxfsnp_item_src), cxfsnp_key);
    }

    return (EC_TRUE);
}

/**
*
*  query and list full path of a file or dir
*
**/
EC_BOOL cxfs_qlist_path(const UINT32 cxfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_path: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_path: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_list_path(CXFS_MD_NPP(cxfs_md), file_path, path_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_path: list path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query and list full path of a file or dir of one np
*
**/
EC_BOOL cxfs_qlist_path_of_np(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 cxfsnp_id, CVECTOR  *path_cstr_vec)
{
    CXFS_MD      *cxfs_md;
    uint32_t      cxfsnp_id_t;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_path_of_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_path_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_id_t = (uint32_t)cxfsnp_id;

    if(EC_FALSE == cxfsnp_mgr_list_path_of_np(CXFS_MD_NPP(cxfs_md), file_path, cxfsnp_id_t, path_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_path_of_np: list path '%s' of np %u failed\n",
                            (char *)cstring_get_str(file_path), cxfsnp_id_t);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query and list short name of a file or dir
*
**/
EC_BOOL cxfs_qlist_seg(const UINT32 cxfs_md_id, const CSTRING *file_path, CVECTOR  *seg_cstr_vec)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_seg: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_seg: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_list_seg(CXFS_MD_NPP(cxfs_md), file_path, seg_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_seg: list seg of path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  query and list short name of a file or dir of one np
*
**/
EC_BOOL cxfs_qlist_seg_of_np(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 cxfsnp_id, CVECTOR  *seg_cstr_vec)
{
    CXFS_MD      *cxfs_md;
    uint32_t      cxfsnp_id_t;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_seg_of_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_seg_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_id_t = (uint32_t)cxfsnp_id;

    if(EC_FALSE == cxfsnp_mgr_list_seg_of_np(CXFS_MD_NPP(cxfs_md), file_path, cxfsnp_id_t, seg_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_seg_of_np: list seg of path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_cat_path(const CXFSNP_ITEM *cxfsnp_item, CSTRING *des_path)
{
    cstring_rtrim(des_path, (UINT8)'/');
    cstring_append_chars(des_path, (UINT32)1, (const UINT8 *)"/", LOC_CXFS_0005);
    cstring_append_chars(des_path, CXFSNP_ITEM_KLEN(cxfsnp_item), CXFSNP_ITEM_KNAME(cxfsnp_item), LOC_CXFS_0006);

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_qlist_tree(CXFSNP_DIT_NODE *cxfsnp_dit_node, CXFSNP *cxfsnp, CXFSNP_ITEM *cxfsnp_item, const uint32_t node_pos)
{
    if(CXFSNP_ITEM_IS_NOT_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_qlist_tree: item was not used\n");
        return (EC_FALSE);
    }

    if(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        CVECTOR *path_cstr_vec;
        CSTRING *base_dir;
        CSTRING *full_path;

        base_dir      = CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, 1);
        path_cstr_vec = CXFSNP_DIT_NODE_ARG(cxfsnp_dit_node, 2);

        full_path = cstring_new(cstring_get_str(base_dir), LOC_CXFS_0007);
        if(NULL_PTR == full_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_qlist_tree: new cstring failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == cstack_walk(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node), (void *)full_path, (CSTACK_DATA_DATA_WALKER)__cxfs_cat_path))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_qlist_tree: walk stack failed\n");

            cstring_free(full_path);
            return (EC_FALSE);
        }

        cvector_push(path_cstr_vec, (void *)full_path);
        return (EC_TRUE);
    }

    if(CXFSNP_ITEM_FILE_IS_DIR == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item))
    {
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_expire: invalid item dflag %u at node pos %u\n",
                        CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), node_pos);
    return (EC_FALSE);
}

/**
*
*  query and list full path of a file or  all files under a dir recursively
*  (looks like shell command: tree)
*
**/
EC_BOOL cxfs_qlist_tree(const UINT32 cxfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CXFS_MD        *cxfs_md;
    CXFSNP_DIT_NODE cxfsnp_dit_node;
    CSTRING        *base_dir;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_tree: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_tree: npp was not open\n");
        return (EC_FALSE);
    }

    base_dir = cstring_new(cstring_get_str(file_path), LOC_CXFS_0008);
    if(NULL_PTR == base_dir)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_tree: new cstring failed\n");
        return (EC_FALSE);
    }

    cstring_rtrim(base_dir, (UINT8)'/');
    cstring_erase_tail_until(base_dir, (UINT8)'/');

    cxfsnp_dit_node_init(&cxfsnp_dit_node);

    CXFSNP_DIT_NODE_HANDLER(&cxfsnp_dit_node) = __cxfs_qlist_tree;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 0)  = (void *)cxfs_md_id;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 1)  = (void *)base_dir;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 2)  = (void *)path_cstr_vec;

    if(EC_FALSE == cxfsnp_mgr_walk(CXFS_MD_NPP(cxfs_md), file_path, CXFSNP_ITEM_FILE_IS_ANY, &cxfsnp_dit_node))
    {
        cstring_free(base_dir);
        cxfsnp_dit_node_clean(&cxfsnp_dit_node);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_path: list path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_qlist_path: after walk, stack is:\n");
        cstack_print(LOGSTDOUT, CXFSNP_DIT_NODE_STACK(&cxfsnp_dit_node), (CSTACK_DATA_DATA_PRINT)cxfsnp_item_and_key_print);
    }

    cstring_free(base_dir);
    cxfsnp_dit_node_clean(&cxfsnp_dit_node);
    return (EC_TRUE);
}

/**
*
*  query and list full path of a file or all files under a dir of one np
*  (looks like shell command: tree)
*
**/
EC_BOOL cxfs_qlist_tree_of_np(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CXFS_MD        *cxfs_md;

    CXFSNP_DIT_NODE cxfsnp_dit_node;
    CSTRING        *base_dir;
    uint32_t        cxfsnp_id_t;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_tree_of_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_tree_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_id_t = (uint32_t)cxfsnp_id;

    base_dir = cstring_new(cstring_get_str(file_path), LOC_CXFS_0009);
    if(NULL_PTR == base_dir)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_tree_of_np: new cstring failed\n");
        return (EC_FALSE);
    }

    cstring_rtrim(base_dir, (UINT8)'/');
    cstring_erase_tail_until(base_dir, (UINT8)'/');

    cxfsnp_dit_node_init(&cxfsnp_dit_node);

    CXFSNP_DIT_NODE_HANDLER(&cxfsnp_dit_node) = __cxfs_qlist_tree;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 0)  = (void *)cxfs_md_id;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 1)  = (void *)file_path;
    CXFSNP_DIT_NODE_ARG(&cxfsnp_dit_node, 2)  = (void *)path_cstr_vec;

    if(EC_FALSE == cxfsnp_mgr_walk_of_np(CXFS_MD_NPP(cxfs_md), cxfsnp_id_t, file_path, CXFSNP_ITEM_FILE_IS_ANY, &cxfsnp_dit_node))
    {
        cstring_free(base_dir);
        cxfsnp_dit_node_clean(&cxfsnp_dit_node);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_tree_of_np: list tree of path '%s' failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_qlist_tree_of_np: after walk, stack is:\n");
        cstack_print(LOGSTDOUT, CXFSNP_DIT_NODE_STACK(&cxfsnp_dit_node), (CSTACK_DATA_DATA_PRINT)cxfsnp_item_and_key_print);
    }

    cstring_free(base_dir);
    cxfsnp_dit_node_clean(&cxfsnp_dit_node);
    return (EC_TRUE);
}

/**
*
*  flush name node pool
*
**/
EC_BOOL cxfs_flush_npp(const UINT32 cxfs_md_id)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_flush_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_flush_npp: npp was not open\n");
        return (EC_TRUE);
    }

    if(EC_FALSE == cxfsnp_mgr_flush(CXFS_MD_NPP(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush_npp: flush failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_flush_npp: flush done\n");
    return (EC_TRUE);
}

/**
*
*  flush data node
*
*
**/
EC_BOOL cxfs_flush_dn(const UINT32 cxfs_md_id)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_flush_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_flush(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush_dn: flush dn failed\n");
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_flush_dn: flush dn done\n");
    return (EC_TRUE);
}

/**
*
*  count file num under specific path
*  if path is regular file, return file_num 1
*  if path is directory, return file num under it
*
**/
EC_BOOL cxfs_file_num(const UINT32 cxfs_md_id, const CSTRING *path_cstr, UINT32 *file_num)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_num: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_file_num: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_file_num(CXFS_MD_NPP(cxfs_md), path_cstr, file_num))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_num: get file num of path '%s' failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  get file size of specific file given full path name
*
**/
EC_BOOL cxfs_file_size(const UINT32 cxfs_md_id, const CSTRING *path_cstr, uint64_t *file_size)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_size: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_file_size: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_file_size(CXFS_MD_NPP(cxfs_md), path_cstr, file_size))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_size: cxfsnp mgr get size of %s failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_size: file %s, size %ld\n",
                             (char *)cstring_get_str(path_cstr),
                             (*file_size));
    return (EC_TRUE);
}

/**
*
*  set file expired time to current time
*
**/
EC_BOOL cxfs_file_expire(const UINT32 cxfs_md_id, const CSTRING *path_cstr)
{
    CXFS_MD      *cxfs_md;
    CSTRING       key;
    CSTRING       val;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_expire: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_expire: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_expire: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_file_expire: npp was not open\n");
        return (EC_FALSE);
    }

    cstring_init(&key, (const UINT8 *)"Expires");
    cstring_init(&val, (const UINT8 *)c_http_time(task_brd_default_get_time()));

    if(EC_FALSE == cxfs_renew_http_header(cxfs_md_id, path_cstr, &key, &val))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_expire: expire %s failed\n", (char *)cstring_get_str(path_cstr));
        cstring_clean(&key);
        cstring_clean(&val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_expire: expire %s done\n", (char *)cstring_get_str(path_cstr));
    cstring_clean(&key);
    cstring_clean(&val);
    return (EC_TRUE);
}

/**
*
*  get file md5sum of specific file given full path name
*
**/
EC_BOOL cxfs_file_md5sum(const UINT32 cxfs_md_id, const CSTRING *path_cstr, CMD5_DIGEST *md5sum)
{
    CXFS_MD      *cxfs_md;
    CBYTES        cbytes;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_md5sum: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_file_md5sum: npp was not open\n");
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, path_cstr, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_md5sum: read %s failed\n", (char *)cstring_get_str(path_cstr));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    cmd5_sum((uint32_t)CBYTES_LEN(&cbytes), CBYTES_BUF(&cbytes), CMD5_DIGEST_SUM(md5sum));
    cbytes_clean(&cbytes);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_md5sum: file %s, md5 %s\n",
                             (char *)cstring_get_str(path_cstr),
                             cmd5_digest_hex_str(md5sum));
    return (EC_TRUE);
}

/**
*
*  mkdir in current name node pool
*
**/
EC_BOOL cxfs_mkdir(const UINT32 cxfs_md_id, const CSTRING *path_cstr)
{
    CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_mkdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mkdir: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mkdir: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_mkdir: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_mkdir(CXFS_MD_NPP(cxfs_md), path_cstr))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mkdir: mkdir '%s' failed\n", (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_dir_add_op(CXFS_MD_OP_MGR(cxfs_md),
                                      (uint32_t )cstring_get_len(path_cstr),
                                      (uint8_t *)cstring_get_str(path_cstr));
    }
    return (EC_TRUE);
}

/**
*
*  search in current name node pool
*
**/
EC_BOOL cxfs_search(const UINT32 cxfs_md_id, const CSTRING *path_cstr, const UINT32 dflag)
{
    CXFS_MD      *cxfs_md;
    uint32_t      cxfsnp_id;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_search: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_search: cxfs_md_id %ld, path %s, dflag %lx\n", cxfs_md_id, (char *)cstring_get_str(path_cstr), dflag);

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_search: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_search(CXFS_MD_NPP(cxfs_md), (uint32_t)cstring_get_len(path_cstr), cstring_get_str(path_cstr), dflag, &cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_search: search '%s' with dflag %lx failed\n", (char *)cstring_get_str(path_cstr), dflag);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_recycle_of_np(const UINT32 cxfs_md_id, const uint32_t cxfsnp_id, const UINT32 max_num, UINT32 *complete_num)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_RECYCLE_DN cxfsnp_recycle_dn;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:__cxfs_recycle_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    CXFSNP_RECYCLE_DN_ARG1(&cxfsnp_recycle_dn)   = cxfs_md_id;
    CXFSNP_RECYCLE_DN_FUNC(&cxfsnp_recycle_dn)   = cxfs_release_dn;

    if(EC_FALSE == cxfsnp_mgr_recycle_np(CXFS_MD_NPP(cxfs_md), cxfsnp_id, max_num, NULL_PTR, &cxfsnp_recycle_dn, complete_num))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_recycle_of_np: recycle np %u failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_recycle_of_np: recycle np %u done where complete %ld\n",
                    cxfsnp_id, (*complete_num));

    return (EC_TRUE);
}

/**
*
*  empty recycle
*
**/
EC_BOOL cxfs_recycle(const UINT32 cxfs_md_id, const UINT32 max_num_per_np, UINT32 *complete_num)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_MGR   *cxfsnp_mgr;

    UINT32        complete_recycle_num;
    uint32_t      cxfsnp_id;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_recycle: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_recycle: recycle beg\n");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_recycle: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_recycle: cxfs is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp_mgr = CXFS_MD_NPP(cxfs_md);
    if(NULL_PTR == cxfsnp_mgr)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_recycle: npp was not open\n");
        return (EC_FALSE);
    }

    complete_recycle_num = 0;/*initialization*/

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        __cxfs_recycle_of_np(cxfs_md_id, cxfsnp_id, max_num_per_np, &complete_recycle_num);
        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_recycle: recycle np %u done\n", cxfsnp_id);
    }

    if(0 < complete_recycle_num)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_recycle: recycle end where complete %ld\n", complete_recycle_num);
    }

    if(NULL_PTR != complete_num)
    {
        (*complete_num) = complete_recycle_num;
    }
    return (EC_TRUE);
}

/**
*
*  check and process retire & recycle if necessary
*
**/
EC_BOOL cxfs_process_space(const UINT32 cxfs_md_id)
{
    CXFS_MD      *cxfs_md;
    REAL          npp_used_ratio;
    REAL          dn_used_ratio;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_process_space: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        /*do not process*/
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        /*do not process*/
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_process_space: npp was not open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_process_space: dn was not open\n");
        return (EC_FALSE);
    }

    npp_used_ratio = cxfsnp_mgr_used_ratio(CXFS_MD_NPP(cxfs_md));
    dn_used_ratio  = cxfsdn_used_ratio(CXFS_MD_DN(cxfs_md));

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_process_space: "
                                         "npp used ratio %.3f, dn used ratio %.3f\n",
                                         npp_used_ratio, dn_used_ratio);

    if(CXFSNP_MAX_USED_RATIO <= npp_used_ratio)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_process_space: "
                                             "npp used ratio %.3f >= %.3f => retire & recycle\n",
                                             npp_used_ratio, CXFSNP_MAX_USED_RATIO);

        cxfs_retire(cxfs_md_id , (UINT32)CXFSNP_TRY_RETIRE_MAX_NUM , NULL_PTR);
        cxfs_recycle(cxfs_md_id, (UINT32)CXFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    dn_used_ratio = cxfsdn_used_ratio(CXFS_MD_DN(cxfs_md));
    if(CXFSDN_MAX_USED_RATIO <= dn_used_ratio)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_process_space: "
                                             "dn used ratio %.3f >= %.3f => retire & recycle\n",
                                             dn_used_ratio, CXFSDN_MAX_USED_RATIO);

        cxfs_retire(cxfs_md_id , (UINT32)CXFSNP_TRY_RETIRE_MAX_NUM , NULL_PTR);
        cxfs_recycle(cxfs_md_id, (UINT32)CXFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    return (EC_TRUE);
}

/**
*
*  check file content on data node
*
**/
EC_BOOL cxfs_check_file_content(const UINT32 cxfs_md_id, const UINT32 disk_no, const UINT32 block_no, const UINT32 page_no, const UINT32 file_size, const CSTRING *file_content_cstr)
{
    CXFS_MD *cxfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_file_content: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: dn is null\n");
        return (EC_FALSE);
    }

    ASSERT(EC_TRUE == c_check_is_uint16_t(disk_no));
    ASSERT(EC_TRUE == c_check_is_uint16_t(block_no));
    ASSERT(EC_TRUE == c_check_is_uint16_t(page_no));

    cbytes = cbytes_new(file_size);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: new cxfs buff with len %ld failed\n", file_size);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_read_p(CXFS_MD_DN(cxfs_md), (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no, file_size,
                                  CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: read %ld bytes from disk %u, block %u, page %u failed\n",
                            file_size, (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < cstring_get_len(file_content_cstr))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: read %ld bytes from disk %u, block %u, page %u to buff len %u less than cstring len %u to compare\n",
                            file_size, (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no,
                            (uint32_t)CBYTES_LEN(cbytes), (uint32_t)cstring_get_len(file_content_cstr));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    len = cstring_get_len(file_content_cstr);

    buff = CBYTES_BUF(cbytes);
    str  = cstring_get_str(file_content_cstr);

    for(pos = 0; pos < len; pos ++)
    {
        if(buff[ pos ] != str[ pos ])
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: char at pos %ld not matched\n", pos);
            sys_print(LOGSTDOUT, "read buff: %.*s\n", (uint32_t)len, buff);
            sys_print(LOGSTDOUT, "expected : %.*s\n", (uint32_t)len, str);

            cbytes_free(cbytes);
            return (EC_FALSE);
        }
    }

    cbytes_free(cbytes);
    return (EC_TRUE);
}

/**
*
*  check file content on data node
*
**/
EC_BOOL cxfs_check_file_is(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *file_content)
{
    CXFS_MD *cxfs_md;

    CBYTES *cbytes;

    UINT8 *buff;
    UINT8 *str;

    UINT32 len;
    UINT32 pos;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_file_is: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: dn is null\n");
        return (EC_FALSE);
    }

    cbytes = cbytes_new(0);
    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: new cbytes failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: read file %s failed\n", (char *)cstring_get_str(file_path));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) != CBYTES_LEN(file_content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: mismatched len: file %s read len %ld which should be %ld\n",
                            (char *)cstring_get_str(file_path),
                            CBYTES_LEN(cbytes), CBYTES_LEN(file_content));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    len  = CBYTES_LEN(file_content);

    buff = CBYTES_BUF(cbytes);
    str  = CBYTES_BUF(file_content);

    for(pos = 0; pos < len; pos ++)
    {
        if(buff[ pos ] != str[ pos ])
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: char at pos %ld not matched\n", pos);
            sys_print(LOGSTDOUT, "read buff: %.*s\n", (uint32_t)len, buff);
            sys_print(LOGSTDOUT, "expected : %.*s\n", (uint32_t)len, str);

            cbytes_free(cbytes);
            return (EC_FALSE);
        }
    }

    cbytes_free(cbytes);
    return (EC_TRUE);
}

/**
*
*  show name node lru list if it is npp
*
*
**/
EC_BOOL cxfs_show_npp_lru_list(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_npp_lru_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cxfsnp_mgr_print_lru_list(log, CXFS_MD_NPP(cxfs_md));

    return (EC_TRUE);
}

/**
*
*  show name node del list if it is npp
*
*
**/
EC_BOOL cxfs_show_npp_del_list(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_npp_del_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cxfsnp_mgr_print_del_list(log, CXFS_MD_NPP(cxfs_md));

    return (EC_TRUE);
}

/**
*
*  show name node pool info if it is npp
*
*
**/
EC_BOOL cxfs_show_npp(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cxfsnp_mgr_print(log, CXFS_MD_NPP(cxfs_md));

    return (EC_TRUE);
}

/*for debug only*/
EC_BOOL cxfs_show_dn_no_lock(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_dn_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cxfsdn_print(log, CXFS_MD_DN(cxfs_md));

    return (EC_TRUE);
}

/**
*
*  show cxfsdn info if it is dn
*
*
**/
EC_BOOL cxfs_show_dn(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cxfsdn_print(log, CXFS_MD_DN(cxfs_md));

    return (EC_TRUE);
}

EC_BOOL cxfs_show_specific_np(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_specific_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np: cxfsnp_id %ld is invalid\n", cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_np(log, CXFS_MD_NPP(cxfs_md), (uint32_t)cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np: show np %ld but failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_show_specific_np_lru_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_specific_np_lru_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_lru_list: cxfsnp_id %ld is invalid\n", cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_np_lru_list(log, CXFS_MD_NPP(cxfs_md), (uint32_t)cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_lru_list: show np %ld but failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_show_specific_np_del_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_specific_np_del_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_del_list: cxfsnp_id %ld is invalid\n", cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_np_del_list(log, CXFS_MD_NPP(cxfs_md), (uint32_t)cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_del_list: show np %ld but failed\n", cxfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_show_path_depth(const UINT32 cxfs_md_id, const CSTRING *path, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_path_depth: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "error:cxfs_show_path_depth: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_path_depth(log, CXFS_MD_NPP(cxfs_md), path))
    {
        sys_log(log, "error:cxfs_show_path_depth: show path %s in depth failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_show_path(const UINT32 cxfs_md_id, const CSTRING *path, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_path: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "error:cxfs_show_path: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_path(log, CXFS_MD_NPP(cxfs_md), path))
    {
        sys_log(log, "error:cxfs_show_path: show path %s failed\n", (char *)cstring_get_str(path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_retire_of_np(const UINT32 cxfs_md_id, const uint32_t cxfsnp_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CXFS_MD      *cxfs_md;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:__cxfs_retire_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_retire_np(CXFS_MD_NPP(cxfs_md), cxfsnp_id, expect_retire_num, complete_retire_num))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_retire_of_np: retire np %u failed where expect retire num %ld\n",
                                            cxfsnp_id, expect_retire_num);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  retire regular/big files created before n seconds and dirs which are empty without file
*  note:
*    expect_retire_num is for per cxfsnp but not all cxfsnp(s)
*
**/
EC_BOOL cxfs_retire(const UINT32 cxfs_md_id, const UINT32 expect_retire_num, UINT32 *complete_retire_num)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_MGR   *cxfsnp_mgr;
    uint32_t      cxfsnp_id;

    UINT32   total_num;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_retire: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retire: cxfs is syncing\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retire: cxfs is read-only\n");
        return (EC_FALSE);
    }

    cxfsnp_mgr = CXFS_MD_NPP(cxfs_md);
    if(NULL_PTR == cxfsnp_mgr)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_retire: npp was not open\n");
        return (EC_FALSE);
    }

    for(cxfsnp_id = 0, total_num = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        UINT32   complete_num;

        __cxfs_retire_of_np(cxfs_md_id, cxfsnp_id, expect_retire_num, &complete_num);
        total_num += complete_num;

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_retire: retire np %u done wher expect retire num %ld, complete %ld\n",
                                cxfsnp_id, expect_retire_num, complete_num);
    }

    if(NULL_PTR != complete_retire_num)
    {
        (*complete_retire_num) = total_num;
    }

    if(0 < total_num)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_retire: retire done where complete %ld\n", total_num);
    }
    return (EC_TRUE);
}

/*------------------------------------------------ interface for file wait ------------------------------------------------*/
CXFS_WAIT_FILE *cxfs_wait_file_new()
{
    CXFS_WAIT_FILE *cxfs_wait_file;
    alloc_static_mem(MM_CXFS_WAIT_FILE, &cxfs_wait_file, LOC_CXFS_0010);
    if(NULL_PTR != cxfs_wait_file)
    {
        cxfs_wait_file_init(cxfs_wait_file);
    }
    return (cxfs_wait_file);
}

EC_BOOL cxfs_wait_file_init(CXFS_WAIT_FILE *cxfs_wait_file)
{
    cstring_init(CXFS_WAIT_FILE_NAME(cxfs_wait_file), NULL_PTR);

    clist_init(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file), MM_MOD_NODE, LOC_CXFS_0011);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_clean(CXFS_WAIT_FILE *cxfs_wait_file)
{
    cstring_clean(CXFS_WAIT_FILE_NAME(cxfs_wait_file));
    clist_clean(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file), (CLIST_DATA_DATA_CLEANER)mod_node_free);
    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_free(CXFS_WAIT_FILE *cxfs_wait_file)
{
    if(NULL_PTR != cxfs_wait_file)
    {
        cxfs_wait_file_clean(cxfs_wait_file);
        free_static_mem(MM_CXFS_WAIT_FILE, cxfs_wait_file, LOC_CXFS_0012);
    }
    return (EC_TRUE);
}

int cxfs_wait_file_cmp(const CXFS_WAIT_FILE *cxfs_wait_file_1st, const CXFS_WAIT_FILE *cxfs_wait_file_2nd)
{
    return cstring_cmp(CXFS_WAIT_FILE_NAME(cxfs_wait_file_1st), CXFS_WAIT_FILE_NAME(cxfs_wait_file_2nd));
}

void cxfs_wait_file_print(LOG *log, const CXFS_WAIT_FILE *cxfs_wait_file)
{
    if(NULL_PTR != cxfs_wait_file)
    {
        sys_log(log, "cxfs_wait_file_print %p: file %s, owner list: ",
                        cxfs_wait_file,
                        (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file)
                        );
        clist_print(log, CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file),(CLIST_DATA_DATA_PRINT)mod_node_print);
    }

    return;
}

void cxfs_wait_files_print(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_files_print: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    crb_tree_print(log, CXFS_MD_WAIT_FILES(cxfs_md));

    return;
}

EC_BOOL cxfs_wait_file_name_set(CXFS_WAIT_FILE *cxfs_wait_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CXFS_WAIT_FILE_NAME(cxfs_wait_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_wait_file_owner_cmp(const MOD_NODE *mod_node, const UINT32 tcid)
{
    if(MOD_NODE_TCID(mod_node) == tcid)
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

EC_BOOL cxfs_wait_file_owner_push(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tcid)
{
    CLIST *owner_list;

    owner_list = CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file);
    if(
       CMPI_ERROR_TCID != tcid
    && CMPI_ANY_TCID != tcid
    && NULL_PTR == clist_search_data_front(owner_list, (void *)tcid, (CLIST_DATA_DATA_CMP)__cxfs_wait_file_owner_cmp)
    )
    {
        MOD_NODE *mod_node;

        mod_node = mod_node_new();
        if(NULL_PTR == mod_node)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_file_owner_push: new mod_node failed\n");
            return (EC_FALSE);
        }

        MOD_NODE_TCID(mod_node) = tcid;
        MOD_NODE_COMM(mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(mod_node) = CMPI_FWD_RANK;
        MOD_NODE_MODI(mod_node) = 0;/*SUPER modi always be 0*/

        clist_push_back(owner_list, (void *)mod_node);

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_push: push %s to file '%.*s'\n",
                    c_word_to_ipv4(tcid), (uint32_t)CXFS_WAIT_FILE_NAME_LEN(cxfs_wait_file), CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file));
    }

    return (EC_TRUE);
}

/**
*
*  wakeup remote waiter (over http)
*
**/
EC_BOOL cxfs_wait_file_owner_wakeup (const UINT32 cxfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    //CXFS_MD     *cxfs_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_file_owner_wakeup: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CXFSHTTP_REST_API_NAME"/cond_wakeup");
    cstring_append_cstr(uri, path);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_wakeup: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_wakeup: wakeup '%.*s' on %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_notify_over_http (CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file)))
    {
        TASK_BRD *task_brd;
        TASK_MGR *task_mgr;
        MOD_NODE  recv_mod_node;
        EC_BOOL   ret; /*ignore it*/

        task_brd = task_brd_default_get();

        /*all tasks own same recv_mod_node*/
        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one cxfs module*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE   *mod_node;
            TASKS_CFG  *remote_tasks_cfg;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), MOD_NODE_TCID(mod_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "info:cxfs_wait_file_owner_notify: not found tasks_cfg of node %s\n", c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
                mod_node_free(mod_node);
                continue;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, &recv_mod_node,
                        &ret,
                        FI_cxfs_wait_file_owner_wakeup,
                        CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                        TASKS_CFG_CSRVPORT(remote_tasks_cfg),
                        CXFS_WAIT_FILE_NAME(cxfs_wait_file));

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_notify_over_bgn (CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file)))
    {
        TASK_MGR *task_mgr;
        EC_BOOL   ret; /*ignore it*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE *mod_node;

            /*note : after notify owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node, &ret, FI_super_cond_wakeup, CMPI_ERROR_MODI, tag, CXFS_WAIT_FILE_NAME(cxfs_wait_file));

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify : file %s tag %ld notify owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify : file %s tag %ld notify none due to no owner\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_notify(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return cxfs_wait_file_owner_notify_over_http(cxfs_wait_file, tag);
    }

    return cxfs_wait_file_owner_notify_over_bgn(cxfs_wait_file, tag);
}

/**
*
*  cancel remote waiter (over http)
*
**/
EC_BOOL cxfs_wait_file_owner_cancel (const UINT32 cxfs_md_id, const UINT32 store_srv_tcid, const UINT32 store_srv_ipaddr, const UINT32 store_srv_port, const CSTRING *path)
{
    //CXFS_MD     *cxfs_md;

    CHTTP_REQ    chttp_req;
    CHTTP_RSP    chttp_rsp;
    CSTRING     *uri;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_file_owner_cancel: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_str(uri, (uint8_t *)CXFSHTTP_REST_API_NAME"/cond_terminate");
    cstring_append_cstr(uri, path);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_cancel: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_file_owner_cancel: terminate '%.*s' on %s:%ld failed\n",
                        (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                        c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_cancel: terminate '%.*s' on %s:%ld done => status %u\n",
                    (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                    c_word_to_ipv4(store_srv_ipaddr), store_srv_port,
                    CHTTP_RSP_STATUS(&chttp_rsp));

    chttp_req_clean(&chttp_req);
    chttp_rsp_clean(&chttp_rsp);

    return (EC_TRUE);
}
EC_BOOL cxfs_wait_file_owner_terminate_over_http (CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file)))
    {
        TASK_BRD *task_brd;
        TASK_MGR *task_mgr;
        MOD_NODE  recv_mod_node;
        EC_BOOL   ret; /*ignore it*/

        task_brd = task_brd_default_get();

        /*all tasks own same recv_mod_node*/
        MOD_NODE_TCID(&recv_mod_node) = TASK_BRD_TCID(task_brd);
        MOD_NODE_COMM(&recv_mod_node) = TASK_BRD_COMM(task_brd);
        MOD_NODE_RANK(&recv_mod_node) = TASK_BRD_RANK(task_brd);
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one cxfs module*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE   *mod_node;
            TASKS_CFG  *remote_tasks_cfg;

            /*note : after terminate owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd), MOD_NODE_TCID(mod_node), CMPI_ANY_MASK, CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "info:cxfs_wait_file_owner_terminate: not found tasks_cfg of node %s\n", c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
                mod_node_free(mod_node);
                continue;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, &recv_mod_node,
                        &ret,
                        FI_cxfs_wait_file_owner_cancel,
                        CMPI_ERROR_MODI,
                        TASKS_CFG_TCID(remote_tasks_cfg),
                        TASKS_CFG_SRVIPADDR(remote_tasks_cfg),
                        TASKS_CFG_CSRVPORT(remote_tasks_cfg),
                        CXFS_WAIT_FILE_NAME(cxfs_wait_file));

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_terminate : file %s tag %ld terminate owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_terminate : file %s tag %ld terminate none due to no owner\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_terminate_over_bgn (CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
    if(EC_FALSE == clist_is_empty(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file)))
    {
        TASK_MGR *task_mgr;
        EC_BOOL   ret; /*ignore it*/

        task_mgr = task_new(NULL_PTR, TASK_PRIO_HIGH, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP);

        for(;;)
        {
            MOD_NODE *mod_node;

            /*note : after terminate owner, we can kick off the owner from list*/
            mod_node = clist_pop_front(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file));
            if(NULL_PTR == mod_node)
            {
                break;
            }

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node, &ret, FI_super_cond_terminate, CMPI_ERROR_MODI, tag, CXFS_WAIT_FILE_NAME(cxfs_wait_file));

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_terminate : file %s tag %ld terminate owner: tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag,
                            MOD_NODE_TCID_STR(mod_node),
                            MOD_NODE_COMM(mod_node),
                            MOD_NODE_RANK(mod_node),
                            MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_terminate : file %s tag %ld terminate none due to no owner\n",
                            (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_terminate(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
    if(SWITCH_ON == NGX_BGN_OVER_HTTP_SWITCH)
    {
        return cxfs_wait_file_owner_terminate_over_http(cxfs_wait_file, tag);
    }

    return cxfs_wait_file_owner_terminate_over_bgn(cxfs_wait_file, tag);
}

STATIC_CAST static EC_BOOL __cxfs_file_wait(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path)
{
    CXFS_MD          *cxfs_md;

    CRB_NODE         *crb_node;
    CXFS_WAIT_FILE   *cxfs_wait_file;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfs_wait_file = cxfs_wait_file_new();
    if(NULL_PTR == cxfs_wait_file)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_wait: new cxfs_wait_file failed\n");
        return (EC_FALSE);
    }

    cxfs_wait_file_name_set(cxfs_wait_file, file_path);

    crb_node = crb_tree_insert_data(CXFS_MD_WAIT_FILES(cxfs_md), (void *)cxfs_wait_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_wait: insert file %s to wait files tree failed\n",
                                (char *)cstring_get_str(file_path));
        cxfs_wait_file_free(cxfs_wait_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cxfs_wait_file)/*found duplicate*/
    {
        CXFS_WAIT_FILE *cxfs_wait_file_duplicate;

        cxfs_wait_file_duplicate = (CXFS_WAIT_FILE *)CRB_NODE_DATA(crb_node);

        cxfs_wait_file_free(cxfs_wait_file); /*no useful*/

        /*when found the file had been wait, register remote owner to it*/
        cxfs_wait_file_owner_push(cxfs_wait_file_duplicate, tcid);

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_file_wait: push %s to duplicated file '%s' in wait files tree done\n",
                            c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*register remote token owner to it*/
    cxfs_wait_file_owner_push(cxfs_wait_file, tcid);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_file_wait: push %s to inserted file %s in wait files tree done\n",
                        c_word_to_ipv4(tcid), (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL cxfs_file_wait(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_wait: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == cxfs_read(cxfs_md_id, file_path, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __cxfs_file_wait(cxfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_file_wait_ready(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *data_ready)
{
#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_wait_ready: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    return cxfs_file_wait(cxfs_md_id, tcid, file_path, NULL_PTR, data_ready);
}

EC_BOOL cxfs_file_wait_e(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, UINT32 *offset, const UINT32 max_len, CBYTES *cbytes, UINT32 *data_ready)
{
#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_wait: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    if(NULL_PTR != data_ready)
    {
        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/
        if(EC_OBSCURE != (*data_ready))
        {
            /*if data is already ready, return now*/
            if(EC_TRUE == cxfs_read_e(cxfs_md_id, file_path, offset, max_len, cbytes))
            {
                (*data_ready) = EC_TRUE;
                return (EC_TRUE);
            }
        }

        (*data_ready) = EC_FALSE;
    }

    if(EC_FALSE == __cxfs_file_wait(cxfs_md_id, tcid, file_path))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/*notify all waiters*/
EC_BOOL cxfs_file_notify(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
    CXFS_MD          *cxfs_md;

    CXFS_WAIT_FILE   *cxfs_wait_file;
    CXFS_WAIT_FILE   *cxfs_wait_file_found;
    CRB_NODE         *crb_node;
    UINT32            tag;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_notify: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfs_wait_file = cxfs_wait_file_new();
    if(NULL_PTR == cxfs_wait_file)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_notify: new cxfs_wait_file failed\n");
        return (EC_FALSE);
    }

    cxfs_wait_file_name_set(cxfs_wait_file, file_path);

    crb_node = crb_tree_search_data(CXFS_MD_WAIT_FILES(cxfs_md), (void *)cxfs_wait_file);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_notify: not found waiters of file '%s'\n",
                        (char *)CSTRING_STR(file_path));
        cxfs_wait_file_free(cxfs_wait_file);
        return (EC_TRUE);
    }

    cxfs_wait_file_free(cxfs_wait_file);

    cxfs_wait_file_found = CRB_NODE_DATA(crb_node);
    tag = MD_CXFS;

    if(EC_FALSE == cxfs_wait_file_owner_notify (cxfs_wait_file_found, tag))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_notify: notify waiters of file '%s' failed\n",
                        (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    crb_tree_delete(CXFS_MD_WAIT_FILES(cxfs_md), crb_node);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_notify: notify waiters of file '%s' done\n",
                    (char *)CSTRING_STR(file_path));
    return (EC_TRUE);
}

/*terminate all waiters*/
EC_BOOL cxfs_file_terminate(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
    CXFS_MD          *cxfs_md;

    CXFS_WAIT_FILE   *cxfs_wait_file;
    CXFS_WAIT_FILE   *cxfs_wait_file_found;
    CRB_NODE         *crb_node;
    UINT32            tag;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_terminate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfs_wait_file = cxfs_wait_file_new();
    if(NULL_PTR == cxfs_wait_file)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_terminate: new cxfs_wait_file failed\n");
        return (EC_FALSE);
    }

    cxfs_wait_file_name_set(cxfs_wait_file, file_path);

    crb_node = crb_tree_search_data(CXFS_MD_WAIT_FILES(cxfs_md), (void *)cxfs_wait_file);
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_terminate: not found waiters of file '%s'\n",
                        (char *)CSTRING_STR(file_path));
        cxfs_wait_file_free(cxfs_wait_file);
        return (EC_TRUE);
    }

    cxfs_wait_file_free(cxfs_wait_file);

    cxfs_wait_file_found = CRB_NODE_DATA(crb_node);
    tag = MD_CXFS;

    if(EC_FALSE == cxfs_wait_file_owner_terminate (cxfs_wait_file_found, tag))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_terminate: terminate waiters of file '%s' failed\n",
                        (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    crb_tree_delete(CXFS_MD_WAIT_FILES(cxfs_md), crb_node);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_terminate: terminate waiters of file '%s' done\n",
                    (char *)CSTRING_STR(file_path));
    return (EC_TRUE);
}

/*------------------------------------------------ interface for file lock ------------------------------------------------*/
CXFS_LOCKED_FILE *cxfs_locked_file_new()
{
    CXFS_LOCKED_FILE *cxfs_locked_file;
    alloc_static_mem(MM_CXFS_LOCKED_FILE, &cxfs_locked_file, LOC_CXFS_0013);
    if(NULL_PTR != cxfs_locked_file)
    {
        cxfs_locked_file_init(cxfs_locked_file);
    }
    return (cxfs_locked_file);
}

EC_BOOL cxfs_locked_file_init(CXFS_LOCKED_FILE *cxfs_locked_file)
{
    cstring_init(CXFS_LOCKED_FILE_NAME(cxfs_locked_file), NULL_PTR);
    cbytes_init(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file));

    CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_locked_file_clean(CXFS_LOCKED_FILE *cxfs_locked_file)
{
    cstring_clean(CXFS_LOCKED_FILE_NAME(cxfs_locked_file));
    cbytes_clean(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file));

    CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file) = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_locked_file_free(CXFS_LOCKED_FILE *cxfs_locked_file)
{
    if(NULL_PTR != cxfs_locked_file)
    {
        cxfs_locked_file_clean(cxfs_locked_file);
        free_static_mem(MM_CXFS_LOCKED_FILE, cxfs_locked_file, LOC_CXFS_0014);
    }
    return (EC_TRUE);
}

int cxfs_locked_file_cmp(const CXFS_LOCKED_FILE *cxfs_locked_file_1st, const CXFS_LOCKED_FILE *cxfs_locked_file_2nd)
{
    return cstring_cmp(CXFS_LOCKED_FILE_NAME(cxfs_locked_file_1st), CXFS_LOCKED_FILE_NAME(cxfs_locked_file_2nd));
}

void cxfs_locked_file_print(LOG *log, const CXFS_LOCKED_FILE *cxfs_locked_file)
{
    if(NULL_PTR != cxfs_locked_file)
    {
        sys_log(log, "cxfs_locked_file_print %p: file %s, expire %ld seconds\n",
                        cxfs_locked_file,
                        (char *)CXFS_LOCKED_FILE_NAME_STR(cxfs_locked_file),
                        CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file)
                        );
        sys_log(log, "cxfs_locked_file_print %p: file %s, token ",
                        cxfs_locked_file,
                        (char *)CXFS_LOCKED_FILE_NAME_STR(cxfs_locked_file)
                        );
        cbytes_print_chars(log, CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file));

        sys_log(log, "cxfs_locked_file_print %p: file %s\n",
                        cxfs_locked_file,
                        (char *)CXFS_LOCKED_FILE_NAME_STR(cxfs_locked_file)
                        );
    }

    return;
}

void cxfs_locked_files_print(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_locked_files_print: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    crb_tree_print(log, CXFS_MD_LOCKED_FILES(cxfs_md));

    return;
}

/*generate token from file_path with time as random*/
EC_BOOL cxfs_locked_file_token_gen(CXFS_LOCKED_FILE *cxfs_locked_file, const CSTRING *file_name)
{
    uint8_t  digest[ CMD5_DIGEST_LEN ];
    CSTRING  cstr;

    cstring_init(&cstr, cstring_get_str(file_name));

    cstring_append_str(&cstr, (const UINT8 *)TASK_BRD_TIME_STR(task_brd_default_get()));

    cmd5_sum(cstring_get_len(&cstr), cstring_get_str(&cstr), digest);
    cstring_clean(&cstr);

    cbytes_set(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file), (const UINT8 *)digest, CMD5_DIGEST_LEN);

    return (EC_TRUE);
}

EC_BOOL cxfs_locked_file_expire_set(CXFS_LOCKED_FILE *cxfs_locked_file, const UINT32 expire_nsec)
{
    CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file) = expire_nsec;

    CTIMET_GET(CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file));
    CTIMET_GET(CXFS_LOCKED_FILE_LAST_TIME(cxfs_locked_file));

    return (EC_TRUE);
}

EC_BOOL cxfs_locked_file_is_expire(const CXFS_LOCKED_FILE *cxfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CXFS_LOCKED_FILE_LAST_TIME(cxfs_locked_file), cur_time);
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_locked_file_is_expire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file));
    if(diff_nsec >= 0.0 + CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

EC_BOOL cxfs_locked_file_name_set(CXFS_LOCKED_FILE *cxfs_locked_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CXFS_LOCKED_FILE_NAME(cxfs_locked_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_locked_file_need_retire(const CXFS_LOCKED_FILE *cxfs_locked_file)
{
    CTIMET cur_time;
    REAL diff_nsec;

    CTIMET_GET(cur_time);

    diff_nsec = CTIMET_DIFF(CXFS_LOCKED_FILE_LAST_TIME(cxfs_locked_file), cur_time);
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_locked_file_need_retire: diff_nsec %.2f, timeout_nsec %ld\n",
                        diff_nsec, CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file));
    if(diff_nsec >= 0.0 + 2 * CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfs_locked_file_retire(CRB_TREE *crbtree, CRB_NODE *node)
{
    CXFS_LOCKED_FILE *cxfs_locked_file;

    if(NULL_PTR == node)
    {
        return (EC_FALSE);
    }

    cxfs_locked_file = CRB_NODE_DATA(node);
    if(EC_TRUE == __cxfs_locked_file_need_retire(cxfs_locked_file))
    {
        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_locked_file_retire: file %s was retired\n",
                            (char *)cstring_get_str(CXFS_LOCKED_FILE_NAME(cxfs_locked_file)));

        crb_tree_delete(crbtree, node);
        return (EC_TRUE);/*succ and terminate*/
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_TRUE == __cxfs_locked_file_retire(crbtree, CRB_NODE_LEFT(node)))
        {
            return (EC_TRUE);
        }
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_TRUE == __cxfs_locked_file_retire(crbtree, CRB_NODE_RIGHT(node)))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*retire the expired locked files over 120 seconds which are garbage*/
EC_BOOL cxfs_locked_file_retire(const UINT32 cxfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num)
{
    CXFS_MD      *cxfs_md;
    CRB_TREE     *crbtree;
    UINT32        retire_idx;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_locked_file_retire: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    crbtree = CXFS_MD_LOCKED_FILES(cxfs_md);

    for(retire_idx = 0; retire_idx < retire_max_num; retire_idx ++)
    {
        if(EC_FALSE == __cxfs_locked_file_retire(crbtree, CRB_TREE_ROOT(crbtree)))
        {
            break;/*no more to retire, terminate*/
        }
    }

    if(NULL_PTR != retire_num)
    {
        (*retire_num) = retire_idx;
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_file_lock(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CBYTES *token, UINT32 *locked_already)
{
    CXFS_MD          *cxfs_md;

    CRB_NODE         *crb_node;
    CXFS_LOCKED_FILE *cxfs_locked_file;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    (*locked_already) = EC_FALSE; /*init*/

    cxfs_locked_file = cxfs_locked_file_new();
    if(NULL_PTR == cxfs_locked_file)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_lock: new cxfs_locked_file failed\n");
        return (EC_FALSE);
    }

    cxfs_locked_file_name_set(cxfs_locked_file, file_path);
    cxfs_locked_file_token_gen(cxfs_locked_file, file_path);/*generate token from file_path with time as random*/
    cxfs_locked_file_expire_set(cxfs_locked_file, expire_nsec);

    crb_node = crb_tree_insert_data(CXFS_MD_LOCKED_FILES(cxfs_md), (void *)cxfs_locked_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_lock: insert file %s to locked files tree failed\n",
                                (char *)cstring_get_str(file_path));
        cxfs_locked_file_free(cxfs_locked_file);
        return (EC_FALSE);
    }

    if(CRB_NODE_DATA(crb_node) != cxfs_locked_file)/*found duplicate*/
    {
        CXFS_LOCKED_FILE *cxfs_locked_file_duplicate;

        cxfs_locked_file_duplicate = (CXFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node);

        if(EC_FALSE == cxfs_locked_file_is_expire(cxfs_locked_file_duplicate))
        {
            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_file_lock: file %s already in locked files tree\n",
                                (char *)cstring_get_str(file_path));

            cxfs_locked_file_free(cxfs_locked_file); /*no useful*/

            (*locked_already) = EC_TRUE;/*means file had been locked by someone else*/
            return (EC_FALSE);
        }

        CRB_NODE_DATA(crb_node) = cxfs_locked_file; /*mount new*/

        cxfs_locked_file_free(cxfs_locked_file_duplicate); /*free the duplicate which is also old*/

        cbytes_clone(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file), token);

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_file_lock: update file %s to locked files tree done\n",
                            (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*now cxfs_locked_file_tmp already insert and mount into tree*/
    cbytes_clone(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file), token);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_file_lock: insert file %s to locked files tree done\n",
                        (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL cxfs_file_lock(const UINT32 cxfs_md_id, const UINT32 tcid, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already)
{
    //CXFS_MD      *cxfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cbytes_init(&token_cbyte);

    if(EC_FALSE == __cxfs_file_lock(cxfs_md_id, tcid, file_path, expire_nsec, &token_cbyte, locked_already))
    {
        return (EC_FALSE);
    }

    cbase64_encode(CBYTES_BUF(&token_cbyte), CBYTES_LEN(&token_cbyte), auth_token, sizeof(auth_token), &auth_token_len);
    cstring_append_chars(token_str, auth_token_len, auth_token, LOC_CXFS_0015);
    cbytes_clean(&token_cbyte);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_file_unlock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *token)
{
    CXFS_MD          *cxfs_md;

    CRB_NODE         *crb_node_searched;

    CXFS_LOCKED_FILE *cxfs_locked_file_tmp;
    CXFS_LOCKED_FILE *cxfs_locked_file_searched;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfs_locked_file_tmp = cxfs_locked_file_new();
    if(NULL_PTR == cxfs_locked_file_tmp)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_unlock: new CXFS_LOCKED_FILE failed\n");
        return (EC_FALSE);
    }

    cxfs_locked_file_name_set(cxfs_locked_file_tmp, file_path);

    crb_node_searched = crb_tree_search_data(CXFS_MD_LOCKED_FILES(cxfs_md), (void *)cxfs_locked_file_tmp);/*compare name*/
    if(NULL_PTR == crb_node_searched)
    {
        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_file_unlock: file %s not in locked files tree\n",
                                (char *)cstring_get_str(file_path));
        cxfs_locked_file_free(cxfs_locked_file_tmp);
        return (EC_FALSE);
    }

    cxfs_locked_file_free(cxfs_locked_file_tmp); /*no useful*/

    cxfs_locked_file_searched = (CXFS_LOCKED_FILE *)CRB_NODE_DATA(crb_node_searched);

    /*if expired already, remove it as garbage, despite of token comparsion*/
    if(EC_TRUE == cxfs_locked_file_is_expire(cxfs_locked_file_searched))
    {
        crb_tree_delete(CXFS_MD_LOCKED_FILES(cxfs_md), crb_node_searched);
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "info:__cxfs_file_unlock: remove expired locked file %s\n",
                        (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    /*if exist, compare token. if not exist, unlock by force!*/
    if(NULL_PTR != token && EC_FALSE == cbytes_cmp(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file_searched), token))
    {
        if(do_log(SEC_0192_CXFS, 9))
        {
            sys_log(LOGSTDOUT, "warn:__cxfs_file_unlock: file %s, searched token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file_searched));

            sys_log(LOGSTDOUT, "warn:__cxfs_file_unlock: file %s, but input token is ", (char *)cstring_get_str(file_path));
            cbytes_print_chars(LOGSTDOUT, token);
        }
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 5))
    {
        sys_log(LOGSTDOUT, "[DEBUG] __cxfs_file_unlock: file %s notify ...\n",
                                (char *)cstring_get_str(file_path));

        sys_log(LOGSTDOUT, "[DEBUG] __cxfs_file_unlock: searched file:\n");
        cxfs_locked_file_print(LOGSTDOUT, cxfs_locked_file_searched);
    }

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_file_unlock: file %s notify ... done\n",
                            (char *)cstring_get_str(file_path));

    crb_tree_delete(CXFS_MD_LOCKED_FILES(cxfs_md), crb_node_searched);

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_file_unlock: file %s unlocked\n",
                            (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL cxfs_file_unlock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CSTRING *token_str)
{
    //CXFS_MD      *cxfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_unlock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cbase64_decode((UINT8 *)CSTRING_STR(token_str), CSTRING_LEN(token_str), auth_token, sizeof(auth_token), &auth_token_len);
    cbytes_mount(&token_cbyte, auth_token_len, auth_token);
#if 0
    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_file_unlock: auth_token str: %.*s\n", (uint32_t)CSTRING_LEN(token_str), CSTRING_STR(token_str));
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_file_unlock: auth_token str => token: ");
        cbytes_print_chars(LOGSTDOUT, &token_cbyte);

        sys_log(LOGSTDOUT, "[DEBUG] cxfs_file_unlock: all locked files are: \n");
        cxfs_locked_files_print(cxfs_md_id, LOGSTDOUT);
    }
#endif
    if(EC_FALSE == __cxfs_file_unlock(cxfs_md_id, file_path, &token_cbyte))
    {
        cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
        return (EC_FALSE);
    }

    cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR);
    return (EC_TRUE);
}


/**
*
*  try to notify owners of a locked-file without any authentication token
*  Note: just wakeup owners but not remove the locked-file
*
**/
EC_BOOL cxfs_file_unlock_notify(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
    //CXFS_MD      *cxfs_md;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_unlock_notify: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_unlock_notify: obsolete interface!!!!\n");

    return (EC_FALSE);
}

/*------------------------------------------------ interface for replay ------------------------------------------------*/
EC_BOOL cxfs_set_op_replay(CXFS_MD *cxfs_md)
{
    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_set_op_replay: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        cxfsnp_mgr_set_op_replay(CXFS_MD_NPP(cxfs_md));
    }

    CXFS_MD_OP_REPLAY_FLAG(cxfs_md) = BIT_TRUE;

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_set_op_replay: "
                                         "xfs set op-replay done\n");
    return (EC_TRUE);
}

EC_BOOL cxfs_unset_op_replay(CXFS_MD *cxfs_md)
{
    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_unset_op_replay: "
                                             "xfs is not in op-replay mode\n");
        return (EC_FALSE);
    }

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        cxfsnp_mgr_unset_op_replay(CXFS_MD_NPP(cxfs_md));
    }

    CXFS_MD_OP_REPLAY_FLAG(cxfs_md) = BIT_FALSE;

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_unset_op_replay: "
                                         "xfs unset op-replay done\n");
    return (EC_TRUE);
}

EC_BOOL cxfs_is_op_replay(CXFS_MD *cxfs_md)
{
    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        return (EC_TRUE);
    }

    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_add_dir(const UINT32 cxfs_md_id, CXFSOP_NP_HDR *cxfsop_np_hdr)
{
    CSTRING          path;

    cstring_init(&path, NULL_PTR);
    cstring_set_chars(&path, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr), CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr));

    /*mkdir*/
    if(EC_FALSE == cxfs_mkdir(cxfs_md_id, &path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_add_dir: "
                     "[D][%s] time %lu, wildcard %u, klen %u, key %.*s => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                     CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

        cstring_clean(&path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_add_dir: "
                 "[D][%s] time %lu, wildcard %u, klen %u, key %.*s => replay done\n",
                 cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                 CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

    cstring_clean(&path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_del_dir(const UINT32 cxfs_md_id, CXFSOP_NP_HDR *cxfsop_np_hdr)
{
    CSTRING          path;

    cstring_init(&path, NULL_PTR);
    cstring_set_chars(&path, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr), CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr));

    /*rm dir*/
    if(EC_FALSE == cxfs_delete_dir(cxfs_md_id, &path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_del_dir: "
                     "[D][%s] time %lu, wildcard %u, klen %u, key %.*s => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                     CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

        cstring_clean(&path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_del_dir: "
                 "[D][%s] time %lu, wildcard %u, klen %u, key %.*s => replay done\n",
                 cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                 CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

    cstring_clean(&path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_del_wildcard_dir(const UINT32 cxfs_md_id, CXFSOP_NP_HDR *cxfsop_np_hdr)
{
    CSTRING          path;

    cstring_init(&path, NULL_PTR);
    cstring_set_chars(&path, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr), CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr));

    /*rm dir with wildcard*/
    if(EC_FALSE == cxfs_delete_dir_wildcard(cxfs_md_id, &path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_del_wildcard_dir: "
                     "[D][%s] time %lu, wildcard %u, klen %u, key %.*s => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                     CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

        cstring_clean(&path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_del_wildcard_dir: "
                 "[D][%s] time %lu, wildcard %u, klen %u, key %.*s => replay done\n",
                 cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                 CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

    cstring_clean(&path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_add_file(const UINT32 cxfs_md_id, CXFSOP_NP_HDR *cxfsop_np_hdr, CXFSOP_NP_FNODE *cxfsop_np_fnode)
{
    CSTRING          path;
    CXFSNP_FNODE    *cxfsnp_fnode;
    CXFSNP_INODE    *cxfsnp_inode;

    cstring_init(&path, NULL_PTR);
    cstring_set_chars(&path, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr), CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr));

    /*write file*/

    cxfsnp_fnode = __cxfs_reserve_npp(cxfs_md_id, &path);
    if(NULL_PTR == cxfsnp_fnode)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_add_file: "
                         "[F][%s] time %lu, wildcard %u, klen %u, key %.*s, "
                         "(disk %u, block %u, page %u, size %u) => replay failed\n",
                         cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                         CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                         CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                         CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                         CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr),
                         CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode),
                         CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode),
                         CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode),
                         CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode));

        cstring_clean(&path);
        return (EC_FALSE);
    }

    CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode);
    CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 1;

    cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
    CXFSNP_INODE_DISK_NO(cxfsnp_inode)  = CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode);
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode) = CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode);
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)  = CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode);

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_add_file: "
                     "[F][%s] time %lu, wildcard %u, klen %u, key %.*s, "
                     "(disk %u, block %u, page %u, size %u) => replay done\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                     CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr),
                     CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode),
                     CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode),
                     CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode),
                     CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode));

    cstring_clean(&path);
    return (EC_TRUE);

}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_del_file(const UINT32 cxfs_md_id, CXFSOP_NP_HDR *cxfsop_np_hdr, CXFSOP_NP_FNODE *cxfsop_np_fnode)
{
    CSTRING          path;

    cstring_init(&path, NULL_PTR);
    cstring_set_chars(&path, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr), CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr));

    /*rm file*/
    if(EC_FALSE == cxfs_delete_file(cxfs_md_id, &path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_del_file: "
                    "[F][%s] time %lu, wildcard %u, klen %u, key %.*s => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                     CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

        cstring_clean(&path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_del_file: "
                "[F][%s] time %lu, wildcard %u, klen %u, key %.*s => replay done\n",
                 cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                 CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

    cstring_clean(&path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_del_wildcard_file(const UINT32 cxfs_md_id, CXFSOP_NP_HDR *cxfsop_np_hdr, CXFSOP_NP_FNODE *cxfsop_np_fnode)
{
    CSTRING          path;

    cstring_init(&path, NULL_PTR);
    cstring_set_chars(&path, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr), CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr));

    /*rm file with wildcard*/
    if(EC_FALSE == cxfs_delete_file_wildcard(cxfs_md_id, &path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_del_wildcard_file: "
                    "[F][%s] time %lu, wildcard %u, klen %u, key %.*s => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                     CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

        cstring_clean(&path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_del_wildcard_file: "
                "[F][%s] time %lu, wildcard %u, klen %u, key %.*s => replay done\n",
                 cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                 CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                 CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr));

    cstring_clean(&path);
    return (EC_TRUE);}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_update_file(const UINT32 cxfs_md_id, CXFSOP_NP_HDR *cxfsop_np_hdr, CXFSOP_NP_FNODE *cxfsop_np_fnode)
{
    CXFSNP_FNODE     cxfsnp_fnode;
    CXFSNP_INODE    *cxfsnp_inode;
    CSTRING          path;

    cstring_init(&path, NULL_PTR);
    cstring_set_chars(&path, CXFSOP_NP_HDR_KEY(cxfsop_np_hdr), CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr));

    /*update file*/

    CXFSNP_FNODE_FILESZ(&cxfsnp_fnode) = CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode);
    CXFSNP_FNODE_REPNUM(&cxfsnp_fnode) = 1;

    cxfsnp_inode = CXFSNP_FNODE_INODE(&cxfsnp_fnode, 0);
    CXFSNP_INODE_DISK_NO(cxfsnp_inode)  = CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode);
    CXFSNP_INODE_BLOCK_NO(cxfsnp_inode) = CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode);
    CXFSNP_INODE_PAGE_NO(cxfsnp_inode)  = CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode);

    if(EC_FALSE == cxfs_update_npp(cxfs_md_id, &path, &cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_update_file: "
                         "[F][%s] time %lu, wildcard %u, klen %u, key %.*s, "
                         "(disk %u, block %u, page %u, size %u) => replay failed\n",
                         cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                         CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                         CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                         CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                         CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr),
                         CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode),
                         CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode),
                         CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode),
                         CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode));

        cstring_clean(&path);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_update_file: "
                     "[F][%s] time %lu, wildcard %u, klen %u, key %.*s, "
                     "(disk %u, block %u, page %u, size %u) => replay done\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_HDR_OP(cxfsop_np_hdr)),
                     CXFSOP_NP_HDR_TIME(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr),
                     CXFSOP_NP_HDR_KLEN(cxfsop_np_hdr), (char *)CXFSOP_NP_HDR_KEY(cxfsop_np_hdr),
                     CXFSOP_NP_FNODE_DISK_NO(cxfsop_np_fnode),
                     CXFSOP_NP_FNODE_BLOCK_NO(cxfsop_np_fnode),
                     CXFSOP_NP_FNODE_PAGE_NO(cxfsop_np_fnode),
                     CXFSOP_NP_FNODE_FILESZ(cxfsop_np_fnode));

    cstring_clean(&path);
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_item_retire(const UINT32 cxfs_md_id, CXFSOP_NP_ITEM *cxfsop_np_item)
{
    CXFS_MD         *cxfs_md;
    CXFSNP          *cxfsnp;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_retire: "
                                             "np npp\n");

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_retire: "
                     "[I][%s] time %lu, np %u, node %u => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                     CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));
        return (EC_FALSE);
    }

    cxfsnp = cxfsnp_mgr_open_np(CXFS_MD_NPP(cxfs_md), CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item));
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_retire: "
                                             "get np %u failed\n",
                                             CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item));

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_retire: "
                     "[I][%s] time %lu, np %u, node %u => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                     CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 3))
    {
        CXFSNP_ITEM     *cxfsnp_item;

        cxfsnp_item = cxfsnp_fetch(cxfsnp, CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));
        ASSERT(NULL_PTR != cxfsnp_item);
        ASSERT(EC_TRUE == cxfsnprb_node_is_used(CXFSNP_ITEMS_POOL(cxfsnp), CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item)));
        ASSERT(CXFSNP_ITEM_IS_USED == CXFSNP_ITEM_USED_FLAG(cxfsnp_item));
        ASSERT(CXFSNP_ITEM_FILE_IS_REG == CXFSNP_ITEM_DIR_FLAG(cxfsnp_item));
    }

    /*retire file*/
    if(EC_FALSE == cxfsnp_umount_item_deep(cxfsnp, CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_retire: "
                     "[I][%s] time %lu, np %u, node %u => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                     CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));

        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_item_retire: "
                 "[I][%s] time %lu, np %u, node %u => replay done\n",
                 cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                 CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                 CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                 CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_np_item_recycle(const UINT32 cxfs_md_id, CXFSOP_NP_ITEM *cxfsop_np_item)
{
    CXFS_MD             *cxfs_md;
    CXFSNP              *cxfsnp;
    CXFSNP_ITEM         *cxfsnp_item;
    CXFSNP_RECYCLE_DN    cxfsnp_recycle_dn;
    uint32_t             node_pos;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_recycle: "
                                             "np npp\n");

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_recycle: "
                     "[I][%s] time %lu, np %u, node %u => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                     CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));
        return (EC_FALSE);
    }

    cxfsnp = cxfsnp_mgr_open_np(CXFS_MD_NPP(cxfs_md), CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item));
    if(NULL_PTR == cxfsnp)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_recycle: "
                                             "get np %u failed\n",
                                             CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item));

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_recycle: "
                     "[I][%s] time %lu, np %u, node %u => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                     CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));
        return (EC_FALSE);
    }

    node_pos = CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item);
    cxfsnp_item = cxfsnp_fetch(cxfsnp, node_pos);

    ASSERT(CXFSNPRB_ERR_POS == CXFSNP_ITEM_PARENT_POS(cxfsnp_item));

    CXFSNP_RECYCLE_DN_ARG1(&cxfsnp_recycle_dn)   = cxfs_md_id;
    CXFSNP_RECYCLE_DN_FUNC(&cxfsnp_recycle_dn)   = cxfs_recycle_dn;

    if(EC_FALSE == cxfsnp_recycle_item(cxfsnp, cxfsnp_item, node_pos, NULL_PTR, &cxfsnp_recycle_dn))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_recycle: recycle item %u # failed\n", node_pos);

        /*should never reach here*/
        cxfsnpdel_node_rmv(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);

        cxfsnprb_node_free(CXFSNP_ITEMS_POOL(cxfsnp), node_pos);/*recycle rb node(item node)*/

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_np_item_recycle: "
                     "[I][%s] time %lu, np %u, node %u => replay failed\n",
                     cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                     CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                     CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));

        return (EC_FALSE);
    }

    cxfsnpdel_node_rmv(cxfsnp, CXFSNP_ITEM_DEL_NODE(cxfsnp_item), node_pos);

    cxfsnprb_node_free(CXFSNP_ITEMS_POOL(cxfsnp), node_pos);/*recycle rb node(item node)*/

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_np_item_recycle: "
                 "[I][%s] time %lu, np %u, node %u => replay done\n",
                 cxfsop_mgr_op_str(CXFSOP_NP_ITEM_OP(cxfsop_np_item)),
                 CXFSOP_NP_ITEM_TIME(cxfsop_np_item),
                 CXFSOP_NP_ITEM_NP_ID(cxfsop_np_item),
                 CXFSOP_NP_ITEM_NODE_POS(cxfsop_np_item));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_dn_reserve(const UINT32 cxfs_md_id, CXFSOP_DN_NODE *cxfsop_dn_node)
{
    CXFS_MD            *cxfs_md;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_reserve: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_reserve: data_len %ld overflow\n",
                                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_reserve: no dn was open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_reserve_space(CXFS_MD_DN(cxfs_md),
                                        CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_reserve: "
                                             "reserved (disk %u, block %u, page %u, size %u) failed\n",
                                             CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_dn_reserve: "
                                         "reserve (disk %u, block %u, page %u, size %u) => replay done\n",
                                         CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_dn_release(const UINT32 cxfs_md_id, CXFSOP_DN_NODE *cxfsop_dn_node)
{
    CXFS_MD            *cxfs_md;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_release: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_release: data_len %ld overflow\n",
                                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_release: no dn was open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_release_space(CXFS_MD_DN(cxfs_md),
                                        CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_release: "
                                             "release (disk %u, block %u, page %u, size %u) failed\n",
                                             CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_dn_release: "
                                         "release (disk %u, block %u, page %u, size %u) => replay done\n",
                                         CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op_dn_recycle(const UINT32 cxfs_md_id, CXFSOP_DN_NODE *cxfsop_dn_node)
{
    CXFS_MD            *cxfs_md;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_recycle: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE <= CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_recycle: data_len %ld overflow\n",
                                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_recycle: no dn was open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_release_space(CXFS_MD_DN(cxfs_md),
                                        CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                        CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_recycle: "
                                             "recycle (disk %u, block %u, page %u, size %u) failed\n",
                                             CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                             CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op_dn_recycle: "
                                         "recycle (disk %u, block %u, page %u, size %u) => replay done\n",
                                         CXFSOP_DN_NODE_DISK_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_BLOCK_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_PAGE_NO(cxfsop_dn_node),
                                         CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node));

    return (EC_TRUE);
}

/**
*
*  check operations and dump if necessary
*
**/
EC_BOOL cxfs_process_op(const UINT32 cxfs_md_id)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

    static uint64_t  time_msec_next = 0; /*init*/

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_process_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md);

    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && CXFS_OP_TABLE_USED_NBYTES_THREAD <= CXFS_MD_OP_DUMP_OFFSET(cxfs_md))
    {
        MOD_NODE      mod_node;

        task_brd_process_del(task_brd_default_get(),
                             (TASK_BRD_CALLBACK)cxfs_process_op,
                             (void *)cxfs_md_id);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_process_op: "
                                             "trigger sync\n");

        MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&mod_node) = cxfs_md_id;

        task_p2p_no_wait(cxfs_md_id, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                     &mod_node,
                     NULL_PTR,
                     FI_cxfs_sync, CMPI_ERROR_MODI);

        return (EC_TRUE);
    }

    if(BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)
    && NULL_PTR != cxfsop_mgr)
    {
        uint64_t         time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        if(0 == time_msec_next)
        {
            time_msec_next = time_msec_cur + CXFS_OP_DUMP_IDLE_NSEC_THREAD * 1000; /*60s later*/
        }

        if(CXFS_OP_DUMP_USED_RATIO_THREAD < cxfsop_mgr_used_ratio(cxfsop_mgr) /*used ratio reach thread*/
        || (0 < cxfsop_mgr_used(cxfsop_mgr) && time_msec_cur >= time_msec_next))/*idle elapsed reach thread*/
        {
            MOD_NODE      mod_node;

            MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
            MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
            MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
            MOD_NODE_MODI(&mod_node) = cxfs_md_id;

            task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &mod_node,
                         NULL_PTR,
                         FI_cxfs_dump_op, CMPI_ERROR_MODI);

            time_msec_next = time_msec_cur + CXFS_OP_DUMP_IDLE_NSEC_THREAD * 1000; /*60s later*/
        }
    }

    return (EC_TRUE);
}

/**
*
*  dump operations
*
**/
EC_BOOL cxfs_dump_op(const UINT32 cxfs_md_id)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md); /*save old*/

    if(BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)
    && NULL_PTR != cxfsop_mgr)
    {
        CXFSCFG         *cxfscfg;
        UINT32           op_offset;     /*absolute offset in disk*/

        uint64_t         s_op_offset;   /*relative offset in op table*/
        uint64_t         e_op_offset;   /*relative offset in op table*/
        uint32_t         dump_retries;

        CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_TRUE; /*set flag as barrier*/

        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_create(CXFS_OP_MCACHE_SIZE_NBYTES);
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_op: "
                                                 "[new] create op mcache failed\n");

            CXFS_MD_OP_MGR(cxfs_md)       = cxfsop_mgr; /*restore*/
            CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_FALSE;  /*restore*/
            return (EC_FALSE);
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md)
        && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
        {
            cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)));
            dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                                 "[new] mount camd to op mgr done\n");
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md)
        && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
        {
            cxfsnp_mgr_umount_op_mgr(CXFS_MD_NPP(cxfs_md));
            cxfsnp_mgr_mount_op_mgr(CXFS_MD_NPP(cxfs_md), CXFS_MD_OP_MGR(cxfs_md));
        }

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                             "[new] create op mcache done\n");

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: start\n");

        cxfscfg = CXFS_MD_CFG(cxfs_md);

        /*absolute offset in disk*/
        op_offset = (UINT32)(CXFSCFG_OP_S_OFFSET(cxfscfg) + CXFS_MD_OP_DUMP_OFFSET(cxfs_md));

        /*relative offset in op table*/
        s_op_offset = (CXFS_MD_OP_DUMP_OFFSET(cxfs_md));
        e_op_offset = (s_op_offset + cxfsop_mgr_used(cxfsop_mgr));

        ASSERT(e_op_offset < CXFS_OP_TABLE_SIZE_NBYTES); /*should never reach the end of op table*/

        dump_retries = 0;
        while(EC_FALSE == cxfsop_mgr_dump(cxfsop_mgr, &op_offset))
        {
            dump_retries ++;

            if(10 <= dump_retries) /*exception last for 300s*/
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "fatal error:cxfs_dump_op: "
                                                     "dump op to disk failed "
                                                     "=> stop xfs now and sync data to disk\n");

                /*stop recording op by free op mgr of cxfs module*/
                cxfsop_mgr_free(CXFS_MD_OP_MGR(cxfs_md));
                CXFS_MD_OP_MGR(cxfs_md) = NULL_PTR;

                cxfsop_mgr_free(cxfsop_mgr);

                CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_FALSE;    /*restore*/

                cxfs_end(cxfs_md_id); /*stop xfs*/

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "fatal error:cxfs_dump_op: "
                                                 "dump op to disk failed %u times "
                                                 "=> retry\n",
                                                 dump_retries);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                             "op dump offset %ld => %ld\n",
                                             CXFS_MD_OP_DUMP_OFFSET(cxfs_md),
                                             op_offset - CXFSCFG_OP_S_OFFSET(cxfscfg));

        CXFS_MD_OP_DUMP_OFFSET(cxfs_md) = op_offset - CXFSCFG_OP_S_OFFSET(cxfscfg); /*update dump offset*/

        cxfsop_mgr_free(cxfsop_mgr);

        CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_FALSE;    /*restore*/

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: done\n");
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_replay_op(const UINT32 cxfs_md_id, void *start, void *end,
                                                uint64_t *c_op_time_msec, const uint64_t e_op_time_msec)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;
    void            *cur;

    uint64_t         cur_time_msec;

    ASSERT(start < end);

    cxfs_md    = CXFS_MD_GET(cxfs_md_id);
    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md);
    cur        = start;

    cur_time_msec  = c_get_cur_time_msec();

    while(NULL_PTR != cur && cur < end)
    {
        CXFSOP_COMM_HDR    *cxfsop_comm_hdr;

        cxfsop_comm_hdr = (CXFSOP_COMM_HDR *)cur;

        if(0 == CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr)
        && 0 == CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            cur = cxfsop_mgr_search(cxfsop_mgr, cur, CXFSOP_SEARCH_MAX_LEN);
            continue;
        }

        /*invalid magic num*/
        if(CXFSOP_MAGIC_NUM != CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:__cxfs_replay_op: "
                                                 "invalid magic num %lx\n",
                                                 CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr));
            cur = cxfsop_mgr_search(cxfsop_mgr, cur, CXFSOP_SEARCH_MAX_LEN);
            continue;
        }

        /*no create time*/
        if(0 == CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:__cxfs_replay_op: "
                                                 "no create time\n");
            cur = cxfsop_mgr_search(cxfsop_mgr, cur, CXFSOP_SEARCH_MAX_LEN);
            continue;
        }

        /*invalid create time*/
        if(cur_time_msec <= CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:__cxfs_replay_op: "
                                                 "create time %lu (%s) >= cur time %lu (%s) => terminate\n",
                                                 CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                                                 c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                                                 cur_time_msec,
                                                 c_get_time_msec_str(cur_time_msec));
            break; /*return (EC_FALSE);*/
        }

        if((*c_op_time_msec) > CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "info:__cxfs_replay_op: "
                                                 "create time %lu (%s) < prev op time %lu (%s) => terminate\n",
                                                 CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                                                 c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                                                 (*c_op_time_msec),
                                                 c_get_time_msec_str((*c_op_time_msec)));
            break;
        }

        if(e_op_time_msec < CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "info:__cxfs_replay_op: "
                                                 "create time %lu (%s) > end time %lu (%s) => terminate\n",
                                                 CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                                                 c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                                                 e_op_time_msec,
                                                 c_get_time_msec_str(e_op_time_msec));
            break;
        }

        (*c_op_time_msec) = CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr); /*update*/

        cur += CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr);

        if(CXFSOP_NP_F_ADD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_NP_HDR   *cxfsop_np_hdr;
            CXFSOP_NP_FNODE *cxfsop_np_fnode;

            cxfsop_np_hdr   = (CXFSOP_NP_HDR   *)cxfsop_comm_hdr;
            cxfsop_np_fnode = (CXFSOP_NP_FNODE *)(cur - sizeof(CXFSOP_NP_FNODE));

            if(EC_FALSE == __cxfs_replay_op_np_add_file(cxfs_md_id, cxfsop_np_hdr, cxfsop_np_fnode))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_NP_F_DEL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_NP_HDR   *cxfsop_np_hdr;
            CXFSOP_NP_FNODE *cxfsop_np_fnode;

            cxfsop_np_hdr   = (CXFSOP_NP_HDR   *)cxfsop_comm_hdr;
            cxfsop_np_fnode = (CXFSOP_NP_FNODE *)(cur - sizeof(CXFSOP_NP_FNODE));

            if(BIT_FALSE == CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr))
            {
                if(EC_FALSE == __cxfs_replay_op_np_del_file(cxfs_md_id, cxfsop_np_hdr, cxfsop_np_fnode))
                {
                    /*return (EC_FALSE);*/
                    break;/*terminate*/
                }
            }
            else
            {
                if(EC_FALSE == __cxfs_replay_op_np_del_wildcard_file(cxfs_md_id, cxfsop_np_hdr, cxfsop_np_fnode))
                {
                    /*return (EC_FALSE);*/
                    break;/*terminate*/
                }
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_NP_F_UPD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_NP_HDR   *cxfsop_np_hdr;
            CXFSOP_NP_FNODE *cxfsop_np_fnode;

            cxfsop_np_hdr   = (CXFSOP_NP_HDR   *)cxfsop_comm_hdr;
            cxfsop_np_fnode = (CXFSOP_NP_FNODE *)(cur - sizeof(CXFSOP_NP_FNODE));

            if(EC_FALSE == __cxfs_replay_op_np_update_file(cxfs_md_id, cxfsop_np_hdr, cxfsop_np_fnode))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_NP_D_ADD_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_NP_HDR   *cxfsop_np_hdr;

            cxfsop_np_hdr   = (CXFSOP_NP_HDR   *)cxfsop_comm_hdr;

            if(EC_FALSE == __cxfs_replay_op_np_add_dir(cxfs_md_id, cxfsop_np_hdr))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_NP_D_DEL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_NP_HDR   *cxfsop_np_hdr;

            cxfsop_np_hdr   = (CXFSOP_NP_HDR   *)cxfsop_comm_hdr;

            if(BIT_FALSE == CXFSOP_NP_HDR_WILDCARD(cxfsop_np_hdr))
            {
                if(EC_FALSE == __cxfs_replay_op_np_del_dir(cxfs_md_id, cxfsop_np_hdr))
                {
                    /*return (EC_FALSE);*/
                    break;/*terminate*/
                }
            }
            else
            {
                if(EC_FALSE == __cxfs_replay_op_np_del_wildcard_dir(cxfs_md_id, cxfsop_np_hdr))
                {
                    /*return (EC_FALSE);*/
                    break;/*terminate*/
                }
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_NP_I_RET_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_NP_ITEM   *cxfsop_np_item;

            cxfsop_np_item = (CXFSOP_NP_ITEM *)cxfsop_comm_hdr;

            if(EC_FALSE == __cxfs_replay_op_np_item_retire(cxfs_md_id, cxfsop_np_item))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_NP_I_REC_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_NP_ITEM   *cxfsop_np_item;

            cxfsop_np_item = (CXFSOP_NP_ITEM *)cxfsop_comm_hdr;

            if(EC_FALSE == __cxfs_replay_op_np_item_recycle(cxfs_md_id, cxfsop_np_item))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_DN_RSV_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_DN_NODE      *cxfsop_dn_node;

            cxfsop_dn_node = (CXFSOP_DN_NODE *)cxfsop_comm_hdr;

            if(EC_FALSE == __cxfs_replay_op_dn_reserve(cxfs_md_id, cxfsop_dn_node))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_DN_REL_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_DN_NODE      *cxfsop_dn_node;

            cxfsop_dn_node = (CXFSOP_DN_NODE *)cxfsop_comm_hdr;

            if(EC_FALSE == __cxfs_replay_op_dn_release(cxfs_md_id, cxfsop_dn_node))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }

        if(CXFSOP_DN_REC_OP == CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr))
        {
            CXFSOP_DN_NODE      *cxfsop_dn_node;

            cxfsop_dn_node = (CXFSOP_DN_NODE *)cxfsop_comm_hdr;

            if(EC_FALSE == __cxfs_replay_op_dn_recycle(cxfs_md_id, cxfsop_dn_node))
            {
                /*return (EC_FALSE);*/
                break;/*terminate*/
            }

            dbg_log(SEC_0192_CXFS, 2)(LOGSTDOUT, "[DEBUG] __cxfs_replay_op: "
                               "offset %ld, time %lu (%s), magic %x, "
                               "op %u, size %u => OK\n",
                               (UINT32)((void *)cxfsop_comm_hdr - CXFSOP_MGR_DATA(cxfsop_mgr)),
                               CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr),
                               c_get_time_msec_str(CXFSOP_COMM_HDR_TIME(cxfsop_comm_hdr)),
                               CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr),
                               CXFSOP_COMM_HDR_SIZE(cxfsop_comm_hdr));
            continue;
        }        


        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op: invalid op %u\n",
                                             CXFSOP_COMM_HDR_OP(cxfsop_comm_hdr));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

/**
*
*  replay operations
*
**/
EC_BOOL cxfs_replay_op(const UINT32 cxfs_md_id)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

    uint64_t         s_op_offset;
    uint64_t         e_op_offset;
    uint64_t         s_op_time_msec;
    uint64_t         e_op_time_msec;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_replay_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md    = CXFS_MD_GET(cxfs_md_id);
    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md);

    if(NULL_PTR == cxfsop_mgr)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_replay_op: op mgr is null\n");
        return (EC_FALSE);
    }

    if(EC_TRUE == cxfs_is_op_replay(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_replay_op: replay is on-going\n");
        return (EC_FALSE);
    }

    s_op_time_msec = CXFSCFG_OP_DUMP_TIME_MSEC(CXFS_MD_CFG(cxfs_md));
    e_op_time_msec = c_get_cur_time_msec();

    if(EC_FALSE == cxfsop_mgr_scan(cxfsop_mgr,
                                   &s_op_offset,
                                   &e_op_offset,
                                   &s_op_time_msec,
                                   &e_op_time_msec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_replay_op: scan op mgr failed\n");
        return (EC_FALSE);
    }

    if(s_op_offset >= e_op_offset)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_replay_op: nothing to replay => done\n");
        return (EC_TRUE);
    }

    cxfs_set_op_replay(cxfs_md);

    if(s_op_offset < e_op_offset)
    {
        void            *start;
        void            *end;
        uint64_t         c_op_time_msec;

        c_op_time_msec = s_op_time_msec;

        start = CXFSOP_MGR_DATA(cxfsop_mgr);
        end   = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);

        if(EC_FALSE == __cxfs_replay_op(cxfs_md_id, start, end, &c_op_time_msec, e_op_time_msec))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_replay_op: "
                                                 "replay range [%ld, %ld), time [%lu, %lu) failed\n",
                                                 start - CXFSOP_MGR_DATA(cxfsop_mgr),
                                                 end   - CXFSOP_MGR_DATA(cxfsop_mgr),
                                                 s_op_time_msec,
                                                 e_op_time_msec);

            cxfs_unset_op_replay(cxfs_md);
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_replay_op: "
                                             "replay range [%ld, %ld), time [%lu, %lu) done\n",
                                             start - CXFSOP_MGR_DATA(cxfsop_mgr),
                                             end   - CXFSOP_MGR_DATA(cxfsop_mgr),
                                             s_op_time_msec,
                                             e_op_time_msec);
    }

    else
    {
        void            *start;
        void            *end;
        uint64_t         c_op_time_msec;

        c_op_time_msec = s_op_time_msec;

        start = CXFSOP_MGR_DATA(cxfsop_mgr) + s_op_offset;
        end   = CXFSOP_MGR_DATA(cxfsop_mgr) + CXFSOP_MGR_USED(cxfsop_mgr);

        if(EC_FALSE == __cxfs_replay_op(cxfs_md_id, start, end, &c_op_time_msec, e_op_time_msec))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_replay_op: "
                                                 "replay range [%ld, %ld), time [%lu, %lu) failed\n",
                                                 start - CXFSOP_MGR_DATA(cxfsop_mgr),
                                                 end   - CXFSOP_MGR_DATA(cxfsop_mgr),
                                                 s_op_time_msec,
                                                 e_op_time_msec);

            cxfs_unset_op_replay(cxfs_md);
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_replay_op: "
                                             "replay range [%ld, %ld), time [%lu, %lu) done\n",
                                             start - CXFSOP_MGR_DATA(cxfsop_mgr),
                                             end   - CXFSOP_MGR_DATA(cxfsop_mgr),
                                             s_op_time_msec,
                                             e_op_time_msec);

        start = CXFSOP_MGR_DATA(cxfsop_mgr) + 0;
        end   = CXFSOP_MGR_DATA(cxfsop_mgr) + e_op_offset;

        if(EC_FALSE == __cxfs_replay_op(cxfs_md_id, start, end, &c_op_time_msec, e_op_time_msec))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_replay_op: "
                                                 "replay range [%ld, %ld), time [%lu, %lu) failed\n",
                                                 start - CXFSOP_MGR_DATA(cxfsop_mgr),
                                                 end   - CXFSOP_MGR_DATA(cxfsop_mgr),
                                                 s_op_time_msec,
                                                 e_op_time_msec);

            cxfs_unset_op_replay(cxfs_md);
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_replay_op: "
                                             "replay range [%ld, %ld), time [%lu, %lu) done\n",
                                             start - CXFSOP_MGR_DATA(cxfsop_mgr),
                                             end   - CXFSOP_MGR_DATA(cxfsop_mgr),
                                             s_op_time_msec,
                                             e_op_time_msec);

    }

    cxfs_unset_op_replay(cxfs_md);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_replay_op: done\n");
    return (EC_TRUE);
}

/**
*
*  pop operation (for debug only)
*
**/
EC_BOOL cxfs_pop_op(const UINT32 cxfs_md_id, const UINT32 op_size)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

#if ( SWITCH_ON == CXFS_DEBUG_SWITCH )
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_pop_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*CXFS_DEBUG_SWITCH*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md);

    if(NULL_PTR == cxfsop_mgr)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_pop_op: op mgr is null\n");
        return (EC_FALSE);
    }

    if(CXFSOP_MGR_USED(cxfsop_mgr) < op_size)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_pop_op: op used %lu < pop expected size %lu\n",
                                             CXFSOP_MGR_USED(cxfsop_mgr), op_size);
        return (EC_FALSE);
    }

    CXFSOP_MGR_USED(cxfsop_mgr) -= op_size;
    return (EC_TRUE);
}

/*------------------------------------------------ interface for liburl ------------------------------------------------*/
STATIC_CAST static EC_BOOL __cxfs_open_url_list_file(const char *fname, char **fmem, UINT32 *fsize, int *fd)
{
    char *cur_fmem;
    int   cur_fd;
    UINT32 cur_fsize;

    cur_fd = c_file_open(fname, O_RDONLY, 0666);
    if(ERR_FD == cur_fd)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_open_url_list_file: open url list file %s failed\n", fname);
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_size(cur_fd, &cur_fsize))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_open_url_list_file: get size of url list file %s failed\n", fname);
        c_file_close(cur_fd);
        return (EC_FALSE);
    }

    cur_fmem = (char *)mmap(NULL_PTR, cur_fsize, PROT_READ, MAP_SHARED, cur_fd, 0);
    if(MAP_FAILED == cur_fmem)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_open_url_list_file: mmap url list file %s with cur_fd %d failed, errno = %d, errorstr = %s\n",
                           fname, cur_fd, errno, strerror(errno));
        return (EC_FALSE);
    }

    (*fd)    = cur_fd;
    (*fmem)  = cur_fmem;
    (*fsize) = cur_fsize;

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_close_url_list_file(char *fmem, const UINT32 fsize, const int fd)
{
    if(ERR_FD != fd)
    {
        close(fd);
    }

    if(NULL_PTR != fmem)
    {
        munmap(fmem, fsize);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_fetch_url_cstr(const char *fmem, const UINT32 fsize, UINT32 *offset, UINT32 *idx,CSTRING *url_cstr)
{
    UINT32 old_offset;
    UINT32 line_len;

    old_offset = (*offset);
    if(fsize <= old_offset)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_fetch_url_cstr: offset %ld overflow fsize %ld\n", old_offset, fsize);
        return (EC_FALSE);
    }

    line_len = c_line_len(fmem + old_offset);
    cstring_append_chars(url_cstr, line_len, (UINT8 *)fmem + old_offset, LOC_CXFS_0016);
    cstring_append_char(url_cstr, '\0');

    (*offset) += line_len + 1;
    (*idx) ++;

    dbg_log(SEC_0192_CXFS, 0)(LOGCONSOLE, "[DEBUG] __cxfs_fetch_url_cstr: [%8ld] %s\n", (*idx), (char *)cstring_get_str(url_cstr));

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

