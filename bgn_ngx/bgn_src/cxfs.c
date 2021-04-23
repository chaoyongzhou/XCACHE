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
#include "coroutine.h"

#include "csocket.h"

#include "cmpie.h"

#include "cpgbitmap.h"

#include "crb.h"
#include "chttp.h"
#include "chttps.h"

#include "cxfs.h"
#include "cxfshttp.h"
#include "cxfshttps.h"
#include "cxfscfg.h"

#include "cxfsop.h"
#include "cxfsnpdel.h"

#include "csdisc.h"

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_free_module_static_mem: cxfs module #%ld not started.\n",
                cxfs_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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
    UINT32      sata_meta_size;
    int         sata_disk_fd;
    int         sata_meta_fd;

    UINT32      ssd_disk_size;
    UINT32      ssd_meta_size;
    int         ssd_disk_fd;
    int         ssd_meta_fd;

    UINT32      cfg_offset;
    UINT32      vdisk_size;
    UINT32      vdisk_num;

    cbc_md_reg(MD_CXFS, 32);

    cxfs_md_id = cbc_md_new(MD_CXFS, sizeof(CXFS_MD));
    if(CMPI_ERROR_MODI == cxfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /*check validity*/
    if(CXFS_MAX_MODI < cxfs_md_id)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: cxfs_md_id %ld overflow\n", cxfs_md_id);

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    sata_disk_size = 0;
    sata_meta_size = 0;

    sata_disk_fd   = ERR_FD;
    sata_meta_fd   = ERR_FD;

    ssd_disk_size  = 0;
    ssd_meta_size  = 0;

    ssd_disk_fd    = ERR_FD;
    ssd_meta_fd    = ERR_FD;

    /*sata*/
    if(NULL_PTR == sata_disk_path)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: sata path is null\n");

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }
    else
    {
        if(EC_FALSE == c_file_exist((char *)cstring_get_str(sata_disk_path))
        && EC_FALSE == c_dev_exist((char *)cstring_get_str(sata_disk_path)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: no sata '%s'\n",
                                                 (char *)cstring_get_str(sata_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
        {
            sata_disk_fd = c_file_open((char *)cstring_get_str(sata_disk_path), O_RDWR | O_DIRECT, 0666);
            if(ERR_FD == sata_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open sata '%s' failed\n",
                                                     (char *)cstring_get_str(sata_disk_path));


                cbc_md_free(MD_CXFS, cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }
        }

        if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
        {
            sata_disk_fd = c_file_open((char *)cstring_get_str(sata_disk_path), O_RDWR, 0666);
            if(ERR_FD == sata_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open sata '%s' failed\n",
                                                     (char *)cstring_get_str(sata_disk_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }
        }

        if(EC_FALSE == c_file_size(sata_disk_fd, &sata_disk_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: size of sata '%s' failed\n",
                                                 (char *)cstring_get_str(sata_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: open sata '%s' done\n",
                                             (char *)cstring_get_str(sata_disk_path));
    }

    /*sata meta*/
    if(ERR_FD != sata_disk_fd)
    {
        CSTRING    *sata_meta_path;

        sata_meta_path = cstring_make("%s.meta", (char *)cstring_get_str(sata_disk_path));
        if(NULL_PTR == sata_meta_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: make sata meta path '%s.meta' failed\n",
                                                 (char *)cstring_get_str(sata_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_exist((char *)cstring_get_str(sata_meta_path))
        && EC_FALSE == c_dev_exist((char *)cstring_get_str(sata_meta_path)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: no sata meta '%s'\n",
                                                 (char *)cstring_get_str(sata_meta_path));

            sata_meta_fd    = sata_disk_fd;
            sata_meta_size  = sata_disk_size;

            cstring_free(sata_meta_path);

            /*fall through*/
        }
        else
        {
            if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
            {
                sata_meta_fd = c_file_open((char *)cstring_get_str(sata_meta_path), O_RDWR | O_DIRECT, 0666);
                if(ERR_FD == sata_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open sata meta '%s' failed\n",
                                                         (char *)cstring_get_str(sata_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(sata_disk_fd);
                    cstring_free(sata_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
            {
                sata_meta_fd = c_file_open((char *)cstring_get_str(sata_meta_path), O_RDWR, 0666);
                if(ERR_FD == sata_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open sata '%s' failed\n",
                                                         (char *)cstring_get_str(sata_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(sata_disk_fd);
                    cstring_free(sata_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(EC_FALSE == c_file_size(sata_meta_fd, &sata_meta_size))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: size of sata meta '%s' failed\n",
                                                     (char *)cstring_get_str(sata_meta_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                c_file_close(sata_meta_fd);
                c_file_close(sata_disk_fd);
                cstring_free(sata_meta_path);
                return (CMPI_ERROR_MODI);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: open sata meta '%s' done\n",
                                                 (char *)cstring_get_str(sata_meta_path));

            cstring_free(sata_meta_path);
        }
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

        if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
        {
            ssd_disk_fd = c_file_open((char *)cstring_get_str(ssd_disk_path), O_RDWR | O_DIRECT, 0666);
            if(ERR_FD == ssd_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open ssd '%s' failed\n",
                                                     (char *)cstring_get_str(ssd_disk_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                if(sata_meta_fd != sata_disk_fd)
                {
                    c_file_close(sata_disk_fd);
                    c_file_close(sata_meta_fd);
                }
                else
                {
                    c_file_close(sata_disk_fd);
                }
                return (CMPI_ERROR_MODI);
            }
        }

        if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
        {
            ssd_disk_fd = c_file_open((char *)cstring_get_str(ssd_disk_path), O_RDWR, 0666);
            if(ERR_FD == ssd_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open ssd '%s' failed\n",
                                                     (char *)cstring_get_str(ssd_disk_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                if(sata_meta_fd != sata_disk_fd)
                {
                    c_file_close(sata_disk_fd);
                    c_file_close(sata_meta_fd);
                }
                else
                {
                    c_file_close(sata_disk_fd);
                }
                return (CMPI_ERROR_MODI);
            }
        }

        if(EC_FALSE == c_file_size(ssd_disk_fd, &ssd_disk_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: size of ssd '%s' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(ssd_disk_fd);
            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }
    }

    /*ssd meta*/
    if(ERR_FD != ssd_disk_fd)
    {
        CSTRING    *ssd_meta_path;

        ssd_meta_path = cstring_make("%s.meta", (char *)cstring_get_str(ssd_disk_path));
        if(NULL_PTR == ssd_meta_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: make ssd meta path '%s.meta' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(ssd_disk_fd);
            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_exist((char *)cstring_get_str(ssd_meta_path))
        && EC_FALSE == c_dev_exist((char *)cstring_get_str(ssd_meta_path)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: no ssd meta '%s'\n",
                                                 (char *)cstring_get_str(ssd_meta_path));

            ssd_meta_fd   = ssd_disk_fd;
            ssd_meta_size = ssd_disk_size;

            cstring_free(ssd_meta_path);

            /*fall through*/
        }
        else
        {
            if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
            {
                ssd_meta_fd = c_file_open((char *)cstring_get_str(ssd_meta_path), O_RDWR | O_DIRECT, 0666);
                if(ERR_FD == ssd_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open ssd meta '%s' failed\n",
                                                         (char *)cstring_get_str(ssd_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(ssd_disk_fd);
                    if(sata_meta_fd != sata_disk_fd)
                    {
                        c_file_close(sata_disk_fd);
                        c_file_close(sata_meta_fd);
                    }
                    else
                    {
                        c_file_close(sata_disk_fd);
                    }
                    cstring_free(ssd_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
            {
                ssd_meta_fd = c_file_open((char *)cstring_get_str(ssd_meta_path), O_RDWR, 0666);
                if(ERR_FD == ssd_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open ssd meta '%s' failed\n",
                                                         (char *)cstring_get_str(ssd_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(ssd_disk_fd);
                    if(sata_meta_fd != sata_disk_fd)
                    {
                        c_file_close(sata_disk_fd);
                        c_file_close(sata_meta_fd);
                    }
                    else
                    {
                        c_file_close(sata_disk_fd);
                    }
                    cstring_free(ssd_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(EC_FALSE == c_file_size(ssd_meta_fd, &ssd_meta_size))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: size of ssd meta '%s' failed\n",
                                                     (char *)cstring_get_str(ssd_meta_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                if(ssd_meta_fd != ssd_disk_fd)
                {
                    c_file_close(ssd_disk_fd);
                    c_file_close(ssd_meta_fd);
                }
                else
                {
                    c_file_close(ssd_disk_fd);
                }

                if(sata_meta_fd != sata_disk_fd)
                {
                    c_file_close(sata_disk_fd);
                    c_file_close(sata_meta_fd);
                }
                else
                {
                    c_file_close(sata_disk_fd);
                }
                cstring_free(ssd_meta_path);
                return (CMPI_ERROR_MODI);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: open ssd meta '%s' done\n",
                                                 (char *)cstring_get_str(ssd_meta_path));

            cstring_free(ssd_meta_path);
        }
    }

    /* initialize new one CXFS module */
    cxfs_md = (CXFS_MD *)cbc_md_get(MD_CXFS, cxfs_md_id);
    cxfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFS_MD_READ_ONLY_FLAG(cxfs_md) = BIT_FALSE;

    CXFS_MD_SATA_META_FD(cxfs_md)  = ERR_FD;

    cstring_init(CXFS_MD_SATA_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;

    CXFS_MD_SSD_META_FD(cxfs_md)  = ERR_FD;

    cstring_init(CXFS_MD_SSD_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ERR_FD;

    cxfscfg_init(CXFS_MD_CFG(cxfs_md));

    cxfs_stat_init(CXFS_MD_STAT(cxfs_md));
    cxfs_stat_init(CXFS_MD_STAT_SAVED(cxfs_md));

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

    clist_init(CXFS_MD_OP_MGR_LIST(cxfs_md), MM_CXFSOP_MGR, LOC_CXFS_0001);

    CXFS_MD_SYNC_FLAG(cxfs_md)              = BIT_FALSE;
    CXFS_MD_NP_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_DN_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_DUMP_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_REPLAY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_CUR_DISK_NO(cxfs_md)            = 0;
    CXFS_MD_DN(cxfs_md)                     = NULL_PTR;
    CXFS_MD_NPP(cxfs_md)                    = NULL_PTR;
    CXFS_MD_SATA_BAD_BITMAP(cxfs_md)        = NULL_PTR;
    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
    CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;
    CXFS_MD_OP_MGR(cxfs_md)                 = NULL_PTR;
    CXFS_MD_OP_DUMP_OFFSET(cxfs_md)         = 0;
    CXFS_MD_NP_CMMAP_NODE(cxfs_md)          = NULL_PTR;
    CXFS_MD_DN_CMMAP_NODE(cxfs_md)          = NULL_PTR;
    CXFS_MD_OVERHEAD_COUNTER(cxfs_md)       = 0;

    /*32G*/
    vdisk_size  = (((UINT32)CXFSPGD_MAX_BLOCK_NUM) * ((UINT32)CXFSPGB_CACHE_MAX_BYTE_SIZE));

    /*load config*/
    if(sata_meta_fd == sata_disk_fd)
    {
        if(EC_FALSE == cxfscfg_compute_offset(sata_disk_size, vdisk_size, &cfg_offset))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: "
                                                 "sata disk size %ld, vdisk size %ld "
                                                 "=> sata disk is tool small\n",
                                                 sata_disk_size, vdisk_size);

            cbc_md_free(MD_CXFS, cxfs_md_id);
            if(ssd_meta_fd != ssd_disk_fd)
            {
                c_file_close(ssd_disk_fd);
                c_file_close(ssd_meta_fd);
            }
            else
            {
                c_file_close(ssd_disk_fd);
            }

            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }

        ASSERT(0 == (cfg_offset % vdisk_size));
        vdisk_num = (cfg_offset / vdisk_size);

        if(EC_FALSE == cxfscfg_load(CXFS_MD_CFG(cxfs_md), sata_disk_fd, cfg_offset))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: load cfg from sata disk failed\n");

            cbc_md_free(MD_CXFS, cxfs_md_id);
            if(ssd_meta_fd != ssd_disk_fd)
            {
                c_file_close(ssd_disk_fd);
                c_file_close(ssd_meta_fd);
            }
            else
            {
                c_file_close(ssd_disk_fd);
            }

            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: load cfg from sata disk done\n");
    }
    else
    {
        cfg_offset = 0;
        vdisk_num  = (sata_disk_size / vdisk_size);

        if(EC_FALSE == cxfscfg_load(CXFS_MD_CFG(cxfs_md), sata_meta_fd, cfg_offset))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: load cfg from sata meta failed\n");

            cbc_md_free(MD_CXFS, cxfs_md_id);
            if(ssd_meta_fd != ssd_disk_fd)
            {
                c_file_close(ssd_disk_fd);
                c_file_close(ssd_meta_fd);
            }
            else
            {
                c_file_close(ssd_disk_fd);
            }

            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: load cfg from sata meta done\n");
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: vdisk_size %ld, vdisk_num %ld\n",
                                         vdisk_size, vdisk_num);

    CXFS_MD_SATA_META_FD(cxfs_md) = sata_meta_fd;
    CXFS_MD_SATA_DISK_FD(cxfs_md) = sata_disk_fd;

    CXFS_MD_SSD_META_FD(cxfs_md)  = ssd_meta_fd;
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ssd_disk_fd;

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    ret = EC_TRUE;

    while(CXFSCFG_MAGIC_VAL == CXFSCFG_MAGIC(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: cxfscfg is\n");
        cxfscfg_print(LOGSTDOUT, cxfscfg);

        ASSERT(cfg_offset == CXFSCFG_OFFSET(cxfscfg));
        ASSERT(vdisk_size == CXFSCFG_SATA_VDISK_SIZE(cxfscfg));
        ASSERT(vdisk_num == CXFSCFG_SATA_VDISK_NUM(cxfscfg));

        if(EC_FALSE == cxfs_load_sata_bad_bitmap(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: load sata bad bitmap failed\n");

            ret = EC_FALSE;
            break; /*terminate*/
        }

        CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr_open(CXFS_MD_SATA_META_FD(cxfs_md), cxfscfg);
        if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open npp failed\n");

            ret = EC_FALSE;
            break; /*terminate*/
        }

        /*fix: to reduce the np loading time cost*/
        if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            if(EC_FALSE == cxfsnp_mgr_open_np_all(CXFS_MD_NPP(cxfs_md)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open all np failed\n");

                cxfsnp_mgr_close_np_all(CXFS_MD_NPP(cxfs_md));/*roll back*/

                ret = EC_FALSE;
                break; /*terminate*/
            }
        }

        CXFS_MD_DN(cxfs_md) = cxfsdn_open(cxfscfg,
                                          CXFS_MD_SATA_META_FD(cxfs_md),
                                          CXFS_MD_SATA_DISK_FD(cxfs_md),
                                          CXFS_MD_SSD_META_FD(cxfs_md),
                                          CXFS_MD_SSD_DISK_FD(cxfs_md));
        if(NULL_PTR == CXFS_MD_DN(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: open dn failed\n");

            ret = EC_FALSE;
            break; /*terminate*/
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md) && NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cxfsdn_mount_sata_bad_bitmap(CXFS_MD_DN(cxfs_md), CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        }

        cxfsdn_set_check_page_used_cb(CXFS_MD_DN(cxfs_md),
                                        (void *)cxfs_md_id,
                                        (void *)cxfs_check_adjacent_used);

        break; /*fall through*/
    }

    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CXFS_MD_DN(cxfs_md))
        {
            cxfsdn_close(CXFS_MD_DN(cxfs_md), cxfscfg);
            CXFS_MD_DN(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            cxfsnp_mgr_close(CXFS_MD_NPP(cxfs_md));
            CXFS_MD_NPP(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cpg_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
            CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;
        }

        CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
        CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;

        if(CXFS_MD_SSD_META_FD(cxfs_md) == CXFS_MD_SSD_DISK_FD(cxfs_md))
        {
            if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
                CXFS_MD_SSD_DISK_FD(cxfs_md)  = ERR_FD;
                CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
            }
        }
        else
        {
            if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
                CXFS_MD_SSD_DISK_FD(cxfs_md) = ERR_FD;
            }

            if(ERR_FD != CXFS_MD_SSD_META_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SSD_META_FD(cxfs_md));
                CXFS_MD_SSD_META_FD(cxfs_md) = ERR_FD;
            }
        }

        if(CXFS_MD_SATA_META_FD(cxfs_md) == CXFS_MD_SATA_DISK_FD(cxfs_md))
        {
            if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
                CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
                CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
            }
        }
        else
        {
            if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
                CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
            }

            if(ERR_FD != CXFS_MD_SATA_META_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SATA_META_FD(cxfs_md));
                CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
            }
        }

        cbc_md_free(MD_CXFS, cxfs_md_id);

        return (CMPI_ERROR_MODI);
    }

    if(SWITCH_ON == CXFS_OP_SWITCH
    && CXFSCFG_MAGIC_VAL != CXFSCFG_MAGIC(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: magic mismatched\n");

        cxfscfg_clean(cxfscfg); /*clean up dirty data*/

        CXFSCFG_OFFSET(cxfscfg)             = cfg_offset;

        CXFSCFG_OP_S_OFFSET(cxfscfg)        = cfg_offset
                                            + CXFSCFG_SIZE
                                            + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

        CXFSCFG_OP_E_OFFSET(cxfscfg)        = cfg_offset
                                            + CXFSCFG_SIZE
                                            + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES
                                            + CXFS_OP_TABLE_DISK_MAX_SIZE_NBYTES;

        /*set basic info to config for fresh xfs*/
        CXFSCFG_SATA_META_SIZE(cxfscfg)     = sata_meta_size;
        CXFSCFG_SATA_DISK_SIZE(cxfscfg)     = sata_disk_size;

        CXFSCFG_SATA_VDISK_SIZE(cxfscfg)    = vdisk_size;
        CXFSCFG_SATA_VDISK_NUM(cxfscfg)     = vdisk_num;

        CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)   = cfg_offset
                                            + CXFSCFG_SIZE
                                            + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES
                                            + CXFS_OP_TABLE_DISK_MAX_SIZE_NBYTES;

        CXFSCFG_SSD_META_SIZE(cxfscfg)      = ssd_meta_size;
        CXFSCFG_SSD_DISK_SIZE(cxfscfg)      = ssd_disk_size;
        CXFSCFG_SSD_DISK_OFFSET(cxfscfg)    = 0;
    }

    if(SWITCH_OFF == CXFS_OP_SWITCH
    && CXFSCFG_MAGIC_VAL != CXFSCFG_MAGIC(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: magic mismatched\n");

        cxfscfg_clean(cxfscfg); /*clean up dirty data*/

        CXFSCFG_OFFSET(cxfscfg)             = cfg_offset;

        CXFSCFG_OP_S_OFFSET(cxfscfg)        = ERR_OFFSET; /*disabled*/

        CXFSCFG_OP_E_OFFSET(cxfscfg)        = ERR_OFFSET; /*disabled*/

        /*set basic info to config for fresh xfs*/
        CXFSCFG_SATA_META_SIZE(cxfscfg)     = sata_meta_size;
        CXFSCFG_SATA_DISK_SIZE(cxfscfg)     = sata_disk_size;
        CXFSCFG_SATA_DISK_OFFSET(cxfscfg)   = 0;

        CXFSCFG_SATA_VDISK_SIZE(cxfscfg)    = vdisk_size;
        CXFSCFG_SATA_VDISK_NUM(cxfscfg)     = vdisk_num;

        CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)   = cfg_offset
                                            + CXFSCFG_SIZE
                                            + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

        CXFSCFG_SSD_META_SIZE(cxfscfg)      = ssd_meta_size;
        CXFSCFG_SSD_DISK_SIZE(cxfscfg)      = ssd_disk_size;
        CXFSCFG_SSD_DISK_OFFSET(cxfscfg)    = 0;
    }

    CXFS_MD_STATE(cxfs_md) = CXFS_WORK_STATE;

    cxfs_md->usedcounter = 1;

    /*sata*/
    cstring_clone(sata_disk_path, CXFS_MD_SATA_DISK_PATH(cxfs_md));

    /*ssd*/
    if(NULL_PTR != ssd_disk_path && EC_FALSE == cstring_is_empty(ssd_disk_path))
    {
        cstring_clone(ssd_disk_path, CXFS_MD_SSD_DISK_PATH(cxfs_md));
    }

    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        /*dump npp to standby zone*/
        if(EC_FALSE == cxfs_dump_npp(cxfs_md_id, CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: dump npp to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        /*dump dn to standby zone*/
        if(EC_FALSE == cxfs_dump_dn(cxfs_md_id, CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: dump dn to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    /*op mgr*/
    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
    {
        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_create(CXFS_OP_DUMP_MCACHE_MAX_SIZE_NBYTES);
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: create op mgr failed\n");
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

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: create op mgr done\n");
    }

    task_brd_set_paused();

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfs_end, cxfs_md_id);

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_sync_sata_bad_bitmap,
                        (void *)cxfs_md);

    if(SWITCH_ON == CXFS_OP_SWITCH)
    {
        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_process_op,
                            (void *)cxfs_md_id);
    }

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_space,
                        (void *)cxfs_md_id);

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_stat,
                        (void *)cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: start CXFS module #%ld\n", cxfs_md_id);

    if(CMPI_FWD_RANK == CMPI_LOCAL_RANK)
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

                task_brd_set_not_paused();

                cxfs_end(cxfs_md_id);

                return (CMPI_ERROR_MODI);
            }

            cxfshttp_log_start();
            task_brd_default_bind_http_srv_modi(cxfs_md_id);
            chttp_rest_list_push((const char *)CXFSHTTP_REST_API_NAME, cxfshttp_commit_request);

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: reg xfs http rest api done\n");
        }

        /*https server*/
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled()
        && NULL_PTR != task_brd_default_get_cepoll()
        && 0 == cxfs_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_start: init cxfshttp defer request queue failed\n");

                task_brd_set_not_paused();

                cxfs_end(cxfs_md_id);

                return (CMPI_ERROR_MODI);
            }
            cxfshttps_log_start();
            task_brd_default_bind_https_srv_modi(cxfs_md_id);
            chttps_rest_list_push((const char *)CXFSHTTPS_REST_API_NAME, cxfshttps_commit_request);

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_start: reg xfs https rest api done\n");
        }

        /*self-discovery of service*/
        if(EC_TRUE == task_brd_default_check_sdisc_running())
        {
            CSDISC_NODE         *csdisc_node;

            csdisc_node = task_brd_default_get_sdisc_running();
            if(NULL_PTR != csdisc_node)
            {
                csdisc_node_push_sender(csdisc_node, (CSDISC_SENDER_FUNC)cxfs_sdisc_sender, (void *)cxfs_md_id);
                csdisc_node_push_recver(csdisc_node, (CSDISC_SENDER_FUNC)cxfs_sdisc_recver, (void *)cxfs_md_id);
            }
        }
    }

    task_brd_set_not_paused();

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
    UINT32      sata_meta_size;
    int         sata_disk_fd;
    int         sata_meta_fd;

    UINT32      ssd_disk_size;
    UINT32      ssd_meta_size;
    int         ssd_disk_fd;
    int         ssd_meta_fd;

    UINT32      cfg_offset;
    UINT32      vdisk_size;
    UINT32      vdisk_num;

    if(SWITCH_OFF == CXFS_OP_SWITCH)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "fatal error:cxfs_retrieve: not support yet!\n");
        return (CMPI_ERROR_MODI);
    }

    cbc_md_reg(MD_CXFS, 32);

    cxfs_md_id = cbc_md_new(MD_CXFS, sizeof(CXFS_MD));
    if(CMPI_ERROR_MODI == cxfs_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /*check validity*/
    if(CXFS_MAX_MODI < cxfs_md_id)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: cxfs_md_id %ld overflow\n", cxfs_md_id);

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }

    sata_disk_size = 0;
    sata_meta_size = 0;

    sata_disk_fd   = ERR_FD;
    sata_meta_fd   = ERR_FD;

    ssd_disk_size  = 0;
    ssd_meta_size  = 0;

    ssd_disk_fd    = ERR_FD;
    ssd_meta_fd    = ERR_FD;

    /*sata*/
    if(NULL_PTR == sata_disk_path)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: sata path is null\n");

        cbc_md_free(MD_CXFS, cxfs_md_id);
        return (CMPI_ERROR_MODI);
    }
    else
    {
        if(EC_FALSE == c_file_exist((char *)cstring_get_str(sata_disk_path))
        && EC_FALSE == c_dev_exist((char *)cstring_get_str(sata_disk_path)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: no sata '%s'\n",
                                                 (char *)cstring_get_str(sata_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }

        if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
        {
            sata_disk_fd = c_file_open((char *)cstring_get_str(sata_disk_path), O_RDWR | O_DIRECT, 0666);
            if(ERR_FD == sata_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open sata '%s' failed\n",
                                                     (char *)cstring_get_str(sata_disk_path));


                cbc_md_free(MD_CXFS, cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }
        }

        if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
        {
            sata_disk_fd = c_file_open((char *)cstring_get_str(sata_disk_path), O_RDWR, 0666);
            if(ERR_FD == sata_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open sata '%s' failed\n",
                                                     (char *)cstring_get_str(sata_disk_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }
        }

        if(EC_FALSE == c_file_size(sata_disk_fd, &sata_disk_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: size of sata '%s' failed\n",
                                                 (char *)cstring_get_str(sata_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: open sata '%s' done\n",
                                             (char *)cstring_get_str(sata_disk_path));
    }

    /*sata meta*/
    if(ERR_FD != sata_disk_fd)
    {
        CSTRING    *sata_meta_path;

        sata_meta_path = cstring_make("%s.meta", (char *)cstring_get_str(sata_disk_path));
        if(NULL_PTR == sata_meta_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: make sata meta path '%s.meta' failed\n",
                                                 (char *)cstring_get_str(sata_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(sata_disk_fd);
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_exist((char *)cstring_get_str(sata_meta_path))
        && EC_FALSE == c_dev_exist((char *)cstring_get_str(sata_meta_path)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: no sata meta '%s'\n",
                                                 (char *)cstring_get_str(sata_meta_path));

            sata_meta_fd   = sata_disk_fd;
            sata_meta_size = sata_disk_size;

            cstring_free(sata_meta_path);

            /*fall through*/
        }
        else
        {
            if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
            {
                sata_meta_fd = c_file_open((char *)cstring_get_str(sata_meta_path), O_RDWR | O_DIRECT, 0666);
                if(ERR_FD == sata_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open sata meta '%s' failed\n",
                                                         (char *)cstring_get_str(sata_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(sata_disk_fd);
                    cstring_free(sata_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
            {
                sata_meta_fd = c_file_open((char *)cstring_get_str(sata_meta_path), O_RDWR, 0666);
                if(ERR_FD == sata_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open sata '%s' failed\n",
                                                         (char *)cstring_get_str(sata_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(sata_disk_fd);
                    cstring_free(sata_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(EC_FALSE == c_file_size(sata_meta_fd, &sata_meta_size))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: size of sata meta '%s' failed\n",
                                                     (char *)cstring_get_str(sata_meta_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                c_file_close(sata_meta_fd);
                c_file_close(sata_disk_fd);
                cstring_free(sata_meta_path);
                return (CMPI_ERROR_MODI);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: open sata meta '%s' done\n",
                                                 (char *)cstring_get_str(sata_meta_path));

            cstring_free(sata_meta_path);
        }
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

        if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
        {
            ssd_disk_fd = c_file_open((char *)cstring_get_str(ssd_disk_path), O_RDWR | O_DIRECT, 0666);
            if(ERR_FD == ssd_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open ssd '%s' failed\n",
                                                     (char *)cstring_get_str(ssd_disk_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                if(sata_meta_fd != sata_disk_fd)
                {
                    c_file_close(sata_disk_fd);
                    c_file_close(sata_meta_fd);
                }
                else
                {
                    c_file_close(sata_disk_fd);
                }
                return (CMPI_ERROR_MODI);
            }
        }

        if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
        {
            ssd_disk_fd = c_file_open((char *)cstring_get_str(ssd_disk_path), O_RDWR, 0666);
            if(ERR_FD == ssd_disk_fd)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open ssd '%s' failed\n",
                                                     (char *)cstring_get_str(ssd_disk_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                if(sata_meta_fd != sata_disk_fd)
                {
                    c_file_close(sata_disk_fd);
                    c_file_close(sata_meta_fd);
                }
                else
                {
                    c_file_close(sata_disk_fd);
                }
                return (CMPI_ERROR_MODI);
            }
        }

        if(EC_FALSE == c_file_size(ssd_disk_fd, &ssd_disk_size))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: size of ssd '%s' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(ssd_disk_fd);
            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }
    }

    /*ssd meta*/
    if(ERR_FD != ssd_disk_fd)
    {
        CSTRING    *ssd_meta_path;

        ssd_meta_path = cstring_make("%s.meta", (char *)cstring_get_str(ssd_disk_path));
        if(NULL_PTR == ssd_meta_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: make ssd meta path '%s.meta' failed\n",
                                                 (char *)cstring_get_str(ssd_disk_path));

            cbc_md_free(MD_CXFS, cxfs_md_id);
            c_file_close(ssd_disk_fd);
            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }

        if(EC_FALSE == c_file_exist((char *)cstring_get_str(ssd_meta_path))
        && EC_FALSE == c_dev_exist((char *)cstring_get_str(ssd_meta_path)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: no ssd meta '%s'\n",
                                                 (char *)cstring_get_str(ssd_meta_path));

            ssd_meta_fd   = ssd_disk_fd;
            ssd_meta_size = ssd_disk_size;

            cstring_free(ssd_meta_path);

            /*fall through*/
        }
        else
        {
            if(SWITCH_ON == CXFSDN_CAMD_SWITCH)
            {
                ssd_meta_fd = c_file_open((char *)cstring_get_str(ssd_meta_path), O_RDWR | O_DIRECT, 0666);
                if(ERR_FD == ssd_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open ssd meta '%s' failed\n",
                                                         (char *)cstring_get_str(ssd_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(ssd_disk_fd);
                    if(sata_meta_fd != sata_disk_fd)
                    {
                        c_file_close(sata_disk_fd);
                        c_file_close(sata_meta_fd);
                    }
                    else
                    {
                        c_file_close(sata_disk_fd);
                    }
                    cstring_free(ssd_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(SWITCH_OFF == CXFSDN_CAMD_SWITCH)
            {
                ssd_meta_fd = c_file_open((char *)cstring_get_str(ssd_meta_path), O_RDWR, 0666);
                if(ERR_FD == ssd_meta_fd)
                {
                    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open ssd meta '%s' failed\n",
                                                         (char *)cstring_get_str(ssd_meta_path));

                    cbc_md_free(MD_CXFS, cxfs_md_id);
                    c_file_close(ssd_disk_fd);
                    if(sata_meta_fd != sata_disk_fd)
                    {
                        c_file_close(sata_disk_fd);
                        c_file_close(sata_meta_fd);
                    }
                    else
                    {
                        c_file_close(sata_disk_fd);
                    }
                    cstring_free(ssd_meta_path);
                    return (CMPI_ERROR_MODI);
                }
            }

            if(EC_FALSE == c_file_size(ssd_meta_fd, &ssd_meta_size))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: size of ssd meta '%s' failed\n",
                                                     (char *)cstring_get_str(ssd_meta_path));

                cbc_md_free(MD_CXFS, cxfs_md_id);
                if(ssd_meta_fd != ssd_disk_fd)
                {
                    c_file_close(ssd_disk_fd);
                    c_file_close(ssd_meta_fd);
                }
                else
                {
                    c_file_close(ssd_disk_fd);
                }

                if(sata_meta_fd != sata_disk_fd)
                {
                    c_file_close(sata_disk_fd);
                    c_file_close(sata_meta_fd);
                }
                else
                {
                    c_file_close(sata_disk_fd);
                }
                cstring_free(ssd_meta_path);
                return (CMPI_ERROR_MODI);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: open ssd meta '%s' done\n",
                                                 (char *)cstring_get_str(ssd_meta_path));

            cstring_free(ssd_meta_path);
        }
    }

    /* initialize new one CXFS module */
    cxfs_md = (CXFS_MD *)cbc_md_get(MD_CXFS, cxfs_md_id);
    cxfs_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFS_MD_READ_ONLY_FLAG(cxfs_md) = BIT_FALSE;

    CXFS_MD_SATA_META_FD(cxfs_md)  = ERR_FD;

    cstring_init(CXFS_MD_SATA_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;

    CXFS_MD_SSD_META_FD(cxfs_md)  = ERR_FD;

    cstring_init(CXFS_MD_SSD_DISK_PATH(cxfs_md), NULL_PTR);
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ERR_FD;

    cxfscfg_init(CXFS_MD_CFG(cxfs_md));

    cxfs_stat_init(CXFS_MD_STAT(cxfs_md));
    cxfs_stat_init(CXFS_MD_STAT_SAVED(cxfs_md));

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

    clist_init(CXFS_MD_OP_MGR_LIST(cxfs_md), MM_CXFSOP_MGR, LOC_CXFS_0002);

    CXFS_MD_SYNC_FLAG(cxfs_md)              = BIT_FALSE;
    CXFS_MD_NP_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_DN_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_DUMP_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_REPLAY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_CUR_DISK_NO(cxfs_md)            = 0;
    CXFS_MD_DN(cxfs_md)                     = NULL_PTR;
    CXFS_MD_NPP(cxfs_md)                    = NULL_PTR;
    CXFS_MD_SATA_BAD_BITMAP(cxfs_md)        = NULL_PTR;
    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
    CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;
    CXFS_MD_OP_MGR(cxfs_md)                 = NULL_PTR;
    CXFS_MD_OP_DUMP_OFFSET(cxfs_md)         = 0;
    CXFS_MD_NP_CMMAP_NODE(cxfs_md)          = NULL_PTR;
    CXFS_MD_DN_CMMAP_NODE(cxfs_md)          = NULL_PTR;
    CXFS_MD_OVERHEAD_COUNTER(cxfs_md)       = 0;

    /*32G*/
    vdisk_size  = (((UINT32)CXFSPGD_MAX_BLOCK_NUM) * ((UINT32)CXFSPGB_CACHE_MAX_BYTE_SIZE));

    /*load config*/
    if(sata_meta_fd == sata_disk_fd)
    {
        if(EC_FALSE == cxfscfg_compute_offset(sata_disk_size, vdisk_size, &cfg_offset))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: "
                                                 "sata disk size %ld, vdisk size %ld "
                                                 "=> sata disk is tool small\n",
                                                 sata_disk_size, vdisk_size);

            cbc_md_free(MD_CXFS, cxfs_md_id);
            if(ssd_meta_fd != ssd_disk_fd)
            {
                c_file_close(ssd_disk_fd);
                c_file_close(ssd_meta_fd);
            }
            else
            {
                c_file_close(ssd_disk_fd);
            }

            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }

        ASSERT(0 == (cfg_offset % vdisk_size));
        vdisk_num = (cfg_offset / vdisk_size);

        if(EC_FALSE == cxfscfg_load(CXFS_MD_CFG(cxfs_md), sata_disk_fd, cfg_offset))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: load cfg from sata disk failed\n");

            cbc_md_free(MD_CXFS, cxfs_md_id);
            if(ssd_meta_fd != ssd_disk_fd)
            {
                c_file_close(ssd_disk_fd);
                c_file_close(ssd_meta_fd);
            }
            else
            {
                c_file_close(ssd_disk_fd);
            }

            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: load cfg from sata disk done\n");
    }
    else
    {
        cfg_offset = 0;
        vdisk_num  = (sata_disk_size / vdisk_size);

        if(EC_FALSE == cxfscfg_load(CXFS_MD_CFG(cxfs_md), sata_meta_fd, cfg_offset))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: load cfg from sata meta failed\n");

            cbc_md_free(MD_CXFS, cxfs_md_id);
            if(ssd_meta_fd != ssd_disk_fd)
            {
                c_file_close(ssd_disk_fd);
                c_file_close(ssd_meta_fd);
            }
            else
            {
                c_file_close(ssd_disk_fd);
            }

            if(sata_meta_fd != sata_disk_fd)
            {
                c_file_close(sata_disk_fd);
                c_file_close(sata_meta_fd);
            }
            else
            {
                c_file_close(sata_disk_fd);
            }
            return (CMPI_ERROR_MODI);
        }
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: load cfg from sata meta done\n");
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: vdisk_size %ld, vdisk_num %ld\n",
                                         vdisk_size, vdisk_num);

    CXFS_MD_SATA_META_FD(cxfs_md) = sata_meta_fd;
    CXFS_MD_SATA_DISK_FD(cxfs_md) = sata_disk_fd;

    CXFS_MD_SSD_META_FD(cxfs_md)  = ssd_meta_fd;
    CXFS_MD_SSD_DISK_FD(cxfs_md)  = ssd_disk_fd;

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    ret = EC_TRUE;

    /*do not check magic and switch active and standby*/
    CXFSCFG_NP_ZONE_SWITCH(cxfscfg);
    CXFSCFG_DN_ZONE_SWITCH(cxfscfg);

    CXFSCFG_MAGIC(cxfscfg) = CXFSCFG_MAGIC_VAL; /*reset*/

    while(CXFSCFG_MAGIC_VAL == CXFSCFG_MAGIC(cxfscfg))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: cxfscfg is\n");
        cxfscfg_print(LOGSTDOUT, cxfscfg);

        ASSERT(cfg_offset == CXFSCFG_OFFSET(cxfscfg));
        ASSERT(vdisk_size == CXFSCFG_SATA_VDISK_SIZE(cxfscfg));
        ASSERT(vdisk_num == CXFSCFG_SATA_VDISK_NUM(cxfscfg));

        if(EC_FALSE == cxfs_load_sata_bad_bitmap(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: load sata bad bitmap failed\n");

            ret = EC_FALSE;
            break; /*terminate*/
        }

        CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr_open(CXFS_MD_SATA_META_FD(cxfs_md), cxfscfg);
        if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open npp failed\n");

            ret = EC_FALSE;
            break; /*terminate*/
        }

        /*fix: to reduce the np loading time elapsed*/
        if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            if(EC_FALSE == cxfsnp_mgr_open_np_all(CXFS_MD_NPP(cxfs_md)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open all np failed\n");

                cxfsnp_mgr_close_np_all(CXFS_MD_NPP(cxfs_md));/*roll back*/

                ret = EC_FALSE;
                break; /*terminate*/
            }
        }

        CXFS_MD_DN(cxfs_md) = cxfsdn_open(cxfscfg,
                                          CXFS_MD_SATA_META_FD(cxfs_md),
                                          CXFS_MD_SATA_DISK_FD(cxfs_md),
                                          CXFS_MD_SSD_META_FD(cxfs_md),
                                          CXFS_MD_SSD_DISK_FD(cxfs_md));
        if(NULL_PTR == CXFS_MD_DN(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: open dn failed\n");

            ret = EC_FALSE;
            break; /*terminate*/
        }

        if(EC_TRUE == ret && NULL_PTR != CXFS_MD_DN(cxfs_md) && NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cxfsdn_mount_sata_bad_bitmap(CXFS_MD_DN(cxfs_md), CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        }

        cxfsdn_set_check_page_used_cb(CXFS_MD_DN(cxfs_md),
                                        (void *)cxfs_md_id,
                                        (void *)cxfs_check_adjacent_used);

        break; /*fall through*/
    }

    if(EC_FALSE == ret)
    {
        if(NULL_PTR != CXFS_MD_DN(cxfs_md))
        {
            cxfsdn_close(CXFS_MD_DN(cxfs_md), cxfscfg);
            CXFS_MD_DN(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            cxfsnp_mgr_close(CXFS_MD_NPP(cxfs_md));
            CXFS_MD_NPP(cxfs_md) = NULL_PTR;
        }

        if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            cpg_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
            CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;
        }

        CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
        CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;

        if(CXFS_MD_SSD_META_FD(cxfs_md) == CXFS_MD_SSD_DISK_FD(cxfs_md))
        {
            if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
                CXFS_MD_SSD_DISK_FD(cxfs_md) = ERR_FD;
                CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
            }
        }
        else
        {
            if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
                CXFS_MD_SSD_DISK_FD(cxfs_md) = ERR_FD;
            }

            if(ERR_FD != CXFS_MD_SSD_META_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SSD_META_FD(cxfs_md));
                CXFS_MD_SSD_META_FD(cxfs_md) = ERR_FD;
            }
        }

        if(CXFS_MD_SATA_META_FD(cxfs_md) == CXFS_MD_SATA_DISK_FD(cxfs_md))
        {
            if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
                CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
                CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
            }
        }
        else
        {
            if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
                CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
            }

            if(ERR_FD != CXFS_MD_SATA_META_FD(cxfs_md))
            {
                c_file_close(CXFS_MD_SATA_META_FD(cxfs_md));
                CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
            }
        }

        cbc_md_free(MD_CXFS, cxfs_md_id);

        return (CMPI_ERROR_MODI);
    }

    CXFS_MD_STATE(cxfs_md) = CXFS_WORK_STATE;

    cxfs_md->usedcounter = 1;

    /*sata*/
    cstring_clone(sata_disk_path, CXFS_MD_SATA_DISK_PATH(cxfs_md));

    /*ssd*/
    if(NULL_PTR != ssd_disk_path && EC_FALSE == cstring_is_empty(ssd_disk_path))
    {
        cstring_clone(ssd_disk_path, CXFS_MD_SSD_DISK_PATH(cxfs_md));
    }

    /*replay op*/
    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR != CXFS_MD_DN(cxfs_md)
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
    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
    {
        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_create(CXFS_OP_DUMP_MCACHE_MAX_SIZE_NBYTES);
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: create op mgr failed\n");
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

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: create op mgr done\n");
    }

    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        /*dump npp to standby zone*/
        if(EC_FALSE == cxfs_dump_npp(cxfs_md_id, CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: dump npp to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        /*dump dn to standby zone*/
        if(EC_FALSE == cxfs_dump_dn(cxfs_md_id, CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: dump dn to standby zone failed\n");
            cxfs_end(cxfs_md_id);
            return (CMPI_ERROR_MODI);
        }
    }

    CXFSCFG_OP_DUMP_TIME_MSEC(CXFS_MD_CFG(cxfs_md)) = c_get_cur_time_msec();

    task_brd_set_paused();

    /*dump cxfscfg*/
    cxfscfg_flush(CXFS_MD_CFG(cxfs_md), CXFS_MD_SATA_META_FD(cxfs_md));

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfs_end, cxfs_md_id);

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_sync_sata_bad_bitmap,
                        (void *)cxfs_md);

    if(SWITCH_ON == CXFS_OP_SWITCH)
    {
        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_process_op,
                            (void *)cxfs_md_id);
    }

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_space,
                        (void *)cxfs_md_id);

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_stat,
                        (void *)cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_retrieve: start CXFS module #%ld\n", cxfs_md_id);

    if(CMPI_FWD_RANK == CMPI_LOCAL_RANK)
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

                task_brd_set_not_paused();

                cxfs_end(cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }

            cxfshttp_log_start();
            task_brd_default_bind_http_srv_modi(cxfs_md_id);
            chttp_rest_list_push((const char *)CXFSHTTP_REST_API_NAME, cxfshttp_commit_request);
        }

        /*https server*/
        else if(EC_TRUE == task_brd_default_check_ssrv_enabled()
        && NULL_PTR != task_brd_default_get_cepoll()
        && 0 == cxfs_md_id)
        {
            if(EC_FALSE == chttps_defer_request_queue_init())
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retrieve: init cxfshttp defer request queue failed\n");

                task_brd_set_not_paused();

                cxfs_end(cxfs_md_id);
                return (CMPI_ERROR_MODI);
            }
            cxfshttps_log_start();
            task_brd_default_bind_https_srv_modi(cxfs_md_id);
            chttps_rest_list_push((const char *)CXFSHTTPS_REST_API_NAME, cxfshttps_commit_request);
        }

        /*self-discovery of service*/
        if(EC_TRUE == task_brd_default_check_sdisc_running())
        {
            CSDISC_NODE         *csdisc_node;

            csdisc_node = task_brd_default_get_sdisc_running();
            if(NULL_PTR != csdisc_node)
            {
                csdisc_node_push_sender(csdisc_node, (CSDISC_SENDER_FUNC)cxfs_sdisc_sender, (void *)cxfs_md_id);
                csdisc_node_push_recver(csdisc_node, (CSDISC_SENDER_FUNC)cxfs_sdisc_recver, (void *)cxfs_md_id);
            }
        }
    }

    task_brd_set_not_paused();

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

    if(NULL_PTR != CXFS_MD_NP_CMMAP_NODE(cxfs_md))
    {
        cmmap_node_free(CXFS_MD_NP_CMMAP_NODE(cxfs_md));
        CXFS_MD_NP_CMMAP_NODE(cxfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFS_MD_DN_CMMAP_NODE(cxfs_md))
    {
        cmmap_node_free(CXFS_MD_DN_CMMAP_NODE(cxfs_md));
        CXFS_MD_DN_CMMAP_NODE(cxfs_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        cxfsdn_close(CXFS_MD_DN(cxfs_md), CXFS_MD_CFG(cxfs_md));
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

    cxfs_stat_clean(CXFS_MD_STAT(cxfs_md));
    cxfs_stat_clean(CXFS_MD_STAT_SAVED(cxfs_md));

    clist_clean(CXFS_MD_OP_MGR_LIST(cxfs_md), (CLIST_DATA_DATA_CLEANER)cxfsop_mgr_free);

    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        cxfs_flush_sata_bad_bitmap(cxfs_md);

        cpg_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;
    }

    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)      = 0;
    CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md)    = 0;

    if(ERR_FD != CXFS_MD_SATA_META_FD(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_end: cxfscfg is\n");
        cxfscfg_print(LOGSTDOUT, CXFS_MD_CFG(cxfs_md));

        cxfscfg_flush(CXFS_MD_CFG(cxfs_md), CXFS_MD_SATA_META_FD(cxfs_md));
        cxfscfg_clean(CXFS_MD_CFG(cxfs_md));
    }

    if(CXFS_MD_SSD_META_FD(cxfs_md) == CXFS_MD_SSD_DISK_FD(cxfs_md))
    {
        if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
            CXFS_MD_SSD_DISK_FD(cxfs_md) = ERR_FD;
            CXFS_MD_SSD_META_FD(cxfs_md) = ERR_FD;
        }
    }
    else
    {
        if(ERR_FD != CXFS_MD_SSD_META_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SSD_META_FD(cxfs_md));
            CXFS_MD_SSD_META_FD(cxfs_md) = ERR_FD;
        }

        if(ERR_FD != CXFS_MD_SSD_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SSD_DISK_FD(cxfs_md));
            CXFS_MD_SSD_DISK_FD(cxfs_md) = ERR_FD;
        }
    }

    if(CXFS_MD_SATA_META_FD(cxfs_md) == CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
            CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
            CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
        }
    }
    else
    {
        if(ERR_FD != CXFS_MD_SATA_META_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SATA_META_FD(cxfs_md));
            CXFS_MD_SATA_META_FD(cxfs_md) = ERR_FD;
        }

        if(ERR_FD != CXFS_MD_SATA_DISK_FD(cxfs_md))
        {
            c_file_close(CXFS_MD_SATA_DISK_FD(cxfs_md));
            CXFS_MD_SATA_DISK_FD(cxfs_md) = ERR_FD;
        }
    }

    cstring_clean(CXFS_MD_SATA_DISK_PATH(cxfs_md));
    cstring_clean(CXFS_MD_SSD_DISK_PATH(cxfs_md));

    crb_tree_clean(CXFS_MD_LOCKED_FILES(cxfs_md));
    crb_tree_clean(CXFS_MD_WAIT_FILES(cxfs_md));

    cxfscfg_clean(CXFS_MD_CFG(cxfs_md));

    CXFS_MD_READ_ONLY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_SYNC_FLAG(cxfs_md)              = BIT_FALSE;
    CXFS_MD_NP_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_DN_SYNC_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_DUMP_FLAG(cxfs_md)           = BIT_FALSE;
    CXFS_MD_OP_REPLAY_FLAG(cxfs_md)         = BIT_FALSE;
    CXFS_MD_CUR_DISK_NO(cxfs_md)            = 0;
    CXFS_MD_OP_DUMP_OFFSET(cxfs_md)         = 0;
    CXFS_MD_OVERHEAD_COUNTER(cxfs_md)       = 0;

    /* free module : */
    //cxfs_free_module_static_mem(cxfs_md_id);

    cxfs_md->usedcounter = 0;

    cbc_md_free(MD_CXFS, cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_end: stop CXFS module #%ld\n", cxfs_md_id);

    return ;
}

EC_BOOL cxfs_sdisc_sender(const UINT32 cxfs_md_id, CSDISC_NODE *csdisc_node)
{
    static uint64_t     seq_no = 0;
    TASKS_CFG          *tasks_cfg;
    char                buff[ 128 ];
    uint32_t            len;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_sdisc_sender: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    tasks_cfg = TASK_BRD_LOCAL_TASKS_CFG(task_brd_default_get());

    /* seq_no, xfs, tcid, ipv4, port, modi
    *
    * jason: {"service":"xfs","tcid":"10.10.67.18","ipv4":"127.0.0.1", "bgn":"618", "modi":"0"}
    * string: xfs|<tcid>|<ipv4>|<bgn port>|<xfs modi>
    *
    */
    len = snprintf(buff, sizeof(buff)/sizeof(buff[0]),
                         "{%ld|xfs|%s|%s|%ld|%ld}",
                         seq_no,
                         c_word_to_ipv4(CMPI_LOCAL_TCID),
                         c_word_to_ipv4(TASKS_CFG_SRVIPADDR(tasks_cfg)),
                         TASKS_CFG_SRVPORT(tasks_cfg),
                         cxfs_md_id);

    if(EC_FALSE == csdisc_node_send_packet(csdisc_node, (const uint8_t *)buff, len))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sdisc_sender: "
                                             "send '%.*s' failed\n",
                                             len, (char *)buff);
        return (EC_FALSE);
    }

    seq_no ++;

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_sdisc_sender: "
                                         "send '%.*s' done\n",
                                         len, (char *)buff);

    return (EC_TRUE);
}

EC_BOOL cxfs_sdisc_recver(const UINT32 cxfs_md_id, CSDISC_NODE *csdisc_node)
{
    static char  buff[ 1024 ];
    char        *s_buff;
    char        *e_buff;
    char        *c_buff;

    uint32_t     len;
    uint32_t     segs_num;
    char        *segs[ 8 ];
    char        *seg;
    UINT32       ngx_tcid;
    UINT32       ngx_ipv4;
    UINT32       ngx_bgn_port;
    MOD_NODE     recv_mod_node;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_sdisc_recver: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(EC_FALSE == csdisc_node_recv_packet(csdisc_node, (uint8_t *)buff,
                            sizeof(buff)/sizeof(buff[0]), &len))
    {
        return (EC_FALSE);
    }

    if(0 == len)
    {
        return (EC_TRUE);
    }

    s_buff = (char *)buff;
    e_buff = s_buff + len;

    while(s_buff < e_buff)
    {
        while('{' != *s_buff && s_buff < e_buff)
        {
            s_buff ++;
        }

        if(s_buff >= e_buff)
        {
            return (EC_TRUE);
        }

        c_buff = s_buff + 1;
        while('}' != *c_buff && c_buff < e_buff)
        {
            c_buff ++;
        }

        if(c_buff >= e_buff)
        {
            return (EC_TRUE);
        }

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_sdisc_recver: "
                                             "recv '%.*s' done\n",
                                             (uint32_t)(c_buff - s_buff + 1), (char *)s_buff);
        s_buff ++;
        *c_buff = '\0';

        segs_num = c_str_split((char *)s_buff, (const char *)"|",
                                (char **)segs, sizeof(segs)/sizeof(segs[0]));

        s_buff = c_buff + 1; /*update*/

        /* seq_no, ngx, tcid, ipv4, port
        *
        * jason: {"service":"ngx","tcid":"10.10.67.18","ipv4":"127.0.0.1", "bgn":"618"}
        * string: ngx|<tcid>|<ipv4>|<bgn port>
        *
        */

        if(5 != segs_num)
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_sdisc_recver: "
                                                 "segs num %u is invalid => ignore\n",
                                                 segs_num);
            continue;
        }

        /*skip seq_no*/

        seg = segs[1];
        if(0 != STRCASECMP(seg, "ngx"))
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_sdisc_recver: "
                                                 "recv '%s' is not ngx => ignore\n",
                                                 seg);
            continue;
        }

        seg = segs[2];
        ngx_tcid = c_ipv4_to_word(seg);
        if(0 == ngx_tcid)
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_sdisc_recver: "
                                                 "recv '%s' invalid tcid => ignore\n",
                                                 seg);
            continue;
        }

        seg = segs[3];
        ngx_ipv4 = c_ipv4_to_word(seg);
        if(0 == ngx_ipv4)
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_sdisc_recver: "
                                                 "recv '%s' invalid ipv4 => ignore\n",
                                                 seg);
            continue;
        }

        seg = segs[4];
        ngx_bgn_port = c_str_to_word(seg);
        if(0 != (ngx_bgn_port & ~(0xFFFF)))
        {
            dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_sdisc_recver: "
                                                 "recv '%s' invalid bgn port => ignore\n",
                                                 seg);
            continue;
        }

        /*connect ngx if necessary*/

        MOD_NODE_TCID(&recv_mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&recv_mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&recv_mod_node) = 0;/*only one super*/

        task_p2p_no_wait(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &recv_mod_node,
                         NULL_PTR,
                         FI_super_add_connection, CMPI_ERROR_MODI, ngx_tcid, CMPI_ANY_COMM, ngx_ipv4, ngx_bgn_port,
                         (UINT32)CSOCKET_CNODE_NUM);

    }
    return (EC_TRUE);
}

/**
*
* wait sync bit flag cleared
*
**/
EC_BOOL cxfs_sync_wait(const UINT32 cxfs_md_id)
{
    CXFS_MD  *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_sync_wait: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        uint64_t        wait_msec;

        for(wait_msec = 0;
            BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md) && wait_msec < CXFS_WAIT_SYNC_MAX_MSEC;
            wait_msec ++)
        {
            coroutine_usleep(1 /*msec*/, LOC_CXFS_0003);
        }

        if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md)) /*wait sync completion failed*/
        {
            return (EC_FALSE);
        }
    }

    return (EC_TRUE);
}

/**
*
* process sync CXFS to disk
*
* warning: cannot rollback if failed
*
**/
EC_BOOL cxfs_sync_do(const UINT32 cxfs_md_id)
{
    CXFS_MD  *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_sync_do: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR != CXFS_MD_DN(cxfs_md)
    && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))
    && NULL_PTR != CXFS_MD_NP_CMMAP_NODE(cxfs_md)
    && NULL_PTR != CXFS_MD_DN_CMMAP_NODE(cxfs_md))
    {
        CXFSCFG         *cxfscfg;
        CXFSZONE        *np_zone;
        CXFSZONE        *dn_zone;
        CAMD_MD         *camd_md;
        MOD_NODE         mod_node;

        /*note: when CXFS_OP_SWITCH = OFF, active zone and standby zone is same one*/

        cxfscfg = CXFS_MD_CFG(cxfs_md);
        np_zone = CXFSCFG_NP_ZONE(cxfscfg, CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg));
        dn_zone = CXFSCFG_DN_ZONE(cxfscfg, CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg));
        camd_md = CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md));

        if(NULL_PTR != CXFS_MD_NP_CMMAP_NODE(cxfs_md))
        {
            if(EC_FALSE == cmmap_node_sync(CXFS_MD_NP_CMMAP_NODE(cxfs_md),
                                            camd_md,
                                            CXFSZONE_S_OFFSET(np_zone)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync_do: sync npp failed! => stop xfs\n");

                cxfs_end(cxfs_md_id);
                return (EC_FALSE);
            }

            cmmap_node_free(CXFS_MD_NP_CMMAP_NODE(cxfs_md));
            CXFS_MD_NP_CMMAP_NODE(cxfs_md) = NULL_PTR;

            /*switch zone*/
            CXFSCFG_NP_ZONE_SWITCH(cxfscfg);

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync_do: sync npp done\n");
        }

        if(NULL_PTR != CXFS_MD_DN_CMMAP_NODE(cxfs_md))
        {
            if(EC_FALSE == cmmap_node_sync(CXFS_MD_DN_CMMAP_NODE(cxfs_md),
                                            camd_md,
                                            CXFSZONE_S_OFFSET(dn_zone)))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync_do: sync dn failed! => stop xfs\n");

                cxfs_end(cxfs_md_id);
                return (EC_FALSE);
            }

            cmmap_node_free(CXFS_MD_DN_CMMAP_NODE(cxfs_md));
            CXFS_MD_DN_CMMAP_NODE(cxfs_md) = NULL_PTR;

            /*switch zone*/
            CXFSCFG_DN_ZONE_SWITCH(cxfscfg);

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync_do: sync dn done\n");
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync_do: "
                                             "trigger dump cfg\n");

        MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&mod_node) = cxfs_md_id;

        task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &mod_node,
                         NULL_PTR,
                         FI_cxfs_dump_cfg, CMPI_ERROR_MODI);

        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync_do: invalid state => stop xfs\n");

    cxfs_end(cxfs_md_id);

    return (EC_FALSE);
}

/**
*
* sync CXFS to disk
*
**/
EC_BOOL cxfs_sync(const UINT32 cxfs_md_id)
{
    CXFS_MD  *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_sync: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    //ASSERT(BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md));
#if 0
    if(BIT_TRUE == CXFS_MD_OP_DUMP_FLAG(cxfs_md))
    {
        /*wait dump completed*/
        task_brd_process_add(task_brd_default_get(),
                             (TASK_BRD_CALLBACK)cxfs_sync,
                             (void *)cxfs_md_id);

        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_sync: "
                                             "add process to wait dump completed\n");

        return (EC_TRUE);
    }
#endif
    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_TRUE; /*set sync mode*/
    }

    /*now in sync mode*/
    if(EC_FALSE == cxfsdn_can_sync(CXFS_MD_DN(cxfs_md)))
    {
        /*wait sync enabled*/
        task_brd_process_add(task_brd_default_get(),
                             (TASK_BRD_CALLBACK)cxfs_sync,
                             (void *)cxfs_md_id);

        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_sync: "
                                             "add process to wait sync enabled\n");

        return (EC_TRUE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md)
    || NULL_PTR == CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync: "
                                             "dn or camd is null\n");

        CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_FALSE; /*quit sync mode*/

        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NP_CMMAP_NODE(cxfs_md)
    && NULL_PTR == CXFS_MD_DN_CMMAP_NODE(cxfs_md))
    {
        MOD_NODE            mod_node;

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
        {
            CXFS_MD_NP_CMMAP_NODE(cxfs_md) = cxfsnp_mgr_create_cmmap_node(CXFS_MD_NPP(cxfs_md));
            if(NULL_PTR == CXFS_MD_NP_CMMAP_NODE(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync: npp create cmmap_node failed\n");

                CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_FALSE; /*quit sync mode*/
                return (EC_FALSE);
            }
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync: npp create cmmap_node done\n");
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md))
        {
            CXFS_MD_DN_CMMAP_NODE(cxfs_md) = cxfsdn_create_cmmap_node(CXFS_MD_DN(cxfs_md));
            if(NULL_PTR == CXFS_MD_DN_CMMAP_NODE(cxfs_md))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_sync: dn create cmmap_node failed\n");

                cmmap_node_free(CXFS_MD_NP_CMMAP_NODE(cxfs_md));
                CXFS_MD_NP_CMMAP_NODE(cxfs_md) = NULL_PTR;

                CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_FALSE; /*quit sync mode*/
                return (EC_FALSE);
            }
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync: dn create cmmap_node done\n");
        }

        /*cannot rollback from here*/
        CXFS_MD_SYNC_FLAG(cxfs_md)                      = BIT_FALSE; /*unset sync mode*/
        CXFS_MD_OP_DUMP_OFFSET(cxfs_md)                 = 0;         /*rewind op dump offset*/
        CXFSCFG_OP_DUMP_TIME_MSEC(CXFS_MD_CFG(cxfs_md)) = c_get_cur_time_msec();

        MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&mod_node) = cxfs_md_id;

        task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &mod_node,
                         NULL_PTR,
                         FI_cxfs_sync_do, CMPI_ERROR_MODI);

        if(SWITCH_ON == CXFS_OP_SWITCH)
        {
            task_brd_process_add(task_brd_default_get(),
                                (TASK_BRD_CALLBACK)cxfs_process_op,
                                (void *)cxfs_md_id);
        }
        return (EC_TRUE);
    }

    /*wait previous sync completed*/
    task_brd_process_add(task_brd_default_get(),
                         (TASK_BRD_CALLBACK)cxfs_sync,
                         (void *)cxfs_md_id);

    return (EC_TRUE);
}

EC_BOOL cxfs_flush(const UINT32 cxfs_md_id)
{
    CXFS_MD  *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_flush: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    if(CXFSCFG_SATA_META_SIZE(cxfscfg) < CXFSCFG_SIZE
                                       + CXFS_SATA_BAD_BITMAP_SIZE_NBYTES)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_load_sata_bad_bitmap: "
                                             "invalid sata disk size %ld\n",
                                             CXFSCFG_SATA_META_SIZE(cxfscfg));
        return (EC_FALSE);
    }

    offset = CXFSCFG_OFFSET(cxfscfg) + CXFSCFG_SIZE;
    offset_saved = offset;

    CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = cpg_bitmap_new(CXFS_SATA_BAD_BITMAP_SIZE_NBYTES,
                                                      CXFS_SATA_BAD_BITMAP_SIZE_NBITS,
                                                      CXFS_SATA_BAD_BITMAP_MEM_ALIGN);
    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_load_sata_bad_bitmap: "
                                             "new sata bad bitmap failed\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_file_pread(CXFS_MD_SATA_META_FD(cxfs_md), &offset,
                                CXFS_SATA_BAD_BITMAP_SIZE_NBYTES,
                                (UINT8 *)CXFS_MD_SATA_BAD_BITMAP(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_load_sata_bad_bitmap: "
                                             "load sata bad bitmap from fd %d, offset %ld, size %u failed\n",
                                             CXFS_MD_SATA_META_FD(cxfs_md),
                                             offset_saved, CXFS_SATA_BAD_BITMAP_SIZE_NBYTES);

        cpg_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
        CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = NULL_PTR;

        return (EC_FALSE);
    }

    cpg_bitmap_revise(CXFS_MD_SATA_BAD_BITMAP(cxfs_md), CXFS_SATA_BAD_BITMAP_SIZE_NBITS);

    CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md) = CPG_BITMAP_USED(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_load_sata_bad_bitmap: "
                                         "load sata bad bitmap from fd %d, offset %ld, size %u done\n",
                                         CXFS_MD_SATA_META_FD(cxfs_md),
                                         offset_saved, CXFS_SATA_BAD_BITMAP_SIZE_NBYTES);

    return (EC_TRUE);
}

/*flush bad bitmap to sata disk*/
EC_BOOL cxfs_flush_sata_bad_bitmap(CXFS_MD *cxfs_md)
{
    CXFSCFG    *cxfscfg;

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md)
    && ERR_FD != CXFS_MD_SATA_META_FD(cxfs_md))
    {
        UINT32   sata_bad_bitmap_offset;
        UINT32   sata_bad_bitmap_offset_saved;
        UINT32   sata_bad_bitmap_size;

        sata_bad_bitmap_offset  = CXFSCFG_OFFSET(cxfscfg) + CXFSCFG_SIZE;
        sata_bad_bitmap_size    = CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

        sata_bad_bitmap_offset_saved = sata_bad_bitmap_offset;

        if(EC_FALSE == c_file_pwrite(CXFS_MD_SATA_META_FD(cxfs_md),
                                     &sata_bad_bitmap_offset,
                                     sata_bad_bitmap_size,
                                     (const UINT8 *)CXFS_MD_SATA_BAD_BITMAP(cxfs_md)))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush_sata_bad_bitmap: "
                                                 "flush sata bad bitmap to fd %d "
                                                 "with offset %ld, size %ld failed\n",
                                                 CXFS_MD_SATA_META_FD(cxfs_md),
                                                 sata_bad_bitmap_offset_saved,
                                                 sata_bad_bitmap_size);
            return (EC_FALSE);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_flush_sata_bad_bitmap: "
                                             "flush sata bad bitmap to fd %d "
                                             "with offset %ld, size %ld done\n",
                                             CXFS_MD_SATA_META_FD(cxfs_md),
                                             sata_bad_bitmap_offset_saved,
                                             sata_bad_bitmap_size);
    }

    return (EC_TRUE);
}

/*sync bad bitmap to sata disk*/
EC_BOOL cxfs_sync_sata_bad_bitmap(CXFS_MD *cxfs_md)
{
    CXFSCFG            *cxfscfg;
    CPG_BITMAP         *sata_bad_bitmap;

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    sata_bad_bitmap = CXFS_MD_SATA_BAD_BITMAP(cxfs_md);

    if(NULL_PTR != sata_bad_bitmap
    && CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md) != CPG_BITMAP_USED(sata_bad_bitmap)
    && NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        uint64_t  time_msec_cur;

        time_msec_cur = c_get_cur_time_msec();

        if(time_msec_cur >= CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md))
        {
            UINT32   sata_bad_bitmap_offset;
            UINT32   sata_bad_bitmap_size;

            sata_bad_bitmap_offset  = CXFSCFG_OFFSET(cxfscfg) + CXFSCFG_SIZE;
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


                task_brd_process_add(task_brd_default_get(),
                                    (TASK_BRD_CALLBACK)cxfs_sync_sata_bad_bitmap,
                                    (void *)cxfs_md);
                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_sync_sata_bad_bitmap: "
                                                 "sync sata bad bitmap to sata "
                                                 "offset %ld, size %ld done\n",
                                                 sata_bad_bitmap_offset,
                                                 sata_bad_bitmap_size);

            CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)   = CPG_BITMAP_USED(sata_bad_bitmap); /*update*/

            CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md) = time_msec_cur + 60 * 1000; /*60s later*/

            task_brd_process_add(task_brd_default_get(),
                                (TASK_BRD_CALLBACK)cxfs_sync_sata_bad_bitmap,
                                (void *)cxfs_md);
            return (EC_TRUE);
        }
    }

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_sync_sata_bad_bitmap,
                        (void *)cxfs_md);
    return (EC_FALSE);
}

/*close bad bitmap without flushing*/
EC_BOOL cxfs_close_sata_bad_bitmap(CXFS_MD *cxfs_md)
{
    if(NULL_PTR != CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
       cpg_bitmap_free(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));
       CXFS_MD_SATA_BAD_BITMAP(cxfs_md)     = NULL_PTR;

       CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md)   = 0;
       CXFS_MD_SATA_BAD_SYNC_NTIME(cxfs_md) = 0;
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_stat_init(CXFS_STAT *cxfs_stat)
{
    CXFS_STAT_READ_COUNTER(cxfs_stat)             = 0;
    CXFS_STAT_READ_NP_SUCC_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_NP_FAIL_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_DN_SUCC_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_DN_FAIL_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_NBYTES(cxfs_stat)              = 0;
    CXFS_STAT_READ_COST_MSEC(cxfs_stat)           = 0;

    CXFS_STAT_WRITE_COUNTER(cxfs_stat)            = 0;
    CXFS_STAT_WRITE_NP_SUCC_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_NP_FAIL_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_DN_SUCC_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_DN_FAIL_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_NBYTES(cxfs_stat)             = 0;
    CXFS_STAT_WRITE_COST_MSEC(cxfs_stat)          = 0;

    CXFS_STAT_UPDATE_COUNTER(cxfs_stat)           = 0;
    CXFS_STAT_UPDATE_SUCC_COUNTER(cxfs_stat)      = 0;
    CXFS_STAT_UPDATE_FAIL_COUNTER(cxfs_stat)      = 0;
    CXFS_STAT_UPDATE_NBYTES(cxfs_stat)            = 0;
    CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat)         = 0;

    CXFS_STAT_RENEW_COUNTER(cxfs_stat)            = 0;
    CXFS_STAT_RENEW_SUCC_COUNTER(cxfs_stat)       = 0;
    CXFS_STAT_RENEW_FAIL_COUNTER(cxfs_stat)       = 0;
    CXFS_STAT_RENEW_NBYTES(cxfs_stat)             = 0;
    CXFS_STAT_RENEW_COST_MSEC(cxfs_stat)          = 0;

    CXFS_STAT_DELETE_COUNTER(cxfs_stat)           = 0;

    CXFS_STAT_RETIRE_COUNTER(cxfs_stat)           = 0;
    CXFS_STAT_RETIRE_COMPLETE(cxfs_stat)          = 0;

    CXFS_STAT_RECYCLE_COUNTER(cxfs_stat)          = 0;
    CXFS_STAT_RECYCLE_COMPLETE(cxfs_stat)         = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_stat_clean(CXFS_STAT *cxfs_stat)
{
    CXFS_STAT_READ_COUNTER(cxfs_stat)             = 0;
    CXFS_STAT_READ_NP_SUCC_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_NP_FAIL_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_DN_SUCC_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_DN_FAIL_COUNTER(cxfs_stat)     = 0;
    CXFS_STAT_READ_NBYTES(cxfs_stat)              = 0;
    CXFS_STAT_READ_COST_MSEC(cxfs_stat)           = 0;

    CXFS_STAT_WRITE_COUNTER(cxfs_stat)            = 0;
    CXFS_STAT_WRITE_NP_SUCC_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_NP_FAIL_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_DN_SUCC_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_DN_FAIL_COUNTER(cxfs_stat)    = 0;
    CXFS_STAT_WRITE_NBYTES(cxfs_stat)             = 0;
    CXFS_STAT_WRITE_COST_MSEC(cxfs_stat)          = 0;

    CXFS_STAT_UPDATE_COUNTER(cxfs_stat)           = 0;
    CXFS_STAT_UPDATE_SUCC_COUNTER(cxfs_stat)      = 0;
    CXFS_STAT_UPDATE_FAIL_COUNTER(cxfs_stat)      = 0;
    CXFS_STAT_UPDATE_NBYTES(cxfs_stat)            = 0;
    CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat)         = 0;

    CXFS_STAT_RENEW_COUNTER(cxfs_stat)            = 0;
    CXFS_STAT_RENEW_SUCC_COUNTER(cxfs_stat)       = 0;
    CXFS_STAT_RENEW_FAIL_COUNTER(cxfs_stat)       = 0;
    CXFS_STAT_RENEW_NBYTES(cxfs_stat)             = 0;
    CXFS_STAT_RENEW_COST_MSEC(cxfs_stat)          = 0;

    CXFS_STAT_DELETE_COUNTER(cxfs_stat)           = 0;

    CXFS_STAT_RETIRE_COUNTER(cxfs_stat)           = 0;
    CXFS_STAT_RETIRE_COMPLETE(cxfs_stat)          = 0;

    CXFS_STAT_RECYCLE_COUNTER(cxfs_stat)          = 0;
    CXFS_STAT_RECYCLE_COMPLETE(cxfs_stat)         = 0;

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_state: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_set_state: cxfs module #%ld: state %lx -> %lx\n",
                        cxfs_md_id, CXFS_MD_STATE(cxfs_md), cxfs_state);

    CXFS_MD_STATE(cxfs_md) = cxfs_state;

    return (EC_TRUE);
}

UINT32 cxfs_get_state(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_get_state: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    return CXFS_MD_STATE(cxfs_md);
}

EC_BOOL cxfs_is_state(const UINT32 cxfs_md_id, const UINT32 cxfs_state)
{
    CXFS_MD   *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_state: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_read_only: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_unset_read_only: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_read_only: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_get_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_get_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    return CXFS_MD_DN(cxfs_md);
}

/**
*
*  get stat of the module
*
**/
CXFS_STAT *cxfs_get_stat(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_get_stat: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    return CXFS_MD_STAT(cxfs_md);
}

/**
*
*  open name node pool
*
**/
EC_BOOL cxfs_open_npp(const UINT32 cxfs_md_id)
{
    CXFS_MD   *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_open_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR != CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_open_npp: npp was open\n");
        return (EC_FALSE);
    }

    CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr_open(CXFS_MD_SATA_META_FD(cxfs_md), CXFS_MD_CFG(cxfs_md));
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_close_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_npp_and_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md) || NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_compute_cfg(const UINT32 cxfs_md_id,
                             const UINT32 cxfsnp_model,
                             const UINT32 cxfsnp_max_num)
{
    CXFS_MD        *cxfs_md;
    CXFSCFG        *cxfscfg;

    UINT32          sata_disk_size;
    UINT32          sata_meta_size;

    UINT32          np_size;
    UINT32          np_zone_size;
    UINT32          np_meta_size;

    UINT32          dn_zone_size;
    UINT32          dn_meta_size;
    UINT32          mask;

    UINT32          vdisk_size;
    UINT32          vdisk_num;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfscfg = CXFS_MD_CFG(cxfs_md);

    sata_disk_size = CXFSCFG_SATA_DISK_SIZE(cxfscfg);
    sata_meta_size = CXFSCFG_SATA_META_SIZE(cxfscfg);
    vdisk_size     = CXFSCFG_SATA_VDISK_SIZE(cxfscfg);
    vdisk_num      = CXFSCFG_SATA_VDISK_NUM(cxfscfg);

    if(EC_FALSE == cxfsnp_model_file_size((uint8_t)cxfsnp_model, &np_size))
    {
        dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfs_compute_cfg: "
                                                  "invalid np_model %u\n",
                                                  (uint8_t)cxfsnp_model);
        return (EC_FALSE);
    }

    np_zone_size  = (cxfsnp_max_num * np_size);

    /*single data node meta data size*/
    dn_zone_size  = cxfspgv_size(vdisk_num);
    mask          = (CXFSDN_MEM_ALIGNMENT - 1);
    dn_zone_size  = VAL_ALIGN_NEXT(dn_zone_size, mask);

    np_meta_size  = 0; /*make GCC happy*/
    dn_meta_size  = 0; /*make GCC happy*/

    if(SWITCH_ON == CXFS_OP_SWITCH) /*active and standy zones*/
    {
        np_meta_size = np_zone_size * 2;

        /*active dn zone and standby dn zone*/
        dn_meta_size = dn_zone_size * 2;
    }

    if(SWITCH_OFF == CXFS_OP_SWITCH) /*only active zone*/
    {
        np_meta_size = np_zone_size;

        dn_meta_size = dn_zone_size;
    }

    if(CXFS_MD_SATA_META_FD(cxfs_md) == CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        UINT32      total_space_size;

        ASSERT(vdisk_num * vdisk_size == CXFSCFG_OFFSET(cxfscfg));
        ASSERT(CXFSCFG_OFFSET(cxfscfg) < CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg));

        total_space_size = CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg) /*size of that before np zone*/
                         + np_meta_size
                         + dn_meta_size
                         ;

        if(total_space_size > sata_disk_size)
        {
           dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfs_compute_cfg: "
                                                     "total_space_size %ld > sata_disk_size %ld\n",
                                                     total_space_size, sata_disk_size);
           return (EC_FALSE);
        }
    }

    if(CXFS_MD_SATA_META_FD(cxfs_md) != CXFS_MD_SATA_DISK_FD(cxfs_md))
    {
        UINT32      meta_data_size;

        meta_data_size = CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg) /*size of that before np zone*/
                       + np_meta_size
                       + dn_meta_size
                       ;

        if(meta_data_size > sata_meta_size)
        {
           dbg_log(SEC_0190_CXFSNPMGR, 0)(LOGSTDOUT, "error:cxfs_compute_cfg: "
                                                     "meta_data_size %ld > sata_meta_size %ld\n",
                                                     meta_data_size, sata_meta_size);
           return (EC_FALSE);
        }
    }

    CXFSCFG_DN_ZONE_SIZE(cxfscfg) = dn_zone_size;

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_create_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

    if(ERR_FD == CXFS_MD_SATA_META_FD(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: no sata fd\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_compute_cfg(cxfs_md_id, cxfsnp_model, cxfsnp_max_num))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_npp: compuate cfg failed\n");
        return (EC_FALSE);
    }

    cxfsnp_mgr = cxfsnp_mgr_create((uint8_t ) cxfsnp_model,
                                   (uint32_t) cxfsnp_max_num,
                                   (uint8_t ) cxfsnp_2nd_chash_algo_id,
                                   CXFS_MD_SATA_META_FD(cxfs_md),
                                   CXFSCFG_SATA_META_SIZE(cxfscfg),
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

    if(SWITCH_ON == CXFS_OP_SWITCH) /*active and standy zones*/
    {
        cxfszone = CXFSCFG_NP_ZONE(cxfscfg, 0);
        CXFSZONE_S_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 0 * np_total_size;
        CXFSZONE_E_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 1 * np_total_size;

        cxfszone = CXFSCFG_NP_ZONE(cxfscfg, 1);
        CXFSZONE_S_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 1 * np_total_size;
        CXFSZONE_E_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 2 * np_total_size;

        CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)      = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 0 * np_total_size;
        CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg)      = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 2 * np_total_size;
    }

    if(SWITCH_OFF == CXFS_OP_SWITCH) /*only active zone*/
    {
        cxfszone = CXFSCFG_NP_ZONE(cxfscfg, 0);
        CXFSZONE_S_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 0 * np_total_size;
        CXFSZONE_E_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 1 * np_total_size;

        cxfszone = CXFSCFG_NP_ZONE(cxfscfg, 1);
        CXFSZONE_S_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 0 * np_total_size;
        CXFSZONE_E_OFFSET(cxfszone)            = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 1 * np_total_size;

        CXFSCFG_NP_ZONE_S_OFFSET(cxfscfg)      = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 0 * np_total_size;
        CXFSCFG_NP_ZONE_E_OFFSET(cxfscfg)      = CXFSNP_MGR_NP_S_OFFSET(cxfsnp_mgr) + 1 * np_total_size;
    }

    CXFS_MD_NPP(cxfs_md) = cxfsnp_mgr;

    /*op mgr*/
    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR != cxfsnp_mgr
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsnp_mgr_mount_op_mgr(cxfsnp_mgr, CXFS_MD_OP_MGR(cxfs_md));
    }

    return (EC_TRUE);
}

/**
*
*  dump name node pool to specific np zone
*
**/
EC_BOOL cxfs_dump_npp(const UINT32 cxfs_md_id, const UINT32 np_zone_idx)
{
    CXFS_MD     *cxfs_md;
    CXFSCFG     *cxfscfg;
    CXFSZONE    *cxfszone;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfscfg = CXFS_MD_CFG(cxfs_md);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_npp: "
                                             "npp is null\n");
        return (EC_FALSE);
    }

    if(ERR_FD == CXFS_MD_SATA_META_FD(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_npp: "
                                             "no sata meta fd\n");
        return (EC_FALSE);
    }

    /*np zone*/
    cxfszone = CXFSCFG_NP_ZONE(cxfscfg, np_zone_idx);

    if(EC_FALSE == cxfsnp_mgr_dump(CXFS_MD_NPP(cxfs_md), CXFSZONE_S_OFFSET(cxfszone)))
    {
        task_brd_update_time_default();
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_npp: "
                                             "dump npp to zone %ld (active %ld, standby %ld)failed\n",
                                             np_zone_idx,
                                             CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg),
                                             CXFSCFG_NP_ZONE_STANDBY_IDX(cxfscfg));
        return (EC_FALSE);
    }
    task_brd_update_time_default();
    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_dump_npp: "
                                         "dump npp to zone %ld (active %ld, standby %ld) done\n",
                                         np_zone_idx,
                                         CXFSCFG_NP_ZONE_ACTIVE_IDX(cxfscfg),
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
    CXFSCFG     *cxfscfg;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_create_sata_bad_bitmap: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
    {
        CXFS_MD_SATA_BAD_BITMAP(cxfs_md) = cpg_bitmap_new(CXFS_SATA_BAD_BITMAP_SIZE_NBYTES,
                                                          CXFS_SATA_BAD_BITMAP_SIZE_NBITS,
                                                          CXFS_SATA_BAD_BITMAP_MEM_ALIGN);
        if(NULL_PTR == CXFS_MD_SATA_BAD_BITMAP(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_create_sata_bad_bitmap: "
                                                 "create sata bad bitmap failed\n");
            return (EC_FALSE);
        }

        CXFS_MD_SATA_BAD_PAGE_NUM(cxfs_md) = CPG_BITMAP_USED(CXFS_MD_SATA_BAD_BITMAP(cxfs_md));

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

            sata_bad_bitmap_offset  = CXFSCFG_OFFSET(cxfscfg) + CXFSCFG_SIZE;
            sata_bad_bitmap_size    = CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

            cxfsdn_sync_sata_bad_bitmap(CXFS_MD_DN(cxfs_md),
                                        sata_bad_bitmap_offset,
                                        sata_bad_bitmap_size);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_sata_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_unset_sata_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_sata_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_sata_bad_pages: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

    cpg_bitmap_print(log, CAMD_MD_SATA_BAD_BITMAP(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))));

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_set_ssd_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_unset_ssd_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_ssd_bad_page: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_ssd_bad_pages: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

    cpg_bitmap_print(log, CAMD_MD_SSD_BAD_BITMAP(CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))));

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_find_dir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_find_file: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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
*  check existing of a file
*
**/
EC_BOOL cxfs_is_file(const UINT32 cxfs_md_id, const CSTRING *file_path)
{
#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_file: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    return cxfs_find_file(cxfs_md_id, file_path);
}

/**
*
*  check existing of a dir
*
**/
EC_BOOL cxfs_is_dir(const UINT32 cxfs_md_id, const CSTRING *dir_path)
{
#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_is_dir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    return cxfs_find_dir(cxfs_md_id, dir_path);
}

/**
*
*  reserve space from dn
*
**/
STATIC_CAST static EC_BOOL __cxfs_reserve_hash_dn(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 data_len, CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_INODE *cxfsnp_inode;
    CXFSPGV      *cxfspgv;

    uint32_t size;
    uint32_t path_hash;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;
    uint16_t fail_tries;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_reserve_hash_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < data_len)
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

    /*calculate hash value of file_path*/
    path_hash = (uint32_t)MD5_hash(cstring_get_len(file_path), cstring_get_str(file_path));

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
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:__cxfs_reserve_hash_dn: "
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

STATIC_CAST static EC_BOOL __cxfs_reserve_no_hash_dn(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 data_len, CXFSNP_FNODE *cxfsnp_fnode)
{
    CXFS_MD      *cxfs_md;
    CXFSNP_INODE *cxfsnp_inode;
    CXFSPGV      *cxfspgv;

    uint32_t size;

    uint16_t disk_no;
    uint16_t block_no;
    uint16_t page_no;

    uint16_t disk_idx;
    uint16_t disk_num;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_reserve_no_hash_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < data_len)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_no_hash_dn: data_len %ld overflow\n", data_len);
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_no_hash_dn: no dn was open\n");
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_no_hash_dn: no pgv exist\n");
        return (EC_FALSE);
    }

    cxfspgv = CXFSDN_CXFSPGV(CXFS_MD_DN(cxfs_md));
    if(NULL_PTR == CXFSPGV_HEADER(cxfspgv))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_no_hash_dn: pgv header is null\n");
        return (EC_FALSE);
    }

    if(0 == CXFSPGV_DISK_NUM(cxfspgv))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_reserve_no_hash_dn: pgv has no disk yet\n");
        return (EC_FALSE);
    }

    size     = (uint32_t)(data_len);

    disk_num = CXFSPGV_DISK_NUM(cxfspgv);
    disk_no  = CXFS_MD_CUR_DISK_NO(cxfs_md);

    for(disk_idx = 0; disk_idx < disk_num; disk_idx ++)
    {
        CXFSPGD     *cxfspgd;

        cxfspgd = CXFSPGV_DISK_NODE(cxfspgv, disk_no);

        if(EC_TRUE == cxfspgd_is_full(cxfspgd))
        {
            /*move to next disk*/
            disk_no = (disk_no + 1) % disk_num;
            CXFS_MD_CUR_DISK_NO(cxfs_md) = disk_no;
            continue;
        }

        while(EC_TRUE == cxfspgv_new_space_from_disk(cxfspgv, size, disk_no, &block_no, &page_no))
        {
            if(EC_FALSE == cxfsdn_cover_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no))
            {
                cxfsnp_fnode_init(cxfsnp_fnode);
                CXFSNP_FNODE_FILESZ(cxfsnp_fnode) = size;
                CXFSNP_FNODE_REPNUM(cxfsnp_fnode) = 1;

                cxfsnp_inode = CXFSNP_FNODE_INODE(cxfsnp_fnode, 0);
                CXFSNP_INODE_DISK_NO(cxfsnp_inode)    = disk_no;
                CXFSNP_INODE_BLOCK_NO(cxfsnp_inode)   = block_no;
                CXFSNP_INODE_PAGE_NO(cxfsnp_inode)    = page_no;

                dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] __cxfs_reserve_no_hash_dn: "
                                                     "size %u => (disk %u, block %u, page %u)\n",
                                                     size, disk_no, block_no, page_no);

                return (EC_TRUE);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] __cxfs_reserve_no_hash_dn: "
                                                 "(disk %u, block %u, page %u), size %u cover bad page\n",
                                                 disk_no, block_no, page_no, size);

            cxfsdn_discard_sata_bad_page(CXFS_MD_DN(cxfs_md), size, disk_no, block_no, page_no);
         }

        /*move to next disk*/
        disk_no = (disk_no + 1) % disk_num;
        CXFS_MD_CUR_DISK_NO(cxfs_md) = disk_no;

        /*try to retire & recycle some files*/
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:__cxfs_reserve_no_hash_dn: "
                                             "no %ld bytes space, try to retire & recycle\n",
                                             data_len);
        cxfs_retire(cxfs_md_id, (UINT32)CXFSNP_TRY_RETIRE_MAX_NUM, NULL_PTR);
        cxfs_recycle(cxfs_md_id, (UINT32)CXFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);
    }

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error::__cxfs_reserve_no_hash_dn: "
                                         "no %ld bytes space\n",
                                         data_len);
    return (EC_FALSE);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_reserve_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_reserve_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < data_len)
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

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_reserve_dn: (disk %u, block %u, page %u), size %u cover bad page\n",
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_release_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_recycle_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

    uint64_t      s_msec;
    uint64_t      e_msec;
    uint64_t      cost_msec;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    s_msec = c_get_cur_time_msec();

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    cxfsnp_fnode = __cxfs_reserve_npp(cxfs_md_id, file_path);
    if(NULL_PTR == cxfsnp_fnode)
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_NP_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write: file %s reserve npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    CXFS_STAT_WRITE_NP_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;

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

    if(SWITCH_ON == CXFS_LRU_MODEL_SWITCH
    && EC_FALSE == __cxfs_reserve_hash_dn(cxfs_md_id, file_path, CBYTES_LEN(cbytes), cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write: [lru] reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/

        return (EC_FALSE);
    }

    if(SWITCH_ON == CXFS_FIFO_MODEL_SWITCH
    && EC_FALSE == __cxfs_reserve_no_hash_dn(cxfs_md_id, file_path, CBYTES_LEN(cbytes), cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write: [fifo] reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/

        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_export_dn(cxfs_md_id, cbytes, cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        cxfs_release_dn(cxfs_md_id, cxfsnp_fnode);

        __cxfs_release_npp(cxfs_md_id, file_path);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path); /*patch*/
        return (EC_FALSE);
    }

    e_msec = c_get_cur_time_msec();
    cost_msec = e_msec - s_msec;

    CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
    CXFS_STAT_WRITE_DN_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    CXFS_STAT_WRITE_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

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

    uint64_t      s_msec;
    uint64_t      e_msec;
    uint64_t      cost_msec;

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    s_msec = c_get_cur_time_msec();

    cxfsnp_fnode = __cxfs_reserve_npp(cxfs_md_id, file_path);
    if(NULL_PTR == cxfsnp_fnode)
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_NP_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write_no_lock: file %s reserve npp failed\n", (char *)cstring_get_str(file_path));

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);/*patch*/

        return (EC_FALSE);
    }

    CXFS_STAT_WRITE_NP_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    /*exception*/
    if(0 == CBYTES_LEN(cbytes))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
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

    if(SWITCH_ON == CXFS_LRU_MODEL_SWITCH
    && EC_FALSE == __cxfs_reserve_hash_dn(cxfs_md_id, file_path, CBYTES_LEN(cbytes), cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write_no_lock: [lru] reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);/*patch*/
        return (EC_FALSE);
    }

    if(SWITCH_ON == CXFS_FIFO_MODEL_SWITCH
    && EC_FALSE == __cxfs_reserve_no_hash_dn(cxfs_md_id, file_path, CBYTES_LEN(cbytes), cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write_no_lock: [fifo] reserve dn %u bytes for file %s failed\n",
                            (uint32_t)CBYTES_LEN(cbytes), (char *)cstring_get_str(file_path));

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);/*patch*/
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_export_dn(cxfs_md_id, cbytes, cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        cxfs_release_dn(cxfs_md_id, cxfsnp_fnode);

        __cxfs_release_npp(cxfs_md_id, file_path);

        /*notify all waiters*/
        cxfs_file_notify(cxfs_md_id, file_path);/*patch*/

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_write_no_lock: export file %s content to dn failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    e_msec = c_get_cur_time_msec();
    cost_msec = e_msec - s_msec;

    CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
    CXFS_STAT_WRITE_DN_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    CXFS_STAT_WRITE_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_no_lock: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_safe: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_safe: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_safe: wait syncing timeout\n");
        return (EC_FALSE);
    }

    CXFS_STAT_READ_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    cxfsnp_fnode_init(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_safe: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

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

    CXFS_STAT_READ_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

    //dbg_log(SEC_0192_CXFS, 9)(LOGSTDNULL, "[DEBUG] cxfs_read_safe: read file %s is %.*s\n", (char *)cstring_get_str(file_path), (uint32_t)DMIN(16, cbytes_len(cbytes)), cbytes_buf(cbytes));
    return (EC_TRUE);
}

EC_BOOL cxfs_read(const UINT32 cxfs_md_id, const CSTRING *file_path, CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;
    CXFSDN       *cxfsdn;
    CXFSNP_FNODE  cxfsnp_fnode;

    uint64_t      s_msec;
    uint64_t      e_msec;
    uint64_t      cost_msec;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfsdn  = CXFS_MD_DN(cxfs_md);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read: wait syncing timeout\n");
        return (EC_FALSE);
    }

    s_msec = c_get_cur_time_msec();

    CXFS_STAT_READ_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    cxfsnp_fnode_init(&cxfsnp_fnode);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read: read file %s start\n", (char *)cstring_get_str(file_path));

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;

        CXFS_STAT_READ_NP_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    CXFS_STAT_READ_NP_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read: read file %s from npp done\n", (char *)cstring_get_str(file_path));

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_read: read file %s with size %ld done\n",
                            (char *)cstring_get_str(file_path), CXFSNP_FNODE_FILESZ(&cxfsnp_fnode));
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
    }

    /*exception*/
    if(0 == CXFSNP_FNODE_FILESZ(&cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &cxfsnp_fnode);
        return (EC_TRUE);
    }

    if(NULL_PTR != cbytes)
    {
        if(NULL_PTR != cxfsdn
        && SWITCH_ON == CXFS_CAMD_OVERHEAD_SWITCH
        && EC_TRUE == camd_is_overhead(CXFSDN_CAMD_MD(cxfsdn)))
        {
            CXFS_MD_OVERHEAD_COUNTER(cxfs_md) ++;

            if(0 == (CXFS_MD_OVERHEAD_COUNTER(cxfs_md) % CXFS_CAMD_DISCARD_RATIO)) /*discard 10% reading*/
            {
                e_msec = c_get_cur_time_msec();
                cost_msec = e_msec - s_msec;

                CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
                CXFS_STAT_READ_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

                dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "error:cxfs_read: offset read file %s from dn failed due to camd overload\n",
                                                     (char *)cstring_get_str(file_path));
                return (EC_FALSE);
            }
        }
        else
        {
            CXFS_MD_OVERHEAD_COUNTER(cxfs_md) = 0;
        }

        if(EC_FALSE == cxfs_read_dn(cxfs_md_id, &cxfsnp_fnode, cbytes))
        {
            e_msec = c_get_cur_time_msec();
            cost_msec = e_msec - s_msec;

            CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
            CXFS_STAT_READ_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read: read file %s from dn failed where fnode is \n", (char *)cstring_get_str(file_path));
            cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
            return (EC_FALSE);
        }

        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_READ_DN_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;
        CXFS_STAT_READ_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

        return (EC_TRUE);
    }

    e_msec = c_get_cur_time_msec();
    cost_msec = e_msec - s_msec;

    CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;

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

    uint64_t      s_msec;
    uint64_t      e_msec;
    uint64_t      cost_msec;

    uint32_t      file_old_size;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_e: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: wait syncing timeout\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: cxfs is read-only\n");
        return (EC_FALSE);
    }

    s_msec = c_get_cur_time_msec();

    CXFS_STAT_WRITE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    cxfsnp_fnode_init(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_READ_NP_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    CXFS_STAT_READ_NP_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    file_old_size = CXFSNP_FNODE_FILESZ(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_write_e_dn(cxfs_md_id, &cxfsnp_fnode, offset, max_len, cbytes))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: offset write to dn failed\n");
        return (EC_FALSE);
    }

    CXFS_STAT_WRITE_DN_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    CXFS_STAT_WRITE_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

    if(file_old_size != CXFSNP_FNODE_FILESZ(&cxfsnp_fnode))
    {
        if(EC_FALSE == cxfs_update_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
        {
            e_msec = c_get_cur_time_msec();
            cost_msec = e_msec - s_msec;

            CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
            CXFS_STAT_WRITE_NP_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e: offset write file %s to npp failed\n", (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }

        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_WRITE_NP_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;
    }
    else
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_WRITE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
    }

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
    CXFSDN       *cxfsdn;
    CXFSNP_FNODE  cxfsnp_fnode;

    uint64_t      s_msec;
    uint64_t      e_msec;
    uint64_t      cost_msec;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_e: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    cxfsdn  = CXFS_MD_DN(cxfs_md);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e: wait syncing timeout\n");
        return (EC_FALSE);
    }

    s_msec = c_get_cur_time_msec();

    CXFS_STAT_READ_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    cxfsnp_fnode_init(&cxfsnp_fnode);

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;

        CXFS_STAT_READ_NP_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "error:cxfs_read_e: read file %s from npp failed\n", (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    CXFS_STAT_READ_NP_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

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
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;

        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_read_e: read file %s with zero len from npp and fnode %p is \n", (char *)cstring_get_str(file_path), &cxfsnp_fnode);
        cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
        return (EC_TRUE);
    }

    if(NULL_PTR != cbytes)
    {
        if(NULL_PTR != cxfsdn
        && SWITCH_ON == CXFS_CAMD_OVERHEAD_SWITCH
        && EC_TRUE == camd_is_overhead(CXFSDN_CAMD_MD(cxfsdn)))
        {
            CXFS_MD_OVERHEAD_COUNTER(cxfs_md) ++;

            if(0 == (CXFS_MD_OVERHEAD_COUNTER(cxfs_md) % CXFS_CAMD_DISCARD_RATIO)) /*discard 10% reading*/
            {
                e_msec = c_get_cur_time_msec();
                cost_msec = e_msec - s_msec;

                CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
                CXFS_STAT_READ_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

                dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "error:cxfs_read_e: offset read file %s from dn failed due to camd overload\n",
                                                     (char *)cstring_get_str(file_path));
                return (EC_FALSE);
            }
        }
        else
        {
            CXFS_MD_OVERHEAD_COUNTER(cxfs_md) = 0; /*reset*/
        }

        if(EC_FALSE == cxfs_read_e_dn(cxfs_md_id, &cxfsnp_fnode, offset, max_len, cbytes))
        {
            e_msec = c_get_cur_time_msec();
            cost_msec = e_msec - s_msec;

            CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
            CXFS_STAT_READ_DN_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e: offset read file %s from dn failed where fnode is\n", (char *)cstring_get_str(file_path));
            cxfsnp_fnode_print(LOGSTDOUT, &cxfsnp_fnode);
            return (EC_FALSE);
        }

        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_READ_DN_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        CXFS_STAT_READ_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

        return (EC_TRUE);
    }

    e_msec = c_get_cur_time_msec();
    cost_msec = e_msec - s_msec;

    CXFS_STAT_READ_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;

    return (EC_TRUE);
}

/**
*
*  truncate a file with all zero content
*
**/
EC_BOOL cxfs_truncate_file(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 file_size)
{
    CBYTES      *file_content;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_truncate_file: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(EC_TRUE == cxfs_is_file(cxfs_md_id, file_path))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_truncate_file: "
                                             "file '%s' exists\n",
                                             (char *)cstring_get_str(file_path));

        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < file_size)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_truncate_file: "
                                             "file '%s', size %ld overflow\n",
                                             (char *)cstring_get_str(file_path),
                                             file_size);
        return (EC_FALSE);
    }

    file_content = cbytes_new(file_size);
    if(NULL_PTR == file_content)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_truncate_file: "
                                             "file '%s', size %ld, alloc content failed\n",
                                             (char *)cstring_get_str(file_path),
                                             file_size);
        return (EC_FALSE);
    }

    BSET(CBYTES_BUF(file_content), 0x00, CBYTES_LEN(file_content));

    if(EC_FALSE == cxfs_write(cxfs_md_id, file_path, file_content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_truncate_file: "
                                             "truncate file '%s', size %l failed\n",
                                             (char *)cstring_get_str(file_path),
                                             file_size);
        cbytes_free(file_content);
        return (EC_FALSE);
    }

    cbytes_free(file_content);
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_truncate_file: "
                                         "truncate file '%s', size %ld done\n",
                                         (char *)cstring_get_str(file_path),
                                         file_size);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_cfg: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR != CXFS_MD_DN(cxfs_md)
    && CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
    {
        UINT32      dump_retries;

        /*retry 3 times at most*/

        dump_retries = 0;
        while(EC_FALSE == cxfscfg_dump(CXFS_MD_CFG(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md))))
        {
            dump_retries ++;

            if(3 <= dump_retries)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_cfg: "
                                                     "dump cxfscfg failed #%ld => stop xfs\n",
                                                     dump_retries);
                cxfs_end(cxfs_md_id);
                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_cfg: "
                                                 "dump cxfscfg failed #%ld\n",
                                                 dump_retries);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_dump_cfg: "
                                             "dump cxfscfg done\n");
        return (EC_TRUE);
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

    UINT32     cxfsdn_zone_size; /*cxfs dn meta data size*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_create_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

    cxfsdn_zone_size = CXFSCFG_DN_ZONE_SIZE(cxfscfg); /*note: set when compute cfg*/

    CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg) = 0;

    if(SWITCH_ON == CXFS_OP_SWITCH) /*active and standy zones*/
    {
        cxfszone = CXFSCFG_DN_ZONE(cxfscfg, 0);
        CXFSZONE_S_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 0 * cxfsdn_zone_size;
        CXFSZONE_E_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 1 * cxfsdn_zone_size;

        cxfszone = CXFSCFG_DN_ZONE(cxfscfg, 1);
        CXFSZONE_S_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 1 * cxfsdn_zone_size;
        CXFSZONE_E_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 2 * cxfsdn_zone_size;

        CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg)   = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 2 * cxfsdn_zone_size;

        CXFSCFG_SATA_DISK_OFFSET(cxfscfg)   = 0;
    }

    if(SWITCH_OFF == CXFS_OP_SWITCH) /*only active zone*/
    {
        cxfszone = CXFSCFG_DN_ZONE(cxfscfg, 0);
        CXFSZONE_S_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 0 * cxfsdn_zone_size;
        CXFSZONE_E_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 1 * cxfsdn_zone_size;

        cxfszone = CXFSCFG_DN_ZONE(cxfscfg, 1);
        CXFSZONE_S_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 0 * cxfsdn_zone_size;
        CXFSZONE_E_OFFSET(cxfszone)         = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 1 * cxfsdn_zone_size;

        CXFSCFG_DN_ZONE_E_OFFSET(cxfscfg)   = CXFSCFG_DN_ZONE_S_OFFSET(cxfscfg) + 1 * cxfsdn_zone_size;

        CXFSCFG_SATA_DISK_OFFSET(cxfscfg)   = 0;
    }

    CXFSCFG_MAGIC(cxfscfg)              = CXFSCFG_MAGIC_VAL;

    cxfsdn = cxfsdn_create(cxfscfg,
                           CXFS_MD_SATA_META_FD(cxfs_md),
                           CXFS_MD_SATA_DISK_FD(cxfs_md),
                           CXFSDN_CAMD_MEM_DISK_SIZE,
                           CXFS_MD_SSD_META_FD(cxfs_md),
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

        sata_bad_bitmap_offset  = CXFSCFG_OFFSET(cxfscfg) + CXFSCFG_SIZE;
        sata_bad_bitmap_size    = CXFS_SATA_BAD_BITMAP_SIZE_NBYTES;

        cxfsdn_sync_sata_bad_bitmap(cxfsdn,
                                    sata_bad_bitmap_offset,
                                    sata_bad_bitmap_size);
    }

    /*op mgr*/
    if(SWITCH_ON == CXFS_OP_SWITCH
    && NULL_PTR != CXFSDN_CAMD_MD(cxfsdn)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(cxfsdn));
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_create_dn: mount camd to op mgr done\n");
    }

    CXFS_MD_DN(cxfs_md) = cxfsdn;

    cxfsdn_set_check_page_used_cb(CXFS_MD_DN(cxfs_md),
                                    (void *)cxfs_md_id,
                                    (void *)cxfs_check_adjacent_used);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_create_dn: create dn done\n");

    return (EC_TRUE);
}

/**
*
*  dump data node to specific zone
*
**/
EC_BOOL cxfs_dump_dn(const UINT32 cxfs_md_id, const UINT32 dn_zone_idx)
{
    CXFS_MD   *cxfs_md;
    CXFSCFG   *cxfscfg;
    CXFSZONE  *cxfszone;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);
    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_dn: "
                                             "dn is null\n");
        return (EC_FALSE);
    }

    cxfscfg = CXFS_MD_CFG(cxfs_md);

    cxfszone = CXFSCFG_DN_ZONE(cxfscfg, dn_zone_idx);

    if(EC_FALSE == cxfsdn_dump(CXFS_MD_DN(cxfs_md), CXFSZONE_S_OFFSET(cxfszone)))
    {
        task_brd_update_time_default();
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_dn: "
                                             "dump dn to zone %ld (active %ld, standby %ld) failed\n",
                                             dn_zone_idx,
                                             CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg),
                                             CXFSCFG_DN_ZONE_STANDBY_IDX(cxfscfg));
        return (EC_FALSE);
    }

    task_brd_update_time_default();
    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_dump_dn: "
                                         "dump dn to zone %ld (active %ld, standby %ld) done\n",
                                         dn_zone_idx,
                                         CXFSCFG_DN_ZONE_ACTIVE_IDX(cxfscfg),
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_add_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_del_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_mount_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_umount_disk: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_open_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_open_dn: try to open dn ...\n");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR != CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_open_dn: dn was open\n");
        return (EC_FALSE);
    }

    CXFS_MD_DN(cxfs_md) = cxfsdn_open(CXFS_MD_CFG(cxfs_md),
                                      CXFS_MD_SATA_META_FD(cxfs_md),
                                      CXFS_MD_SATA_DISK_FD(cxfs_md),
                                      CXFS_MD_SSD_META_FD(cxfs_md),
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

    cxfsdn_set_check_page_used_cb(CXFS_MD_DN(cxfs_md),
                                    (void *)cxfs_md_id,
                                    (void *)cxfs_check_adjacent_used);

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_close_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_close_dn: no dn was open\n");
        return (EC_FALSE);
    }

    cxfsdn_close(CXFS_MD_DN(cxfs_md), CXFS_MD_CFG(cxfs_md));
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_export_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    data_len = DMIN(CBYTES_LEN(cbytes), CXFSNP_FNODE_FILESZ(cxfsnp_fnode));

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < data_len)
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_dn: wait syncing timeout\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_dn: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < CBYTES_LEN(cbytes))
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == cbytes)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: "
                                             "cbytes is null\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: wait syncing timeout\n");
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
    disk_no      = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no     = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no      = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

    if(CBYTES_LEN(cbytes) < file_size)
    {
        void        *data;

        if(NULL_PTR != CBYTES_BUF(cbytes))
        {
            safe_free(CBYTES_BUF(cbytes), LOC_CXFS_0004);
            CBYTES_BUF(cbytes) = NULL_PTR;
        }

        data = c_memalign_new(file_size, CMCPGB_PAGE_SIZE_NBYTES);
        if(NULL_PTR == data)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_dn: no memory\n");
            return (EC_FALSE);
        }
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read_dn: file size %u, align %u\n",
                                             file_size, CMCPGB_PAGE_SIZE_NBYTES);

        CBYTES_BUF(cbytes)      = (UINT8 *)data;
        CBYTES_LEN(cbytes)      = 0;
        CBYTES_ALIGNED(cbytes)  = BIT_TRUE;
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_e_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_e_dn: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_e_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: wait syncing timeout\n");
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
    disk_no      = CXFSNP_INODE_DISK_NO(cxfsnp_inode) ;
    block_no     = CXFSNP_INODE_BLOCK_NO(cxfsnp_inode);
    page_no      = CXFSNP_INODE_PAGE_NO(cxfsnp_inode) ;

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
            safe_free(CBYTES_BUF(cbytes), LOC_CXFS_0005);
            CBYTES_BUF(cbytes) = NULL_PTR;
        }

        if(0 < offset_t)
        {
            void        *data;

            data = safe_malloc(max_len_t, LOC_CXFS_0006);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: "
                                                     "no memory, max_len_t %ld\n",
                                                     max_len_t);
                return (EC_FALSE);
            }

            CBYTES_BUF(cbytes) = (UINT8 *)data;
            CBYTES_LEN(cbytes) = 0;
        }
        else
        {
            void        *data;

            data = c_memalign_new(file_size, CMCPGB_PAGE_SIZE_NBYTES);
            if(NULL_PTR == data)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_e_dn: "
                                                     "no memory, file_size %u, align %u\n",
                                                     file_size, CMCPGB_PAGE_SIZE_NBYTES);
                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_read_e_dn: file size %u, align %u\n",
                                                 file_size, CMCPGB_PAGE_SIZE_NBYTES);

            CBYTES_BUF(cbytes)      = (UINT8 *)data;
            CBYTES_LEN(cbytes)      = 0;
            CBYTES_ALIGNED(cbytes)  = BIT_TRUE;
        }
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_reserve_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_release_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_write_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_write_npp: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_read_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_npp: "
                                             "xfs is in op-replay mode\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_read_npp: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_npp: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew_http_header: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_header: wait syncing timeout\n");
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

    uint64_t      s_msec;
    uint64_t      e_msec;
    uint64_t      cost_msec;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew_http_headers: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: wait syncing timeout\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: cxfs is read-only\n");
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);

    s_msec = c_get_cur_time_msec();
    CXFS_STAT_RENEW_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, &cbytes))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_RENEW_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_RENEW_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: read '%s' failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes), (uint32_t)CBYTES_LEN(&cbytes)))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_RENEW_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_RENEW_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

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
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_RENEW_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_RENEW_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: '%s' encode http rsp failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_update(cxfs_md_id, file_path, &cbytes))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_RENEW_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_RENEW_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers: '%s' update failed\n", (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    e_msec = c_get_cur_time_msec();
    cost_msec = e_msec - s_msec;

    CXFS_STAT_RENEW_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
    CXFS_STAT_RENEW_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;
    CXFS_STAT_RENEW_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(&cbytes);

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_renew_http_headers_with_token: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_renew_http_headers_with_token: wait syncing timeout\n");
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
EC_BOOL cxfs_wait_http_header(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, const CSTRING *key, const CSTRING *val, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_http_header: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_header: "
                                             "read '%s' failed\n",
                                             (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes),
                                                (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_header: "
                                             "'%s' decode to http rsp failed\n",
                                             (char *)CSTRING_STR(file_path));
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
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_http_header: "
                                             "'%s' wait header '%s':'%s' => ready\n",
                                             (char *)CSTRING_STR(file_path),
                                             (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

        return (EC_TRUE);
    }

    if(EC_FALSE == cxfs_file_wait(cxfs_md_id, mod_node, file_path, expire_nsec, NULL_PTR, NULL_PTR))
    {
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_http_header: "
                                         "'%s' wait header '%s':'%s' => OK\n",
                                         (char *)CSTRING_STR(file_path),
                                         (char *)CSTRING_STR(key), (char *)CSTRING_STR(val));

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_http_headers(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, const CSTRKV_MGR *cstrkv_mgr, UINT32 *header_ready)
{
    CBYTES        cbytes;
    CHTTP_RSP     chttp_rsp;

    CLIST_DATA   *clist_data;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_http_headers: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, file_path, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_headers: "
                                             "read '%s' failed\n",
                                             (char *)CSTRING_STR(file_path));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    chttp_rsp_init(&chttp_rsp);
    if(EC_FALSE == chttp_rsp_decode(&chttp_rsp, (const uint8_t *)CBYTES_BUF(&cbytes),
                                                 (uint32_t)CBYTES_LEN(&cbytes)))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_http_headers: "
                                             "'%s' decode to http rsp failed\n",
                                             (char *)CSTRING_STR(file_path));
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

    if(EC_FALSE == cxfs_file_wait(cxfs_md_id, mod_node, file_path, expire_nsec, NULL_PTR, NULL_PTR))
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:__cxfs_delete_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_delete_dn: "
                                             "remove file fsize %u, disk %u, block %u, page %u failed\n",
                                             file_size, disk_no, block_no, page_no);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_delete_dn: "
                                         "remove file fsize %u, disk %u, block %u, page %u done\n",
                                         file_size, disk_no, block_no, page_no);

    return (EC_TRUE);
}

EC_BOOL cxfs_delete_dn(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, const CXFSNP_ITEM *cxfsnp_item)
{
    CXFS_MD     *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dn: wait syncing timeout\n");
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
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dn: "
                                                     "delete regular file from dn failed\n");
                return (EC_FALSE);
            }
            return (EC_TRUE);
        }

        /*Oops! not implement or not support yet ...*/
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dn: "
                                             "cxfsnp_item %p dflag flag 0x%x is unknown\n",
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_file: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(EC_TRUE == __cxfs_check_path_has_wildcard(path))
    {
        return cxfs_delete_file_wildcard(cxfs_md_id, path);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file: wait syncing timeout\n");
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

    CXFS_STAT_DELETE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_file_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file_no_lock: wait syncing timeout\n");
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

    CXFS_STAT_DELETE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_file_wildcard: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_file_wildcard: wait syncing timeout\n");
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

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file_wildcard: "
                                         "cxfs_md_id %ld, path %s ...\n",
                                         cxfs_md_id, (char *)cstring_get_str(path));

    if(BIT_FALSE == CXFS_MD_OP_REPLAY_FLAG(cxfs_md)
    && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
    {
        cxfsop_mgr_np_push_file_wildcard_delete_op(CXFS_MD_OP_MGR(cxfs_md),
                                                   (uint32_t )cstring_get_len(path),
                                                   (uint8_t *)cstring_get_str(path));
    }

    CXFS_STAT_DELETE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfsnp_mgr_umount_wildcard(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_REG))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_delete_file_wildcard: "
                                             "umount %.*s failed or terminated\n",
                                             (uint32_t)cstring_get_len(path), cstring_get_str(path));

        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_file_wildcard: "
                                         "cxfs_md_id %ld, path %s succ\n",
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(EC_TRUE == __cxfs_check_path_has_wildcard(path))
    {
        return cxfs_delete_dir_wildcard(cxfs_md_id, path);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir: wait syncing timeout\n");
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

    CXFS_STAT_DELETE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dir_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_no_lock: wait syncing timeout\n");
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

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_no_lock: "
                                         "cxfs_md_id %ld, path %s ...\n",
                                         cxfs_md_id, (char *)cstring_get_str(path));

    CXFS_STAT_DELETE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfsnp_mgr_umount_deep(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_no_lock: "
                                             "umount %.*s failed\n",
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

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_no_lock: "
                                         "cxfs_md_id %ld, path %s done\n",
                                         cxfs_md_id, (char *)cstring_get_str(path));

    return (EC_TRUE);
}

EC_BOOL cxfs_delete_dir_wildcard(const UINT32 cxfs_md_id, const CSTRING *path)
{
    CXFS_MD      *cxfs_md;
    MOD_NODE      mod_node;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_delete_dir_wildcard: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_delete_dir_wildcard: wait syncing timeout\n");
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

    CXFS_STAT_DELETE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfsnp_mgr_umount_wildcard_deep(CXFS_MD_NPP(cxfs_md), path, CXFSNP_ITEM_FILE_IS_DIR))
    {
        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_wildcard: "
                                             "umount %.*s failed or terminated\n",
                                             (uint32_t)cstring_get_len(path), cstring_get_str(path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_delete_dir_wildcard: "
                                         "cxfs_md_id %ld, path %s succ\n",
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
*  update a file
*  (atomic operation)
*
**/
EC_BOOL cxfs_update(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update: wait syncing timeout\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update: cxfs is read-only\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfs_update_no_lock(cxfs_md_id, file_path, cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update: "
                                             "update file %s failed\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update: "
                                         "update file %s done\n",
                                         (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL cxfs_update_no_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes)
{
    CXFS_MD      *cxfs_md;

    uint64_t      s_msec;
    uint64_t      e_msec;
    uint64_t      cost_msec;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: wait syncing timeout\n");
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: cxfs is read-only\n");
        return (EC_FALSE);
    }

    s_msec = c_get_cur_time_msec();

    CXFS_STAT_UPDATE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    if(EC_FALSE == cxfs_read_npp(cxfs_md_id, file_path, NULL_PTR))
    {
        /*file not exist, write as new file*/
        if(EC_FALSE == cxfs_write_no_lock(cxfs_md_id, file_path, cbytes))
        {
            e_msec = c_get_cur_time_msec();
            cost_msec = e_msec - s_msec;

            CXFS_STAT_UPDATE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
            CXFS_STAT_UPDATE_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: "
                                                 "write file %s failed\n",
                                                 (char *)cstring_get_str(file_path));
            return (EC_FALSE);
        }

        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_UPDATE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_UPDATE_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;
        CXFS_STAT_UPDATE_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update_no_lock: "
                                             "write file %s done\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*file exist, update it*/
    if(EC_FALSE == cxfs_delete_file_no_lock(cxfs_md_id, file_path))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_UPDATE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_UPDATE_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: "
                                             "delete old file %s failed\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }
    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update_no_lock: "
                                         "delete old file %s done\n",
                                         (char *)cstring_get_str(file_path));

    if(EC_FALSE == cxfs_write_no_lock(cxfs_md_id, file_path, cbytes))
    {
        e_msec = c_get_cur_time_msec();
        cost_msec = e_msec - s_msec;

        CXFS_STAT_UPDATE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
        CXFS_STAT_UPDATE_FAIL_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_no_lock: "
                                             "write new file %s failed\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    e_msec = c_get_cur_time_msec();
    cost_msec = e_msec - s_msec;

    CXFS_STAT_UPDATE_COST_MSEC(CXFS_MD_STAT(cxfs_md)) += cost_msec;
    CXFS_STAT_UPDATE_SUCC_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;
    CXFS_STAT_UPDATE_NBYTES(CXFS_MD_STAT(cxfs_md)) += CBYTES_LEN(cbytes);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_update_no_lock: "
                                         "write new file %s done\n",
                                         (char *)cstring_get_str(file_path));

    return (EC_TRUE);
}

EC_BOOL cxfs_update_with_token(const UINT32 cxfs_md_id, const CSTRING *file_path, const CBYTES *cbytes, const CSTRING *token_str)
{
    CXFS_MD      *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_update_with_token: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_update_with_token: wait syncing timeout\n");
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qfile: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_path: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_path: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_list_path(CXFS_MD_NPP(cxfs_md), file_path, CXFSNP_ITEM_FILE_IS_DIR,
                                        path_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_path: "
                                             "list dir '%s' failed\n",
                                             (char *)cstring_get_str(file_path));
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_path_of_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_path_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_id_t = (uint32_t)cxfsnp_id;

    if(EC_FALSE == cxfsnp_mgr_list_path_of_np(CXFS_MD_NPP(cxfs_md), file_path, CXFSNP_ITEM_FILE_IS_REG,
                                                cxfsnp_id_t, path_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_path_of_np: "
                                             "list file '%s' of np %u failed\n",
                                             (char *)cstring_get_str(file_path),
                                             cxfsnp_id_t);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_list_path_of_np(CXFS_MD_NPP(cxfs_md), file_path, CXFSNP_ITEM_FILE_IS_DIR,
                                                cxfsnp_id_t, path_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_path_of_np: "
                                             "list dir '%s' of np %u failed\n",
                                             (char *)cstring_get_str(file_path),
                                             cxfsnp_id_t);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_seg: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_seg: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_list_seg(CXFS_MD_NPP(cxfs_md), file_path, CXFSNP_ITEM_FILE_IS_DIR,
                                        seg_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_seg: "
                                             "list seg of dir '%s' failed\n",
                                             (char *)cstring_get_str(file_path));
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_seg_of_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_seg_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_id_t = (uint32_t)cxfsnp_id;

    if(EC_FALSE == cxfsnp_mgr_list_seg_of_np(CXFS_MD_NPP(cxfs_md), file_path, CXFSNP_ITEM_FILE_IS_DIR,
                                            cxfsnp_id_t, seg_cstr_vec))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_seg_of_np: "
                                             "list seg of dir '%s' failed\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_cat_path(const CXFSNP_ITEM *cxfsnp_item, CSTRING *des_path)
{
    cstring_rtrim(des_path, (UINT8)'/');
    cstring_append_chars(des_path, (UINT32)1, (const UINT8 *)"/", LOC_CXFS_0007);
    cstring_append_chars(des_path, CXFSNP_ITEM_KLEN(cxfsnp_item), CXFSNP_ITEM_KNAME(cxfsnp_item), LOC_CXFS_0008);

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

        full_path = cstring_new(cstring_get_str(base_dir), LOC_CXFS_0009);
        if(NULL_PTR == full_path)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_qlist_tree: new cstring failed\n");
            return (EC_FALSE);
        }

        if(EC_FALSE == cstack_walk(CXFSNP_DIT_NODE_STACK(cxfsnp_dit_node), (void *)full_path,
                                        (CSTACK_DATA_DATA_WALKER)__cxfs_cat_path))
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

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_expire: "
                                         "invalid item dflag %u at node pos %u\n",
                                         CXFSNP_ITEM_DIR_FLAG(cxfsnp_item), node_pos);
    return (EC_FALSE);
}

/**
*
*  query and list full path of a file or all files under a dir recursively
*  (looks like shell command: tree)
*
**/
EC_BOOL cxfs_qlist_tree(const UINT32 cxfs_md_id, const CSTRING *file_path, CVECTOR  *path_cstr_vec)
{
    CXFS_MD        *cxfs_md;
    CXFSNP_DIT_NODE cxfsnp_dit_node;
    CSTRING        *base_dir;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_tree: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_tree: npp was not open\n");
        return (EC_FALSE);
    }

    base_dir = cstring_new(cstring_get_str(file_path), LOC_CXFS_0010);
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

    if(EC_FALSE == cxfsnp_mgr_walk(CXFS_MD_NPP(cxfs_md), file_path, CXFSNP_ITEM_FILE_IS_DIR, &cxfsnp_dit_node))
    {
        cstring_free(base_dir);
        cxfsnp_dit_node_clean(&cxfsnp_dit_node);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_tree: "
                                             "list dir '%s' failed\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_qlist_tree: after walk, stack is:\n");
        cstack_print(LOGSTDOUT, CXFSNP_DIT_NODE_STACK(&cxfsnp_dit_node),
                                (CSTACK_DATA_DATA_PRINT)cxfsnp_item_and_key_print);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_qlist_tree_of_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_qlist_tree_of_np: npp was not open\n");
        return (EC_FALSE);
    }

    cxfsnp_id_t = (uint32_t)cxfsnp_id;

    base_dir = cstring_new(cstring_get_str(file_path), LOC_CXFS_0011);
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

    if(EC_FALSE == cxfsnp_mgr_walk_of_np(CXFS_MD_NPP(cxfs_md), cxfsnp_id_t, file_path, CXFSNP_ITEM_FILE_IS_REG, &cxfsnp_dit_node))
    {
        cstring_free(base_dir);
        cxfsnp_dit_node_clean(&cxfsnp_dit_node);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_tree_of_np: "
                                             "list tree of file '%s' failed\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_walk_of_np(CXFS_MD_NPP(cxfs_md), cxfsnp_id_t, file_path, CXFSNP_ITEM_FILE_IS_DIR, &cxfsnp_dit_node))
    {
        cstring_free(base_dir);
        cxfsnp_dit_node_clean(&cxfsnp_dit_node);

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_qlist_tree_of_np: "
                                             "list tree of dir '%s' failed\n",
                                             (char *)cstring_get_str(file_path));
        return (EC_FALSE);
    }

    if(do_log(SEC_0192_CXFS, 9))
    {
        sys_log(LOGSTDOUT, "[DEBUG] cxfs_qlist_tree_of_np: after walk, stack is:\n");
        cstack_print(LOGSTDOUT, CXFSNP_DIT_NODE_STACK(&cxfsnp_dit_node),
                                (CSTACK_DATA_DATA_PRINT)cxfsnp_item_and_key_print);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_flush_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_flush_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_flush_dn: dn is null\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_flush(CXFS_MD_DN(cxfs_md), CXFS_MD_CFG(cxfs_md)))
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_num: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_file_num: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_file_num(CXFS_MD_NPP(cxfs_md), path_cstr, file_num))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_num: "
                                             "get file num of path '%s' failed\n",
                                             (char *)cstring_get_str(path_cstr));
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_size: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_file_size: npp was not open\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_file_size(CXFS_MD_NPP(cxfs_md), path_cstr, file_size))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "error:cxfs_file_size: "
                                             "cxfsnp mgr get size of %s failed\n",
                                             (char *)cstring_get_str(path_cstr));
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_size: "
                                         "file %s, size %ld\n",
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_expire: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_expire: wait syncing timeout\n");
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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_expire: "
                                             "expire %s failed\n",
                                             (char *)cstring_get_str(path_cstr));
        cstring_clean(&key);
        cstring_clean(&val);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_expire: "
                                         "expire %s done\n",
                                         (char *)cstring_get_str(path_cstr));
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_md5sum: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_file_md5sum: npp was not open\n");
        return (EC_FALSE);
    }

    cbytes_init(&cbytes);

    if(EC_FALSE == cxfs_read(cxfs_md_id, path_cstr, &cbytes))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_md5sum: "
                                             "read %s failed\n",
                                             (char *)cstring_get_str(path_cstr));
        cbytes_clean(&cbytes);
        return (EC_FALSE);
    }

    cmd5_sum((uint32_t)CBYTES_LEN(&cbytes), CBYTES_BUF(&cbytes), CMD5_DIGEST_SUM(md5sum));
    cbytes_clean(&cbytes);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_md5sum: "
                                         "file %s, md5 %s\n",
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_mkdir: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mkdir: wait syncing timeout\n");
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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_mkdir: "
                                             "mkdir '%s' failed\n",
                                             (char *)cstring_get_str(path_cstr));
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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_recycle_of_np: "
                                             "recycle np %u failed\n",
                                             cxfsnp_id);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_recycle_of_np: "
                                         "recycle np %u done where complete %ld\n",
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_recycle: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_recycle: recycle beg\n");

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_recycle: wait syncing timeout\n");
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

    CXFS_STAT_RECYCLE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    complete_recycle_num = 0;/*initialization*/

    for(cxfsnp_id = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        __cxfs_recycle_of_np(cxfs_md_id, cxfsnp_id, max_num_per_np, &complete_recycle_num);
        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_recycle: recycle np %u done\n", cxfsnp_id);
    }

    if(0 < complete_recycle_num)
    {
        CXFS_STAT_RECYCLE_COMPLETE(CXFS_MD_STAT(cxfs_md)) += complete_recycle_num;

        dbg_log(SEC_0192_CXFS, 4)(LOGSTDOUT, "[DEBUG] cxfs_recycle: recycle end where complete %ld\n", complete_recycle_num);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_process_space: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(BIT_TRUE == CXFS_MD_SYNC_FLAG(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_process_space: xfs in sync mode\n");

        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_process_space,
                            (void *)cxfs_md_id);
        return (EC_FALSE);
    }

    if(BIT_TRUE == CXFS_MD_READ_ONLY_FLAG(cxfs_md))
    {
        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_process_space,
                            (void *)cxfs_md_id);

        /*do not process*/
        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_process_space: npp was not open\n");

        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_process_space,
                            (void *)cxfs_md_id);

        return (EC_FALSE);
    }

    if(NULL_PTR == CXFS_MD_DN(cxfs_md))
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_process_space: dn was not open\n");

        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_process_space,
                            (void *)cxfs_md_id);
        return (EC_FALSE);
    }

    npp_used_ratio = cxfsnp_mgr_used_ratio(CXFS_MD_NPP(cxfs_md));
    dn_used_ratio  = cxfsdn_used_ratio(CXFS_MD_DN(cxfs_md));

    dbg_log(SEC_0192_CXFS, 6)(LOGSTDOUT, "[DEBUG] cxfs_process_space: "
                                         "npp used ratio %.3f, dn used ratio %.3f\n",
                                         npp_used_ratio, dn_used_ratio);

    if(CXFSNP_MAX_USED_RATIO <= npp_used_ratio)
    {
        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_process_space: "
                                             "npp used ratio %.3f >= %.3f => retire & recycle\n",
                                             npp_used_ratio, CXFSNP_MAX_USED_RATIO);

        cxfs_retire(cxfs_md_id , (UINT32)CXFSNP_TRY_RETIRE_MAX_NUM , NULL_PTR);
    }

    dn_used_ratio = cxfsdn_used_ratio(CXFS_MD_DN(cxfs_md));
    if(CXFSDN_MAX_USED_RATIO <= dn_used_ratio)
    {
        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_process_space: "
                                             "dn used ratio %.3f >= %.3f => retire & recycle\n",
                                             dn_used_ratio, CXFSDN_MAX_USED_RATIO);

        cxfs_retire(cxfs_md_id , (UINT32)CXFSNP_TRY_RETIRE_MAX_NUM , NULL_PTR);
    }

    /*anyway, try to recycle*/
    cxfs_recycle(cxfs_md_id, (UINT32)CXFSNP_TRY_RECYCLE_MAX_NUM, NULL_PTR);

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_space,
                        (void *)cxfs_md_id);

    return (EC_TRUE);
}

/**
*
*  process statistics
*
**/
EC_BOOL cxfs_process_stat(const UINT32 cxfs_md_id)
{
    CXFS_MD      *cxfs_md;
    CXFS_STAT    *cxfs_stat;
    CXFS_STAT    *cxfs_stat_saved;

    static uint64_t next_time_msec  = 0;
    uint64_t        cur_time_msec;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_process_stat: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cur_time_msec = c_get_cur_time_msec();
    if(cur_time_msec < next_time_msec)
    {
        task_brd_process_add(task_brd_default_get(),
                            (TASK_BRD_CALLBACK)cxfs_process_stat,
                            (void *)cxfs_md_id);
        return (EC_TRUE);
    }

    /*set next time*/
    next_time_msec = cur_time_msec + CXFS_STAT_INTERVAL_NSEC * 1000;
    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_stat,
                        (void *)cxfs_md_id);

    cxfs_stat = CXFS_MD_STAT(cxfs_md);
    cxfs_stat_saved = CXFS_MD_STAT_SAVED(cxfs_md);

    if(do_log(SEC_0192_CXFS, 3))
    {
        uint64_t        read_speed;   /*Bps*/
        uint64_t        write_speed;  /*Bps*/
        uint64_t        update_speed; /*Bps*/
        uint64_t        renew_speed;  /*Bps*/
        uint64_t        cost_msec;
        uint64_t        cost_nbytes;

        cost_nbytes  = (CXFS_STAT_READ_NBYTES(cxfs_stat)    - CXFS_STAT_READ_NBYTES(cxfs_stat_saved));
        cost_msec    = (CXFS_STAT_READ_COST_MSEC(cxfs_stat) - CXFS_STAT_READ_COST_MSEC(cxfs_stat_saved));
        read_speed   = (0 == cost_msec? 0 : ((cost_nbytes * 1000) / cost_msec));

        cost_nbytes  = (CXFS_STAT_WRITE_NBYTES(cxfs_stat)    - CXFS_STAT_WRITE_NBYTES(cxfs_stat_saved));
        cost_msec    = (CXFS_STAT_WRITE_COST_MSEC(cxfs_stat) - CXFS_STAT_WRITE_COST_MSEC(cxfs_stat_saved));
        write_speed  = (0 == cost_msec? 0 : ((cost_nbytes * 1000) / cost_msec));

        cost_nbytes  = (CXFS_STAT_UPDATE_NBYTES(cxfs_stat)    - CXFS_STAT_UPDATE_NBYTES(cxfs_stat_saved));
        cost_msec    = (CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat) - CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat_saved));
        update_speed = (0 == cost_msec? 0 : ((cost_nbytes * 1000) / cost_msec));

        cost_nbytes  = (CXFS_STAT_RENEW_NBYTES(cxfs_stat)    - CXFS_STAT_RENEW_NBYTES(cxfs_stat_saved));
        cost_msec    = (CXFS_STAT_RENEW_COST_MSEC(cxfs_stat) - CXFS_STAT_RENEW_COST_MSEC(cxfs_stat_saved));
        renew_speed  = (0 == cost_msec? 0 : ((cost_nbytes * 1000) / cost_msec));

        sys_log(LOGSTDOUT, "cxfs_process_stat: "
               "[READ] counter %lu, "
               "np succ %lu, np fail %lu, "
               "dn succ %lu, dn fail %lu, "
               "nbytes %lu, cost %lu, avg %lu Bps, "

               "[WRITE] counter %lu, "
               "np succ %lu, np fail %lu, "
               "dn succ %lu, dn fail %lu, "
               "nbytes %lu, avg %lu Bps, "

               "[UPDATE] counter %lu, "
               "succ %lu, fail %lu, "
               "nbytes %lu, cost %lu, avg %lu Bps, "

               "[RENEW] counter %lu, "
               "succ %lu, fail %lu, "
               "nbytes %lu, cost %lu, avg %lu Bps, "

               "[DELETE] counter %lu, "
               "[RETIRE] counter %lu, complete %lu, "
               "[RECYCLE] counter %lu, complete %lu\n",

               CXFS_STAT_READ_COUNTER(cxfs_stat)           -  CXFS_STAT_READ_COUNTER(cxfs_stat_saved),
               CXFS_STAT_READ_NP_SUCC_COUNTER(cxfs_stat)   -  CXFS_STAT_READ_NP_SUCC_COUNTER(cxfs_stat_saved),
               CXFS_STAT_READ_NP_FAIL_COUNTER(cxfs_stat)   -  CXFS_STAT_READ_NP_FAIL_COUNTER(cxfs_stat_saved),
               CXFS_STAT_READ_DN_SUCC_COUNTER(cxfs_stat)   -  CXFS_STAT_READ_DN_SUCC_COUNTER(cxfs_stat_saved),
               CXFS_STAT_READ_DN_FAIL_COUNTER(cxfs_stat)   -  CXFS_STAT_READ_DN_FAIL_COUNTER(cxfs_stat_saved),
               CXFS_STAT_READ_NBYTES(cxfs_stat)            -  CXFS_STAT_READ_NBYTES(cxfs_stat_saved),
               CXFS_STAT_READ_COST_MSEC(cxfs_stat)         -  CXFS_STAT_READ_COST_MSEC(cxfs_stat_saved),
               read_speed,

               CXFS_STAT_WRITE_COUNTER(cxfs_stat)          -  CXFS_STAT_WRITE_COUNTER(cxfs_stat_saved),
               CXFS_STAT_WRITE_NP_SUCC_COUNTER(cxfs_stat)  -  CXFS_STAT_WRITE_NP_SUCC_COUNTER(cxfs_stat_saved),
               CXFS_STAT_WRITE_NP_FAIL_COUNTER(cxfs_stat)  -  CXFS_STAT_WRITE_NP_FAIL_COUNTER(cxfs_stat_saved),
               CXFS_STAT_WRITE_DN_SUCC_COUNTER(cxfs_stat)  -  CXFS_STAT_WRITE_DN_SUCC_COUNTER(cxfs_stat_saved),
               CXFS_STAT_WRITE_DN_FAIL_COUNTER(cxfs_stat)  -  CXFS_STAT_WRITE_DN_FAIL_COUNTER(cxfs_stat_saved),
               CXFS_STAT_WRITE_NBYTES(cxfs_stat)           -  CXFS_STAT_WRITE_NBYTES(cxfs_stat_saved),
               CXFS_STAT_WRITE_COST_MSEC(cxfs_stat)        -  CXFS_STAT_WRITE_COST_MSEC(cxfs_stat_saved),
               write_speed,

               CXFS_STAT_UPDATE_COUNTER(cxfs_stat)         -  CXFS_STAT_UPDATE_COUNTER(cxfs_stat_saved),
               CXFS_STAT_UPDATE_SUCC_COUNTER(cxfs_stat)    -  CXFS_STAT_UPDATE_SUCC_COUNTER(cxfs_stat_saved),
               CXFS_STAT_UPDATE_FAIL_COUNTER(cxfs_stat)    -  CXFS_STAT_UPDATE_FAIL_COUNTER(cxfs_stat_saved),
               CXFS_STAT_UPDATE_NBYTES(cxfs_stat)          -  CXFS_STAT_UPDATE_NBYTES(cxfs_stat_saved),
               CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat)       -  CXFS_STAT_UPDATE_COST_MSEC(cxfs_stat_saved),
               update_speed,

               CXFS_STAT_RENEW_COUNTER(cxfs_stat)          -  CXFS_STAT_RENEW_COUNTER(cxfs_stat_saved),
               CXFS_STAT_RENEW_SUCC_COUNTER(cxfs_stat)     -  CXFS_STAT_RENEW_SUCC_COUNTER(cxfs_stat_saved),
               CXFS_STAT_RENEW_FAIL_COUNTER(cxfs_stat)     -  CXFS_STAT_RENEW_FAIL_COUNTER(cxfs_stat_saved),
               CXFS_STAT_RENEW_NBYTES(cxfs_stat)           -  CXFS_STAT_RENEW_NBYTES(cxfs_stat_saved),
               CXFS_STAT_RENEW_COST_MSEC(cxfs_stat)        -  CXFS_STAT_RENEW_COST_MSEC(cxfs_stat_saved),
               renew_speed,

               CXFS_STAT_DELETE_COUNTER(cxfs_stat)         -  CXFS_STAT_DELETE_COUNTER(cxfs_stat_saved),

               CXFS_STAT_RETIRE_COUNTER(cxfs_stat)         -  CXFS_STAT_RETIRE_COUNTER(cxfs_stat_saved),
               CXFS_STAT_RETIRE_COMPLETE(cxfs_stat)        -  CXFS_STAT_RETIRE_COMPLETE(cxfs_stat_saved),

               CXFS_STAT_RECYCLE_COUNTER(cxfs_stat)        -  CXFS_STAT_RECYCLE_COUNTER(cxfs_stat_saved),
               CXFS_STAT_RECYCLE_COMPLETE(cxfs_stat)       -  CXFS_STAT_RECYCLE_COMPLETE(cxfs_stat_saved)
               );
    }

    /*save*/
    BCOPY(cxfs_stat, cxfs_stat_saved, sizeof(CXFS_STAT));

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_file_content: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: "
                                             "new cxfs buff with len %ld failed\n",
                                             file_size);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsdn_read_p(CXFS_MD_DN(cxfs_md), (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no, file_size,
                                  CBYTES_BUF(cbytes), &(CBYTES_LEN(cbytes))))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: "
                            "read %ld bytes from disk %u, block %u, page %u failed\n",
                            file_size, (uint16_t)disk_no, (uint16_t)block_no, (uint16_t)page_no);
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) < cstring_get_len(file_content_cstr))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: "
                            "read %ld bytes from disk %u, block %u, page %u to buff len %u "
                            "less than cstring len %u to compare\n",
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
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_content: "
                                                 "char at pos %ld not matched\n",
                                                 pos);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_file_is: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: "
                                             "read file %s failed\n",
                                             (char *)cstring_get_str(file_path));
        cbytes_free(cbytes);
        return (EC_FALSE);
    }

    if(CBYTES_LEN(cbytes) != CBYTES_LEN(file_content))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: "
                            "mismatched len: file %s read len %ld which should be %ld\n",
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
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_file_is: "
                                                 "char at pos %ld not matched\n",
                                                 pos);
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
*  check space [s_offset, e_offset) is used or not
*
**/
EC_BOOL cxfs_check_space_used(const UINT32 cxfs_md_id, const UINT32 s_offset, const UINT32 e_offset)
{
    CXFS_MD     *cxfs_md;

    uint64_t     f_s_offset;
    uint64_t     f_e_offset;
    uint64_t     mask;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_space_used: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(s_offset > e_offset)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_check_space_used: "
                                             "invalid [%ld, %ld)\n",
                                             s_offset, e_offset);
        return (EC_FALSE);
    }

    mask       = ((uint64_t)(~((uint64_t)(CXFSPGB_PAGE_BYTE_SIZE - 1))));
    f_s_offset = (((uint64_t)(s_offset + 0                         )) & mask);
    f_e_offset = (((uint64_t)(e_offset + CXFSPGB_PAGE_BYTE_SIZE - 1)) & mask);

    /*fix: s_offset == e_offset => adjust*/
    if(f_e_offset == f_s_offset)
    {
        f_e_offset += CXFSPGB_PAGE_BYTE_SIZE;
    }

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_check_space_used: "
                                         "page size %u, mask %#lx, [%ld, %ld) => [%ld, %ld)\n",
                                         CXFSPGB_PAGE_BYTE_SIZE, mask,
                                         s_offset, e_offset,
                                         f_s_offset, f_e_offset);

    for(; f_s_offset < f_e_offset; f_s_offset += CXFSPGB_PAGE_BYTE_SIZE)
    {
        uint64_t    offset_t;
        uint16_t    disk_no;
        uint16_t    block_no;
        uint16_t    page_no;

        offset_t = f_s_offset;

        disk_no     = ((uint16_t)(offset_t  >> CXFSPGD_SIZE_NBITS));
        offset_t   -= (((uint64_t)disk_no) << CXFSPGD_SIZE_NBITS);

        block_no    = ((uint16_t)(offset_t  >> CXFSPGB_CACHE_BIT_SIZE));
        offset_t   -= (((uint64_t)block_no) << CXFSPGB_CACHE_BIT_SIZE);

        page_no     = ((uint16_t)(offset_t >> CXFSPGB_PAGE_BIT_SIZE));
        offset_t   -= (((uint64_t)page_no) << CXFSPGB_PAGE_BIT_SIZE);

        ASSERT(offset_t < CXFSPGB_PAGE_BYTE_SIZE);

        if(EC_TRUE == cxfsdn_check_space_used(CXFS_MD_DN(cxfs_md), disk_no, block_no, page_no))
        {
            dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_check_space_used: "
                                                 "[%ld, %ld) => f_s_offset %ld "
                                                 "=> (disk %u, block %u, page %u) => used\n",
                                                 s_offset, e_offset, f_s_offset,
                                                 disk_no, block_no, page_no);
            return (EC_TRUE);
        }

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_check_space_used: "
                                             "[%ld, %ld) => f_s_offset %ld "
                                             "=> (disk %u, block %u, page %u) => not used\n",
                                             s_offset, e_offset, f_s_offset,
                                             disk_no, block_no, page_no);
    }

    return (EC_FALSE);
}

/**
*
*  check space [o_s_offset, o_e_offset) except [i_s_offset, i_e_offset) is used or not
*  where
*       o_s_offset <= i_s_offset <= i_e_offset <= o_e_offset
*
**/
EC_BOOL cxfs_check_adjacent_used(const UINT32 cxfs_md_id, const UINT32 o_s_offset, const UINT32 o_e_offset, const UINT32 i_s_offset, const UINT32 i_e_offset)
{
    uint64_t     mask;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_check_adjacent_used: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    mask = ((uint64_t)(~((uint64_t)(CXFSPGB_PAGE_BYTE_SIZE - 1))));

    if(o_s_offset + CXFSPGB_PAGE_BYTE_SIZE < i_s_offset)
    {
        uint64_t     f_s_offset;
        uint64_t     f_e_offset;

        f_s_offset = (((uint64_t)(o_s_offset )) & mask);
        f_e_offset = (((uint64_t)(i_s_offset )) & mask);

        if(EC_TRUE == cxfs_check_space_used(cxfs_md_id, f_s_offset, f_e_offset))
        {
            return (EC_TRUE);
        }
    }

    if(i_e_offset + CXFSPGB_PAGE_BYTE_SIZE < o_e_offset)
    {
        uint64_t     f_s_offset;
        uint64_t     f_e_offset;

        f_s_offset = (((uint64_t)(i_e_offset + CXFSPGB_PAGE_BYTE_SIZE - 1)) & mask);
        f_e_offset = (((uint64_t)(o_e_offset + CXFSPGB_PAGE_BYTE_SIZE - 1)) & mask);

        if(EC_TRUE == cxfs_check_space_used(cxfs_md_id, f_s_offset, f_e_offset))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/**
*
*  show name node que list if it is npp
*
*
**/
EC_BOOL cxfs_show_npp_que_list(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_npp_que_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_TRUE);
    }

    cxfsnp_mgr_print_que_list(log, CXFS_MD_NPP(cxfs_md));

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_npp_del_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_npp: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_dn_no_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_dn: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_specific_np: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np: "
                                             "cxfsnp_id %ld is invalid\n",
                                             cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_np(log, CXFS_MD_NPP(cxfs_md), (uint32_t)cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np: "
                                             "show np %ld but failed\n",
                                             cxfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_show_specific_np_que_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_specific_np_que_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_que_list: "
                                             "cxfsnp_id %ld is invalid\n",
                                             cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_np_que_list(log, CXFS_MD_NPP(cxfs_md), (uint32_t)cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_que_list: "
                                             "show np %ld but failed\n",
                                             cxfsnp_id);
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_show_specific_np_del_list(const UINT32 cxfs_md_id, const UINT32 cxfsnp_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_show_specific_np_del_list: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(NULL_PTR == CXFS_MD_NPP(cxfs_md))
    {
        sys_log(log, "(null)\n");
        return (EC_FALSE);
    }

    if(EC_FALSE == c_check_is_uint32_t(cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_del_list: "
                                             "cxfsnp_id %ld is invalid\n",
                                             cxfsnp_id);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnp_mgr_show_np_del_list(log, CXFS_MD_NPP(cxfs_md), (uint32_t)cxfsnp_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_show_specific_np_del_list: "
                                             "show np %ld but failed\n",
                                             cxfsnp_id);
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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_retire_of_np: "
                                             "retire np %u failed "
                                             "where expect retire num %ld\n",
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

    UINT32        total_num;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_retire: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    if(EC_FALSE == cxfs_sync_wait(cxfs_md_id))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_retire: wait syncing timeout\n");
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

    CXFS_STAT_RETIRE_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

    for(cxfsnp_id = 0, total_num = 0; cxfsnp_id < CXFSNP_MGR_NP_MAX_NUM(cxfsnp_mgr); cxfsnp_id ++)
    {
        UINT32   complete_num;

        __cxfs_retire_of_np(cxfs_md_id, cxfsnp_id, expect_retire_num, &complete_num);
        total_num += complete_num;

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_retire: "
                                             "retire np %u done "
                                             "where expect retire num %ld, complete %ld\n",
                                             cxfsnp_id, expect_retire_num, complete_num);
    }

    if(NULL_PTR != complete_retire_num)
    {
        (*complete_retire_num) = total_num;
    }

    if(0 < total_num)
    {
        CXFS_STAT_RETIRE_COMPLETE(CXFS_MD_STAT(cxfs_md)) += total_num;

        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_retire: "
                                             "retire done where complete %ld\n",
                                             total_num);
    }
    return (EC_TRUE);
}

/*------------------------------------------------ interface for file wait ------------------------------------------------*/
CXFS_WAIT_FILE *cxfs_wait_file_new()
{
    CXFS_WAIT_FILE *cxfs_wait_file;
    alloc_static_mem(MM_CXFS_WAIT_FILE, &cxfs_wait_file, LOC_CXFS_0012);
    if(NULL_PTR != cxfs_wait_file)
    {
        cxfs_wait_file_init(cxfs_wait_file);
    }
    return (cxfs_wait_file);
}

EC_BOOL cxfs_wait_file_init(CXFS_WAIT_FILE *cxfs_wait_file)
{
    cstring_init(CXFS_WAIT_FILE_NAME(cxfs_wait_file), NULL_PTR);

    clist_init(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file), MM_MOD_NODE, LOC_CXFS_0013);

    CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file) = 0;
    CXFS_WAIT_FILE_START_TIME(cxfs_wait_file)  = 0;

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_clean(CXFS_WAIT_FILE *cxfs_wait_file)
{
    cstring_clean(CXFS_WAIT_FILE_NAME(cxfs_wait_file));
    clist_clean(CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file), (CLIST_DATA_DATA_CLEANER)mod_node_free);

    CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file) = 0;
    CXFS_WAIT_FILE_START_TIME(cxfs_wait_file)  = 0;
    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_free(CXFS_WAIT_FILE *cxfs_wait_file)
{
    if(NULL_PTR != cxfs_wait_file)
    {
        cxfs_wait_file_clean(cxfs_wait_file);
        free_static_mem(MM_CXFS_WAIT_FILE, cxfs_wait_file, LOC_CXFS_0014);
    }
    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_expire_set(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 expire_nsec)
{
    CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file) = expire_nsec;
    CXFS_WAIT_FILE_START_TIME(cxfs_wait_file)  = (UINT32)c_get_cur_time_nsec();

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_is_expire(const CXFS_WAIT_FILE *cxfs_wait_file)
{
    UINT32 cur_time;

    cur_time = (UINT32)c_get_cur_time_nsec();

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_is_expire: "
                                          "diff_nsec %ld, timeout_nsec %ld\n",
                                          cur_time - CXFS_WAIT_FILE_START_TIME(cxfs_wait_file),
                                          CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file));
    if(cur_time >= CXFS_WAIT_FILE_START_TIME(cxfs_wait_file) + CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfs_wait_file_need_retire(const CXFS_WAIT_FILE *cxfs_wait_file)
{
    UINT32 cur_time;

    cur_time = (UINT32)c_get_cur_time_nsec();

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_wait_file_need_retire: diff_nsec %ld, timeout_nsec %ld\n",
                                          cur_time - CXFS_WAIT_FILE_START_TIME(cxfs_wait_file),
                                          CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file));
    if(cur_time >= CXFS_WAIT_FILE_START_TIME(cxfs_wait_file) + 2 * CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

STATIC_CAST static EC_BOOL __cxfs_wait_file_retire(CRB_TREE *crbtree, CRB_NODE *node)
{
    CXFS_WAIT_FILE *cxfs_wait_file;

    if(NULL_PTR == node)
    {
        return (EC_FALSE);
    }

    cxfs_wait_file = CRB_NODE_DATA(node);
    if(EC_TRUE == __cxfs_wait_file_need_retire(cxfs_wait_file))
    {
        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_wait_file_retire: file %s was retired\n",
                            (char *)cstring_get_str(CXFS_WAIT_FILE_NAME(cxfs_wait_file)));

        crb_tree_delete(crbtree, node);
        return (EC_TRUE);/*succ and terminate*/
    }

    if(NULL_PTR != CRB_NODE_LEFT(node))
    {
        if(EC_TRUE == __cxfs_wait_file_retire(crbtree, CRB_NODE_LEFT(node)))
        {
            return (EC_TRUE);
        }
    }

    if(NULL_PTR != CRB_NODE_RIGHT(node))
    {
        if(EC_TRUE == __cxfs_wait_file_retire(crbtree, CRB_NODE_RIGHT(node)))
        {
            return (EC_TRUE);
        }
    }

    return (EC_FALSE);
}

/*retire the expired wait files over 120 seconds which are garbage*/
EC_BOOL cxfs_wait_file_retire(const UINT32 cxfs_md_id, const UINT32 retire_max_num, UINT32 *retire_num)
{
    CXFS_MD      *cxfs_md;
    CRB_TREE     *crbtree;
    UINT32        retire_idx;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_file_retire: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    crbtree = CXFS_MD_WAIT_FILES(cxfs_md);

    for(retire_idx = 0; retire_idx < retire_max_num; retire_idx ++)
    {
        if(EC_FALSE == __cxfs_wait_file_retire(crbtree, CRB_TREE_ROOT(crbtree)))
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

int cxfs_wait_file_cmp(const CXFS_WAIT_FILE *cxfs_wait_file_1st, const CXFS_WAIT_FILE *cxfs_wait_file_2nd)
{
    return cstring_cmp(CXFS_WAIT_FILE_NAME(cxfs_wait_file_1st), CXFS_WAIT_FILE_NAME(cxfs_wait_file_2nd));
}

void cxfs_wait_file_print(LOG *log, const CXFS_WAIT_FILE *cxfs_wait_file)
{
    if(NULL_PTR != cxfs_wait_file)
    {
        sys_log(log, "cxfs_wait_file_print %p: file %s, expire %ld seconds, owner list: ",
                        cxfs_wait_file,
                        CXFS_WAIT_FILE_EXPIRE_NSEC(cxfs_wait_file),
                        (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file)
                        );
        clist_print(log, CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file),(CLIST_DATA_DATA_PRINT)mod_node_print);
    }

    return;
}

void cxfs_wait_files_print(const UINT32 cxfs_md_id, LOG *log)
{
    CXFS_MD *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_files_print: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    crb_tree_print(log, CXFS_MD_WAIT_FILES(cxfs_md));

    return;
}

EC_BOOL cxfs_wait_file_name_set(CXFS_WAIT_FILE *cxfs_wait_file, const CSTRING *file_name)
{
    cstring_clone(file_name, CXFS_WAIT_FILE_NAME(cxfs_wait_file));
    return (EC_TRUE);
}

STATIC_CAST static EC_BOOL __cxfs_wait_file_owner_cmp(const MOD_NODE *mod_node_1st, const MOD_NODE *mod_node_2nd)
{
    if(MOD_NODE_TCID(mod_node_1st) != MOD_NODE_TCID(mod_node_2nd))
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_COMM != MOD_NODE_COMM(mod_node_1st)
    && CMPI_ANY_COMM != MOD_NODE_COMM(mod_node_2nd)
    && MOD_NODE_COMM(mod_node_1st) != MOD_NODE_COMM(mod_node_2nd))
    {
        return (EC_FALSE);
    }

    if(CMPI_ANY_RANK != MOD_NODE_RANK(mod_node_1st)
    && CMPI_ANY_RANK != MOD_NODE_RANK(mod_node_2nd)
    && MOD_NODE_RANK(mod_node_1st) != MOD_NODE_RANK(mod_node_2nd))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_push(CXFS_WAIT_FILE *cxfs_wait_file, const MOD_NODE *mod_node)
{
    CLIST *owner_list;

    owner_list = CXFS_WAIT_FILE_OWNER_LIST(cxfs_wait_file);
    if(
       CMPI_ERROR_TCID != MOD_NODE_TCID(mod_node)
    && CMPI_ANY_TCID != MOD_NODE_TCID(mod_node)
    && NULL_PTR == clist_search_data_front(owner_list, (void *)mod_node, (CLIST_DATA_DATA_CMP)__cxfs_wait_file_owner_cmp)
    )
    {
        MOD_NODE *mod_node_t;

        mod_node_t = mod_node_new();
        if(NULL_PTR == mod_node_t)
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_file_owner_push: new mod_node failed\n");
            return (EC_FALSE);
        }

        MOD_NODE_TCID(mod_node_t) = MOD_NODE_TCID(mod_node);
        MOD_NODE_COMM(mod_node_t) = MOD_NODE_COMM(mod_node);
        MOD_NODE_RANK(mod_node_t) = MOD_NODE_RANK(mod_node);
        MOD_NODE_MODI(mod_node_t) = 0;/*SUPER modi always be 0*/

        clist_push_back(owner_list, (void *)mod_node_t);

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_push: "
                                             "push (tcid %s, comm %ld, rank %ld) to file '%.*s'\n",
                                             MOD_NODE_TCID_STR(mod_node_t),
                                             MOD_NODE_COMM(mod_node_t),
                                             MOD_NODE_RANK(mod_node_t),
                                             (uint32_t)CXFS_WAIT_FILE_NAME_LEN(cxfs_wait_file),
                                             CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file));
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_file_owner_wakeup: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_cstr(uri, path);
    cstring_append_str(uri, (uint8_t *)"?mod="CXFSHTTP_REST_API_NAME"&op=cond_wakeup");

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_wakeup: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_file_owner_wakeup: "
                                             "wakeup '%.*s' on %s:%ld failed\n",
                                             (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                                             c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_wakeup: "
                                         "wakeup '%.*s' on %s:%ld done => status %u\n",
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

            remote_tasks_cfg = sys_cfg_search_tasks_cfg(TASK_BRD_SYS_CFG(task_brd),
                                                        MOD_NODE_TCID(mod_node),
                                                        CMPI_ANY_MASK,
                                                        CMPI_ANY_MASK);
            if(NULL_PTR == remote_tasks_cfg)
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "info:cxfs_wait_file_owner_notify_over_http: "
                                                     "not found tasks_cfg of node %s\n",
                                                     c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
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

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify_over_http: "
                                                 "file %s tag %ld notify owner: "
                                                 "tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                                                 (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file),
                                                 tag,
                                                 MOD_NODE_TCID_STR(mod_node),
                                                 MOD_NODE_COMM(mod_node),
                                                 MOD_NODE_RANK(mod_node),
                                                 MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify_over_http: "
                                         "file %s tag %ld notify none due to no owner\n",
                                         (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file),
                                         tag);

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

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node,
                         &ret,
                         FI_super_cond_wakeup, CMPI_ERROR_MODI, tag, CXFS_WAIT_FILE_NAME(cxfs_wait_file));

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify_over_bgn: "
                                                 "file %s tag %ld notify owner: "
                                                 "tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
                                                 (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file),
                                                 tag,
                                                 MOD_NODE_TCID_STR(mod_node),
                                                 MOD_NODE_COMM(mod_node),
                                                 MOD_NODE_RANK(mod_node),
                                                 MOD_NODE_MODI(mod_node));

            mod_node_free(mod_node);
        }

        task_no_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);
        return (EC_TRUE);
    }

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_notify_over_bgn: "
                                         "file %s tag %ld notify none due to no owner\n",
                                         (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file),
                                         tag);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_notify(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_wait_file_owner_cancel: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    chttp_req_init(&chttp_req);
    chttp_rsp_init(&chttp_rsp);

    chttp_req_set_ipaddr_word(&chttp_req, store_srv_ipaddr);
    chttp_req_set_port_word(&chttp_req, store_srv_port);
    chttp_req_set_method(&chttp_req, (const char *)"GET");

    uri = CHTTP_REQ_URI(&chttp_req);
    cstring_append_cstr(uri, path);
    cstring_append_str(uri, (uint8_t *)"?mod="CXFSHTTP_REST_API_NAME"&op=cond_terminate");

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_cancel: req uri '%.*s' done\n",
                (uint32_t)CSTRING_LEN(uri), CSTRING_STR(uri));

    chttp_req_add_header(&chttp_req, (const char *)"Connection", (char *)"Keep-Alive");
    chttp_req_add_header(&chttp_req, (const char *)"Content-Length", (char *)"0");

    if(EC_FALSE == chttp_request(&chttp_req, NULL_PTR, &chttp_rsp, NULL_PTR))/*block*/
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_wait_file_owner_cancel: "
                                             "terminate '%.*s' on %s:%ld failed\n",
                                             (uint32_t)CSTRING_LEN(path), CSTRING_STR(path),
                                             c_word_to_ipv4(store_srv_ipaddr), store_srv_port);

        chttp_req_clean(&chttp_req);
        chttp_rsp_clean(&chttp_rsp);
        return (EC_FALSE);
    }

    dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_cancel: "
                                         "terminate '%.*s' on %s:%ld done => status %u\n",
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
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "info:cxfs_wait_file_owner_terminate: "
                                                     "not found tasks_cfg of node %s\n",
                                                     c_word_to_ipv4(MOD_NODE_TCID(mod_node)));
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

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_terminate : "
                                                 "file %s tag %ld terminate owner: "
                                                 "tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
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

            task_p2p_inc(task_mgr, CMPI_ANY_MODI, mod_node,
                         &ret,
                         FI_super_cond_terminate, CMPI_ERROR_MODI, tag, CXFS_WAIT_FILE_NAME(cxfs_wait_file));

            dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_terminate : "
                                                 "file %s tag %ld terminate owner: "
                                                 "tcid %s, comm %ld, rank %ld, modi %ld => kick off\n",
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

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] cxfs_wait_file_owner_terminate : "
                                         "file %s tag %ld terminate none due to no owner\n",
                                         (char *)CXFS_WAIT_FILE_NAME_STR(cxfs_wait_file), tag);

    return (EC_TRUE);
}

EC_BOOL cxfs_wait_file_owner_terminate(CXFS_WAIT_FILE *cxfs_wait_file, const UINT32 tag)
{
    return cxfs_wait_file_owner_terminate_over_bgn(cxfs_wait_file, tag);
}

STATIC_CAST static EC_BOOL __cxfs_file_wait(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec)
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
    cxfs_wait_file_expire_set(cxfs_wait_file, expire_nsec);

    crb_node = crb_tree_insert_data(CXFS_MD_WAIT_FILES(cxfs_md), (void *)cxfs_wait_file);/*compare name*/
    if(NULL_PTR == crb_node)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_file_wait: "
                                             "insert file %s to wait files tree failed\n",
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
        cxfs_wait_file_owner_push(cxfs_wait_file_duplicate, mod_node);

        dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_file_wait: "
                                             "push %s to duplicated file '%s' in wait files tree done\n",
                                             MOD_NODE_TCID_STR(mod_node),
                                             (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*register remote token owner to it*/
    cxfs_wait_file_owner_push(cxfs_wait_file, mod_node);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_file_wait: "
                                         "push %s to inserted file %s in wait files tree done\n",
                                         MOD_NODE_TCID_STR(mod_node),
                                         (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL cxfs_file_wait(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, UINT32 *file_size, UINT32 *data_ready)
{
#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_wait: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    while(NULL_PTR != data_ready)
    {
        uint64_t        file_size_t;
        if(EC_OBSCURE == (*data_ready))
        {
            (*data_ready) = EC_FALSE;
            break; /*fall through*/
        }

        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/

        /*if data is already ready, return now*/
        if(EC_TRUE == cxfs_file_size(cxfs_md_id, file_path, &file_size_t))
        {
            if(NULL_PTR != file_size)
            {
                (*file_size) = (UINT32)file_size_t;
            }

            (*data_ready) = EC_TRUE;

            /*notify all waiters*/
            cxfs_file_notify(cxfs_md_id, file_path); /*patch*/

            return (EC_TRUE);
        }

        (*data_ready) = EC_FALSE;
        break; /*fall through*/
    }

    if(EC_FALSE == __cxfs_file_wait(cxfs_md_id, mod_node, file_path, expire_nsec))
    {
        return (EC_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_file_wait_ready(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, UINT32 *data_ready)
{
#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_wait_ready: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    return cxfs_file_wait(cxfs_md_id, mod_node, file_path, expire_nsec, NULL_PTR, data_ready);
}

EC_BOOL cxfs_file_wait_e(const UINT32 cxfs_md_id, const MOD_NODE *mod_node, const CSTRING *file_path, const UINT32 expire_nsec, UINT32 *offset, const UINT32 max_len, UINT32 *len, UINT32 *data_ready)
{
    //CXFS_MD          *cxfs_md;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_wait_e: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    while(NULL_PTR != data_ready)
    {
        CXFSNP_FNODE        cxfsnp_fnode;

        if(EC_OBSCURE == (*data_ready))
        {
            (*data_ready) = EC_FALSE;
            break; /*fall through*/
        }

        /*trick! when input data_ready = EC_OBSCURE, wait file notification only but not read data*/

        /*if data is already ready, return now*/

        //CXFS_STAT_READ_COUNTER(CXFS_MD_STAT(cxfs_md)) ++;

        cxfsnp_fnode_init(&cxfsnp_fnode);

        if(EC_TRUE == cxfs_read_npp(cxfs_md_id, file_path, &cxfsnp_fnode))
        {
            UINT32          file_size;

            (*data_ready) = EC_TRUE;

            file_size = CXFSNP_FNODE_FILESZ(&cxfsnp_fnode);

            if((*offset) >= file_size)
            {
                (*len) = 0;
                return (EC_TRUE);
            }

            if(0 == max_len)
            {
                (*len) = file_size - (*offset);
            }
            else
            {
                (*len) = DMIN(max_len, file_size - (*offset));
            }

            (*offset) += (*len);

            /*notify all waiters*/
            cxfs_file_notify(cxfs_md_id, file_path); /*patch*/

            return (EC_TRUE);
        }

        (*data_ready) = EC_FALSE;
        break; /*fall through*/
    }

    if(EC_FALSE == __cxfs_file_wait(cxfs_md_id, mod_node, file_path, expire_nsec))
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_notify: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_terminate: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_file_terminate: "
                                             "terminate waiters of file '%s' failed\n",
                                             (char *)CSTRING_STR(file_path));
        return (EC_FALSE);
    }

    crb_tree_delete(CXFS_MD_WAIT_FILES(cxfs_md), crb_node);

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_file_terminate: "
                                         "terminate waiters of file '%s' done\n",
                                         (char *)CSTRING_STR(file_path));
    return (EC_TRUE);
}

/*------------------------------------------------ interface for file lock ------------------------------------------------*/
CXFS_LOCKED_FILE *cxfs_locked_file_new()
{
    CXFS_LOCKED_FILE *cxfs_locked_file;
    alloc_static_mem(MM_CXFS_LOCKED_FILE, &cxfs_locked_file, LOC_CXFS_0015);
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
        free_static_mem(MM_CXFS_LOCKED_FILE, cxfs_locked_file, LOC_CXFS_0016);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_locked_files_print: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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
    CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file)  = (UINT32)c_get_cur_time_nsec();

    return (EC_TRUE);
}

EC_BOOL cxfs_locked_file_is_expire(const CXFS_LOCKED_FILE *cxfs_locked_file)
{
    UINT32 cur_time;

    cur_time = (UINT32)c_get_cur_time_nsec();

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_locked_file_is_expire: diff_nsec %ld, timeout_nsec %ld\n",
                        cur_time - CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file),
                        CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file));
    if(cur_time >= CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file) + CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file))
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
    UINT32 cur_time;

    cur_time = (UINT32)c_get_cur_time_nsec();

    dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] __cxfs_locked_file_need_retire: diff_nsec %ld, timeout_nsec %ld\n",
                                          cur_time - CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file),
                                          CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file));
    if(cur_time >= CXFS_LOCKED_FILE_START_TIME(cxfs_locked_file) + 2 * CXFS_LOCKED_FILE_EXPIRE_NSEC(cxfs_locked_file))
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_locked_file_retire: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

STATIC_CAST static EC_BOOL __cxfs_file_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 expire_nsec, CBYTES *token, UINT32 *locked_already)
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

        dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_file_lock: update file %s to locked files tree done\n",
                            (char *)cstring_get_str(file_path));
        return (EC_TRUE);
    }

    /*now cxfs_locked_file_tmp already insert and mount into tree*/
    cbytes_clone(CXFS_LOCKED_FILE_TOKEN(cxfs_locked_file), token);

    dbg_log(SEC_0192_CXFS, 5)(LOGSTDOUT, "[DEBUG] __cxfs_file_lock: insert file %s to locked files tree done\n",
                        (char *)cstring_get_str(file_path));
    return (EC_TRUE);
}

EC_BOOL cxfs_file_lock(const UINT32 cxfs_md_id, const CSTRING *file_path, const UINT32 expire_nsec, CSTRING *token_str, UINT32 *locked_already)
{
    //CXFS_MD      *cxfs_md;

    CBYTES        token_cbyte;
    UINT8         auth_token[CMD5_DIGEST_LEN * 8];
    UINT32        auth_token_len;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_lock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cbytes_init(&token_cbyte);

    if(EC_FALSE == __cxfs_file_lock(cxfs_md_id, file_path, expire_nsec, &token_cbyte, locked_already))
    {
        return (EC_FALSE);
    }

    cbase64_encode(CBYTES_BUF(&token_cbyte), CBYTES_LEN(&token_cbyte), auth_token, sizeof(auth_token), &auth_token_len);
    cstring_append_chars(token_str, auth_token_len, auth_token, LOC_CXFS_0017);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_unlock: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    //cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cbase64_decode((UINT8 *)CSTRING_STR(token_str), CSTRING_LEN(token_str), auth_token, sizeof(auth_token), &auth_token_len);
    cbytes_mount(&token_cbyte, auth_token_len, auth_token, BIT_FALSE);

    if(EC_FALSE == __cxfs_file_unlock(cxfs_md_id, file_path, &token_cbyte))
    {
        cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR, NULL_PTR);
        return (EC_FALSE);
    }

    cbytes_umount(&token_cbyte, NULL_PTR, NULL_PTR, NULL_PTR);
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_file_unlock_notify: cxfs module #%ld not started.\n",
                cxfs_md_id);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_reserve: data_len %u overflow\n",
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

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_release: data_len %u overflow\n",
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

    if(CXFSPGB_CACHE_MAX_BYTE_SIZE < CXFSOP_DN_NODE_DATA_LEN(cxfsop_dn_node))
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:__cxfs_replay_op_dn_recycle: data_len %u overflow\n",
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
EC_BOOL cxfs_process_op_old(const UINT32 cxfs_md_id)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

    static uint64_t  time_msec_next = 0; /*init*/

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_process_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(SWITCH_OFF == CXFS_OP_SWITCH)
    {
        return (EC_TRUE);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md);

    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)
    && CXFS_OP_TABLE_DISK_MAX_USED_NBYTES <= CXFS_MD_OP_DUMP_OFFSET(cxfs_md))
    {
        MOD_NODE      mod_node;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_process_op: "
                                             "trigger sync\n");

        CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_TRUE; /*set sync mode*/

        MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&mod_node) = cxfs_md_id;

        task_p2p_no_wait(cxfs_md_id, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                     &mod_node,
                     NULL_PTR,
                     FI_cxfs_sync, CMPI_ERROR_MODI);

        /*not process op during sync*/

        return (EC_TRUE);
    }

    /*note: when sync flag is true, xfs is prepare for syncing and would rewind dump offset after that*/

    /*dump op even in sync mode*/
    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)
    && NULL_PTR != cxfsop_mgr)
    {
        uint64_t         time_msec_cur;
        uint64_t         op_used;

        time_msec_cur = c_get_cur_time_msec();

        if(0 == time_msec_next)
        {
            time_msec_next = time_msec_cur + CXFS_OP_DUMP_MCACHE_MAX_IDLE_NSEC * 1000; /*10s later*/
        }

        op_used = cxfsop_mgr_used(cxfsop_mgr);

        if(CXFS_OP_DUMP_MCACHE_MAX_USED_NBYTES < op_used    /*used reach thread*/
        || (0 < op_used && time_msec_cur >= time_msec_next))/*idle elapsed reach thread*/
        {
            MOD_NODE      mod_node;

            CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_TRUE; /*set flag as barrier*/

            MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
            MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
            MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
            MOD_NODE_MODI(&mod_node) = cxfs_md_id;

            task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                         &mod_node,
                         NULL_PTR,
                         FI_cxfs_dump_op, CMPI_ERROR_MODI);

            time_msec_next = time_msec_cur + CXFS_OP_DUMP_MCACHE_MAX_IDLE_NSEC * 1000; /*10s later*/
        }
    }

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_op,
                        (void *)cxfs_md_id);

    return (EC_TRUE);
}

EC_BOOL cxfs_process_op(const UINT32 cxfs_md_id)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_process_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(SWITCH_OFF == CXFS_OP_SWITCH)
    {
        return (EC_TRUE);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md);

    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)
    && CXFS_OP_TABLE_DISK_MAX_USED_NBYTES <= CXFS_MD_OP_DUMP_OFFSET(cxfs_md))
    {
        MOD_NODE      mod_node;

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_process_op: "
                                             "trigger sync\n");

        CXFS_MD_SYNC_FLAG(cxfs_md) = BIT_TRUE; /*set sync mode*/

        MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&mod_node) = cxfs_md_id;

        task_p2p_no_wait(cxfs_md_id, TASK_ALWAYS_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                     &mod_node,
                     NULL_PTR,
                     FI_cxfs_sync, CMPI_ERROR_MODI);

        /*not process op during sync*/

        return (EC_TRUE);
    }

    /*note: when sync flag is true, xfs is prepare for syncing and would rewind dump offset after that*/

    if(1/*BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)*/
    && NULL_PTR != cxfsop_mgr
    && CXFS_OP_DUMP_MCACHE_MAX_USED_NBYTES < cxfsop_mgr_used(cxfsop_mgr))
    {
        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_create(CXFS_OP_DUMP_MCACHE_MAX_SIZE_NBYTES);
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_process_op: "
                                                 "[new] create op mgr failed\n");

            CXFS_MD_OP_MGR(cxfs_md)       = cxfsop_mgr; /*restore*/
            return (EC_FALSE);
        }

        if(NULL_PTR != CXFS_MD_DN(cxfs_md)
        && NULL_PTR != CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)))
        {
            cxfsop_mgr_mount_camd(CXFS_MD_OP_MGR(cxfs_md), CXFSDN_CAMD_MD(CXFS_MD_DN(cxfs_md)));
            dbg_log(SEC_0192_CXFS, 9)(LOGSTDOUT, "[DEBUG] cxfs_process_op: "
                                                 "[new] mount camd to op mgr done\n");
        }

        if(NULL_PTR != CXFS_MD_NPP(cxfs_md)
        && NULL_PTR != CXFS_MD_OP_MGR(cxfs_md))
        {
            cxfsnp_mgr_umount_op_mgr(CXFS_MD_NPP(cxfs_md));                         /*umount old*/
            cxfsnp_mgr_mount_op_mgr(CXFS_MD_NPP(cxfs_md), CXFS_MD_OP_MGR(cxfs_md)); /*mount new*/
        }

        clist_push_back(CXFS_MD_OP_MGR_LIST(cxfs_md), (void *)cxfsop_mgr);

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_process_op: "
                                             "[new] create op mgr %p done => op mgrs %ld\n",
                                             CXFS_MD_OP_MGR(cxfs_md),
                                             clist_size(CXFS_MD_OP_MGR_LIST(cxfs_md)));
    }

    task_brd_process_add(task_brd_default_get(),
                        (TASK_BRD_CALLBACK)cxfs_process_op,
                        (void *)cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDNULL, "[DEBUG] cxfs_process_op: "
                                         "[check] op mgrs %ld, sync flag %u, op dump flag %u\n",
                                         clist_size(CXFS_MD_OP_MGR_LIST(cxfs_md)),
                                         CXFS_MD_SYNC_FLAG(cxfs_md),
                                         CXFS_MD_OP_DUMP_FLAG(cxfs_md));

    if(EC_FALSE == clist_is_empty(CXFS_MD_OP_MGR_LIST(cxfs_md))
    && BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_FALSE == CXFS_MD_OP_DUMP_FLAG(cxfs_md))
    {
        MOD_NODE      mod_node;

        CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_TRUE; /*set flag as barrier*/

        MOD_NODE_TCID(&mod_node) = CMPI_LOCAL_TCID;
        MOD_NODE_COMM(&mod_node) = CMPI_LOCAL_COMM;
        MOD_NODE_RANK(&mod_node) = CMPI_LOCAL_RANK;
        MOD_NODE_MODI(&mod_node) = cxfs_md_id;

        task_p2p_no_wait(cxfs_md_id, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NOT_NEED_RSP_FLAG, TASK_NEED_NONE_RSP,
                     &mod_node,
                     NULL_PTR,
                     FI_cxfs_dump_op, CMPI_ERROR_MODI);
    }

    return (EC_TRUE);
}

/**
*
*  dump operations
*
**/
EC_BOOL cxfs_dump_op_old(const UINT32 cxfs_md_id)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(SWITCH_OFF == CXFS_OP_SWITCH)
    {
        return (EC_TRUE);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    cxfsop_mgr = CXFS_MD_OP_MGR(cxfs_md); /*save old*/

    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_TRUE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)
    && NULL_PTR != cxfsop_mgr)
    {
        CXFSCFG         *cxfscfg;
        UINT32           op_offset;     /*absolute offset in disk*/

        uint64_t         s_op_offset;   /*relative offset in op table*/
        uint64_t         e_op_offset;   /*relative offset in op table*/
        uint32_t         dump_retries;

        CXFS_MD_OP_MGR(cxfs_md) = cxfsop_mgr_create(CXFS_OP_DUMP_MCACHE_MAX_SIZE_NBYTES);
        if(NULL_PTR == CXFS_MD_OP_MGR(cxfs_md))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_op: "
                                                 "[new] create op mgr failed\n");

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
            cxfsnp_mgr_umount_op_mgr(CXFS_MD_NPP(cxfs_md));                         /*umount old*/
            cxfsnp_mgr_mount_op_mgr(CXFS_MD_NPP(cxfs_md), CXFS_MD_OP_MGR(cxfs_md)); /*mount new*/
        }

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                             "[new] create op mgr done\n");

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: start\n");

        cxfscfg = CXFS_MD_CFG(cxfs_md);

        /*absolute offset in disk*/
        op_offset = (UINT32)(CXFSCFG_OP_S_OFFSET(cxfscfg) + CXFS_MD_OP_DUMP_OFFSET(cxfs_md));

        /*relative offset in op table*/
        s_op_offset = (CXFS_MD_OP_DUMP_OFFSET(cxfs_md));
        e_op_offset = (s_op_offset + cxfsop_mgr_used(cxfsop_mgr));

        ASSERT(e_op_offset < CXFS_OP_TABLE_DISK_MAX_SIZE_NBYTES); /*should never reach the end of op table*/

        dump_retries = 0;
        while(EC_FALSE == cxfsop_mgr_dump(cxfsop_mgr, &op_offset))
        {
            dump_retries ++;

            if(10 <= dump_retries) /*exception last for 300s*/
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "fatal error:cxfs_dump_op: "
                                                     "dump op %p to disk failed "
                                                     "=> stop xfs now and sync data to disk\n",
                                                     cxfsop_mgr);

                /*stop recording op by free op mgr of cxfs module*/
                cxfsop_mgr_free(CXFS_MD_OP_MGR(cxfs_md));
                CXFS_MD_OP_MGR(cxfs_md) = NULL_PTR;

                cxfsop_mgr_free(cxfsop_mgr);

                CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_FALSE;    /*restore*/

                cxfs_end(cxfs_md_id); /*stop xfs*/

                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "fatal error:cxfs_dump_op: "
                                                 "dump op %p to disk failed %u times "
                                                 "=> retry\n",
                                                 cxfsop_mgr, dump_retries);
        }

        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                             "op %p dump offset %ld => %ld\n",
                                             cxfsop_mgr,
                                             CXFS_MD_OP_DUMP_OFFSET(cxfs_md),
                                             op_offset - CXFSCFG_OP_S_OFFSET(cxfscfg));

        CXFS_MD_OP_DUMP_OFFSET(cxfs_md) = op_offset - CXFSCFG_OP_S_OFFSET(cxfscfg); /*update dump offset*/

        cxfsop_mgr_free(cxfsop_mgr);

        CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_FALSE;    /*restore*/

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: done\n");
    }

    return (EC_TRUE);
}

EC_BOOL cxfs_dump_op(const UINT32 cxfs_md_id)
{
    CXFS_MD         *cxfs_md;
    CXFSOP_MGR      *cxfsop_mgr;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_dump_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(SWITCH_OFF == CXFS_OP_SWITCH)
    {
        return (EC_TRUE);
    }

    cxfs_md = CXFS_MD_GET(cxfs_md_id);

    dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                         "[check] op mgrs %ld, sync flag %u, op dump flag %u\n",
                                         clist_size(CXFS_MD_OP_MGR_LIST(cxfs_md)),
                                         CXFS_MD_SYNC_FLAG(cxfs_md),
                                         CXFS_MD_OP_DUMP_FLAG(cxfs_md));

    if(BIT_FALSE == CXFS_MD_SYNC_FLAG(cxfs_md)
    && BIT_TRUE == CXFS_MD_OP_DUMP_FLAG(cxfs_md)
    && NULL_PTR != (cxfsop_mgr = clist_pop_front(CXFS_MD_OP_MGR_LIST(cxfs_md))))
    {
        CXFSCFG         *cxfscfg;
        UINT32           op_offset;     /*absolute offset in disk*/

        uint64_t         s_op_offset;   /*relative offset in op table*/
        uint64_t         e_op_offset;   /*relative offset in op table*/
        void            *data;

        uint64_t         page_size_nbytes;
        uint64_t         page_size_mask;

        //CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_TRUE; /*set barrier flag*/

        cxfscfg = CXFS_MD_CFG(cxfs_md);

        /*absolute offset in disk*/
        op_offset = (UINT32)(CXFSCFG_OP_S_OFFSET(cxfscfg) + CXFS_MD_OP_DUMP_OFFSET(cxfs_md));

        /*relative offset in op table*/
        s_op_offset = (CXFS_MD_OP_DUMP_OFFSET(cxfs_md));
        e_op_offset = (s_op_offset + cxfsop_mgr_used(cxfsop_mgr));

        ASSERT(e_op_offset < CXFS_OP_TABLE_DISK_MAX_SIZE_NBYTES); /*should never reach the end of op table*/

        page_size_nbytes = CMCPGB_PAGE_SIZE_NBYTES;
        page_size_mask   = CMCPGB_PAGE_SIZE_NBYTES - 1;

        data = CXFSOP_MGR_DATA(cxfsop_mgr);

        while(s_op_offset < e_op_offset)
        {
            UINT32    n_op_offset;
            UINT32    data_len;

            n_op_offset = (UINT32)VAL_ALIGN_NEXT(s_op_offset + page_size_nbytes, page_size_mask);
            n_op_offset = (UINT32)DMIN(n_op_offset, e_op_offset);
            data_len    = (UINT32)(n_op_offset - s_op_offset);

            dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                                 "op mgr %p, dump data %p, "
                                                 "[%lu, %lu) => data len %ld to offset %ld\n",
                                                 cxfsop_mgr, data,
                                                 s_op_offset, e_op_offset,
                                                 data_len, op_offset);

            if(EC_FALSE == camd_file_write_dio((CAMD_MD *)CXFSOP_MGR_CAMD(cxfsop_mgr),
                                                &op_offset, data_len, (UINT8 *)data))
            {
                dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "error:cxfs_dump_op: "
                                                     "op mgr %p, dump data %p, "
                                                     "data len %ld to offset %ld failed\n",
                                                     cxfsop_mgr, data, data_len, op_offset);

                clist_push_front(CXFS_MD_OP_MGR_LIST(cxfs_md), (void *)cxfsop_mgr);

                CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_FALSE;    /*restore*/
                return (EC_FALSE);
            }

            dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                                 "op mgr %p, dump data %p, "
                                                 "len %ld => offset %ld\n",
                                                 cxfsop_mgr, data, data_len, op_offset);

            /*move forward*/
            s_op_offset = n_op_offset;
            data       += data_len;
        }

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: "
                                             "op mgr %p dump offset %ld => %ld\n",
                                             cxfsop_mgr,
                                             CXFS_MD_OP_DUMP_OFFSET(cxfs_md),
                                             op_offset - CXFSCFG_OP_S_OFFSET(cxfscfg));

        CXFS_MD_OP_DUMP_OFFSET(cxfs_md) = op_offset - CXFSCFG_OP_S_OFFSET(cxfscfg); /*update dump offset*/

        cxfsop_mgr_free(cxfsop_mgr);

        CXFS_MD_OP_DUMP_FLAG(cxfs_md) = BIT_FALSE;    /*restore*/

        dbg_log(SEC_0192_CXFS, 3)(LOGSTDOUT, "[DEBUG] cxfs_dump_op: done => left %ld op mgrs\n",
                                             clist_size(CXFS_MD_OP_MGR_LIST(cxfs_md)));
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
        if(CXFSOP_MAGIC_VAL != CXFSOP_COMM_HDR_MAGIC(cxfsop_comm_hdr))
        {
            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:__cxfs_replay_op: "
                                                 "invalid magic num %#x\n",
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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_replay_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    if(SWITCH_OFF == CXFS_OP_SWITCH)
    {
        return (EC_TRUE);
    }

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

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_pop_op: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

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

/**
*
*  register xfs to ngx consistent hash table
*
**/
EC_BOOL cxfs_reg_ngx(const UINT32 cxfs_md_id)
{
    TASK_BRD                *task_brd;
    CLUSTER_CFG             *cluster_cfg;           /*cluster xfs-ngx*/
    CLUSTER_NODE_CFG        *cluster_node_cfg_xfs;  /*xfs node in cluster xfs-ngx*/

    const char              *role_str_ngx;          /*ngx role. if xfs is master, ngx is slave, otherwise master*/

    UINT32                   cluster_node_num;
    UINT32                   cluster_node_pos;

    TASK_MGR                *task_mgr;
    CMON_NODE                cmon_node;
    EC_BOOL                  ret;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_reg_ngx: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    task_brd = task_brd_default_get();

    cluster_cfg = sys_cfg_get_cluster_cfg_by_name_str(TASK_BRD_SYS_CFG(task_brd), (const char *)"xfs-ngx:ngx-xfs");
    if(NULL_PTR == cluster_cfg)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:cxfs_reg_ngx: no cluster 'xfs-ngx' or 'ngx-xfs'\n");
        return (EC_FALSE);
    }

    cluster_node_cfg_xfs = cluster_cfg_search_by_tcid_rank(cluster_cfg, TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
    if(NULL_PTR == cluster_node_cfg_xfs)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_reg_ngx: current tcid %s rank %ld not belong to cluster %ld\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), CLUSTER_CFG_ID(cluster_cfg));
        return (EC_FALSE);
    }

    /*init*/
    cmon_node_init(&cmon_node);

    CMON_NODE_TCID(&cmon_node)   = TASK_BRD_TCID(task_brd);
    CMON_NODE_IPADDR(&cmon_node) = TASK_BRD_IPADDR(task_brd);
    CMON_NODE_PORT(&cmon_node)   = TASK_BRD_PORT(task_brd);
    CMON_NODE_MODI(&cmon_node)   = cxfs_md_id;
    CMON_NODE_STATE(&cmon_node)  = CMON_NODE_IS_DOWN; /*set down and activate later*/

    ret = EC_FALSE;

    role_str_ngx = NULL_PTR;

    /*determine ngx role*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg_xfs, (const char *)"master"))
    {
        role_str_ngx = (const char *)"slave";
    }
    else
    {
        role_str_ngx = (const char *)"master";
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    /*scan out all ngx*/
    cluster_node_num = cvector_size(CLUSTER_CFG_NODES(cluster_cfg));
    for(cluster_node_pos = 0; cluster_node_pos < cluster_node_num; cluster_node_pos ++)
    {
        CLUSTER_NODE_CFG        *cluster_node_cfg_ngx;  /*ngx node in cluster xfs-ngx*/
        UINT32                   rank_num;
        UINT32                   rank_pos;

        cluster_node_cfg_ngx = cvector_get(CLUSTER_CFG_NODES(cluster_cfg), cluster_node_pos);
        if(NULL_PTR == cluster_node_cfg_ngx)
        {
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_role_str(cluster_node_cfg_ngx, role_str_ngx))
        {
            continue;
        }

        if(EC_FALSE == super_check_tcid_connected(0, CLUSTER_NODE_CFG_TCID(cluster_node_cfg_ngx)))
        {
            continue;
        }

        rank_num = cvector_size(CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg_ngx));
        for(rank_pos = 0; rank_pos < rank_num; rank_pos ++)
        {
            MOD_NODE                recv_mod_node;
            UINT32                  rank;

            rank = (UINT32)cvector_get(CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg_ngx), rank_pos);

            MOD_NODE_TCID(&recv_mod_node) = CLUSTER_NODE_CFG_TCID(cluster_node_cfg_ngx);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = rank;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one cmon*/

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_reg_ngx: "
                                                 "reg ngx tcid %s rank %ld in cluster %ld\n",
                                                 c_word_to_ipv4(MOD_NODE_TCID(&recv_mod_node)),
                                                 MOD_NODE_RANK(&recv_mod_node),
                                                 CLUSTER_CFG_ID(cluster_cfg));


            task_p2p_inc(task_mgr, cxfs_md_id, &recv_mod_node,
                        &ret, FI_cmon_add_node, CMPI_ERROR_MODI, &cmon_node);

        }
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cmon_node_clean(&cmon_node);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_reg_ngx: done\n");

    return (EC_TRUE);
}

/**
*
*  activate xfs on all ngx
*  i.e., notify all ngx that I am up
*
**/
EC_BOOL cxfs_activate_ngx(const UINT32 cxfs_md_id)
{
    TASK_BRD                *task_brd;
    CLUSTER_CFG             *cluster_cfg;           /*cluster xfs-ngx*/
    CLUSTER_NODE_CFG        *cluster_node_cfg_xfs;  /*xfs node in cluster xfs-ngx*/

    const char              *role_str_ngx;          /*ngx role. if xfs is master, ngx is slave, otherwise master*/

    UINT32                   cluster_node_num;
    UINT32                   cluster_node_pos;

    TASK_MGR                *task_mgr;
    CMON_NODE                cmon_node;
    EC_BOOL                  ret;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_activate_ngx: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    task_brd = task_brd_default_get();

    cluster_cfg = sys_cfg_get_cluster_cfg_by_name_str(TASK_BRD_SYS_CFG(task_brd), (const char *)"xfs-ngx:ngx-xfs");
    if(NULL_PTR == cluster_cfg)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:cxfs_activate_ngx: no cluster 'xfs-ngx' or 'ngx-xfs'\n");
        return (EC_FALSE);
    }

    cluster_node_cfg_xfs = cluster_cfg_search_by_tcid_rank(cluster_cfg, TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
    if(NULL_PTR == cluster_node_cfg_xfs)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_activate_ngx: current tcid %s rank %ld not belong to cluster %ld\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), CLUSTER_CFG_ID(cluster_cfg));
        return (EC_FALSE);
    }

    /*init*/
    cmon_node_init(&cmon_node);

    CMON_NODE_TCID(&cmon_node)   = TASK_BRD_TCID(task_brd);
    CMON_NODE_IPADDR(&cmon_node) = TASK_BRD_IPADDR(task_brd);
    CMON_NODE_PORT(&cmon_node)   = TASK_BRD_PORT(task_brd);
    CMON_NODE_MODI(&cmon_node)   = cxfs_md_id;
    CMON_NODE_STATE(&cmon_node)  = CMON_NODE_IS_UP; /*notify ngx that xfs is up*/

    ret = EC_FALSE;

    role_str_ngx = NULL_PTR;

    /*determine ngx role*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg_xfs, (const char *)"master"))
    {
        role_str_ngx = (const char *)"slave";
    }
    else
    {
        role_str_ngx = (const char *)"master";
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    /*scan out all ngx*/
    cluster_node_num = cvector_size(CLUSTER_CFG_NODES(cluster_cfg));
    for(cluster_node_pos = 0; cluster_node_pos < cluster_node_num; cluster_node_pos ++)
    {
        CLUSTER_NODE_CFG        *cluster_node_cfg_ngx;  /*ngx node in cluster xfs-ngx*/
        UINT32                   rank_num;
        UINT32                   rank_pos;

        cluster_node_cfg_ngx = cvector_get(CLUSTER_CFG_NODES(cluster_cfg), cluster_node_pos);
        if(NULL_PTR == cluster_node_cfg_ngx)
        {
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_role_str(cluster_node_cfg_ngx, role_str_ngx))
        {
            continue;
        }

        if(EC_FALSE == super_check_tcid_connected(0, CLUSTER_NODE_CFG_TCID(cluster_node_cfg_ngx)))
        {
            continue;
        }

        rank_num = cvector_size(CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg_ngx));
        for(rank_pos = 0; rank_pos < rank_num; rank_pos ++)
        {
            MOD_NODE                recv_mod_node;
            UINT32                  rank;

            rank = (UINT32)cvector_get(CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg_ngx), rank_pos);

            MOD_NODE_TCID(&recv_mod_node) = CLUSTER_NODE_CFG_TCID(cluster_node_cfg_ngx);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = rank;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one cmon*/

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_activate_ngx: "
                                                 "activate ngx tcid %s rank %ld in cluster %ld\n",
                                                 c_word_to_ipv4(MOD_NODE_TCID(&recv_mod_node)),
                                                 MOD_NODE_RANK(&recv_mod_node),
                                                 CLUSTER_CFG_ID(cluster_cfg));


            task_p2p_inc(task_mgr, cxfs_md_id, &recv_mod_node,
                        &ret, FI_cmon_add_node, CMPI_ERROR_MODI, &cmon_node);

        }
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cmon_node_clean(&cmon_node);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_activate_ngx: done\n");

    return (EC_TRUE);
}

/**
*
*  deactivate xfs on all ngx
*  i.e., notify all ngx that I am down
*
**/
EC_BOOL cxfs_deactivate_ngx(const UINT32 cxfs_md_id)
{
    TASK_BRD                *task_brd;
    CLUSTER_CFG             *cluster_cfg;           /*cluster xfs-ngx*/
    CLUSTER_NODE_CFG        *cluster_node_cfg_xfs;  /*xfs node in cluster xfs-ngx*/

    const char              *role_str_ngx;          /*ngx role. if xfs is master, ngx is slave, otherwise master*/

    UINT32                   cluster_node_num;
    UINT32                   cluster_node_pos;

    TASK_MGR                *task_mgr;
    CMON_NODE                cmon_node;
    EC_BOOL                  ret;

#if (SWITCH_ON == CXFS_DEBUG_SWITCH)
    if ( CXFS_MD_ID_CHECK_INVALID(cxfs_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfs_deactivate_ngx: cxfs module #%ld not started.\n",
                cxfs_md_id);
        cxfs_print_module_status(cxfs_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFS, cxfs_md_id);
    }
#endif/*(SWITCH_ON == CXFS_DEBUG_SWITCH)*/

    task_brd = task_brd_default_get();

    cluster_cfg = sys_cfg_get_cluster_cfg_by_name_str(TASK_BRD_SYS_CFG(task_brd), (const char *)"xfs-ngx:ngx-xfs");
    if(NULL_PTR == cluster_cfg)
    {
        dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "warn:cxfs_deactivate_ngx: no cluster 'xfs-ngx' or 'ngx-xfs'\n");
        return (EC_FALSE);
    }

    cluster_node_cfg_xfs = cluster_cfg_search_by_tcid_rank(cluster_cfg, TASK_BRD_TCID(task_brd), TASK_BRD_RANK(task_brd));
    if(NULL_PTR == cluster_node_cfg_xfs)
    {
        dbg_log(SEC_0192_CXFS, 1)(LOGSTDOUT, "warn:cxfs_deactivate_ngx: current tcid %s rank %ld not belong to cluster %ld\n",
                           TASK_BRD_TCID_STR(task_brd), TASK_BRD_RANK(task_brd), CLUSTER_CFG_ID(cluster_cfg));
        return (EC_FALSE);
    }

    /*init*/
    cmon_node_init(&cmon_node);

    CMON_NODE_TCID(&cmon_node)   = TASK_BRD_TCID(task_brd);
    CMON_NODE_IPADDR(&cmon_node) = TASK_BRD_IPADDR(task_brd);
    CMON_NODE_PORT(&cmon_node)   = TASK_BRD_PORT(task_brd);
    CMON_NODE_MODI(&cmon_node)   = cxfs_md_id;
    CMON_NODE_STATE(&cmon_node)  = CMON_NODE_IS_DOWN; /*notify ngx that xfs is down*/

    ret = EC_FALSE;

    role_str_ngx = NULL_PTR;

    /*determine ngx role*/
    if(EC_TRUE == cluster_node_cfg_check_role_str(cluster_node_cfg_xfs, (const char *)"master"))
    {
        role_str_ngx = (const char *)"slave";
    }
    else
    {
        role_str_ngx = (const char *)"master";
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);

    /*scan out all ngx*/
    cluster_node_num = cvector_size(CLUSTER_CFG_NODES(cluster_cfg));
    for(cluster_node_pos = 0; cluster_node_pos < cluster_node_num; cluster_node_pos ++)
    {
        CLUSTER_NODE_CFG        *cluster_node_cfg_ngx;  /*ngx node in cluster xfs-ngx*/
        UINT32                   rank_num;
        UINT32                   rank_pos;

        cluster_node_cfg_ngx = cvector_get(CLUSTER_CFG_NODES(cluster_cfg), cluster_node_pos);
        if(NULL_PTR == cluster_node_cfg_ngx)
        {
            continue;
        }

        if(EC_FALSE == cluster_node_cfg_check_role_str(cluster_node_cfg_ngx, role_str_ngx))
        {
            continue;
        }

        rank_num = cvector_size(CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg_ngx));
        for(rank_pos = 0; rank_pos < rank_num; rank_pos ++)
        {
            MOD_NODE                recv_mod_node;
            UINT32                  rank;

            rank = (UINT32)cvector_get(CLUSTER_NODE_CFG_RANK_VEC(cluster_node_cfg_ngx), rank_pos);

            MOD_NODE_TCID(&recv_mod_node) = CLUSTER_NODE_CFG_TCID(cluster_node_cfg_ngx);
            MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
            MOD_NODE_RANK(&recv_mod_node) = rank;
            MOD_NODE_MODI(&recv_mod_node) = 0;/*only one cmon*/

            dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_deactivate_ngx: "
                                                 "deactivate ngx tcid %s rank %ld in cluster %ld\n",
                                                 c_word_to_ipv4(MOD_NODE_TCID(&recv_mod_node)),
                                                 MOD_NODE_RANK(&recv_mod_node),
                                                 CLUSTER_CFG_ID(cluster_cfg));


            task_p2p_inc(task_mgr, cxfs_md_id, &recv_mod_node,
                        &ret, FI_cmon_add_node, CMPI_ERROR_MODI, &cmon_node);

        }
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    cmon_node_clean(&cmon_node);

    dbg_log(SEC_0192_CXFS, 0)(LOGSTDOUT, "[DEBUG] cxfs_deactivate_ngx: done\n");

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

