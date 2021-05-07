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

#include "type.h"
#include "mm.h"
#include "log.h"
#include "cstring.h"

#include "cbc.h"
#include "cmisc.h"
#include "task.h"

#include "cbytes.h"

#include "cepoll.h"

#include "cnbd.h"
#include "cxfsc.h"
#include "cxfsnbd.h"
#include "cxfsnbdc.h"

#include "findex.inc"

#define CXFSNBDC_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFSNBDC))

#define CXFSNBDC_MD_GET(cxfsnbdc_md_id)     ((CXFSNBDC_MD *)cbc_md_get(MD_CXFSNBDC, (cxfsnbdc_md_id)))

#define CXFSNBDC_MD_ID_CHECK_INVALID(cxfsnbdc_md_id)  \
    ((CMPI_ANY_MODI != (cxfsnbdc_md_id)) && ((NULL_PTR == CXFSNBDC_MD_GET(cxfsnbdc_md_id)) || (0 == (CXFSNBDC_MD_GET(cxfsnbdc_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CXFSNBDC Module
*
**/
void cxfsnbdc_print_module_status(const UINT32 cxfsnbdc_md_id, LOG *log)
{
    CXFSNBDC_MD *cxfsnbdc_md;
    UINT32 this_cxfsnbdc_md_id;

    for( this_cxfsnbdc_md_id = 0; this_cxfsnbdc_md_id < CXFSNBDC_MD_CAPACITY(); this_cxfsnbdc_md_id ++ )
    {
        cxfsnbdc_md = CXFSNBDC_MD_GET(this_cxfsnbdc_md_id);

        if ( NULL_PTR != cxfsnbdc_md && 0 < cxfsnbdc_md->usedcounter )
        {
            sys_log(log,"CXFSNBDC Module # %ld : %ld refered\n",
                    this_cxfsnbdc_md_id,
                    cxfsnbdc_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CXFSNBDC module
*
*
**/
UINT32 cxfsnbdc_free_module_static_mem(const UINT32 cxfsnbdc_md_id)
{
#if (SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)
    if ( CXFSNBDC_MD_ID_CHECK_INVALID(cxfsnbdc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbdc_free_module_static_mem: cxfs module #%ld not started.\n",
                cxfsnbdc_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*(SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)*/

    free_module_static_mem(MD_CXFSNBDC, cxfsnbdc_md_id);

    return 0;
}

/**
*
* start CXFSNBDC module
*
**/
UINT32 cxfsnbdc_start(const CSTRING *nbd_dev_name,
                        const UINT32   nbd_blk_size, /*sector size*/
                        const UINT32   nbd_dev_size,
                        const UINT32   nbd_timeout,
                        const CSTRING *bucket_name,
                        const UINT32   cxfsc_tcid,
                        const UINT32   cxfsc_md_id)
{
    CXFSNBDC_MD     *cxfsnbdc_md;
    UINT32           cxfsnbdc_md_id;

    cbc_md_reg(MD_CXFSNBDC, 16);

    cxfsnbdc_md_id = cbc_md_new(MD_CXFSNBDC, sizeof(CXFSNBDC_MD));
    if(CMPI_ERROR_MODI == cxfsnbdc_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CXFSNBDC module */
    cxfsnbdc_md = (CXFSNBDC_MD *)cbc_md_get(MD_CXFSNBDC, cxfsnbdc_md_id);
    cxfsnbdc_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md)   = CMPI_ERROR_TCID;
    CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md)   = CMPI_ERROR_MODI;

    CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md)    = CMPI_ERROR_MODI;

    CXFSNBDC_MD_NBD_BLK_SIZE(cxfsnbdc_md) = 0;
    CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md) = 0;
    CXFSNBDC_MD_NBD_TIMEOUT(cxfsnbdc_md)  = 0;
    CXFSNBDC_MD_NBD_T_FLAGS(cxfsnbdc_md)  = 0;/*xxx*/

    CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md) = NULL_PTR;
    CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md)  = NULL_PTR;

    cxfsnbdc_md->usedcounter = 1;

    /* fetch config */

    CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md)   = cxfsc_tcid;
    CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md)   = cxfsc_md_id;

    /*debug config*/
    CXFSNBDC_MD_NBD_BLK_SIZE(cxfsnbdc_md) = nbd_blk_size;
    CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md) = nbd_dev_size;
    CXFSNBDC_MD_NBD_TIMEOUT(cxfsnbdc_md)  = nbd_timeout;
    CXFSNBDC_MD_NBD_T_FLAGS(cxfsnbdc_md)  = 0;/*xxx*/

    if(NULL_PTR == bucket_name)
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_start:"
                                                 "bucket_name is null\n");

        cxfsnbdc_end(cxfsnbdc_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md) = cstring_dup(bucket_name);
    if(NULL_PTR == CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_start:"
                                                 "new bucket_name '%s' failed\n",
                                                 (char *)cstring_get_str(bucket_name));

        cxfsnbdc_end(cxfsnbdc_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md) = cstring_dup(nbd_dev_name);
    if(NULL_PTR == CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_start:"
                                                 "new dev name '%s' failed\n",
                                                 (char *)cstring_get_str(nbd_dev_name));

        cxfsnbdc_end(cxfsnbdc_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md) = cnbd_start(CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md),
                                                  CXFSNBDC_MD_NBD_BLK_SIZE(cxfsnbdc_md),
                                                  CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md),
                                                  CXFSNBDC_MD_NBD_TIMEOUT(cxfsnbdc_md),
                                                  CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md));

    if(CMPI_ERROR_MODI == CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_start:"
            "start nbd (dev %s, bucket %s, block size %lu, dev size %lu, timeout %lu) failed\n",
            (char *)CXFSNBDC_MD_NBD_DEV_NAME_STR(cxfsnbdc_md),
            (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
            CXFSNBDC_MD_NBD_BLK_SIZE(cxfsnbdc_md),
            CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md),
            CXFSNBDC_MD_NBD_TIMEOUT(cxfsnbdc_md));

        cxfsnbdc_end(cxfsnbdc_md_id);
        return (CMPI_ERROR_MODI);
    }

    dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_start:"
        "start nbd (dev %s, bucket %s, block size %lu, dev size %lu, timeout %lu) done\n",
        (char *)CXFSNBDC_MD_NBD_DEV_NAME_STR(cxfsnbdc_md),
        (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
        CXFSNBDC_MD_NBD_BLK_SIZE(cxfsnbdc_md),
        CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md),
        CXFSNBDC_MD_NBD_TIMEOUT(cxfsnbdc_md));

    cnbd_set_bucket_read_handler(CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md), cxfsnbdc_bucket_read);
    cnbd_set_bucket_write_handler(CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md), cxfsnbdc_bucket_write);

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfsnbdc_end, cxfsnbdc_md_id);

    dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_start: "
                                             "start CXFSNBDC module #%ld\n",
                                             cxfsnbdc_md_id);

    return ( cxfsnbdc_md_id );
}

/**
*
* end CXFSNBDC module
*
**/
void cxfsnbdc_end(const UINT32 cxfsnbdc_md_id)
{
    CXFSNBDC_MD *cxfsnbdc_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cxfsnbdc_end, cxfsnbdc_md_id);

    cxfsnbdc_md = CXFSNBDC_MD_GET(cxfsnbdc_md_id);
    if(NULL_PTR == cxfsnbdc_md)
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_end: "
                                                 "cxfsnbdc_md_id = %ld not exist.\n",
                                                 cxfsnbdc_md_id);
        dbg_exit(MD_CXFSNBDC, cxfsnbdc_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cxfsnbdc_md->usedcounter )
    {
        cxfsnbdc_md->usedcounter --;
        return ;
    }

    if ( 0 == cxfsnbdc_md->usedcounter )
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_end: "
                                                 "cxfsnbdc_md_id = %ld is not started.\n",
                                                 cxfsnbdc_md_id);
        dbg_exit(MD_CXFSNBDC, cxfsnbdc_md_id);
    }

    if(CMPI_ERROR_MODI != CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md))
    {
        cnbd_end(CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md));
        CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md) = CMPI_ERROR_MODI;
    }

    if(NULL_PTR != CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md))
    {
        cstring_free(CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md));
        CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md))
    {
        cstring_free(CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md));
        CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md) = NULL_PTR;
    }

    CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md)   = CMPI_ERROR_TCID;
    CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md)   = CMPI_ERROR_MODI;

    CXFSNBDC_MD_NBD_BLK_SIZE(cxfsnbdc_md) = 0;
    CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md) = 0;
    CXFSNBDC_MD_NBD_TIMEOUT(cxfsnbdc_md)  = 0;
    CXFSNBDC_MD_NBD_T_FLAGS(cxfsnbdc_md)  = 0;

    /* free module : */
    //cxfsnbdc_free_module_static_mem(cxfsnbdc_md_id);

    cxfsnbdc_md->usedcounter = 0;

    cbc_md_free(MD_CXFSNBDC, cxfsnbdc_md_id);

    dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_end: "
                                             "stop CXFSNBDC module #%ld\n",
                                             cxfsnbdc_md_id);

    return ;
}

EC_BOOL cxfsnbdc_bucket_check(const UINT32 cxfsnbdc_md_id)
{
    CXFSNBDC_MD  *cxfsnbdc_md;
    UINT32        bucket_size;

    UINT32        cxfs_seg_num;
    UINT32        cxfs_seg_idx;

#if (SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)
    if ( CXFSNBDC_MD_ID_CHECK_INVALID(cxfsnbdc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbdc_bucket_check: cxfsnbdc module #%ld not started.\n",
                cxfsnbdc_md_id);
        cxfsnbdc_print_module_status(cxfsnbdc_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBDC, cxfsnbdc_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)*/

    cxfsnbdc_md = CXFSNBDC_MD_GET(cxfsnbdc_md_id);

    if(EC_TRUE == cstring_is_empty(CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md)))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_check:"
                                                 "no bucket name\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_TCID == CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_check:"
                                                 "cxfsc tcid is invalid\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_check:"
                                                 "cxfsc modi is invalid\n");
        return (EC_FALSE);
    }

    bucket_size  = (UINT32)CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md);
    cxfs_seg_num = ((bucket_size + CXFSNBD_CXFS_SEG_SIZE - 1) / CXFSNBD_CXFS_SEG_SIZE);

    for(cxfs_seg_idx = 0; cxfs_seg_idx < cxfs_seg_num; cxfs_seg_idx ++)
    {
        CSTRING    *cxfs_seg_fname;
        UINT32      cxfs_seg_size;
        MOD_NODE    recv_mod_node;
        EC_BOOL     ret;

        cxfs_seg_fname = cxfsnbd_make_bucket_seg_name( CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md), cxfs_seg_idx);
        if(NULL_PTR == cxfs_seg_fname)
        {
            dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_check:"
                                                     "bucket %s make seg %lu name failed\n",
                                                     (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                     cxfs_seg_idx);

            return (EC_FALSE);
        }

        dbg_log(SEC_0142_CXFSNBDC, 6)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_check:"
                                                 "make bucket seg name '%s' done\n",
                                                 (char *)cstring_get_str(cxfs_seg_fname));

        ret = EC_FALSE;
        cxfs_seg_size = 0;

        MOD_NODE_TCID(&recv_mod_node) = CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
        MOD_NODE_MODI(&recv_mod_node) = CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md);

        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfsc_file_size, CMPI_ERROR_MODI, cxfs_seg_fname, &cxfs_seg_size);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_check:"
                                                     "bucket %s seg %lu/%lu size failed\n",
                                                     (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                     cxfs_seg_idx, cxfs_seg_num);

            cstring_free(cxfs_seg_fname);
            return (EC_FALSE);
        }

        if(CXFSNBD_CXFS_SEG_SIZE != cxfs_seg_size)
        {
            dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_check:"
                                                     "bucket %s seg %lu/%lu size %lu != %lu\n",
                                                     (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                     cxfs_seg_idx, cxfs_seg_num,
                                                     cxfs_seg_size, CXFSNBD_CXFS_SEG_SIZE);

            cstring_free(cxfs_seg_fname);
            return (EC_FALSE);
        }

        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_check:"
                                                 "bucket %s seg %lu/%lu size %lu => OK\n",
                                                 (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                 cxfs_seg_idx, cxfs_seg_num,
                                                 cxfs_seg_size);
        cstring_free(cxfs_seg_fname);
    }

    dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_check:"
                                             "check bucket %s size %lu done\n",
                                             (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                             bucket_size);

    return (EC_TRUE);
}

EC_BOOL cxfsnbdc_bucket_create(const UINT32 cxfsnbdc_md_id)
{
    CXFSNBDC_MD  *cxfsnbdc_md;
    UINT32        bucket_size;

    UINT32        cxfs_seg_num;
    UINT32        cxfs_seg_idx;

#if (SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)
    if ( CXFSNBDC_MD_ID_CHECK_INVALID(cxfsnbdc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbdc_bucket_create: cxfsnbdc module #%ld not started.\n",
                cxfsnbdc_md_id);
        cxfsnbdc_print_module_status(cxfsnbdc_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBDC, cxfsnbdc_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)*/

    cxfsnbdc_md = CXFSNBDC_MD_GET(cxfsnbdc_md_id);

    if(EC_TRUE == cstring_is_empty(CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md)))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_create:"
                                                 "no bucket name\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_TCID == CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_create:"
                                                 "cxfsc tcid is invalid\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_create:"
                                                 "cxfsc modi is invalid\n");
        return (EC_FALSE);
    }

    bucket_size  = (UINT32)CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md);
    cxfs_seg_num = ((bucket_size + CXFSNBD_CXFS_SEG_SIZE - 1) / CXFSNBD_CXFS_SEG_SIZE);

    for(cxfs_seg_idx = 0; cxfs_seg_idx < cxfs_seg_num; cxfs_seg_idx ++)
    {
        CSTRING    *cxfs_seg_fname;
        MOD_NODE    recv_mod_node;
        EC_BOOL     ret;

        cxfs_seg_fname = cxfsnbd_make_bucket_seg_name( CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md), cxfs_seg_idx);
        if(NULL_PTR == cxfs_seg_fname)
        {
            dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_create:"
                                                     "bucket %s seg %lu make name failed\n",
                                                     (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                     cxfs_seg_idx);

            return (EC_FALSE);
        }

        dbg_log(SEC_0142_CXFSNBDC, 6)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_create:"
                                                 "make bucket seg name '%s' done\n",
                                                 (char *)cstring_get_str(cxfs_seg_fname));

        MOD_NODE_TCID(&recv_mod_node) = CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
        MOD_NODE_MODI(&recv_mod_node) = CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md);

        /*check seg file exist*/
        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfsc_is_file, CMPI_ERROR_MODI, cxfs_seg_fname);

        if(EC_TRUE == ret)
        {
            /*delete seg file*/
            ret = EC_FALSE;
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &recv_mod_node,
                     &ret,
                     FI_cxfsc_delete_file, CMPI_ERROR_MODI, cxfs_seg_fname);

            if(EC_FALSE == ret)
            {
                dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_create:"
                                                         "delete bucket %s seg %lu/%lu failed\n",
                                                         (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                         cxfs_seg_idx, cxfs_seg_num);

                cstring_free(cxfs_seg_fname);
                return (EC_FALSE);
            }
        }

        /*truncate seg*/
        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfsc_truncate_file, CMPI_ERROR_MODI, cxfs_seg_fname, (UINT32)CXFSNBD_CXFS_SEG_SIZE);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_create:"
                                                     "create bucket %s seg %lu/%lu failed\n",
                                                     (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                     cxfs_seg_idx, cxfs_seg_num);

            cstring_free(cxfs_seg_fname);
            return (EC_FALSE);
        }

        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_create:"
                                                 "create bucket %s seg %lu/%lu done\n",
                                                 (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                                 cxfs_seg_idx, cxfs_seg_num);
        cstring_free(cxfs_seg_fname);
    }

    dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_create:"
                                             "create bucket %s, size %lu done\n",
                                             CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md),
                                             bucket_size);

    return (EC_TRUE);
}

EC_BOOL cxfsnbdc_bucket_launch(const UINT32 cxfsnbdc_md_id)
{
    CXFSNBDC_MD  *cxfsnbdc_md;

#if (SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)
    if ( CXFSNBDC_MD_ID_CHECK_INVALID(cxfsnbdc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbdc_bucket_launch: cxfsnbdc module #%ld not started.\n",
                cxfsnbdc_md_id);
        cxfsnbdc_print_module_status(cxfsnbdc_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBDC, cxfsnbdc_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)*/

    cxfsnbdc_md = CXFSNBDC_MD_GET(cxfsnbdc_md_id);

    if(EC_TRUE == cxfsnbdc_bucket_check(cxfsnbdc_md_id))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_launch:"
                                                 "check bucket %s done\n",
                                                 (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md));

        return (EC_TRUE);
    }

    dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_launch:"
                                             "check bucket %s failed\n",
                                             (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md));

    if(EC_TRUE == cxfsnbdc_bucket_create(cxfsnbdc_md_id))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "[DEBUG] cxfsnbdc_launch:"
                                                 "create bucket %s done\n",
                                                 (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md));

        return (EC_TRUE);
    }

    dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_launch:"
                                             "create bucket %s failed\n",
                                             (char *)CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md));

    /*destroy cxfsnbdc module */
    cxfsnbdc_end(cxfsnbdc_md_id);

    return (EC_FALSE);
}

EC_BOOL cxfsnbdc_bucket_read(const UINT32 cxfsnbdc_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp)
{
    CXFSNBDC_MD  *cxfsnbdc_md;

    UINT32        cnbd_req_offset_s;
    UINT32        cnbd_req_offset_e;

    uint8_t      *data;
    TASK_MGR     *task_mgr;
    MOD_NODE      recv_mod_node;

    CVECTOR      *cxfsnbd_seg_vec;
    UINT32        pos;
    UINT32        num;

#if (SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)
    if ( CXFSNBDC_MD_ID_CHECK_INVALID(cxfsnbdc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbdc_bucket_read: cxfsnbdc module #%ld not started.\n",
                cxfsnbdc_md_id);
        cxfsnbdc_print_module_status(cxfsnbdc_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBDC, cxfsnbdc_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)*/

    cxfsnbdc_md = CXFSNBDC_MD_GET(cxfsnbdc_md_id);

    if(0 == CNBD_REQ_LEN(cnbd_req))
    {
        CNBD_RSP_MAGIC(cnbd_rsp)  = CNBD_RSP_MAGIC_NUM;
        CNBD_RSP_STATUS(cnbd_rsp) = 0;
        CNBD_RSP_SEQNO(cnbd_rsp)  = CNBD_REQ_SEQNO(cnbd_req);

        return (EC_TRUE);
    }

    cnbd_req_offset_s = (UINT32)(CNBD_REQ_OFFSET(cnbd_req) +                      0);
    cnbd_req_offset_e = (UINT32)(CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req));

    data = safe_malloc(CNBD_REQ_LEN(cnbd_req), LOC_CXFSNBDC_0001);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_read: "
                                                 "alloc %u bytes failed\n",
                                                 CNBD_REQ_LEN(cnbd_req));

        return (EC_FALSE);
    }

    cxfsnbd_seg_vec = cxfsnbd_make_bucket_segs(CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md),
                                                 cnbd_req_offset_s, cnbd_req_offset_e);
    if(NULL_PTR == cxfsnbd_seg_vec)
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_read: "
                                                 "new cxfsnbd_seg_vec failed\n");

        safe_free(data, LOC_CXFSNBDC_0002);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnbd_seg_vec_mount_data(cxfsnbd_seg_vec, data, CNBD_REQ_LEN(cnbd_req)))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_read: "
                                                 "cxfsnbd_seg_vec mount data failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        safe_free(data, LOC_CXFSNBDC_0003);
        return (EC_FALSE);
    }

    if(0 && do_log(SEC_0142_CXFSNBDC, 9))
    {
        cnbd_req_print(LOGSTDOUT, cnbd_req);
        dbg_log(SEC_0142_CXFSNBDC, 9)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_read: "
                                                 "req %p => [%lu, %lu)\n",
                                                 cnbd_req,
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req));

        dbg_log(SEC_0142_CXFSNBDC, 9)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_read: "
                                                 "req %p, segs =>\n",
                                                 cnbd_req);

        cxfsnbd_seg_vec_print(LOGSTDOUT, cxfsnbd_seg_vec);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    if(NULL_PTR == task_mgr)
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_read: "
                                                 "new task_mgr failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        safe_free(data, LOC_CXFSNBDC_0004);
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md);
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
    MOD_NODE_MODI(&recv_mod_node) = CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md);

    num = cvector_size(cxfsnbd_seg_vec);
    for(pos = 0; pos < num; pos ++)
    {
        CXFSNBD_SEG     *cxfsnbd_seg;

        cxfsnbd_seg = (CXFSNBD_SEG *)cvector_get(cxfsnbd_seg_vec, pos);
        CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg) = EC_FALSE;

        task_p2p_inc(task_mgr, cxfsnbdc_md_id,
             &recv_mod_node,
             &CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg),
             FI_cxfsc_read_e,
             CMPI_ERROR_MODI,
             CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg),
             &CXFSNBD_CXFS_SEG_T_OFFSET(cxfsnbd_seg),
             CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg) - CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg),
             CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg));
    }
    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    for(pos = 0; pos < num; pos ++)
    {
        CXFSNBD_SEG     *cxfsnbd_seg;

        cxfsnbd_seg = (CXFSNBD_SEG *)cvector_set(cxfsnbd_seg_vec, pos, NULL_PTR);

        if(EC_FALSE == CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg))
        {
            dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_read: "
                                                     "bucket read [%lu, %lu) of [%lu, %lu) failed\n",
                                                     CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                     CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                     cnbd_req_offset_s,
                                                     cnbd_req_offset_e);

            cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
            cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

            safe_free(data, LOC_CXFSNBDC_0005);
            return (EC_FALSE);
        }

        dbg_log(SEC_0142_CXFSNBDC, 7)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_read: "
                                                 "bucket read [%lu, %lu) of [%lu, %lu) done\n",
                                                 CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                 cnbd_req_offset_s,
                                                 cnbd_req_offset_e);

        dbg_log(SEC_0142_CXFSNBDC, 6)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_read: "
                                                 "bucket [%lu, %lu) herit data [%lu, %lu] done\n",
                                                 CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg));

        cxfsnbd_seg_umount_data(cxfsnbd_seg);
        cxfsnbd_seg_free(cxfsnbd_seg);
    }

    cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

    CNBD_RSP_DATA_LEN(cnbd_rsp)   = CNBD_REQ_LEN(cnbd_req);
    CNBD_RSP_DATA_ZONE(cnbd_rsp)  = data; /*handover data*/

    CNBD_RSP_MAGIC(cnbd_rsp)      = CNBD_RSP_MAGIC_NUM;
    CNBD_RSP_STATUS(cnbd_rsp)     = 0;
    CNBD_RSP_SEQNO(cnbd_rsp)      = CNBD_REQ_SEQNO(cnbd_req);

    dbg_log(SEC_0142_CXFSNBDC, 6)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_read: "
                                             "read (offset %lu, len %u) done\n",
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));

    dbg_log(SEC_0142_CXFSNBDC, 5)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_read: "
                                             "read [%lu, %lu) len %u done\n",
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));

    return (EC_TRUE);
}

EC_BOOL cxfsnbdc_bucket_write(const UINT32 cxfsnbdc_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp)
{
    CXFSNBDC_MD  *cxfsnbdc_md;

    UINT32        cnbd_req_offset_s;
    UINT32        cnbd_req_offset_e;

    TASK_MGR     *task_mgr;
    MOD_NODE      recv_mod_node;

    CVECTOR      *cxfsnbd_seg_vec;
    UINT32        pos;
    UINT32        num;

#if (SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)
    if ( CXFSNBDC_MD_ID_CHECK_INVALID(cxfsnbdc_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbdc_bucket_write: cxfsnbdc module #%ld not started.\n",
                cxfsnbdc_md_id);
        cxfsnbdc_print_module_status(cxfsnbdc_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBDC, cxfsnbdc_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBDC_DEBUG_SWITCH)*/

    cxfsnbdc_md = CXFSNBDC_MD_GET(cxfsnbdc_md_id);

    if(0 == CNBD_REQ_LEN(cnbd_req)
    || NULL_PTR == CNBD_REQ_DATA_ZONE(cnbd_req))
    {
        CNBD_RSP_MAGIC(cnbd_rsp)  = CNBD_RSP_MAGIC_NUM;
        CNBD_RSP_STATUS(cnbd_rsp) = 0;
        CNBD_RSP_SEQNO(cnbd_rsp)  = CNBD_REQ_SEQNO(cnbd_req);

        return (EC_TRUE);
    }

    cnbd_req_offset_s = (UINT32)(CNBD_REQ_OFFSET(cnbd_req) +                      0);
    cnbd_req_offset_e = (UINT32)(CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req));

    cxfsnbd_seg_vec = cxfsnbd_make_bucket_segs(CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md),
                                                 cnbd_req_offset_s, cnbd_req_offset_e);
    if(NULL_PTR == cxfsnbd_seg_vec)
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_write: "
                                                 "new cxfsnbd_seg_vec failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnbd_seg_vec_mount_data(cxfsnbd_seg_vec,
                           CNBD_REQ_DATA_ZONE(cnbd_req), CNBD_REQ_LEN(cnbd_req)))
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_write: "
                                                 "cxfsnbd_seg_vec mount data failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        return (EC_FALSE);
    }

    if(0 && do_log(SEC_0142_CXFSNBDC, 9))
    {
        cnbd_req_print(LOGSTDOUT, cnbd_req);
        dbg_log(SEC_0142_CXFSNBDC, 9)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_write: "
                                                 "req %p => [%lu, %lu)\n",
                                                 cnbd_req,
                                                 CNBD_REQ_OFFSET(cnbd_req),
                                                 CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req));

        dbg_log(SEC_0142_CXFSNBDC, 9)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_write: "
                                                 "req %p, segs =>\n",
                                                 cnbd_req);

        cxfsnbd_seg_vec_print(LOGSTDOUT, cxfsnbd_seg_vec);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    if(NULL_PTR == task_mgr)
    {
        dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_write: "
                                                 "new task_mgr failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md);
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
    MOD_NODE_MODI(&recv_mod_node) = CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md);

    num = cvector_size(cxfsnbd_seg_vec);
    for(pos = 0; pos < num; pos ++)
    {
        CXFSNBD_SEG     *cxfsnbd_seg;

        cxfsnbd_seg = (CXFSNBD_SEG *)cvector_get(cxfsnbd_seg_vec, pos);
        CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg) = EC_FALSE;

        task_p2p_inc(task_mgr, cxfsnbdc_md_id,
             &recv_mod_node,
             &CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg),
             FI_cxfsc_write_e,
             CMPI_ERROR_MODI,
             CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg),
             &CXFSNBD_CXFS_SEG_T_OFFSET(cxfsnbd_seg),
             CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg) - CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg),
             CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg));
    }

    task_wait(task_mgr, TASK_DEFAULT_LIVE, TASK_NOT_NEED_RESCHEDULE_FLAG, NULL_PTR);

    for(pos = 0; pos < num; pos ++)
    {
        CXFSNBD_SEG     *cxfsnbd_seg;

        cxfsnbd_seg = (CXFSNBD_SEG *)cvector_set(cxfsnbd_seg_vec, pos, NULL_PTR);

        if(EC_FALSE == CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg))
        {
            dbg_log(SEC_0142_CXFSNBDC, 0)(LOGSTDOUT, "error:cxfsnbdc_bucket_write: "
                                                     "bucket write [%lu, %lu) of [%lu, %lu) failed\n",
                                                     CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                     CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                     cnbd_req_offset_s,
                                                     cnbd_req_offset_e);

            cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
            cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

            return (EC_FALSE);
        }

        dbg_log(SEC_0142_CXFSNBDC, 7)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_write: "
                                                 "bucket write [%lu, %lu) of [%lu, %lu) done\n",
                                                 CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                 cnbd_req_offset_s,
                                                 cnbd_req_offset_e);

        dbg_log(SEC_0142_CXFSNBDC, 6)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_write: "
                                                 "bucket [%lu, %lu) herit data [%lu, %lu]\n",
                                                 CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                                                 CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg));

        cxfsnbd_seg_umount_data(cxfsnbd_seg);
        cxfsnbd_seg_free(cxfsnbd_seg);
    }

    cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

    CNBD_RSP_MAGIC(cnbd_rsp)      = CNBD_RSP_MAGIC_NUM;
    CNBD_RSP_STATUS(cnbd_rsp)     = 0;
    CNBD_RSP_SEQNO(cnbd_rsp)      = CNBD_REQ_SEQNO(cnbd_req);

    dbg_log(SEC_0142_CXFSNBDC, 6)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_write: "
                                             "write (offset %lu, len %u) done\n",
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));

    dbg_log(SEC_0142_CXFSNBDC, 5)(LOGSTDOUT, "[DEBUG] cxfsnbdc_bucket_write: "
                                             "write [%lu, %lu) len %u done\n",
                                             CNBD_REQ_OFFSET(cnbd_req),
                                             CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req),
                                             CNBD_REQ_LEN(cnbd_req));

    return (EC_TRUE);
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

