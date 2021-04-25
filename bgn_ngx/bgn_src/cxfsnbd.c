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
#include "cxfs.h"
#include "cxfsnbd.h"

#include "findex.inc"

#define CXFSNBD_MD_CAPACITY()                  (cbc_md_capacity(MD_CXFSNBD))

#define CXFSNBD_MD_GET(cxfsnbd_md_id)     ((CXFSNBD_MD *)cbc_md_get(MD_CXFSNBD, (cxfsnbd_md_id)))

#define CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id)  \
    ((CMPI_ANY_MODI != (cxfsnbd_md_id)) && ((NULL_PTR == CXFSNBD_MD_GET(cxfsnbd_md_id)) || (0 == (CXFSNBD_MD_GET(cxfsnbd_md_id)->usedcounter))))

/**
*   for test only
*
*   to query the status of CXFSNBD Module
*
**/
void cxfsnbd_print_module_status(const UINT32 cxfsnbd_md_id, LOG *log)
{
    CXFSNBD_MD *cxfsnbd_md;
    UINT32 this_cxfsnbd_md_id;

    for( this_cxfsnbd_md_id = 0; this_cxfsnbd_md_id < CXFSNBD_MD_CAPACITY(); this_cxfsnbd_md_id ++ )
    {
        cxfsnbd_md = CXFSNBD_MD_GET(this_cxfsnbd_md_id);

        if ( NULL_PTR != cxfsnbd_md && 0 < cxfsnbd_md->usedcounter )
        {
            sys_log(log,"CXFSNBD Module # %ld : %ld refered\n",
                    this_cxfsnbd_md_id,
                    cxfsnbd_md->usedcounter);
        }
    }

    return ;
}

/**
*
*   free all static memory occupied by the appointed CXFSNBD module
*
*
**/
UINT32 cxfsnbd_free_module_static_mem(const UINT32 cxfsnbd_md_id)
{
#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_free_module_static_mem: cxfs module #%ld not started.\n",
                cxfsnbd_md_id);
        /*note: here do not exit but return only*/
        return ((UINT32)-1);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    free_module_static_mem(MD_CXFSNBD, cxfsnbd_md_id);

    return 0;
}

/**
*
* start CXFSNBD module
*
**/
UINT32 cxfsnbd_start(const CSTRING *bucket_name, const UINT32 cxfs_tcid, const UINT32 cxfs_md_id)
{
    CXFSNBD_MD     *cxfsnbd_md;
    UINT32          cxfsnbd_md_id;

    cbc_md_reg(MD_CXFSNBD, 16);

    cxfsnbd_md_id = cbc_md_new(MD_CXFSNBD, sizeof(CXFSNBD_MD));
    if(CMPI_ERROR_MODI == cxfsnbd_md_id)
    {
        return (CMPI_ERROR_MODI);
    }

    /* initialize new one CXFSNBD module */
    cxfsnbd_md = (CXFSNBD_MD *)cbc_md_get(MD_CXFSNBD, cxfsnbd_md_id);
    cxfsnbd_md->usedcounter   = 0;

    /* create a new module node */
    init_static_mem();

    CXFSNBD_MD_CXFS_TCID(cxfsnbd_md)    = CMPI_ERROR_TCID;
    CXFSNBD_MD_CXFS_MODI(cxfsnbd_md)    = CMPI_ERROR_MODI;

    CXFSNBD_MD_CNBD_MODI(cxfsnbd_md)    = CMPI_ERROR_MODI;

    CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)  = 0;
    CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)  = 0;/*xxx*/

    CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md) = NULL_PTR;
    CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md)  = NULL_PTR;

    cxfsnbd_md->usedcounter = 1;

    /* fetch config */

    CXFSNBD_MD_CXFS_TCID(cxfsnbd_md)    = cxfs_tcid;
    CXFSNBD_MD_CXFS_MODI(cxfsnbd_md)    = cxfs_md_id;

    /*debug config*/
    CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md) = CXFSNBD_BLK_SIZE;
    CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md) = CXFSNBD_DEV_SIZE;
    CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)  = CXFSNBD_TIMEOUT;
    CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)  = 0;/*xxx*/

    if(NULL_PTR == bucket_name)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "bucket_name is null\n");

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md) = cstring_dup(bucket_name);
    if(NULL_PTR == CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "new bucket_name '%s' failed\n",
                                                (char *)cstring_get_str(bucket_name));

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md) = cstring_new((const UINT8 *)CXFSNBD_DEV_NAME, LOC_CXFSNBD_0001);
    if(NULL_PTR == CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "new dev name '%s' failed\n",
                                                (char *)CXFSNBD_DEV_NAME);

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    while(0 && NULL_PTR != bucket_name)
    {
        if(EC_TRUE == cxfsnbd_bucket_check(cxfsnbd_md_id))
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start:"
                                                    "check bucket %s done\n",
                                                    (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

            break;
        }

        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "check bucket %s failed\n",
                                                (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

        if(EC_TRUE == cxfsnbd_bucket_create(cxfsnbd_md_id))
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start:"
                                                    "create bucket %s done\n",
                                                    (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

            break;
        }

        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
                                                "create bucket %s failed\n",
                                                (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    CXFSNBD_MD_CNBD_MODI(cxfsnbd_md) = cnbd_start(CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md),
                                                  CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md),
                                                  CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md),
                                                  CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md),
                                                  CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md));

    if(CMPI_ERROR_MODI == CXFSNBD_MD_CNBD_MODI(cxfsnbd_md))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_start:"
            "start nbd (dev %s, bucket %s, block size %ld, dev size %ld, timeout %ld) failed\n",
            (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
            (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
            CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md),
            CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md),
            CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md));

        cxfsnbd_end(cxfsnbd_md_id);
        return (CMPI_ERROR_MODI);
    }

    dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start:"
        "start nbd (dev %s, bucket %s, block size %ld, dev size %ld, timeout %ld) done\n",
        (char *)CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md),
        (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
        CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md),
        CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md),
        CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md));

    cnbd_set_bucket_read_handler(CXFSNBD_MD_CNBD_MODI(cxfsnbd_md), cxfsnbd_bucket_read);
    cnbd_set_bucket_write_handler(CXFSNBD_MD_CNBD_MODI(cxfsnbd_md), cxfsnbd_bucket_write);

    csig_atexit_register((CSIG_ATEXIT_HANDLER)cxfsnbd_end, cxfsnbd_md_id);

    dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_start: "
                                            "start CXFSNBD module #%ld\n",
                                            cxfsnbd_md_id);

    return ( cxfsnbd_md_id );
}

/**
*
* end CXFSNBD module
*
**/
void cxfsnbd_end(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD *cxfsnbd_md;

    csig_atexit_unregister((CSIG_ATEXIT_HANDLER)cxfsnbd_end, cxfsnbd_md_id);

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);
    if(NULL_PTR == cxfsnbd_md)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_end: "
                                                "cxfsnbd_md_id = %ld not exist.\n",
                                                cxfsnbd_md_id);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }

    /* if the module is occupied by others,then decrease counter only */
    if ( 1 < cxfsnbd_md->usedcounter )
    {
        cxfsnbd_md->usedcounter --;
        return ;
    }

    if ( 0 == cxfsnbd_md->usedcounter )
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_end: "
                                                "cxfsnbd_md_id = %ld is not started.\n",
                                                cxfsnbd_md_id);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }

    if(CMPI_ERROR_MODI != CXFSNBD_MD_CNBD_MODI(cxfsnbd_md))
    {
        cnbd_end(CXFSNBD_MD_CNBD_MODI(cxfsnbd_md));
        CXFSNBD_MD_CNBD_MODI(cxfsnbd_md) = CMPI_ERROR_MODI;
    }

    if(NULL_PTR != CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md))
    {
        cstring_free(CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md));
        CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md) = NULL_PTR;
    }

    if(NULL_PTR != CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md))
    {
        cstring_free(CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));
        CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md) = NULL_PTR;
    }

    CXFSNBD_MD_CXFS_TCID(cxfsnbd_md)    = CMPI_ERROR_TCID;
    CXFSNBD_MD_CXFS_MODI(cxfsnbd_md)    = CMPI_ERROR_MODI;

    CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md) = 0;
    CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)  = 0;
    CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)  = 0;

    /* free module : */
    //cxfsnbd_free_module_static_mem(cxfsnbd_md_id);

    cxfsnbd_md->usedcounter = 0;

    cbc_md_free(MD_CXFSNBD, cxfsnbd_md_id);

    dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_end: "
                                            "stop CXFSNBD module #%ld\n",
                                            cxfsnbd_md_id);

    return ;
}

STATIC_CAST CSTRING *__cxfsnbd_make_bucket_seg_name(const CSTRING *bucket_name, const UINT32 seg_idx)
{
    return cstring_make("%s/%ld", (char *)cstring_get_str(bucket_name), seg_idx);
}

STATIC_CAST CVECTOR *__cxfsnbd_make_bucket_segs(const CSTRING *bucket_name,
                                                        const UINT32 nbd_offset_s,
                                                        const UINT32 nbd_offset_e)
{
    UINT32       nbd_offset_c;

    UINT32       cxfs_seg_no_s;
    UINT32       cxfs_seg_no_e;
    UINT32       cxfs_seg_no_c;

    CVECTOR     *cxfsnbd_seg_vec;


    if(EC_TRUE == cstring_is_empty(bucket_name))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:__cxfsnbd_make_bucket_segs:"
                                                "no bucket name\n");
        return (NULL_PTR);
    }

    /*[cxfs_seg_no_s, cxfs_seg_no_e)*/
    cxfs_seg_no_s = (nbd_offset_s / CXFSNBD_CXFS_SEG_SIZE);
    cxfs_seg_no_e = ((nbd_offset_e + CXFSNBD_CXFS_SEG_SIZE - 1) / CXFSNBD_CXFS_SEG_SIZE);

    cxfsnbd_seg_vec = cxfsnbd_seg_vec_new(cxfs_seg_no_e - cxfs_seg_no_s);
    if(NULL_PTR == cxfsnbd_seg_vec)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:__cxfsnbd_make_bucket_segs:"
                                                "new cxfsnbd_seg_vec failed\n");
        return (NULL_PTR);
    }

    nbd_offset_c = nbd_offset_s;
    for(cxfs_seg_no_c = cxfs_seg_no_s; cxfs_seg_no_c < cxfs_seg_no_e; cxfs_seg_no_c ++)
    {
        UINT32               cxfs_seg_offset;
        UINT32               cxfs_seg_size;
        CXFSNBD_SEG         *cxfsnbd_seg;

        cxfs_seg_offset = (nbd_offset_c % CXFSNBD_CXFS_SEG_SIZE);
        cxfs_seg_size   = (nbd_offset_e - nbd_offset_c);

        if(cxfs_seg_offset + cxfs_seg_size > CXFSNBD_CXFS_SEG_SIZE)
        {
            cxfs_seg_size = (CXFSNBD_CXFS_SEG_SIZE - cxfs_seg_offset);
        }

        dbg_log(SEC_0141_CXFSNBD, 6)(LOGSTDOUT, "[DEBUG] __cxfsnbd_make_bucket_segs:"
                                                "[#%ld] bucket %s seg %ld : offset %ld, size %ld\n",
                                                cxfs_seg_no_c - cxfs_seg_no_s,
                                                (char *)cstring_get_str(bucket_name),
                                                cxfs_seg_no_c, cxfs_seg_offset, cxfs_seg_size);

        cxfsnbd_seg = (CXFSNBD_SEG *)cvector_get(cxfsnbd_seg_vec, cxfs_seg_no_c - cxfs_seg_no_s);

        CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg) = __cxfsnbd_make_bucket_seg_name(
                                                bucket_name, cxfs_seg_no_c);

        if(NULL_PTR == CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg))
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:__cxfsnbd_make_bucket_segs:"
                                                    "bucket %s make seg %ld name failed\n",
                                                    (char *)cstring_get_str(bucket_name),
                                                    cxfs_seg_no_c);

            cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);
            return (NULL_PTR);
        }

        CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg)      = nbd_offset_c - nbd_offset_s;
        CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg)      = CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg)
                                                    + cxfs_seg_size;

        CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg)      = nbd_offset_c;
        CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg)      = nbd_offset_c + cxfs_seg_size;

        CXFSNBD_CXFS_SEG_IDX(cxfsnbd_seg)           = cxfs_seg_no_c;
        CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg)      = cxfs_seg_offset;
        CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg)      = cxfs_seg_offset + cxfs_seg_size;
        CXFSNBD_CXFS_SEG_T_OFFSET(cxfsnbd_seg)      = CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg);
        CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg)        = EC_FALSE;

        nbd_offset_c += cxfs_seg_size;
    }

    return (cxfsnbd_seg_vec);
}

CXFSNBD_SEG *cxfsnbd_seg_new()
{
    CXFSNBD_SEG *cxfsnbd_seg;

    alloc_static_mem(MM_CXFSNBD_SEG, &cxfsnbd_seg, LOC_CXFSNBD_0002);
    if(NULL_PTR == cxfsnbd_seg)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_new: "
                                                "new cxfsnbd_seg failed\n");
        return (NULL_PTR);
    }

    if(EC_FALSE == cxfsnbd_seg_init(cxfsnbd_seg))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_new: "
                                                "init cxfsnbd_seg failed\n");
        free_static_mem(MM_CXFSNBD_SEG, cxfsnbd_seg, LOC_CXFSNBD_0003);
        return (NULL_PTR);
    }

    return (cxfsnbd_seg);
}

EC_BOOL cxfsnbd_seg_init(CXFSNBD_SEG *cxfsnbd_seg)
{
    if(NULL_PTR != cxfsnbd_seg)
    {
        CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg)               = NULL_PTR;
        CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg)               = NULL_PTR;

        CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);

        CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);

        CXFSNBD_CXFS_SEG_IDX(cxfsnbd_seg)                = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_T_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg)             = EC_FALSE;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_seg_clean(CXFSNBD_SEG *cxfsnbd_seg)
{
    if(NULL_PTR != cxfsnbd_seg)
    {
        if(NULL_PTR != CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg))
        {
            cstring_free(CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg));
            CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg) = NULL_PTR;
        }

        if(NULL_PTR != CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg))
        {
            cbytes_free(CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg));
            CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg) = NULL_PTR;
        }

        CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);

        CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);

        CXFSNBD_CXFS_SEG_IDX(cxfsnbd_seg)                = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_T_OFFSET(cxfsnbd_seg)           = ((UINT32)~0);
        CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg)             = EC_FALSE;
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_seg_mount_data(CXFSNBD_SEG *cxfsnbd_seg, UINT8 *data, UINT32 len)
{
    if(NULL_PTR != cxfsnbd_seg)
    {
        if(NULL_PTR == CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg))
        {
            CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg) = cbytes_new(0);
            if(NULL_PTR == CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg))
            {
                dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_mount_data:"
                                                        "new seg data failed\n");

                return (EC_FALSE);
            }
        }

        cbytes_mount(CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg), len, data, BIT_FALSE);
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_seg_umount_data(CXFSNBD_SEG *cxfsnbd_seg)
{
    if(NULL_PTR != cxfsnbd_seg)
    {
        if(NULL_PTR != CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg))
        {
            cbytes_umount_only(CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg));
        }
    }

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_seg_free(CXFSNBD_SEG *cxfsnbd_seg)
{
    if(NULL_PTR != cxfsnbd_seg)
    {
        cxfsnbd_seg_clean(cxfsnbd_seg);
        free_static_mem(MM_CXFSNBD_SEG, cxfsnbd_seg, LOC_CXFSNBD_0004);
    }

    return (EC_TRUE);
}

void cxfsnbd_seg_print(LOG *log, const CXFSNBD_SEG *cxfsnbd_seg)
{
    if(NULL_PTR != cxfsnbd_seg)
    {
        sys_log(log, "cxfsnbd_seg_print: "
                     "seg %p: name %s, data len %ld, data buf %p, "
                     "nbd [%ld, %ld), data [%ld, %ld), xfs (#%ld, [%ld, %ld), %s)\n",
                     cxfsnbd_seg,
                     (char *)CXFSNBD_CXFS_SEG_NAME_STR(cxfsnbd_seg),
                     CXFSNBD_CXFS_SEG_DATA_LEN(cxfsnbd_seg),
                     CXFSNBD_CXFS_SEG_DATA_BUF(cxfsnbd_seg),

                     CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                     CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),

                     CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                     CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg),

                     CXFSNBD_CXFS_SEG_IDX(cxfsnbd_seg),
                     CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg),
                     CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg),
                     c_bool_str(CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg)));
    }
    return;
}

void cxfsnbd_seg_print_plain(LOG *log, const CXFSNBD_SEG *cxfsnbd_seg)
{
    if(NULL_PTR != cxfsnbd_seg)
    {
        sys_print(log, "seg %p: name %s, data len %ld, data buf %p, "
                       "nbd [%ld, %ld), data [%ld, %ld), xfs (#%ld, [%ld, %ld), %s)\n",
                       cxfsnbd_seg,
                       (char *)CXFSNBD_CXFS_SEG_NAME_STR(cxfsnbd_seg),
                       CXFSNBD_CXFS_SEG_DATA_LEN(cxfsnbd_seg),
                       CXFSNBD_CXFS_SEG_DATA_BUF(cxfsnbd_seg),

                       CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                       CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),

                       CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                       CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg),

                       CXFSNBD_CXFS_SEG_IDX(cxfsnbd_seg),
                       CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg),
                       CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg),
                       c_bool_str(CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg)));
    }
    return;
}

CVECTOR *cxfsnbd_seg_vec_new(const UINT32 capacity)
{
    CVECTOR *cxfsnbd_seg_vec;
    UINT32   pos;

    cxfsnbd_seg_vec = cvector_new(capacity, MM_CXFSNBD_SEG, LOC_CXFSNBD_0005);
    if(NULL_PTR == cxfsnbd_seg_vec)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_vec_new: "
                                                "new cxfsnbd_seg vector capacity %ld failed\n",
                                                capacity);
        return (NULL_PTR);
    }

    for(pos = 0; pos < capacity; pos ++)
    {
        CXFSNBD_SEG     *cxfsnbd_seg;

        cxfsnbd_seg = cxfsnbd_seg_new();
        if(NULL_PTR == cxfsnbd_seg)
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_vec_new: "
                                                    "new cxfsnbd_seg failed\n");

            cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);
            return (NULL_PTR);
        }

        cvector_push(cxfsnbd_seg_vec, (void *)cxfsnbd_seg);
    }

    return (cxfsnbd_seg_vec);
}

EC_BOOL cxfsnbd_seg_vec_clean(CVECTOR *cxfsnbd_seg_vec)
{
    if(NULL_PTR != cxfsnbd_seg_vec)
    {
        cvector_clean(cxfsnbd_seg_vec, (CVECTOR_DATA_CLEANER)cxfsnbd_seg_free, LOC_CXFSNBD_0006);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnbd_seg_vec_mount_data(CVECTOR *cxfsnbd_seg_vec, UINT8 *data, const UINT32 len)
{
    if(NULL_PTR != cxfsnbd_seg_vec)
    {
        UINT32      pos;
        UINT32      num;

        num = cvector_size(cxfsnbd_seg_vec);

        for(pos = 0; pos < num; pos ++)
        {
            CXFSNBD_SEG     *cxfsnbd_seg;
            UINT8           *seg_data;
            UINT32           seg_data_len;

            cxfsnbd_seg = cvector_get(cxfsnbd_seg_vec, pos);
            ASSERT(NULL_PTR != cxfsnbd_seg);

            if(len < CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg))
            {
                dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_vec_mount_data: "
                                                        "seg data range [%ld, %ld) overflow, "
                                                        "data len = %ld\n",
                                                        CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                                                        CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg),
                                                        len);
                return (EC_FALSE);
            }

            if(CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg) >= CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg))
            {
                dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_vec_mount_data: "
                                                        "invalid seg data range [%ld, %ld)\n",
                                                        CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                                                        CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg));
                return (EC_FALSE);
            }

            seg_data = data + CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg);
            seg_data_len = CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg) - CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg);

            if(EC_FALSE == cxfsnbd_seg_mount_data(cxfsnbd_seg, seg_data, seg_data_len))
            {
                dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_seg_vec_mount_data: "
                                                        "mount seg data range [%ld, %ld) failed\n",
                                                        CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                                                        CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg));
                return (EC_FALSE);
            }
            dbg_log(SEC_0141_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_seg_vec_mount_data: "
                                                    "mount seg data range [%ld, %ld) done\n",
                                                    CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg),
                                                    CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg));
        }
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnbd_seg_vec_umount_data(CVECTOR *cxfsnbd_seg_vec)
{
    if(NULL_PTR != cxfsnbd_seg_vec)
    {
        cvector_loop_front(cxfsnbd_seg_vec, (CVECTOR_DATA_CLEANER)cxfsnbd_seg_umount_data);
    }
    return (EC_TRUE);
}

EC_BOOL cxfsnbd_seg_vec_free(CVECTOR *cxfsnbd_seg_vec)
{
    if(NULL_PTR != cxfsnbd_seg_vec)
    {
        cxfsnbd_seg_vec_clean(cxfsnbd_seg_vec);
        cvector_free(cxfsnbd_seg_vec, LOC_CXFSNBD_0007);
    }
    return (EC_TRUE);
}

void cxfsnbd_seg_vec_print(LOG *log, const CVECTOR *cxfsnbd_seg_vec)
{
    cvector_print(log, cxfsnbd_seg_vec, (CVECTOR_DATA_PRINT)cxfsnbd_seg_print_plain);
    return;
}

EC_BOOL cxfsnbd_bucket_check(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;
    UINT32       bucket_size;

    UINT32       cxfs_seg_num;
    UINT32       cxfs_seg_idx;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_bucket_check: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(EC_TRUE == cstring_is_empty(CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md)))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_check:"
                                                "no bucket name\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_TCID == CXFSNBD_MD_CXFS_TCID(cxfsnbd_md))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_check:"
                                                "cxfs tcid is invalid\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CXFSNBD_MD_CXFS_MODI(cxfsnbd_md))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_check:"
                                                "cxfs modi is invalid\n");
        return (EC_FALSE);
    }

    bucket_size  = (UINT32)CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md);
    cxfs_seg_num = ((bucket_size + CXFSNBD_CXFS_SEG_SIZE - 1) / CXFSNBD_CXFS_SEG_SIZE);

    for(cxfs_seg_idx = 0; cxfs_seg_idx < cxfs_seg_num; cxfs_seg_idx ++)
    {
        CSTRING    *cxfs_seg_fname;
        UINT32      cxfs_seg_size;
        MOD_NODE    recv_mod_node;
        EC_BOOL     ret;

        cxfs_seg_fname = __cxfsnbd_make_bucket_seg_name( CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md), cxfs_seg_idx);
        if(NULL_PTR == cxfs_seg_fname)
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_check:"
                                                    "bucket %s make seg %ld name failed\n",
                                                    (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                                    cxfs_seg_idx);

            return (EC_FALSE);
        }

        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_check:"
                                                "make bucket seg name '%s' done\n",
                                                (char *)cstring_get_str(cxfs_seg_fname));

        ret = EC_FALSE;
        cxfs_seg_size = 0;

        MOD_NODE_TCID(&recv_mod_node) = CXFSNBD_MD_CXFS_TCID(cxfsnbd_md);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
        MOD_NODE_MODI(&recv_mod_node) = CXFSNBD_MD_CXFS_MODI(cxfsnbd_md);

        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_file_size, CMPI_ERROR_MODI, cxfs_seg_fname, &cxfs_seg_size);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_check:"
                                                    "bucket %s seg %ld/%ld size failed\n",
                                                    (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                                    cxfs_seg_idx, cxfs_seg_num);

            cstring_free(cxfs_seg_fname);
            return (EC_FALSE);
        }

        if(CXFSNBD_CXFS_SEG_SIZE != cxfs_seg_size)
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_check:"
                                                    "bucket %s seg %ld/%ld size %ld != %ld\n",
                                                    (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                                    cxfs_seg_idx, cxfs_seg_num,
                                                    cxfs_seg_size, CXFSNBD_CXFS_SEG_SIZE);

            cstring_free(cxfs_seg_fname);
            return (EC_FALSE);
        }

        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_check:"
                                                "bucket %s seg %ld/%ld size %ld => OK\n",
                                                (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                                cxfs_seg_idx, cxfs_seg_num,
                                                cxfs_seg_size);
        cstring_free(cxfs_seg_fname);
    }

    dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_check:"
                                            "check bucket %s size %ld done\n",
                                            CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                            bucket_size);

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_bucket_create(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;
    UINT32       bucket_size;

    UINT32       cxfs_seg_num;
    UINT32       cxfs_seg_idx;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_bucket_create: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(EC_TRUE == cstring_is_empty(CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md)))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_create:"
                                                "no bucket name\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_TCID == CXFSNBD_MD_CXFS_TCID(cxfsnbd_md))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_create:"
                                                "cxfs tcid is invalid\n");
        return (EC_FALSE);
    }

    if(CMPI_ERROR_MODI == CXFSNBD_MD_CXFS_MODI(cxfsnbd_md))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_create:"
                                                "cxfs modi is invalid\n");
        return (EC_FALSE);
    }

    bucket_size  = (UINT32)CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md);
    cxfs_seg_num = ((bucket_size + CXFSNBD_CXFS_SEG_SIZE - 1) / CXFSNBD_CXFS_SEG_SIZE);

    for(cxfs_seg_idx = 0; cxfs_seg_idx < cxfs_seg_num; cxfs_seg_idx ++)
    {
        CSTRING    *cxfs_seg_fname;
        MOD_NODE    recv_mod_node;
        EC_BOOL     ret;

        cxfs_seg_fname = __cxfsnbd_make_bucket_seg_name( CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md), cxfs_seg_idx);
        if(NULL_PTR == cxfs_seg_fname)
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_create:"
                                                    "bucket %s seg %ld make name failed\n",
                                                    (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                                    cxfs_seg_idx);

            return (EC_FALSE);
        }

        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_create:"
                                                "make bucket seg name '%s' done\n",
                                                (char *)cstring_get_str(cxfs_seg_fname));

        MOD_NODE_TCID(&recv_mod_node) = CXFSNBD_MD_CXFS_TCID(cxfsnbd_md);
        MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
        MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
        MOD_NODE_MODI(&recv_mod_node) = CXFSNBD_MD_CXFS_MODI(cxfsnbd_md);

        /*check seg file exist*/
        ret = EC_FALSE;
        task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                 &recv_mod_node,
                 &ret,
                 FI_cxfs_is_file, CMPI_ERROR_MODI, cxfs_seg_fname);

        if(EC_TRUE == ret)
        {
            /*delete seg file*/
            ret = EC_FALSE;
            task_p2p(CMPI_ANY_MODI, TASK_DEFAULT_LIVE, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP,
                     &recv_mod_node,
                     &ret,
                     FI_cxfs_delete_file, CMPI_ERROR_MODI, cxfs_seg_fname);

            if(EC_FALSE == ret)
            {
                dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_create:"
                                                        "delete bucket %s seg %ld/%ld failed\n",
                                                        (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
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
                 FI_cxfs_truncate_file, CMPI_ERROR_MODI, cxfs_seg_fname, (UINT32)CXFSNBD_CXFS_SEG_SIZE);

        if(EC_FALSE == ret)
        {
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_create:"
                                                    "create bucket %s seg %ld/%ld failed\n",
                                                    (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                                    cxfs_seg_idx, cxfs_seg_num);

            cstring_free(cxfs_seg_fname);
            return (EC_FALSE);
        }

        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_create:"
                                                "create bucket %s seg %ld/%ld done\n",
                                                (char *)CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                                cxfs_seg_idx, cxfs_seg_num);
        cstring_free(cxfs_seg_fname);
    }

    dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_create:"
                                            "create bucket %s, size %ld done\n",
                                            CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md),
                                            bucket_size);

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_bucket_launch(const UINT32 cxfsnbd_md_id)
{
    CXFSNBD_MD  *cxfsnbd_md;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_bucket_launch: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(EC_TRUE == cxfsnbd_bucket_check(cxfsnbd_md_id))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_launch:"
                                                "check bucket %s done\n",
                                                (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

        return (EC_TRUE);
    }

    dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_launch:"
                                            "check bucket %s failed\n",
                                            (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

    if(EC_TRUE == cxfsnbd_bucket_create(cxfsnbd_md_id))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "[DEBUG] cxfsnbd_launch:"
                                                "create bucket %s done\n",
                                                (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

        return (EC_TRUE);
    }

    dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_launch:"
                                            "create bucket %s failed\n",
                                            (char *)CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md));

    /*destroy cxfsnbd module */
    cxfsnbd_end(cxfsnbd_md_id);

    return (EC_FALSE);
}

EC_BOOL cxfsnbd_bucket_read(const UINT32 cxfsnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp)
{
    CXFSNBD_MD  *cxfsnbd_md;

    UINT32       cnbd_req_offset_s;
    UINT32       cnbd_req_offset_e;

    uint8_t     *data;
    TASK_MGR    *task_mgr;
    MOD_NODE     recv_mod_node;

    CVECTOR     *cxfsnbd_seg_vec;
    UINT32       pos;
    UINT32       num;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_bucket_read: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

    if(0 == CNBD_REQ_LEN(cnbd_req))
    {
        CNBD_RSP_MAGIC(cnbd_rsp)  = CNBD_RSP_MAGIC_NUM;
        CNBD_RSP_STATUS(cnbd_rsp) = 0;
        CNBD_RSP_SEQNO(cnbd_rsp)  = CNBD_REQ_SEQNO(cnbd_req);

        return (EC_TRUE);
    }

    cnbd_req_offset_s = (UINT32)(CNBD_REQ_OFFSET(cnbd_req) +                      0);
    cnbd_req_offset_e = (UINT32)(CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req));

    data = safe_malloc(CNBD_REQ_LEN(cnbd_req), LOC_CXFSNBD_0008);
    if(NULL_PTR == data)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_read: "
                                                "alloc %u bytes failed\n",
                                                CNBD_REQ_LEN(cnbd_req));

        return (EC_FALSE);
    }

    cxfsnbd_seg_vec = __cxfsnbd_make_bucket_segs(CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md),
                                                 cnbd_req_offset_s, cnbd_req_offset_e);
    if(NULL_PTR == cxfsnbd_seg_vec)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_read: "
                                                "new cxfsnbd_seg_vec failed\n");

        safe_free(data, LOC_CXFSNBD_0009);
        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnbd_seg_vec_mount_data(cxfsnbd_seg_vec, data, CNBD_REQ_LEN(cnbd_req)))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_read: "
                                                "cxfsnbd_seg_vec mount data failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        safe_free(data, LOC_CXFSNBD_0010);
        return (EC_FALSE);
    }

    if(do_log(SEC_0141_CXFSNBD, 9))
    {
        cnbd_req_print(LOGSTDOUT, cnbd_req);
        dbg_log(SEC_0141_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_read: "
                                                "req %p => [%u, %u)\n",
                                                cnbd_req,
                                                CNBD_REQ_OFFSET(cnbd_req),
                                                CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req));

        dbg_log(SEC_0141_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_read: "
                                                "req %p, segs =>\n",
                                                cnbd_req);

        cxfsnbd_seg_vec_print(LOGSTDOUT, cxfsnbd_seg_vec);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    if(NULL_PTR == task_mgr)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_read: "
                                                "new task_mgr failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        safe_free(data, LOC_CXFSNBD_0011);
        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = CXFSNBD_MD_CXFS_TCID(cxfsnbd_md);
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
    MOD_NODE_MODI(&recv_mod_node) = CXFSNBD_MD_CXFS_MODI(cxfsnbd_md);

    num = cvector_size(cxfsnbd_seg_vec);
    for(pos = 0; pos < num; pos ++)
    {
        CXFSNBD_SEG     *cxfsnbd_seg;

        cxfsnbd_seg = (CXFSNBD_SEG *)cvector_get(cxfsnbd_seg_vec, pos);

        task_p2p_inc(task_mgr, cxfsnbd_md_id,
             &recv_mod_node,
             &CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg),
             FI_cxfs_read_e,
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
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_read: "
                                                    "bucket read [%ld, %ld) of [%ld, %ld) failed\n",
                                                    CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                    CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                    cnbd_req_offset_s,
                                                    cnbd_req_offset_e);

            cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
            cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

            safe_free(data, LOC_CXFSNBD_0012);
            return (EC_FALSE);
        }

        dbg_log(SEC_0141_CXFSNBD, 7)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_read: "
                                                "bucket read [%ld, %ld) of [%ld, %ld) done\n",
                                                CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                cnbd_req_offset_s,
                                                cnbd_req_offset_e);

        dbg_log(SEC_0141_CXFSNBD, 6)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_read: "
                                                "bucket [%ld, %ld) herit data [%ld, %ld] done\n",
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

    dbg_log(SEC_0141_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_read: "
                                            "read (offset %u, len %u) done\n",
                                            CNBD_REQ_OFFSET(cnbd_req),
                                            CNBD_REQ_LEN(cnbd_req));

    return (EC_TRUE);
}

EC_BOOL cxfsnbd_bucket_write(const UINT32 cxfsnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp)
{
    CXFSNBD_MD  *cxfsnbd_md;

    UINT32       cnbd_req_offset_s;
    UINT32       cnbd_req_offset_e;

    TASK_MGR    *task_mgr;
    MOD_NODE     recv_mod_node;

    CVECTOR     *cxfsnbd_seg_vec;
    UINT32       pos;
    UINT32       num;

#if (SWITCH_ON == CXFSNBD_DEBUG_SWITCH)
    if ( CXFSNBD_MD_ID_CHECK_INVALID(cxfsnbd_md_id) )
    {
        sys_log(LOGSTDOUT,
                "error:cxfsnbd_bucket_write: cxfsnbd module #%ld not started.\n",
                cxfsnbd_md_id);
        cxfsnbd_print_module_status(cxfsnbd_md_id, LOGSTDOUT);
        dbg_exit(MD_CXFSNBD, cxfsnbd_md_id);
    }
#endif/*(SWITCH_ON == CXFSNBD_DEBUG_SWITCH)*/

    cxfsnbd_md = CXFSNBD_MD_GET(cxfsnbd_md_id);

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

    cxfsnbd_seg_vec = __cxfsnbd_make_bucket_segs(CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md),
                                                 cnbd_req_offset_s, cnbd_req_offset_e);
    if(NULL_PTR == cxfsnbd_seg_vec)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_write: "
                                                "new cxfsnbd_seg_vec failed\n");

        return (EC_FALSE);
    }

    if(EC_FALSE == cxfsnbd_seg_vec_mount_data(cxfsnbd_seg_vec,
                           CNBD_REQ_DATA_ZONE(cnbd_req), CNBD_REQ_LEN(cnbd_req)))
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_write: "
                                                "cxfsnbd_seg_vec mount data failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        return (EC_FALSE);
    }

    if(do_log(SEC_0141_CXFSNBD, 9))
    {
        cnbd_req_print(LOGSTDOUT, cnbd_req);
        dbg_log(SEC_0141_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_write: "
                                                "req %p => [%u, %u)\n",
                                                cnbd_req,
                                                CNBD_REQ_OFFSET(cnbd_req),
                                                CNBD_REQ_OFFSET(cnbd_req) + CNBD_REQ_LEN(cnbd_req));

        dbg_log(SEC_0141_CXFSNBD, 9)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_write: "
                                                "req %p, segs =>\n",
                                                cnbd_req);

        cxfsnbd_seg_vec_print(LOGSTDOUT, cxfsnbd_seg_vec);
    }

    task_mgr = task_new(NULL_PTR, TASK_PRIO_NORMAL, TASK_NEED_RSP_FLAG, TASK_NEED_ALL_RSP);
    if(NULL_PTR == task_mgr)
    {
        dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_write: "
                                                "new task_mgr failed\n");

        cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
        cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

        return (EC_FALSE);
    }

    MOD_NODE_TCID(&recv_mod_node) = CXFSNBD_MD_CXFS_TCID(cxfsnbd_md);
    MOD_NODE_COMM(&recv_mod_node) = CMPI_ANY_COMM;
    MOD_NODE_RANK(&recv_mod_node) = CMPI_ANY_RANK;
    MOD_NODE_MODI(&recv_mod_node) = CXFSNBD_MD_CXFS_MODI(cxfsnbd_md);

    num = cvector_size(cxfsnbd_seg_vec);
    for(pos = 0; pos < num; pos ++)
    {
        CXFSNBD_SEG     *cxfsnbd_seg;

        cxfsnbd_seg = (CXFSNBD_SEG *)cvector_get(cxfsnbd_seg_vec, pos);

        task_p2p_inc(task_mgr, cxfsnbd_md_id,
             &recv_mod_node,
             &CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg),
             FI_cxfs_write_e,
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
            dbg_log(SEC_0141_CXFSNBD, 0)(LOGSTDOUT, "error:cxfsnbd_bucket_write: "
                                                    "bucket write [%ld, %ld) of [%ld, %ld) failed\n",
                                                    CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                    CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                    cnbd_req_offset_s,
                                                    cnbd_req_offset_e);

            cxfsnbd_seg_vec_umount_data(cxfsnbd_seg_vec);
            cxfsnbd_seg_vec_free(cxfsnbd_seg_vec);

            return (EC_FALSE);
        }

        dbg_log(SEC_0141_CXFSNBD, 7)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_write: "
                                                "bucket write [%ld, %ld) of [%ld, %ld) done\n",
                                                CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg),
                                                CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg),
                                                cnbd_req_offset_s,
                                                cnbd_req_offset_e);

        dbg_log(SEC_0141_CXFSNBD, 6)(LOGSTDOUT, "[DEBUG] cxfsnbd_bucket_write: "
                                                "bucket [%ld, %ld) herit data [%ld, %ld]\n",
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

    dbg_log(SEC_0141_CXFSNBD, 5)(LOGSTDOUT, "[DEBUG] cxfsnbd_handle_req_write: "
                                            "write (offset %u, len %u) done\n",
                                            CNBD_REQ_OFFSET(cnbd_req),
                                            CNBD_REQ_LEN(cnbd_req));
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

