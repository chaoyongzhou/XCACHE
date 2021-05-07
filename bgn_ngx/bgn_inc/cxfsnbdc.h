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

#ifndef _CXFSNBDC_H
#define _CXFSNBDC_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"
#include "cbytes.h"

#include "cnbd.h"
#include "cxfs.h"

#define CXFSNBDC_CXFS_SEG_SIZE       (((UINT32)64) << 20) /*64MB*/

typedef struct
{
    /* used counter >= 0 */
    UINT32                      usedcounter;

    CSTRING                    *nbd_dev_name;
    CSTRING                    *bucket_name;

    UINT32                      cxfsc_tcid;
    UINT32                      cxfsc_modi;

    UINT32                      cnbd_modi;

    uint64_t                    nbd_blk_size;
    uint64_t                    nbd_dev_size;
    uint64_t                    nbd_timeout;
    uint64_t                    nbd_t_flags;   /*transmission flags*/

}CXFSNBDC_MD;

#define CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md)             ((cxfsnbdc_md)->nbd_dev_name)
#define CXFSNBDC_MD_NBD_DEV_NAME_STR(cxfsnbdc_md)         (cstring_get_str(CXFSNBDC_MD_NBD_DEV_NAME(cxfsnbdc_md)))

#define CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md)              ((cxfsnbdc_md)->bucket_name)
#define CXFSNBDC_MD_BUCKET_NAME_STR(cxfsnbdc_md)          (cstring_get_str(CXFSNBDC_MD_BUCKET_NAME(cxfsnbdc_md)))

#define CXFSNBDC_MD_CXFSC_TCID(cxfsnbdc_md)               ((cxfsnbdc_md)->cxfsc_tcid)
#define CXFSNBDC_MD_CXFSC_MODI(cxfsnbdc_md)               ((cxfsnbdc_md)->cxfsc_modi)

#define CXFSNBDC_MD_CNBD_MODI(cxfsnbdc_md)                ((cxfsnbdc_md)->cnbd_modi)

#define CXFSNBDC_MD_NBD_BLK_SIZE(cxfsnbdc_md)             ((cxfsnbdc_md)->nbd_blk_size)
#define CXFSNBDC_MD_NBD_DEV_SIZE(cxfsnbdc_md)             ((cxfsnbdc_md)->nbd_dev_size)
#define CXFSNBDC_MD_NBD_TIMEOUT(cxfsnbdc_md)              ((cxfsnbdc_md)->nbd_timeout)
#define CXFSNBDC_MD_NBD_T_FLAGS(cxfsnbdc_md)              ((cxfsnbdc_md)->nbd_t_flags)

/**
*   for test only
*
*   to query the status of CXFSNBDC Module
*
**/
void cxfsnbdc_print_module_status(const UINT32 cxfsnbdc_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CXFSNBDC module
*
*
**/
UINT32 cxfsnbdc_free_module_static_mem(const UINT32 cxfsnbdc_md_id);

/**
*
* start CXFSNBDC module
*
**/
UINT32 cxfsnbdc_start(const CSTRING *nbd_dev_name,
                        const UINT32   nbd_blk_size,
                        const UINT32   nbd_dev_size,
                        const UINT32   nbd_timeout,
                        const CSTRING *bucket_name,
                        const UINT32   cxfsc_tcid,
                        const UINT32   cxfsc_md_id);

/**
*
* end CXFSNBDC module
*
**/
void cxfsnbdc_end(const UINT32 cxfsnbdc_md_id);

EC_BOOL cxfsnbdc_bucket_check(const UINT32 cxfsnbdc_md_id);

EC_BOOL cxfsnbdc_bucket_create(const UINT32 cxfsnbdc_md_id);

EC_BOOL cxfsnbdc_bucket_launch(const UINT32 cxfsnbdc_md_id);

EC_BOOL cxfsnbdc_bucket_read(const UINT32 cxfsnbdc_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp);

EC_BOOL cxfsnbdc_bucket_write(const UINT32 cxfsnbdc_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp);

#endif /*_CXFSNBDC_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

