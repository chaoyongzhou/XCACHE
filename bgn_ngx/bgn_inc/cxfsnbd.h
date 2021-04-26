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

#ifndef _CXFSNBD_H
#define _CXFSNBD_H

#include "type.h"
#include "mm.h"
#include "log.h"

#include "clist.h"
#include "cbytes.h"

#include "cnbd.h"
#include "cxfs.h"

#define CXFSNBD_CXFS_SEG_SIZE       (((UINT32)64) << 20) /*64MB*/

typedef struct
{
    /* used counter >= 0 */
    UINT32                      usedcounter;

    CSTRING                    *nbd_dev_name;
    CSTRING                    *bucket_name;

    UINT32                      cxfs_tcid;
    UINT32                      cxfs_modi;

    UINT32                      cnbd_modi;

    uint64_t                    nbd_blk_size;
    uint64_t                    nbd_dev_size;
    uint64_t                    nbd_timeout;
    uint64_t                    nbd_t_flags;   /*transmission flags*/

}CXFSNBD_MD;

#define CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md)             ((cxfsnbd_md)->nbd_dev_name)
#define CXFSNBD_MD_NBD_DEV_NAME_STR(cxfsnbd_md)         (cstring_get_str(CXFSNBD_MD_NBD_DEV_NAME(cxfsnbd_md)))

#define CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md)              ((cxfsnbd_md)->bucket_name)
#define CXFSNBD_MD_BUCKET_NAME_STR(cxfsnbd_md)          (cstring_get_str(CXFSNBD_MD_BUCKET_NAME(cxfsnbd_md)))

#define CXFSNBD_MD_CXFS_TCID(cxfsnbd_md)                ((cxfsnbd_md)->cxfs_tcid)
#define CXFSNBD_MD_CXFS_MODI(cxfsnbd_md)                ((cxfsnbd_md)->cxfs_modi)

#define CXFSNBD_MD_CNBD_MODI(cxfsnbd_md)                ((cxfsnbd_md)->cnbd_modi)

#define CXFSNBD_MD_NBD_BLK_SIZE(cxfsnbd_md)             ((cxfsnbd_md)->nbd_blk_size)
#define CXFSNBD_MD_NBD_DEV_SIZE(cxfsnbd_md)             ((cxfsnbd_md)->nbd_dev_size)
#define CXFSNBD_MD_NBD_TIMEOUT(cxfsnbd_md)              ((cxfsnbd_md)->nbd_timeout)
#define CXFSNBD_MD_NBD_T_FLAGS(cxfsnbd_md)              ((cxfsnbd_md)->nbd_t_flags)

typedef struct
{
    CSTRING        *cxfs_seg_name;
    CBYTES         *cxfs_seg_data;

    UINT32          cnbd_seg_s_offset;
    UINT32          cnbd_seg_e_offset;

    UINT32          data_seg_s_offset;
    UINT32          data_seg_e_offset;

    UINT32          cxfs_seg_idx;
    UINT32          cxfs_seg_s_offset;
    UINT32          cxfs_seg_e_offset;
    UINT32          cxfs_seg_t_offset;  /*temporary offset for reading or writting*/
    EC_BOOL         cxfs_seg_result;
}CXFSNBD_SEG;

#define CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg)                   ((cxfsnbd_seg)->cxfs_seg_name)
#define CXFSNBD_CXFS_SEG_NAME_STR(cxfsnbd_seg)               (cstring_get_str(CXFSNBD_CXFS_SEG_NAME(cxfsnbd_seg)))

#define CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg)                   ((cxfsnbd_seg)->cxfs_seg_data)
#define CXFSNBD_CXFS_SEG_DATA_LEN(cxfsnbd_seg)               (CBYTES_LEN(CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg)))
#define CXFSNBD_CXFS_SEG_DATA_BUF(cxfsnbd_seg)               (CBYTES_BUF(CXFSNBD_CXFS_SEG_DATA(cxfsnbd_seg)))

#define CXFSNBD_CNBD_SEG_S_OFFSET(cxfsnbd_seg)               ((cxfsnbd_seg)->cnbd_seg_s_offset)
#define CXFSNBD_CNBD_SEG_E_OFFSET(cxfsnbd_seg)               ((cxfsnbd_seg)->cnbd_seg_e_offset)

#define CXFSNBD_DATA_SEG_S_OFFSET(cxfsnbd_seg)               ((cxfsnbd_seg)->data_seg_s_offset)
#define CXFSNBD_DATA_SEG_E_OFFSET(cxfsnbd_seg)               ((cxfsnbd_seg)->data_seg_e_offset)

#define CXFSNBD_CXFS_SEG_IDX(cxfsnbd_seg)                    ((cxfsnbd_seg)->cxfs_seg_idx)
#define CXFSNBD_CXFS_SEG_S_OFFSET(cxfsnbd_seg)               ((cxfsnbd_seg)->cxfs_seg_s_offset)
#define CXFSNBD_CXFS_SEG_E_OFFSET(cxfsnbd_seg)               ((cxfsnbd_seg)->cxfs_seg_e_offset)
#define CXFSNBD_CXFS_SEG_T_OFFSET(cxfsnbd_seg)               ((cxfsnbd_seg)->cxfs_seg_t_offset)
#define CXFSNBD_CXFS_SEG_RESULT(cxfsnbd_seg)                 ((cxfsnbd_seg)->cxfs_seg_result)

/**
*   for test only
*
*   to query the status of CXFSNBD Module
*
**/
void cxfsnbd_print_module_status(const UINT32 cxfsnbd_md_id, LOG *log);

/**
*
*   free all static memory occupied by the appointed CXFSNBD module
*
*
**/
UINT32 cxfsnbd_free_module_static_mem(const UINT32 cxfsnbd_md_id);

/**
*
* start CXFSNBD module
*
**/
UINT32 cxfsnbd_start(const CSTRING *nbd_dev_name,
                        const UINT32   nbd_blk_size,
                        const UINT32   nbd_dev_size,
                        const UINT32   nbd_timeout,
                        const CSTRING *bucket_name,
                        const UINT32   cxfs_tcid,
                        const UINT32   cxfs_md_id);

/**
*
* end CXFSNBD module
*
**/
void cxfsnbd_end(const UINT32 cxfsnbd_md_id);

CXFSNBD_SEG *cxfsnbd_seg_new();

EC_BOOL cxfsnbd_seg_init(CXFSNBD_SEG *cxfsnbd_seg);

EC_BOOL cxfsnbd_seg_clean(CXFSNBD_SEG *cxfsnbd_seg);

EC_BOOL cxfsnbd_seg_mount_data(CXFSNBD_SEG *cxfsnbd_seg, UINT8 *data, UINT32 len);

EC_BOOL cxfsnbd_seg_umount_data(CXFSNBD_SEG *cxfsnbd_seg);

EC_BOOL cxfsnbd_seg_free(CXFSNBD_SEG *cxfsnbd_seg);

void cxfsnbd_seg_print(LOG *log, const CXFSNBD_SEG *cxfsnbd_seg);

void cxfsnbd_seg_print_plain(LOG *log, const CXFSNBD_SEG *cxfsnbd_seg);

CVECTOR *cxfsnbd_seg_vec_new(const UINT32 capacity);

EC_BOOL cxfsnbd_seg_vec_clean(CVECTOR *cxfsnbd_seg_vec);

EC_BOOL cxfsnbd_seg_vec_mount_data(CVECTOR *cxfsnbd_seg_vec, UINT8 *data, const UINT32 len);

EC_BOOL cxfsnbd_seg_vec_umount_data(CVECTOR *cxfsnbd_seg_vec);

EC_BOOL cxfsnbd_seg_vec_free(CVECTOR *cxfsnbd_seg_vec);

void cxfsnbd_seg_vec_print(LOG *log, const CVECTOR *cxfsnbd_seg_vec);

EC_BOOL cxfsnbd_bucket_check(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_bucket_create(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_bucket_launch(const UINT32 cxfsnbd_md_id);

EC_BOOL cxfsnbd_bucket_read(const UINT32 cxfsnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp);

EC_BOOL cxfsnbd_bucket_write(const UINT32 cxfsnbd_md_id, const CNBD_REQ *cnbd_req, CNBD_RSP *cnbd_rsp);



#endif /*_CXFSNBD_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

