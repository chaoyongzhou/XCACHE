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

#ifndef _CDSK_H
#define _CDSK_H


#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cstring.h"

#define CDSK_SHARED_ERR_DISK_ID             ((UINT32)-1)
#define CDSK_SHARED_ERR_PATH_ID             ((UINT32)-1)


typedef struct
{
    UINT32  disk_id;    /*disk id*/
    UINT32  path_id;    /*path id on above disk*/
}CDSK_SHARD;

#define CDSK_SHARD_DISK_ID(cdsk_shard)       ((cdsk_shard)->disk_id)
#define CDSK_SHARD_PATH_ID(cdsk_shard)       ((cdsk_shard)->path_id)

#define CDSK_PATH_LAYOUT_TO_DISK_ID(path_layout, dsk_num)       ((path_layout) % (dsk_num))
#define CDSK_PATH_LAYOUT_TO_PATH_ID(path_layout, dsk_num)       ((path_layout) / (dsk_num))

#define CDSK_SHARD_TO_PATH_LAYOUT(dsk_num, cdsk_shard)          (CDSK_SHARD_DISK_ID(cdsk_shard)  + CDSK_SHARD_DISK_ID(cdsk_shard) * (dsk_num))

#define CDSK_PATH_LAYOUT_TO_SHARD(path_layout, dsk_num, cdsk_shard)         do{\
    CDSK_SHARD_DISK_ID(cdsk_shard) = CDSK_PATH_LAYOUT_TO_DISK_ID(path_layout, dsk_num);\
    CDSK_SHARD_PATH_ID(cdsk_shard) = CDSK_PATH_LAYOUT_TO_PATH_ID(path_layout, dsk_num);\
}while(0)

EC_BOOL cdsk_shard_init(CDSK_SHARD *cdsk_shard);

EC_BOOL cdsk_shard_clean(CDSK_SHARD *cdsk_shard);

EC_BOOL cdsk_pathlayout_to_shard(const UINT32 path_layout, const UINT32 dsk_num, CDSK_SHARD *cdsk_shard);

EC_BOOL cdsk_shard_to_pathlayout(const UINT32 dsk_num, const CDSK_SHARD *cdsk_shard, UINT32 *path_layout);

/*maybe only apply for adding new disk*/
EC_BOOL cdsk_shard_transfer(const UINT32 dsk_num_src, const CDSK_SHARD *cdsk_shard_src, const UINT32 dsk_num_des, CDSK_SHARD *cdsk_shard_des);


#endif/* _CDSK_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

