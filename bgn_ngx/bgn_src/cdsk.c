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
#include "cmisc.h"
#include "cdsk.h"

/**
*                       map between path layout and disk shards
* ===========================================================================================================
*
* for example, let physical node has 4 disks, the path layout (or block) store in disks as following
* ----------------------------------------------------
*   DSK         Path Layout
* ----------------------------------------------------
*   dsk0    0       4       8       12      16
*   dsk1    1       5       9       13      17
*   dsk2    2       6       10      14      18
*   dsk3    3       7       11      15      19
* ----------------------------------------------------
*
*   the map P_{n}, where n is the disk num, from path layout k to store full path is
*       P_{n}:  k   ----->  (k % n, k / n)
*   or
*       P(n, k) = (k % n, k / n) ( =  k % n || k / n )
*
*   the inverse path P^{-1}_{n}, where n is the disk num, from store full path (i, j) to path layout is
*       P^{-1}_{n}: (i, j)  -----> i + j * n
*
*   when add new disk, for example, disk num increase from n to m,
*   the map C_{n, m} from the old store full path (i, j) to new store full path is
*       C_{n, m}(i, j)  -----> P_{m}(P^{-1}_{n}(i, j))  = P_{m}(i + j * n) = ((i + j * n) % m, (i + j * n) / m)
*
*   when remvoe old disk, ....
*
**/

EC_BOOL cdsk_shard_init(CDSK_SHARD *cdsk_shard)
{
    CDSK_SHARD_DISK_ID(cdsk_shard) = CDSK_SHARED_ERR_DISK_ID;
    CDSK_SHARD_PATH_ID(cdsk_shard) = CDSK_SHARED_ERR_PATH_ID;
    return (EC_TRUE);
}

EC_BOOL cdsk_shard_clean(CDSK_SHARD *cdsk_shard)
{
    CDSK_SHARD_DISK_ID(cdsk_shard) = CDSK_SHARED_ERR_DISK_ID;
    CDSK_SHARD_PATH_ID(cdsk_shard) = CDSK_SHARED_ERR_PATH_ID;
    return (EC_TRUE);
}

EC_BOOL cdsk_pathlayout_to_shard(const UINT32 path_layout, const UINT32 dsk_num, CDSK_SHARD *cdsk_shard)
{
    CDSK_PATH_LAYOUT_TO_SHARD(path_layout, dsk_num, cdsk_shard);
    return (EC_TRUE);
}

EC_BOOL cdsk_shard_to_pathlayout(const UINT32 dsk_num, const CDSK_SHARD *cdsk_shard, UINT32 *path_layout)
{
    (*path_layout) = CDSK_SHARD_TO_PATH_LAYOUT(dsk_num, cdsk_shard);
    return (EC_TRUE);
}

/*maybe only apply for adding new disk*/
EC_BOOL cdsk_shard_transfer(const UINT32 dsk_num_src, const CDSK_SHARD *cdsk_shard_src, const UINT32 dsk_num_des, CDSK_SHARD *cdsk_shard_des)
{
    UINT32 path_layout_src;

    if(dsk_num_src > dsk_num_des)
    {
        dbg_log(SEC_0032_CDSK, 0)(LOGSTDOUT, "error:cdsk_shard_transfer src disk num %ld > des disk num %ld\n", dsk_num_src, dsk_num_des);
        return (EC_FALSE);
    }

    path_layout_src = CDSK_SHARD_TO_PATH_LAYOUT(dsk_num_src, cdsk_shard_src);
    CDSK_PATH_LAYOUT_TO_SHARD(path_layout_src, dsk_num_des, cdsk_shard_des);
    return (EC_TRUE);
}


#ifdef __cplusplus
}
#endif/*__cplusplus*/

