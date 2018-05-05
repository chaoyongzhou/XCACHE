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

#ifndef _CSFSMC_H
#define _CSFSMC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cmutex.h"
#include "cstring.h"

#include "chashalgo.h"
#include "csfsnprb.h"
#include "csfsnp.h"
#include "csfsmc.inc"

CSFSMC *csfsmc_new(const UINT32 csfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num);

EC_BOOL csfsmc_init(CSFSMC *csfsmc, const UINT32 csfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num);

EC_BOOL csfsmc_clean(CSFSMC *csfsmc);

EC_BOOL csfsmc_free(CSFSMC *csfsmc);

CSFSNP_FNODE *csfsmc_reserve_np_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, uint32_t *node_pos);

EC_BOOL csfsmc_release_np_no_lock(CSFSMC *csfsmc, const CSTRING *file_path);

EC_BOOL csfsmc_reserve_dn_no_lock(CSFSMC *csfsmc, const uint32_t size, uint16_t *block_no, uint16_t *page_no);

EC_BOOL csfsmc_release_dn_no_lock(CSFSMC *csfsmc, const uint32_t size, const uint16_t block_no, const uint16_t page_no);

EC_BOOL csfsmc_import_dn_no_lock(CSFSMC *csfsmc, const CBYTES *cbytes, const CSFSNP_FNODE *csfsnp_fnode);

EC_BOOL csfsmc_write_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL csfsmc_write_dn_no_lock(CSFSMC *csfsmc, CSFSNP_FNODE *csfsnp_fnode, const CBYTES *cbytes );

EC_BOOL csfsmc_read_np_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, CSFSNP_FNODE *csfsnp_fnode, uint32_t *node_pos);

/* check whether np is in memcache only, do not read np or change the lru list */
EC_BOOL csfsmc_check_np(CSFSMC *csfsmc, const CSTRING *file_path);

EC_BOOL csfsmc_read_dn_no_lock(CSFSMC *csfsmc, const CSFSNP_FNODE *csfsnp_fnode, CBYTES *cbytes);

EC_BOOL csfsmc_read_e_dn_no_lock(CSFSMC *csfsmc, const CSFSNP_FNODE *csfsnp_fnode, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL csfsmc_file_size_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, uint64_t *file_size);

EC_BOOL csfsmc_read_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL csfsmc_read_e_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL csfsmc_update_no_lock(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL csfsmc_delete_no_lock(CSFSMC *csfsmc, const CSTRING *file_path);

EC_BOOL csfsmc_retire_no_lock(CSFSMC *csfsmc);

EC_BOOL csfsmc_recycle_no_lock(CSFSMC *csfsmc, const UINT32 max_num, UINT32 *complete_num);

EC_BOOL csfsmc_room_is_ok_no_lock(CSFSMC *csfsmc, const REAL level);

EC_BOOL csfsmc_write(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL csfsmc_read(CSFSMC *csfsmc, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL csfsmc_read_e(CSFSMC *csfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL csfsmc_file_size(CSFSMC *csfsmc, const CSTRING *file_path, uint64_t *file_size);

EC_BOOL csfsmc_update(CSFSMC *csfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL csfsmc_delete(CSFSMC *csfsmc, const CSTRING *file_path);

EC_BOOL csfsmc_retire(CSFSMC *csfsmc);

void    csfsmc_print(LOG *log, const CSFSMC *csfsmc);

EC_BOOL csfsmc_ensure_room_safe_level(CSFSMC *csfsmc);

EC_BOOL csfsmc_ensure_room_safe_level_no_lock(CSFSMC *csfsmc);

#endif/* _CSFSMC_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

