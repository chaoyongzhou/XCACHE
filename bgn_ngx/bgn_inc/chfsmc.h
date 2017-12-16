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

#ifndef _CHFSMC_H
#define _CHFSMC_H

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
#include "chfsnprb.h"
#include "chfsnp.h"
#include "chfsmc.inc"

CHFSMC *chfsmc_new(const UINT32 chfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num);

EC_BOOL chfsmc_init(CHFSMC *chfsmc, const UINT32 chfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_1st_algo_id, const uint8_t hash_2nd_algo_id, const uint32_t bucket_max_num, const uint16_t block_num);

EC_BOOL chfsmc_clean(CHFSMC *chfsmc);

EC_BOOL chfsmc_free(CHFSMC *chfsmc);

CHFSNP_FNODE *chfsmc_reserve_np_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, uint32_t *node_pos);

EC_BOOL chfsmc_release_np_no_lock(CHFSMC *chfsmc, const CSTRING *file_path);

EC_BOOL chfsmc_reserve_dn_no_lock(CHFSMC *chfsmc, const uint32_t size, uint16_t *block_no, uint16_t *page_no);

EC_BOOL chfsmc_release_dn_no_lock(CHFSMC *chfsmc, const uint32_t size, const uint16_t block_no, const uint16_t page_no);

EC_BOOL chfsmc_import_dn_no_lock(CHFSMC *chfsmc, const CBYTES *cbytes, const CHFSNP_FNODE *chfsnp_fnode);

EC_BOOL chfsmc_write_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL chfsmc_write_dn_no_lock(CHFSMC *chfsmc, CHFSNP_FNODE *chfsnp_fnode, const CBYTES *cbytes );

EC_BOOL chfsmc_read_np_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, CHFSNP_FNODE *chfsnp_fnode, uint32_t *node_pos);

/* check whether np is in memcache only, do not read np or change the lru list */
EC_BOOL chfsmc_check_np(CHFSMC *chfsmc, const CSTRING *file_path);

EC_BOOL chfsmc_read_dn_no_lock(CHFSMC *chfsmc, const CHFSNP_FNODE *chfsnp_fnode, CBYTES *cbytes);

EC_BOOL chfsmc_read_e_dn_no_lock(CHFSMC *chfsmc, const CHFSNP_FNODE *chfsnp_fnode, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL chfsmc_file_size_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, uint64_t *file_size);

EC_BOOL chfsmc_read_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL chfsmc_read_e_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL chfsmc_update_no_lock(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL chfsmc_delete_no_lock(CHFSMC *chfsmc, const CSTRING *file_path);

EC_BOOL chfsmc_retire_no_lock(CHFSMC *chfsmc);

EC_BOOL chfsmc_recycle_no_lock(CHFSMC *chfsmc, const UINT32 max_num, UINT32 *complete_num);

EC_BOOL chfsmc_room_is_ok_no_lock(CHFSMC *chfsmc, const REAL level);

EC_BOOL chfsmc_write(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL chfsmc_read(CHFSMC *chfsmc, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL chfsmc_read_e(CHFSMC *chfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL chfsmc_file_size(CHFSMC *chfsmc, const CSTRING *file_path, uint64_t *file_size);

EC_BOOL chfsmc_update(CHFSMC *chfsmc, const CSTRING *file_path, const CBYTES *cbytes );

EC_BOOL chfsmc_delete(CHFSMC *chfsmc, const CSTRING *file_path);

EC_BOOL chfsmc_retire(CHFSMC *chfsmc);

EC_BOOL chfsmc_recycle(CHFSMC *chfsmc, const UINT32 max_num, UINT32 *complete_num);

void    chfsmc_print(LOG *log, const CHFSMC *chfsmc);

EC_BOOL chfsmc_ensure_room_safe_level(CHFSMC *chfsmc);

EC_BOOL chfsmc_ensure_room_safe_level_no_lock(CHFSMC *chfsmc);

#endif/* _CHFSMC_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

