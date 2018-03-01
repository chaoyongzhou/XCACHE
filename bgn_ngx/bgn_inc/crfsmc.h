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

#ifndef _CRFSMC_H
#define _CRFSMC_H

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
#include "crfsnprb.h"
#include "crfsnp.inc"
#include "crfsmc.inc"

CRFSMC *crfsmc_new(const UINT32 crfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const uint16_t block_num);

EC_BOOL crfsmc_init(CRFSMC *crfsmc, const UINT32 crfs_md_id, const uint32_t np_id, const uint8_t np_model, const uint8_t hash_2nd_algo_id, const uint16_t block_num);

EC_BOOL crfsmc_clean(CRFSMC *crfsmc);

EC_BOOL crfsmc_free(CRFSMC *crfsmc);

CRFSNP_FNODE *crfsmc_reserve_np_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, uint32_t *node_pos);

EC_BOOL crfsmc_release_np_no_lock(CRFSMC *crfsmc, const CSTRING *file_path);

EC_BOOL crfsmc_reserve_dn_no_lock(CRFSMC *crfsmc, const uint32_t size, uint16_t *block_no, uint16_t *page_no);

EC_BOOL crfsmc_release_dn_no_lock(CRFSMC *crfsmc, const uint32_t size, const uint16_t block_no, const uint16_t page_no);

EC_BOOL crfsmc_import_dn_no_lock(CRFSMC *crfsmc, const CBYTES *cbytes, const CRFSNP_FNODE *crfsnp_fnode);

EC_BOOL crfsmc_write_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum);

EC_BOOL crfsmc_write_dn_no_lock(CRFSMC *crfsmc, CRFSNP_FNODE *crfsnp_fnode, const CBYTES *cbytes, const uint8_t *md5sum);

EC_BOOL crfsmc_read_np_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, CRFSNP_FNODE *crfsnp_fnode, uint32_t *node_pos);

/* check whether np is in memcache only, do not read np or change the lru list */
EC_BOOL crfsmc_check_np(CRFSMC *crfsmc, const CSTRING *file_path);

EC_BOOL crfsmc_read_dn_no_lock(CRFSMC *crfsmc, const CRFSNP_FNODE *crfsnp_fnode, CBYTES *cbytes);

EC_BOOL crfsmc_read_e_dn_no_lock(CRFSMC *crfsmc, const CRFSNP_FNODE *crfsnp_fnode, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL crfsmc_file_size_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, uint64_t *file_size);

EC_BOOL crfsmc_read_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL crfsmc_read_e_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL crfsmc_update_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum);

EC_BOOL crfsmc_delete_no_lock(CRFSMC *crfsmc, const CSTRING *file_path, const UINT32 dflag);

EC_BOOL crfsmc_retire_no_lock(CRFSMC *crfsmc);

EC_BOOL crfsmc_recycle_no_lock(CRFSMC *crfsmc, const UINT32 max_num, UINT32 *complete_num);

EC_BOOL crfsmc_room_is_ok_no_lock(CRFSMC *crfsmc, const REAL level);

EC_BOOL crfsmc_write(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum);

EC_BOOL crfsmc_read(CRFSMC *crfsmc, const CSTRING *file_path, CBYTES *cbytes);

EC_BOOL crfsmc_read_e(CRFSMC *crfsmc, const CSTRING *file_path, UINT32 *store_offset, const UINT32 store_size, CBYTES *cbytes);

EC_BOOL crfsmc_file_size(CRFSMC *crfsmc, const CSTRING *file_path, uint64_t *file_size);

EC_BOOL crfsmc_update(CRFSMC *crfsmc, const CSTRING *file_path, const CBYTES *cbytes, const uint8_t *md5sum);

EC_BOOL crfsmc_delete(CRFSMC *crfsmc, const CSTRING *file_path, const UINT32 dflag);

EC_BOOL crfsmc_delete_wildcard(CRFSMC *crfsmc, const CSTRING *file_path, const UINT32 dflag);

EC_BOOL crfsmc_retire(CRFSMC *crfsmc);

EC_BOOL crfsmc_recycle(CRFSMC *crfsmc, const UINT32 max_num, UINT32 *complete_num);

void    crfsmc_print(LOG *log, const CRFSMC *crfsmc);

EC_BOOL crfsmc_ensure_room_safe_level(CRFSMC *crfsmc);

EC_BOOL crfsmc_ensure_room_safe_level_no_lock(CRFSMC *crfsmc);

#endif/* _CRFSMC_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

