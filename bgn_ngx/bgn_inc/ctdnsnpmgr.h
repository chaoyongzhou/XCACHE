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

#ifndef _CTDNSNPMGR_H
#define _CTDNSNPMGR_H

#include "type.h"
#include "cvector.h"
#include "clist.h"
#include "cstring.h"

#include "chashalgo.h"
#include "ctdnsnp.h"
#include "ctdnsnprb.h"

#define CTDNSNP_DB_NAME      ((const char *)"np_cfg.dat")

typedef struct
{
    CSTRING          ctdnsnp_db_root_dir;           /*ctdnsnp database root dir*/

    uint8_t          ctdnsnp_model;                  /*ctdnsnp model, e.g, CTDNSNP_001G_MODEL*/
    uint8_t          ctdnsnp_2nd_chash_algo_id;
    uint16_t         rsvd1;
    uint32_t         ctdnsnp_item_max_num;
    uint32_t         ctdnsnp_max_num;                /*max np num*/
    uint32_t         rsvd2;
    CVECTOR          ctdnsnp_vec;                    /*item is CTDNSNP*/
}CTDNSNP_MGR;

#define CTDNSNP_MGR_DB_ROOT_DIR(ctdnsnp_mgr)                    (&((ctdnsnp_mgr)->ctdnsnp_db_root_dir))
#define CTDNSNP_MGR_DB_ROOT_DIR_STR(ctdnsnp_mgr)                (cstring_get_str(CTDNSNP_MGR_DB_ROOT_DIR(ctdnsnp_mgr)))

#define CTDNSNP_MGR_NP_MODEL(ctdnsnp_mgr)                        ((ctdnsnp_mgr)->ctdnsnp_model)
#define CTDNSNP_MGR_NP_2ND_CHASH_ALGO_ID(ctdnsnp_mgr)            ((ctdnsnp_mgr)->ctdnsnp_2nd_chash_algo_id)
#define CTDNSNP_MGR_NP_ITEM_MAX_NUM(ctdnsnp_mgr)                 ((ctdnsnp_mgr)->ctdnsnp_item_max_num)
#define CTDNSNP_MGR_NP_MAX_NUM(ctdnsnp_mgr)                      ((ctdnsnp_mgr)->ctdnsnp_max_num)
#define CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr)                          (&((ctdnsnp_mgr)->ctdnsnp_vec))
#define CTDNSNP_MGR_NP(ctdnsnp_mgr, ctdnsnp_id)                  ((CTDNSNP *)cvector_get(CTDNSNP_MGR_NP_VEC(ctdnsnp_mgr), ctdnsnp_id))

CTDNSNP_MGR *ctdnsnp_mgr_new();

EC_BOOL ctdnsnp_mgr_init(CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_clean(CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_free(CTDNSNP_MGR *ctdnsnp_mgr);

CTDNSNP *ctdnsnp_mgr_open_np(CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id);

EC_BOOL ctdnsnp_mgr_close_np(CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id);

EC_BOOL ctdnsnp_mgr_open_np_all(CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_close_np_all(CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_load_db(CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_create_db(CTDNSNP_MGR *ctdnsnp_mgr, const CSTRING *ctdnsnp_db_root_dir);

EC_BOOL ctdnsnp_mgr_flush_db(CTDNSNP_MGR *ctdnsnp_mgr);

void ctdnsnp_mgr_print_db(LOG *log, const CTDNSNP_MGR *ctdnsnp_mgr);

void ctdnsnp_mgr_print(LOG *log, const CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_load(CTDNSNP_MGR *ctdnsnp_mgr, const CSTRING *ctdnsnp_db_root_dir);

EC_BOOL ctdnsnp_mgr_flush(CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_show_np(LOG *log, CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id);

EC_BOOL ctdnsnp_mgr_search(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, uint32_t *searched_ctdnsnp_id);

CTDNSNP_ITEM *ctdnsnp_mgr_search_item(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid);

CTDNSNP_MGR *ctdnsnp_mgr_create(const uint8_t ctdnsnp_model,
                                const uint32_t ctdnsnp_max_num,
                                const uint8_t  ctdnsnp_2nd_chash_algo_id,
                                const CSTRING *ctdnsnp_db_root_dir);

EC_BOOL ctdnsnp_mgr_exist(const CSTRING *ctdnsnp_db_root_dir);

CTDNSNP_MGR * ctdnsnp_mgr_open(const CSTRING *ctdnsnp_db_root_dir);

EC_BOOL ctdnsnp_mgr_close(CTDNSNP_MGR *ctdnsnp_mgr);

EC_BOOL ctdnsnp_mgr_find(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid);

EC_BOOL ctdnsnp_mgr_set(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, const UINT32 ipaddr, const uint32_t klen, const uint8_t *key);

EC_BOOL ctdnsnp_mgr_get(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid, UINT32 *ipaddr, uint32_t *klen, uint8_t **key);

EC_BOOL ctdnsnp_mgr_delete(CTDNSNP_MGR *ctdnsnp_mgr, const UINT32 tcid);

EC_BOOL ctdnsnp_mgr_tcid_num_of_np(CTDNSNP_MGR *ctdnsnp_mgr, const uint32_t ctdnsnp_id, UINT32 *tcid_num);

EC_BOOL ctdnsnp_mgr_tcid_num(CTDNSNP_MGR *ctdnsnp_mgr, UINT32 *tcid_num);


#endif/* _CTDNSNPMGR_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

