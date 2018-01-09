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

#ifndef _CTDNSSVMGR_H
#define _CTDNSSVMGR_H

#include "type.h"
#include "clist.h"
#include "cstring.h"

#include "ctdnssv.h"

#define CTDNSSV_SP_MODEL_DEFAULT                (CTDNSSV_032M_MODEL)

typedef struct
{
    CSTRING          ctdnssv_sp_root_dir;            /*ctdnssv database root dir*/

    CLIST            ctdnssv_list;               /*item is CTDNSSV*/
}CTDNSSV_MGR;

#define CTDNSSV_MGR_SP_ROOT_DIR(ctdnssv_mgr)                    (&((ctdnssv_mgr)->ctdnssv_sp_root_dir))
#define CTDNSSV_MGR_SP_ROOT_DIR_STR(ctdnssv_mgr)                (cstring_get_str(CTDNSSV_MGR_SP_ROOT_DIR(ctdnssv_mgr)))

#define CTDNSSV_MGR_SP_SERVICES(ctdnssv_mgr)                    (&((ctdnssv_mgr)->ctdnssv_list))

CTDNSSV_MGR *ctdnssv_mgr_new();

EC_BOOL ctdnssv_mgr_init(CTDNSSV_MGR *ctdnssv_mgr);

EC_BOOL ctdnssv_mgr_clean(CTDNSSV_MGR *ctdnssv_mgr);

EC_BOOL ctdnssv_mgr_free(CTDNSSV_MGR *ctdnssv_mgr);

CTDNSSV *ctdnssv_mgr_search_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

CTDNSSV *ctdnssv_mgr_open_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

CTDNSSV *ctdnssv_mgr_delete_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

EC_BOOL ctdnssv_mgr_close_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

CTDNSSV *ctdnssv_mgr_create_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

EC_BOOL ctdnssv_mgr_open_sp_all(CTDNSSV_MGR *ctdnssv_mgr);

EC_BOOL ctdnssv_mgr_close_sp_all(CTDNSSV_MGR *ctdnssv_mgr);

void ctdnssv_mgr_print(LOG *log, const CTDNSSV_MGR *ctdnssv_mgr);

EC_BOOL ctdnssv_mgr_load(CTDNSSV_MGR *ctdnssv_mgr);

EC_BOOL ctdnssv_mgr_sync_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

EC_BOOL ctdnssv_mgr_flush(CTDNSSV_MGR *ctdnssv_mgr);

EC_BOOL ctdnssv_mgr_show_sp(LOG *log, CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

CTDNSSV_MGR *ctdnssv_mgr_create(const CSTRING *ctdnssv_sp_root_dir);

CTDNSSV_MGR * ctdnssv_mgr_open(const CSTRING *ctdnssv_sp_root_dir);

EC_BOOL ctdnssv_mgr_close(CTDNSSV_MGR *ctdnssv_mgr);

EC_BOOL ctdnssv_mgr_exists(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name);

EC_BOOL ctdnssv_mgr_set(CTDNSSV_MGR *ctdnssv_mgr, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port, const CSTRING *service_name);

EC_BOOL ctdnssv_mgr_get(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdnssv_mgr_delete_one(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name, const UINT32 tcid);

EC_BOOL ctdnssv_mgr_delete(CTDNSSV_MGR *ctdnssv_mgr, const UINT32 tcid);

EC_BOOL ctdnssv_mgr_node_num_of_sp(CTDNSSV_MGR *ctdnssv_mgr, const CSTRING *service_name, UINT32 *node_num);

EC_BOOL ctdnssv_mgr_node_num(CTDNSSV_MGR *ctdnssv_mgr, UINT32 *node_num);


#endif/* _CTDNSSVMGR_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

