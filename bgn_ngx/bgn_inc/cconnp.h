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

#ifndef _CCONNP_H
#define _CCONNP_H

#include "type.h"
#include "csocket.inc"
#include "cconnp.inc"

CCONNP *cconnp_new();

EC_BOOL cconnp_init(CCONNP *cconnp);

EC_BOOL cconnp_clean(CCONNP *cconnp);

EC_BOOL cconnp_free(CCONNP *cconnp);

CSOCKET_CNODE *cconnp_reserve(CCONNP *cconnp);

EC_BOOL cconnp_release(CCONNP *cconnp, CSOCKET_CNODE *csocket_cnode);

EC_BOOL cconnp_erase(CSOCKET_CNODE *csocket_cnode);

void cconnp_print(LOG *log, const CCONNP *cconnp);

int cconnp_cmp(const CCONNP *cconnp_1, const CCONNP *cconnp_2);

CCONNP_MGR *cconnp_mgr_new();

EC_BOOL cconnp_mgr_init(CCONNP_MGR *cconnp_mgr);

EC_BOOL cconnp_mgr_clean(CCONNP_MGR *cconnp_mgr);

EC_BOOL cconnp_mgr_free(CCONNP_MGR *cconnp_mgr);

void cconnp_mgr_print(LOG *log, const CCONNP_MGR *cconnp_mgr);

CCONNP *cconnp_mgr_add(CCONNP_MGR *cconnp_mgr, const UINT32 srv_tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);

CCONNP *cconnp_mgr_search(CCONNP_MGR *cconnp_mgr, const UINT32 srv_tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);

CSOCKET_CNODE *cconnp_mgr_reserve(CCONNP_MGR *cconnp_mgr, const UINT32 srv_tcid, const UINT32 srv_ipaddr, const UINT32 srv_port);

EC_BOOL cconnp_mgr_release(CCONNP_MGR *cconnp_mgr, CSOCKET_CNODE *csocket_cnode);


#endif/*_CCONNP_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/


