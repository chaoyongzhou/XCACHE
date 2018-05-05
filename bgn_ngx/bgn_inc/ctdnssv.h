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

#ifndef _CTDNSSV_H
#define _CTDNSSV_H

#include "type.h"
#include "log.h"

#include "cvector.h"
#include "cstring.h"
#include "task.inc"
#include "chashalgo.h"
#include "ctdnssvrb.h"
#include "ctdnssv.inc"


const char *ctdnssv_model_str(const uint8_t ctdnssv_model);

uint8_t ctdnssv_model_get(const char *model_str);

EC_BOOL ctdnssv_model_file_size(const uint8_t ctdnssv_model, UINT32 *file_size);

EC_BOOL ctdnssv_model_item_max_num(const uint8_t ctdnssv_model, uint32_t *item_max_num);

CTDNSSV_ITEM *ctdnssv_item_new();

EC_BOOL ctdnssv_item_init(CTDNSSV_ITEM *ctdnssv_item);

EC_BOOL ctdnssv_item_clean(CTDNSSV_ITEM *ctdnssv_item);

EC_BOOL ctdnssv_item_clone(const CTDNSSV_ITEM *ctdnssv_item_src, CTDNSSV_ITEM *ctdnssv_item_des);

EC_BOOL ctdnssv_item_free(CTDNSSV_ITEM *ctdnssv_item);

void   ctdnssv_item_print(LOG *log, const CTDNSSV_ITEM *ctdnssv_item);

EC_BOOL ctdnssv_item_load(CTDNSSV *ctdnssv, uint32_t *offset, CTDNSSV_ITEM *ctdnssv_item);

EC_BOOL ctdnssv_item_flush(CTDNSSV *ctdnssv, uint32_t *offset, const CTDNSSV_ITEM *ctdnssv_item);

EC_BOOL ctdnssv_item_is_tcid(const CTDNSSV_ITEM *ctdnssv_item, const UINT32 tcid);

CTDNSSV_NODE *ctdnssv_node_new();

EC_BOOL ctdnssv_node_init(CTDNSSV_NODE *ctdnssv_node);

EC_BOOL ctdnssv_node_clean(CTDNSSV_NODE *ctdnssv_node);

EC_BOOL ctdnssv_node_clone(const CTDNSSV_NODE *ctdnssv_node_src, CTDNSSV_NODE *ctdnssv_node_des);

EC_BOOL ctdnssv_node_free(CTDNSSV_NODE *ctdnssv_node);

void ctdnssv_node_print(LOG *log, const CTDNSSV_NODE *ctdnssv_node);

CTDNSSV_NODE_MGR *ctdnssv_node_mgr_new();

EC_BOOL ctdnssv_node_mgr_init(CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdnssv_node_mgr_clean(CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdnssv_node_mgr_free(CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdnssv_node_mgr_is_empty(const CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

void ctdnssv_node_mgr_print(LOG *log, const CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdnssv_header_load(CTDNSSV *ctdnssv, uint32_t *offset, CTDNSSV_HEADER *ctdnssv_header);

EC_BOOL ctdnssv_header_flush(CTDNSSV *ctdnssv, uint32_t *offset, const CTDNSSV_HEADER *ctdnssv_header);

EC_BOOL ctdnssv_header_is(const CTDNSSV_HEADER *ctdnssv_header, const uint32_t sname_len, const uint8_t *sname);

CTDNSSV_HEADER *ctdnssv_header_open(const UINT32 fsize, int fd);

CTDNSSV_HEADER *ctdnssv_header_create(const UINT32 fsize, int fd, const uint8_t model);

CTDNSSV_HEADER *ctdnssv_header_sync(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd);

CTDNSSV_HEADER *ctdnssv_header_close(CTDNSSV_HEADER *ctdnssv_header, const UINT32 fsize, int fd);

CTDNSSV *ctdnssv_new();

EC_BOOL ctdnssv_init(CTDNSSV *ctdnssv);

EC_BOOL ctdnssv_clean(CTDNSSV *ctdnssv);

EC_BOOL ctdnssv_free(CTDNSSV *ctdnssv);

void ctdnssv_print(LOG *log, const CTDNSSV *ctdnssv);

CTDNSSV *ctdnssv_open(const char *service_fname);

EC_BOOL ctdnssv_close(CTDNSSV *ctdnssv);

EC_BOOL ctdnssv_sync(CTDNSSV *ctdnssv);

CTDNSSV *ctdnssv_create(const char *sp_root_dir, const char *sname, const uint8_t model);

EC_BOOL ctdnssv_delete(CTDNSSV *ctdnssv, const UINT32 tcid);

EC_BOOL ctdnssv_is_service(const CTDNSSV *ctdnssv, const CSTRING *service_name);

EC_BOOL ctdnssv_is_full(const CTDNSSV *ctdnssv);

EC_BOOL ctdnssv_insert(CTDNSSV *ctdnssv, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port);

CTDNSSV_ITEM *ctdnssv_fetch(const CTDNSSV *ctdnssv, const uint32_t node_pos);

uint32_t ctdnssv_search(CTDNSSV *ctdnssv, const UINT32 tcid);

CTDNSSV_ITEM *ctdnssv_set(CTDNSSV *ctdnssv, const UINT32 tcid, const UINT32 ipaddr, const UINT32 port);

CTDNSSV_ITEM *ctdnssv_get(CTDNSSV *ctdnssv, const UINT32 tcid);

EC_BOOL ctdnssv_finger(CTDNSSV *ctdnssv, const UINT32 max_num, CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

EC_BOOL ctdnssv_pop(CTDNSSV *ctdnssv, UINT32 *tcid, UINT32 *ipaddr, UINT32 *port);

EC_BOOL ctdnssv_show_item(LOG *log, const CTDNSSV *ctdnssv, const uint32_t node_pos);

EC_BOOL ctdnssv_node_num(const CTDNSSV *ctdnssv, UINT32 *node_num);


#endif/* _CTDNSSV_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

