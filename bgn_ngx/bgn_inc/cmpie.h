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

#ifndef _CMPIE_H
#define _CMPIE_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "type.h"

#include "cvector.h"

#include "task.h"
#include "super.h"

#include "kbuff.h"

#include "cxfs.h"
#include "cxfsnp.h"
#include "cxfsdn.h"
#include "cmon.h"

#include "csocket.h"

#include "csys.h"
#include "cload.h"
#include "cbytes.h"
#include "csession.h"
#include "cmd5.h"
#include "cbuffer.h"

#include "cstrkv.h"
#include "chttp.inc"
#include "chttps.inc"

#include "ctdnssv.h"
#include "cp2p.h"
#include "cfuses.h"

UINT32 cmpi_encode_uint8(const UINT32 comm, const UINT8 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_uint8_ptr(const UINT32 comm, const UINT8 *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint8(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *num);
UINT32 cmpi_encode_uint8_size(const UINT32 comm, const UINT8 num, UINT32 *size);
UINT32 cmpi_encode_uint8_ptr_size(const UINT32 comm, const UINT8 *num, UINT32 *size);

UINT32 cmpi_encode_uint16(const UINT32 comm, const UINT16 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_uint16_ptr(const UINT32 comm, const UINT16 *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint16(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT16 *num);
UINT32 cmpi_encode_uint16_size(const UINT32 comm, const UINT16 num, UINT32 *size);
UINT32 cmpi_encode_uint16_ptr_size(const UINT32 comm, const UINT16 *num, UINT32 *size);

UINT32 cmpi_encode_uint32(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_uint32_ptr(const UINT32 comm, const UINT32 *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint32(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num);
UINT32 cmpi_encode_uint32_size(const UINT32 comm, const UINT32 num, UINT32 *size);
UINT32 cmpi_encode_uint32_ptr_size(const UINT32 comm, const UINT32 *num, UINT32 *size);

/*compress mode*/
UINT32 cmpi_encode_uint32_compressed_uint32_t(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint32_compressed_uint32_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num);
UINT32 cmpi_encode_uint32_compressed_uint32_t_size(const UINT32 comm, const UINT32 num, UINT32 *size);

/*compress mode*/
UINT32 cmpi_encode_uint32_compressed_uint16_t(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint32_compressed_uint16_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num);
UINT32 cmpi_encode_uint32_compressed_uint16_t_size(const UINT32 comm, const UINT32 num, UINT32 *size);

/*compress mode*/
UINT32 cmpi_encode_uint32_compressed_uint8_t(const UINT32 comm, const UINT32 num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint32_compressed_uint8_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num);
UINT32 cmpi_encode_uint32_compressed_uint8_t_size(const UINT32 comm, const UINT32 num, UINT32 *size);

UINT32 cmpi_encode_uint32_t(const UINT32 comm, const uint32_t num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_uint32_t_ptr(const UINT32 comm, const uint32_t *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_uint32_t_size(const UINT32 comm, const uint32_t num, UINT32 *size);
UINT32 cmpi_encode_uint32_t_ptr_size(const UINT32 comm, const uint32_t *num, UINT32 *size);
UINT32 cmpi_decode_uint32_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, uint32_t *num);

UINT32 cmpi_encode_uint64(const UINT32 comm, const uint64_t num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_uint64_ptr(const UINT32 comm, const uint64_t *num, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_uint64_size(const UINT32 comm, const uint64_t num, UINT32 *size);
UINT32 cmpi_encode_uint64_ptr_size(const UINT32 comm, const uint64_t *num, UINT32 *size);
UINT32 cmpi_decode_uint64(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, uint64_t *num);

UINT32 cmpi_encode_real(const UINT32 comm, const REAL *real, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_real(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, REAL *real);
UINT32 cmpi_encode_real_size(const UINT32 comm, const REAL *real, UINT32 *size);

UINT32 cmpi_encode_macaddr(const UINT32 comm, const UINT8 *macaddr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_macaddr_size(const UINT32 comm, const UINT8 *macaddr, UINT32 *size);
UINT32 cmpi_decode_macaddr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *macaddr);

/*internal interface only: beg*/
UINT32 cmpi_encode_uint8_array(const UINT32 comm, const UINT8 *num, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint8_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT8 *num, UINT32 *len);
UINT32 cmpi_encode_uint8_array_size(const UINT32 comm, const UINT8 *num, const UINT32 len, UINT32 *size);

UINT32 cmpi_encode_uint16_array(const UINT32 comm, const UINT16 *num, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint16_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT16 *num, UINT32 *len);
UINT32 cmpi_encode_uint16_array_size(const UINT32 comm, const UINT16 *num, const UINT32 len, UINT32 *size);

UINT32 cmpi_encode_uint32_array(const UINT32 comm, const UINT32 *num, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_uint32_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, UINT32 *num, UINT32 *len);
UINT32 cmpi_encode_uint32_array_size(const UINT32 comm, const UINT32 *num, const UINT32 len, UINT32 *size);

UINT32 cmpi_encode_real_array(const UINT32 comm, const REAL *real, const UINT32 len, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_real_array(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, REAL *real, UINT32 *len);
UINT32 cmpi_encode_real_array_size(const UINT32 comm, const REAL *real, const UINT32 len, UINT32 *size);
/*internal interface only: end*/

UINT32 cmpi_encode_mod_node(const UINT32 comm, const MOD_NODE *mod_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_mod_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MOD_NODE *mod_node);
UINT32 cmpi_encode_mod_node_size(const UINT32 comm, const MOD_NODE *mod_node, UINT32 *size);

UINT32 cmpi_encode_mod_mgr(const UINT32 comm, const MOD_MGR *mod_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_decode_mod_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MOD_MGR *mod_mgr);
UINT32 cmpi_encode_mod_mgr_size(const UINT32 comm, const MOD_MGR *mod_mgr, UINT32 *size);

UINT32 cmpi_encode_cstring(const UINT32 comm, const CSTRING *cstring, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cstring_size(const UINT32 comm, const CSTRING *cstring, UINT32 *size);
UINT32 cmpi_decode_cstring(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSTRING *cstring);

UINT32 cmpi_encode_taskc_node(const UINT32 comm, const TASKC_NODE *taskc_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_taskc_node_size(const UINT32 comm, const TASKC_NODE *taskc_node, UINT32 *size);
UINT32 cmpi_decode_taskc_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASKC_NODE *taskc_node);

UINT32 cmpi_encode_taskc_mgr(const UINT32 comm, const TASKC_MGR *taskc_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_taskc_mgr_size(const UINT32 comm, const TASKC_MGR *taskc_mgr, UINT32 *size);
UINT32 cmpi_decode_taskc_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASKC_MGR *taskc_mgr);

UINT32 cmpi_encode_log(const UINT32 comm, const LOG *log, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_log_size(const UINT32 comm, const LOG *log, UINT32 *size);
UINT32 cmpi_decode_log(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, LOG *log);

UINT32 cmpi_encode_kbuff(const UINT32 comm, const KBUFF *kbuff, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_kbuff_size(const UINT32 comm, const KBUFF *kbuff, UINT32 *size);
UINT32 cmpi_decode_kbuff(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, KBUFF *kbuff);

/*codec of cvector: must define data_encoder, data_encoder_size, data_decoder, data_init*/
UINT32 cmpi_encode_cvector(const UINT32 comm, const CVECTOR *cvector, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cvector_size(const UINT32 comm, const CVECTOR *cvector, UINT32 *size);
UINT32 cmpi_decode_cvector(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CVECTOR *cvector);

UINT32 cmpi_encode_csocket_cnode(const UINT32 comm, const CSOCKET_CNODE *csocket_cnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_csocket_cnode_size(const UINT32 comm, const CSOCKET_CNODE *csocket_cnode, UINT32 *size);
UINT32 cmpi_decode_csocket_cnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSOCKET_CNODE *csocket_cnode);

UINT32 cmpi_encode_csys_cpu_stat(const UINT32 comm, const CSYS_CPU_STAT *csys_cpu_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_csys_cpu_stat_size(const UINT32 comm, const CSYS_CPU_STAT *csys_cpu_stat, UINT32 *size);
UINT32 cmpi_decode_csys_cpu_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSYS_CPU_STAT *csys_cpu_stat);

UINT32 cmpi_encode_mm_man_occupy_node(const UINT32 comm, const MM_MAN_OCCUPY_NODE *mm_man_occupy_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_mm_man_occupy_node_size(const UINT32 comm, const MM_MAN_OCCUPY_NODE *mm_man_occupy_node, UINT32 *size);
UINT32 cmpi_decode_mm_man_occupy_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MM_MAN_OCCUPY_NODE *mm_man_occupy_node);

UINT32 cmpi_encode_mm_man_load_node(const UINT32 comm, const MM_MAN_LOAD_NODE *mm_man_load_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_mm_man_load_node_size(const UINT32 comm, const MM_MAN_LOAD_NODE *mm_man_load_node, UINT32 *size);
UINT32 cmpi_decode_mm_man_load_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, MM_MAN_LOAD_NODE *mm_man_load_node);

UINT32 cmpi_encode_cproc_module_stat(const UINT32 comm, const CPROC_MODULE_STAT *cproc_module_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cproc_module_stat_size(const UINT32 comm, const CPROC_MODULE_STAT *cproc_module_stat, UINT32 *size);
UINT32 cmpi_decode_cproc_module_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CPROC_MODULE_STAT *cproc_module_stat);

UINT32 cmpi_encode_crank_thread_stat(const UINT32 comm, const CRANK_THREAD_STAT *crank_thread_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_crank_thread_stat_size(const UINT32 comm, const CRANK_THREAD_STAT *crank_thread_stat, UINT32 *size);
UINT32 cmpi_decode_crank_thread_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CRANK_THREAD_STAT *crank_thread_stat);

UINT32 cmpi_encode_csys_eth_stat(const UINT32 comm, const CSYS_ETH_STAT *csys_eth_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_csys_eth_stat_size(const UINT32 comm, const CSYS_ETH_STAT *csys_eth_stat, UINT32 *size);
UINT32 cmpi_decode_csys_eth_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSYS_ETH_STAT *csys_eth_stat);

UINT32 cmpi_encode_csys_dsk_stat(const UINT32 comm, const CSYS_DSK_STAT *csys_dsk_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_csys_dsk_stat_size(const UINT32 comm, const CSYS_DSK_STAT *csys_dsk_stat, UINT32 *size);
UINT32 cmpi_decode_csys_dsk_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSYS_DSK_STAT *csys_dsk_stat);

UINT32 cmpi_encode_task_time_fmt(const UINT32 comm, const TASK_TIME_FMT *task_time_fmt, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_task_time_fmt_size(const UINT32 comm, const TASK_TIME_FMT *task_time_fmt, UINT32 *size);
UINT32 cmpi_decode_task_time_fmt(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASK_TIME_FMT *task_time_fmt);

UINT32 cmpi_encode_task_report_node(const UINT32 comm, const TASK_REPORT_NODE *task_report_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_task_report_node_size(const UINT32 comm, const TASK_REPORT_NODE *task_report_node, UINT32 *size);
UINT32 cmpi_decode_task_report_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASK_REPORT_NODE *task_report_node);

UINT32 cmpi_encode_cload_stat(const UINT32 comm, const CLOAD_STAT *cload_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cload_stat_size(const UINT32 comm, const CLOAD_STAT *cload_stat, UINT32 *size);
UINT32 cmpi_decode_cload_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLOAD_STAT *cload_stat);

UINT32 cmpi_encode_cload_node(const UINT32 comm, const CLOAD_NODE *cload_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cload_node_size(const UINT32 comm, const CLOAD_NODE *cload_node, UINT32 *size);
UINT32 cmpi_decode_cload_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLOAD_NODE *cload_node);

UINT32 cmpi_encode_cload_mgr(const UINT32 comm, const CLOAD_MGR *cload_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cload_mgr_size(const UINT32 comm, const CLOAD_MGR *cload_mgr, UINT32 *size);
UINT32 cmpi_decode_cload_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLOAD_MGR *cload_mgr);

UINT32 cmpi_encode_cbytes(const UINT32 comm, const CBYTES *cbytes, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cbytes_size(const UINT32 comm, const CBYTES *cbytes, UINT32 *size);
UINT32 cmpi_decode_cbytes(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CBYTES *cbytes);

UINT32 cmpi_encode_cbytes_ext(const UINT32 comm, const CBYTES *cbytes_ext, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cbytes_ext_size(const UINT32 comm, const CBYTES *cbytes_ext, UINT32 *size);
UINT32 cmpi_decode_cbytes_ext(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CBYTES *cbytes_ext);

UINT32 cmpi_encode_ctimet(const UINT32 comm, const CTIMET *ctimet, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_ctimet_size(const UINT32 comm, const CTIMET *ctimet, UINT32 *size);
UINT32 cmpi_decode_ctimet(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CTIMET *ctimet);

UINT32 cmpi_encode_csession_node(const UINT32 comm, const CSESSION_NODE *csession_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_csession_node_size(const UINT32 comm, const CSESSION_NODE *csession_node, UINT32 *size);
UINT32 cmpi_decode_csession_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSESSION_NODE *csession_node);

UINT32 cmpi_encode_csession_item(const UINT32 comm, const CSESSION_ITEM *csession_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_csession_item_size(const UINT32 comm, const CSESSION_ITEM *csession_item, UINT32 *size);
UINT32 cmpi_decode_csession_item(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSESSION_ITEM *csession_item);

UINT32 cmpi_encode_clist(const UINT32 comm, const CLIST *clist, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_clist_size(const UINT32 comm, const CLIST *clist, UINT32 *size);
UINT32 cmpi_decode_clist(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CLIST *clist);

UINT32 cmpi_encode_cmd5_digest(const UINT32 comm, const CMD5_DIGEST *cmd5_digest, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cmd5_digest_size(const UINT32 comm, const CMD5_DIGEST *cmd5_digest, UINT32 *size);
UINT32 cmpi_decode_cmd5_digest(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CMD5_DIGEST *cmd5_digest);

UINT32 cmpi_encode_cbuffer(const UINT32 comm, const CBUFFER *cbuffer, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cbuffer_size(const UINT32 comm, const CBUFFER *cbuffer, UINT32 *size);
UINT32 cmpi_decode_cbuffer(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CBUFFER *cbuffer);

UINT32 cmpi_encode_cstrkv(const UINT32 comm, const CSTRKV *cstrkv, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cstrkv_size(const UINT32 comm, const CSTRKV *cstrkv, UINT32 *size);
UINT32 cmpi_decode_cstrkv(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSTRKV *cstrkv);

UINT32 cmpi_encode_cstrkv_mgr(const UINT32 comm, const CSTRKV_MGR *cstrkv_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cstrkv_mgr_size(const UINT32 comm, const CSTRKV_MGR *cstrkv_mgr, UINT32 *size);
UINT32 cmpi_decode_cstrkv_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CSTRKV_MGR *cstrkv_mgr);

UINT32 cmpi_encode_chttp_req(const UINT32 comm, const CHTTP_REQ *chttp_req, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_chttp_req_size(const UINT32 comm, const CHTTP_REQ *chttp_req, UINT32 *size);
UINT32 cmpi_decode_chttp_req(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_REQ *chttp_req);

UINT32 cmpi_encode_chttp_rsp(const UINT32 comm, const CHTTP_RSP *chttp_rsp, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_chttp_rsp_size(const UINT32 comm, const CHTTP_RSP *chttp_rsp, UINT32 *size);
UINT32 cmpi_decode_chttp_rsp(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_RSP *chttp_rsp);

UINT32 cmpi_encode_chttp_stat(const UINT32 comm, const CHTTP_STAT *chttp_stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_chttp_stat_size(const UINT32 comm, const CHTTP_STAT *chttp_stat, UINT32 *size);
UINT32 cmpi_decode_chttp_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_STAT *chttp_stat);

UINT32 cmpi_encode_chttp_store(const UINT32 comm, const CHTTP_STORE *chttp_store, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_chttp_store_size(const UINT32 comm, const CHTTP_STORE *chttp_store, UINT32 *size);
UINT32 cmpi_decode_chttp_store(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CHTTP_STORE *chttp_store);

UINT32 cmpi_encode_tasks_node(const UINT32 comm, const TASKS_NODE *tasks_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_tasks_node_size(const UINT32 comm, const TASKS_NODE *tasks_node, UINT32 *size);
UINT32 cmpi_decode_tasks_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, TASKS_NODE *tasks_node);

UINT32 cmpi_encode_time_t(const UINT32 comm, const ctime_t time, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_time_t_size(const UINT32 comm, const ctime_t time, UINT32 *size);
UINT32 cmpi_decode_time_t(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, ctime_t *time);

UINT32 cmpi_encode_ctdnssv_node(const UINT32 comm, const CTDNSSV_NODE *ctdnssv_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_ctdnssv_node_size(const UINT32 comm, const CTDNSSV_NODE *ctdnssv_node, UINT32 *size);
UINT32 cmpi_decode_ctdnssv_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CTDNSSV_NODE *ctdnssv_node);

UINT32 cmpi_encode_ctdnssv_node_mgr(const UINT32 comm, const CTDNSSV_NODE_MGR *ctdnssv_node_mgr, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_ctdnssv_node_mgr_size(const UINT32 comm, const CTDNSSV_NODE_MGR *ctdnssv_node_mgr, UINT32 *size);
UINT32 cmpi_decode_ctdnssv_node_mgr(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CTDNSSV_NODE_MGR *ctdnssv_node_mgr);

UINT32 cmpi_encode_cp2p_file(const UINT32 comm, const CP2P_FILE *cp2p_file, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cp2p_file_size(const UINT32 comm, const CP2P_FILE *cp2p_file, UINT32 *size);
UINT32 cmpi_decode_cp2p_file(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CP2P_FILE *cp2p_file);

UINT32 cmpi_encode_cp2p_cmd(const UINT32 comm, const CP2P_CMD *cp2p_cmd, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cp2p_cmd_size(const UINT32 comm, const CP2P_CMD *cp2p_cmd, UINT32 *size);
UINT32 cmpi_decode_cp2p_cmd(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CP2P_CMD *cp2p_cmd);

UINT32 cmpi_encode_cxfsnp_inode(const UINT32 comm, const CXFSNP_INODE *cxfsnp_inode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cxfsnp_inode_size(const UINT32 comm, const CXFSNP_INODE *cxfsnp_inode, UINT32 *size);
UINT32 cmpi_decode_cxfsnp_inode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_INODE *cxfsnp_inode);

UINT32 cmpi_encode_cxfsnp_fnode(const UINT32 comm, const CXFSNP_FNODE *cxfsnp_fnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cxfsnp_fnode_size(const UINT32 comm, const CXFSNP_FNODE *cxfsnp_fnode, UINT32 *size);
UINT32 cmpi_decode_cxfsnp_fnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_FNODE *cxfsnp_fnode);

UINT32 cmpi_encode_cxfsnp_key(const UINT32 comm, const CXFSNP_KEY *cxfsnp_key, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cxfsnp_key_size(const UINT32 comm, const CXFSNP_KEY *cxfsnp_key, UINT32 *size);
UINT32 cmpi_decode_cxfsnp_key(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_KEY *cxfsnp_key);

UINT32 cmpi_encode_cxfsnpque_node(const UINT32 comm, const CXFSNPQUE_NODE *cxfsnpque_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cxfsnpque_node_size(const UINT32 comm, const CXFSNPQUE_NODE *cxfsnpque_node, UINT32 *size);
UINT32 cmpi_decode_cxfsnpque_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNPQUE_NODE *cxfsnpque_node);

UINT32 cmpi_encode_cxfsnpdel_node(const UINT32 comm, const CXFSNPDEL_NODE *cxfsnpdel_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cxfsnpdel_node_size(const UINT32 comm, const CXFSNPDEL_NODE *cxfsnpdel_node, UINT32 *size);
UINT32 cmpi_decode_cxfsnpdel_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNPDEL_NODE *cxfsnpdel_node);

UINT32 cmpi_encode_cxfsnp_item(const UINT32 comm, const CXFSNP_ITEM *cxfsnp_item, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cxfsnp_item_size(const UINT32 comm, const CXFSNP_ITEM *cxfsnp_item, UINT32 *size);
UINT32 cmpi_decode_cxfsnp_item(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CXFSNP_ITEM *cxfsnp_item);

UINT32 cmpi_encode_cmon_node(const UINT32 comm, const CMON_NODE *cmon_node, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_cmon_node_size(const UINT32 comm, const CMON_NODE *cmon_node, UINT32 *size);
UINT32 cmpi_decode_cmon_node(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, CMON_NODE *cmon_node);

UINT32 cmpi_encode_i32(const UINT32 comm, const int *i32, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_i32_size(const UINT32 comm, const int *i32, UINT32 *size);
UINT32 cmpi_decode_i32(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, int *i32);

UINT32 cmpi_encode_stat(const UINT32 comm, const struct stat *stat, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_stat_size(const UINT32 comm, const struct stat *stat, UINT32 *size);
UINT32 cmpi_decode_stat(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct stat *stat);

UINT32 cmpi_encode_statvfs(const UINT32 comm, const struct statvfs *statvfs, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_statvfs_size(const UINT32 comm, const struct statvfs *statvfs, UINT32 *size);
UINT32 cmpi_decode_statvfs(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct statvfs *statvfs);

UINT32 cmpi_encode_timespec(const UINT32 comm, const struct timespec *timespec, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_timespec_size(const UINT32 comm, const struct timespec *timespec, UINT32 *size);
UINT32 cmpi_decode_timespec(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct timespec *timespec);

UINT32 cmpi_encode_utimbuf(const UINT32 comm, const struct utimbuf *utimbuf, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_utimbuf_size(const UINT32 comm, const struct utimbuf *utimbuf, UINT32 *size);
UINT32 cmpi_decode_utimbuf(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct utimbuf *utimbuf);

UINT32 cmpi_encode_dirnode(const UINT32 comm, const struct dirnode *dirnode, UINT8 *out_buff, const UINT32 out_buff_max_len, UINT32 *position);
UINT32 cmpi_encode_dirnode_size(const UINT32 comm, const struct dirnode *dirnode, UINT32 *size);
UINT32 cmpi_decode_dirnode(const UINT32 comm, const UINT8 *in_buff, const UINT32 in_buff_max_len, UINT32 *position, struct dirnode *dirnode);

#endif/*_CMPIE_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

