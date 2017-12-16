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

#ifndef _CSYS_H
#define _CSYS_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "cstring.h"
#include "cvector.h"

#include "log.h"

#include "task.inc"
#include "csys.inc"

UINT32 csys_info_print();

void csys_test();

/*------------------------------- CSYS_CPU_CFG_VEC interface -------------------------------*/
CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec_new();

UINT32 csys_cpu_cfg_vec_init(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec);

UINT32 csys_cpu_cfg_vec_clean(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec);

UINT32 csys_cpu_cfg_vec_free(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec);

void   csys_cpu_cfg_vec_print(LOG *log, const CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec);

UINT32 csys_cpu_cfg_vec_get(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec);

/*------------------------------- CSYS_CPU_STAT interface -------------------------------*/

CSYS_CPU_STAT *csys_cpu_stat_new();

UINT32 csys_cpu_stat_init(CSYS_CPU_STAT *csys_cpu_stat);

UINT32 csys_cpu_stat_clean(CSYS_CPU_STAT *csys_cpu_stat);

UINT32 csys_cpu_stat_free(CSYS_CPU_STAT *csys_cpu_stat);

UINT32 csys_cpu_stat_get(const char *buff, CSYS_CPU_STAT *csys_cpu_stat);

UINT32 csys_cpu_stat_clone(CSYS_CPU_STAT *csys_cpu_stat_src, CSYS_CPU_STAT *csys_cpu_stat_des);

void   csys_cpu_stat_print(LOG *log, const CSYS_CPU_STAT *csys_cpu_stat);

/*------------------------------- CSYS_CPU_STAT_VEC interface -------------------------------*/
CSYS_CPU_STAT_VEC *csys_cpu_stat_vec_new();

UINT32 csys_cpu_stat_vec_init(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec);

UINT32 csys_cpu_stat_vec_clean(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec);

UINT32 csys_cpu_stat_vec_free(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec);

UINT32 csys_cpu_stat_vec_get(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec);

UINT32 csys_cpu_stat_vec_size(const CSYS_CPU_STAT_VEC *csys_cpu_stat_vec);

CSYS_CPU_STAT * csys_cpu_stat_vec_fetch(const CSYS_CPU_STAT_VEC *csys_cpu_stat_vec, const UINT32 csys_cpu_stat_pos);

void   csys_cpu_stat_vec_print(LOG *log, const CSYS_CPU_STAT_VEC *csys_cpu_stat_vec);

/*------------------------------- CSYS_CPU_AVG_STAT interface -------------------------------*/
CSYS_CPU_AVG_STAT *csys_cpu_avg_stat_new();

UINT32 csys_cpu_avg_stat_init(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat);

UINT32 csys_cpu_avg_stat_clean(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat);

UINT32 csys_cpu_avg_stat_free(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat);

void csys_cpu_avg_stat_print(LOG *log, const CSYS_CPU_AVG_STAT *csys_cpu_avg_stat);

UINT32 csys_cpu_avg_stat_get(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat);

/*------------------------------- CSYS_MEM_STAT interface -------------------------------*/
CSYS_MEM_STAT *csys_mem_stat_new();

UINT32 csys_mem_stat_init(CSYS_MEM_STAT *csys_mem_stat);

UINT32 csys_mem_stat_clean(CSYS_MEM_STAT *csys_mem_stat);

UINT32 csys_mem_stat_free(CSYS_MEM_STAT *csys_mem_stat);

UINT32 csys_mem_stat_get(CSYS_MEM_STAT *csys_mem_stat);

void   csys_mem_stat_print(LOG *log, const CSYS_MEM_STAT *csys_mem_stat);

/*------------------------------- CPROC_MEM_STAT interface -------------------------------*/
CPROC_MEM_STAT *cproc_mem_stat_new();

UINT32 cproc_mem_stat_init(CPROC_MEM_STAT *cproc_mem_stat);

UINT32 cproc_mem_stat_clean(CPROC_MEM_STAT *cproc_mem_stat);

UINT32 cproc_mem_stat_free(CPROC_MEM_STAT *cproc_mem_stat);

void cproc_mem_stat_print(LOG *log, const CPROC_MEM_STAT *cproc_mem_stat);

UINT32 cproc_mem_stat_get(CPROC_MEM_STAT *cproc_mem_stat);

/*------------------------------- CPROC_CPU_STAT interface -------------------------------*/
CPROC_CPU_STAT *cproc_cpu_stat_new();

UINT32 cproc_cpu_stat_init(CPROC_CPU_STAT *cproc_cpu_stat);

UINT32 cproc_cpu_stat_clean(CPROC_CPU_STAT *cproc_cpu_stat);

UINT32 cproc_cpu_stat_free(CPROC_CPU_STAT *cproc_cpu_stat);

void cproc_cpu_stat_print(LOG *log, const CPROC_CPU_STAT *cproc_cpu_stat);

UINT32 cproc_cpu_stat_get(CPROC_CPU_STAT *cproc_cpu_stat);

/*------------------------------- CTOP_OLINE interface -------------------------------*/
UINT32 ctop_process_stat(const UINT32 pid, CTOP_OLINE *ctop_oline);

/*------------------------------- CPROC_THREAD_STAT interface -------------------------------*/
CPROC_THREAD_STAT *cproc_thread_stat_new();

UINT32 cproc_thread_stat_init(CPROC_THREAD_STAT *cproc_thread_stat);

UINT32 cproc_thread_stat_clean(CPROC_THREAD_STAT *cproc_thread_stat);

UINT32 cproc_thread_stat_free(CPROC_THREAD_STAT *cproc_thread_stat);

void cproc_thread_stat_print(LOG *log, const CPROC_THREAD_STAT *cproc_thread_stat);

UINT32 cproc_thread_stat_get(CPROC_THREAD_STAT *cproc_thread_stat);

/*------------------------------- CPROC_MODULE_STAT interface -------------------------------*/
CPROC_MODULE_STAT *cproc_module_stat_new();
UINT32 cproc_module_stat_init(CPROC_MODULE_STAT *cproc_module_stat);

UINT32 cproc_module_stat_clean(CPROC_MODULE_STAT *cproc_module_stat);

UINT32 cproc_module_stat_free(CPROC_MODULE_STAT *cproc_module_stat);

UINT32 cproc_module_stat_clone(CPROC_MODULE_STAT *cproc_module_stat_src, CPROC_MODULE_STAT *cproc_module_stat_des);

EC_BOOL cproc_module_stat_cmp_type(const CPROC_MODULE_STAT *cproc_module_stat_1st, const CPROC_MODULE_STAT *cproc_module_stat_2nd);

void cproc_module_stat_print(LOG *log, const CPROC_MODULE_STAT *cproc_module_stat);

UINT32 cproc_module_stat_get(CPROC_MODULE_STAT *cproc_module_stat);

/*------------------------------- CPROC_MODULE_STAT_VEC interface -------------------------------*/
CPROC_MODULE_STAT_VEC *cproc_module_stat_vec_new();

UINT32 cproc_module_stat_vec_init(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec);

UINT32 cproc_module_stat_vec_clean(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec);

UINT32 cproc_module_stat_vec_free(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec);

UINT32 cproc_module_stat_vec_size(const CPROC_MODULE_STAT_VEC *cproc_module_stat_vec);

CPROC_MODULE_STAT * cproc_module_stat_vec_fetch(const CPROC_MODULE_STAT_VEC *cproc_module_stat_vec, const UINT32 cproc_module_stat_pos);

void cproc_module_stat_vec_print(LOG *log, const CPROC_MODULE_STAT_VEC *cproc_module_stat_vec);

UINT32 cproc_module_stat_vec_get(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec);

/*------------------------------- CRANK_THREAD_STAT interface -------------------------------*/
CRANK_THREAD_STAT *crank_thread_stat_new();

UINT32 crank_thread_stat_init(CRANK_THREAD_STAT *crank_thread_stat);

UINT32 crank_thread_stat_clean(CRANK_THREAD_STAT *crank_thread_stat);

UINT32 crank_thread_stat_free(CRANK_THREAD_STAT *crank_thread_stat);

UINT32 crank_thread_stat_clone(const CRANK_THREAD_STAT *crank_thread_stat_src, CRANK_THREAD_STAT *crank_thread_stat_des);

void crank_thread_stat_print(LOG *log, const CRANK_THREAD_STAT *crank_thread_stat);

UINT32 crank_thread_stat_get(CRANK_THREAD_STAT *crank_thread_stat);

/*------------------------------- CSYS_ETH_STAT interface -------------------------------*/
CSYS_ETH_STAT *csys_eth_stat_new();

UINT32 csys_eth_stat_init(CSYS_ETH_STAT *csys_eth_stat);

UINT32 csys_eth_stat_clean(CSYS_ETH_STAT *csys_eth_stat);

UINT32 csys_eth_stat_free(CSYS_ETH_STAT *csys_eth_stat);

UINT32 csys_eth_stat_clone(CSYS_ETH_STAT *csys_eth_stat_src, CSYS_ETH_STAT *csys_eth_stat_des);

void csys_eth_stat_print(LOG *log, const CSYS_ETH_STAT *csys_eth_stat);

UINT32 csys_eth_stat_get(char *buff, CSYS_ETH_STAT *csys_eth_stat);

/*------------------------------- CSYS_ETH_VEC interface -------------------------------*/
CSYS_ETH_VEC *csys_eth_stat_vec_new();

UINT32 csys_eth_stat_vec_init(CSYS_ETH_VEC *csys_eth_stat_vec);

UINT32 csys_eth_stat_vec_clean(CSYS_ETH_VEC *csys_eth_stat_vec);

UINT32 csys_eth_stat_vec_free(CSYS_ETH_VEC *csys_eth_stat_vec);

UINT32 csys_eth_stat_vec_size(const CSYS_ETH_VEC *csys_eth_stat_vec);

CSYS_ETH_STAT * csys_eth_stat_vec_fetch(const CSYS_ETH_VEC *csys_eth_stat_vec, const UINT32 csys_eth_stat_pos);

void csys_eth_stat_vec_print(LOG *log, const CSYS_ETH_VEC *csys_eth_stat_vec);

UINT32 csys_eth_stat_vec_get(CSYS_ETH_VEC *csys_eth_stat_vec);

/*------------------------------- CSYS_DSK_STAT interface -------------------------------*/
CSYS_DSK_STAT *csys_dsk_stat_new();

UINT32 csys_dsk_stat_init(CSYS_DSK_STAT *csys_dsk_stat);

UINT32 csys_dsk_stat_clean(CSYS_DSK_STAT *csys_dsk_stat);

UINT32 csys_dsk_stat_free(CSYS_DSK_STAT *csys_dsk_stat);

UINT32 csys_dsk_stat_clone(CSYS_DSK_STAT *csys_dsk_stat_src, CSYS_DSK_STAT *csys_dsk_stat_des);

void csys_dsk_stat_print(LOG *log, const CSYS_DSK_STAT *csys_dsk_stat);

UINT32 csys_dsk_stat_get(char *buff, CSYS_DSK_STAT *csys_dsk_stat);

/*------------------------------- CSYS_DSK_VEC interface -------------------------------*/
CSYS_DSK_VEC *csys_dsk_stat_vec_new();

UINT32 csys_dsk_stat_vec_init(CSYS_DSK_VEC *csys_dsk_stat_vec);

UINT32 csys_dsk_stat_vec_clean(CSYS_DSK_VEC *csys_dsk_stat_vec);

UINT32 csys_dsk_stat_vec_free(CSYS_DSK_VEC *csys_dsk_stat_vec);

UINT32 csys_dsk_stat_vec_size(const CSYS_DSK_VEC *csys_dsk_stat_vec);

CSYS_DSK_STAT * csys_dsk_stat_vec_fetch(const CSYS_DSK_VEC *csys_dsk_stat_vec, const UINT32 csys_dsk_stat_pos);

void csys_dsk_stat_vec_print(LOG *log, const CSYS_DSK_VEC *csys_dsk_stat_vec);

UINT32 csys_dsk_stat_vec_get(CSYS_DSK_VEC *csys_dsk_stat_vec);

/*------------------------------- CRANK_TASK_REPORT_VEC interface -------------------------------*/
CRANK_TASK_REPORT_VEC *crank_task_report_vec_new();

UINT32 crank_task_report_vec_init(CRANK_TASK_REPORT_VEC *crank_task_report_vec);

UINT32 crank_task_report_vec_clean(CRANK_TASK_REPORT_VEC *crank_task_report_vec);

UINT32 crank_task_report_vec_free(CRANK_TASK_REPORT_VEC *crank_task_report_vec);

UINT32 crank_task_report_vec_size(const CRANK_TASK_REPORT_VEC *crank_task_report_vec);

TASK_REPORT_NODE * crank_task_report_vec_fetch(const CRANK_TASK_REPORT_VEC *crank_task_report_vec, const UINT32 crank_task_report_pos);

void crank_task_report_vec_print(LOG *log, const CRANK_TASK_REPORT_VEC *crank_task_report_vec);

UINT32 crank_task_report_vec_get(CRANK_TASK_REPORT_VEC *crank_task_report_vec);

#endif /*_CSYS_H*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

