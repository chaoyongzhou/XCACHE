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

#ifndef _CSYS_INC
#define _CSYS_INC

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "cstring.h"
#include "cvector.h"

#include "log.h"

#include "task.inc"

#define CSYS_SHELL_BUF_MAX_SIZE             ((UINT32) 1 * 1024 * 1024)

/*file: /proc/cpuinfo*/
typedef CVECTOR CSYS_CPU_CFG_VEC; /*data item type is MM_CSTRING*/
#define CSYS_CPU_CFG_VEC_INFO(csys_cpu_cfg_vec)      (csys_cpu_cfg_vec)

/*file: /proc/loadavg */
typedef CVECTOR CSYS_CPU_LOAD_AVG;/*data item type is MM_REAL*/
#define CSYS_CPU_01_MIN_LOAD_POS   ((UINT32) 0)
#define CSYS_CPU_05_MIN_LOAD_POS   ((UINT32) 5)
#define CSYS_CPU_15_MIN_LOAD_POS   ((UINT32)15)

/*file: /proc/stat */
typedef struct
{
    CSTRING  cstr;
    UINT32   user;
    UINT32   nice;
    UINT32   sys;
    UINT32   idle;
    UINT32   total;

    REAL     load; /*private data without encoding & decoding*/
}CSYS_CPU_STAT;

#define CSYS_CPU_STAT_CSTR(csys_cpu_stat)         (&((csys_cpu_stat)->cstr))
#define CSYS_CPU_STAT_USER(csys_cpu_stat)         ((csys_cpu_stat)->user)
#define CSYS_CPU_STAT_NICE(csys_cpu_stat)         ((csys_cpu_stat)->nice)
#define CSYS_CPU_STAT_SYS(csys_cpu_stat)          ((csys_cpu_stat)->sys)
#define CSYS_CPU_STAT_IDLE(csys_cpu_stat)         ((csys_cpu_stat)->idle)
#define CSYS_CPU_STAT_TOTAL(csys_cpu_stat)        ((csys_cpu_stat)->total)
#define CSYS_CPU_STAT_LOAD(csys_cpu_stat)         ((csys_cpu_stat)->load)

typedef CVECTOR CSYS_CPU_STAT_VEC;/*data item type is CSYS_CPU_STAT*/
#define CSYS_CPU_LOAD_VEC_INFO(csys_cpu_stat_vec)       (csys_cpu_stat_vec)

typedef struct
{
    REAL  avg_01_min;
    REAL  avg_05_min;
    REAL  avg_15_min;
}CSYS_CPU_AVG_STAT;

#define CSYS_CPU_AVG_STAT_01_MIN(csys_cpu_avg_stat)     ((csys_cpu_avg_stat)->avg_01_min)
#define CSYS_CPU_AVG_STAT_05_MIN(csys_cpu_avg_stat)     ((csys_cpu_avg_stat)->avg_05_min)
#define CSYS_CPU_AVG_STAT_15_MIN(csys_cpu_avg_stat)     ((csys_cpu_avg_stat)->avg_15_min)

typedef struct
{
    UINT32   mem_total;
    UINT32   mem_free;
}CSYS_MEM_STAT;

#define CSYS_MEM_TOTAL(csys_mem_stat)       ((csys_mem_stat)->mem_total)
#define CSYS_MEM_FREE(csys_mem_stat)        ((csys_mem_stat)->mem_free)

typedef struct
{
    UINT32        mem_occupy;
    REAL          mem_load;
}CPROC_MEM_STAT;
#define CPROC_MEM_OCCUPY(cproc_mem_stat)   ((cproc_mem_stat)->mem_occupy)
#define CPROC_MEM_LOAD(cproc_mem_stat)     ((cproc_mem_stat)->mem_load)

typedef struct
{
    UINT32 thread_num;
}CPROC_THREAD_STAT;
#define CPROC_THREAD_NUM(cproc_thread_stat) ((cproc_thread_stat)->thread_num)

typedef struct
{
    UINT32 max_thread_num;
    UINT32 busy_thread_num;
    UINT32 post_thread_num;
    UINT32 idle_thread_num;
}CRANK_THREAD_STAT;
#define CRANK_THREAD_MAX_NUM(crank_thread_stat)      ((crank_thread_stat)->max_thread_num)
#define CRANK_THREAD_BUSY_NUM(crank_thread_stat)     ((crank_thread_stat)->busy_thread_num)
#define CRANK_THREAD_POST_NUM(crank_thread_stat)     ((crank_thread_stat)->post_thread_num)
#define CRANK_THREAD_IDLE_NUM(crank_thread_stat)     ((crank_thread_stat)->idle_thread_num)

typedef struct
{
    REAL        cpu_load;
}CPROC_CPU_STAT;
#define CPROC_CPU_LOAD(cproc_cpu_stat)   ((cproc_cpu_stat)->cpu_load)

typedef struct
{
    UINT32 module_type;
    UINT32 module_num;
}CPROC_MODULE_STAT;
#define CPROC_MODULE_TYPE(cproc_module_stat)     ((cproc_module_stat)->module_type)
#define CPROC_MODULE_NUM(cproc_module_stat)      ((cproc_module_stat)->module_num)

typedef CVECTOR CPROC_MODULE_STAT_VEC;/*data item type is CPROC_MODULE_STAT*/
#define CPROC_MODULE_VEC_INFO(cproc_module_stat_vec)       (cproc_module_stat_vec)

typedef struct
{
    CSTRING eth_name;
    UINT32  eth_speed; /*Mb/s*/
    UINT32  eth_rxmoct;/*in KBytes*/
    UINT32  eth_txmoct;/*in KBytes*/
    UINT32  eth_rxflow;/*in KBytes*/
    UINT32  eth_txflow;/*in KBytes*/
}CSYS_ETH_STAT;

#define CSYS_ETH_NAME(csys_eth_stat)               (&((csys_eth_stat)->eth_name))
#define CSYS_ETH_SPEEDMBS(csys_eth_stat)           ((csys_eth_stat)->eth_speed)
#define CSYS_ETH_RXMOCT(csys_eth_stat)             ((csys_eth_stat)->eth_rxmoct)
#define CSYS_ETH_TXMOCT(csys_eth_stat)             ((csys_eth_stat)->eth_txmoct)
#define CSYS_ETH_RXTHROUGHPUT(csys_eth_stat)       ((csys_eth_stat)->eth_rxflow)
#define CSYS_ETH_TXTHROUGHPUT(csys_eth_stat)       ((csys_eth_stat)->eth_txflow)

typedef CVECTOR CSYS_ETH_VEC;/*data item type is CSYS_ETH_STAT*/
#define CSYS_ETH_VEC_INFO(csys_eth_stat_vec)       (csys_eth_stat_vec)

typedef struct
{
    CSTRING dsk_name;/*Filesystem*/
    UINT32  dsk_size;/*in MB*/
    UINT32  dsk_used;/*in MB*/
    UINT32  dsk_aval;/*in MB*/
    REAL    dsk_load;/*percent(%)*/
}CSYS_DSK_STAT;

#define CSYS_DSK_NAME(csys_dsk_stat)      (&((csys_dsk_stat)->dsk_name))
#define CSYS_DSK_SIZE(csys_dsk_stat)      ((csys_dsk_stat)->dsk_size)
#define CSYS_DSK_USED(csys_dsk_stat)      ((csys_dsk_stat)->dsk_used)
#define CSYS_DSK_AVAL(csys_dsk_stat)      ((csys_dsk_stat)->dsk_aval)
#define CSYS_DSK_LOAD(csys_dsk_stat)      ((csys_dsk_stat)->dsk_load)

typedef CVECTOR CSYS_DSK_VEC;/*data item type is CSYS_DSK_STAT*/
#define CSYS_DSK_VEC_INFO(csys_dsk_stat_vec)       (csys_dsk_stat_vec)

typedef CVECTOR CRANK_TASK_REPORT_VEC;/*data item type is TASK_REPORT_NODE*/
#define CRANK_TASK_VEC_INFO(crank_task_report_vec)       (crank_task_report_vec)

/*
[root@node129 test]# top -b -n 1 -p 2358
top - 21:28:35 up  2:43,  7 users,  load average: 0.00, 0.01, 0.00
Tasks:   1 total,   0 running,   1 sleeping,   0 stopped,   0 zombie
Cpu(s):  0.3% us,  1.4% sy,  0.0% ni, 97.3% id,  0.8% wa,  0.2% hi,  0.0% si
Mem:    808112k total,   564864k used,   243248k free,    96524k buffers
Swap:   524280k total,        0k used,   524280k free,   341696k cached

  PID USER      PR  NI  VIRT  RES  SHR S %CPU %MEM    TIME+  COMMAND
 2358 root      15   0     0    0    0 S  0.0  0.0   0:00.00 vmmemctl
*/
typedef struct
{
    UINT32    pid;
    UINT8  *  usr;
    UINT32    pr;
    UINT32    ni;
    UINT32    virt;
    UINT32    res;
    UINT32    shr;
    UINT8  *  status;
    REAL      cpu_load;
    REAL      mem_load;
}CTOP_OLINE; /*top command output line*/


#endif /*_CSYS_INC*/

#ifdef __cplusplus
}
#endif/*__cplusplus*/

