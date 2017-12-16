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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>

#include <sys/sysinfo.h>
#include <sys/resource.h>

#include "type.h"
#include "mm.h"

#include "cstring.h"
#include "cset.h"
#include "cvector.h"

#include "csys.h"

#include "cmisc.h"
#include "real.h"
#include "cbc.h"
#include "cmpic.inc"

#include "task.inc"
#include "task.h"

#include "log.h"

#if 0
SYNOPSIS
#include <sys/sysinfo.h>

int sysinfo(struct sysinfo *info);
DESCRIPTION
Until Linux 2.3.16, sysinfo used to return information in the following structure:

    struct sysinfo {
            long uptime;             /* Seconds since boot */
            unsigned long loads[3];  /* 1, 5, and 15 minute load averages */
            unsigned long totalram;  /* Total usable main memory size */
            unsigned long freeram;   /* Available memory size */
            unsigned long sharedram; /* Amount of shared memory */
            unsigned long bufferram; /* Memory used by buffers */
            unsigned long totalswap; /* Total swap space size */
            unsigned long freeswap;  /* swap space still available */
            unsigned short procs;    /* Number of current processes */
            char _f[22];             /* Pads structure to 64 bytes */
    };

and the sizes were given in bytes. Since Linux 2.3.23 (i386), 2.3.48 (all architectures) the structure is

    struct sysinfo {
            long uptime;             /* Seconds since boot */
            unsigned long loads[3];  /* 1, 5, and 15 minute load averages */
            unsigned long totalram;  /* Total usable main memory size */
            unsigned long freeram;   /* Available memory size */
            unsigned long sharedram; /* Amount of shared memory */
            unsigned long bufferram; /* Memory used by buffers */
            unsigned long totalswap; /* Total swap space size */
            unsigned long freeswap;  /* swap space still available */
            unsigned short procs;    /* Number of current processes */
            unsigned long totalhigh; /* Total high memory size */
            unsigned long freehigh;  /* Available high memory size */
            unsigned int mem_unit;   /* Memory unit size in bytes */
            char _f[20-2*sizeof(long)-sizeof(int)]; /* Padding for libc5 */
    };

and the sizes are given as multiples of mem_unit bytes.

sysinfo provides a simple way of getting overall system statistics. This is more portable than reading /dev/kmem. For an example of its use, see intro(2).
RETURN VALUE
On success, zero is returned. On error, -1 is returned, and errno is set appropriately.
ERRORS

EFAULT
    pointer to struct sysinfo is invalid


CONFORMING TO
This function is Linux-specific, and should not be used in programs intended to be portable.

The Linux kernel has a sysinfo system call since 0.98.pl6. Linux libc contains a sysinfo() routine since 5.3.5, and glibc has one since 1.90.
SEE ALSO
proc(5)
#endif

#if 0
#include <sys/resource>
int getrusage(int who, struct rusage *r_usage);

利用getrusage可以得到进程的相关资源信息。如：用户开销时间，系统开销时间，接收的信号量等等;

下面是rusage的结构：
struct rusage {
  struct timeval ru_utime; /* user time used */
  struct timeval ru_stime; /* system time used */
  long ru_maxrss;
  #define ru_first ru_ixrss
  long ru_ixrss; /* XXX: 0 */
  long ru_idrss; /* XXX: sum of rm_asrss */
  long ru_isrss; /* XXX: 0 */
  long ru_minflt; /* any page faults not requiring I/O */
  long ru_majflt; /* any page faults requiring I/O */
  long ru_nswap; /* swaps */
  long ru_inblock; /* block input operations */
  long ru_oublock; /* block output operations */
  long ru_msgsnd; /* messages sent */
  long ru_msgrcv; /* messages received */
  long ru_nsignals; /* signals received */
  long ru_nvcsw; /* voluntary context switches */
  long ru_nivcsw; /* involuntary " */
  #define ru_last ru_nivcsw
};

不行，struct rusage中内存的使用条目如下
long int ru_maxrss
The maximum resident set size used, in kilobytes. That is, the maximum number of kilobytes of physical memory that processes used simultaneously
这是RSS所占的内存
long int ru_ixrss
An intergral value expressed in kilobytes times ticks of execution, which indicates the amount of memory used by text that was shared with other processes
这是text（代码段）部分所占的内存，如果程序有几个实例在运行的话，这部分一般是共享的
long int ru_idrss
An integral value expressed the same way, which is the amount of unshared memory used for data
这是数据段所占的内存
long int ru_isrss
An integral value expressed the same way, which is the amount of unshared memory used for stack space
这是栈所用的内存大小

进程在内存中除了进程数据结构之外，有RSS，代码段，数据段，栈等部分，应该加起来考虑吧；这是主要的部分；
#endif

//#define CSYS_DBG(x) sys_log x
#define CSYS_DBG(x) do{}while(0)
#define CSYS_INFO(x) sys_log x

UINT32 csys_info_print()
{
    struct sysinfo info;

    if(0 != sysinfo(&info))
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_info_print: failed to fetch sysinfo\n");
        return ((UINT32)-1);
    }

    #define _S2M_(nsecs)   ((nsecs) / 60)
    #define _S2H_(nsecs)   ((nsecs) / (60*60))

    #define _LDR_(load)    ((REAL)load / ((REAL) (1 << SI_LOAD_SHIFT)))

    #define _B2KB_(nbytes) ((nbytes) >> 10)
    #define _B2MB_(nbytes) ((nbytes) >> 20)
    #define _B2GB_(nbytes) ((nbytes) >> 30)

    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "uptime   : %ld secs or %ld mins or %ld hours since boot\n", info.uptime, _S2M_(info.uptime), _S2H_(info.uptime));
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "loads    : %ld(%.2f), %ld(%.2f), %ld(%.2f)\n",
                                   info.loads[0], _LDR_(info.loads[0]),
                                   info.loads[1], _LDR_(info.loads[1]),
                                   info.loads[2], _LDR_(info.loads[2])
                                   );
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:totalram : %ld Bytes, %ld KB, %ld MB\n", info.totalram , _B2KB_(info.totalram) , _B2MB_(info.totalram));
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:freeram  : %ld Bytes, %ld KB, %ld MB\n", info.freeram  , _B2KB_(info.freeram)  , _B2MB_(info.freeram));
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:sharedram: %ld Bytes, %ld KB, %ld MB\n", info.sharedram, _B2KB_(info.sharedram), _B2MB_(info.sharedram));
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:bufferram: %ld Bytes, %ld KB, %ld MB\n", info.bufferram, _B2KB_(info.bufferram), _B2MB_(info.bufferram));
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:totalswap: %ld Bytes, %ld KB, %ld MB\n", info.totalswap, _B2KB_(info.totalswap), _B2MB_(info.totalswap));
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:freeswap : %ld Bytes, %ld KB, %ld MB\n", info.freeswap , _B2KB_(info.freeswap) , _B2MB_(info.freeswap));
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:procs    : %ld\n", info.procs);
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:totalhigh: %ld\n", info.totalhigh);
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:freehigh : %ld\n", info.freehigh);
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_info_print:mem_unit : %ld\n", info.mem_unit);

    #undef _S2M_
    #undef _S2H_

    #undef _B2KB_
    #undef _B2MB_
    #undef _B2GB_

    return (0);
}

CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec_new()
{
    CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec;

    alloc_static_mem(MM_CVECTOR, &csys_cpu_cfg_vec, LOC_CSYS_0001);
    csys_cpu_cfg_vec_init(csys_cpu_cfg_vec);

    return (csys_cpu_cfg_vec);
}

UINT32 csys_cpu_cfg_vec_init(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec)
{
    cvector_init(csys_cpu_cfg_vec, 0, MM_CSTRING, CVECTOR_LOCK_ENABLE, LOC_CSYS_0002);
    return (0);
}

UINT32 csys_cpu_cfg_vec_clean(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec)
{
    cvector_clean(csys_cpu_cfg_vec, (CVECTOR_DATA_CLEANER)cstring_free, LOC_CSYS_0003);
    return (0);
}

UINT32 csys_cpu_cfg_vec_free(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec)
{
    csys_cpu_cfg_vec_clean(csys_cpu_cfg_vec);
    free_static_mem(MM_CVECTOR, csys_cpu_cfg_vec, LOC_CSYS_0004);
    return (0);
}

void csys_cpu_cfg_vec_print(LOG *log, const CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec)
{
    cvector_print(log, csys_cpu_cfg_vec, (CVECTOR_DATA_PRINT)cstring_print);
    return;
}

UINT32 csys_cpu_cfg_vec_get(CSYS_CPU_CFG_VEC *csys_cpu_cfg_vec)
{
    char *cache;
    char *buff;
    char *next;

    CSTRING *cstring;

    cache = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0005);
    if(NULL_PTR == cache)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_cpu_cfg_vec_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    exec_shell("cat /proc/cpuinfo", cache, CSYS_SHELL_BUF_MAX_SIZE);

    cstring = NULL_PTR;
    next = cache;

    for(buff = next; NULL_PTR != (buff = c_str_fetch_line(buff)); buff = next)
    {
        next = c_str_move_next(buff);

        //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] csys_cpu_cfg_vec_get: buff: [%s]\n", buff);

        if ('\0' == buff[0])/*blank line*/
        {
            cvector_push(CSYS_CPU_CFG_VEC_INFO(csys_cpu_cfg_vec), (void *)cstring);
            cstring = NULL_PTR;
            continue;
        }

        if(NULL_PTR == cstring)
        {
            cstring = cstring_new((UINT8 *)buff, LOC_CSYS_0006);
        }
        else
        {
            cstring_append_char(cstring, (UINT8)'\n');
            cstring_append_str(cstring, (UINT8 *)buff);
        }
    }

    SAFE_FREE(cache, LOC_CSYS_0007);

    return (0);
}

CSYS_CPU_STAT *csys_cpu_stat_new()
{
    CSYS_CPU_STAT *csys_cpu_stat;

    alloc_static_mem(MM_CSYS_CPU_STAT, &csys_cpu_stat, LOC_CSYS_0008);

    csys_cpu_stat_init(csys_cpu_stat);
    return (csys_cpu_stat);
}

UINT32 csys_cpu_stat_init(CSYS_CPU_STAT *csys_cpu_stat)
{
    cstring_init(CSYS_CPU_STAT_CSTR(csys_cpu_stat), NULL_PTR);
    CSYS_CPU_STAT_USER(csys_cpu_stat) = 0;
    CSYS_CPU_STAT_NICE(csys_cpu_stat) = 0;
    CSYS_CPU_STAT_SYS(csys_cpu_stat)  = 0;
    CSYS_CPU_STAT_IDLE(csys_cpu_stat) = 0;
    CSYS_CPU_STAT_TOTAL(csys_cpu_stat)= 0;
    CSYS_CPU_STAT_LOAD(csys_cpu_stat) = 0.0;

    return (0);
}

UINT32 csys_cpu_stat_clean(CSYS_CPU_STAT *csys_cpu_stat)
{
    cstring_clean(CSYS_CPU_STAT_CSTR(csys_cpu_stat));
    CSYS_CPU_STAT_USER(csys_cpu_stat) = 0;
    CSYS_CPU_STAT_NICE(csys_cpu_stat) = 0;
    CSYS_CPU_STAT_SYS(csys_cpu_stat)  = 0;
    CSYS_CPU_STAT_IDLE(csys_cpu_stat) = 0;
    CSYS_CPU_STAT_TOTAL(csys_cpu_stat)= 0;
    CSYS_CPU_STAT_LOAD(csys_cpu_stat) = 0.0;

    return (0);
}

UINT32 csys_cpu_stat_free(CSYS_CPU_STAT *csys_cpu_stat)
{
    if(NULL_PTR == csys_cpu_stat)
    {
        return (0);
    }

    csys_cpu_stat_clean(csys_cpu_stat);

    free_static_mem(MM_CSYS_CPU_STAT, csys_cpu_stat, LOC_CSYS_0009);

    return (0);
}

UINT32 csys_cpu_stat_clone(CSYS_CPU_STAT *csys_cpu_stat_src, CSYS_CPU_STAT *csys_cpu_stat_des)
{
    cstring_clone(CSYS_CPU_STAT_CSTR(csys_cpu_stat_src), CSYS_CPU_STAT_CSTR(csys_cpu_stat_des));
    CSYS_CPU_STAT_USER(csys_cpu_stat_des) = CSYS_CPU_STAT_USER(csys_cpu_stat_src);
    CSYS_CPU_STAT_NICE(csys_cpu_stat_des) = CSYS_CPU_STAT_NICE(csys_cpu_stat_src);
    CSYS_CPU_STAT_SYS(csys_cpu_stat_des)  = CSYS_CPU_STAT_SYS(csys_cpu_stat_src);
    CSYS_CPU_STAT_IDLE(csys_cpu_stat_des) = CSYS_CPU_STAT_IDLE(csys_cpu_stat_src);
    CSYS_CPU_STAT_TOTAL(csys_cpu_stat_des)= CSYS_CPU_STAT_TOTAL(csys_cpu_stat_src);
    CSYS_CPU_STAT_LOAD(csys_cpu_stat_des) = CSYS_CPU_STAT_LOAD(csys_cpu_stat_src);

    return (0);
}

void csys_cpu_stat_print(LOG *log, const CSYS_CPU_STAT *csys_cpu_stat)
{
    sys_log(log, "cpu stat: name  = %s\n", (char *)cstring_get_str(CSYS_CPU_STAT_CSTR(csys_cpu_stat)));
    sys_log(log, "cpu stat: user  = %ld\n", CSYS_CPU_STAT_USER(csys_cpu_stat));
    sys_log(log, "cpu stat: nice  = %ld\n", CSYS_CPU_STAT_NICE(csys_cpu_stat));
    sys_log(log, "cpu stat: sys   = %ld\n", CSYS_CPU_STAT_SYS(csys_cpu_stat));
    sys_log(log, "cpu stat: idle  = %ld\n", CSYS_CPU_STAT_IDLE(csys_cpu_stat));
    sys_log(log, "cpu stat: total = %ld\n", CSYS_CPU_STAT_TOTAL(csys_cpu_stat));
    sys_log(log, "cpu stat: load  = %.2f\n", CSYS_CPU_STAT_LOAD(csys_cpu_stat));
    return;
}

UINT32 csys_cpu_stat_get(const char *buff, CSYS_CPU_STAT *csys_cpu_stat)
{
    char  *safe_ptr;
    char  *seg_ptr;

/*
#    user    sys   nice    idle       iowait irq  softirq
cpu  2769276 25300 1289765 1135539778 868321 0    54609    47504
cpu0 664717  10559 336856  283310413  792970 0    15245    17876
cpu1 565598  3997  257912  284279705  20498  0    13471    7454
cpu2 763112  5355  447672  283895488  21134  0    8451     7424
cpu3 775847  5388  247323  284054170  33718  0    17440    14749
*/

    safe_ptr = (char *)buff;
    //dbg_log(SEC_0077_CSYS, 3)(LOGSTDOUT, "info:csys_cpu_stat_get: %s\n", buff);
    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        cstring_init(CSYS_CPU_STAT_CSTR(csys_cpu_stat), (UINT8 *)seg_ptr);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_STAT_USER(csys_cpu_stat) = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "%s ===> %ld\n", seg_ptr, CSYS_CPU_STAT_USER(csys_cpu_stat));
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_STAT_NICE(csys_cpu_stat) = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "%s ===> %ld\n", seg_ptr, CSYS_CPU_STAT_NICE(csys_cpu_stat));
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_STAT_SYS(csys_cpu_stat) = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "%s ===> %ld\n", seg_ptr, CSYS_CPU_STAT_SYS(csys_cpu_stat));
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_STAT_IDLE(csys_cpu_stat) = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "%s ===> %ld\n", seg_ptr, CSYS_CPU_STAT_IDLE(csys_cpu_stat));
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_STAT_TOTAL(csys_cpu_stat) = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "%s ===> %ld\n", seg_ptr, CSYS_CPU_STAT_TOTAL(csys_cpu_stat));
    }

    return (0);
}


CSYS_CPU_STAT_VEC *csys_cpu_stat_vec_new()
{
    CSYS_CPU_STAT_VEC *csys_cpu_stat_vec;

    alloc_static_mem(MM_CVECTOR, &csys_cpu_stat_vec, LOC_CSYS_0010);
    csys_cpu_stat_vec_init(csys_cpu_stat_vec);

    return (csys_cpu_stat_vec);
}

UINT32 csys_cpu_stat_vec_init(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec)
{
    cvector_init(csys_cpu_stat_vec, 0, MM_CSYS_CPU_STAT, CVECTOR_LOCK_ENABLE, LOC_CSYS_0011);
    return (0);
}

UINT32 csys_cpu_stat_vec_clean(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec)
{
    cvector_clean(csys_cpu_stat_vec, (CVECTOR_DATA_CLEANER)csys_cpu_stat_free, LOC_CSYS_0012);
    return (0);
}

UINT32 csys_cpu_stat_vec_free(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec)
{
    csys_cpu_stat_vec_clean(csys_cpu_stat_vec);
    free_static_mem(MM_CVECTOR, csys_cpu_stat_vec, LOC_CSYS_0013);
    return (0);
}

UINT32 csys_cpu_stat_vec_size(const CSYS_CPU_STAT_VEC *csys_cpu_stat_vec)
{
    return cvector_size(csys_cpu_stat_vec);
}

CSYS_CPU_STAT * csys_cpu_stat_vec_fetch(const CSYS_CPU_STAT_VEC *csys_cpu_stat_vec, const UINT32 csys_cpu_stat_pos)
{
    return (CSYS_CPU_STAT *)cvector_get(csys_cpu_stat_vec, csys_cpu_stat_pos);
}

void csys_cpu_stat_vec_print(LOG *log, const CSYS_CPU_STAT_VEC *csys_cpu_stat_vec)
{
    cvector_print(log, csys_cpu_stat_vec, (CVECTOR_DATA_PRINT)csys_cpu_stat_print);
    return;
}

UINT32 csys_cpu_stat_vec_get(CSYS_CPU_STAT_VEC *csys_cpu_stat_vec)
{
    char  *cache;
    char  *buff;
    char  *next;

    cache = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0014);
    if(NULL_PTR == cache)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_cpu_stat_vec_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    exec_shell("cat /proc/stat | grep '^cpu'", cache, CSYS_SHELL_BUF_MAX_SIZE);
    //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] cache: \n%s\n", cache);

    /*note:skip the cpu average load info which locate the 1st line in /proc/stat*/
    buff = c_str_fetch_line(cache);
    next = c_str_move_next(buff);

    for(buff = next; NULL_PTR != (buff = c_str_fetch_line(buff)); buff = next)
    {
        CSYS_CPU_STAT *csys_cpu_stat;

        next = c_str_move_next(buff);

        //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] CPU: \n%s\n", buff);

        if (0 != strncasecmp(buff, "cpu", 3))
        {
            break;
        }

        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_cpu_stat_vec_get: %s\n", (char *)buff);

        csys_cpu_stat = csys_cpu_stat_new();
        csys_cpu_stat_get(buff, csys_cpu_stat);/*here buff will be modified*/
        cvector_push(csys_cpu_stat_vec, (void *)csys_cpu_stat);
    }

    SAFE_FREE(cache, CSYS_SHELL_BUF_MAX_SIZE);
    return (0);
}

CSYS_CPU_AVG_STAT *csys_cpu_avg_stat_new()
{
    CSYS_CPU_AVG_STAT *csys_cpu_avg_stat;

    alloc_static_mem(MM_CSYS_CPU_AVG_STAT, &csys_cpu_avg_stat, LOC_CSYS_0015);

    csys_cpu_avg_stat_init(csys_cpu_avg_stat);
    return (csys_cpu_avg_stat);
}

UINT32 csys_cpu_avg_stat_init(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat)
{
    CSYS_CPU_AVG_STAT_01_MIN(csys_cpu_avg_stat) = 0.0;
    CSYS_CPU_AVG_STAT_05_MIN(csys_cpu_avg_stat) = 0.0;
    CSYS_CPU_AVG_STAT_15_MIN(csys_cpu_avg_stat) = 0.0;

    return (0);
}

UINT32 csys_cpu_avg_stat_clean(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat)
{
    CSYS_CPU_AVG_STAT_01_MIN(csys_cpu_avg_stat) = 0.0;
    CSYS_CPU_AVG_STAT_05_MIN(csys_cpu_avg_stat) = 0.0;
    CSYS_CPU_AVG_STAT_15_MIN(csys_cpu_avg_stat) = 0.0;

    return (0);
}

UINT32 csys_cpu_avg_stat_free(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat)
{
    csys_cpu_avg_stat_clean(csys_cpu_avg_stat);

    free_static_mem(MM_CSYS_CPU_AVG_STAT, csys_cpu_avg_stat, LOC_CSYS_0016);

    return (0);
}

void csys_cpu_avg_stat_print(LOG *log, const CSYS_CPU_AVG_STAT *csys_cpu_avg_stat)
{
    sys_log(log, "cpu avg stat: avg. of  1 min  = %.2f\n", CSYS_CPU_AVG_STAT_01_MIN(csys_cpu_avg_stat));
    sys_log(log, "cpu avg stat: avg. of  5 min  = %.2f\n", CSYS_CPU_AVG_STAT_05_MIN(csys_cpu_avg_stat));
    sys_log(log, "cpu avg stat: avg. of 15 min  = %.2f\n", CSYS_CPU_AVG_STAT_15_MIN(csys_cpu_avg_stat));

    return;
}

UINT32 csys_cpu_avg_stat_get(CSYS_CPU_AVG_STAT *csys_cpu_avg_stat)
{
    char  *buff;

    char  *safe_ptr;
    char  *seg_ptr;

    buff = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0017);
    if(NULL_PTR == buff)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_cpu_avg_stat_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

/*
#    1min    5min   15min
    0.01     0.00   0.00 1/65 6189
*/

    exec_shell("cat /proc/loadavg", buff, CSYS_SHELL_BUF_MAX_SIZE);
    //dbg_log(SEC_0077_CSYS, 9)(LOGSTDNULL, "[DEBUG]csys_cpu_avg_stat_get: \n%s\n", buff);

    safe_ptr = (char *)buff;
    //dbg_log(SEC_0077_CSYS, 3)(LOGSTDOUT, "info:csys_cpu_avg_stat_get: %s\n", buff);
    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_AVG_STAT_01_MIN(csys_cpu_avg_stat) = strtod(seg_ptr, (char **)0);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_cpu_avg_stat_get: avg of 01 min: %s => %.2f\n", seg_ptr, CSYS_CPU_AVG_STAT_01_MIN(csys_cpu_avg_stat));
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_AVG_STAT_05_MIN(csys_cpu_avg_stat) = strtod(seg_ptr, (char **)0);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_cpu_avg_stat_get: avg of 05 min: %s => %.2f\n", seg_ptr, CSYS_CPU_AVG_STAT_05_MIN(csys_cpu_avg_stat));
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        CSYS_CPU_AVG_STAT_15_MIN(csys_cpu_avg_stat) = strtod(seg_ptr, (char **)0);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_cpu_avg_stat_get: avg of 15 min: %s => %.2f\n", seg_ptr, CSYS_CPU_AVG_STAT_15_MIN(csys_cpu_avg_stat));
    }

    SAFE_FREE(buff, LOC_CSYS_0018);
    return (0);
}


CSYS_MEM_STAT *csys_mem_stat_new()
{
    CSYS_MEM_STAT *csys_mem_stat;

    alloc_static_mem(MM_CSYS_MEM_STAT, &csys_mem_stat, LOC_CSYS_0019);
    csys_mem_stat_init(csys_mem_stat);

    return (csys_mem_stat);
}

UINT32 csys_mem_stat_init(CSYS_MEM_STAT *csys_mem_stat)
{
    CSYS_MEM_TOTAL(csys_mem_stat) = 0;
    CSYS_MEM_FREE(csys_mem_stat)  = 0;
    return (0);
}

UINT32 csys_mem_stat_clean(CSYS_MEM_STAT *csys_mem_stat)
{
    CSYS_MEM_TOTAL(csys_mem_stat) = 0;
    CSYS_MEM_FREE(csys_mem_stat)  = 0;
    return (0);
}

UINT32 csys_mem_stat_free(CSYS_MEM_STAT *csys_mem_stat)
{
    csys_mem_stat_clean(csys_mem_stat);
    free_static_mem(MM_CSYS_MEM_STAT, csys_mem_stat, LOC_CSYS_0020);
    return (0);
}

void csys_mem_stat_print(LOG *log, const CSYS_MEM_STAT *csys_mem_stat)
{
    sys_log(log, "sys mem stat: total = %ld\n", CSYS_MEM_TOTAL(csys_mem_stat));
    sys_log(log, "sys mem stat: free  = %ld\n", CSYS_MEM_FREE(csys_mem_stat));
    return;
}

UINT32 csys_mem_stat_get(CSYS_MEM_STAT *csys_mem_stat)
{
    char  *cache;
    char  *buff;
    char  *next;

    cache = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0021);
    if(NULL_PTR == cache)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_mem_stat_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    exec_shell("cat /proc/meminfo", cache, CSYS_SHELL_BUF_MAX_SIZE);
    //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] csys_mem_stat_get: cache is \n %s\n", cache);

    next = cache;

    for(buff = next; NULL_PTR != (buff = c_str_fetch_line(buff)); buff = next)
    {
        char  *safe_ptr;
        char  *seg_ptr[ 3 ];
        UINT32 seg_pos;
        UINT32 seg_num;

        next = c_str_move_next(buff);

        //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] csys_mem_stat_get: buff is \n%s\n", buff);

        seg_num = sizeof(seg_ptr)/sizeof(seg_ptr[0]);

        safe_ptr = (char *)buff;
        for(seg_pos  = 0; seg_pos < seg_num; seg_pos ++)
        {
            seg_ptr[ seg_pos ] = strtok_r(NULL_PTR, ": ", &safe_ptr);
            if((char *)0 == seg_ptr[ seg_pos ])
            {
                break;
            }
        }

        if(2 < seg_pos && 0 == strcasecmp(seg_ptr[0], "MemTotal"))
        {
            CSYS_MEM_TOTAL(csys_mem_stat) = c_str_to_word(seg_ptr[1]);/*unit: KB*/
            //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_mem_load_get: MemTotal: %s => %ld\n", seg_ptr[1], CSYS_MEM_TOTAL(csys_mem_stat));
            continue;
        }

        if(2 < seg_pos && 0 == strcasecmp(seg_ptr[0], "MemFree"))
        {
            CSYS_MEM_FREE(csys_mem_stat) = c_str_to_word(seg_ptr[1]);/*unit: KB*/
            //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "csys_mem_load_get: MemFree: %s => %ld\n", seg_ptr[1], CSYS_MEM_FREE(csys_mem_stat));
            continue;
        }
    }

    SAFE_FREE(cache, CSYS_SHELL_BUF_MAX_SIZE);
    return (0);
}

CPROC_MEM_STAT *cproc_mem_stat_new()
{
    CPROC_MEM_STAT *cproc_mem_stat;

    alloc_static_mem(MM_CPROC_MEM_STAT, &cproc_mem_stat, LOC_CSYS_0022);
    cproc_mem_stat_init(cproc_mem_stat);

    return (cproc_mem_stat);
}

UINT32 cproc_mem_stat_init(CPROC_MEM_STAT *cproc_mem_stat)
{
    CPROC_MEM_OCCUPY(cproc_mem_stat) = 0;
    CPROC_MEM_LOAD(cproc_mem_stat) = 0.0;
    return (0);
}

UINT32 cproc_mem_stat_clean(CPROC_MEM_STAT *cproc_mem_stat)
{
    CPROC_MEM_OCCUPY(cproc_mem_stat) = 0;
    CPROC_MEM_LOAD(cproc_mem_stat) = 0.0;
    return (0);
}

UINT32 cproc_mem_stat_free(CPROC_MEM_STAT *cproc_mem_stat)
{
    cproc_mem_stat_clean(cproc_mem_stat);
    free_static_mem(MM_CPROC_MEM_STAT, cproc_mem_stat, LOC_CSYS_0023);
    return (0);
}

void cproc_mem_stat_print(LOG *log, const CPROC_MEM_STAT *cproc_mem_stat)
{
    sys_log(log, "proc mem stat: occupy  = %ld, load = %.1f\n", CPROC_MEM_OCCUPY(cproc_mem_stat), CPROC_MEM_LOAD(cproc_mem_stat));
    return;
}

UINT32 cproc_mem_stat_get(CPROC_MEM_STAT *cproc_mem_stat)
{
    /*due to getrusage return almost all fields with zero value, */
    /*and ioctl not support PIOCPSINFO for prpsinfo_t fetching, (PIOCPSINFO not provided by CentOS) */
    /*and ioctl not suppport PIOCSTATU for Sprstatus_t fetching,(PIOCSTATU not provided by CentOS)  */
    /*and thread_info structer not found in kernal headers,*/
    /*we conclude that CentOS limit some important functions in kernel access, so that we use the most*/
    /*popular command 'top' to fetch specific process memory usage info*/

    CTOP_OLINE ctop_oline;

    ctop_process_stat(getpid(), &ctop_oline);

    CPROC_MEM_OCCUPY(cproc_mem_stat) = ctop_oline.virt + ctop_oline.res + ctop_oline.shr;
    CPROC_MEM_LOAD(cproc_mem_stat)   = ctop_oline.mem_load;
    CSYS_DBG((LOGSTDOUT, "cproc_mem_stat_get: occupy: %ld + %ld + %ld => %ld\n", ctop_oline.virt, ctop_oline.res, ctop_oline.shr, CPROC_MEM_OCCUPY(cproc_mem_stat)));
    CSYS_DBG((LOGSTDOUT, "cproc_mem_stat_get: load: %.1f => %.1f\n", ctop_oline.mem_load, CPROC_MEM_LOAD(cproc_mem_stat)));

    return (0);
}

CPROC_CPU_STAT *cproc_cpu_stat_new()
{
    CPROC_CPU_STAT *cproc_cpu_stat;

    alloc_static_mem(MM_CPROC_CPU_STAT, &cproc_cpu_stat, LOC_CSYS_0024);
    cproc_cpu_stat_init(cproc_cpu_stat);

    return (cproc_cpu_stat);
}

UINT32 cproc_cpu_stat_init(CPROC_CPU_STAT *cproc_cpu_stat)
{
    CPROC_CPU_LOAD(cproc_cpu_stat) = 0.0;
    return (0);
}

UINT32 cproc_cpu_stat_clean(CPROC_CPU_STAT *cproc_cpu_stat)
{
    CPROC_CPU_LOAD(cproc_cpu_stat) = 0.0;
    return (0);
}

UINT32 cproc_cpu_stat_free(CPROC_CPU_STAT *cproc_cpu_stat)
{
    cproc_cpu_stat_clean(cproc_cpu_stat);
    free_static_mem(MM_CPROC_CPU_STAT, cproc_cpu_stat, LOC_CSYS_0025);
    return (0);
}

void cproc_cpu_stat_print(LOG *log, const CPROC_CPU_STAT *cproc_cpu_stat)
{
    sys_log(log, "proc cpu stat: load = %.1f\n", CPROC_CPU_LOAD(cproc_cpu_stat));
    return;
}

UINT32 cproc_cpu_stat_get(CPROC_CPU_STAT *cproc_cpu_stat)
{
    /*due to getrusage return almost all fields with zero value, */
    /*and ioctl not support PIOCPSINFO for prpsinfo_t fetching, (PIOCPSINFO not provided by CentOS) */
    /*and ioctl not suppport PIOCSTATU for Sprstatus_t fetching,(PIOCSTATU not provided by CentOS)  */
    /*and thread_info structer not found in kernal headers,*/
    /*we conclude that CentOS limit some important functions in kernel access, so that we use the most*/
    /*popular command 'top' to fetch specific process cpuory usage info*/

    CTOP_OLINE ctop_oline;

    ctop_process_stat(getpid(), &ctop_oline);

    CPROC_CPU_LOAD(cproc_cpu_stat) = ctop_oline.cpu_load;

    return (0);
}

static UINT32 ctop_mem_str_to_uint32(char *mem_str)
{
    char *last_pch;

    last_pch = mem_str + strlen(mem_str) - 1;
    if('m' == (*last_pch) || 'M' == (*last_pch))
    {
        (*last_pch) = '\0';
        return lrint(strtod(mem_str, (char **)0) * 1024);/*MBytes -> KBytes*/
    }

    return lrint(strtod(mem_str, (char **)0));
}

static UINT32 ctop_oline_parse(char *oline_buff, CTOP_OLINE *ctop_oline)
{
    char  *safe_ptr;
    char  *seg_ptr;

/**
example:
========
  PID USER      PR  NI  VIRT  RES  SHR S %CPU %MEM    TIME+  COMMAND
 3704 gdm       15   0 22764  11m 6412 S  0.3  1.4   0:14.34 gdmgreeter
**/
    //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: %s\n", oline_buff);
    safe_ptr = oline_buff;
    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->pid = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: pid: %s => %ld\n", seg_ptr, ctop_oline->pid);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->usr = (UINT8 *)seg_ptr;
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: usr: %s => %s\n", seg_ptr, ctop_oline->usr);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->pr = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: pr : %s => %ld\n", seg_ptr, ctop_oline->pr);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->ni = c_str_to_word(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: ni : %s => %ld\n", seg_ptr, ctop_oline->ni);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->virt = ctop_mem_str_to_uint32(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: virt : %s => %ld\n", seg_ptr, ctop_oline->virt);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->res = ctop_mem_str_to_uint32(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: res : %s => %ld\n", seg_ptr, ctop_oline->res);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->shr = ctop_mem_str_to_uint32(seg_ptr);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: shr : %s => %ld\n", seg_ptr, ctop_oline->shr);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->status = (UINT8 *)seg_ptr;
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: status : %s => %s\n", seg_ptr, ctop_oline->status);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->cpu_load = strtod(seg_ptr, (char **)0);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: cpu_load : %s => %.1f\n", seg_ptr, ctop_oline->cpu_load);
    }

    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " ", &safe_ptr)))
    {
        ctop_oline->mem_load = strtod(seg_ptr, (char **)0);
        //dbg_log(SEC_0077_CSYS, 5)(LOGSTDOUT, "ctop_oline_parse: mem_load : %s => %.1f\n", seg_ptr, ctop_oline->mem_load);
    }
    return (0);
}

UINT32 ctop_process_stat(const UINT32 pid, CTOP_OLINE *ctop_oline)
{
    FILE   *rstream;
    char   *cmd_line;
    char   *cmd_output;
    EC_BOOL flag;

    cmd_line = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0026);
    if(NULL_PTR == cmd_line)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:ctop_process_stat: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    cmd_output = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0027);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:ctop_process_stat: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        SAFE_FREE(cmd_line, LOC_CSYS_0028);
        return ((UINT32)-1);
    }

    snprintf(cmd_line, CSYS_SHELL_BUF_MAX_SIZE, "top -b -n 1 -p %ld", pid);

    CSYS_DBG((LOGSTDOUT, "ctop_process_stat: execute shell command: %s\n", cmd_line));

    flag = EC_FALSE;
    rstream = popen((char *)cmd_line, "r");
    if(NULL_PTR == rstream)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:ctop_process_stat: popen %s failed\n", cmd_line);
        SAFE_FREE(cmd_line, LOC_CSYS_0029);
        SAFE_FREE(cmd_output, LOC_CSYS_0030);
        return ((UINT32)-1);
    }
    while(fgets(cmd_output, CSYS_SHELL_BUF_MAX_SIZE, rstream))
    {
        if(EC_TRUE == flag)
        {
            CSYS_DBG((LOGSTDOUT, "ctop_process_stat: %s\n", cmd_output));
            ctop_oline_parse(cmd_output, ctop_oline);
            break;
        }

        if((char *)0 != strstr(cmd_output, "COMMAND"))
        {
            CSYS_DBG((LOGSTDOUT, "ctop_process_stat: %s\n", cmd_output));
            flag = EC_TRUE;
        }
    }
    pclose( rstream );

    SAFE_FREE(cmd_line, LOC_CSYS_0031);
    SAFE_FREE(cmd_output, LOC_CSYS_0032);
    return (0);
}

CPROC_THREAD_STAT *cproc_thread_stat_new()
{
    CPROC_THREAD_STAT *cproc_thread_stat;

    alloc_static_mem(MM_CPROC_THREAD_STAT, &cproc_thread_stat, LOC_CSYS_0033);
    cproc_thread_stat_init(cproc_thread_stat);

    return (cproc_thread_stat);
}

UINT32 cproc_thread_stat_init(CPROC_THREAD_STAT *cproc_thread_stat)
{
    CPROC_THREAD_NUM(cproc_thread_stat) = 0;
    return (0);
}

UINT32 cproc_thread_stat_clean(CPROC_THREAD_STAT *cproc_thread_stat)
{
    CPROC_THREAD_NUM(cproc_thread_stat) = 0;
    return (0);
}

UINT32 cproc_thread_stat_free(CPROC_THREAD_STAT *cproc_thread_stat)
{
    cproc_thread_stat_clean(cproc_thread_stat);
    free_static_mem(MM_CPROC_THREAD_STAT, cproc_thread_stat, LOC_CSYS_0034);
    return (0);
}

void cproc_thread_stat_print(LOG *log, const CPROC_THREAD_STAT *cproc_thread_stat)
{
    sys_log(log, "proc thread stat: thread num = %ld\n", CPROC_THREAD_NUM(cproc_thread_stat));
    return;
}

UINT32 cproc_thread_stat_get(CPROC_THREAD_STAT *cproc_thread_stat)
{
    FILE  *rstream;
    char  *cmd_line;
    char  *cmd_output;

    char  *safe_ptr;
    char  *seg_ptr;

    cmd_line = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0035);
    if(NULL_PTR == cmd_line)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:cproc_thread_stat_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    cmd_output = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0036);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:cproc_thread_stat_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        SAFE_FREE(cmd_line, LOC_CSYS_0037);
        return ((UINT32)-1);
    }

    snprintf(cmd_line, CSYS_SHELL_BUF_MAX_SIZE, "cat /proc/%u/stat | awk '{print $20}'", getpid());

    CSYS_DBG((LOGSTDOUT, "cproc_thread_stat_get: execute shell command: %s\n", cmd_line));

    rstream = popen((char *)cmd_line, "r");
    if(NULL_PTR == rstream)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:cproc_thread_stat_get: popen %s failed\n", cmd_line);
        SAFE_FREE(cmd_line, LOC_CSYS_0038);
        SAFE_FREE(cmd_output, LOC_CSYS_0039);
        return ((UINT32)-1);
    }
    fgets(cmd_output, CSYS_SHELL_BUF_MAX_SIZE, rstream);

    safe_ptr = (char *)cmd_output;
    if((char *)0 != (seg_ptr = strtok_r(NULL_PTR, " \t\r\n", &safe_ptr)))
    {
        CPROC_THREAD_NUM(cproc_thread_stat) = c_str_to_word(seg_ptr);
    }

    CSYS_DBG((LOGSTDOUT, "cproc_thread_stat_get: %s ==> %ld\n", cmd_output, CPROC_THREAD_NUM(cproc_thread_stat)));

    pclose( rstream );

    SAFE_FREE(cmd_line, LOC_CSYS_0040);
    SAFE_FREE(cmd_output, LOC_CSYS_0041);
    return (0);
}

CPROC_MODULE_STAT *cproc_module_stat_new()
{
    CPROC_MODULE_STAT *cproc_module_stat;

    alloc_static_mem(MM_CPROC_MODULE_STAT, &cproc_module_stat, LOC_CSYS_0042);
    cproc_module_stat_init(cproc_module_stat);

    return (cproc_module_stat);
}

UINT32 cproc_module_stat_init(CPROC_MODULE_STAT *cproc_module_stat)
{
    CPROC_MODULE_TYPE(cproc_module_stat) = MD_END;
    CPROC_MODULE_NUM(cproc_module_stat) = 0;
    return (0);
}

UINT32 cproc_module_stat_clean(CPROC_MODULE_STAT *cproc_module_stat)
{
    CPROC_MODULE_TYPE(cproc_module_stat) = MD_END;
    CPROC_MODULE_NUM(cproc_module_stat) = 0;
    return (0);
}

UINT32 cproc_module_stat_free(CPROC_MODULE_STAT *cproc_module_stat)
{
    if(NULL_PTR != cproc_module_stat)
    {
        cproc_module_stat_clean(cproc_module_stat);
        free_static_mem(MM_CPROC_MODULE_STAT, cproc_module_stat, LOC_CSYS_0043);
    }
    return (0);
}

void cproc_module_stat_print(LOG *log, const CPROC_MODULE_STAT *cproc_module_stat)
{
    sys_log(log, "proc module stat: type = %ld, num = %ld\n",
                 CPROC_MODULE_TYPE(cproc_module_stat), CPROC_MODULE_NUM(cproc_module_stat));
    return;
}

UINT32 cproc_module_stat_clone(CPROC_MODULE_STAT *cproc_module_stat_src, CPROC_MODULE_STAT *cproc_module_stat_des)
{
    CPROC_MODULE_TYPE(cproc_module_stat_des) = CPROC_MODULE_TYPE(cproc_module_stat_src);
    CPROC_MODULE_NUM(cproc_module_stat_des) = CPROC_MODULE_NUM(cproc_module_stat_src);

    return (0);
}

EC_BOOL cproc_module_stat_cmp_type(const CPROC_MODULE_STAT *cproc_module_stat_1st, const CPROC_MODULE_STAT *cproc_module_stat_2nd)
{
    if(CPROC_MODULE_TYPE(cproc_module_stat_1st) == CPROC_MODULE_TYPE(cproc_module_stat_2nd))
    {
        return (EC_TRUE);
    }
    return (EC_FALSE);
}

UINT32 cproc_module_stat_get(CPROC_MODULE_STAT *cproc_module_stat)
{
    //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] cproc_module_stat_get: type = %ld\n", CPROC_MODULE_TYPE(cproc_module_stat));
    CPROC_MODULE_NUM(cproc_module_stat) = cbc_md_num(CPROC_MODULE_TYPE(cproc_module_stat));

    return (0);
}

CPROC_MODULE_STAT_VEC *cproc_module_stat_vec_new()
{
    CPROC_MODULE_STAT_VEC *cproc_module_stat_vec;

    alloc_static_mem(MM_CVECTOR, &cproc_module_stat_vec, LOC_CSYS_0044);
    cproc_module_stat_vec_init(cproc_module_stat_vec);

    return (cproc_module_stat_vec);
}

UINT32 cproc_module_stat_vec_init(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec)
{
    cvector_init(cproc_module_stat_vec, 0, MM_CPROC_MODULE_STAT, CVECTOR_LOCK_ENABLE, LOC_CSYS_0045);
    return (0);
}

UINT32 cproc_module_stat_vec_clean(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec)
{
    cvector_clean(cproc_module_stat_vec, (CVECTOR_DATA_CLEANER)cproc_module_stat_free, LOC_CSYS_0046);
    return (0);
}

UINT32 cproc_module_stat_vec_free(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec)
{
    cproc_module_stat_vec_clean(cproc_module_stat_vec);
    free_static_mem(MM_CVECTOR, cproc_module_stat_vec, LOC_CSYS_0047);
    return (0);
}

UINT32 cproc_module_stat_vec_size(const CPROC_MODULE_STAT_VEC *cproc_module_stat_vec)
{
    return cvector_size(cproc_module_stat_vec);
}

CPROC_MODULE_STAT * cproc_module_stat_vec_fetch(const CPROC_MODULE_STAT_VEC *cproc_module_stat_vec, const UINT32 cproc_module_stat_pos)
{
    return (CPROC_MODULE_STAT *)cvector_get(cproc_module_stat_vec, cproc_module_stat_pos);
}

void cproc_module_stat_vec_print(LOG *log, const CPROC_MODULE_STAT_VEC *cproc_module_stat_vec)
{
    cvector_print(log, cproc_module_stat_vec, (CVECTOR_DATA_PRINT)cproc_module_stat_print);
    return;
}

UINT32 cproc_module_stat_vec_get(CPROC_MODULE_STAT_VEC *cproc_module_stat_vec)
{
    UINT32 module_type;

    for(module_type = 0; module_type < cbc_size(); module_type ++)
    {
        CPROC_MODULE_STAT *cproc_module_stat;

        if(0 == cbc_md_num(module_type))
        {
            continue;
        }

        cproc_module_stat = cproc_module_stat_new();
        CPROC_MODULE_TYPE(cproc_module_stat) = module_type;
        cproc_module_stat_get(cproc_module_stat);
/*
        dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] cproc_module_stat_vec_get: module type %ld, module num %ld\n",
                            CPROC_MODULE_TYPE(cproc_module_stat), CPROC_MODULE_NUM(cproc_module_stat));
*/
        cvector_push(cproc_module_stat_vec, (void *)cproc_module_stat);
    }

    return (0);
}




CRANK_THREAD_STAT *crank_thread_stat_new()
{
    CRANK_THREAD_STAT *crank_thread_stat;

    alloc_static_mem(MM_CRANK_THREAD_STAT, &crank_thread_stat, LOC_CSYS_0048);
    crank_thread_stat_init(crank_thread_stat);

    return (crank_thread_stat);
}

UINT32 crank_thread_stat_init(CRANK_THREAD_STAT *crank_thread_stat)
{
    CRANK_THREAD_MAX_NUM(crank_thread_stat)  = 0;
    CRANK_THREAD_BUSY_NUM(crank_thread_stat) = 0;
    CRANK_THREAD_IDLE_NUM(crank_thread_stat) = 0;
    return (0);
}

UINT32 crank_thread_stat_clean(CRANK_THREAD_STAT *crank_thread_stat)
{
    CRANK_THREAD_MAX_NUM(crank_thread_stat)  = 0;
    CRANK_THREAD_BUSY_NUM(crank_thread_stat) = 0;
    CRANK_THREAD_IDLE_NUM(crank_thread_stat) = 0;
    return (0);
}

UINT32 crank_thread_stat_free(CRANK_THREAD_STAT *crank_thread_stat)
{
    crank_thread_stat_clean(crank_thread_stat);
    free_static_mem(MM_CRANK_THREAD_STAT, crank_thread_stat, LOC_CSYS_0049);
    return (0);
}

UINT32 crank_thread_stat_clone(const CRANK_THREAD_STAT *crank_thread_stat_src, CRANK_THREAD_STAT *crank_thread_stat_des)
{
    CRANK_THREAD_MAX_NUM(crank_thread_stat_des)  = CRANK_THREAD_MAX_NUM(crank_thread_stat_src);
    CRANK_THREAD_BUSY_NUM(crank_thread_stat_des) = CRANK_THREAD_BUSY_NUM(crank_thread_stat_src);
    CRANK_THREAD_IDLE_NUM(crank_thread_stat_des) = CRANK_THREAD_IDLE_NUM(crank_thread_stat_src);
    return (0);
}

void crank_thread_stat_print(LOG *log, const CRANK_THREAD_STAT *crank_thread_stat)
{
    sys_log(log, "rank thread stat: total %ld, busy %ld, idle %ld\n",
                    CRANK_THREAD_MAX_NUM(crank_thread_stat),
                    CRANK_THREAD_BUSY_NUM(crank_thread_stat),
                    CRANK_THREAD_IDLE_NUM(crank_thread_stat)
                    );
    return;
}

UINT32 crank_thread_stat_get(CRANK_THREAD_STAT *crank_thread_stat)
{
    TASK_BRD  *task_brd;
    task_brd = task_brd_default_get();

    croutine_pool_num_info(TASK_REQ_CTHREAD_POOL(task_brd),
                     &CRANK_THREAD_IDLE_NUM(crank_thread_stat),
                     &CRANK_THREAD_BUSY_NUM(crank_thread_stat),
                     &CRANK_THREAD_MAX_NUM(crank_thread_stat)
                     );
    return (0);
}

/*warning: need root priviledge*/
static UINT32 csys_eth_stat_speed(const char *eth_name)
{
    FILE  *rstream;
    char  *ethtool = "/sbin/ethtool";
    char  *cmd_line;
    char  *cmd_output;
    UINT32 speed;

    if(0 != access(ethtool, X_OK))
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_eth_stat_speed: unable to execute %s\n", ethtool);
        return (0);
    }

    cmd_line = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0050);
    if(NULL_PTR == cmd_line)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_eth_stat_speed: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    cmd_output = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0051);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_eth_stat_speed: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        SAFE_FREE(cmd_line, LOC_CSYS_0052);
        return ((UINT32)-1);
    }

    snprintf(cmd_line, CSYS_SHELL_BUF_MAX_SIZE, (char *)"%s %s 2>/dev/null", ethtool, eth_name);

    CSYS_DBG((LOGSTDOUT, "csys_eth_stat_speed: execute shell command: %s\n", cmd_line));

    speed = 0;

    rstream = popen((char *)cmd_line, "r");
    if(NULL_PTR == rstream)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_eth_stat_speed: popen %s failed\n", cmd_line);
        speed = 1000;/*guess default*/
        SAFE_FREE(cmd_line, LOC_CSYS_0053);
        SAFE_FREE(cmd_output, LOC_CSYS_0054);
        return (speed);
    }
    while(fgets(cmd_output, CSYS_SHELL_BUF_MAX_SIZE, rstream))
    {
        if((char *)0 != strcasestr(cmd_output, "Speed"))
        {
           sscanf(cmd_output + strspn(cmd_output," "), "Speed: %ldMb/s", &speed);
           break;
        }

        if((char *)0 != strcasestr(cmd_output, "No data available"))
        {
           dbg_log(SEC_0077_CSYS, 1)(LOGSTDNULL, "warn:csys_eth_stat_speed: please check netcard %s installation"
                              " or permission of execution \"%s\", set to default 1000Mb/s\n",
                              eth_name, cmd_line);
           speed = 1000;/*guess default*/
           break;
        }

        if(
           (char *)0 != strcasestr(cmd_output, "Cannot get device settings: Operation not permitted")
        || (char *)0 != strcasestr(cmd_output, "Cannot get wake-on-lan settings: Operation not permitted")
        || (char *)0 != strcasestr(cmd_output, "Cannot get message level: Operation not permitted")
        || (char *)0 != strcasestr(cmd_output, "Cannot get link status: Operation not permitted")
        )
        {
           dbg_log(SEC_0077_CSYS, 1)(LOGSTDNULL, "warn:csys_eth_stat_speed: please check permission of execution \"%s\", set to default 1000Mb/s\n", cmd_line);
           speed = 1000;/*guess default*/
           break;
        }
    }
    pclose( rstream );

    SAFE_FREE(cmd_line, LOC_CSYS_0055);
    SAFE_FREE(cmd_output, LOC_CSYS_0056);
    return (speed);
}

CSYS_ETH_STAT *csys_eth_stat_new()
{
    CSYS_ETH_STAT *csys_eth_stat;

    alloc_static_mem(MM_CSYS_ETH_STAT, &csys_eth_stat, LOC_CSYS_0057);

    csys_eth_stat_init(csys_eth_stat);
    return (csys_eth_stat);
}

UINT32 csys_eth_stat_init(CSYS_ETH_STAT *csys_eth_stat)
{
    cstring_init(CSYS_ETH_NAME(csys_eth_stat), NULL_PTR);
    CSYS_ETH_SPEEDMBS(csys_eth_stat) = 0;
    CSYS_ETH_RXMOCT(csys_eth_stat)   = 0;
    CSYS_ETH_TXMOCT(csys_eth_stat)   = 0;
    CSYS_ETH_RXTHROUGHPUT(csys_eth_stat)   = 0;
    CSYS_ETH_TXTHROUGHPUT(csys_eth_stat)   = 0;

    return (0);
}

UINT32 csys_eth_stat_clean(CSYS_ETH_STAT *csys_eth_stat)
{
    cstring_clean(CSYS_ETH_NAME(csys_eth_stat));
    CSYS_ETH_SPEEDMBS(csys_eth_stat) = 0;
    CSYS_ETH_RXMOCT(csys_eth_stat)   = 0;
    CSYS_ETH_TXMOCT(csys_eth_stat)   = 0;
    CSYS_ETH_RXTHROUGHPUT(csys_eth_stat)   = 0;
    CSYS_ETH_TXTHROUGHPUT(csys_eth_stat)   = 0;

    return (0);
}

UINT32 csys_eth_stat_free(CSYS_ETH_STAT *csys_eth_stat)
{
    if(NULL_PTR != csys_eth_stat)
    {
        csys_eth_stat_clean(csys_eth_stat);
        free_static_mem(MM_CSYS_ETH_STAT, csys_eth_stat, LOC_CSYS_0058);
    }
    return (0);
}

UINT32 csys_eth_stat_clone(CSYS_ETH_STAT *csys_eth_stat_src, CSYS_ETH_STAT *csys_eth_stat_des)
{
    cstring_clone(CSYS_ETH_NAME(csys_eth_stat_src), CSYS_ETH_NAME(csys_eth_stat_des));
    CSYS_ETH_SPEEDMBS(csys_eth_stat_des) = CSYS_ETH_SPEEDMBS(csys_eth_stat_src);
    CSYS_ETH_RXMOCT(csys_eth_stat_des) = CSYS_ETH_RXMOCT(csys_eth_stat_src);
    CSYS_ETH_TXMOCT(csys_eth_stat_des) = CSYS_ETH_TXMOCT(csys_eth_stat_src);
    CSYS_ETH_RXTHROUGHPUT(csys_eth_stat_des) = CSYS_ETH_RXTHROUGHPUT(csys_eth_stat_src);
    CSYS_ETH_TXTHROUGHPUT(csys_eth_stat_des) = CSYS_ETH_TXTHROUGHPUT(csys_eth_stat_src);

    return (0);
}

void csys_eth_stat_print(LOG *log, const CSYS_ETH_STAT *csys_eth_stat)
{
    sys_log(log, "eth stat: name  = %s\n", (char *)cstring_get_str(CSYS_ETH_NAME(csys_eth_stat)));
    sys_log(log, "eth stat: speed  = %ld Mb/s\n" , CSYS_ETH_SPEEDMBS(csys_eth_stat));
    sys_log(log, "eth stat: rxmoct = %u MBytes\n", CSYS_ETH_RXMOCT(csys_eth_stat));
    sys_log(log, "eth stat: txmoct = %u MBytes\n", CSYS_ETH_TXMOCT(csys_eth_stat));
    return;
}

UINT32 csys_eth_stat_get(char *buff, CSYS_ETH_STAT *csys_eth_stat)
{
    char  *fields[16];
    UINT32 field_num;

/*
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:18247732  850312    0    0    0     0          0         0 18247732  850312    0    0    0     0       0          0
  eth0: 8828650   12288    0    0    0     0          0         0  1427337   10360    0    0    0     0       0          0
*/

    //dbg_log(SEC_0077_CSYS, 5)(LOGSTDNULL, "csys_eth_stat_get: buff: \n%s\n", buff);
    field_num = c_str_split(buff, " :\t\r\n", fields, sizeof(fields)/sizeof(fields[ 0 ]));
    if(11 > field_num)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_eth_stat_get: too few fields, field num %ld\n", field_num);
        return ((UINT32)-1);
    }

    cstring_init(CSYS_ETH_NAME(csys_eth_stat), (UINT8 *)(fields[ 0 ]));
    CSYS_ETH_SPEEDMBS(csys_eth_stat) = csys_eth_stat_speed(fields[ 0 ]);
    CSYS_ETH_RXMOCT(csys_eth_stat) = (atoll (fields[ 1 ]) >> 20);/*MBytes*/
    CSYS_ETH_TXMOCT(csys_eth_stat) = (atoll (fields[ 9 ]) >> 20);/*MBytes*/
#if 0
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDNULL, "csys_eth_stat_get: name:%s, speed %ld Mb/s, rxmoct %u MBytes, txmoct %u MBytes\n",
                        (char *)cstring_get_str(CSYS_ETH_NAME(csys_eth_stat)),
                        CSYS_ETH_SPEEDMBS(csys_eth_stat),
                        CSYS_ETH_RXMOCT(csys_eth_stat),
                        CSYS_ETH_TXMOCT(csys_eth_stat)
           );
#endif
    return (0);
}


CSYS_ETH_VEC *csys_eth_stat_vec_new()
{
    CSYS_ETH_VEC *csys_eth_stat_vec;

    alloc_static_mem(MM_CVECTOR, &csys_eth_stat_vec, LOC_CSYS_0059);
    csys_eth_stat_vec_init(csys_eth_stat_vec);

    return (csys_eth_stat_vec);
}

UINT32 csys_eth_stat_vec_init(CSYS_ETH_VEC *csys_eth_stat_vec)
{
    cvector_init(csys_eth_stat_vec, 0, MM_CSYS_ETH_STAT, CVECTOR_LOCK_ENABLE, LOC_CSYS_0060);
    return (0);
}

UINT32 csys_eth_stat_vec_clean(CSYS_ETH_VEC *csys_eth_stat_vec)
{
    cvector_clean(csys_eth_stat_vec, (CVECTOR_DATA_CLEANER)csys_eth_stat_free, LOC_CSYS_0061);
    return (0);
}

UINT32 csys_eth_stat_vec_free(CSYS_ETH_VEC *csys_eth_stat_vec)
{
    csys_eth_stat_vec_clean(csys_eth_stat_vec);
    free_static_mem(MM_CVECTOR, csys_eth_stat_vec, LOC_CSYS_0062);
    return (0);
}

UINT32 csys_eth_stat_vec_size(const CSYS_ETH_VEC *csys_eth_stat_vec)
{
    return cvector_size(csys_eth_stat_vec);
}

CSYS_ETH_STAT * csys_eth_stat_vec_fetch(const CSYS_ETH_VEC *csys_eth_stat_vec, const UINT32 csys_eth_stat_pos)
{
    return (CSYS_ETH_STAT *)cvector_get(csys_eth_stat_vec, csys_eth_stat_pos);
}

void csys_eth_stat_vec_print(LOG *log, const CSYS_ETH_VEC *csys_eth_stat_vec)
{
    cvector_print(log, csys_eth_stat_vec, (CVECTOR_DATA_PRINT)csys_eth_stat_print);
    return;
}

UINT32 csys_eth_stat_vec_get(CSYS_ETH_VEC *csys_eth_stat_vec)
{
    char  *cache;
    char  *buff;
    char  *next;

    cache = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0063);
    if(NULL_PTR == cache)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_eth_stat_vec_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    exec_shell("cat /proc/net/dev", cache, CSYS_SHELL_BUF_MAX_SIZE);
    //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] csys_eth_stat_vec_get:cache: \n%s\n", cache);

    /**
      cache format:
    ===============
    Inter-|   Receive                                                |  Transmit
     face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
        lo: 3910340    2390    0    0    0     0          0         0  3910340    2390    0    0    0     0       0          0
      eth0: 7330407   42441    0    0    0     0          0         0 56330820   48197    0    0    0     0       0          0
    **/

    /*skip the eth average load info which locate the 1st line in /proc/stat*/
    buff = c_str_fetch_line(cache);
    next = c_str_move_next(buff);

    for(buff = next; NULL_PTR != (buff = c_str_fetch_line(buff)); buff = next)
    {
        CSYS_ETH_STAT *csys_eth_stat;

        next = c_str_move_next(buff);

        //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] csys_eth_stat_vec_get: buff %p, next %p\n", buff, next);
        //dbg_log(SEC_0077_CSYS, 9)(LOGSTDOUT, "[DEBUG] csys_eth_stat_vec_get: buff %s\n", buff);
     
        if (NULL_PTR == strchr(buff, ':'))
        {
            continue;
        }

        //dbg_log(SEC_0077_CSYS, 9)(LOGSTDNULL, "[DEBUG]csys_eth_stat_vec_get:buff: \n%s\n", buff);

        csys_eth_stat = csys_eth_stat_new();
        csys_eth_stat_get(buff + strspn(buff," "), csys_eth_stat);/*skip leading spaces*/

        /*skip lo*/
        if(0 == strcasecmp((char *)cstring_get_str(CSYS_ETH_NAME(csys_eth_stat)), (char *)"lo"))
        {
            csys_eth_stat_free(csys_eth_stat);
            continue;
        }
        cvector_push(csys_eth_stat_vec, (void *)csys_eth_stat);
    }

    SAFE_FREE(cache, CSYS_SHELL_BUF_MAX_SIZE);

    return (0);
}

CSYS_DSK_STAT *csys_dsk_stat_new()
{
    CSYS_DSK_STAT *csys_dsk_stat;

    alloc_static_mem(MM_CSYS_DSK_STAT, &csys_dsk_stat, LOC_CSYS_0064);

    csys_dsk_stat_init(csys_dsk_stat);
    return (csys_dsk_stat);
}

UINT32 csys_dsk_stat_init(CSYS_DSK_STAT *csys_dsk_stat)
{
    cstring_init(CSYS_DSK_NAME(csys_dsk_stat), NULL_PTR);
    CSYS_DSK_SIZE(csys_dsk_stat) = 0;
    CSYS_DSK_USED(csys_dsk_stat) = 0;
    CSYS_DSK_AVAL(csys_dsk_stat) = 0;
    CSYS_DSK_LOAD(csys_dsk_stat) = 0.0;

    return (0);
}

UINT32 csys_dsk_stat_clean(CSYS_DSK_STAT *csys_dsk_stat)
{
    cstring_clean(CSYS_DSK_NAME(csys_dsk_stat));
    CSYS_DSK_SIZE(csys_dsk_stat) = 0;
    CSYS_DSK_USED(csys_dsk_stat) = 0;
    CSYS_DSK_AVAL(csys_dsk_stat) = 0;
    CSYS_DSK_LOAD(csys_dsk_stat) = 0.0;

    return (0);
}

UINT32 csys_dsk_stat_free(CSYS_DSK_STAT *csys_dsk_stat)
{
    if(NULL_PTR != csys_dsk_stat)
    {
        csys_dsk_stat_clean(csys_dsk_stat);
        free_static_mem(MM_CSYS_DSK_STAT, csys_dsk_stat, LOC_CSYS_0065);
    }

    return (0);
}

UINT32 csys_dsk_stat_clone(CSYS_DSK_STAT *csys_dsk_stat_src, CSYS_DSK_STAT *csys_dsk_stat_des)
{
    cstring_clone(CSYS_DSK_NAME(csys_dsk_stat_src), CSYS_DSK_NAME(csys_dsk_stat_des));
    CSYS_DSK_SIZE(csys_dsk_stat_des) = CSYS_DSK_SIZE(csys_dsk_stat_src);
    CSYS_DSK_USED(csys_dsk_stat_des) = CSYS_DSK_USED(csys_dsk_stat_src);
    CSYS_DSK_AVAL(csys_dsk_stat_des) = CSYS_DSK_AVAL(csys_dsk_stat_src);
    CSYS_DSK_LOAD(csys_dsk_stat_des) = CSYS_DSK_LOAD(csys_dsk_stat_src);

    return (0);
}

void csys_dsk_stat_print(LOG *log, const CSYS_DSK_STAT *csys_dsk_stat)
{
    sys_log(log, "dsk stat: name  = %s\n", (char *)cstring_get_str(CSYS_DSK_NAME(csys_dsk_stat)));
    sys_log(log, "dsk stat: size  = %ld MBytes\n" , CSYS_DSK_SIZE(csys_dsk_stat));
    sys_log(log, "dsk stat: used  = %ld MBytes\n", CSYS_DSK_USED(csys_dsk_stat));
    sys_log(log, "dsk stat: aval  = %ld MBytes\n", CSYS_DSK_AVAL(csys_dsk_stat));
    sys_log(log, "dsk stat: load  = %.2f %%\n", CSYS_DSK_LOAD(csys_dsk_stat));
    return;
}

UINT32 csys_dsk_stat_get(char *buff, CSYS_DSK_STAT *csys_dsk_stat)
{
    char  *fields[8];
    UINT32 field_num;

/*
Filesystem           1M-blocks      Used Available Use% Mounted on
/dev/sda2                17560      6879      9776  42% /
/dev/sda1                  289        16       258   6% /boot
tmpfs                      506         0       506   0% /dev/shm
*/

    //dbg_log(SEC_0077_CSYS, 5)(LOGSTDNULL, "csys_dsk_stat_get: buff: \n%s\n", buff);
    field_num = c_str_split(buff, " %\t\r\n", fields, sizeof(fields)/sizeof(fields[ 0 ]));
    if(6 > field_num)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_dsk_stat_get: too few fields, field num %ld\n", field_num);
        return ((UINT32)-1);
    }

    cstring_init(CSYS_DSK_NAME(csys_dsk_stat), (UINT8 *)(fields[ 0 ]));
    CSYS_DSK_SIZE(csys_dsk_stat) = c_str_to_word(fields[ 1 ]);/*MBytes*/
    CSYS_DSK_USED(csys_dsk_stat) = c_str_to_word(fields[ 2 ]);/*MBytes*/
    CSYS_DSK_AVAL(csys_dsk_stat) = c_str_to_word(fields[ 3 ]);/*MBytes*/
    CSYS_DSK_LOAD(csys_dsk_stat) = atof(fields[ 4 ]);
#if 0
    dbg_log(SEC_0077_CSYS, 5)(LOGSTDNULL, "csys_dsk_stat_get: name:%s, size %ld MBytes, used %ld MBytes, aval %ld MBytes, load %.2f%%\n",
                        (char *)cstring_get_str(CSYS_DSK_NAME(csys_dsk_stat)),
                        CSYS_DSK_SIZE(csys_dsk_stat),
                        CSYS_DSK_USED(csys_dsk_stat),
                        CSYS_DSK_AVAL(csys_dsk_stat),
                        CSYS_DSK_LOAD(csys_dsk_stat)
           );
#endif
    return (0);
}


CSYS_DSK_VEC *csys_dsk_stat_vec_new()
{
    CSYS_DSK_VEC *csys_dsk_stat_vec;

    alloc_static_mem(MM_CVECTOR, &csys_dsk_stat_vec, LOC_CSYS_0066);
    csys_dsk_stat_vec_init(csys_dsk_stat_vec);

    return (csys_dsk_stat_vec);
}

UINT32 csys_dsk_stat_vec_init(CSYS_DSK_VEC *csys_dsk_stat_vec)
{
    cvector_init(csys_dsk_stat_vec, 0, MM_CSYS_DSK_STAT, CVECTOR_LOCK_ENABLE, LOC_CSYS_0067);
    return (0);
}

UINT32 csys_dsk_stat_vec_clean(CSYS_DSK_VEC *csys_dsk_stat_vec)
{
    cvector_clean(csys_dsk_stat_vec, (CVECTOR_DATA_CLEANER)csys_dsk_stat_free, LOC_CSYS_0068);
    return (0);
}

UINT32 csys_dsk_stat_vec_free(CSYS_DSK_VEC *csys_dsk_stat_vec)
{
    csys_dsk_stat_vec_clean(csys_dsk_stat_vec);
    free_static_mem(MM_CVECTOR, csys_dsk_stat_vec, LOC_CSYS_0069);
    return (0);
}

UINT32 csys_dsk_stat_vec_size(const CSYS_DSK_VEC *csys_dsk_stat_vec)
{
    return cvector_size(csys_dsk_stat_vec);
}

CSYS_DSK_STAT * csys_dsk_stat_vec_fetch(const CSYS_DSK_VEC *csys_dsk_stat_vec, const UINT32 csys_dsk_stat_pos)
{
    return (CSYS_DSK_STAT *)cvector_get(csys_dsk_stat_vec, csys_dsk_stat_pos);
}

void csys_dsk_stat_vec_print(LOG *log, const CSYS_DSK_VEC *csys_dsk_stat_vec)
{
    cvector_print(log, csys_dsk_stat_vec, (CVECTOR_DATA_PRINT)csys_dsk_stat_print);
    return;
}

UINT32 csys_dsk_stat_vec_get(CSYS_DSK_VEC *csys_dsk_stat_vec)
{
    FILE  *rstream;
    char  *df = "/bin/df";
    char  *cmd_line;
    char  *cmd_output;

    if(0 != access(df, X_OK))
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_dsk_stat_vec_get: unable to execute %s\n", df);
        return (0);
    }

    cmd_line = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0070);
    if(NULL_PTR == cmd_line)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_dsk_stat_vec_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        return ((UINT32)-1);
    }

    cmd_output = (char *)SAFE_MALLOC(CSYS_SHELL_BUF_MAX_SIZE, LOC_CSYS_0071);
    if(NULL_PTR == cmd_output)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_dsk_stat_vec_get: alloc %ld bytes failed\n", CSYS_SHELL_BUF_MAX_SIZE);
        SAFE_FREE(cmd_line, LOC_CSYS_0072);
        return ((UINT32)-1);
    }

    /*1048576 = 1024 * 1024 Bytes = 1 MB*/
    snprintf(cmd_line, CSYS_SHELL_BUF_MAX_SIZE, (char *)"%s -B1048576 -P 2>/dev/null", df);

    CSYS_DBG((LOGSTDOUT, "csys_dsk_stat_vec_get: execute shell command: %s\n", cmd_line));

    rstream = popen((char *)cmd_line, "r");
    if(NULL_PTR == rstream)
    {
        dbg_log(SEC_0077_CSYS, 0)(LOGSTDOUT, "error:csys_dsk_stat_vec_get: popen %s failed\n", cmd_line);

        SAFE_FREE(cmd_line, LOC_CSYS_0073);
        SAFE_FREE(cmd_output, LOC_CSYS_0074);
        return ((UINT32)-1);
    }
    while(fgets(cmd_output, CSYS_SHELL_BUF_MAX_SIZE, rstream))
    {
        if(0 != strncmp((char *)cmd_output, (char *)"Filesystem", strlen((char *)"Filesystem")))
        {
            CSYS_DSK_STAT *csys_dsk_stat;

            csys_dsk_stat = csys_dsk_stat_new();
            csys_dsk_stat_get((char *)cmd_output, csys_dsk_stat);
            cvector_push(csys_dsk_stat_vec, (void *)csys_dsk_stat);
        }
    }
    pclose( rstream );

    SAFE_FREE(cmd_line, LOC_CSYS_0075);
    SAFE_FREE(cmd_output, LOC_CSYS_0076);
    return (0);
}

CRANK_TASK_REPORT_VEC *crank_task_report_vec_new()
{
    CRANK_TASK_REPORT_VEC *crank_task_report_vec;

    alloc_static_mem(MM_CVECTOR, &crank_task_report_vec, LOC_CSYS_0077);
    crank_task_report_vec_init(crank_task_report_vec);

    return (crank_task_report_vec);
}

UINT32 crank_task_report_vec_init(CRANK_TASK_REPORT_VEC *crank_task_report_vec)
{
    cvector_init(crank_task_report_vec, 0, MM_TASK_REPORT_NODE, CVECTOR_LOCK_ENABLE, LOC_CSYS_0078);
    return (0);
}

UINT32 crank_task_report_vec_clean(CRANK_TASK_REPORT_VEC *crank_task_report_vec)
{
    cvector_clean(crank_task_report_vec, (CVECTOR_DATA_CLEANER)task_report_node_free, LOC_CSYS_0079);
    return (0);
}

UINT32 crank_task_report_vec_free(CRANK_TASK_REPORT_VEC *crank_task_report_vec)
{
    if(NULL_PTR != crank_task_report_vec)
    {
        crank_task_report_vec_clean(crank_task_report_vec);
        free_static_mem(MM_CVECTOR, crank_task_report_vec, LOC_CSYS_0080);
    }
    return (0);
}

UINT32 crank_task_report_vec_size(const CRANK_TASK_REPORT_VEC *crank_task_report_vec)
{
    return cvector_size(crank_task_report_vec);
}

TASK_REPORT_NODE * crank_task_report_vec_fetch(const CRANK_TASK_REPORT_VEC *crank_task_report_vec, const UINT32 crank_task_report_pos)
{
    return (TASK_REPORT_NODE *)cvector_get(crank_task_report_vec, crank_task_report_pos);
}

void crank_task_report_vec_print(LOG *log, const CRANK_TASK_REPORT_VEC *crank_task_report_vec)
{
    cvector_print(log, crank_task_report_vec, (CVECTOR_DATA_PRINT)task_report_node_print);
    return;
}

UINT32 crank_task_report_vec_get(CRANK_TASK_REPORT_VEC *crank_task_report_vec)
{
    TASK_BRD  *task_brd;
    task_brd = task_brd_default_get();

    task_brd_report_list_dump(task_brd, 128, CRANK_TASK_VEC_INFO(crank_task_report_vec));

    return (0);
}

void csys_test()
{
    CRANK_TASK_REPORT_VEC  *crank_task_report_vec;

    crank_task_report_vec = crank_task_report_vec_new();

    crank_task_report_vec_get(crank_task_report_vec);

    crank_task_report_vec_print(LOGSTDOUT, crank_task_report_vec);

    crank_task_report_vec_free(crank_task_report_vec);

    return;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/

