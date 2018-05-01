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

#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>
#include <stdlib.h>

#include "type.h"
#include "cstring.h"

#define LOG_FILE_DEVICE      ((UINT32) 1)
#define LOG_CSTR_DEVICE      ((UINT32) 2)
#define LOG_NULL_DEVICE      ((UINT32) 3)

#define LOG_DEFAULT_DBG_LEVEL    ((UINT32) 0)
#define LOG_MAX_DBG_LEVEL        ((UINT32) 9)
#define LOG_ERR_DBG_LEVEL        ((UINT32)-1)

#define LOG_LEVEL_NEVER_HAPPEN   ((UINT32)~0)
#define LOG_LEVEL_ALWAYS_HAPPEN  ((UINT32) 0)

#define stdnull ((FILE *)-1)

#define DEFAULT_STDOUT_LOG_INDEX    0
#define DEFAULT_STDIN_LOG_INDEX     1
#define DEFAULT_STDERR_LOG_INDEX    2
#define DEFAULT_STDNULL_LOG_INDEX   3
#define DEFAULT_CONSOLE_LOG_INDEX   4
#define DEFAULT_USRER05_LOG_INDEX   5
#define DEFAULT_USRER06_LOG_INDEX   6
#define DEFAULT_USRER07_LOG_INDEX   7
#define DEFAULT_USRER08_LOG_INDEX   8
#define DEFAULT_USRER09_LOG_INDEX   9
#define DEFAULT_END_LOG_INDEX       10

extern LOG g_default_log_tbl[];
#define LOGSTDOUT  (&g_default_log_tbl[ DEFAULT_STDOUT_LOG_INDEX  ])
#define LOGSTDIN   (&g_default_log_tbl[ DEFAULT_STDIN_LOG_INDEX   ])
#define LOGSTDERR  (&g_default_log_tbl[ DEFAULT_STDERR_LOG_INDEX  ])
#define LOGSTDNULL (&g_default_log_tbl[ DEFAULT_STDNULL_LOG_INDEX ])
#define LOGCONSOLE (&g_default_log_tbl[ DEFAULT_CONSOLE_LOG_INDEX ])
#define LOGUSER05  (&g_default_log_tbl[ DEFAULT_USRER05_LOG_INDEX ])
#define LOGUSER06  (&g_default_log_tbl[ DEFAULT_USRER06_LOG_INDEX ])
#define LOGUSER07  (&g_default_log_tbl[ DEFAULT_USRER07_LOG_INDEX ])
#define LOGUSER08  (&g_default_log_tbl[ DEFAULT_USRER08_LOG_INDEX ])
#define LOGUSER09  (&g_default_log_tbl[ DEFAULT_USRER09_LOG_INDEX ])

#define LOG_DEVICE_TYPE(this_log)                   ((this_log)->type)
#define LOG_SWITCH_OFF_ENABLE(this_log)             ((this_log)->switch_off_enable)
#define LOG_PID_INFO_ENABLE(this_log)               ((this_log)->pid_info_enable)
#define LOG_REDIRECT(this_log)                      ((this_log)->redirect_log)

#define LOG_FILE_NAME_WITH_DATE_SWITCH(file_log)    ((file_log)->logd.file.fname_with_date_switch)
#define LOG_FILE_NAME(file_log)                     ((file_log)->logd.file.fname)
#define LOG_FILE_NAME_STR(file_log)                 (cstring_get_str(LOG_FILE_NAME(file_log)))
#define LOG_FILE_MODE(file_log)                     ((file_log)->logd.file.mode)
#define LOG_FILE_MODE_STR(file_log)                 (cstring_get_str(LOG_FILE_MODE(file_log)))
#define LOG_FILE_FP(file_log)                       ((file_log)->logd.file.fp)
#define LOG_FILE_CMUTEX(file_log)                   ((file_log)->logd.file.mutex)
#define LOG_FILE_LIMIT_ENABLED(file_log)            ((file_log)->logd.file.record_limit_enabled)
#define LOG_FILE_RECORDS_LIMIT(file_log)            ((file_log)->logd.file.max_records)
#define LOG_FILE_CUR_RECORDS(file_log)              ((file_log)->logd.file.cur_records)
#define LOG_FILE_TCID(file_log)                     ((file_log)->logd.file.tcid)
#define LOG_FILE_RANK(file_log)                     ((file_log)->logd.file.rank)
                                               
#define LOG_CSTR(cstr_log)                          ((cstr_log)->logd.cstring)

#if 1
#define LOG_FILE_LOCK(file_log, location) do{\
if(NULL_PTR != LOG_FILE_CMUTEX(file_log)) {\
    c_mutex_lock(LOG_FILE_CMUTEX(file_log), location);\
}\
}while(0)

#define LOG_FILE_UNLOCK(file_log, location) do{\
if(NULL_PTR != LOG_FILE_CMUTEX(file_log)) {\
    c_mutex_unlock(LOG_FILE_CMUTEX(file_log), location);\
}\
}while(0)
#endif


#if 0
#define LOG_FILE_LOCK(file_log, location) do{\
if(NULL_PTR != (file_log) && NULL_PTR != LOG_FILE_CMUTEX(file_log)) {\
    c_mutex_lock(LOG_FILE_CMUTEX(file_log), location);\
}\
}while(0)

#define LOG_FILE_UNLOCK(file_log, location) do{\
if(NULL_PTR != (file_log) && NULL_PTR != LOG_FILE_CMUTEX(file_log)) {\
    c_mutex_unlock(LOG_FILE_CMUTEX(file_log), location);\
}\
}while(0)
#endif

#if 0
#define LOG_FILE_LOCK(file_log, location) do{\
if(NULL_PTR != (file_log) && LOG_FILE_DEVICE == LOG_DEVICE_TYPE(file_log) && NULL_PTR != LOG_FILE_FP(file_log) && NULL_PTR != LOG_FILE_CMUTEX(file_log)) {\
    c_mutex_lock(LOG_FILE_CMUTEX(file_log), location);\
}\
}while(0)

#define LOG_FILE_UNLOCK(file_log, location) do{\
if(NULL_PTR != (file_log) && LOG_FILE_DEVICE == LOG_DEVICE_TYPE(file_log) && NULL_PTR != LOG_FILE_FP(file_log) && NULL_PTR != LOG_FILE_CMUTEX(file_log)) {\
    c_mutex_unlock(LOG_FILE_CMUTEX(file_log), location);\
}\
}while(0)
#endif

#if 0
#define LOG_FILE_LOCK(file_log, location) do{}while(0)
#define LOG_FILE_UNLOCK(file_log, location) do{}while(0)
#endif

#define LOG_TM()        (task_brd_default_get_localtime())
#define LOG_TMV()       (task_brd_default_get_daytime())
#define LOG_TIME_STR()  (task_brd_default_get_time_str())

#define user_log        sys_log

extern UINT32 g_log_level[ SEC_NONE_END ];

#define do_log(SECTION, LEVEL)     (((UINT32)(LEVEL)) <= g_log_level[SECTION])

#define dbg_log(SECTION, LEVEL)    !do_log(SECTION, LEVEL) ? (void) 0 : sys_log

#define dbg_print(SECTION, LEVEL)  !do_log(SECTION, LEVEL) ? (void) 0 : sys_print

#define NULL_LOG(X, ...)            do{}while(0)
#define DBG_LOG(SECTION, LEVEL)     NULL_LOG
//#define DBG_LOG                     dbg_log

/*for debug only: finger out log format issue*/
#define std_log(X, ...)            fprintf(stdout, __VA_ARGS__)

//#define rlog(SECTION, LEVEL)        !do_log(SECTION, LEVEL) ? (void) 0 : sys_log
#define rlog(SECTION, LEVEL)        NULL_LOG 

typedef struct
{
    int     len;
    int     rsvd;
    char   *buf;
}LOG_NODE;

#define LOG_NODE_LEN(log_node)       ((log_node)->len)
#define LOG_NODE_BUF(log_node)       ((log_node)->buf)

EC_BOOL log_start();

void log_end();

void log_level_set(UINT32 *log_level_tab, const UINT32 log_level_tab_size, const UINT32 log_sector, const UINT32 log_level);

UINT32 log_level_get(const UINT32 *log_level_tab, const UINT32 log_level_tab_size, const UINT32 log_sector);

void log_level_tab_init(UINT32 *log_level_tab, const UINT32 log_level_tab_size, const UINT32 log_level);

void log_level_tab_clean(UINT32 *log_level_tab, const UINT32 log_level_tab_size);

void log_level_tab_clone(const UINT32 *log_level_tab_src, UINT32 *log_level_tab_des, const UINT32 log_level_tab_size);

void log_level_tab_set_all(UINT32 *log_level_tab, const UINT32 log_level_tab_size, const UINT32 log_level);

void log_level_import_from(const UINT32 *log_level_tab_src, UINT32 *log_level_tab_des, const UINT32 log_level_tab_size);

void log_level_import(const UINT32 *log_level_tab, const UINT32 log_level_tab_size);

void log_level_export(UINT32 *log_level_tab, const UINT32 log_level_tab_size);

void log_level_tab_print(LOG *log, const UINT32 *log_level_tab, const UINT32 log_level_tab_size);

void log_level_print(LOG *log);

EC_BOOL log_level_set_all(const UINT32 log_level);

EC_BOOL log_level_set_sector(const UINT32 log_sector, const UINT32 log_level);

LOG *log_get_by_fp(FILE *fp);

LOG *log_get_by_fd(const UINT32 fd);

/*register user log only!*/
EC_BOOL log_reg(LOG *log, FILE *fp);

/*unregister user log only!*/
FILE *log_unreg(LOG *log);

EC_BOOL user_log_open(LOG *log, const char *fname, const char *mode);

EC_BOOL user_log_close(LOG *log);

int sys_log_no_lock(LOG *log, const char * format, ...);

int sys_log(LOG *log, const char * format, ...);

int sys_log_rotate(LOG *log);

int sys_log_rotate_by_index(const UINT32 log_index);

int sys_print_no_lock(LOG *log, const char * format, ...);

int sys_print(LOG *log, const char * format, ...);

int sys_log_switch_on();

int sys_log_switch_off();

int sys_log_redirect_setup(LOG *old_log, LOG *new_log);

LOG * sys_log_redirect_cancel(LOG *log);

LOG *log_file_new(const char *fname, const char *mode, const UINT32 tcid, const UINT32 rank, const UINT32 record_limit_enabled, const UINT32 fname_with_date_switch, const UINT32 switch_off_enable, const UINT32 pid_info_enable);

EC_BOOL log_file_init(LOG *log, const char *fname, const char *mode, const UINT32 tcid, const UINT32 rank, const UINT32 record_limit_enabled, const UINT32 fname_with_date_switch, const UINT32 switch_off_enable, const UINT32 pid_info_enable);

EC_BOOL log_file_clean(LOG *log);

EC_BOOL log_file_fopen(LOG *log);

EC_BOOL log_file_fclose(LOG *log);

EC_BOOL log_file_freopen(LOG *log);

EC_BOOL log_file_rotate(LOG *log);

void log_file_free(LOG *log);

LOG * log_file_open(const char *fname, const char *mode, const UINT32 tcid, const UINT32 rank, const UINT32 record_limit_enabled, const UINT32 fname_with_date_switch, const UINT32 switch_off_enable, const UINT32 pid_info_enable);

EC_BOOL log_file_close(LOG *log);

LOG *log_cstr_new();

EC_BOOL log_cstr_init(LOG *log);

EC_BOOL log_cstr_clean(LOG *log);

void log_cstr_free(LOG *log);

LOG * log_cstr_open();

EC_BOOL log_cstr_close(LOG *log);

UINT32 log_init(LOG *log);

EC_BOOL log_clean(LOG *log);

EC_BOOL log_free(LOG *log);

LOG *log_open(const char *fname, const char *mode);

EC_BOOL log_close(LOG *log);

EC_BOOL log_set_level(const char *level_cfg);

void echo_msg(const char * format, ...);/*for debug only*/

#endif/* _LOG_H */

#ifdef __cplusplus
}
#endif/*__cplusplus*/

